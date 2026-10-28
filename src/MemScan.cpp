#include "MemScan.h"
#include "Logger.h"

#include <windows.h>

#include <cstring>

namespace drs {

namespace {

// ---------------------------------------------------------------------------
// Leaf functions. MSVC forbids mixing __try with objects that need unwinding,
// so each guarded access lives in its own tiny function with no such objects.
// ---------------------------------------------------------------------------

bool guardedReadFloat(const void* address, float* out) noexcept
{
    __try
    {
        *out = *reinterpret_cast<const float*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

bool guardedReadDword(const void* address, std::uint32_t* out) noexcept
{
    __try
    {
        *out = *reinterpret_cast<const std::uint32_t*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

bool guardedReadPointer(const void* address, std::uint64_t* out) noexcept
{
    __try
    {
        *out = *reinterpret_cast<const std::uint64_t*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

bool guardedWriteFloat(void* address, float value) noexcept
{
    __try
    {
        *reinterpret_cast<float*>(address) = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

// Copies at most capacity - 1 characters. Returns how many were copied, or
// SIZE_MAX if the source faulted part-way (the caller then reports 0).
std::size_t guardedCopyCString(const char* source, char* dest, std::size_t capacity) noexcept
{
    std::size_t copied = 0;
    __try
    {
        while (copied + 1u < capacity)
        {
            const char c = source[copied];
            if (c == '\0')
            {
                break;
            }
            dest[copied] = c;
            ++copied;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return static_cast<std::size_t>(-1);
    }
    return copied;
}

// Scans one region for a set of 4-byte values. Kept as a leaf so the whole
// inner loop sits inside one __try: taking the guard per dword would cost more
// than the comparison itself.
//
// maybeTable is a 64 KiB lookup indexed by the low 16 bits of the candidate.
// It turns "is this dword one of my few dozen hashes" into one cached byte read.
std::size_t guardedScanRegion(const std::uint8_t* base,
                              std::size_t regionSize,
                              const std::uint8_t* maybeTable,
                              const std::uint32_t* values,
                              std::size_t valueCount,
                              std::uint8_t** hitAddresses,
                              std::uint32_t* hitValueIndex,
                              std::size_t hitCapacity) noexcept
{
    std::size_t hitCount = 0;
    __try
    {
        const std::size_t steps = regionSize / 4u;
        const std::uint32_t* cursor = reinterpret_cast<const std::uint32_t*>(base);
        for (std::size_t i = 0; i < steps; ++i)
        {
            const std::uint32_t candidate = cursor[i];
            if (maybeTable[candidate & 0xFFFFu] == 0u)
            {
                continue;
            }
            for (std::size_t v = 0; v < valueCount; ++v)
            {
                if (values[v] != candidate)
                {
                    continue;
                }
                if (hitCount < hitCapacity)
                {
                    hitAddresses[hitCount]  = const_cast<std::uint8_t*>(
                        reinterpret_cast<const std::uint8_t*>(cursor + i));
                    hitValueIndex[hitCount] = static_cast<std::uint32_t>(v);
                    ++hitCount;
                }
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Region vanished mid-scan. Keep whatever was collected and move on.
    }
    return hitCount;
}

// Same idea for 8-byte values at 8-byte aligned positions. Region bases are page
// aligned and chunk offsets are multiples of 16 MB, so `base` is always aligned.
std::size_t guardedScanQwordRegion(const std::uint8_t* base,
                                   std::size_t regionSize,
                                   const std::uint64_t* values,
                                   std::size_t valueCount,
                                   std::uint8_t** hitAddresses,
                                   std::size_t hitCapacity) noexcept
{
    std::size_t hitCount = 0;
    __try
    {
        const std::size_t steps = regionSize / 8u;
        const std::uint64_t* cursor = reinterpret_cast<const std::uint64_t*>(base);
        const std::uint64_t first = values[0];
        for (std::size_t i = 0; i < steps; ++i)
        {
            const std::uint64_t candidate = cursor[i];
            bool match = (candidate == first);
            for (std::size_t v = 1; !match && v < valueCount; ++v)
            {
                match = (candidate == values[v]);
            }
            if (!match)
            {
                continue;
            }
            if (hitCount < hitCapacity)
            {
                hitAddresses[hitCount] = const_cast<std::uint8_t*>(
                    reinterpret_cast<const std::uint8_t*>(cursor + i));
                ++hitCount;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return hitCount;
}

std::size_t guardedScanBytes(const std::uint8_t* base,
                             std::size_t regionSize,
                             const std::uint8_t* needle,
                             std::size_t needleLength,
                             std::uint8_t** hitAddresses,
                             std::size_t hitCapacity) noexcept
{
    std::size_t hitCount = 0;
    __try
    {
        if (regionSize < needleLength)
        {
            return 0;
        }
        const std::size_t limit = regionSize - needleLength;
        for (std::size_t i = 0; i <= limit; ++i)
        {
            if (base[i] != needle[0])
            {
                continue;
            }
            std::size_t k = 1;
            while (k < needleLength && base[i + k] == needle[k])
            {
                ++k;
            }
            if (k == needleLength)
            {
                if (hitCount < hitCapacity)
                {
                    hitAddresses[hitCount] = const_cast<std::uint8_t*>(base + i);
                    ++hitCount;
                }
                if (hitCount >= hitCapacity)
                {
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return hitCount;
}

bool isUncachedProtection(DWORD protect) noexcept
{
    // Write-combined / uncached pages are GPU upload heaps and similar. Reading
    // them from the CPU bypasses the cache and is orders of magnitude slower than
    // normal RAM, and parsed weapons.ymt data never lives there.
    return (protect & (PAGE_WRITECOMBINE | PAGE_NOCACHE)) != 0u;
}

bool isWritableProtection(DWORD protect) noexcept
{
    if ((protect & PAGE_GUARD) != 0u || (protect & PAGE_NOACCESS) != 0u)
    {
        return false;
    }
    // Copy-on-write variants exist only for image and mapped sections, never for
    // the private heap that holds weapon data, so they are not accepted. An
    // executable-writable heap is unusual but possible, and writing a float into
    // it is no different from a plain read-write page; it is accepted as-is.
    // Protection is never CHANGED by this plugin (1.2).
    return (protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0u;
}

bool protectionAllowsRead(DWORD protect) noexcept
{
    if ((protect & PAGE_GUARD) != 0u || (protect & PAGE_NOACCESS) != 0u)
    {
        return false;
    }
    if (isUncachedProtection(protect))
    {
        return false;
    }
    const DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                           PAGE_EXECUTE_WRITECOPY;
    return (protect & readable) != 0u;
}

struct ModuleBounds
{
    const std::uint8_t* base = nullptr;
    std::size_t         size = 0;

    bool contains(const void* address) const noexcept
    {
        const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(address);
        return base != nullptr && p >= base && p < base + size;
    }
};

// Image size straight out of the PE headers. Deliberately avoids psapi.h so the
// plugin links against nothing but kernel32 — one less thing to go wrong on a
// user's machine, and /MT stays clean.
ModuleBounds boundsOf(HMODULE module) noexcept
{
    ModuleBounds bounds;
    if (module == nullptr)
    {
        return bounds;
    }

    const std::uint8_t* base = reinterpret_cast<const std::uint8_t*>(module);
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return bounds;
    }

    const IMAGE_NT_HEADERS* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return bounds;
    }

    bounds.base = base;
    bounds.size = static_cast<std::size_t>(nt->OptionalHeader.SizeOfImage);
    return bounds;
}

const ModuleBounds& ownModuleBounds() noexcept
{
    static ModuleBounds bounds = [] {
        HMODULE self = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&protectionAllowsRead),
                           &self);
        return boundsOf(self);
    }();
    return bounds;
}

const ModuleBounds& mainModuleBounds() noexcept
{
    static ModuleBounds bounds = boundsOf(GetModuleHandleW(nullptr));
    return bounds;
}

} // namespace

// ---------------------------------------------------------------------------

bool MemScan::readFloat(const void* address, float& out) noexcept
{
    return address != nullptr && guardedReadFloat(address, &out);
}

bool MemScan::readDword(const void* address, std::uint32_t& out) noexcept
{
    return address != nullptr && guardedReadDword(address, &out);
}

bool MemScan::readPointer(const void* address, std::uint64_t& out) noexcept
{
    return address != nullptr && guardedReadPointer(address, &out);
}

bool MemScan::writeFloat(void* address, float value) noexcept
{
    return address != nullptr && guardedWriteFloat(address, value);
}

std::size_t MemScan::readCString(const char* source, char* dest, std::size_t capacity) noexcept
{
    if (dest == nullptr || capacity == 0)
    {
        return 0;
    }
    dest[0] = '\0';
    if (source == nullptr)
    {
        return 0;
    }
    const std::size_t copied = guardedCopyCString(source, dest, capacity);
    if (copied == static_cast<std::size_t>(-1))
    {
        dest[0] = '\0';
        return 0;
    }
    dest[copied] = '\0';
    return copied;
}

bool MemScan::isCommittedReadable(const void* address, std::size_t bytes) noexcept
{
    if (address == nullptr)
    {
        return false;
    }
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
    {
        return false;
    }
    if (mbi.State != MEM_COMMIT || !protectionAllowsRead(mbi.Protect))
    {
        return false;
    }
    const std::uint8_t* start = reinterpret_cast<const std::uint8_t*>(address);
    const std::uint8_t* end   = start + bytes;
    const std::uint8_t* regionEnd =
        reinterpret_cast<const std::uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    return end <= regionEnd;
}

bool MemScan::isInsideOwnModule(const void* address) noexcept
{
    return ownModuleBounds().contains(address);
}

bool MemScan::isInsideMainModule(const void* address) noexcept
{
    return mainModuleBounds().contains(address);
}

std::uint64_t MemScan::mainModuleOffset(const void* address) noexcept
{
    const ModuleBounds& bounds = mainModuleBounds();
    if (!bounds.contains(address))
    {
        return 0u;
    }
    return static_cast<std::uint64_t>(reinterpret_cast<const std::uint8_t*>(address) -
                                      bounds.base);
}

bool MemScan::isOnCurrentThreadStack(const void* address) noexcept
{
    // The TIB gives the current thread's stack limits directly; no guessing.
    const NT_TIB* tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
    if (tib == nullptr)
    {
        return false;
    }
    const std::uint8_t* p     = reinterpret_cast<const std::uint8_t*>(address);
    const std::uint8_t* limit = reinterpret_cast<const std::uint8_t*>(tib->StackLimit);
    const std::uint8_t* base  = reinterpret_cast<const std::uint8_t*>(tib->StackBase);
    return limit != nullptr && base != nullptr && p >= limit && p < base;
}

bool MemScan::passesStaticChecks(const void* address) noexcept
{
    if (address == nullptr)
    {
        return false;
    }
    if (isInsideOwnModule(address))
    {
        return false;
    }
    if (isOnCurrentThreadStack(address))
    {
        return false;
    }
    return (reinterpret_cast<std::uintptr_t>(address) % alignof(float)) == 0u;
}

const MemoryRegion* MemScan::regionFor(const void* address) const noexcept
{
    if (address == nullptr || m_regions.empty())
    {
        return nullptr;
    }
    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(address);
    // m_regions is built by walking the address space upwards, so it is sorted
    // by base. Find the last region whose base is <= address.
    std::size_t lo = 0;
    std::size_t hi = m_regions.size();
    while (lo < hi)
    {
        const std::size_t mid = lo + (hi - lo) / 2u;
        if (m_regions[mid].base <= p) { lo = mid + 1u; } else { hi = mid; }
    }
    if (lo == 0)
    {
        return nullptr;
    }
    const MemoryRegion& region = m_regions[lo - 1u];
    if (p >= region.base + region.size)
    {
        return nullptr;
    }
    return &region;
}

std::size_t MemScan::spanFromRegions(const std::uint8_t* address, std::size_t cap) const noexcept
{
    const MemoryRegion* region = regionFor(address);
    if (region == nullptr)
    {
        return 0;
    }
    const std::uint8_t* end = region->base + region->size;
    const std::size_t span = static_cast<std::size_t>(end - address);
    return (span > cap) ? cap : span;
}

bool MemScan::regionAllowsWrite(const void* address, std::size_t bytes) const noexcept
{
    const MemoryRegion* region = regionFor(address);
    if (region == nullptr)
    {
        return false;
    }
    const std::uint8_t* start = reinterpret_cast<const std::uint8_t*>(address);
    if (start + bytes > region->base + region->size)
    {
        return false;
    }
    return isWritableProtection(static_cast<DWORD>(region->protect));
}

bool MemScan::buildRegionList(bool includeMapped, std::uint64_t maxScanBytes)
{
    m_regions.clear();
    m_scannableBytes = 0;

    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);

    std::uint8_t* cursor  = reinterpret_cast<std::uint8_t*>(systemInfo.lpMinimumApplicationAddress);
    std::uint8_t* maximum = reinterpret_cast<std::uint8_t*>(systemInfo.lpMaximumApplicationAddress);

    std::size_t   skippedImage         = 0;
    std::size_t   skippedMapped        = 0;
    std::size_t   skippedUncached      = 0;
    std::uint64_t skippedUncachedBytes = 0;

    while (cursor < maximum)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(cursor, &mbi, sizeof(mbi)) == 0)
        {
            break;
        }

        std::uint8_t* regionBase = reinterpret_cast<std::uint8_t*>(mbi.BaseAddress);
        const std::size_t regionSize = static_cast<std::size_t>(mbi.RegionSize);
        if (regionSize == 0)
        {
            break;
        }

        const bool committed = (mbi.State == MEM_COMMIT);
        const bool readable  = protectionAllowsRead(mbi.Protect);
        const bool isImage   = (mbi.Type == MEM_IMAGE);
        const bool isMapped  = (mbi.Type == MEM_MAPPED);
        const bool isPrivate = (mbi.Type == MEM_PRIVATE);
        const bool ours      = ownModuleBounds().contains(regionBase);

        if (committed && isUncachedProtection(mbi.Protect))
        {
            ++skippedUncached;
            skippedUncachedBytes += regionSize;
        }

        if (committed && readable && !ours && !isImage)
        {
            if (isPrivate || (includeMapped && isMapped))
            {
                if (maxScanBytes == 0ull ||
                    m_scannableBytes + regionSize <= maxScanBytes)
                {
                    MemoryRegion region;
                    region.base    = regionBase;
                    region.size    = regionSize;
                    region.type    = static_cast<std::uint32_t>(mbi.Type);
                    region.protect = static_cast<std::uint32_t>(mbi.Protect);
                    m_regions.push_back(region);
                    m_scannableBytes += regionSize;
                }
            }
            else if (isMapped)
            {
                ++skippedMapped;
            }
        }
        else if (committed && isImage)
        {
            ++skippedImage;
        }

        std::uint8_t* next = regionBase + regionSize;
        if (next <= cursor)
        {
            break;   // defensive: never loop forever on a strange region
        }
        cursor = next;
    }

    DRS_INFO("memscan: regions=%zu scannable=%.1f MB (image regions skipped=%zu, "
             "mapped regions skipped=%zu, includeMapped=%d, "
             "uncached/GPU regions skipped=%zu = %.1f MB)",
             m_regions.size(),
             static_cast<double>(m_scannableBytes) / (1024.0 * 1024.0),
             skippedImage, skippedMapped, includeMapped ? 1 : 0,
             skippedUncached,
             static_cast<double>(skippedUncachedBytes) / (1024.0 * 1024.0));

    return !m_regions.empty();
}

std::vector<ScanResult> MemScan::findDwords(const std::vector<ScanRequest>& requests,
                                            std::uint64_t& bytesScannedOut) const
{
    std::vector<ScanResult> results;
    results.reserve(requests.size());
    bytesScannedOut = 0;

    if (requests.empty() || m_regions.empty())
    {
        return results;
    }

    std::vector<std::uint32_t> values;
    values.reserve(requests.size());
    for (const ScanRequest& request : requests)
    {
        ScanResult result;
        result.value = request.value;
        results.push_back(result);
        values.push_back(request.value);
    }

    // 64 KiB "maybe" table: one byte per low-16-bit key.
    std::vector<std::uint8_t> maybeTable(0x10000u, 0u);
    for (std::uint32_t value : values)
    {
        maybeTable[value & 0xFFFFu] = 1u;
    }

    // Per-chunk hit buffer. Common weapon hashes appear thousands of times in
    // memory (every ped loadout, every weapon object), and the one structure we
    // need may sit behind all of them - 1.1 kept only the first 64 hits per name
    // and lost the real CWeaponInfo of the base Cattleman that way.
    constexpr std::size_t kChunkHitCapacity = 65536;
    std::vector<std::uint8_t*> hitAddresses(kChunkHitCapacity, nullptr);
    std::vector<std::uint32_t> hitValueIndex(kChunkHitCapacity, 0u);

    const ULONGLONG startTicks = GetTickCount64();
    ULONGLONG lastProgressTicks = startTicks;
    std::size_t fullChunks = 0;   // chunks that filled the hit buffer (hits beyond it are lost)

    // Cooperative yield granularity. The scan is a background job: between
    // chunks it hands the core back to any ready thread, so a single huge region
    // never hogs memory bandwidth for seconds at a time.
    constexpr std::size_t kChunkBytes = 16u * 1024u * 1024u;

    for (const MemoryRegion& region : m_regions)
    {
        for (std::size_t offset = 0; offset < region.size; offset += kChunkBytes)
        {
            const std::size_t remaining = region.size - offset;
            const std::size_t chunk     = (remaining < kChunkBytes) ? remaining : kChunkBytes;

            const std::size_t found = guardedScanRegion(region.base + offset, chunk,
                                                        maybeTable.data(),
                                                        values.data(), values.size(),
                                                        hitAddresses.data(),
                                                        hitValueIndex.data(),
                                                        kChunkHitCapacity);
            if (found >= kChunkHitCapacity)
            {
                ++fullChunks;
            }

            for (std::size_t i = 0; i < found; ++i)
            {
                ScanResult& result = results[hitValueIndex[i]];
                if (result.hits.size() < requests[hitValueIndex[i]].maxHits)
                {
                    result.hits.push_back(hitAddresses[i]);
                }
                else
                {
                    result.truncated = true;
                }
            }

            SwitchToThread();
        }

        bytesScannedOut += region.size;

        // A progress line every few seconds: if a scan is ever slow on some
        // machine, the log shows how far it got instead of just stopping.
        const ULONGLONG nowTicks = GetTickCount64();
        if (nowTicks - lastProgressTicks >= 3000u)
        {
            lastProgressTicks = nowTicks;
            DRS_INFO("memscan: progress %.1f / %.1f MB after %llu ms",
                     static_cast<double>(bytesScannedOut) / (1024.0 * 1024.0),
                     static_cast<double>(m_scannableBytes) / (1024.0 * 1024.0),
                     static_cast<unsigned long long>(nowTicks - startTicks));
        }
    }

    DRS_INFO("memscan: pass complete, %.1f MB in %llu ms",
             static_cast<double>(bytesScannedOut) / (1024.0 * 1024.0),
             static_cast<unsigned long long>(GetTickCount64() - startTicks));
    if (fullChunks != 0u)
    {
        // Not an error: the class scan (WeaponPatcher) recovers any weapon
        // structure lost here. Logged so a report shows it happened.
        DRS_INFO("memscan: %zu chunk(s) had more than %zu hits; the extra hits were not kept",
                 fullChunks, kChunkHitCapacity);
    }

    return results;
}

std::vector<std::uint8_t*> MemScan::findQwords(const std::uint64_t* values,
                                               std::size_t valueCount,
                                               std::size_t maxHits,
                                               std::uint64_t& bytesScannedOut) const
{
    std::vector<std::uint8_t*> hits;
    bytesScannedOut = 0;
    if (values == nullptr || valueCount == 0 || valueCount > 4 || m_regions.empty())
    {
        return hits;
    }

    constexpr std::size_t kChunkHitCapacity = 8192;
    std::vector<std::uint8_t*> buffer(kChunkHitCapacity, nullptr);
    constexpr std::size_t kChunkBytes = 16u * 1024u * 1024u;

    const ULONGLONG startTicks = GetTickCount64();

    for (const MemoryRegion& region : m_regions)
    {
        for (std::size_t offset = 0; offset < region.size; offset += kChunkBytes)
        {
            const std::size_t remaining = region.size - offset;
            const std::size_t chunk     = (remaining < kChunkBytes) ? remaining : kChunkBytes;

            const std::size_t found = guardedScanQwordRegion(region.base + offset, chunk,
                                                             values, valueCount,
                                                             buffer.data(),
                                                             kChunkHitCapacity);
            for (std::size_t i = 0; i < found && hits.size() < maxHits; ++i)
            {
                hits.push_back(buffer[i]);
            }
            SwitchToThread();
        }
        bytesScannedOut += region.size;
        if (hits.size() >= maxHits)
        {
            break;
        }
    }

    DRS_INFO("memscan: class pass complete, %.1f MB in %llu ms, %zu object(s)",
             static_cast<double>(bytesScannedOut) / (1024.0 * 1024.0),
             static_cast<unsigned long long>(GetTickCount64() - startTicks),
             hits.size());
    return hits;
}

std::vector<std::uint8_t*> MemScan::findAscii(const char* text, std::size_t maxHits) const
{
    std::vector<std::uint8_t*> hits;
    if (text == nullptr)
    {
        return hits;
    }
    const std::size_t length = std::strlen(text);
    if (length == 0)
    {
        return hits;
    }

    constexpr std::size_t kRegionHitCapacity = 256;
    std::vector<std::uint8_t*> buffer(kRegionHitCapacity, nullptr);

    for (const MemoryRegion& region : m_regions)
    {
        const std::size_t found = guardedScanBytes(
            region.base, region.size,
            reinterpret_cast<const std::uint8_t*>(text), length,
            buffer.data(), kRegionHitCapacity);

        for (std::size_t i = 0; i < found && hits.size() < maxHits; ++i)
        {
            hits.push_back(buffer[i]);
        }
        if (hits.size() >= maxHits)
        {
            break;
        }
    }
    return hits;
}

std::vector<std::uint8_t*> MemScan::findPointersTo(const std::uint8_t* target,
                                                   std::size_t maxHits) const
{
    std::vector<std::uint8_t*> hits;
    if (target == nullptr)
    {
        return hits;
    }

    const std::uint64_t needleValue = reinterpret_cast<std::uint64_t>(target);
    std::uint8_t needle[sizeof(std::uint64_t)] = {};
    std::memcpy(needle, &needleValue, sizeof(needle));

    constexpr std::size_t kRegionHitCapacity = 256;
    std::vector<std::uint8_t*> buffer(kRegionHitCapacity, nullptr);

    for (const MemoryRegion& region : m_regions)
    {
        const std::size_t found = guardedScanBytes(region.base, region.size,
                                                   needle, sizeof(needle),
                                                   buffer.data(), kRegionHitCapacity);
        for (std::size_t i = 0; i < found && hits.size() < maxHits; ++i)
        {
            hits.push_back(buffer[i]);
        }
        if (hits.size() >= maxHits)
        {
            break;
        }
    }
    return hits;
}

} // namespace drs

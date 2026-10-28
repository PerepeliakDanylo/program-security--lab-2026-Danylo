// MemScan.h — raw memory primitives. Knows nothing about weapons or profiles.
//
// Everything here is read-only except writeFloat(), and every single access goes
// through a structured-exception guard: a page can be freed by another thread
// between the moment it was checked and the moment it is touched, and that is
// not a reason to take the player's game down.
//
// 1.2: the region list is also the validation source. VirtualQuery is called
// only while the list is built (once, on the resolver thread). On this process
// one VirtualQuery into the multi-gigabyte heap that holds CWeaponInfo costs
// ~4 ms - the 1.1 log showed two of them per field, i.e. ~450 ms of frozen main
// thread on every CALM/COMBAT switch. Nothing on the switching path may make a
// system call any more; the address checks there are pure arithmetic against
// the list built here.
//
// Deliberately NOT here: any function that takes an address from configuration.
// See docs/DESIGN.md section 3.6.
//
// No dependency on the ScriptHookRDR2 SDK.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace drs {

struct MemoryRegion
{
    std::uint8_t* base    = nullptr;
    std::size_t   size    = 0;
    std::uint32_t type    = 0;    // MEM_PRIVATE or MEM_MAPPED
    std::uint32_t protect = 0;    // PAGE_* of the whole region (VirtualQuery reports
                                  // a region as a run of pages with equal attributes)
};

struct ScanRequest
{
    std::uint32_t value   = 0u;    // the 4-byte value to look for
    std::size_t   maxHits = 64u;   // stop collecting after this many
};

struct ScanResult
{
    std::uint32_t              value = 0u;
    std::vector<std::uint8_t*> hits;
    bool                       truncated = false;   // maxHits reached
};

class MemScan
{
public:
    // Walks the whole user address space once. includeMapped=false keeps only
    // MEM_PRIVATE regions, which is where a RAGE heap allocation lands; the
    // caller retries with true only if nothing at all was found, and logs that.
    bool buildRegionList(bool includeMapped, std::uint64_t maxScanBytes);

    std::size_t   regionCount()    const noexcept { return m_regions.size(); }
    std::uint64_t scannableBytes() const noexcept { return m_scannableBytes; }

    // One pass over every region, looking for all requested values at once.
    // Doing this per value would mean one full pass per weapon, which on a
    // multi-gigabyte process is minutes instead of seconds.
    std::vector<ScanResult> findDwords(const std::vector<ScanRequest>& requests,
                                       std::uint64_t& bytesScannedOut) const;

    // One pass looking for up to four 8-byte values at 8-byte aligned addresses
    // (1.2: used to enumerate every object of one class by its vtable pointer).
    std::vector<std::uint8_t*> findQwords(const std::uint64_t* values,
                                          std::size_t valueCount,
                                          std::size_t maxHits,
                                          std::uint64_t& bytesScannedOut) const;

    // Strategy B from DESIGN.md 3.2: find the literal name bytes, then find a
    // pointer to them. Only used if the hash search found nothing.
    std::vector<std::uint8_t*> findAscii(const char* text, std::size_t maxHits) const;
    std::vector<std::uint8_t*> findPointersTo(const std::uint8_t* target,
                                              std::size_t maxHits) const;

    // --- region list lookups (no system call) --------------------------------
    // The scanned region containing `address`, or nullptr.
    const MemoryRegion* regionFor(const void* address) const noexcept;

    // Readable span from `address` to the end of the scanned region that contains
    // it, capped at `cap`. A binary search instead of one VirtualQuery per
    // candidate (the 1.0 log showed ~8 s spent in thousands of those calls).
    std::size_t spanFromRegions(const std::uint8_t* address, std::size_t cap) const noexcept;

    // True when [address, address + bytes) lies inside one scanned region whose
    // protection, as recorded when the list was built, already allows writing.
    // This is the only "is it writable" test the plugin makes: page protection
    // is never changed by this plugin (1.2).
    bool regionAllowsWrite(const void* address, std::size_t bytes) const noexcept;

    // --- guarded primitives -------------------------------------------------
    static bool readFloat(const void* address, float& out) noexcept;
    static bool readDword(const void* address, std::uint32_t& out) noexcept;
    static bool readPointer(const void* address, std::uint64_t& out) noexcept;
    static bool writeFloat(void* address, float value) noexcept;

    // Copies a NUL-terminated string from memory the plugin does not own into
    // `dest`, at most capacity - 1 characters, always terminated. Returns the
    // number of characters copied; 0 on a fault or a null pointer.
    static std::size_t readCString(const char* source, char* dest,
                                   std::size_t capacity) noexcept;

    // --- address classification --------------------------------------------
    // isCommittedReadable makes a VirtualQuery call: resolver thread only.
    static bool isCommittedReadable(const void* address, std::size_t bytes) noexcept;
    static bool isInsideOwnModule(const void* address) noexcept;
    static bool isInsideMainModule(const void* address) noexcept;
    static bool isOnCurrentThreadStack(const void* address) noexcept;

    // Offset of `address` from the start of RDR2.exe's image, for log lines
    // (an RVA, never an absolute address). 0 if the address is not in the image.
    static std::uint64_t mainModuleOffset(const void* address) noexcept;

    // Arithmetic-only part of target validation: not inside the plugin's own
    // image, not on this thread's stack, float-aligned. Usable on any thread.
    static bool passesStaticChecks(const void* address) noexcept;

private:
    std::vector<MemoryRegion> m_regions;
    std::uint64_t             m_scannableBytes = 0;
};

} // namespace drs

// MemScan.h — raw memory primitives. Knows nothing about weapons or profiles.
//
// Everything here is read-only except writeFloat(), and every single access goes
// through a structured-exception guard: a page can be freed by another thread
// between VirtualQuery saying "committed" and us touching it, and that is not a
// reason to take the player's game down.
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
    std::uint8_t* base = nullptr;
    std::size_t   size = 0;
    std::uint32_t type = 0;    // MEM_PRIVATE or MEM_MAPPED
};

struct ScanRequest
{
    std::uint32_t value      = 0u;   // the 4-byte value to look for
    std::size_t   maxHits    = 64u;  // stop collecting after this many
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

    std::size_t   regionCount()  const noexcept { return m_regions.size(); }
    std::uint64_t scannableBytes() const noexcept { return m_scannableBytes; }

    // One pass over every region, looking for all requested values at once.
    // Doing this per value would mean one full pass per weapon, which on a
    // multi-gigabyte process is minutes instead of seconds.
    std::vector<ScanResult> findDwords(const std::vector<ScanRequest>& requests,
                                       std::uint64_t& bytesScannedOut) const;

    // Strategy B from DESIGN.md 3.2: find the literal name bytes, then find a
    // pointer to them. Only used if the hash search found nothing.
    std::vector<std::uint8_t*> findAscii(const char* text, std::size_t maxHits) const;
    std::vector<std::uint8_t*> findPointersTo(const std::uint8_t* target,
                                              std::size_t maxHits) const;

    // --- guarded primitives -------------------------------------------------
    static bool readFloat(const void* address, float& out) noexcept;
    static bool readDword(const void* address, std::uint32_t& out) noexcept;
    static bool readPointer(const void* address, std::uint64_t& out) noexcept;
    static bool writeFloat(void* address, float value) noexcept;

    // --- address classification --------------------------------------------
    static bool isCommittedReadable(const void* address, std::size_t bytes) noexcept;
    static bool isInsideOwnModule(const void* address) noexcept;
    static bool isInsideMainModule(const void* address) noexcept;
    static bool isOnCurrentThreadStack(const void* address) noexcept;

    // A target address is acceptable when it is committed and readable, is not
    // part of the plugin's own image, and is not on this thread's stack.
    // Note it is NOT required to be inside the main module: weapon structures are
    // built by the RAGE parser on the heap. See DESIGN.md 3.3 and SR-09.
    static bool isAcceptableTarget(const void* address, std::size_t bytes) noexcept;

    // True when the range is committed and its page is ALREADY writable. The RAGE
    // heap that holds CWeaponInfo is plain read-write memory, so in practice this
    // is always true and no protection change is needed (FR-37: protection is
    // changed only if the page is not writable).
    static bool isWritable(const void* address, std::size_t bytes) noexcept;

    // Readable span from `address` to the end of the scanned region that contains
    // it, capped at `cap`. Uses the region list built by buildRegionList(), so it
    // costs a binary search instead of one VirtualQuery system call per candidate
    // (the 1.0 log showed ~8 s spent in thousands of those calls after the scan).
    std::size_t spanFromRegions(const std::uint8_t* address, std::size_t cap) const noexcept;

private:
    std::vector<MemoryRegion> m_regions;
    std::uint64_t             m_scannableBytes = 0;
};

} // namespace drs

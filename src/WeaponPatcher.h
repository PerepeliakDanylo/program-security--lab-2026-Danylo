// WeaponPatcher.h — resolves weapon structures, snapshots them, writes the three
// reload fields, and puts everything back exactly as it was on the way out.
//
// Three invariants this class exists to enforce, and which nothing may relax:
//
//   1. The snapshot is taken once, after resolution, before the first write, and
//      is never refreshed. A "snapshot" read back after our own write is not a
//      snapshot, it is our own value, and restore would then restore nothing.
//   2. Before the first write to a field, the value currently there must equal
//      the snapshot. If it does not, either the offset is wrong or something else
//      writes there — either way that field is dropped for the session, loudly,
//      and the remaining ones keep working.
//   3. Exactly three fields are ever written. Not four. Adding one is an
//      architecture change and a policy change, not an implementation detail.
//
// No dependency on the ScriptHookRDR2 SDK.

#pragma once

#include "Config.h"
#include "MemScan.h"
#include "WeaponTable.h"

#include <cstdint>
#include <string>
#include <vector>

namespace drs {

struct FieldTarget
{
    std::uint8_t* address        = nullptr;
    float         snapshot       = 0.0f;
    bool          hasSnapshot    = false;
    bool          unpatchable    = false;
    bool          firstWriteDone = false;
    float         lastWritten    = 0.0f;
};

struct WeaponTarget
{
    std::string            name;
    std::uint32_t          hash        = 0u;
    const WeaponEntry*     config      = nullptr;
    const WeaponReference* reference   = nullptr;
    std::uint8_t*          nameAddress = nullptr;
    bool                   inMainModule = false;
    FieldTarget            anim;
};

struct ProfileTarget
{
    std::string               name;
    std::uint32_t             hash         = 0u;
    const ConditionReference* reference    = nullptr;
    std::uint8_t*             nameAddress  = nullptr;
    bool                      inMainModule = false;
    int                       conditions   = 1;   // 1 or kConditionCount
    FieldTarget               loop[kConditionCount];
    FieldTarget               time[kConditionCount];
};

struct DiscoveryResult
{
    bool          ok             = false;
    std::uint32_t offset         = 0u;
    int           score          = 0;
    int           signatureHits  = 0;
    std::uint32_t runnerUpOffset = 0u;
    int           runnerUpScore  = 0;
    const char*   signatureUsed  = "none";
};

class WeaponPatcher
{
public:
    // Scans memory, discovers offsets, takes the snapshot. Returns false if the
    // mod must go idle; failureReason() then says why in one line.
    bool initialise(const Config& config);

    void applyProfile(bool combat, const Config& config);
    void restoreAll();

    // MUST be called after Config::loadFromFile() re-reads the INI (the F9 path).
    //
    // WeaponTarget::config points INTO Config::m_weapons. loadFromFile() clears
    // and refills that vector, which invalidates every one of those pointers;
    // the next applyProfile() would then read freed memory and write values
    // derived from it into the game's address space. Re-reading the config is a
    // documented, user-triggered feature, so this is a live path, not a corner
    // case. It happens to survive while the vector's capacity does not change -
    // that is luck, not correctness, and it ends the moment the user adds a
    // weapon section, which the INI explicitly allows.
    //
    // Only the config pointers are refreshed. Addresses, snapshots and
    // first-write state are deliberately left alone: re-reading the config must
    // never change what "original" means (FR-57, invariant 1 above).
    void rebindConfig(const Config& config);

    bool ready() const noexcept { return m_ready; }
    int  resolvedWeapons() const noexcept;
    int  resolvedProfiles() const noexcept;
    const std::string& failureReason() const noexcept { return m_failure; }

    const DiscoveryResult& animDiscovery() const noexcept { return m_animDiscovery; }
    const DiscoveryResult& loopDiscovery() const noexcept { return m_loopDiscovery; }
    const DiscoveryResult& timeDiscovery() const noexcept { return m_timeDiscovery; }

private:
    struct Candidate
    {
        std::uint8_t* address      = nullptr;
        std::size_t   readableSpan = 0;
    };

    bool collectTargets(const Config& config);
    bool discoverAll(const Config& config);
    bool discoverConditionStride(const Config& config);
    void takeSnapshot();

    DiscoveryResult discoverOffset(const char* fieldName,
                                   const std::vector<std::vector<Candidate>>& candidates,
                                   const std::vector<float>& expected,
                                   const char* signatureName,
                                   const Config& config);

    void bindAddresses(const std::vector<std::vector<Candidate>>& candidates,
                       const std::vector<float>& expected,
                       std::uint32_t offset,
                       std::vector<std::uint8_t*>& chosenOut,
                       const Config& config);

    bool writeField(FieldTarget& field, float value, const char* what,
                    const Config& config);
    bool restoreField(FieldTarget& field, const char* what);

    static std::size_t readableSpanFrom(const std::uint8_t* address, std::size_t cap);

    MemScan                     m_scan;
    std::vector<WeaponTarget>   m_weapons;
    std::vector<ProfileTarget>  m_profiles;

    std::vector<std::vector<Candidate>> m_weaponCandidates;
    std::vector<std::vector<Candidate>> m_profileCandidates;

    DiscoveryResult m_animDiscovery;
    DiscoveryResult m_loopDiscovery;
    DiscoveryResult m_timeDiscovery;
    std::uint32_t   m_conditionStride = 0u;

    bool        m_ready = false;
    std::string m_failure;
};

} // namespace drs

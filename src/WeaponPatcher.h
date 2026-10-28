// WeaponPatcher.h — resolves weapon structures, snapshots them, writes the reload
// fields, and puts everything back exactly as it was on the way out.
//
// Invariants this class exists to enforce, and which nothing may relax:
//
//   1. The snapshot is taken once, after resolution, before the first write, and
//      is never refreshed. A "snapshot" read back after our own write is not a
//      snapshot, it is our own value, and restore would then restore nothing.
//   2. Before every write the value currently in the field must be either the
//      snapshot or the value this plugin wrote last. Anything else means another
//      writer (or a wrong address): that field is dropped for the session, loudly,
//      and the remaining ones keep working.
//   3. Exactly three fields are ever written (AnimReloadRate, and - only with
//      PatchSectionedReload = 1 - LoopRate and TimeBetweenBulletsInLoop). Adding
//      one is an architecture change and a policy change, not a detail.
//   4. (1.2) Nothing on the switching path makes a system call. Addresses are
//      validated once, at bind time, against the region list the scan built;
//      every write is then guarded by: the name hash still at its address, the
//      weapon-info class marker still next to it, the value continuity check of
//      invariant 2, an SEH-guarded write and a read-back. Page protection is never
//      changed: a target whose page is not already writable is not patched.
//
// How a structure is recognised (1.2, DESIGN.md 3.7). A weapon NAME hash occurs
// thousands of times in memory - every ped loadout, every inventory entry - and
// the real CWeaponInfo can sit behind all of them. 1.1 kept the first 64 hits per
// name and bound "the first candidate with a plausible value" when no exact value
// was known; the logs showed both failures (base Cattleman never bound, Navy and
// LeMat bound to different, wrong structures on different launches). 1.2 learns
// from the data which 8-byte value sits at a fixed distance from the name hash in
// every confirmed weapon structure - in practice the class's vtable pointer into
// RDR2.exe - and binds only objects that carry it. A second pass then enumerates
// every object of that class, which also covers guns that are not in WeaponTable.h.
//
// No dependency on the ScriptHookRDR2 SDK.

#pragma once

#include "Config.h"
#include "MemScan.h"
#include "WeaponTable.h"

#include <cstddef>
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

// How a weapon structure was tied to its name. Logged per weapon.
enum class BindKind : std::uint8_t
{
    None,
    ValueAndClass,   // weapon-info class marker present AND the value is the expected one
    ClassOnly,       // class marker present; no expected value known, or it differs
    ValueOnly        // no class marker could be learned; the value is the expected one
};

const char* bindKindName(BindKind kind);

struct WeaponTarget
{
    std::string            name;              // WEAPON_... (or the game label / 0xHASH for an unknown gun)
    std::uint32_t          hash         = 0u;
    const WeaponEntry*     config       = nullptr;
    const WeaponReference* reference    = nullptr;   // nullptr for a gun that is not in the table
    std::uint8_t*          nameAddress  = nullptr;
    bool                   inMainModule = false;
    bool                   unlisted     = false;     // found by the class scan, not in kWeaponReference
    BindKind               bind         = BindKind::None;
    int                    instance     = 0;         // 0 .. kMaxInstancesPerName - 1
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
    int           score          = 0;     // exact matches (minus contradictions in strict mode)
    int           signatureHits  = 0;     // names whose value at the offset is exactly the expected one
    int           contradicted   = 0;     // strict mode: names whose single object holds another value
    int           distinctValues = 0;     // different expected values among the exact matches
    std::uint32_t runnerUpOffset = 0u;
    int           runnerUpScore  = 0;
    const char*   signatureUsed  = "none";
};

// A weapon-info object found by the class scan whose name hash is not in the
// table. Its snapshot is taken on the resolver thread; whether it is a gun is
// asked on the script thread (natives), see Script::adoptUnlistedGuns.
struct UnlistedObject
{
    std::uint32_t hash        = 0u;
    std::uint8_t* nameAddress = nullptr;
    FieldTarget   anim;
};

// What the script thread hands back for one unlisted hash that IS a gun.
struct UnlistedGun
{
    std::uint32_t hash         = 0u;
    std::string   name;              // WEAPON_... derived from the game label, else the label, else 0xHASH
    std::string   label;             // the game's text label, may be empty
    bool          nameVerified = false;   // joaat(name) == hash
};

// For the overlay and the log: what the plugin does with one weapon hash.
struct HeldWeaponStatus
{
    bool        known     = false;   // the plugin has heard of this name at all
    bool        managed   = false;   // at least one patchable structure is bound
    int         instances = 0;
    float       value     = 0.0f;    // what is in the field now (last written, else the snapshot)
    std::string name;
};

class WeaponPatcher
{
public:
    static constexpr int kMaxInstancesPerName = 4;

    // Resolver thread. Scans memory, recognises the structures, takes the
    // snapshot. Returns false if the mod must go idle; failureReason() says why.
    bool initialise(const Config& config);

    // Script thread, once, right after initialise() returned true.
    std::vector<std::uint32_t> unlistedHashes() const;
    int  adoptUnlisted(const std::vector<UnlistedGun>& guns, const Config& config);
    void releaseUnlisted();

    // One info line per weapon name: snapshot and the CALM / COMBAT values the
    // current config produces. Called at start and after F9.
    void logPlan(const Config& config) const;

    void applyProfile(bool combat, const Config& config);
    void restoreAll();

    // MUST be called after Config::loadFromFile() re-reads the INI (the F9 path).
    //
    // WeaponTarget::config points INTO Config::m_weapons. loadFromFile() clears
    // and refills that vector, which invalidates every one of those pointers;
    // the next applyProfile() would then read freed memory and write values
    // derived from it into the game's address space. Only the config pointers are
    // refreshed. Addresses, snapshots and first-write state are deliberately left
    // alone: re-reading the config must never change what "original" means (FR-57).
    void rebindConfig(const Config& config);

    HeldWeaponStatus describe(std::uint32_t hash) const;

    bool ready() const noexcept { return m_ready; }
    int  resolvedWeapons() const noexcept;     // bound, patchable structures
    int  resolvedNames() const noexcept;       // distinct names among them
    int  resolvedProfiles() const noexcept;
    const std::string& failureReason() const noexcept { return m_failure; }

    const DiscoveryResult& animDiscovery() const noexcept { return m_animDiscovery; }
    const DiscoveryResult& loopDiscovery() const noexcept { return m_loopDiscovery; }
    const DiscoveryResult& timeDiscovery() const noexcept { return m_timeDiscovery; }
    bool classKnown() const noexcept { return m_classKnown; }

private:
    struct Candidate
    {
        std::uint8_t* address      = nullptr;
        std::size_t   readableSpan = 0;
    };

    struct NamedWeapon
    {
        std::string            name;
        std::uint32_t          hash      = 0u;
        const WeaponReference* reference = nullptr;
        const WeaponEntry*     config    = nullptr;
    };

    struct ClassHypothesis
    {
        std::int32_t  delta           = 0;    // class qword address minus name hash address
        std::uint64_t value           = 0u;
        int           names           = 0;    // names with at least one candidate carrying it
        int           definitionNames = 0;    // names with 1..kMaxInstancesPerName such candidates
    };

    enum class WriteOutcome { Written, Unchanged, Skipped, Dropped };

    void resetState();
    bool collectNames(const Config& config);
    bool resolve(const Config& config);
    std::vector<ClassHypothesis> learnClassHypotheses(int minNames) const;
    std::vector<std::vector<Candidate>> filterByClass(std::int32_t delta, std::uint64_t value,
                                                      std::size_t cap) const;
    bool chooseClassAndOffset(const Config& config,
                              const std::vector<float>& vanillaAnim,
                              const std::vector<float>& calmAnim,
                              bool& matchedCalmOut);
    void bindWeapons(const Config& config, const std::vector<float>& expected);
    void classScan();
    void resolveSectioned(const Config& config);
    bool discoverConditionStride(const Config& config);
    void takeSnapshot();

    // strict = the candidates were filtered by the class marker, so each name has
    // (about) one object and a non-matching value there counts AGAINST an offset.
    DiscoveryResult discoverOffset(const char* fieldName,
                                   const std::vector<std::vector<Candidate>>& candidates,
                                   const std::vector<float>& expected,
                                   const char* signatureName,
                                   const Config& config,
                                   std::size_t maxPerName,
                                   bool strict,
                                   bool logResult) const;

    int exactHitsAt(const std::vector<std::vector<Candidate>>& candidates,
                    const std::vector<float>& expected,
                    std::uint32_t offset,
                    float epsilon) const;

    bool  ownerStillThere(const WeaponTarget& target) const;
    static bool hashStillThere(const std::uint8_t* nameAddress, std::uint32_t hash);

    bool  snapshotIsStock(const WeaponTarget& target, const Config& config) const;
    float decideAnim(const WeaponTarget& target, bool combat, const Config& config,
                     const char*& why) const;

    WriteOutcome writeField(FieldTarget& field, float value, const char* what,
                            const Config& config);
    bool restoreField(FieldTarget& field, const char* what);

    MemScan                     m_scan;
    std::vector<NamedWeapon>    m_names;
    std::vector<WeaponTarget>   m_weapons;
    std::vector<ProfileTarget>  m_profiles;
    std::vector<UnlistedObject> m_unlisted;

    // Table names that are in memory but could not be bound, for describe().
    std::vector<std::uint32_t>  m_unboundHashes;

    std::vector<std::vector<Candidate>> m_candidates;          // per m_names entry
    std::vector<std::vector<Candidate>> m_profileCandidates;   // per m_profiles entry

    DiscoveryResult m_animDiscovery;
    DiscoveryResult m_loopDiscovery;
    DiscoveryResult m_timeDiscovery;
    std::uint32_t   m_conditionStride = 0u;

    bool          m_classKnown = false;
    std::int32_t  m_classDelta = 0;
    std::uint64_t m_classValue = 0u;

    bool        m_ready = false;
    std::string m_failure;
};

} // namespace drs

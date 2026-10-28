#include "WeaponPatcher.h"
#include "Joaat.h"
#include "Logger.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace drs {

namespace {

constexpr float kLiveValueMin = 0.001f;   // FR-35: what may legitimately be in a field
constexpr float kLiveValueMax = 100.0f;

// What a gun's AnimReloadRate can be. Keeps foreign values (8.0 and 3.0094 in the
// 1.1 logs) out of class-only bindings and out of unlisted guns.
constexpr float kRateMin = 0.05f;
constexpr float kRateMax = 5.0f;

// Hits kept per weapon name by the first scan. A common weapon's hash occurs in
// thousands of places (ped loadouts, inventories, pickups) and the real
// CWeaponInfo may sit behind all of them: 1.1 kept 64 and lost the base
// Cattleman that way on both logged launches.
constexpr std::size_t  kMaxHitsPerName           = 4096u;
constexpr std::size_t  kMaxHitsPerProfile        = 1024u;
// Candidates per name used to SEARCH for the field offset without a class marker
// (fallback path only). Binding always looks at every candidate.
constexpr std::size_t  kDiscoveryCandidates      = 256u;
// Class-filtered candidates per name used to verify a class hypothesis.
constexpr std::size_t  kClassDiscoveryCandidates = 8u;
// Where the class marker may sit relative to the name hash, in bytes. The name
// is a member near the start of the object; the vtable pointer is at its start.
constexpr std::int32_t kClassDeltaMin            = -0x100;
constexpr std::int32_t kClassDeltaMax            = 0x10;
// Every structure type that keeps a weapon hash next to a pointer into RDR2.exe
// becomes a hypothesis; only the weapon-info class also holds the reload field,
// which the verification step proves. 12 leaves room for catalog-like tables
// that rank above it (one entry per weapon, too) - each costs ~1 M reads.
constexpr std::size_t  kMaxClassHypotheses       = 12u;
constexpr std::size_t  kMaxClassObjects          = 16384u;
constexpr std::size_t  kMaxUnlistedObjects       = 4096u;
constexpr int          kMaxUnlistedAdopted       = 256;

std::string toLowerCopy(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string hashLabel(std::uint32_t hash)
{
    char buffer[16] = {};
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "0x%08X", hash);
    return std::string(buffer);
}

bool closeEnough(float a, float b, float epsilon)
{
    return std::fabs(a - b) <= epsilon;
}

// Stock AnimReloadRate takes exactly two values in the game's data.
bool isStockRate(float value, float epsilon)
{
    return closeEnough(value, 1.0f, epsilon) || closeEnough(value, 1.3f, epsilon);
}

bool isSaneRate(float value)
{
    return std::isfinite(value) && value >= kRateMin && value <= kRateMax;
}

double millisecondsSince(std::chrono::steady_clock::time_point start)
{
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
}

// The class marker is the first member of an object the engine allocates with at
// least 16-byte alignment, so it is always 8-byte aligned. Reads anywhere else
// are refused instead of being compared.
bool readClassQword(const std::uint8_t* nameAddress, std::int32_t delta, std::uint64_t& out)
{
    if (nameAddress == nullptr)
    {
        return false;
    }
    const std::uint8_t* at = nameAddress + delta;
    if ((reinterpret_cast<std::uintptr_t>(at) & 7u) != 0u)
    {
        return false;
    }
    return MemScan::readPointer(at, out);
}

// "-0x10" / "+0x08", for log lines.
void formatDelta(std::int32_t delta, char* buffer, std::size_t size)
{
    const unsigned magnitude = static_cast<unsigned>(delta < 0 ? -delta : delta);
    _snprintf_s(buffer, size, _TRUNCATE, "%s0x%X", delta < 0 ? "-" : "+", magnitude);
}

} // namespace

const char* bindKindName(BindKind kind)
{
    switch (kind)
    {
    case BindKind::None:          return "unbound";
    case BindKind::ValueAndClass: return "value+class";
    case BindKind::ClassOnly:     return "class";
    case BindKind::ValueOnly:     return "value only";
    }
    return "?";
}

// ---------------------------------------------------------------------------

int WeaponPatcher::resolvedWeapons() const noexcept
{
    int count = 0;
    for (const WeaponTarget& target : m_weapons)
    {
        if (target.anim.address != nullptr && !target.anim.unpatchable && target.anim.hasSnapshot)
        {
            ++count;
        }
    }
    return count;
}

int WeaponPatcher::resolvedNames() const noexcept
{
    int count = 0;
    for (std::size_t i = 0; i < m_weapons.size(); ++i)
    {
        const WeaponTarget& target = m_weapons[i];
        if (target.anim.address == nullptr || target.anim.unpatchable || !target.anim.hasSnapshot)
        {
            continue;
        }
        bool seenBefore = false;
        for (std::size_t k = 0; k < i && !seenBefore; ++k)
        {
            const WeaponTarget& earlier = m_weapons[k];
            seenBefore = (earlier.hash == target.hash) && earlier.anim.address != nullptr &&
                         !earlier.anim.unpatchable && earlier.anim.hasSnapshot;
        }
        if (!seenBefore)
        {
            ++count;
        }
    }
    return count;
}

int WeaponPatcher::resolvedProfiles() const noexcept
{
    int count = 0;
    for (const ProfileTarget& target : m_profiles)
    {
        if (target.loop[0].address != nullptr && !target.loop[0].unpatchable)
        {
            ++count;
        }
    }
    return count;
}

// ---------------------------------------------------------------------------

bool WeaponPatcher::hashStillThere(const std::uint8_t* nameAddress, std::uint32_t hash)
{
    std::uint32_t current = 0u;
    return nameAddress != nullptr && MemScan::readDword(nameAddress, current) &&
           current == hash;
}

// A bound structure is only written while it is still the object it was bound
// to: the name hash where it was found AND (when the class was recognised) the
// class marker next to it. If the game freed or reused the object, one of the two
// reads differs and the target is dropped instead of writing into unrelated data.
// Two guarded reads, no system call.
bool WeaponPatcher::ownerStillThere(const WeaponTarget& target) const
{
    if (!hashStillThere(target.nameAddress, target.hash))
    {
        return false;
    }
    if (m_classKnown && target.bind != BindKind::ValueOnly)
    {
        std::uint64_t marker = 0u;
        return readClassQword(target.nameAddress, m_classDelta, marker) && marker == m_classValue;
    }
    return true;
}

// ---------------------------------------------------------------------------

void WeaponPatcher::rebindConfig(const Config& config)
{
    // See the comment on the declaration. Deliberately does NOT touch addresses,
    // snapshots or firstWriteDone - only the pointers into Config::m_weapons,
    // which loadFromFile() has just invalidated.
    int rebound = 0;
    int dropped = 0;
    for (WeaponTarget& target : m_weapons)
    {
        const WeaponEntry* const entry = config.matchWeapon(target.name);
        if (entry == nullptr && target.config != nullptr)
        {
            ++dropped;
        }
        else if (entry != nullptr)
        {
            ++rebound;
        }
        target.config = entry;
    }

    DRS_INFO("config rebind: %d weapon structure(s) re-bound, %d lost their section",
             rebound, dropped);
}

// ---------------------------------------------------------------------------

void WeaponPatcher::resetState()
{
    m_names.clear();
    m_weapons.clear();
    m_profiles.clear();
    m_unlisted.clear();
    m_unboundHashes.clear();
    m_candidates.clear();
    m_profileCandidates.clear();
    m_animDiscovery   = DiscoveryResult();
    m_loopDiscovery   = DiscoveryResult();
    m_timeDiscovery   = DiscoveryResult();
    m_conditionStride = 0u;
    m_classKnown      = false;
    m_classDelta      = 0;
    m_classValue      = 0u;
}

bool WeaponPatcher::collectNames(const Config& config)
{
    m_names.clear();
    m_profiles.clear();

    const bool sectioned = config.memory().patchSectionedReload;

    for (const WeaponReference& row : kWeaponReference)
    {
        NamedWeapon named;
        named.name      = row.weaponName;
        named.hash      = joaat(toLowerCopy(named.name).c_str());
        named.reference = &row;
        named.config    = config.matchWeapon(named.name);
        m_names.push_back(named);

        if (!sectioned)
        {
            continue;
        }

        const std::uint32_t profileHash =
            (row.profileHash != 0u)
                ? row.profileHash
                : (row.profileName != nullptr ? joaat(row.profileName) : 0u);
        if (profileHash == 0u)
        {
            continue;
        }
        const bool alreadyKnown = std::any_of(
            m_profiles.begin(), m_profiles.end(),
            [profileHash](const ProfileTarget& p) { return p.hash == profileHash; });
        if (alreadyKnown)
        {
            continue;
        }

        ProfileTarget profile;
        profile.hash      = profileHash;
        profile.name      = (row.profileName != nullptr) ? row.profileName
                                                         : hashLabel(profileHash);
        profile.reference = findConditionReference(row.profileName, row.profileHash);
        m_profiles.push_back(profile);
    }

    DRS_INFO("resolver: %zu weapon names, %zu sectioned profiles to look for%s",
             m_names.size(), m_profiles.size(),
             sectioned ? "" : " (PatchSectionedReload = 0: AnimReloadRate only)");
    return !m_names.empty();
}

// ---------------------------------------------------------------------------

// Offset search (rewritten in 1.2).
//
// An offset is a CANDIDATE only if
//   (A) at least MinConsensusWeapons names show exactly their expected value there,
//   (B) those exact matches cover at least min(3, available) DIFFERENT expected
//       values - for the stock set that means both 1.00 and 1.30. This is what
//       rejects a field that holds a constant 1.0 in every weapon: on a stock
//       weapons.ymt such a field matches all 44 "1.00" guns and none of the "1.30"
//       ones, and with the 1.1 margin rule it tied with the real field (the 1.1
//       log shows two of them, 0x032C and 0x0330, at 44 exact matches each);
//   (C) strict mode only: it is contradicted (another value in the one object of
//       a name) less often than it is confirmed.
// Among candidates the highest score wins - exact matches, minus contradictions
// in strict mode - and it must clearly beat the second candidate: by 10 % in
// strict mode (the objects are known to be the right class), by ConsensusMargin
// otherwise.
DiscoveryResult WeaponPatcher::discoverOffset(const char* fieldName,
                                              const std::vector<std::vector<Candidate>>& candidates,
                                              const std::vector<float>& expected,
                                              const char* signatureName,
                                              const Config& config,
                                              std::size_t maxPerName,
                                              bool strict,
                                              bool logResult) const
{
    DiscoveryResult best;
    best.signatureUsed = signatureName;

    const MemorySettings&   memory   = config.memory();
    const DefaultsSettings& defaults = config.defaults();
    const float             epsilon  = defaults.vanillaEpsilon;

    const std::uint32_t step   = (memory.offsetStep == 0u) ? 4u : memory.offsetStep;
    const std::uint32_t window = memory.maxOffsetWindow;

    auto valueKey = [](float value) { return static_cast<int>(std::lround(value * 100.0f)); };

    // How many different expected values the names that are present can show.
    std::vector<int> keys;
    keys.reserve(candidates.size());
    for (std::size_t i = 0; i < candidates.size(); ++i)
    {
        const float want = (i < expected.size()) ? expected[i] : 0.0f;
        if (want > 0.0f && !candidates[i].empty())
        {
            keys.push_back(valueKey(want));
        }
    }
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    const int requiredDistinct = std::min(3, static_cast<int>(keys.size()));
    const int required         = memory.minConsensusWeapons;

    bool          haveBest     = false;
    bool          haveSecond   = false;
    int           bestScore    = 0;
    int           bestExact    = 0;
    int           bestContra   = 0;
    int           bestDistinct = 0;
    std::uint32_t bestOffset   = 0u;
    int           secondScore  = 0;
    std::uint32_t secondOffset = 0u;
    int           mostExact    = 0;   // for the log when nothing qualifies

    std::vector<int> matchedKeys;
    matchedKeys.reserve(candidates.size());

    for (std::uint32_t offset = 0u; offset + 4u <= window; offset += step)
    {
        int exact        = 0;
        int contradicted = 0;
        matchedKeys.clear();

        for (std::size_t i = 0; i < candidates.size(); ++i)
        {
            const float want = (i < expected.size()) ? expected[i] : 0.0f;
            if (want <= 0.0f)
            {
                continue;
            }
            bool        sawExact = false;
            bool        sawValue = false;
            std::size_t used     = 0;
            for (const Candidate& candidate : candidates[i])
            {
                if (maxPerName != 0u && used >= maxPerName)
                {
                    break;
                }
                ++used;
                if (candidate.readableSpan < static_cast<std::size_t>(offset) + 4u)
                {
                    continue;   // not readable this far; no contribution, no penalty
                }
                float value = 0.0f;
                if (!MemScan::readFloat(candidate.address + offset, value))
                {
                    continue;
                }
                sawValue = true;
                if (std::isfinite(value) && closeEnough(value, want, epsilon))
                {
                    sawExact = true;
                    break;
                }
            }
            if (sawExact)
            {
                ++exact;
                matchedKeys.push_back(valueKey(want));
            }
            else if (sawValue)
            {
                ++contradicted;
            }
        }

        if (exact > mostExact)
        {
            mostExact = exact;
        }
        if (exact < required)
        {
            continue;   // (A)
        }
        std::sort(matchedKeys.begin(), matchedKeys.end());
        const int distinct = static_cast<int>(
            std::unique(matchedKeys.begin(), matchedKeys.end()) - matchedKeys.begin());
        if (distinct < requiredDistinct)
        {
            continue;   // (B)
        }
        if (strict && contradicted >= exact)
        {
            continue;   // (C)
        }

        const int score = strict ? (exact - contradicted) : exact;
        if (!haveBest || score > bestScore)
        {
            if (haveBest)
            {
                haveSecond   = true;
                secondScore  = bestScore;
                secondOffset = bestOffset;
            }
            haveBest     = true;
            bestScore    = score;
            bestExact    = exact;
            bestContra   = contradicted;
            bestDistinct = distinct;
            bestOffset   = offset;
        }
        else if (!haveSecond || score > secondScore)
        {
            haveSecond   = true;
            secondScore  = score;
            secondOffset = offset;
        }
    }

    best.offset         = bestOffset;
    best.score          = bestScore;
    best.signatureHits  = bestExact;
    best.contradicted   = bestContra;
    best.distinctValues = bestDistinct;
    best.runnerUpOffset = secondOffset;
    best.runnerUpScore  = haveSecond ? secondScore : 0;

    bool clearWinner = true;
    if (haveSecond)
    {
        clearWinner = strict
            ? (secondScore * 10 < bestScore * 9)
            : (static_cast<float>(bestScore) >=
               memory.consensusMargin * static_cast<float>(secondScore));
    }
    best.ok = haveBest && clearWinner;

    if (logResult)
    {
        DRS_INFO("resolver: %s signature=%s%s best offset=0x%04X exact=%d contradicted=%d "
                 "distinct=%d/%d runner-up offset=0x%04X score=%d -> %s",
                 fieldName, signatureName, strict ? " (class objects)" : "",
                 bestOffset, bestExact, bestContra, bestDistinct, requiredDistinct,
                 secondOffset, best.runnerUpScore, best.ok ? "accepted" : "REJECTED");
        if (!haveBest)
        {
            DRS_INFO("resolver: %s: no offset reaches %d exact %s matches over %d different "
                     "values (best was %d exact)", fieldName, required, signatureName,
                     requiredDistinct, mostExact);
        }
        else if (!clearWinner)
        {
            DRS_INFO("resolver: %s rejected because a second offset fits almost as well",
                     fieldName);
        }
    }
    else
    {
        DRS_DEBUG("resolver: %s signature=%s%s best offset=0x%04X exact=%d contradicted=%d "
                  "distinct=%d runner-up offset=0x%04X score=%d -> %s",
                  fieldName, signatureName, strict ? " (class objects)" : "",
                  bestOffset, bestExact, bestContra, bestDistinct,
                  secondOffset, best.runnerUpScore, best.ok ? "accepted" : "rejected");
    }

    return best;
}

int WeaponPatcher::exactHitsAt(const std::vector<std::vector<Candidate>>& candidates,
                               const std::vector<float>& expected,
                               std::uint32_t offset,
                               float epsilon) const
{
    int hits = 0;
    for (std::size_t i = 0; i < candidates.size(); ++i)
    {
        const float want = (i < expected.size()) ? expected[i] : 0.0f;
        if (want <= 0.0f)
        {
            continue;
        }
        for (const Candidate& candidate : candidates[i])
        {
            if (candidate.readableSpan < static_cast<std::size_t>(offset) + 4u)
            {
                continue;
            }
            float value = 0.0f;
            if (MemScan::readFloat(candidate.address + offset, value) &&
                closeEnough(value, want, epsilon))
            {
                ++hits;
                break;
            }
        }
    }
    return hits;
}

// ---------------------------------------------------------------------------
// Class learning (1.2).
//
// For every candidate of every name, read each 8-byte aligned qword within
// [kClassDeltaMin, kClassDeltaMax] of the name hash and keep those that point
// into RDR2.exe - a vtable, or a pointer to static data. Every CWeaponInfo has
// its vtable at the same distance from its name, so one (distance, value) pair
// shows up for (almost) every name with exactly one object each. Structures that
// merely MENTION a weapon (inventories, loadouts) have their own class pairs, but
// many objects per name, which is how they are told apart ("definition" score).
// The best few pairs are then verified by searching the reload field among the
// objects that carry them.
// ---------------------------------------------------------------------------

std::vector<WeaponPatcher::ClassHypothesis> WeaponPatcher::learnClassHypotheses(int minNames) const
{
    struct Vote
    {
        std::int32_t  delta;
        std::uint64_t value;
        std::uint32_t name;
        std::uint32_t count;
    };
    auto byKey = [](const Vote& a, const Vote& b) {
        if (a.delta != b.delta)
        {
            return a.delta < b.delta;
        }
        return a.value < b.value;
    };
    auto sameKey = [](const Vote& a, const Vote& b) {
        return a.delta == b.delta && a.value == b.value;
    };

    std::vector<Vote> votes;
    std::vector<Vote> local;

    for (std::size_t n = 0; n < m_candidates.size(); ++n)
    {
        local.clear();
        for (const Candidate& candidate : m_candidates[n])
        {
            for (std::int32_t delta = kClassDeltaMin; delta <= kClassDeltaMax; delta += 4)
            {
                if (delta >= 0 && candidate.readableSpan < static_cast<std::size_t>(delta) + 8u)
                {
                    continue;
                }
                std::uint64_t qword = 0u;
                if (!readClassQword(candidate.address, delta, qword) || qword == 0u)
                {
                    continue;
                }
                if (!MemScan::isInsideMainModule(reinterpret_cast<const void*>(qword)))
                {
                    continue;
                }
                local.push_back(Vote{ delta, qword, static_cast<std::uint32_t>(n), 1u });
            }
        }
        if (local.empty())
        {
            continue;
        }

        // One vote per (distance, value) per name, carrying how many objects of
        // this name had it.
        std::sort(local.begin(), local.end(), byKey);
        std::size_t first = 0;
        while (first < local.size())
        {
            std::size_t last = first + 1;
            while (last < local.size() && sameKey(local[last], local[first]))
            {
                ++last;
            }
            Vote merged  = local[first];
            merged.count = static_cast<std::uint32_t>(last - first);
            votes.push_back(merged);
            first = last;
        }
    }

    std::sort(votes.begin(), votes.end(), byKey);

    std::vector<ClassHypothesis> hypotheses;
    std::size_t first = 0;
    while (first < votes.size())
    {
        std::size_t last = first + 1;
        while (last < votes.size() && sameKey(votes[last], votes[first]))
        {
            ++last;
        }
        ClassHypothesis hypothesis;
        hypothesis.delta = votes[first].delta;
        hypothesis.value = votes[first].value;
        hypothesis.names = static_cast<int>(last - first);
        for (std::size_t k = first; k < last; ++k)
        {
            if (votes[k].count <= static_cast<std::uint32_t>(kMaxInstancesPerName))
            {
                ++hypothesis.definitionNames;
            }
        }
        if (hypothesis.names >= minNames)
        {
            hypotheses.push_back(hypothesis);
        }
        first = last;
    }

    std::sort(hypotheses.begin(), hypotheses.end(),
              [](const ClassHypothesis& a, const ClassHypothesis& b) {
                  if (a.definitionNames != b.definitionNames)
                  {
                      return a.definitionNames > b.definitionNames;
                  }
                  if (a.names != b.names)
                  {
                      return a.names > b.names;
                  }
                  const std::int32_t da = a.delta < 0 ? -a.delta : a.delta;
                  const std::int32_t db = b.delta < 0 ? -b.delta : b.delta;
                  return da < db;
              });
    if (hypotheses.size() > kMaxClassHypotheses)
    {
        hypotheses.erase(hypotheses.begin() + static_cast<std::ptrdiff_t>(kMaxClassHypotheses),
                         hypotheses.end());
    }
    return hypotheses;
}

std::vector<std::vector<WeaponPatcher::Candidate>>
WeaponPatcher::filterByClass(std::int32_t delta, std::uint64_t value, std::size_t cap) const
{
    std::vector<std::vector<Candidate>> filtered(m_candidates.size());
    for (std::size_t n = 0; n < m_candidates.size(); ++n)
    {
        for (const Candidate& candidate : m_candidates[n])
        {
            if (cap != 0u && filtered[n].size() >= cap)
            {
                break;
            }
            if (delta >= 0 && candidate.readableSpan < static_cast<std::size_t>(delta) + 8u)
            {
                continue;
            }
            std::uint64_t qword = 0u;
            if (readClassQword(candidate.address, delta, qword) && qword == value)
            {
                filtered[n].push_back(candidate);
            }
        }
    }
    return filtered;
}

bool WeaponPatcher::chooseClassAndOffset(const Config& config,
                                         const std::vector<float>& vanillaAnim,
                                         const std::vector<float>& calmAnim,
                                         bool& matchedCalmOut)
{
    const MemorySettings& memory  = config.memory();
    const float           epsilon = config.defaults().vanillaEpsilon;

    const int minNames = std::max(8, memory.minConsensusWeapons);
    const std::vector<ClassHypothesis> hypotheses = learnClassHypotheses(minNames);

    char deltaText[16] = {};
    for (std::size_t h = 0; h < hypotheses.size(); ++h)
    {
        const ClassHypothesis& hypothesis = hypotheses[h];
        formatDelta(hypothesis.delta, deltaText, sizeof(deltaText));
        DRS_INFO("resolver: class candidate %zu: qword at name%s = RDR2.exe+0x%llX, on %d names "
                 "(%d of them with 1-%d objects)",
                 h + 1, deltaText,
                 static_cast<unsigned long long>(MemScan::mainModuleOffset(
                     reinterpret_cast<const void*>(hypothesis.value))),
                 hypothesis.names, hypothesis.definitionNames, kMaxInstancesPerName);
    }
    if (hypotheses.empty())
    {
        DRS_INFO("resolver: no class candidate is shared by %d or more weapon names", minNames);
    }

    // --- pinned offset ------------------------------------------------------
    if (memory.forceAnimOffset >= 0)
    {
        const std::uint32_t offset = static_cast<std::uint32_t>(memory.forceAnimOffset);

        int         bestHits  = 0;
        std::size_t bestIndex = hypotheses.size();
        bool        bestCalm  = false;
        for (std::size_t h = 0; h < hypotheses.size(); ++h)
        {
            const std::vector<std::vector<Candidate>> filtered =
                filterByClass(hypotheses[h].delta, hypotheses[h].value, kClassDiscoveryCandidates);
            const int stockHits = exactHitsAt(filtered, vanillaAnim, offset, epsilon);
            const int calmHits  = exactHitsAt(filtered, calmAnim, offset, epsilon);
            const int hits      = std::max(stockHits, calmHits);
            if (hits > bestHits)
            {
                bestHits  = hits;
                bestIndex = h;
                bestCalm  = (calmHits >= stockHits);
            }
        }

        m_animDiscovery               = DiscoveryResult();
        m_animDiscovery.ok            = true;
        m_animDiscovery.offset        = offset;
        m_animDiscovery.signatureUsed = "forced by config";

        if (bestIndex < hypotheses.size() &&
            bestHits >= std::max(3, memory.minConsensusWeapons / 2))
        {
            m_classKnown                  = true;
            m_classDelta                  = hypotheses[bestIndex].delta;
            m_classValue                  = hypotheses[bestIndex].value;
            m_animDiscovery.signatureHits = bestHits;
            matchedCalmOut                = bestCalm;
        }
        else
        {
            const int stockHits = exactHitsAt(m_candidates, vanillaAnim, offset, epsilon);
            const int calmHits  = exactHitsAt(m_candidates, calmAnim, offset, epsilon);
            m_animDiscovery.signatureHits = std::max(stockHits, calmHits);
            matchedCalmOut                = (calmHits > stockHits);
        }

        DRS_INFO("resolver: AnimReloadRate offset pinned to 0x%04X by [Memory] (%d exact "
                 "matches, bound against %s values, weapon-info class %s)",
                 offset, m_animDiscovery.signatureHits, matchedCalmOut ? "calm" : "stock",
                 m_classKnown ? "recognised" : "NOT recognised - exact values only");
        return true;
    }

    // --- automatic: verify each class candidate by finding the field --------
    std::size_t     bestIndex  = hypotheses.size();
    int             bestSig    = -1;
    bool            bestCalm   = false;
    DiscoveryResult bestResult;

    for (std::size_t h = 0; h < hypotheses.size(); ++h)
    {
        const std::vector<std::vector<Candidate>> filtered =
            filterByClass(hypotheses[h].delta, hypotheses[h].value, kClassDiscoveryCandidates);

        const DiscoveryResult stockPass = discoverOffset("AnimReloadRate", filtered, vanillaAnim,
                                                         "stock", config,
                                                         kClassDiscoveryCandidates, true, false);
        const DiscoveryResult calmPass  = discoverOffset("AnimReloadRate", filtered, calmAnim,
                                                         "calm profile", config,
                                                         kClassDiscoveryCandidates, true, false);

        bool            useCalm = false;
        DiscoveryResult picked;
        if (stockPass.ok && calmPass.ok)
        {
            // A tie goes to calm: its values are high-entropy, so an equal count
            // is stronger evidence for it than for the 1.00 / 1.30 stock set.
            useCalm = (calmPass.signatureHits >= stockPass.signatureHits);
            picked  = useCalm ? calmPass : stockPass;
        }
        else if (calmPass.ok)
        {
            useCalm = true;
            picked  = calmPass;
        }
        else if (stockPass.ok)
        {
            picked = stockPass;
        }

        DRS_INFO("resolver: class candidate %zu: AnimReloadRate stock ok=%d sig=%d off=0x%04X | "
                 "calm ok=%d sig=%d off=0x%04X",
                 h + 1, stockPass.ok ? 1 : 0, stockPass.signatureHits, stockPass.offset,
                 calmPass.ok ? 1 : 0, calmPass.signatureHits, calmPass.offset);

        if (picked.ok && picked.signatureHits > bestSig)
        {
            bestSig    = picked.signatureHits;
            bestIndex  = h;
            bestCalm   = useCalm;
            bestResult = picked;
        }
    }

    if (bestIndex < hypotheses.size())
    {
        m_classKnown    = true;
        m_classDelta    = hypotheses[bestIndex].delta;
        m_classValue    = hypotheses[bestIndex].value;
        m_animDiscovery = bestResult;
        matchedCalmOut  = bestCalm;

        // The winning search once more, with its full line in the log.
        {
            const std::vector<std::vector<Candidate>> filtered =
                filterByClass(m_classDelta, m_classValue, kClassDiscoveryCandidates);
            discoverOffset("AnimReloadRate", filtered, bestCalm ? calmAnim : vanillaAnim,
                           bestCalm ? "calm profile" : "stock", config,
                           kClassDiscoveryCandidates, true, true);
        }

        formatDelta(m_classDelta, deltaText, sizeof(deltaText));
        DRS_INFO("resolver: weapon-info class recognised: qword at name%s = RDR2.exe+0x%llX on "
                 "%d names; AnimReloadRate at name+0x%04X, %d exact %s values "
                 "(runner-up offset 0x%04X score %d vs %d)",
                 deltaText,
                 static_cast<unsigned long long>(MemScan::mainModuleOffset(
                     reinterpret_cast<const void*>(m_classValue))),
                 hypotheses[bestIndex].names, m_animDiscovery.offset,
                 m_animDiscovery.signatureHits, bestCalm ? "calm" : "stock",
                 m_animDiscovery.runnerUpOffset, m_animDiscovery.runnerUpScore,
                 m_animDiscovery.score);
        return true;
    }

    // --- fallback: no class could be confirmed ------------------------------
    // The 1.1 search over the raw candidates, but binding stays EXACT-ONLY: a
    // structure is patched only where its value is the one this weapon is known
    // to have. Nothing is bound "by plausibility" any more.
    DRS_INFO("resolver: no weapon-info class could be confirmed; falling back to the "
             "value-only search (exact matches only, nothing is bound by guess)");

    const DiscoveryResult stockPass = discoverOffset("AnimReloadRate", m_candidates, vanillaAnim,
                                                     "stock", config, kDiscoveryCandidates,
                                                     false, true);
    const DiscoveryResult calmPass  = discoverOffset("AnimReloadRate", m_candidates, calmAnim,
                                                     "calm profile", config, kDiscoveryCandidates,
                                                     false, true);
    bool useCalm = false;
    if (stockPass.ok && calmPass.ok)
    {
        useCalm = (calmPass.signatureHits >= stockPass.signatureHits);
    }
    else if (calmPass.ok)
    {
        useCalm = true;
    }
    else if (!stockPass.ok)
    {
        useCalm = (calmPass.signatureHits > stockPass.signatureHits);
    }
    m_animDiscovery = useCalm ? calmPass : stockPass;
    matchedCalmOut  = useCalm;

    DRS_INFO("resolver: AnimReloadRate chose the %s pass "
             "(stock: ok=%d sig=%d off=0x%04X | calm: ok=%d sig=%d off=0x%04X)",
             useCalm ? "calm" : "stock",
             stockPass.ok ? 1 : 0, stockPass.signatureHits, stockPass.offset,
             calmPass.ok ? 1 : 0, calmPass.signatureHits, calmPass.offset);

    if (!m_animDiscovery.ok)
    {
        m_failure = "could not identify the AnimReloadRate field with enough confidence";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------

void WeaponPatcher::bindWeapons(const Config& config, const std::vector<float>& expected)
{
    const DefaultsSettings& defaults = config.defaults();
    const std::uint32_t     offset   = m_animDiscovery.offset;

    struct Pick
    {
        std::uint8_t* address;
        float         value;
        bool          exact;
    };
    std::vector<Pick> picks;

    int valueAndClass = 0;
    int classOnly     = 0;
    int valueOnly     = 0;

    for (std::size_t n = 0; n < m_names.size(); ++n)
    {
        const NamedWeapon& named = m_names[n];
        const float        want  = (n < expected.size()) ? expected[n] : 0.0f;

        picks.clear();
        for (const Candidate& candidate : m_candidates[n])
        {
            if (candidate.readableSpan < static_cast<std::size_t>(offset) + 4u)
            {
                continue;
            }
            if (m_classKnown)
            {
                if (m_classDelta >= 0 &&
                    candidate.readableSpan < static_cast<std::size_t>(m_classDelta) + 8u)
                {
                    continue;
                }
                std::uint64_t marker = 0u;
                if (!readClassQword(candidate.address, m_classDelta, marker) ||
                    marker != m_classValue)
                {
                    continue;
                }
            }
            float current = 0.0f;
            if (!MemScan::readFloat(candidate.address + offset, current) || !std::isfinite(current))
            {
                continue;
            }
            const bool exact = (want > 0.0f) && closeEnough(current, want, defaults.vanillaEpsilon);
            if (!m_classKnown && !exact)
            {
                continue;   // without the class marker, only an exact value is proof
            }
            if (!exact && !isSaneRate(current))
            {
                continue;   // a gun's weapon-info object always holds a sane rate here
            }
            picks.push_back(Pick{ candidate.address, current, exact });
        }

        if (picks.empty())
        {
            continue;   // reported after the class scan, which may still find it
        }

        // Exact matches first; otherwise keep address order.
        std::stable_partition(picks.begin(), picks.end(), [](const Pick& p) { return p.exact; });
        if (picks.size() > static_cast<std::size_t>(kMaxInstancesPerName))
        {
            DRS_INFO("resolver: %s: %zu weapon-info objects carry this name; patching the first %d",
                     named.name.c_str(), picks.size(), kMaxInstancesPerName);
            picks.erase(picks.begin() + kMaxInstancesPerName, picks.end());
        }
        else if (picks.size() > 1u)
        {
            DRS_INFO("resolver: %s: %zu weapon-info objects carry this name; all are patched",
                     named.name.c_str(), picks.size());
        }

        for (std::size_t k = 0; k < picks.size(); ++k)
        {
            WeaponTarget target;
            target.name         = named.name;
            target.hash         = named.hash;
            target.reference    = named.reference;
            target.config       = named.config;
            target.nameAddress  = picks[k].address;
            target.inMainModule = MemScan::isInsideMainModule(picks[k].address);
            target.instance     = static_cast<int>(k);
            if (!m_classKnown)
            {
                target.bind = BindKind::ValueOnly;
                ++valueOnly;
            }
            else if (picks[k].exact)
            {
                target.bind = BindKind::ValueAndClass;
                ++valueAndClass;
            }
            else
            {
                target.bind = BindKind::ClassOnly;
                ++classOnly;
            }
            target.anim.address = picks[k].address + offset;
            DRS_DEBUG("bind: %s #%d value %.4f (%s)", target.name.c_str(), target.instance,
                      picks[k].value, bindKindName(target.bind));
            m_weapons.push_back(target);
        }
    }

    DRS_INFO("resolver: AnimReloadRate bindings from the name scan: %d value+class, %d class "
             "only, %d value only", valueAndClass, classOnly, valueOnly);
}

// ---------------------------------------------------------------------------
// Class scan (1.2): every object of the recognised class, by its marker. Two
// jobs: a safety net for table weapons whose structure lay behind more than
// kMaxHitsPerName other mentions of their name, and the list of weapon-info
// objects whose names are NOT in the table (unlisted guns, DLC, add-ons).
// Read-only, resolver thread, one pass like the name scan.
// ---------------------------------------------------------------------------

void WeaponPatcher::classScan()
{
    const std::uint32_t offset = m_animDiscovery.offset;
    const std::size_t   need   = static_cast<std::size_t>(offset) + 4u;

    std::uint64_t scanned = 0;
    const std::vector<std::uint8_t*> hits = m_scan.findQwords(&m_classValue, 1u,
                                                              kMaxClassObjects, scanned);

    int tableObjects = 0;
    int added        = 0;
    int otherNames   = 0;
    int rejected     = 0;

    for (std::uint8_t* hit : hits)
    {
        std::uint8_t* nameAddress = hit - m_classDelta;
        if (m_scan.spanFromRegions(nameAddress, need) < need)
        {
            ++rejected;
            continue;
        }
        std::uint32_t hash  = 0u;
        float         value = 0.0f;
        if (!MemScan::readDword(nameAddress, hash) || hash == 0u ||
            !MemScan::readFloat(nameAddress + offset, value) || !std::isfinite(value))
        {
            ++rejected;
            continue;
        }

        const auto named = std::find_if(m_names.begin(), m_names.end(),
                                        [hash](const NamedWeapon& n) { return n.hash == hash; });
        if (named != m_names.end())
        {
            ++tableObjects;
            int  instances    = 0;
            bool alreadyBound = false;
            for (const WeaponTarget& target : m_weapons)
            {
                if (target.hash != hash)
                {
                    continue;
                }
                ++instances;
                if (target.nameAddress == nameAddress)
                {
                    alreadyBound = true;
                }
            }
            if (alreadyBound || instances >= kMaxInstancesPerName)
            {
                continue;
            }
            if (!isSaneRate(value))
            {
                ++rejected;
                continue;
            }
            WeaponTarget target;
            target.name         = named->name;
            target.hash         = hash;
            target.reference    = named->reference;
            target.config       = named->config;
            target.nameAddress  = nameAddress;
            target.inMainModule = MemScan::isInsideMainModule(nameAddress);
            target.instance     = instances;
            target.bind         = BindKind::ClassOnly;
            target.anim.address = nameAddress + offset;
            m_weapons.push_back(target);
            ++added;
            DRS_INFO("resolver: %s: weapon-info object found by the class scan (value %.4f)",
                     target.name.c_str(), value);
            continue;
        }

        if (isNeverManaged(hash))
        {
            continue;
        }
        ++otherNames;
        if (m_unlisted.size() >= kMaxUnlistedObjects || !isSaneRate(value))
        {
            continue;   // melee, thrown and animal "weapons" usually hold 0 here
        }
        UnlistedObject object;
        object.hash         = hash;
        object.nameAddress  = nameAddress;
        object.anim.address = nameAddress + offset;
        m_unlisted.push_back(object);
    }

    DRS_INFO("resolver: class scan: %zu weapon-info objects, %d with table names (%d added that "
             "the name scan missed), %d with other names (%zu with a usable reload rate), "
             "%d rejected",
             hits.size(), tableObjects, added, otherNames, m_unlisted.size(), rejected);
}

// ---------------------------------------------------------------------------
// Sectioned reload (PatchSectionedReload = 1 only, experimental since 1.2).
// ---------------------------------------------------------------------------

void WeaponPatcher::resolveSectioned(const Config& config)
{
    const MemorySettings&   memory   = config.memory();
    const DefaultsSettings& defaults = config.defaults();

    std::vector<float> vanillaLoop;
    std::vector<float> vanillaTime;
    vanillaLoop.reserve(m_profiles.size());
    vanillaTime.reserve(m_profiles.size());
    for (const ProfileTarget& target : m_profiles)
    {
        vanillaLoop.push_back(target.reference != nullptr ? target.reference->loopRate[0] : 0.0f);
        vanillaTime.push_back(target.reference != nullptr ? target.reference->timeBetween[0] : 0.0f);
    }

    if (memory.forceLoopOffset >= 0)
    {
        m_loopDiscovery               = DiscoveryResult();
        m_loopDiscovery.ok            = true;
        m_loopDiscovery.offset        = static_cast<std::uint32_t>(memory.forceLoopOffset);
        m_loopDiscovery.signatureUsed = "forced by config";
        DRS_INFO("resolver: LoopRate offset pinned to 0x%04X by [Memory]", m_loopDiscovery.offset);
    }
    else
    {
        m_loopDiscovery = discoverOffset("LoopRate", m_profileCandidates, vanillaLoop, "stock",
                                         config, 0u, false, true);
    }

    if (memory.forceTimeOffset >= 0)
    {
        m_timeDiscovery               = DiscoveryResult();
        m_timeDiscovery.ok            = true;
        m_timeDiscovery.offset        = static_cast<std::uint32_t>(memory.forceTimeOffset);
        m_timeDiscovery.signatureUsed = "forced by config";
        DRS_INFO("resolver: TimeBetweenBulletsInLoop offset pinned to 0x%04X by [Memory]",
                 m_timeDiscovery.offset);
    }
    else
    {
        m_timeDiscovery = discoverOffset("TimeBetweenBulletsInLoop", m_profileCandidates,
                                         vanillaTime, "stock", config, 0u, false, true);
        // TimeBetweenBulletsInLoop is the 10th float of the same 14-float block in
        // which LoopRate is the 3rd: exactly 0x24 bytes further. Its stock values
        // are low-entropy (0.100 / 0.125) and lose the margin rule to unrelated
        // fields (1.1 log: 0x0054 vs 0x018C) - the structure decides instead.
        if (!m_timeDiscovery.ok && m_loopDiscovery.ok)
        {
            const std::uint32_t structural = m_loopDiscovery.offset + 0x24u;
            const int hits = exactHitsAt(m_profileCandidates, vanillaTime, structural,
                                         defaults.vanillaEpsilon);
            if (hits >= memory.minConsensusWeapons)
            {
                m_timeDiscovery               = DiscoveryResult();
                m_timeDiscovery.ok            = true;
                m_timeDiscovery.offset        = structural;
                m_timeDiscovery.signatureHits = hits;
                m_timeDiscovery.signatureUsed = "structural (LoopRate + 0x24)";
                DRS_INFO("resolver: TimeBetweenBulletsInLoop accepted at 0x%04X = LoopRate + 0x24 "
                         "(%d exact stock matches)", structural, hits);
            }
        }
    }

    if (!m_loopDiscovery.ok || !m_timeDiscovery.ok)
    {
        DRS_INFO("resolver: sectioned reload fields not identified; only AnimReloadRate is "
                 "switched");
        return;
    }

    // A profile is bound only where BOTH stock values are found exactly.
    const std::size_t need =
        static_cast<std::size_t>(std::max(m_loopDiscovery.offset, m_timeDiscovery.offset)) + 4u;
    int bound = 0;
    for (std::size_t i = 0; i < m_profiles.size(); ++i)
    {
        ProfileTarget& profile  = m_profiles[i];
        const float    wantLoop = vanillaLoop[i];
        const float    wantTime = vanillaTime[i];
        if (wantLoop <= 0.0f || wantTime <= 0.0f)
        {
            continue;
        }
        for (const Candidate& candidate : m_profileCandidates[i])
        {
            if (candidate.readableSpan < need)
            {
                continue;
            }
            float loopValue = 0.0f;
            float timeValue = 0.0f;
            if (!MemScan::readFloat(candidate.address + m_loopDiscovery.offset, loopValue) ||
                !MemScan::readFloat(candidate.address + m_timeDiscovery.offset, timeValue))
            {
                continue;
            }
            if (closeEnough(loopValue, wantLoop, defaults.vanillaEpsilon) &&
                closeEnough(timeValue, wantTime, defaults.vanillaEpsilon))
            {
                profile.nameAddress     = candidate.address;
                profile.inMainModule    = MemScan::isInsideMainModule(candidate.address);
                profile.loop[0].address = candidate.address + m_loopDiscovery.offset;
                profile.time[0].address = candidate.address + m_timeDiscovery.offset;
                profile.conditions      = 1;
                ++bound;
                break;
            }
        }
        if (profile.nameAddress == nullptr)
        {
            DRS_INFO("resolver: profile %s: no structure holds both stock values - not patched",
                     profile.name.c_str());
        }
    }
    DRS_INFO("resolver: %d of %zu sectioned profiles bound (exact stock values only)",
             bound, m_profiles.size());

    if (memory.patchAllConditions)
    {
        discoverConditionStride(config);
    }
    else
    {
        DRS_INFO("resolver: PatchAllConditions = 0, only GoodCondition is patched");
    }
}

bool WeaponPatcher::discoverConditionStride(const Config& config)
{
    const DefaultsSettings& defaults = config.defaults();

    std::uint32_t bestStride = 0u;
    int           bestScore  = 0;
    int           eligible   = 0;

    for (const ProfileTarget& profile : m_profiles)
    {
        if (profile.loop[0].address != nullptr && profile.reference != nullptr)
        {
            ++eligible;
        }
    }

    for (std::uint32_t stride = 16u; stride <= 512u; stride += 4u)
    {
        int score = 0;
        for (const ProfileTarget& profile : m_profiles)
        {
            if (profile.loop[0].address == nullptr || profile.reference == nullptr)
            {
                continue;
            }
            bool allMatch = true;
            for (int c = 1; c < kConditionCount && allMatch; ++c)
            {
                const std::uint8_t* address =
                    profile.loop[0].address + static_cast<std::size_t>(stride) * static_cast<std::size_t>(c);
                float value = 0.0f;
                allMatch = m_scan.spanFromRegions(address, sizeof(float)) >= sizeof(float) &&
                           MemScan::readFloat(address, value) &&
                           closeEnough(value, profile.reference->loopRate[c], defaults.vanillaEpsilon);
            }
            if (allMatch)
            {
                ++score;
            }
        }
        if (score > bestScore)
        {
            bestScore  = score;
            bestStride = stride;
        }
    }

    // Needs a clear majority of the bound profiles, not one lucky hit.
    const int required = std::max(3, eligible / 2);
    if (bestScore < required)
    {
        m_conditionStride = 0u;
        DRS_INFO("resolver: conditions: good only (stride unresolved, best %d of %d needed)",
                 bestScore, required);
        return false;
    }

    m_conditionStride = bestStride;
    DRS_INFO("resolver: condition block stride = 0x%03X, confirmed on %d profiles",
             bestStride, bestScore);

    for (ProfileTarget& profile : m_profiles)
    {
        if (profile.loop[0].address == nullptr)
        {
            continue;
        }
        for (int c = 1; c < kConditionCount; ++c)
        {
            const std::size_t step = static_cast<std::size_t>(bestStride) * static_cast<std::size_t>(c);
            profile.loop[c].address = profile.loop[0].address + step;
            profile.time[c].address = profile.time[0].address + step;
        }
        profile.conditions = kConditionCount;
    }
    return true;
}

// ---------------------------------------------------------------------------

bool WeaponPatcher::resolve(const Config& config)
{
    m_failure.clear();
    m_weapons.clear();
    m_unlisted.clear();
    m_unboundHashes.clear();
    m_candidates.clear();
    m_profileCandidates.clear();
    m_animDiscovery = DiscoveryResult();
    m_loopDiscovery = DiscoveryResult();
    m_timeDiscovery = DiscoveryResult();
    m_classKnown    = false;
    m_classDelta    = 0;
    m_classValue    = 0u;
    for (ProfileTarget& profile : m_profiles)
    {
        ProfileTarget fresh;
        fresh.name      = profile.name;
        fresh.hash      = profile.hash;
        fresh.reference = profile.reference;
        profile         = fresh;
    }

    const MemorySettings& memory = config.memory();
    const std::size_t     span   = static_cast<std::size_t>(memory.maxOffsetWindow) + 4u;

    // --- pass 1: every name and profile hash at once -------------------------
    std::vector<ScanRequest> requests;
    requests.reserve(m_names.size() + m_profiles.size());
    for (const NamedWeapon& named : m_names)
    {
        ScanRequest request;
        request.value   = named.hash;
        request.maxHits = kMaxHitsPerName;
        requests.push_back(request);
    }
    for (const ProfileTarget& profile : m_profiles)
    {
        ScanRequest request;
        request.value   = profile.hash;
        request.maxHits = kMaxHitsPerProfile;
        requests.push_back(request);
    }

    std::uint64_t scanned = 0;
    std::vector<ScanResult> results = m_scan.findDwords(requests, scanned);
    if (results.size() != requests.size())
    {
        m_failure = "memory scan returned an inconsistent result set";
        return false;
    }

    auto toCandidates = [this, span](const ScanResult& result) {
        std::vector<Candidate> list;
        list.reserve(result.hits.size());
        for (std::uint8_t* hit : result.hits)
        {
            Candidate candidate;
            candidate.address      = hit;
            candidate.readableSpan = m_scan.spanFromRegions(hit, span);
            if (candidate.readableSpan >= 8u)
            {
                list.push_back(candidate);
            }
        }
        return list;
    };

    int present   = 0;
    int truncated = 0;
    for (std::size_t i = 0; i < m_names.size(); ++i)
    {
        m_candidates.push_back(toCandidates(results[i]));
        if (results[i].truncated)
        {
            ++truncated;
        }
        if (!m_candidates.back().empty())
        {
            ++present;
        }
        else
        {
            DRS_INFO("resolver: %s hash not found in memory", m_names[i].name.c_str());
        }
    }
    for (std::size_t i = 0; i < m_profiles.size(); ++i)
    {
        m_profileCandidates.push_back(toCandidates(results[m_names.size() + i]));
        if (m_profileCandidates.back().empty())
        {
            DRS_INFO("resolver: profile %s hash not found in memory", m_profiles[i].name.c_str());
        }
    }
    results.clear();
    results.shrink_to_fit();

    DRS_INFO("resolver: %d of %zu weapon names present in memory, %.1f MB scanned "
             "(up to %zu hits kept per name; %d name(s) had more)",
             present, m_names.size(), static_cast<double>(scanned) / (1024.0 * 1024.0),
             kMaxHitsPerName, truncated);

    if (present == 0)
    {
        m_failure = "no weapon name hash found anywhere in memory";
        return false;
    }

    // --- expected values: stock (table) and calm (INI) -----------------------
    std::vector<float> vanillaAnim;
    std::vector<float> calmAnim;
    vanillaAnim.reserve(m_names.size());
    calmAnim.reserve(m_names.size());
    for (const NamedWeapon& named : m_names)
    {
        vanillaAnim.push_back(named.reference != nullptr ? named.reference->vanillaAnimReloadRate
                                                         : 0.0f);
        calmAnim.push_back((named.config != nullptr && named.config->calm.animReloadRate.present)
                               ? named.config->calm.animReloadRate.value
                               : 0.0f);
    }

    bool matchedCalm = false;
    if (!chooseClassAndOffset(config, vanillaAnim, calmAnim, matchedCalm))
    {
        if (m_failure.empty())
        {
            m_failure = "could not identify the AnimReloadRate field with enough confidence";
        }
        return false;
    }

    bindWeapons(config, matchedCalm ? calmAnim : vanillaAnim);

    if (m_classKnown)
    {
        classScan();
    }
    else
    {
        DRS_INFO("resolver: class scan skipped (no class marker); guns outside the table are "
                 "not switched this session");
    }

    if (!m_profiles.empty())
    {
        resolveSectioned(config);
    }

    // Names in memory that still have no structure: say so, by name.
    int unbound = 0;
    for (std::size_t i = 0; i < m_names.size(); ++i)
    {
        const std::uint32_t hash  = m_names[i].hash;
        const bool          bound = std::any_of(m_weapons.begin(), m_weapons.end(),
                                                [hash](const WeaponTarget& t) { return t.hash == hash; });
        if (bound || m_candidates[i].empty())
        {
            continue;
        }
        ++unbound;
        m_unboundHashes.push_back(hash);
        DRS_INFO("resolver: %s: %zu mention(s) of the name in memory, none of them its "
                 "weapon-info structure - not patched",
                 m_names[i].name.c_str(), m_candidates[i].size());
    }

    int valueAndClass = 0;
    int classOnly     = 0;
    int valueOnly     = 0;
    for (const WeaponTarget& target : m_weapons)
    {
        if (target.bind == BindKind::ValueAndClass) { ++valueAndClass; }
        else if (target.bind == BindKind::ClassOnly) { ++classOnly; }
        else if (target.bind == BindKind::ValueOnly) { ++valueOnly; }
    }
    DRS_INFO("resolver: AnimReloadRate bindings: %d value+class, %d class only, %d value only; "
             "%d name(s) present but unbound", valueAndClass, classOnly, valueOnly, unbound);

    if (m_weapons.empty())
    {
        m_failure = "no weapon structure could be bound";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------

void WeaponPatcher::takeSnapshot()
{
    // Runs on the resolver thread, read-only. The page check uses the protection
    // the region list recorded (no system call); this plugin never changes it.
    auto snap = [this](FieldTarget& field) -> bool {
        if (field.address == nullptr)
        {
            return false;
        }
        float value = 0.0f;
        if (!MemScan::passesStaticChecks(field.address) ||
            !m_scan.regionAllowsWrite(field.address, sizeof(float)) ||
            !MemScan::readFloat(field.address, value) ||
            !std::isfinite(value) || value < kLiveValueMin || value > kLiveValueMax)
        {
            field.unpatchable = true;
            return false;
        }
        field.snapshot    = value;
        field.hasSnapshot = true;
        field.lastWritten = value;
        return true;
    };

    for (WeaponTarget& target : m_weapons)
    {
        if (!snap(target.anim))
        {
            DRS_ERROR("snapshot failed for %s #%d AnimReloadRate: page not writable or value out "
                      "of range; not patched", target.name.c_str(), target.instance);
        }
    }
    for (UnlistedObject& object : m_unlisted)
    {
        snap(object.anim);   // silently: these are only candidates until classified
    }
    for (ProfileTarget& profile : m_profiles)
    {
        for (int c = 0; c < profile.conditions; ++c)
        {
            if (profile.loop[c].address != nullptr && !snap(profile.loop[c]))
            {
                DRS_ERROR("snapshot failed for %s %s LoopRate", profile.name.c_str(),
                          kConditionName[c]);
            }
            if (profile.time[c].address != nullptr && !snap(profile.time[c]))
            {
                DRS_ERROR("snapshot failed for %s %s TimeBetweenBulletsInLoop",
                          profile.name.c_str(), kConditionName[c]);
            }
        }
    }

    // Three weapons' worth of proof that the snapshot is real.
    int printed = 0;
    for (const WeaponTarget& target : m_weapons)
    {
        if (target.anim.hasSnapshot && printed < 3)
        {
            DRS_INFO("snapshot: %s AnimReloadRate = %.4f  in-module: %s",
                     target.name.c_str(), target.anim.snapshot,
                     target.inMainModule ? "yes" : "no");
            ++printed;
        }
    }
}

bool WeaponPatcher::initialise(const Config& config)
{
    const auto started = std::chrono::steady_clock::now();

    m_ready = false;
    m_failure.clear();
    resetState();

    if (!collectNames(config))
    {
        m_failure = "no weapons configured";
        return false;
    }

    if (!m_scan.buildRegionList(false, config.memory().maxScanBytes))
    {
        m_failure = "no scannable memory regions";
        return false;
    }

    if (!resolve(config))
    {
        // One retry including file-backed regions, in case the weapon pool does
        // not live in a plain private allocation on this build.
        DRS_INFO("resolver: retry including mapped regions (%s)", m_failure.c_str());
        if (!m_scan.buildRegionList(true, config.memory().maxScanBytes) || !resolve(config))
        {
            if (m_failure.empty())
            {
                m_failure = "resolution failed";
            }
            return false;
        }
    }

    takeSnapshot();

    // The scan results are not needed past this point, and the config pointers in
    // m_names are only valid until the next F9 - drop both.
    m_candidates.clear();
    m_candidates.shrink_to_fit();
    m_profileCandidates.clear();
    m_profileCandidates.shrink_to_fit();
    for (NamedWeapon& named : m_names)
    {
        named.config = nullptr;
    }

    const int weapons = resolvedWeapons();
    if (weapons == 0)
    {
        m_failure = "no weapon survived snapshot validation";
        return false;
    }

    DRS_INFO("resolver: ready in %.0f ms: %d weapon structures for %d names, %zu unlisted "
             "candidates, %d sectioned profiles patchable",
             millisecondsSince(started), weapons, resolvedNames(), m_unlisted.size(),
             resolvedProfiles());
    m_ready = true;
    return true;
}

// ---------------------------------------------------------------------------

std::vector<std::uint32_t> WeaponPatcher::unlistedHashes() const
{
    std::vector<std::uint32_t> hashes;
    hashes.reserve(m_unlisted.size());
    for (const UnlistedObject& object : m_unlisted)
    {
        if (object.anim.hasSnapshot)
        {
            hashes.push_back(object.hash);
        }
    }
    std::sort(hashes.begin(), hashes.end());
    hashes.erase(std::unique(hashes.begin(), hashes.end()), hashes.end());
    return hashes;
}

int WeaponPatcher::adoptUnlisted(const std::vector<UnlistedGun>& guns, const Config& config)
{
    int adopted = 0;
    for (const UnlistedGun& gun : guns)
    {
        int   instance = 0;
        float loaded   = 0.0f;
        for (const UnlistedObject& object : m_unlisted)
        {
            if (object.hash != gun.hash || !object.anim.hasSnapshot)
            {
                continue;
            }
            if (instance >= kMaxInstancesPerName || adopted >= kMaxUnlistedAdopted)
            {
                break;
            }
            WeaponTarget target;
            target.name         = gun.name;
            target.hash         = gun.hash;
            target.config       = config.matchWeapon(gun.name);
            target.reference    = nullptr;
            target.nameAddress  = object.nameAddress;
            target.inMainModule = MemScan::isInsideMainModule(object.nameAddress);
            target.unlisted     = true;
            target.bind         = BindKind::ClassOnly;
            target.instance     = instance;
            target.anim         = object.anim;
            if (instance == 0)
            {
                loaded = object.anim.snapshot;
            }
            m_weapons.push_back(target);
            ++instance;
            ++adopted;
        }
        if (instance > 0)
        {
            const WeaponEntry* section = config.matchWeapon(gun.name);
            DRS_INFO("unlisted gun: %s (label %s, name %s): %d structure(s), loaded %.4f, "
                     "INI section %s",
                     gun.name.c_str(), gun.label.empty() ? "none" : gun.label.c_str(),
                     gun.nameVerified ? "verified" : "not verified", instance, loaded,
                     section != nullptr ? section->name.c_str() : "none (defaults)");
        }
    }
    return adopted;
}

void WeaponPatcher::releaseUnlisted()
{
    m_unlisted.clear();
    m_unlisted.shrink_to_fit();
}

// ---------------------------------------------------------------------------
// Which value goes where.
//
// auto mode, per structure:
//   * Decide whether the value the game loaded is the STOCK one or an already
//     SLOWED one (the player's own weapons.ymt, an overhaul):
//       - stock value known (table)  -> loaded == stock
//       - else an INI Calm value     -> loaded is faster than it
//       - else                       -> loaded is 1.00 or 1.30 (the only stock values)
//   * stock file : CALM = INI Calm (else loaded x CalmAnimReloadRateMul),
//                  COMBAT = loaded
//   * slowed file: CALM = loaded,
//                  COMBAT = INI Combat (else the table's stock value,
//                  else loaded x CombatAnimReloadRateMul)
// A gun with no INI section whose loaded value is not a stock value therefore
// gets loaded/loaded - it is left exactly as it is.
// manual mode: CalmSource / CombatSource literally, as in 1.0.
// ---------------------------------------------------------------------------

bool WeaponPatcher::snapshotIsStock(const WeaponTarget& target, const Config& config) const
{
    const float epsilon = config.defaults().vanillaEpsilon;
    const float loaded  = target.anim.snapshot;
    const float stock   = (target.reference != nullptr) ? target.reference->vanillaAnimReloadRate
                                                        : 0.0f;
    if (stock > 0.0f)
    {
        return closeEnough(loaded, stock, epsilon);
    }
    if (target.config != nullptr && target.config->calm.animReloadRate.present)
    {
        return loaded > target.config->calm.animReloadRate.value + epsilon;
    }
    return isStockRate(loaded, epsilon);
}

float WeaponPatcher::decideAnim(const WeaponTarget& target, bool combat, const Config& config,
                                const char*& why) const
{
    const DefaultsSettings& defaults = config.defaults();
    const ProfileSettings&  profiles = config.profiles();
    const float             loaded   = target.anim.snapshot;

    const FieldValue* calmIni   = (target.config != nullptr) ? &target.config->calm.animReloadRate
                                                             : nullptr;
    const FieldValue* combatIni = (target.config != nullptr) ? &target.config->combat.animReloadRate
                                                             : nullptr;
    const bool haveCalm   = (calmIni != nullptr) && calmIni->present;
    const bool haveCombat = (combatIni != nullptr) && combatIni->present;

    if (profiles.mode == ProfileMode::Manual)
    {
        const ValueSource source = combat ? profiles.combatSource : profiles.calmSource;
        if (source == ValueSource::Snapshot)
        {
            why = "manual: loaded";
            return loaded;
        }
        if (source == ValueSource::Ini && combat && haveCombat)
        {
            why = "manual: ini";
            return combatIni->value;
        }
        if (source == ValueSource::Ini && !combat && haveCalm)
        {
            why = "manual: ini";
            return calmIni->value;
        }
        why = "manual: loaded x multiplier";
        return loaded * (combat ? defaults.combatAnimMul : defaults.calmAnimMul);
    }

    if (snapshotIsStock(target, config))
    {
        if (combat)
        {
            why = "loaded";
            return loaded;
        }
        if (haveCalm)
        {
            why = "ini";
            return calmIni->value;
        }
        why = "loaded x CalmAnimReloadRateMul";
        return loaded * defaults.calmAnimMul;
    }

    if (!combat)
    {
        why = "loaded";
        return loaded;
    }
    if (haveCombat)
    {
        why = "ini";
        return combatIni->value;
    }
    const float stock = (target.reference != nullptr) ? target.reference->vanillaAnimReloadRate
                                                      : 0.0f;
    if (stock > 0.0f)
    {
        why = "stock";
        return stock;
    }
    why = "loaded x CombatAnimReloadRateMul";
    return loaded * defaults.combatAnimMul;
}

void WeaponPatcher::logPlan(const Config& config) const
{
    int lines = 0;
    for (const WeaponTarget& target : m_weapons)
    {
        if (target.instance != 0 || target.anim.address == nullptr || target.anim.unpatchable ||
            !target.anim.hasSnapshot)
        {
            continue;
        }
        int copies = 0;
        for (const WeaponTarget& other : m_weapons)
        {
            if (other.hash == target.hash && other.instance != 0)
            {
                ++copies;
            }
        }
        const char* whyCalm   = "";
        const char* whyCombat = "";
        const float calm      = decideAnim(target, false, config, whyCalm);
        const float combat    = decideAnim(target, true, config, whyCombat);
        DRS_INFO("plan: %s%s loaded %.4f (%s) -> CALM %.4f [%s] / COMBAT %.4f [%s]%s%s",
                 target.name.c_str(), target.unlisted ? " (unlisted)" : "",
                 target.anim.snapshot,
                 snapshotIsStock(target, config) ? "stock" : "slowed or unknown",
                 calm, whyCalm, combat, whyCombat,
                 copies > 0 ? " +copies" : "",
                 (calm > combat + 0.0001f) ? "  NOTE: CALM is faster than COMBAT" : "");
        ++lines;
    }
    DRS_INFO("plan: %d weapon name(s), mode %s", lines,
             config.profiles().mode == ProfileMode::Auto ? "auto" : "manual");
}

// ---------------------------------------------------------------------------
// Writing (script thread). No system call anywhere below.
// ---------------------------------------------------------------------------

WeaponPatcher::WriteOutcome WeaponPatcher::writeField(FieldTarget& field, float value,
                                                      const char* what, const Config& config)
{
    if (field.address == nullptr || field.unpatchable || !field.hasSnapshot)
    {
        return WriteOutcome::Skipped;
    }

    const DefaultsSettings& defaults = config.defaults();

    if (!std::isfinite(value) || value <= 0.0f)
    {
        DRS_ERROR("%s: refusing to write a non-finite or non-positive value", what);
        return WriteOutcome::Skipped;
    }
    float clamped = value;
    if (clamped < defaults.minValue) { clamped = defaults.minValue; }
    if (clamped > defaults.maxValue) { clamped = defaults.maxValue; }
    if (!closeEnough(clamped, value, 0.0001f))
    {
        DRS_INFO("%s: clamped %.4f to %.4f by [MinValue, MaxValue]", what, value, clamped);
    }

    float current = 0.0f;
    if (!MemScan::readFloat(field.address, current) || !std::isfinite(current) ||
        current < kLiveValueMin || current > kLiveValueMax)
    {
        field.unpatchable = true;
        DRS_ERROR("%s: current value is not a plausible rate; target dropped for this session",
                  what);
        return WriteOutcome::Dropped;
    }

    // Continuity (invariant 2): the field must still hold what the game loaded or
    // what this plugin wrote last.
    const bool isLast     = field.firstWriteDone && closeEnough(current, field.lastWritten, 0.0005f);
    const bool isSnapshot = closeEnough(current, field.snapshot, 0.0005f);
    if (!isLast && !isSnapshot)
    {
        field.unpatchable = true;
        DRS_ERROR("%s: value is %.4f, expected %.4f (written last) or %.4f (boot snapshot) - "
                  "something else writes here. Target dropped; the rest keep working.",
                  what, current, field.lastWritten, field.snapshot);
        return WriteOutcome::Dropped;
    }

    if (closeEnough(current, clamped, 0.00001f))
    {
        return WriteOutcome::Unchanged;
    }

    if (!MemScan::writeFloat(field.address, clamped))
    {
        field.unpatchable = true;
        DRS_ERROR("%s: write faulted, target dropped", what);
        return WriteOutcome::Dropped;
    }

    float readBack = 0.0f;
    if (!MemScan::readFloat(field.address, readBack) || !closeEnough(readBack, clamped, 0.0005f))
    {
        field.unpatchable = true;
        DRS_ERROR("%s: readback mismatch, wrote %.4f read %.4f, target dropped",
                  what, clamped, readBack);
        return WriteOutcome::Dropped;
    }
    // SR-10 / T-23: the log records the confirmed result, not the intent.
    DRS_DEBUG("%s: wrote %.4f, read back %.4f", what, clamped, readBack);

    field.firstWriteDone = true;
    field.lastWritten    = clamped;
    return WriteOutcome::Written;
}

bool WeaponPatcher::restoreField(FieldTarget& field, const char* what)
{
    if (field.address == nullptr || !field.hasSnapshot || !field.firstWriteDone)
    {
        return false;
    }
    float current = 0.0f;
    if (!MemScan::readFloat(field.address, current))
    {
        DRS_ERROR("restore skipped: %s (unreadable)", what);
        return false;
    }
    if (closeEnough(current, field.snapshot, 0.0005f))
    {
        field.firstWriteDone = false;
        field.lastWritten    = field.snapshot;
        return false;   // already the original value
    }
    if (!closeEnough(current, field.lastWritten, 0.0005f))
    {
        DRS_ERROR("restore skipped: %s (value %.4f was changed by something else)", what, current);
        return false;
    }
    if (!MemScan::writeFloat(field.address, field.snapshot))
    {
        DRS_ERROR("restore skipped: %s (write faulted)", what);
        return false;
    }
    // 1.2.1: the same read-back as every write (SR-11), and on debug level one line
    // per field with all three numbers - what FR-28 / AT-32 ask the log to show.
    float readBack = 0.0f;
    if (!MemScan::readFloat(field.address, readBack) || !closeEnough(readBack, field.snapshot, 0.0005f))
    {
        DRS_ERROR("restore: %s readback mismatch, wrote %.4f read %.4f", what, field.snapshot,
                  readBack);
        return false;
    }
    DRS_DEBUG("restored: %s %.4f -> %.4f (boot snapshot), read back %.4f", what, current,
              field.snapshot, readBack);
    field.firstWriteDone = false;
    field.lastWritten    = field.snapshot;
    return true;
}

// ---------------------------------------------------------------------------

void WeaponPatcher::applyProfile(bool combat, const Config& config)
{
    if (!m_ready)
    {
        return;
    }
    const auto started = std::chrono::steady_clock::now();

    const DefaultsSettings& defaults = config.defaults();

    char label[160] = {};
    int  written    = 0;
    int  unchanged  = 0;
    int  skipped    = 0;

    for (WeaponTarget& target : m_weapons)
    {
        if (target.anim.address == nullptr || target.anim.unpatchable || !target.anim.hasSnapshot)
        {
            continue;
        }
        if (!ownerStillThere(target))
        {
            target.anim.unpatchable = true;
            DRS_ERROR("%s #%d: the weapon structure is no longer where it was found; target "
                      "dropped for this session", target.name.c_str(), target.instance);
            ++skipped;
            continue;
        }

        const char* why   = "";
        const float value = decideAnim(target, combat, config, why);

        _snprintf_s(label, sizeof(label), _TRUNCATE, "%s #%d %s AnimReloadRate [%s]",
                    target.name.c_str(), target.instance, combat ? "COMBAT" : "CALM", why);
        switch (writeField(target.anim, value, label, config))
        {
        case WriteOutcome::Written:
            ++written;
            break;
        case WriteOutcome::Unchanged:
            ++unchanged;
            break;
        case WriteOutcome::Skipped:
        case WriteOutcome::Dropped:
            ++skipped;
            break;
        }
    }

    // Sectioned profiles (PatchSectionedReload = 1 only).
    for (ProfileTarget& profile : m_profiles)
    {
        if (profile.nameAddress == nullptr)
        {
            continue;
        }
        if (!hashStillThere(profile.nameAddress, profile.hash))
        {
            for (int c = 0; c < profile.conditions; ++c)
            {
                profile.loop[c].unpatchable = true;
                profile.time[c].unpatchable = true;
            }
            DRS_ERROR("%s: the sectioned-reload structure is no longer where it was found; "
                      "dropped for this session", profile.name.c_str());
            continue;
        }

        // Which weapon section owns this profile? The first bound table weapon
        // that references it; they all share the same sectioned values.
        const WeaponEntry* owner = nullptr;
        for (const WeaponTarget& weapon : m_weapons)
        {
            if (weapon.reference == nullptr || weapon.config == nullptr)
            {
                continue;
            }
            const std::uint32_t weaponProfileHash =
                (weapon.reference->profileHash != 0u)
                    ? weapon.reference->profileHash
                    : (weapon.reference->profileName != nullptr
                           ? joaat(weapon.reference->profileName) : 0u);
            if (weaponProfileHash == profile.hash)
            {
                owner = weapon.config;
                break;
            }
        }

        const ConditionReference* reference = profile.reference;

        for (int c = 0; c < profile.conditions; ++c)
        {
            for (int pass = 0; pass < 2; ++pass)
            {
                const bool   isLoop = (pass == 0);
                FieldTarget& field  = isLoop ? profile.loop[c] : profile.time[c];
                if (field.address == nullptr || field.unpatchable || !field.hasSnapshot)
                {
                    continue;
                }

                float base = 0.0f;
                if (owner != nullptr)
                {
                    const ProfileValues& values = combat ? owner->combat : owner->calm;
                    const FieldValue&    picked = isLoop ? values.loopRate : values.timeBetween;
                    if (picked.present)
                    {
                        base = picked.value;
                    }
                }
                if (base <= 0.0f)
                {
                    const float multiplier = isLoop
                        ? (combat ? defaults.combatLoopMul : defaults.calmLoopMul)
                        : (combat ? defaults.combatTimeMul : defaults.calmTimeMul);
                    base = field.snapshot * multiplier;
                }

                // Keep the clean-vs-worn relationship instead of flattening it.
                float ratio = 1.0f;
                if (c > 0 && reference != nullptr)
                {
                    const float stockHere = isLoop ? reference->loopRate[c]
                                                   : reference->timeBetween[c];
                    const float stockGood = isLoop ? reference->loopRate[0]
                                                   : reference->timeBetween[0];
                    if (stockGood > 0.0f && stockHere > 0.0f)
                    {
                        ratio = stockHere / stockGood;
                    }
                }

                _snprintf_s(label, sizeof(label), _TRUNCATE, "%s %s %s %s",
                            profile.name.c_str(), combat ? "COMBAT" : "CALM",
                            kConditionName[c], isLoop ? "LoopRate" : "TimeBetween");
                switch (writeField(field, base * ratio, label, config))
                {
                case WriteOutcome::Written:   ++written;   break;
                case WriteOutcome::Unchanged: ++unchanged; break;
                case WriteOutcome::Skipped:
                case WriteOutcome::Dropped:   ++skipped;   break;
                }
            }
        }
    }

    DRS_INFO("%s applied: %d written, %d already in place, %d skipped, %.3f ms",
             combat ? "COMBAT" : "CALM", written, unchanged, skipped,
             millisecondsSince(started));
}

void WeaponPatcher::restoreAll()
{
    char label[160] = {};
    int  restored   = 0;

    for (WeaponTarget& target : m_weapons)
    {
        if (target.anim.address == nullptr || !target.anim.firstWriteDone)
        {
            continue;
        }
        _snprintf_s(label, sizeof(label), _TRUNCATE, "%s #%d AnimReloadRate",
                    target.name.c_str(), target.instance);
        if (!ownerStillThere(target))
        {
            DRS_ERROR("restore skipped: %s (structure moved)", label);
            continue;
        }
        if (restoreField(target.anim, label))
        {
            ++restored;
        }
    }
    for (ProfileTarget& profile : m_profiles)
    {
        if (profile.nameAddress == nullptr || !hashStillThere(profile.nameAddress, profile.hash))
        {
            continue;
        }
        for (int c = 0; c < profile.conditions; ++c)
        {
            _snprintf_s(label, sizeof(label), _TRUNCATE, "%s %s LoopRate",
                        profile.name.c_str(), kConditionName[c]);
            if (restoreField(profile.loop[c], label)) { ++restored; }

            _snprintf_s(label, sizeof(label), _TRUNCATE, "%s %s TimeBetween",
                        profile.name.c_str(), kConditionName[c]);
            if (restoreField(profile.time[c], label)) { ++restored; }
        }
    }

    DRS_INFO("restore: %d fields returned to their boot snapshot", restored);
}

// ---------------------------------------------------------------------------

HeldWeaponStatus WeaponPatcher::describe(std::uint32_t hash) const
{
    HeldWeaponStatus status;
    if (hash == 0u)
    {
        return status;
    }
    for (const WeaponTarget& target : m_weapons)
    {
        if (target.hash != hash)
        {
            continue;
        }
        if (!status.known)
        {
            status.known = true;
            status.name  = target.name;
        }
        if (target.anim.address == nullptr || target.anim.unpatchable || !target.anim.hasSnapshot)
        {
            continue;
        }
        if (!status.managed)
        {
            status.managed = true;
            status.value   = target.anim.firstWriteDone ? target.anim.lastWritten
                                                        : target.anim.snapshot;
        }
        ++status.instances;
    }
    if (!status.known)
    {
        for (const NamedWeapon& named : m_names)
        {
            if (named.hash == hash)
            {
                status.known = true;
                status.name  = named.name;
                break;
            }
        }
    }
    return status;
}

} // namespace drs

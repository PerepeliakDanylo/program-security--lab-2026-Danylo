#include "WeaponPatcher.h"
#include "Joaat.h"
#include "Logger.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>

namespace drs {

namespace {

constexpr float kLiveValueMin = 0.001f;   // FR-35: what may legitimately be there
constexpr float kLiveValueMax = 100.0f;

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

// A bound structure is only written while the name hash it was found by is still
// where we found it. If the game freed or moved the object, that dword now holds
// something else and the address belongs to unrelated data: writing there would
// corrupt the game. One guarded 4-byte read, checked before every write and
// every restore.
bool ownerStillThere(const std::uint8_t* nameAddress, std::uint32_t hash)
{
    std::uint32_t current = 0u;
    return nameAddress != nullptr && MemScan::readDword(nameAddress, current) &&
           current == hash;
}

} // namespace

std::size_t WeaponPatcher::readableSpanFrom(const std::uint8_t* address, std::size_t cap)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    if (address == nullptr || VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
    {
        return 0;
    }
    if (mbi.State != MEM_COMMIT)
    {
        return 0;
    }
    const std::uint8_t* regionEnd =
        reinterpret_cast<const std::uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    if (regionEnd <= address)
    {
        return 0;
    }
    const std::size_t span = static_cast<std::size_t>(regionEnd - address);
    return (span > cap) ? cap : span;
}

// ---------------------------------------------------------------------------

int WeaponPatcher::resolvedWeapons() const noexcept
{
    int count = 0;
    for (const WeaponTarget& target : m_weapons)
    {
        if (target.anim.address != nullptr && !target.anim.unpatchable)
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

    DRS_INFO("config rebind: %d weapon(s) re-bound, %d lost their section",
             rebound, dropped);
}

// ---------------------------------------------------------------------------

bool WeaponPatcher::collectTargets(const Config& config)
{
    m_weapons.clear();
    m_profiles.clear();

    // One target per shipped weapon name, plus one per distinct sectioned profile.
    for (const WeaponReference& row : kWeaponReference)
    {
        WeaponTarget target;
        target.name      = row.weaponName;
        target.hash      = joaat(toLowerCopy(target.name).c_str());
        target.reference = &row;
        target.config    = config.matchWeapon(target.name);
        m_weapons.push_back(target);

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

    DRS_INFO("resolver: %zu weapon names, %zu sectioned profiles to look for",
             m_weapons.size(), m_profiles.size());
    return !m_weapons.empty();
}

// ---------------------------------------------------------------------------

DiscoveryResult WeaponPatcher::discoverOffset(const char* fieldName,
                                              const std::vector<std::vector<Candidate>>& candidates,
                                              const std::vector<float>& expected,
                                              const char* signatureName,
                                              const Config& config)
{
    DiscoveryResult best;
    best.signatureUsed = signatureName;

    const MemorySettings&  memory   = config.memory();
    const DefaultsSettings& defaults = config.defaults();

    const std::uint32_t step   = (memory.offsetStep == 0u) ? 4u : memory.offsetStep;
    const std::uint32_t window = memory.maxOffsetWindow;

    int bestScore       = 0;
    int bestSignature   = 0;
    std::uint32_t bestOffset = 0u;
    int secondScore     = 0;
    std::uint32_t secondOffset = 0u;

    for (std::uint32_t offset = 0u; offset + 4u <= window; offset += step)
    {
        int score         = 0;
        int signatureHits = 0;

        for (std::size_t i = 0; i < candidates.size(); ++i)
        {
            const float want = (i < expected.size()) ? expected[i] : 0.0f;
            int bestForThis  = 0;

            for (const Candidate& candidate : candidates[i])
            {
                if (candidate.readableSpan < static_cast<std::size_t>(offset) + 4u)
                {
                    continue;   // not readable this far; no contribution, no penalty
                }
                float value = 0.0f;
                if (!MemScan::readFloat(candidate.address + offset, value))
                {
                    continue;
                }
                if (!std::isfinite(value) ||
                    value < defaults.minValue || value > defaults.maxValue)
                {
                    continue;
                }
                if (want > 0.0f && closeEnough(value, want, defaults.vanillaEpsilon))
                {
                    if (bestForThis < 10) { bestForThis = 10; }
                }
                else if (bestForThis < 1)
                {
                    bestForThis = 1;
                }
            }

            score += bestForThis;
            if (bestForThis == 10)
            {
                ++signatureHits;
            }
        }

        if (score > bestScore)
        {
            secondScore  = bestScore;
            secondOffset = bestOffset;
            bestScore     = score;
            bestSignature = signatureHits;
            bestOffset    = offset;
        }
        else if (score > secondScore)
        {
            secondScore  = score;
            secondOffset = offset;
        }
    }

    best.offset         = bestOffset;
    best.score          = bestScore;
    best.signatureHits  = bestSignature;
    best.runnerUpOffset = secondOffset;
    best.runnerUpScore  = secondScore;

    const int required = memory.minConsensusWeapons;
    const bool enoughSignature = (bestSignature >= required);
    const bool clearWinner =
        (secondScore == 0) ||
        (static_cast<float>(bestScore) >=
         memory.consensusMargin * static_cast<float>(secondScore));

    best.ok = enoughSignature && clearWinner;

    DRS_INFO("resolver: %s signature=%s best offset=0x%04X score=%d sig=%d/%d "
             "runner-up offset=0x%04X score=%d -> %s",
             fieldName, signatureName, bestOffset, bestScore, bestSignature, required,
             secondOffset, secondScore,
             best.ok ? "accepted" : "REJECTED");

    if (!best.ok)
    {
        if (!enoughSignature)
        {
            DRS_INFO("resolver: %s rejected because only %d of the required %d weapons "
                     "matched the stock signature", fieldName, bestSignature, required);
        }
        if (!clearWinner)
        {
            DRS_INFO("resolver: %s rejected because the runner-up is too close "
                     "(margin required %.2f)", fieldName, memory.consensusMargin);
        }
    }

    return best;
}

void WeaponPatcher::bindAddresses(const std::vector<std::vector<Candidate>>& candidates,
                                  const std::vector<float>& expected,
                                  std::uint32_t offset,
                                  std::vector<std::uint8_t*>& chosenOut,
                                  const Config& config)
{
    const DefaultsSettings& defaults = config.defaults();
    chosenOut.assign(candidates.size(), nullptr);

    for (std::size_t i = 0; i < candidates.size(); ++i)
    {
        const float want = (i < expected.size()) ? expected[i] : 0.0f;
        std::uint8_t* fallback = nullptr;

        for (const Candidate& candidate : candidates[i])
        {
            if (candidate.readableSpan < static_cast<std::size_t>(offset) + 4u)
            {
                continue;
            }
            float value = 0.0f;
            if (!MemScan::readFloat(candidate.address + offset, value))
            {
                continue;
            }
            if (!std::isfinite(value) ||
                value < defaults.minValue || value > defaults.maxValue)
            {
                continue;
            }
            if (want > 0.0f && closeEnough(value, want, defaults.vanillaEpsilon))
            {
                chosenOut[i] = candidate.address;
                fallback     = nullptr;
                break;
            }
            if (fallback == nullptr)
            {
                fallback = candidate.address;
            }
        }

        if (chosenOut[i] == nullptr)
        {
            chosenOut[i] = fallback;
        }
    }
}

// ---------------------------------------------------------------------------

bool WeaponPatcher::discoverAll(const Config& config)
{
    m_failure.clear();   // this may be the retry pass; last pass's reason is stale

    const MemorySettings& memory = config.memory();
    const std::size_t     span   = static_cast<std::size_t>(memory.maxOffsetWindow) + 4u;

    // One memory pass for every hash we care about.
    std::vector<ScanRequest> requests;
    requests.reserve(m_weapons.size() + m_profiles.size());
    for (const WeaponTarget& target : m_weapons)
    {
        ScanRequest request;
        request.value   = target.hash;
        request.maxHits = 64u;
        requests.push_back(request);
    }
    for (const ProfileTarget& target : m_profiles)
    {
        ScanRequest request;
        request.value   = target.hash;
        request.maxHits = 64u;
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

    m_weaponCandidates.clear();
    m_profileCandidates.clear();

    int weaponsFound = 0;
    for (std::size_t i = 0; i < m_weapons.size(); ++i)
    {
        m_weaponCandidates.push_back(toCandidates(results[i]));
        if (!m_weaponCandidates.back().empty())
        {
            ++weaponsFound;
        }
        else
        {
            // This is the line that settles assumption A-4 for the five weapons
            // that have no entry in weapons.ymt.
            DRS_INFO("resolver: %s hash not found in memory", m_weapons[i].name.c_str());
        }
    }
    for (std::size_t i = 0; i < m_profiles.size(); ++i)
    {
        m_profileCandidates.push_back(toCandidates(results[m_weapons.size() + i]));
        if (m_profileCandidates.back().empty())
        {
            DRS_INFO("resolver: profile %s hash not found in memory",
                     m_profiles[i].name.c_str());
        }
    }

    DRS_INFO("resolver: %d of %zu weapon names present in memory, %.1f MB scanned",
             weaponsFound, m_weapons.size(),
             static_cast<double>(scanned) / (1024.0 * 1024.0));

    if (weaponsFound == 0)
    {
        m_failure = "no weapon name hash found anywhere in memory";
        return false;
    }

    // --- AnimReloadRate ----------------------------------------------------
    std::vector<float> vanillaAnim;
    std::vector<float> calmAnim;
    vanillaAnim.reserve(m_weapons.size());
    calmAnim.reserve(m_weapons.size());
    for (const WeaponTarget& target : m_weapons)
    {
        vanillaAnim.push_back(target.reference != nullptr
                                  ? target.reference->vanillaAnimReloadRate : 0.0f);
        calmAnim.push_back((target.config != nullptr && target.config->calm.animReloadRate.present)
                               ? target.config->calm.animReloadRate.value : 0.0f);
    }

    // Which set of expected values the accepted offset was actually matched
    // against. Tracked explicitly: binding addresses against the other set would
    // silently pick the wrong candidate for every weapon.
    bool animMatchedCalmValues = false;

    // Count, at a given offset, how many weapons have a candidate whose value
    // EXACTLY matches the value expected for that specific weapon. This is what
    // tells a real field from a spurious one: the CALM value set is high-entropy
    // (0.50, 0.45, 0.36, 0.59, ...), so a wrong offset cannot reproduce it, while
    // the stock set is only 1.00/1.30 and a field of unrelated ~1.0 floats can
    // match it by accident (the 0x06FC trap in the first in-game log, which is
    // why a manual ForceAnimReloadRateOffset was needed on 1.0).
    const DefaultsSettings& animDefaults = config.defaults();
    auto exactHitsAt = [&](const std::vector<float>& expected, std::uint32_t offset) -> int {
        int hits = 0;
        for (std::size_t i = 0; i < m_weaponCandidates.size(); ++i)
        {
            const float want = (i < expected.size()) ? expected[i] : 0.0f;
            if (want <= 0.0f)
            {
                continue;
            }
            for (const Candidate& candidate : m_weaponCandidates[i])
            {
                if (candidate.readableSpan < static_cast<std::size_t>(offset) + 4u)
                {
                    continue;
                }
                float value = 0.0f;
                if (!MemScan::readFloat(candidate.address + offset, value))
                {
                    continue;
                }
                if (closeEnough(value, want, animDefaults.vanillaEpsilon))
                {
                    ++hits;
                    break;
                }
            }
        }
        return hits;
    };

    if (memory.forceAnimOffset >= 0)
    {
        m_animDiscovery               = DiscoveryResult();
        m_animDiscovery.ok            = true;
        m_animDiscovery.offset        = static_cast<std::uint32_t>(memory.forceAnimOffset);
        m_animDiscovery.signatureUsed = "forced by config";
        // Even with a pinned offset, decide which value set actually lives there,
        // so binding picks the right candidate per weapon. 1.0 always bound
        // against the STOCK set here, although a slowed weapons.ymt puts the CALM
        // values at the real offset - so the wrong structure could be bound.
        const int vHits = exactHitsAt(vanillaAnim, m_animDiscovery.offset);
        const int cHits = exactHitsAt(calmAnim, m_animDiscovery.offset);
        animMatchedCalmValues = (cHits > vHits);
        DRS_INFO("resolver: AnimReloadRate offset pinned to 0x%04X by [Memory] "
                 "(stock hits=%d, calm hits=%d -> bind against %s)",
                 m_animDiscovery.offset, vHits, cHits,
                 animMatchedCalmValues ? "calm" : "stock");
    }
    else
    {
        // Run BOTH passes and keep the stronger one (D-4). On a slowed
        // weapons.ymt the calm pass wins with many exact hits; on a clean install
        // the CALM values are not in memory, the calm pass finds nothing and the
        // stock pass wins. Both deployments resolve without a forced offset.
        const DiscoveryResult stockPass = discoverOffset("AnimReloadRate", m_weaponCandidates,
                                                         vanillaAnim, "stock", config);
        const DiscoveryResult calmPass  = discoverOffset("AnimReloadRate", m_weaponCandidates,
                                                         calmAnim, "calm profile", config);
        if (stockPass.ok && calmPass.ok)
        {
            // A tie goes to calm: its signature is higher-entropy, so an equal
            // hit count is stronger evidence for it than for stock.
            animMatchedCalmValues = (calmPass.signatureHits >= stockPass.signatureHits);
        }
        else if (calmPass.ok)
        {
            animMatchedCalmValues = true;
        }
        else if (stockPass.ok)
        {
            animMatchedCalmValues = false;
        }
        else
        {
            animMatchedCalmValues = (calmPass.signatureHits > stockPass.signatureHits);
        }

        m_animDiscovery = animMatchedCalmValues ? calmPass : stockPass;

        DRS_INFO("resolver: AnimReloadRate chose the %s pass "
                 "(stock: ok=%d sig=%d off=0x%04X | calm: ok=%d sig=%d off=0x%04X)",
                 animMatchedCalmValues ? "calm" : "stock",
                 stockPass.ok ? 1 : 0, stockPass.signatureHits, stockPass.offset,
                 calmPass.ok ? 1 : 0, calmPass.signatureHits, calmPass.offset);
    }

    if (!m_animDiscovery.ok)
    {
        m_failure = "could not identify the AnimReloadRate field with enough confidence";
        return false;
    }

    std::vector<std::uint8_t*> chosen;
    bindAddresses(m_weaponCandidates,
                  animMatchedCalmValues ? calmAnim : vanillaAnim,
                  m_animDiscovery.offset, chosen, config);
    // Every binding is either CONFIRMED (the value at the offset equals the value
    // this weapon is expected to have) or PLAUSIBLE ONLY (no expected value is
    // known - the five weapons absent from weapons.ymt - or none matched, so the
    // first candidate with a sane float was taken). A plausible-only binding is
    // kept only if its value looks like a reload rate at all; otherwise it is
    // dropped rather than risk writing into an unrelated structure. Each decision
    // is logged, so a player's log shows exactly which weapons are certain.
    const std::vector<float>& expectedAnim = animMatchedCalmValues ? calmAnim : vanillaAnim;
    constexpr float kPlausibleRateMin = 0.10f;   // slowest shipped CALM preset is 0.21
    constexpr float kPlausibleRateMax = 3.00f;   // stock tops out at 1.30
    int confirmed     = 0;
    int plausibleOnly = 0;
    int dropped       = 0;
    for (std::size_t i = 0; i < m_weapons.size(); ++i)
    {
        WeaponTarget& target = m_weapons[i];
        target.nameAddress  = chosen[i];
        target.inMainModule = MemScan::isInsideMainModule(chosen[i]);
        target.anim.address =
            (chosen[i] != nullptr) ? chosen[i] + m_animDiscovery.offset : nullptr;

        if (target.anim.address == nullptr)
        {
            if (!m_weaponCandidates[i].empty())
            {
                DRS_INFO("resolver: %s hash present, but no candidate has a plausible "
                         "value at the offset - not patched", target.name.c_str());
            }
            continue;
        }

        float value = 0.0f;
        const bool  readable = MemScan::readFloat(target.anim.address, value);
        const float want     = (i < expectedAnim.size()) ? expectedAnim[i] : 0.0f;
        if (readable && want > 0.0f && closeEnough(value, want, animDefaults.vanillaEpsilon))
        {
            ++confirmed;
            continue;
        }
        if (readable && std::isfinite(value) &&
            value >= kPlausibleRateMin && value <= kPlausibleRateMax)
        {
            ++plausibleOnly;
            DRS_INFO("resolver: %s bound by plausibility only (value %.4f, no exact "
                     "reference) - verify its reload in game", target.name.c_str(), value);
            continue;
        }
        ++dropped;
        DRS_INFO("resolver: %s dropped - value %.4f at the offset does not look like a "
                 "reload rate", target.name.c_str(), readable ? value : 0.0f);
        target.nameAddress  = nullptr;
        target.anim.address = nullptr;
    }
    DRS_INFO("resolver: AnimReloadRate bindings: %d confirmed, %d plausible only, %d dropped",
             confirmed, plausibleOnly, dropped);

    // --- LoopRate and TimeBetweenBulletsInLoop ------------------------------
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
        m_loopDiscovery = DiscoveryResult();
        m_loopDiscovery.ok            = true;
        m_loopDiscovery.offset        = static_cast<std::uint32_t>(memory.forceLoopOffset);
        m_loopDiscovery.signatureUsed = "forced by config";
        DRS_INFO("resolver: LoopRate offset pinned to 0x%04X by [Memory]",
                 m_loopDiscovery.offset);
    }
    else
    {
        m_loopDiscovery = discoverOffset("LoopRate", m_profileCandidates,
                                         vanillaLoop, "stock", config);
    }

    if (memory.forceTimeOffset >= 0)
    {
        m_timeDiscovery = DiscoveryResult();
        m_timeDiscovery.ok            = true;
        m_timeDiscovery.offset        = static_cast<std::uint32_t>(memory.forceTimeOffset);
        m_timeDiscovery.signatureUsed = "forced by config";
        DRS_INFO("resolver: TimeBetweenBulletsInLoop offset pinned to 0x%04X by [Memory]",
                 m_timeDiscovery.offset);
    }
    else
    {
        m_timeDiscovery = discoverOffset("TimeBetweenBulletsInLoop", m_profileCandidates,
                                         vanillaTime, "stock", config);
    }

    if (m_loopDiscovery.ok && m_timeDiscovery.ok)
    {
        std::vector<std::uint8_t*> loopChosen;
        bindAddresses(m_profileCandidates, vanillaLoop, m_loopDiscovery.offset,
                      loopChosen, config);
        for (std::size_t i = 0; i < m_profiles.size(); ++i)
        {
            m_profiles[i].nameAddress  = loopChosen[i];
            m_profiles[i].inMainModule = MemScan::isInsideMainModule(loopChosen[i]);
            if (loopChosen[i] == nullptr)
            {
                continue;
            }
            m_profiles[i].loop[0].address = loopChosen[i] + m_loopDiscovery.offset;
            m_profiles[i].time[0].address = loopChosen[i] + m_timeDiscovery.offset;
            m_profiles[i].conditions      = 1;
        }

        if (memory.patchAllConditions)
        {
            discoverConditionStride(config);
        }
        else
        {
            DRS_INFO("resolver: PatchAllConditions = 0, only GoodCondition is patched");
        }
    }
    else
    {
        DRS_INFO("resolver: sectioned reload fields not identified; the mod will still "
                 "change AnimReloadRate, which is the dominant term for most weapons");
    }

    return true;
}

bool WeaponPatcher::discoverConditionStride(const Config& config)
{
    const DefaultsSettings& defaults = config.defaults();

    std::uint32_t bestStride = 0u;
    int           bestScore  = 0;

    for (std::uint32_t stride = 16u; stride <= 512u; stride += 4u)
    {
        int score = 0;
        for (std::size_t i = 0; i < m_profiles.size(); ++i)
        {
            const ProfileTarget& profile = m_profiles[i];
            if (profile.loop[0].address == nullptr || profile.reference == nullptr)
            {
                continue;
            }
            bool allMatch = true;
            for (int c = 1; c < kConditionCount; ++c)
            {
                const std::uint8_t* address =
                    profile.loop[0].address + static_cast<std::size_t>(stride) * c;
                float value = 0.0f;
                if (!MemScan::isCommittedReadable(address, sizeof(float)) ||
                    !MemScan::readFloat(address, value) ||
                    !closeEnough(value, profile.reference->loopRate[c], defaults.vanillaEpsilon))
                {
                    allMatch = false;
                    break;
                }
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

    // Needs a clear majority of profiles, not one lucky hit.
    const int required = std::max(3, static_cast<int>(m_profiles.size()) / 2);
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
            profile.loop[c].address =
                profile.loop[0].address + static_cast<std::size_t>(bestStride) * c;
            profile.time[c].address =
                profile.time[0].address + static_cast<std::size_t>(bestStride) * c;
        }
        profile.conditions = kConditionCount;
    }
    return true;
}

// ---------------------------------------------------------------------------

void WeaponPatcher::takeSnapshot()
{
    auto snap = [](FieldTarget& field, const char* what, const char* owner) {
        if (field.address == nullptr)
        {
            return;
        }
        float value = 0.0f;
        if (!MemScan::isAcceptableTarget(field.address, sizeof(float)) ||
            !MemScan::readFloat(field.address, value) ||
            !std::isfinite(value) || value < kLiveValueMin || value > kLiveValueMax)
        {
            field.unpatchable = true;
            DRS_ERROR("snapshot failed for %s %s: address unusable or value out of range",
                      owner, what);
            return;
        }
        field.snapshot    = value;
        field.hasSnapshot = true;
    };

    for (WeaponTarget& target : m_weapons)
    {
        snap(target.anim, "AnimReloadRate", target.name.c_str());
    }
    for (ProfileTarget& profile : m_profiles)
    {
        for (int c = 0; c < profile.conditions; ++c)
        {
            snap(profile.loop[c], "LoopRate", profile.name.c_str());
            snap(profile.time[c], "TimeBetweenBulletsInLoop", profile.name.c_str());
        }
    }

    // Three weapons' worth of proof that the snapshot is real, as required by
    // the acceptance checklist.
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
    m_ready   = false;
    m_failure.clear();

    if (!collectTargets(config))
    {
        m_failure = "no weapons configured";
        return false;
    }

    if (!m_scan.buildRegionList(false, config.memory().maxScanBytes))
    {
        m_failure = "no scannable memory regions";
        return false;
    }

    if (!discoverAll(config))
    {
        // One retry including file-backed regions, in case the weapon pool does
        // not live in a plain private allocation on this build.
        DRS_INFO("resolver: retry: including mapped regions");
        if (!m_scan.buildRegionList(true, config.memory().maxScanBytes) ||
            !discoverAll(config))
        {
            if (m_failure.empty())
            {
                m_failure = "resolution failed";
            }
            return false;
        }
    }

    takeSnapshot();

    const int weapons = resolvedWeapons();
    if (weapons == 0)
    {
        m_failure = "no weapon survived snapshot validation";
        return false;
    }

    DRS_INFO("resolver: ready, %d weapons and %d sectioned profiles patchable",
             weapons, resolvedProfiles());
    m_ready = true;
    return true;
}

// ---------------------------------------------------------------------------

bool WeaponPatcher::writeField(FieldTarget& field, float value, const char* what,
                               const Config& config)
{
    if (field.address == nullptr || field.unpatchable || !field.hasSnapshot)
    {
        return false;
    }

    const DefaultsSettings& defaults = config.defaults();

    if (!std::isfinite(value) || value <= 0.0f)
    {
        DRS_ERROR("%s: refusing to write a non-finite or non-positive value", what);
        return false;
    }
    float clamped = value;
    if (clamped < defaults.minValue) { clamped = defaults.minValue; }
    if (clamped > defaults.maxValue) { clamped = defaults.maxValue; }
    if (!closeEnough(clamped, value, 0.0001f))
    {
        DRS_INFO("%s: clamped %.4f to %.4f by [MinValue, MaxValue]", what, value, clamped);
    }

    if (!MemScan::isAcceptableTarget(field.address, sizeof(float)))
    {
        field.unpatchable = true;
        DRS_ERROR("%s: address rejected by validation, target dropped for this session", what);
        return false;
    }

    float current = 0.0f;
    if (!MemScan::readFloat(field.address, current) || !std::isfinite(current) ||
        current < kLiveValueMin || current > kLiveValueMax)
    {
        field.unpatchable = true;
        DRS_ERROR("%s: current value not a plausible rate, target dropped", what);
        return false;
    }
    DRS_DEBUG("%s: validated", what);

    if (!field.firstWriteDone)
    {
        if (!closeEnough(current, field.snapshot, 0.0005f))
        {
            field.unpatchable = true;
            DRS_ERROR("%s: first write aborted, value is %.4f but the boot snapshot was "
                      "%.4f - either the offset is wrong or another mod writes here. "
                      "Dropping this target, the rest keep working.",
                      what, current, field.snapshot);
            return false;
        }
        DRS_DEBUG("%s: snapshot compare ok", what);
    }

    // FR-37: change page protection only if the page is NOT writable. The RAGE
    // heap is already read-write, so in practice no change is made. 1.0 called
    // VirtualProtect twice per field unconditionally (and asked for an EXECUTE
    // right data never needs): 44 system calls per state change on the game's
    // main thread, felt as a hitch on every CALM/COMBAT switch. When a change is
    // needed, it is PAGE_READWRITE - never executable - and it is restored.
    DWORD previousProtect = 0;
    bool  protectChanged  = false;
    if (MemScan::isWritable(field.address, sizeof(float)))
    {
        DRS_DEBUG("%s: page already writable, protection left untouched", what);
    }
    else
    {
        if (!VirtualProtect(field.address, sizeof(float), PAGE_READWRITE, &previousProtect))
        {
            field.unpatchable = true;
            DRS_ERROR("%s: could not make the page writable, target dropped", what);
            return false;
        }
        protectChanged = true;
        DRS_DEBUG("%s: protect changed", what);
    }

    const bool written = MemScan::writeFloat(field.address, clamped);

    if (protectChanged)
    {
        DWORD restored = 0;
        VirtualProtect(field.address, sizeof(float), previousProtect, &restored);
        DRS_DEBUG("%s: protect restored", what);
    }

    if (!written)
    {
        field.unpatchable = true;
        DRS_ERROR("%s: write faulted, target dropped", what);
        return false;
    }

    float readBack = 0.0f;
    if (!MemScan::readFloat(field.address, readBack) ||
        !closeEnough(readBack, clamped, 0.0005f))
    {
        field.unpatchable = true;
        DRS_ERROR("%s: readback mismatch, wrote %.4f read %.4f, target dropped",
                  what, clamped, readBack);
        return false;
    }

    field.firstWriteDone = true;
    field.lastWritten    = clamped;
    DRS_DEBUG("%s: readback %.4f", what, readBack);
    return true;
}

bool WeaponPatcher::restoreField(FieldTarget& field, const char* what)
{
    if (field.address == nullptr || !field.hasSnapshot || !field.firstWriteDone)
    {
        return false;
    }
    if (!MemScan::isAcceptableTarget(field.address, sizeof(float)))
    {
        DRS_ERROR("restore skipped: %s", what);
        return false;
    }

    DWORD previousProtect = 0;
    bool  protectChanged  = false;
    if (!MemScan::isWritable(field.address, sizeof(float)))
    {
        if (!VirtualProtect(field.address, sizeof(float), PAGE_READWRITE, &previousProtect))
        {
            DRS_ERROR("restore skipped: %s (page not writable)", what);
            return false;
        }
        protectChanged = true;
    }

    const bool written = MemScan::writeFloat(field.address, field.snapshot);

    if (protectChanged)
    {
        DWORD restored = 0;
        VirtualProtect(field.address, sizeof(float), previousProtect, &restored);
    }

    if (!written)
    {
        DRS_ERROR("restore skipped: %s (write faulted)", what);
        return false;
    }
    field.firstWriteDone = false;
    return true;
}

// ---------------------------------------------------------------------------

void WeaponPatcher::applyProfile(bool combat, const Config& config)
{
    if (!m_ready)
    {
        return;
    }
    const ULONGLONG applyStart = GetTickCount64();

    const DefaultsSettings& defaults = config.defaults();
    const ProfileSettings&  profiles = config.profiles();

    char label[128] = {};
    int  written    = 0;
    int  skipped    = 0;

    for (WeaponTarget& target : m_weapons)
    {
        if (target.anim.address == nullptr || target.anim.unpatchable)
        {
            continue;
        }
        if (!ownerStillThere(target.nameAddress, target.hash))
        {
            target.anim.unpatchable = true;
            DRS_ERROR("%s: the weapon structure is no longer where it was found "
                      "(name hash changed); target dropped for this session",
                      target.name.c_str());
            ++skipped;
            continue;
        }

        // Which side of the pair the snapshot belongs to. In auto mode the answer
        // comes from comparing the snapshot with the stock reference; in manual
        // mode it comes straight from the config.
        bool snapshotIsVanilla = true;
        if (target.reference != nullptr && target.reference->vanillaAnimReloadRate > 0.0f)
        {
            snapshotIsVanilla = closeEnough(target.anim.snapshot,
                                            target.reference->vanillaAnimReloadRate,
                                            defaults.vanillaEpsilon);
        }

        ValueSource source = ValueSource::Ini;
        if (profiles.mode == ProfileMode::Auto)
        {
            const bool wantIni = combat ? !snapshotIsVanilla : snapshotIsVanilla;
            source = wantIni ? ValueSource::Ini : ValueSource::Snapshot;
        }
        else
        {
            source = combat ? profiles.combatSource : profiles.calmSource;
        }

        float value      = 0.0f;
        bool  haveValue  = false;
        const ProfileValues* configured =
            (target.config != nullptr) ? (combat ? &target.config->combat : &target.config->calm)
                                       : nullptr;

        if (source == ValueSource::Ini && configured != nullptr &&
            configured->animReloadRate.present)
        {
            value     = configured->animReloadRate.value;
            haveValue = true;
        }
        else if (source == ValueSource::Snapshot)
        {
            value     = target.anim.snapshot;
            haveValue = true;
        }

        if (!haveValue)
        {
            const float multiplier = combat ? defaults.combatAnimMul : defaults.calmAnimMul;
            value     = target.anim.snapshot * multiplier;
            haveValue = true;
            DRS_DEBUG("%s: no %s AnimReloadRate in config, falling back to multiplier %.2f",
                      target.name.c_str(), combat ? "COMBAT" : "CALM", multiplier);
        }

        _snprintf_s(label, sizeof(label), _TRUNCATE, "%s %s AnimReloadRate",
                    target.name.c_str(), combat ? "COMBAT" : "CALM");
        if (writeField(target.anim, value, label, config))
        {
            ++written;
        }
        else
        {
            ++skipped;
        }
    }

    for (ProfileTarget& profile : m_profiles)
    {
        if (profile.nameAddress != nullptr && !ownerStillThere(profile.nameAddress, profile.hash))
        {
            for (int c = 0; c < profile.conditions; ++c)
            {
                profile.loop[c].unpatchable = true;
                profile.time[c].unpatchable = true;
            }
            DRS_ERROR("%s: the sectioned-reload structure is no longer where it was "
                      "found; dropped for this session", profile.name.c_str());
            continue;
        }

        const ConditionReference* reference = profile.reference;

        for (int c = 0; c < profile.conditions; ++c)
        {
            auto applyOne = [&](FieldTarget& field, bool isLoop) {
                if (field.address == nullptr || field.unpatchable)
                {
                    return;
                }

                // Which weapon section owns this profile? The first shipped weapon
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

                float base = 0.0f;
                if (owner != nullptr)
                {
                    const ProfileValues& values = combat ? owner->combat : owner->calm;
                    const FieldValue& picked = isLoop ? values.loopRate : values.timeBetween;
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
                if (writeField(field, base * ratio, label, config))
                {
                    ++written;
                }
                else
                {
                    ++skipped;
                }
            };

            applyOne(profile.loop[c], true);
            applyOne(profile.time[c], false);
        }
    }

    DRS_INFO("%s applied: %d fields written, %d skipped, %llu ms",
             combat ? "COMBAT" : "CALM", written, skipped,
             static_cast<unsigned long long>(GetTickCount64() - applyStart));
}

void WeaponPatcher::restoreAll()
{
    char label[128] = {};
    int restored = 0;

    for (WeaponTarget& target : m_weapons)
    {
        _snprintf_s(label, sizeof(label), _TRUNCATE, "%s AnimReloadRate",
                    target.name.c_str());
        if (target.anim.address != nullptr && target.anim.firstWriteDone &&
            !ownerStillThere(target.nameAddress, target.hash))
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

} // namespace drs

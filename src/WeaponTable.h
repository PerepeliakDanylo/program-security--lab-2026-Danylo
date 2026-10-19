// WeaponTable.h — compiled-in reference data, read out of an unmodified
// weapons.ymt on 2026-09-26 and cross-checked line by line against the file.
//
// Why this is compiled in and not only in the INI: these numbers are what lets
// the resolver recognise the right field in memory (DESIGN.md 3.4). If the
// player's INI is missing, rejected or edited into nonsense, discovery must
// still work — otherwise a broken config would turn into "mod silently does
// nothing" instead of "mod falls back to defaults".
//
// These are NOT tuning values. They are stock Rockstar values used as a
// signature. Never write them to memory as if they were a profile.
//
// No dependency on the ScriptHookRDR2 SDK.

#pragma once

#include <cstdint>

namespace drs {

struct WeaponReference
{
    const char* weaponName;      // INI section name, upper case
    const char* profileName;     // CSectionedReloadInfo name, lower case, or nullptr
    std::uint32_t profileHash;   // non-zero only when the profile name is itself a hash
    float vanillaAnimReloadRate; // stock CWeaponInfo::AnimReloadRate, 0 = unknown
    float vanillaLoopRate;       // stock GoodCondition LoopRate, 0 = unknown
    float vanillaTimeBetween;    // stock GoodCondition TimeBetweenBulletsInLoop, 0 = unknown
};

// 24 shipped weapons. The last five have no CWeaponInfo entry in stock data at
// all, so every stock value is 0 = unknown and they take no part in discovery.
// The Rolling Block's sectioned profile is stored under a joaat hash whose
// source string is not in any known dictionary, so it is matched by hash.
// The Carcano's profile is called sniper_carcano, NOT sniperrifle_carcano —
// a config keyed on the weapon name would silently never match it.
inline constexpr WeaponReference kWeaponReference[] = {
    { "WEAPON_RIFLE_VARMINT",            "rifle_varmint",         0u,          1.30f, 2.20f,  0.125f },
    { "WEAPON_REPEATER_CARBINE",         "repeater_carbine",      0u,          1.30f, 2.00f,  0.020f },
    { "WEAPON_REPEATER_WINCHESTER",      "repeater_winchester",   0u,          1.30f, 3.00f,  0.125f },
    { "WEAPON_REPEATER_HENRY",           "repeater_henry",        0u,          1.30f, 3.00f,  0.125f },
    { "WEAPON_RIFLE_BOLTACTION",         "rifle_boltaction",      0u,          1.30f, 3.00f,  0.125f },
    { "WEAPON_RIFLE_SPRINGFIELD",        "rifle_springfield",     0u,          1.00f, 3.00f,  0.125f },
    { "WEAPON_SNIPERRIFLE_ROLLINGBLOCK", nullptr,                 0xDC893365u, 1.00f, 2.25f,  0.125f },
    { "WEAPON_SNIPERRIFLE_CARCANO",      "sniper_carcano",        0u,          1.00f, 3.00f,  0.125f },
    { "WEAPON_REVOLVER_CATTLEMAN",       "revolver_cattleman",    0u,          1.00f, 5.00f,  0.100f },
    { "WEAPON_REVOLVER_SCHOFIELD",       "revolver_schofield",    0u,          1.00f, 3.50f,  0.100f },
    { "WEAPON_REVOLVER_DOUBLEACTION",    "revolver_doubleaction", 0u,          1.00f, 5.00f,  0.100f },
    { "WEAPON_PISTOL_VOLCANIC",          "pistol_volcanic",       0u,          1.00f, 5.00f,  0.100f },
    { "WEAPON_PISTOL_MAUSER",            "pistol_mauser",         0u,          1.00f, 5.00f,  0.100f },
    { "WEAPON_PISTOL_SEMIAUTO",          "pistol_semiauto",       0u,          1.00f, 10.00f, 0.100f },
    { "WEAPON_SHOTGUN_PUMP",             "shotgun_pump",          0u,          1.00f, 3.00f,  0.125f },
    { "WEAPON_SHOTGUN_REPEATING",        "shotgun_repeating",     0u,          1.00f, 3.50f,  0.125f },
    { "WEAPON_SHOTGUN_SEMIAUTO",         "shotgun_semiauto",      0u,          1.00f, 3.00f,  0.125f },
    { "WEAPON_SHOTGUN_DOUBLEBARREL",     "shotgun_doublebarrel",  0u,          1.00f, 3.00f,  0.125f },
    { "WEAPON_SHOTGUN_SAWEDOFF",         "shotgun_sawedoff",      0u,          1.00f, 3.00f,  0.125f },
    { "WEAPON_REVOLVER_LEMAT",           nullptr,                 0u,          0.0f,  0.0f,   0.0f },
    { "WEAPON_REVOLVER_NAVY",            nullptr,                 0u,          0.0f,  0.0f,   0.0f },
    { "WEAPON_PISTOL_M1899",             nullptr,                 0u,          0.0f,  0.0f,   0.0f },
    { "WEAPON_REPEATER_EVANS",           nullptr,                 0u,          0.0f,  0.0f,   0.0f },
    { "WEAPON_RIFLE_ELEPHANT",           nullptr,                 0u,          0.0f,  0.0f,   0.0f },
};

// Stock per-condition LoopRate and TimeBetweenBulletsInLoop, in the order
// GoodCondition, WornCondition, GoodConditionOH, WornConditionOH.
//
// Note the counter-intuitive part: WornCondition often has a HIGHER LoopRate
// than GoodCondition (varmint 3.0 vs 2.2). The wear penalty lives in
// TimeBetweenBulletsInLoop (0.225 vs 0.125), not in LoopRate. A mod that simply
// lowers LoopRate in every block inverts clean vs worn.
struct ConditionReference
{
    const char*   profileName;
    std::uint32_t profileHash;
    float         loopRate[4];
    float         timeBetween[4];
};

inline constexpr ConditionReference kConditionReference[] = {
    { "rifle_varmint",         0u,          { 2.20f, 3.00f, 1.80f, 1.65f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "repeater_carbine",      0u,          { 2.00f, 2.00f, 2.00f, 1.70f }, { 0.020f, 0.025f, 0.020f, 0.025f } },
    { "repeater_winchester",   0u,          { 3.00f, 3.00f, 2.00f, 1.75f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "repeater_henry",        0u,          { 3.00f, 3.00f, 2.00f, 1.75f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "rifle_boltaction",      0u,          { 3.00f, 3.00f, 2.00f, 2.00f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "rifle_springfield",     0u,          { 3.00f, 2.50f, 3.00f, 2.50f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { nullptr,                 0xDC893365u, { 2.25f, 1.75f, 2.25f, 1.75f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "sniper_carcano",        0u,          { 3.00f, 3.00f, 2.50f, 2.25f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "revolver_cattleman",    0u,          { 5.00f, 3.50f, 2.50f, 2.20f }, { 0.100f, 0.100f, 0.100f, 0.100f } },
    { "revolver_schofield",    0u,          { 3.50f, 3.50f, 3.50f, 3.50f }, { 0.100f, 0.100f, 0.100f, 0.100f } },
    { "revolver_doubleaction", 0u,          { 5.00f, 3.50f, 3.00f, 2.80f }, { 0.100f, 0.100f, 0.100f, 0.100f } },
    { "pistol_volcanic",       0u,          { 5.00f, 3.50f, 1.70f, 1.50f }, { 0.100f, 0.100f, 0.100f, 0.100f } },
    { "pistol_mauser",         0u,          { 5.00f, 3.50f, 2.50f, 2.20f }, { 0.100f, 0.100f, 0.100f, 0.100f } },
    { "pistol_semiauto",       0u,          { 10.00f, 10.00f, 10.00f, 10.00f }, { 0.100f, 0.100f, 0.100f, 0.100f } },
    { "shotgun_pump",          0u,          { 3.00f, 3.00f, 3.50f, 3.20f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "shotgun_repeating",     0u,          { 3.50f, 3.25f, 3.75f, 3.55f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "shotgun_semiauto",      0u,          { 3.00f, 3.00f, 3.50f, 3.20f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "shotgun_doublebarrel",  0u,          { 3.00f, 3.00f, 2.00f, 1.80f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
    { "shotgun_sawedoff",      0u,          { 3.00f, 3.00f, 2.30f, 2.00f }, { 0.125f, 0.225f, 0.100f, 0.100f } },
};

constexpr int kConditionCount = 4;
constexpr const char* kConditionName[kConditionCount] = {
    "GoodCondition", "WornCondition", "GoodConditionOH", "WornConditionOH"
};

inline bool sameCString(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return a == b;
    }
    while (*a != '\0' && *b != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == *b;
}

inline const WeaponReference* findWeaponReference(const char* upperWeaponName)
{
    for (const WeaponReference& row : kWeaponReference)
    {
        if (sameCString(row.weaponName, upperWeaponName))
        {
            return &row;
        }
    }
    return nullptr;
}

inline const ConditionReference* findConditionReference(const char* profileName,
                                                        std::uint32_t profileHash)
{
    for (const ConditionReference& row : kConditionReference)
    {
        if (profileHash != 0u && row.profileHash == profileHash)
        {
            return &row;
        }
        if (profileHash == 0u && profileName != nullptr &&
            sameCString(row.profileName, profileName))
        {
            return &row;
        }
    }
    return nullptr;
}

} // namespace drs

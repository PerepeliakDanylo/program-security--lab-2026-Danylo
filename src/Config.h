// Config.h — the INI is untrusted input, and this header treats it that way.
//
// Everything a player, a mod pack author, or anyone with write access to the game
// folder can put in DynamicReloadSpeed.ini arrives here first. The parser is
// deliberately forgiving about SYNTAX (comments, missing keys, junk numbers all
// fall back to defaults with a log line) and deliberately strict about SIZE
// (an unbounded parser is a denial-of-service vector at game start).
//
// What it will never accept: a key that names an address or a base pointer.
// See docs/DESIGN.md section 3 — that channel was removed by construction, not
// by validation after the fact.
//
// Keys added in 1.2 (all optional, an INI without them gets the defaults below):
//   [Signals] AttackingHumans, ShootingSustainsCombat
//   [Memory]  IncludeUnlistedGuns, PatchSectionedReload
// MaxPedsScanned keeps its name but now means "how many of the NEAREST peds in
// ThreatRadius are checked"; the ped list itself is always read in full.
//
// No dependency on the ScriptHookRDR2 SDK.

#pragma once

#include "Logger.h"

#include <cstdint>
#include <string>
#include <vector>

namespace drs {

enum class ProfileMode { Auto, Manual };
enum class ValueSource { Ini, Snapshot, Multiplier };

struct FieldValue
{
    float value   = 0.0f;
    bool  present = false;

    void set(float v) { value = v; present = true; }
};

struct ProfileValues
{
    FieldValue animReloadRate;
    FieldValue loopRate;
    FieldValue timeBetween;

    bool complete() const
    {
        return animReloadRate.present && loopRate.present && timeBetween.present;
    }
};

struct WeaponEntry
{
    std::string   name;                    // as written in the INI, upper case by convention
    std::uint32_t hash = 0u;               // joaat of the lower-cased name
    ProfileValues calm;
    ProfileValues combat;
    FieldValue    vanillaAnimReloadRate;   // from [Vanilla], or from the built-in table
};

struct GeneralSettings
{
    bool  enabled             = true;
    float cooldownSeconds     = 5.0f;
    int   detectorHz          = 4;
    int   pedScanHz           = 2;
    float threatRadius        = 80.0f;
    int   maxPedsScanned      = 32;     // nearest N peds inside threatRadius (1.2)
    float damageMemorySeconds = 8.0f;   // also how long "you attacked a person" lasts
    bool  disableInOnline     = true;
    bool  ignoreVersionCheck  = false;
};

struct SignalSettings
{
    bool playerShooting         = true;
    bool playerAiming           = true;
    bool melee                  = true;
    bool recentDamage           = true;
    bool hostileNearby          = true;
    bool wantedByLaw            = true;
    bool deadEye                = false;
    bool attackingHumans        = true;   // 1.2: a shot at a living person counts
    bool shootingSustainsCombat = true;   // 1.2: own shots keep an existing fight on
};

struct ProfileSettings
{
    ProfileMode mode         = ProfileMode::Auto;
    ValueSource calmSource   = ValueSource::Ini;
    ValueSource combatSource = ValueSource::Snapshot;
};

struct DefaultsSettings
{
    float calmAnimMul     = 0.50f;   // lower = slower
    float calmLoopMul     = 1.00f;   // must stay 1.0, see DESIGN.md section 1
    float calmTimeMul     = 2.00f;   // must be 1 / calmAnimMul
    float combatAnimMul   = 1.00f;
    float combatLoopMul   = 1.00f;
    float combatTimeMul   = 1.00f;
    float vanillaEpsilon  = 0.02f;
    float minValue        = 0.05f;
    // 12.0 and not 8.0: stock LoopRate for WEAPON_PISTOL_SEMIAUTO is 10.0, so a
    // cap below that would clamp a genuine stock value on the way back to COMBAT
    // and leave that pistol permanently slowed.
    float maxValue        = 12.00f;
};

struct MemorySettings
{
    std::uint32_t maxOffsetWindow      = 4096u;
    std::uint32_t offsetStep           = 4u;
    int           minConsensusWeapons  = 12;
    float         consensusMargin      = 1.5f;
    std::uint64_t maxScanBytes         = 0ull;   // 0 = no limit
    bool          patchAllConditions   = true;
    bool          includeUnlistedGuns  = true;   // 1.2: switch guns found by class
    bool          patchSectionedReload = false;  // 1.2: off - see DESIGN.md 3.8

    // -1 means "auto". Any other value must lie inside [0, maxOffsetWindow).
    std::int32_t  forceAnimOffset = -1;
    std::int32_t  forceLoopOffset = -1;
    std::int32_t  forceTimeOffset = -1;
};

struct DebugSettings
{
    LogLevel      logLevel           = LogLevel::Info;
    std::string   logFile            = "DynamicReloadSpeed.log";
    std::uint32_t maxLogSizeMb       = 32u;
    bool          onScreenState      = false;
    int           hotkeyToggleMod    = 0x76;   // VK_F7
    int           hotkeyForceCombat  = 0x77;   // VK_F8
    int           hotkeyReloadConfig = 0x78;   // VK_F9
};

// Hard limits. Exceeding any of them rejects the WHOLE file: a partially applied
// config is worse than a known-good default set, because nobody can tell which
// half took effect.
struct ParseLimits
{
    static constexpr std::size_t kMaxFileBytes  = 1024u * 1024u;  // 1 MB
    static constexpr std::size_t kMaxLineChars  = 4096u;
    static constexpr std::size_t kMaxSections   = 512u;
};

class Config
{
public:
    // Reads <plugin directory>/<fileName>. fileName is a bare name; any directory
    // part is stripped. Returns false if the file was rejected or missing — in
    // that case the object still holds a complete, usable set of built-in
    // defaults, so the caller keeps running.
    bool loadFromFile(const std::string& fileName);

    void applyBuiltInDefaults();

    const GeneralSettings&  general()  const noexcept { return m_general; }
    const SignalSettings&   signals()  const noexcept { return m_signals; }
    const ProfileSettings&  profiles() const noexcept { return m_profiles; }
    const DefaultsSettings& defaults() const noexcept { return m_defaults; }
    const MemorySettings&   memory()   const noexcept { return m_memory; }
    const DebugSettings&    debug()    const noexcept { return m_debug; }

    const std::vector<WeaponEntry>& weapons() const noexcept { return m_weapons; }
    const std::vector<std::string>& supportedBuilds() const noexcept { return m_supportedBuilds; }

    bool loadedFromFile() const noexcept { return m_loadedFromFile; }
    int  warningCount()   const noexcept { return m_warnings; }

    // Longest configured name that the actual weapon name starts with.
    // WEAPON_REVOLVER_CATTLEMAN_MEXICAN therefore resolves to the
    // WEAPON_REVOLVER_CATTLEMAN section.
    const WeaponEntry* matchWeapon(const std::string& actualWeaponName) const;

    // Weapons that carry a known stock AnimReloadRate, used as the signature the
    // resolver matches against. See DESIGN.md section 3.4.
    std::vector<const WeaponEntry*> signatureWeapons() const;

    static int  parseVirtualKey(const std::string& text, int fallback);
    static bool parseBool(const std::string& text, bool fallback, bool& ok);
    static bool parseFloat(const std::string& text, float& out);
    static bool parseInt(const std::string& text, long& out);

private:
    void  warn(const char* format, ...);
    void  applySectionKey(const std::string& section, const std::string& key,
                          const std::string& value);
    WeaponEntry& weaponFor(const std::string& sectionName);
    void  seedVanillaTable();
    void  validateAfterLoad();

    GeneralSettings          m_general;
    SignalSettings           m_signals;
    ProfileSettings          m_profiles;
    DefaultsSettings         m_defaults;
    MemorySettings           m_memory;
    DebugSettings            m_debug;
    std::vector<WeaponEntry> m_weapons;
    std::vector<std::string> m_supportedBuilds;

    bool m_loadedFromFile = false;
    int  m_warnings       = 0;
};

} // namespace drs

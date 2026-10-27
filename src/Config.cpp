#include "Config.h"
#include "Joaat.h"
#include "PluginPaths.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace drs {

namespace {

struct VanillaRow
{
    const char* name;
    float       animReloadRate;
};

// Stock AnimReloadRate, read out of an unmodified weapons.ymt on 2026-09-26.
// In stock data this field takes exactly two values, 1.00 and 1.30, and that
// split is the signature the resolver matches against (DESIGN.md 3.4).
// Compiled in so the mod still resolves when the INI is missing or rejected.
// The five weapons that have no CWeaponInfo entry at all are deliberately absent:
// their stock value is unknown and guessing it would poison the signature.
const VanillaRow kBuiltInVanilla[] = {
    { "WEAPON_RIFLE_VARMINT",            1.30f },
    { "WEAPON_REPEATER_CARBINE",         1.30f },
    { "WEAPON_REPEATER_WINCHESTER",      1.30f },
    { "WEAPON_REPEATER_HENRY",           1.30f },
    { "WEAPON_RIFLE_BOLTACTION",         1.30f },
    { "WEAPON_RIFLE_SPRINGFIELD",        1.00f },
    { "WEAPON_SNIPERRIFLE_ROLLINGBLOCK", 1.00f },
    { "WEAPON_SNIPERRIFLE_CARCANO",      1.00f },
    { "WEAPON_REVOLVER_CATTLEMAN",       1.00f },
    { "WEAPON_REVOLVER_SCHOFIELD",       1.00f },
    { "WEAPON_REVOLVER_DOUBLEACTION",    1.00f },
    { "WEAPON_PISTOL_VOLCANIC",          1.00f },
    { "WEAPON_PISTOL_MAUSER",            1.00f },
    { "WEAPON_PISTOL_SEMIAUTO",          1.00f },
    { "WEAPON_SHOTGUN_PUMP",             1.00f },
    { "WEAPON_SHOTGUN_REPEATING",        1.00f },
    { "WEAPON_SHOTGUN_SEMIAUTO",         1.00f },
    { "WEAPON_SHOTGUN_DOUBLEBARREL",     1.00f },
    { "WEAPON_SHOTGUN_SAWEDOFF",         1.00f },
};

std::string trim(const std::string& text)
{
    std::size_t first = 0;
    while (first < text.size() &&
           std::isspace(static_cast<unsigned char>(text[first])) != 0)
    {
        ++first;
    }
    std::size_t last = text.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(text[last - 1])) != 0)
    {
        --last;
    }
    return text.substr(first, last - first);
}

std::string toUpper(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return text;
}

std::string toLower(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool iequals(const std::string& a, const char* b)
{
    return _stricmp(a.c_str(), b) == 0;
}

// A section name is a weapon section if it starts with WEAPON_ and is not one of
// the reserved section names.
bool isWeaponSection(const std::string& section)
{
    return section.rfind("WEAPON_", 0) == 0;
}

} // namespace

bool Config::parseFloat(const std::string& text, float& out)
{
    if (text.empty())
    {
        return false;
    }
    char* end = nullptr;
    const double value = std::strtod(text.c_str(), &end);
    if (end == text.c_str())
    {
        return false;
    }
    while (*end != '\0' && std::isspace(static_cast<unsigned char>(*end)) != 0)
    {
        ++end;
    }
    if (*end != '\0')
    {
        return false;
    }
    if (!std::isfinite(value))
    {
        return false;   // "nan" and "inf" are spelled out and must never get through
    }
    out = static_cast<float>(value);
    return true;
}

bool Config::parseInt(const std::string& text, long& out)
{
    if (text.empty())
    {
        return false;
    }
    char* end = nullptr;
    const long value = std::strtol(text.c_str(), &end, 0);
    if (end == text.c_str())
    {
        return false;
    }
    while (*end != '\0' && std::isspace(static_cast<unsigned char>(*end)) != 0)
    {
        ++end;
    }
    if (*end != '\0')
    {
        return false;
    }
    out = value;
    return true;
}

bool Config::parseBool(const std::string& text, bool fallback, bool& ok)
{
    ok = true;
    if (iequals(text, "1") || iequals(text, "true") || iequals(text, "yes") ||
        iequals(text, "on"))
    {
        return true;
    }
    if (iequals(text, "0") || iequals(text, "false") || iequals(text, "no") ||
        iequals(text, "off"))
    {
        return false;
    }
    ok = false;
    return fallback;
}

int Config::parseVirtualKey(const std::string& text, int fallback)
{
    const std::string value = toUpper(trim(text));
    if (value.empty())
    {
        return fallback;
    }

    if (value.size() >= 2 && value[0] == 'F')
    {
        long index = 0;
        if (parseInt(value.substr(1), index) && index >= 1 && index <= 24)
        {
            return 0x70 + static_cast<int>(index) - 1;   // VK_F1 == 0x70
        }
    }
    if (value.size() == 1)
    {
        const char c = value[0];
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))
        {
            return static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    // Raw virtual-key code, decimal or 0x-prefixed.
    long raw = 0;
    if (parseInt(value, raw) && raw > 0 && raw < 0xFF)
    {
        return static_cast<int>(raw);
    }
    return fallback;
}

void Config::warn(const char* format, ...)
{
    ++m_warnings;

    char body[512] = {};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(body, sizeof(body), _TRUNCATE, format, args);
    va_end(args);

    DRS_INFO("config: %s", body);
}

void Config::seedVanillaTable()
{
    for (const VanillaRow& row : kBuiltInVanilla)
    {
        WeaponEntry& entry = weaponFor(row.name);
        entry.vanillaAnimReloadRate.set(row.animReloadRate);
    }
}

void Config::applyBuiltInDefaults()
{
    m_general  = GeneralSettings();
    m_signals  = SignalSettings();
    m_profiles = ProfileSettings();
    m_defaults = DefaultsSettings();
    m_memory   = MemorySettings();
    m_debug    = DebugSettings();
    m_weapons.clear();
    m_supportedBuilds.clear();
    m_warnings       = 0;
    m_loadedFromFile = false;

    seedVanillaTable();
}

WeaponEntry& Config::weaponFor(const std::string& sectionName)
{
    const std::string name = toUpper(sectionName);
    for (WeaponEntry& entry : m_weapons)
    {
        if (entry.name == name)
        {
            return entry;
        }
    }
    WeaponEntry entry;
    entry.name = name;
    entry.hash = joaat(toLower(name).c_str());
    m_weapons.push_back(entry);
    return m_weapons.back();
}

void Config::applySectionKey(const std::string& section, const std::string& key,
                             const std::string& value)
{
    bool  boolOk = true;
    float number = 0.0f;
    long  integer = 0;

    auto floatKey = [&](const char* name, float& target, float low, float high) -> bool {
        if (!iequals(key, name))
        {
            return false;
        }
        if (!parseFloat(value, number))
        {
            warn("[%s] %s = '%s' is not a number, keeping %.4f",
                 section.c_str(), name, value.c_str(), target);
            return true;
        }
        if (number < low || number > high)
        {
            warn("[%s] %s = %.4f is outside [%.4f, %.4f], keeping %.4f",
                 section.c_str(), name, number, low, high, target);
            return true;
        }
        target = number;
        return true;
    };

    auto intKey = [&](const char* name, int& target, long low, long high) -> bool {
        if (!iequals(key, name))
        {
            return false;
        }
        if (!parseInt(value, integer))
        {
            warn("[%s] %s = '%s' is not a number, keeping %d",
                 section.c_str(), name, value.c_str(), target);
            return true;
        }
        if (integer < low || integer > high)
        {
            warn("[%s] %s = %ld is outside [%ld, %ld], keeping %d",
                 section.c_str(), name, integer, low, high, target);
            return true;
        }
        target = static_cast<int>(integer);
        return true;
    };

    auto boolKey = [&](const char* name, bool& target) -> bool {
        if (!iequals(key, name))
        {
            return false;
        }
        const bool parsed = parseBool(value, target, boolOk);
        if (!boolOk)
        {
            warn("[%s] %s = '%s' is not a boolean, keeping %d",
                 section.c_str(), name, value.c_str(), target ? 1 : 0);
            return true;
        }
        target = parsed;
        return true;
    };

    if (iequals(section, "General"))
    {
        if (boolKey("Enabled", m_general.enabled)) { return; }
        if (floatKey("CooldownSeconds", m_general.cooldownSeconds, 0.0f, 120.0f)) { return; }
        if (intKey("DetectorHz", m_general.detectorHz, 1, 60)) { return; }
        if (intKey("PedScanHz", m_general.pedScanHz, 1, 30)) { return; }
        if (floatKey("ThreatRadius", m_general.threatRadius, 1.0f, 500.0f)) { return; }
        if (intKey("MaxPedsScanned", m_general.maxPedsScanned, 1, 256)) { return; }
        if (floatKey("DamageMemorySeconds", m_general.damageMemorySeconds, 0.0f, 120.0f)) { return; }
        if (boolKey("DisableInOnline", m_general.disableInOnline)) { return; }
        if (boolKey("IgnoreVersionCheck", m_general.ignoreVersionCheck)) { return; }
        warn("unknown key [General] %s", key.c_str());
        return;
    }

    if (iequals(section, "Signals"))
    {
        if (boolKey("PlayerShooting", m_signals.playerShooting)) { return; }
        if (boolKey("PlayerAiming", m_signals.playerAiming)) { return; }
        if (boolKey("Melee", m_signals.melee)) { return; }
        if (boolKey("RecentDamage", m_signals.recentDamage)) { return; }
        if (boolKey("HostileNearby", m_signals.hostileNearby)) { return; }
        if (boolKey("WantedByLaw", m_signals.wantedByLaw)) { return; }
        if (boolKey("DeadEye", m_signals.deadEye)) { return; }
        warn("unknown key [Signals] %s", key.c_str());
        return;
    }

    if (iequals(section, "Profiles"))
    {
        if (iequals(key, "Mode"))
        {
            if (iequals(value, "auto"))        { m_profiles.mode = ProfileMode::Auto; }
            else if (iequals(value, "manual")) { m_profiles.mode = ProfileMode::Manual; }
            else { warn("[Profiles] Mode = '%s' unknown, keeping auto", value.c_str()); }
            return;
        }
        auto sourceKey = [&](const char* name, ValueSource& target) -> bool {
            if (!iequals(key, name)) { return false; }
            if (iequals(value, "ini"))             { target = ValueSource::Ini; }
            else if (iequals(value, "snapshot"))   { target = ValueSource::Snapshot; }
            else if (iequals(value, "multiplier")) { target = ValueSource::Multiplier; }
            else { warn("[Profiles] %s = '%s' unknown, keeping previous", name, value.c_str()); }
            return true;
        };
        if (sourceKey("CalmSource", m_profiles.calmSource)) { return; }
        if (sourceKey("CombatSource", m_profiles.combatSource)) { return; }
        warn("unknown key [Profiles] %s", key.c_str());
        return;
    }

    if (iequals(section, "Defaults"))
    {
        if (floatKey("CalmAnimReloadRateMul", m_defaults.calmAnimMul, 0.01f, 100.0f)) { return; }
        if (floatKey("CalmLoopRateMul", m_defaults.calmLoopMul, 0.01f, 100.0f)) { return; }
        if (floatKey("CalmTimeBetweenMul", m_defaults.calmTimeMul, 0.01f, 100.0f)) { return; }
        if (floatKey("CombatAnimReloadRateMul", m_defaults.combatAnimMul, 0.01f, 100.0f)) { return; }
        if (floatKey("CombatLoopRateMul", m_defaults.combatLoopMul, 0.01f, 100.0f)) { return; }
        if (floatKey("CombatTimeBetweenMul", m_defaults.combatTimeMul, 0.01f, 100.0f)) { return; }
        if (floatKey("VanillaEpsilon", m_defaults.vanillaEpsilon, 0.0001f, 1.0f)) { return; }
        if (floatKey("MinValue", m_defaults.minValue, 0.001f, 100.0f)) { return; }
        if (floatKey("MaxValue", m_defaults.maxValue, 0.001f, 100.0f)) { return; }
        warn("unknown key [Defaults] %s", key.c_str());
        return;
    }

    if (iequals(section, "Memory"))
    {
        // Deliberately absent: any key that could name an address or a base.
        // If one ever appears here it is a bug, not a feature (SR-09).
        if (iequals(key, "MaxOffsetWindow"))
        {
            if (parseInt(value, integer) && integer >= 16 && integer <= 65536)
            {
                m_memory.maxOffsetWindow = static_cast<std::uint32_t>(integer);
            }
            else
            {
                warn("[Memory] MaxOffsetWindow = '%s' rejected, keeping %u",
                     value.c_str(), m_memory.maxOffsetWindow);
            }
            return;
        }
        if (iequals(key, "OffsetStep"))
        {
            if (parseInt(value, integer) && (integer == 4 || integer == 8))
            {
                m_memory.offsetStep = static_cast<std::uint32_t>(integer);
            }
            else
            {
                warn("[Memory] OffsetStep must be 4 or 8, keeping %u", m_memory.offsetStep);
            }
            return;
        }
        if (intKey("MinConsensusWeapons", m_memory.minConsensusWeapons, 3, 64)) { return; }
        if (floatKey("ConsensusMargin", m_memory.consensusMargin, 1.0f, 100.0f)) { return; }
        if (iequals(key, "MaxScanBytes"))
        {
            if (parseInt(value, integer) && integer >= 0)
            {
                m_memory.maxScanBytes = static_cast<std::uint64_t>(integer);
            }
            else
            {
                warn("[Memory] MaxScanBytes = '%s' rejected, keeping no limit", value.c_str());
            }
            return;
        }
        if (boolKey("PatchAllConditions", m_memory.patchAllConditions)) { return; }

        auto forcedOffset = [&](const char* name, std::int32_t& target) -> bool {
            if (!iequals(key, name)) { return false; }
            if (!parseInt(value, integer))
            {
                warn("[Memory] %s = '%s' is not a number, staying on auto", name, value.c_str());
                return true;
            }
            if (integer == 0)
            {
                // Offset 0 is the name-hash field itself and can never hold a reload
                // rate, so 0 is read as "auto", exactly as the shipped INI comment
                // says. 1.0 accepted it as a real offset.
                warn("[Memory] %s = 0 means auto; auto-discovery stays on", name);
                return true;
            }
            if (integer < 0 || static_cast<std::uint32_t>(integer) >= m_memory.maxOffsetWindow)
            {
                // This is the exact line the security test looks for.
                DRS_ERROR("offset rejected: out of window (%s = %ld, window = [0, %u))",
                          name, integer, m_memory.maxOffsetWindow);
                ++m_warnings;
                return true;
            }
            if ((static_cast<std::uint32_t>(integer) % m_memory.offsetStep) != 0u)
            {
                DRS_ERROR("offset rejected: misaligned (%s = %ld, step = %u)",
                          name, integer, m_memory.offsetStep);
                ++m_warnings;
                return true;
            }
            target = static_cast<std::int32_t>(integer);
            warn("[Memory] %s pinned to %ld by config; auto-discovery skipped for this field",
                 name, integer);
            return true;
        };
        if (forcedOffset("ForceAnimReloadRateOffset", m_memory.forceAnimOffset)) { return; }
        if (forcedOffset("ForceLoopRateOffset", m_memory.forceLoopOffset)) { return; }
        if (forcedOffset("ForceTimeBetweenOffset", m_memory.forceTimeOffset)) { return; }

        warn("unknown key [Memory] %s", key.c_str());
        return;
    }

    if (iequals(section, "Versions"))
    {
        if (iequals(key, "Supported"))
        {
            std::string list = value;
            std::size_t start = 0;
            while (start <= list.size())
            {
                const std::size_t comma = list.find(',', start);
                const std::string item  = trim(list.substr(
                    start, comma == std::string::npos ? std::string::npos : comma - start));
                if (!item.empty())
                {
                    m_supportedBuilds.push_back(item);
                }
                if (comma == std::string::npos) { break; }
                start = comma + 1;
            }
            return;
        }
        warn("unknown key [Versions] %s", key.c_str());
        return;
    }

    if (iequals(section, "Debug"))
    {
        if (iequals(key, "LogLevel"))
        {
            m_debug.logLevel = parseLogLevel(value, m_debug.logLevel);
            return;
        }
        if (iequals(key, "LogFile"))
        {
            m_debug.logFile = stripDirectory(trim(value), "DynamicReloadSpeed.log");
            return;
        }
        if (iequals(key, "MaxLogSizeMB"))
        {
            if (parseInt(value, integer) && integer >= 1 && integer <= 1024)
            {
                m_debug.maxLogSizeMb = static_cast<std::uint32_t>(integer);
            }
            else
            {
                warn("[Debug] MaxLogSizeMB = '%s' rejected, keeping %u",
                     value.c_str(), m_debug.maxLogSizeMb);
            }
            return;
        }
        if (boolKey("OnScreenState", m_debug.onScreenState)) { return; }
        if (iequals(key, "HotkeyToggleMod"))
        {
            m_debug.hotkeyToggleMod = parseVirtualKey(value, m_debug.hotkeyToggleMod);
            return;
        }
        if (iequals(key, "HotkeyForceCombat"))
        {
            m_debug.hotkeyForceCombat = parseVirtualKey(value, m_debug.hotkeyForceCombat);
            return;
        }
        if (iequals(key, "HotkeyReloadConfig"))
        {
            m_debug.hotkeyReloadConfig = parseVirtualKey(value, m_debug.hotkeyReloadConfig);
            return;
        }
        warn("unknown key [Debug] %s", key.c_str());
        return;
    }

    if (iequals(section, "Vanilla"))
    {
        if (!parseFloat(value, number) || number <= 0.0f || number > 100.0f)
        {
            warn("[Vanilla] %s = '%s' rejected", key.c_str(), value.c_str());
            return;
        }
        weaponFor(key).vanillaAnimReloadRate.set(number);
        return;
    }

    if (isWeaponSection(section))
    {
        WeaponEntry& entry = weaponFor(section);

        struct FieldBinding { const char* key; ProfileValues* profile; FieldValue ProfileValues::*field; };
        const FieldBinding bindings[] = {
            { "Calm_AnimReloadRate",             &entry.calm,   &ProfileValues::animReloadRate },
            { "Calm_LoopRate",                   &entry.calm,   &ProfileValues::loopRate },
            { "Calm_TimeBetweenBulletsInLoop",   &entry.calm,   &ProfileValues::timeBetween },
            { "Combat_AnimReloadRate",           &entry.combat, &ProfileValues::animReloadRate },
            { "Combat_LoopRate",                 &entry.combat, &ProfileValues::loopRate },
            { "Combat_TimeBetweenBulletsInLoop", &entry.combat, &ProfileValues::timeBetween },
        };

        for (const FieldBinding& binding : bindings)
        {
            if (!iequals(key, binding.key))
            {
                continue;
            }
            if (!parseFloat(value, number))
            {
                warn("[%s] %s = '%s' is not a finite number, key ignored",
                     section.c_str(), binding.key, value.c_str());
                return;
            }
            if (number <= 0.0f)
            {
                warn("[%s] %s = %.4f is not positive, key ignored",
                     section.c_str(), binding.key, number);
                return;
            }
            (binding.profile->*(binding.field)).set(number);
            return;
        }

        warn("unknown key [%s] %s", section.c_str(), key.c_str());
        return;
    }

    warn("unknown section [%s]", section.c_str());
}

void Config::validateAfterLoad()
{
    if (m_defaults.minValue >= m_defaults.maxValue)
    {
        warn("MinValue %.4f >= MaxValue %.4f, restoring built-in 0.05 / 8.0",
             m_defaults.minValue, m_defaults.maxValue);
        m_defaults.minValue = 0.05f;
        m_defaults.maxValue = 8.0f;
    }

    // The three CALM multipliers are not independent; see DESIGN.md section 1.
    // A config that breaks the rule is applied AS WRITTEN and warned about —
    // silently "fixing" someone's config is worse than obeying it loudly.
    if (std::fabs(m_defaults.calmLoopMul - 1.0f) > 0.0001f)
    {
        warn("CalmLoopRateMul = %.4f: AnimReloadRate already scales the per-round loop, "
             "so scaling LoopRate applies the slowdown twice. Applying as written.",
             m_defaults.calmLoopMul);
    }
    const float expectedTimeMul = 1.0f / m_defaults.calmAnimMul;
    if (std::fabs(m_defaults.calmTimeMul - expectedTimeMul) > 0.01f)
    {
        warn("CalmTimeBetweenMul = %.4f but 1 / CalmAnimReloadRateMul = %.4f; "
             "the pair is inconsistent with the timing model. Applying as written.",
             m_defaults.calmTimeMul, expectedTimeMul);
    }

    if (m_memory.offsetStep == 0u)
    {
        m_memory.offsetStep = 4u;
    }

    int withVanilla = 0;
    for (const WeaponEntry& entry : m_weapons)
    {
        if (entry.vanillaAnimReloadRate.present)
        {
            ++withVanilla;
        }
    }
    if (withVanilla < m_memory.minConsensusWeapons)
    {
        warn("only %d weapons carry a stock reference value but MinConsensusWeapons is %d; "
             "offset discovery will have to fall back to structural matching",
             withVanilla, m_memory.minConsensusWeapons);
    }
}

bool Config::loadFromFile(const std::string& fileName)
{
    applyBuiltInDefaults();

    const std::wstring path = pluginFilePath(fileName);
    if (path.empty())
    {
        DRS_ERROR("config: plugin directory unknown, running on built-in defaults");
        return false;
    }

    std::FILE* file = nullptr;
    if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || file == nullptr)
    {
        // Missing INI is not an error: the built-in defaults are a complete,
        // working configuration. Requirement: a fresh install must already work.
        DRS_INFO("config: %s not found, running on built-in defaults", fileName.c_str());
        return false;
    }

    std::fseek(file, 0, SEEK_END);
    const long size = std::ftell(file);
    std::fseek(file, 0, SEEK_SET);

    if (size < 0 || static_cast<std::size_t>(size) > ParseLimits::kMaxFileBytes)
    {
        std::fclose(file);
        DRS_ERROR("ini rejected: size limit (%ld bytes, limit %zu)",
                  size, ParseLimits::kMaxFileBytes);
        applyBuiltInDefaults();
        return false;
    }

    std::string content(static_cast<std::size_t>(size), '\0');
    const std::size_t read = std::fread(&content[0], 1, static_cast<std::size_t>(size), file);
    std::fclose(file);
    content.resize(read);

    // Strip a UTF-8 BOM; Notepad adds one and it would poison the first section name.
    if (content.size() >= 3 &&
        static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB &&
        static_cast<unsigned char>(content[2]) == 0xBF)
    {
        content.erase(0, 3);
    }

    std::string section;
    std::size_t sectionCount = 0;
    std::size_t lineStart    = 0;
    std::size_t lineNumber   = 0;

    while (lineStart <= content.size())
    {
        std::size_t lineEnd = content.find('\n', lineStart);
        if (lineEnd == std::string::npos)
        {
            lineEnd = content.size();
        }
        ++lineNumber;

        if (lineEnd - lineStart > ParseLimits::kMaxLineChars)
        {
            DRS_ERROR("ini rejected: line %zu is longer than %zu characters",
                      lineNumber, ParseLimits::kMaxLineChars);
            applyBuiltInDefaults();
            return false;
        }

        std::string line = content.substr(lineStart, lineEnd - lineStart);
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        line = trim(line);

        if (lineEnd >= content.size())
        {
            lineStart = content.size() + 1;
        }
        else
        {
            lineStart = lineEnd + 1;
        }

        if (line.empty() || line[0] == ';' || line[0] == '#')
        {
            continue;
        }

        if (line.front() == '[')
        {
            const std::size_t close = line.find(']');
            if (close == std::string::npos)
            {
                warn("line %zu: section without a closing bracket, ignored", lineNumber);
                continue;
            }
            ++sectionCount;
            if (sectionCount > ParseLimits::kMaxSections)
            {
                DRS_ERROR("ini rejected: more than %zu sections", ParseLimits::kMaxSections);
                applyBuiltInDefaults();
                return false;
            }
            section = toUpper(trim(line.substr(1, close - 1)));
            continue;
        }

        const std::size_t equals = line.find('=');
        if (equals == std::string::npos)
        {
            warn("line %zu: no '=' found, ignored", lineNumber);
            continue;
        }

        std::string key   = trim(line.substr(0, equals));
        std::string value = trim(line.substr(equals + 1));

        // Trailing comment after a value: "0.50   ; twice as slow"
        const std::size_t comment = value.find_first_of(";#");
        if (comment != std::string::npos)
        {
            value = trim(value.substr(0, comment));
        }

        if (section.empty())
        {
            warn("line %zu: key '%s' outside any section, ignored", lineNumber, key.c_str());
            continue;
        }

        applySectionKey(section, key, value);
    }

    m_loadedFromFile = true;
    validateAfterLoad();
    return true;
}

const WeaponEntry* Config::matchWeapon(const std::string& actualWeaponName) const
{
    const std::string name = toUpper(actualWeaponName);
    const WeaponEntry* best = nullptr;

    for (const WeaponEntry& entry : m_weapons)
    {
        if (entry.name.size() > name.size())
        {
            continue;
        }
        if (name.compare(0, entry.name.size(), entry.name) != 0)
        {
            continue;
        }
        if (best == nullptr || entry.name.size() > best->name.size())
        {
            best = &entry;
        }
    }
    return best;
}

std::vector<const WeaponEntry*> Config::signatureWeapons() const
{
    std::vector<const WeaponEntry*> result;
    result.reserve(m_weapons.size());
    for (const WeaponEntry& entry : m_weapons)
    {
        if (entry.vanillaAnimReloadRate.present)
        {
            result.push_back(&entry);
        }
    }
    return result;
}

} // namespace drs

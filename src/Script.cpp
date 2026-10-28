#include "Script.h"
#include "GameApi.h"
#include "GameBuild.h"
#include "Joaat.h"
#include "Logger.h"
#include "Overlay.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace drs {

namespace {

constexpr const char*   kPluginVersion  = "1.2.0";
constexpr int           kMaxTickErrors  = 10;

// Start-up timing (1.1). Weapon data is parsed at game boot, long before any
// script runs, so there is nothing to "wait for" in that sense. What we wait for
// is the hand-off from the loading screen: the scan starts only once the world is
// on screen, plus a short settle delay, so it does not compete with the burst of
// streaming right after loading. 1.0 waited a blind 8 s from script start.
constexpr std::uint64_t kSettleDelayMs  = 5000;
constexpr std::uint64_t kReadyTimeoutMs = 120000;   // never wait forever

constexpr const char*   kScanLabel      = "SCANNING";

constexpr std::uint32_t kUnarmed        = joaat("weapon_unarmed");

bool startsWith(const char* text, const char* prefix)
{
    return text != nullptr && std::strncmp(text, prefix, std::strlen(prefix)) == 0;
}

// Mounted and emplaced guns: their "reload" is a crew or cool-down animation, not
// the player's hands. Checked on the game's own label in addition to the hash
// list in WeaponTable.h, because the exact turret names are not all known.
bool labelLooksMounted(const char* label)
{
    return std::strstr(label, "TURRET") != nullptr || std::strstr(label, "CANNON") != nullptr ||
           std::strstr(label, "GATLING") != nullptr || std::strstr(label, "MAXIM") != nullptr;
}

// The game's label for a weapon is "WNS_" + the rest of its internal name in the
// cases checked so far ("WNS_INVALID" for an unknown hash). "WEAPON_" + that rest
// is therefore the likely internal name; hashing it back tells whether it IS.
// Either way it is used to look up an INI section by prefix, so an unknown
// double-action revolver still gets the double-action section.
std::string nameFromLabel(std::uint32_t hash, const char* label, bool& verified)
{
    verified = false;
    if (startsWith(label, "WNS_") && label[4] != '\0')
    {
        std::string name = "WEAPON_";
        name += (label + 4);
        for (char& c : name)
        {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        verified = (joaat(name.c_str()) == hash);   // joaat lower-cases by itself
        return name;
    }
    if (label != nullptr && label[0] != '\0')
    {
        return std::string(label);
    }
    char buffer[16] = {};
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "0x%08X", hash);
    return std::string(buffer);
}

} // namespace

const char* modStateName(ModState state)
{
    switch (state)
    {
    case ModState::Initialising:      return "INIT";
    case ModState::Calm:              return "CALM";
    case ModState::Combat:            return "COMBAT";
    case ModState::Cooldown:          return "COOLDOWN";
    case ModState::DisabledByUser:    return "DISABLED";
    case ModState::DisabledPermanent: return "DISABLED_PERMANENT";
    }
    return "?";
}

Script& Script::instance()
{
    static Script script;
    return script;
}

void Script::onKeyDown(int virtualKey)
{
    // Input thread. Compare against the published atomic copies and set a flag:
    // nothing here may touch the game or the Config object.
    if (virtualKey == m_hotkeyToggle.load())       { m_requestToggle.store(true); }
    if (virtualKey == m_hotkeyForceCombat.load())  { m_requestForceCombat.store(true); }
    if (virtualKey == m_hotkeyReloadConfig.load()) { m_requestReloadConfig.store(true); }
}

void Script::publishHotkeys()
{
    const DebugSettings& debug = m_config.debug();
    m_hotkeyToggle.store(debug.hotkeyToggleMod);
    m_hotkeyForceCombat.store(debug.hotkeyForceCombat);
    m_hotkeyReloadConfig.store(debug.hotkeyReloadConfig);
}

void Script::disablePermanently(const char* reason)
{
    if (m_state == ModState::DisabledPermanent)
    {
        return;
    }
    DRS_ERROR("disabling permanently: %s", reason);
    m_patcher.restoreAll();
    m_state          = ModState::DisabledPermanent;
    m_stateEnteredMs = GetTickCount64();
    m_pendingWrite   = false;
    Overlay::instance().setDetail(nullptr);
}

bool Script::versionGatePasses()
{
    const std::string build = gameBuildVersion();

    // One line, always, whatever happens next. It is the line a player is asked
    // to copy into a bug report, and the line they copy into [Versions].
    DRS_INFO("game build: %s", build.empty() ? "unknown" : build.c_str());

    if (m_config.supportedBuilds().empty())
    {
        DRS_INFO("version check: no build list configured in [Versions], proceeding");
        return true;
    }

    if (build.empty())
    {
        if (m_config.general().ignoreVersionCheck)
        {
            DRS_INFO("version check bypassed by user: build could not be determined");
            return true;
        }
        DRS_ERROR("unsupported build: the game's build number could not be read and "
                  "[Versions] Supported is not empty. Set IgnoreVersionCheck = 1 to "
                  "override. The mod will do nothing.");
        return false;
    }

    const auto& list  = m_config.supportedBuilds();
    const bool  known = std::any_of(list.begin(), list.end(),
                                    [&build](const std::string& entry) {
                                        return gameBuildMatches(build, entry);
                                    });
    if (known)
    {
        DRS_INFO("version check: game build %s is listed as supported", build.c_str());
        return true;
    }

    if (m_config.general().ignoreVersionCheck)
    {
        DRS_INFO("version check bypassed by user: build %s is not in the list",
                 build.c_str());
        return true;
    }

    DRS_ERROR("unsupported build: %s is not listed in [Versions]. The mod will do "
              "nothing. Add it to the list once you have verified reload timing.",
              build.c_str());
    return false;
}

void Script::waitForGameplay()
{
    const std::uint64_t started  = GetTickCount64();
    bool                timedOut = false;

    // Phase 1: the loading screen is gone and the screen has faded in. Drawn as
    // INIT every frame so a player with OnScreenState = 1 sees the mod is alive.
    while (!game::isGameplayReady())
    {
        if (GetTickCount64() - started >= kReadyTimeoutMs)
        {
            timedOut = true;
            break;
        }
        Overlay::instance().update(modStateName(ModState::Initialising), 0, -1,
                                   kPluginVersion);
        game::waitTicks(0);
    }

    if (timedOut)
    {
        DRS_INFO("start-up: the game did not report the world on screen within %llu s; "
                 "continuing anyway",
                 static_cast<unsigned long long>(kReadyTimeoutMs / 1000));
    }
    else
    {
        DRS_INFO("start-up: world on screen after %llu ms, settling %llu ms before the scan",
                 static_cast<unsigned long long>(GetTickCount64() - started),
                 static_cast<unsigned long long>(kSettleDelayMs));
    }

    // Phase 2: settle.
    const std::uint64_t settleStart = GetTickCount64();
    while (GetTickCount64() - settleStart < kSettleDelayMs)
    {
        Overlay::instance().update(modStateName(ModState::Initialising), 0, -1,
                                   kPluginVersion);
        game::waitTicks(0);
    }
}

bool Script::initialise()
{
    // 1. Open the log on built-in defaults FIRST. Reading the config produces log
    //    lines of its own, and those lines are the ones that explain why the rest
    //    of the session behaves the way it does - losing them would be the worst
    //    possible trade for tidier ordering.
    Logger::instance().configure("DynamicReloadSpeed.log", LogLevel::Info, 32u);
    DRS_INFO("RDR2 Dynamic Reload %s starting", kPluginVersion);

    // 2. Now the player's own settings. If the file names a different log or a
    //    different level, the logger switches over without losing what is above.
    m_config.loadFromFile("DynamicReloadSpeed.ini");
    Logger::instance().configure(m_config.debug().logFile,
                                 m_config.debug().logLevel,
                                 m_config.debug().maxLogSizeMb);
    publishHotkeys();

    DRS_INFO("config: %s, %d warning(s), %zu weapon sections",
             m_config.loadedFromFile() ? "loaded from file" : "built-in defaults",
             m_config.warningCount(), m_config.weapons().size());

    game::initialise();

    // Configured this early so the overlay can show INIT / SCANNING while the
    // mod starts up instead of appearing out of nowhere 15 s later.
    Overlay::instance().configure(m_config);

    if (!m_config.general().enabled)
    {
        DRS_INFO("Enabled = 0 in the config; the mod will do nothing this session");
        m_state = ModState::DisabledPermanent;
        return false;
    }

    if (!versionGatePasses())
    {
        m_state = ModState::DisabledPermanent;
        return false;
    }

    if (m_config.general().disableInOnline && !game::onlineCheckAvailable())
    {
        DRS_INFO("online check is not available on this build; the mod cannot verify "
                 "single player and relies on the player not using it online");
    }

    // 3. Start the scan only once the world is on screen (see kSettleDelayMs).
    waitForGameplay();

    if (!runResolver())
    {
        DRS_ERROR("resolver failed: %s", m_patcher.failureReason().empty()
                                             ? "unexpected exception in the resolver"
                                             : m_patcher.failureReason().c_str());
        DRS_ERROR("the mod will do nothing this session; the game is untouched");
        m_state = ModState::DisabledPermanent;
        return false;
    }

    // 4. Back on the script thread: the natives that tell which of the unlisted
    //    weapon-info objects are guns, then one line per weapon with the values
    //    it will get, so a log is enough to check every weapon's behaviour.
    adoptUnlistedGuns();
    m_patcher.logPlan(m_config);
    DRS_INFO("start-up: %d weapon structures for %d names will be switched",
             m_patcher.resolvedWeapons(), m_patcher.resolvedNames());

    m_detector.configure(m_config);

    m_state          = ModState::Calm;
    m_stateEnteredMs = GetTickCount64();
    requestProfile(false);
    return true;
}

bool Script::runResolver()
{
    // See the threading note in Script.h. While the worker runs, this fiber does
    // nothing but yield and draw the overlay, so nobody else logs or touches
    // m_patcher/m_config concurrently; the keyboard handler only sets atomic flags.
    //
    // The shared state lives on the heap and the thread is detached: if
    // ScriptHook ever tears this fiber down mid-wait, the worker must not write
    // into a freed fiber stack, and a joinable std::thread must never be
    // destroyed (that is std::terminate).
    struct ResolverJob
    {
        std::atomic<bool> done{false};
        bool              ok = false;
    };
    auto job = std::make_shared<ResolverJob>();

    const ULONGLONG started = GetTickCount64();
    // Logged BEFORE the worker exists: the Logger is single-writer by design.
    DRS_INFO("resolver: scanning on a background thread, the game keeps running");
    try
    {
        std::thread([this, job]() {
            // Below normal, not idle. The game's own threads always win the CPU,
            // and the scan also yields cooperatively every few MB (MemScan), so it
            // does not saturate memory bandwidth. IDLE was tried and rejected: on
            // a machine where the game keeps every core busy an idle thread can
            // starve for many seconds, and the mod would switch on far too late.
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
            try
            {
                job->ok = m_patcher.initialise(m_config);
            }
            catch (...)
            {
                // e.g. std::bad_alloc: never let it reach std::terminate.
                job->ok = false;
            }
            job->done.store(true, std::memory_order_release);
        }).detach();
    }
    catch (const std::system_error&)
    {
        DRS_ERROR("resolver: could not start the background thread");
        return false;
    }

    // acquire pairs with the worker's release: once done is seen, everything
    // initialise() wrote into m_patcher is visible to this thread. One yield per
    // frame keeps the overlay steady while waiting.
    while (!job->done.load(std::memory_order_acquire))
    {
        Overlay::instance().update(kScanLabel, 0, -1, kPluginVersion);
        game::waitTicks(0);
    }

    DRS_INFO("resolver: background scan finished in %llu ms",
             static_cast<unsigned long long>(GetTickCount64() - started));
    return job->ok;
}

void Script::adoptUnlistedGuns()
{
    const std::vector<std::uint32_t> hashes = m_patcher.unlistedHashes();
    if (hashes.empty())
    {
        m_patcher.releaseUnlisted();
        return;
    }

    // A few hundred names at most, two cheap natives each, once per session.
    std::vector<UnlistedGun> guns;
    int  notGuns   = 0;
    int  excluded  = 0;
    char label[64] = {};

    for (const std::uint32_t hash : hashes)
    {
        if (isNeverManaged(hash))
        {
            ++excluded;
            continue;
        }
        if (!game::isWeaponAGun(hash))
        {
            ++notGuns;
            continue;
        }
        const bool haveLabel = game::weaponLabel(hash, label, sizeof(label));
        if (haveLabel && labelLooksMounted(label))
        {
            ++excluded;
            continue;
        }

        UnlistedGun gun;
        gun.hash = hash;
        if (haveLabel)
        {
            gun.label = label;
        }
        gun.name = nameFromLabel(hash, haveLabel ? label : nullptr, gun.nameVerified);
        guns.push_back(gun);
    }

    int adopted = 0;
    if (m_config.memory().includeUnlistedGuns)
    {
        adopted = m_patcher.adoptUnlisted(guns, m_config);
    }
    else
    {
        for (const UnlistedGun& gun : guns)
        {
            DRS_INFO("unlisted gun left alone (IncludeUnlistedGuns = 0): %s (label %s)",
                     gun.name.c_str(), gun.label.empty() ? "none" : gun.label.c_str());
        }
    }

    DRS_INFO("unlisted: %zu other weapon-info names, %zu of them guns (%d structure(s) "
             "adopted), %d not guns, %d excluded (mounted guns, bows)",
             hashes.size(), guns.size(), adopted, notGuns, excluded);

    m_patcher.releaseUnlisted();
}

void Script::requestProfile(bool combat)
{
    m_pendingWrite       = true;
    m_pendingWriteCombat = combat;
    m_deferralLogged     = false;
}

void Script::flushPendingWrite()
{
    if (!m_pendingWrite || !m_patcher.ready())
    {
        return;
    }

    // Not in the middle of a reload: changing the rate mid-animation would make
    // that one reload a mix of both speeds.
    const int ped = game::playerPed();
    if (ped != 0 && game::isPedReloading(ped))
    {
        if (!m_deferralLogged)
        {
            DRS_INFO("deferred: reloading");
            m_deferralLogged = true;
        }
        return;   // try again next tick
    }

    m_patcher.applyProfile(m_pendingWriteCombat, m_config);
    m_pendingWrite    = false;
    m_deferralLogged  = false;
    m_heldDetailDirty = true;   // the rate shown for the weapon in hand changed
}

void Script::enterState(ModState next, std::uint64_t nowMs, const char* reason)
{
    if (m_state == next)
    {
        return;
    }
    DRS_INFO("%s -> %s (%s)", modStateName(m_state), modStateName(next), reason);
    const ModState previous = m_state;
    m_state          = next;
    m_stateEnteredMs = nowMs;

    if (next == ModState::Combat)
    {
        // From COOLDOWN the COMBAT values are still in place (COOLDOWN never
        // writes), so writing them again would be a write without an effect -
        // FR-46 / AT-39.
        if (previous != ModState::Cooldown)
        {
            requestProfile(true);
        }
    }
    else if (next == ModState::Calm)
    {
        requestProfile(false);
    }
    // COOLDOWN deliberately writes nothing: values stay on the COMBAT profile
    // until the timer actually expires.
}

void Script::handleRequests(std::uint64_t nowMs)
{
    if (m_requestReloadConfig.exchange(false))
    {
        DRS_INFO("hotkey: re-reading the config");
        m_config.loadFromFile("DynamicReloadSpeed.ini");
        // loadFromFile() rebuilt Config::m_weapons, so every WeaponTarget::config
        // pointer the patcher holds now dangles. Rebind BEFORE anything can call
        // applyProfile() - requestProfile() below does exactly that.
        m_patcher.rebindConfig(m_config);
        Logger::instance().configure(m_config.debug().logFile,
                                     m_config.debug().logLevel,
                                     m_config.debug().maxLogSizeMb);
        publishHotkeys();
        m_detector.configure(m_config);
        Overlay::instance().configure(m_config);
        if (m_patcher.ready())
        {
            m_patcher.logPlan(m_config);
        }
        // The snapshot is NOT re-taken. Re-reading the config must never change
        // what "original" means (FR-57).
        requestProfile(m_state == ModState::Combat || m_state == ModState::Cooldown);
    }

    if (m_requestToggle.exchange(false))
    {
        if (m_state == ModState::DisabledPermanent)
        {
            DRS_INFO("hotkey: toggle ignored, the mod is permanently disabled this session");
        }
        else if (m_state == ModState::DisabledByUser)
        {
            // Back on: always CALM (AsiPlugin business logic, status lifecycle).
            // The detector's decision from before the pause is stale; if a fight is
            // still on, the next poll moves to COMBAT at once.
            DRS_INFO("hotkey: mod switched back on");
            m_state          = ModState::Calm;
            m_stateEnteredMs = nowMs;
            m_heldHash       = 0u;   // re-describe the weapon in hand
            requestProfile(false);
        }
        else
        {
            DRS_INFO("hotkey: mod switched off, restoring boot values");
            m_patcher.restoreAll();
            m_pendingWrite   = false;
            m_state          = ModState::DisabledByUser;
            m_stateEnteredMs = nowMs;
            Overlay::instance().setDetail(nullptr);
        }
    }

    if (m_requestForceCombat.exchange(false))
    {
        m_forcedCombat = !m_forcedCombat;
        DRS_INFO("hotkey: forced COMBAT %s", m_forcedCombat ? "on" : "off");
    }
}

int Script::cooldownTenthsLeft(std::uint64_t nowMs) const
{
    if (m_state != ModState::Cooldown)
    {
        return -1;
    }
    const std::uint64_t cooldownMs =
        static_cast<std::uint64_t>(m_config.general().cooldownSeconds * 1000.0f);
    const std::uint64_t elapsed   = nowMs - m_stateEnteredMs;
    const std::uint64_t remaining = (elapsed < cooldownMs) ? (cooldownMs - elapsed) : 0u;
    return static_cast<int>(remaining / 100u);
}

void Script::refreshHeldWeapon(int playerPedHandle)
{
    if (playerPedHandle == 0)
    {
        return;
    }

    const std::uint32_t held    = game::currentWeaponHash(playerPedHandle);
    const bool          changed = (held != m_heldHash);
    m_heldHash = held;

    // Same weapon, same values: nothing to describe, format or log (NFR-01 - this
    // runs at DetectorHz on the script thread).
    if (!changed && !m_heldDetailDirty)
    {
        return;
    }
    m_heldDetailDirty = false;

    const HeldWeaponStatus status = m_patcher.describe(held);

    if (changed && !status.managed)
    {
        // Only for a weapon the plugin does not manage: is it a gun at all, and
        // what does the game call it? Two natives, once per weapon change.
        m_heldIsGun    = (held != 0u) && (held != kUnarmed) && game::isWeaponAGun(held);
        m_heldLabel[0] = '\0';
        if (m_heldIsGun)
        {
            game::weaponLabel(held, m_heldLabel, sizeof(m_heldLabel));
        }
    }
    else if (changed)
    {
        m_heldIsGun    = true;
        m_heldLabel[0] = '\0';
    }

    char detail[128] = {};
    if (status.managed)
    {
        const char* shown = status.name.c_str();
        if (startsWith(shown, "WEAPON_"))
        {
            shown += 7;
        }
        _snprintf_s(detail, sizeof(detail), _TRUNCATE, "%s  |  reload rate %.2f%s",
                    shown, static_cast<double>(status.value),
                    status.instances > 1 ? "  (+copies)" : "");
    }
    else if (m_heldIsGun)
    {
        if (status.known)
        {
            _snprintf_s(detail, sizeof(detail), _TRUNCATE, "%s  |  not managed",
                        status.name.c_str());
        }
        else if (m_heldLabel[0] != '\0')
        {
            _snprintf_s(detail, sizeof(detail), _TRUNCATE, "%s  |  not managed", m_heldLabel);
        }
        else
        {
            _snprintf_s(detail, sizeof(detail), _TRUNCATE, "0x%08X  |  not managed", held);
        }
    }
    Overlay::instance().setDetail(detail);

    // One info line the first time each gun is taken in hand this session: the
    // quickest way for a player to report "this one does not switch".
    if (!changed || held == 0u || !(status.managed || m_heldIsGun))
    {
        return;
    }
    for (int i = 0; i < m_seenWeaponCount; ++i)
    {
        if (m_seenWeapons[i] == held)
        {
            DRS_DEBUG("weapon in hand: 0x%08X again", held);
            return;
        }
    }
    if (m_seenWeaponCount < kSeenCapacity)
    {
        m_seenWeapons[m_seenWeaponCount] = held;
        ++m_seenWeaponCount;
    }

    if (status.managed)
    {
        DRS_INFO("weapon in hand: %s - managed (%d structure(s)), reload rate now %.4f",
                 status.name.c_str(), status.instances, static_cast<double>(status.value));
    }
    else if (status.known)
    {
        DRS_INFO("weapon in hand: %s - known name, but no weapon structure was bound for it "
                 "(see the resolver lines)", status.name.c_str());
    }
    else
    {
        DRS_INFO("weapon in hand: hash 0x%08X, label %s - a gun this plugin does NOT manage",
                 held, m_heldLabel[0] != '\0' ? m_heldLabel : "none");
    }
}

void Script::tick(std::uint64_t nowMs)
{
    handleRequests(nowMs);

    // Draw the on-screen overlay every tick. UIDEBUG text is immediate-mode: if
    // it is issued only at the detector poll rate (DetectorHz = 4) it shows for
    // one frame and vanishes for the next ~15, which is the flicker reported in
    // game on 1.0. Re-issuing it every tick costs a few native calls (the text is
    // cached, see Overlay.h) and is a no-op when OnScreenState = 0. It is drawn in
    // every state, including the two disabled ones, so the overlay honestly shows
    // when the mod is off. hostileCount is the last polled value.
    Overlay::instance().update(modStateName(m_state), m_lastHostileCount,
                               cooldownTenthsLeft(nowMs), kPluginVersion);

    if (m_state == ModState::DisabledPermanent || m_state == ModState::DisabledByUser)
    {
        return;
    }

    if (m_config.general().disableInOnline && game::onlineCheckAvailable() &&
        game::isOnlineSession())
    {
        if (!m_onlineNotified)
        {
            m_onlineNotified = true;
            disablePermanently("a multiplayer session was detected; this mod is "
                               "single player only");
        }
        return;
    }

    const int ped      = game::playerPed();
    const int playerId = game::playerId();

    // Every frame (1.2): a shot is visible to the game for only a few frames.
    m_detector.sampleTick(ped, playerId, nowMs);

    const int detectorHz = std::max(1, m_config.general().detectorHz);
    const std::uint64_t intervalMs = static_cast<std::uint64_t>(1000 / detectorHz);

    if (m_lastDetectorMs == 0 || nowMs - m_lastDetectorMs >= intervalMs)
    {
        m_lastDetectorMs = nowMs;

        const bool inFight = (m_state == ModState::Combat || m_state == ModState::Cooldown);
        const SignalSnapshot signals = m_detector.poll(ped, playerId, nowMs, inFight);
        const bool combatNow = m_forcedCombat || signals.anyCombat();

        // Cache for the overlay, which draws every tick (see above).
        m_lastHostileCount = signals.hostileCount;

        // The reason text is built only for a transition that is actually logged,
        // not on every poll (NFR-01).
        // A forced fight with no real signal is named as such; 1.1 logged it as "(none)".
        char reason[128] = {};
        auto why = [&]() -> const char* {
            if (m_forcedCombat && !signals.anyCombat())
            {
                return "forced by hotkey";
            }
            return m_detector.describe(reason, sizeof(reason));
        };

        switch (m_state)
        {
        case ModState::Calm:
            if (combatNow) { enterState(ModState::Combat, nowMs, why()); }
            break;

        case ModState::Combat:
            if (!combatNow) { enterState(ModState::Cooldown, nowMs, "all signals false"); }
            break;

        case ModState::Cooldown:
            if (combatNow)
            {
                enterState(ModState::Combat, nowMs, why());
            }
            else
            {
                const std::uint64_t cooldownMs =
                    static_cast<std::uint64_t>(m_config.general().cooldownSeconds * 1000.0f);
                if (nowMs - m_stateEnteredMs >= cooldownMs)
                {
                    enterState(ModState::Calm, nowMs, "cooldown expired");
                }
            }
            break;

        default:
            break;
        }

        refreshHeldWeapon(ped);
    }

    flushPendingWrite();
}

void Script::run()
{
    if (!initialise())
    {
        // Idle forever rather than unregister: unregistering would make the
        // failure invisible, and the log is the only diagnostic a user can send.
        // The overlay keeps showing the disabled state if it is switched on.
        while (true)
        {
            Overlay::instance().update(modStateName(m_state), 0, -1, kPluginVersion);
            game::waitTicks(0);
        }
    }

    while (true)
    {
        try
        {
            tick(GetTickCount64());
            m_consecutiveErrors = 0;
        }
        catch (...)
        {
            ++m_consecutiveErrors;
            DRS_ERROR("tick failed (%d in a row)", m_consecutiveErrors);
            if (m_consecutiveErrors >= kMaxTickErrors)
            {
                disablePermanently("too many consecutive tick failures");
            }
        }
        game::waitTicks(0);
    }
}

void Script::onUnload()
{
    DRS_INFO("unloading, restoring boot values");
    m_patcher.restoreAll();
    Logger::instance().shutdown();
}

} // namespace drs

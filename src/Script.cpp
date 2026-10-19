#include "Script.h"
#include "GameApi.h"
#include "GameBuild.h"
#include "Logger.h"
#include "Overlay.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <memory>
#include <system_error>
#include <thread>

namespace drs {

namespace {

constexpr const char* kPluginVersion   = "1.0.0";
constexpr int         kMaxTickErrors   = 10;
constexpr std::uint32_t kInitDelayMs   = 8000;   // let the game finish loading weapon data

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
    // Input thread. Set a flag and return: nothing here may touch the game.
    const DebugSettings& debug = m_config.debug();
    if (virtualKey == debug.hotkeyToggleMod)    { m_requestToggle.store(true); }
    if (virtualKey == debug.hotkeyForceCombat)  { m_requestForceCombat.store(true); }
    if (virtualKey == debug.hotkeyReloadConfig) { m_requestReloadConfig.store(true); }
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

    DRS_INFO("config: %s, %d warning(s), %zu weapon sections",
             m_config.loadedFromFile() ? "loaded from file" : "built-in defaults",
             m_config.warningCount(), m_config.weapons().size());

    game::initialise();

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

    // 3. Give the game time to parse weapons.ymt before looking for the result.
    DRS_INFO("waiting %u ms for the game to finish loading weapon data", kInitDelayMs);
    game::waitTicks(kInitDelayMs);

    if (!runResolver())
    {
        DRS_ERROR("resolver failed: %s", m_patcher.failureReason().empty()
                                             ? "unexpected exception in the resolver"
                                             : m_patcher.failureReason().c_str());
        DRS_ERROR("the mod will do nothing this session; the game is untouched");
        m_state = ModState::DisabledPermanent;
        return false;
    }

    m_detector.configure(m_config);
    Overlay::instance().configure(m_config);

    m_state          = ModState::Calm;
    m_stateEnteredMs = GetTickCount64();
    requestProfile(false);
    return true;
}

bool Script::runResolver()
{
    // See the threading note in Script.h. While the worker runs, this fiber does
    // nothing but yield, so nobody else logs or touches m_patcher/m_config
    // concurrently; the keyboard handler only sets atomic flags.
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
            // Below normal: the game's own threads always win the CPU.
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
    // initialise() wrote into m_patcher is visible to this thread.
    while (!job->done.load(std::memory_order_acquire))
    {
        game::waitTicks(100);   // yield the game's main thread
    }

    DRS_INFO("resolver: background scan finished in %llu ms",
             static_cast<unsigned long long>(GetTickCount64() - started));
    return job->ok;
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
    m_pendingWrite   = false;
    m_deferralLogged = false;
}

void Script::enterState(ModState next, std::uint64_t nowMs, const char* reason)
{
    if (m_state == next)
    {
        return;
    }
    DRS_INFO("%s -> %s (%s)", modStateName(m_state), modStateName(next), reason);
    m_state          = next;
    m_stateEnteredMs = nowMs;

    if (next == ModState::Combat)
    {
        requestProfile(true);
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
        m_detector.configure(m_config);
        Overlay::instance().configure(m_config);
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
            DRS_INFO("hotkey: mod switched back on");
            m_state          = m_stateBeforeDisable;
            m_stateEnteredMs = nowMs;
            requestProfile(m_state == ModState::Combat || m_state == ModState::Cooldown);
        }
        else
        {
            DRS_INFO("hotkey: mod switched off, restoring boot values");
            m_stateBeforeDisable = m_state;
            m_patcher.restoreAll();
            m_pendingWrite   = false;
            m_state          = ModState::DisabledByUser;
            m_stateEnteredMs = nowMs;
        }
    }

    if (m_requestForceCombat.exchange(false))
    {
        m_forcedCombat = !m_forcedCombat;
        DRS_INFO("hotkey: forced COMBAT %s", m_forcedCombat ? "on" : "off");
    }
}

void Script::tick(std::uint64_t nowMs)
{
    handleRequests(nowMs);

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

    const int detectorHz = std::max(1, m_config.general().detectorHz);
    const std::uint64_t intervalMs = static_cast<std::uint64_t>(1000 / detectorHz);

    if (m_lastDetectorMs == 0 || nowMs - m_lastDetectorMs >= intervalMs)
    {
        m_lastDetectorMs = nowMs;

        const int ped      = game::playerPed();
        const int playerId = game::playerId();
        const SignalSnapshot signals = m_detector.poll(ped, playerId, nowMs);
        const bool combatNow = m_forcedCombat || signals.anyCombat();

        char reason[128] = {};
        m_detector.describe(reason, sizeof(reason));

        switch (m_state)
        {
        case ModState::Calm:
            if (combatNow) { enterState(ModState::Combat, nowMs, reason); }
            break;

        case ModState::Combat:
            if (!combatNow) { enterState(ModState::Cooldown, nowMs, "all signals false"); }
            break;

        case ModState::Cooldown:
            if (combatNow)
            {
                enterState(ModState::Combat, nowMs, reason);
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

        Overlay::instance().update(modStateName(m_state), signals.hostileCount,
                                   kPluginVersion);
    }

    flushPendingWrite();
}

void Script::run()
{
    if (!initialise())
    {
        // Idle forever rather than unregister: unregistering would make the
        // failure invisible, and the log is the only diagnostic a user can send.
        while (true)
        {
            game::waitTicks(1000);
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

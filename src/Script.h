// Script.h — the main loop and the state machine. Owns everything else.
//
// Threading rules, both of which exist to avoid a class of crash that is very
// hard to diagnose from a user's log:
//
//   * The keyboard handler runs on the game's input thread. It is allowed to do
//     exactly one thing: set a flag. It never reads or writes game memory, and it
//     does not read Config either — it compares against atomic copies of the
//     hotkeys that the script thread publishes (publishHotkeys()), so a config
//     re-read can never race with a key press.
//   * Everything that touches the game happens on the script thread, inside the
//     guarded tick body.
//   * One exception: the start-up memory scan (WeaponPatcher::initialise) runs on
//     a short-lived worker thread. ScriptHookRDR2 runs scripts as fibers on the
//     game's MAIN thread, so a multi-gigabyte scan there freezes the game
//     ("not responding"). The scan only READS memory through SEH guards; every
//     WRITE still happens here, on the script thread, after the worker is done.
//     While the worker runs, this fiber only yields and draws the overlay.

#pragma once

#include "CombatDetector.h"
#include "Config.h"
#include "WeaponPatcher.h"

#include <atomic>
#include <cstdint>

namespace drs {

enum class ModState
{
    Initialising,
    Calm,
    Combat,
    Cooldown,
    DisabledByUser,
    DisabledPermanent
};

const char* modStateName(ModState state);

class Script
{
public:
    static Script& instance();

    void run();        // script thread entry point
    void onUnload();   // called on script unregister and DLL_PROCESS_DETACH

    // Input thread. Only sets flags.
    void onKeyDown(int virtualKey);

    ModState state() const noexcept { return m_state; }

private:
    Script() = default;

    bool initialise();
    void waitForGameplay();   // world on screen + settle delay, overlay shows INIT
    bool runResolver();       // scans on a worker thread, keeps yielding to the game
    void tick(std::uint64_t nowMs);
    void handleRequests(std::uint64_t nowMs);
    void enterState(ModState next, std::uint64_t nowMs, const char* reason);
    void requestProfile(bool combat);
    void flushPendingWrite();
    bool versionGatePasses();
    void disablePermanently(const char* reason);
    void publishHotkeys();
    int  cooldownTenthsLeft(std::uint64_t nowMs) const;

    Config         m_config;
    CombatDetector m_detector;
    WeaponPatcher  m_patcher;

    ModState      m_state              = ModState::Initialising;
    ModState      m_stateBeforeDisable = ModState::Calm;
    std::uint64_t m_stateEnteredMs     = 0;
    std::uint64_t m_lastDetectorMs     = 0;

    // Cached so the on-screen overlay, which is redrawn every tick to stop it
    // flickering, has the hostile count from the last detector poll to show.
    int  m_lastHostileCount    = 0;

    bool m_pendingWrite        = false;
    bool m_pendingWriteCombat  = false;
    bool m_deferralLogged      = false;

    int  m_consecutiveErrors   = 0;
    bool m_forcedCombat        = false;
    bool m_onlineNotified      = false;

    std::atomic<bool> m_requestToggle{false};
    std::atomic<bool> m_requestForceCombat{false};
    std::atomic<bool> m_requestReloadConfig{false};

    // Published by the script thread, read by the input thread.
    std::atomic<int> m_hotkeyToggle{0x76};        // VK_F7 until the config says otherwise
    std::atomic<int> m_hotkeyForceCombat{0x77};   // VK_F8
    std::atomic<int> m_hotkeyReloadConfig{0x78};  // VK_F9
};

} // namespace drs

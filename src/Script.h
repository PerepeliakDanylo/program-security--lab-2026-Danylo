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
//
// Cost on the main thread (1.2): a CALM/COMBAT switch writes every bound field
// with no system call - tens of microseconds for ~60 weapons. 1.1 spent ~450 ms
// there (two VirtualQuery calls per field into a multi-gigabyte heap region),
// which was the hitch felt on every switch.

#pragma once

#include "CombatDetector.h"
#include "Config.h"
#include "WeaponPatcher.h"

#include <atomic>
#include <cstddef>
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
    void adoptUnlistedGuns(); // script thread: asks the game which unlisted objects are guns
    void tick(std::uint64_t nowMs);
    void handleRequests(std::uint64_t nowMs);
    void enterState(ModState next, std::uint64_t nowMs, const char* reason);
    void requestProfile(bool combat);
    void flushPendingWrite();
    void refreshHeldWeapon(int playerPedHandle);
    void clearHeldDisplay();
    bool versionGatePasses();
    void disablePermanently(const char* reason);
    void publishHotkeys();
    int  cooldownTenthsLeft(std::uint64_t nowMs) const;

    Config         m_config;
    CombatDetector m_detector;
    WeaponPatcher  m_patcher;

    ModState      m_state              = ModState::Initialising;
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

    // The weapons in the player's hands (1.2; the left hand since 1.2.1): what the
    // overlay's second and third lines and the "weapon in (left) hand" log lines
    // show. The label natives are asked only when a hand's weapon changes.
    struct HeldHand
    {
        static constexpr int kSeenCapacity = 64;
        std::uint32_t hash                = 0u;
        bool          isGun               = false;   // asked only for a gun the plugin does not manage
        char          label[64]           = {};
        std::uint32_t seen[kSeenCapacity] = {};      // first time in this hand = one info line
        int           seenCount           = 0;
    };
    // Describes one hand after its weapon changed: whether an unmanaged weapon is
    // a gun and the game's label for it (two natives, once per change).
    void describeHand(HeldHand& hand, const HeldWeaponStatus& status);
    // One overlay line for a hand; suffix is "x2" for two identical guns.
    void formatHand(char* out, std::size_t size, const HeldHand& hand,
                    const HeldWeaponStatus& status, const char* suffix) const;
    // One info line the first time a gun is taken in this hand this session.
    void logHand(const char* which, HeldHand& hand, const HeldWeaponStatus& status,
                 const char* note);
    // Revolver or pistol: the game's class natives, else the WEAPON_REVOLVER_ /
    // WEAPON_PISTOL_ prefix of a name the plugin knows. Called once per new pair.
    bool isSidearmHash(std::uint32_t hash) const;
    // true the first time `hash` is seen in this hand this session.
    static bool firstTimeInHand(HeldHand& hand, std::uint32_t hash);

    HeldHand m_right;   // primary hand
    HeldHand m_left;    // secondary hand; hash != 0 only for a dual-wield pair
    // The last pair of weapons seen in the two hands and whether both are
    // sidearms - classified once per pair, not at every poll (NFR-01).
    std::uint32_t m_pairRight      = 0u;
    std::uint32_t m_pairLeft       = 0u;
    bool          m_pairIsSidearms = false;
    // Set when the value shown for the weapon in hand may have changed (a profile
    // was written). Without a change of weapon or of values, refreshHeldWeapon()
    // returns before describing or formatting anything (NFR-01).
    bool     m_heldDetailDirty = true;

    std::atomic<bool> m_requestToggle{false};
    std::atomic<bool> m_requestForceCombat{false};
    std::atomic<bool> m_requestReloadConfig{false};

    // Published by the script thread, read by the input thread.
    std::atomic<int> m_hotkeyToggle{0x76};        // VK_F7 until the config says otherwise
    std::atomic<int> m_hotkeyForceCombat{0x77};   // VK_F8
    std::atomic<int> m_hotkeyReloadConfig{0x78};  // VK_F9
};

} // namespace drs

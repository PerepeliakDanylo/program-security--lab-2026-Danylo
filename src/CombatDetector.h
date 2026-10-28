// CombatDetector.h — decides "is there a gunfight", nothing else.
//
// It does not change state, does not write to memory and does not know that
// profiles exist. It polls a handful of signals and answers one question.
//
// The logic worth arguing about:
//
//   * Aiming on its own is NOT combat. Hunting a deer means aiming, holding still
//     and firing precisely - exactly the situation where a slow, deliberate
//     reload is the point of the mod. Aiming only counts when something hostile
//     is already established.
//   * (1.2) Shooting AT A PERSON is combat even with PlayerShooting = 0: the shot
//     is sampled every frame and, at that moment, the entity under the crosshair
//     or locked on to is checked - living human, not an animal, not the player.
//     The fight then lasts DamageMemorySeconds after the last such shot.
//   * (1.2) Once a fight is on (COMBAT or COOLDOWN), the player's own shots keep
//     it on even with PlayerShooting = 0 (ShootingSustainsCombat). Shooting at
//     game in CALM still never starts a fight.
//   * (1.2) Shots are latched per frame. 1.1 asked IS_PED_SHOOTING four times a
//     second, so most shots fell between two questions.
//   * (1.2.1) A shot counts for two seconds, not for one poll: 1.2.0 flipped
//     COMBAT -> COOLDOWN between two shots and back on the next one.

#pragma once

#include "Config.h"

#include <cstddef>
#include <cstdint>

namespace drs {

struct SignalSnapshot
{
    bool shooting        = false;   // PlayerShooting: a shot in the last 2 s (1.2.1)
    bool aiming          = false;
    bool melee           = false;
    bool recentDamage    = false;
    bool hostileNearby   = false;
    bool wanted          = false;
    bool deadEye         = false;
    bool attacking       = false;   // AttackingHumans: shot at a person recently
    bool sustainedByShot = false;   // ShootingSustainsCombat: shot during a fight
    int  hostileCount    = 0;

    bool anyCombat() const
    {
        const bool hardEvidence = shooting || melee || recentDamage || hostileNearby ||
                                  wanted || deadEye || attacking || sustainedByShot;
        const bool aimingCounts = aiming && (hostileNearby || recentDamage);
        return hardEvidence || aimingCounts;
    }
};

class CombatDetector
{
public:
    void configure(const Config& config);

    // Called from the script thread on EVERY tick. Cheap: one native unless the
    // player is firing in that very frame.
    void sampleTick(int playerPedHandle, int playerIdHandle, std::uint64_t nowMs);

    // Called from the script thread at DetectorHz. nowMs is a monotonic tick
    // count. inFight is true while the state machine is in COMBAT or COOLDOWN.
    SignalSnapshot poll(int playerPedHandle, int playerIdHandle, std::uint64_t nowMs,
                        bool inFight);

    const SignalSnapshot& last() const noexcept { return m_last; }

    // Human-readable list of the signals that are currently true, for the log.
    const char* describe(char* buffer, std::size_t bufferSize) const;

private:
    GeneralSettings m_general;
    SignalSettings  m_signals;

    SignalSnapshot m_last;
    std::uint64_t  m_lastPedScanMs   = 0;
    std::uint64_t  m_lastDamageMs    = 0;
    std::uint64_t  m_lastAttackMs    = 0;
    std::uint64_t  m_lastShotMs      = 0;   // frame time of the player's last shot
    int            m_cachedHostiles  = 0;
    bool           m_warnedNoWanted  = false;
    bool           m_warnedNoDeadEye = false;
};

} // namespace drs

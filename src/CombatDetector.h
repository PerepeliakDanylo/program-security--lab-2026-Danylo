// CombatDetector.h — decides "is there a gunfight", nothing else.
//
// It does not change state, does not write to memory and does not know that
// profiles exist. It polls a handful of signals and answers one question.
//
// The one piece of logic worth arguing about: aiming on its own is NOT combat.
// Hunting a deer means aiming, holding still and firing precisely — exactly the
// situation where a slow, deliberate reload is the point of the mod. Aiming only
// counts when something hostile is already established.

#pragma once

#include "Config.h"

#include <cstdint>

namespace drs {

struct SignalSnapshot
{
    bool shooting      = false;
    bool aiming        = false;
    bool melee         = false;
    bool recentDamage  = false;
    bool hostileNearby = false;
    bool wanted        = false;
    bool deadEye       = false;
    int  hostileCount  = 0;

    bool anyCombat() const
    {
        const bool hardEvidence = shooting || melee || recentDamage || hostileNearby ||
                                  wanted || deadEye;
        const bool aimingCounts = aiming && (hostileNearby || recentDamage);
        return hardEvidence || aimingCounts;
    }
};

class CombatDetector
{
public:
    void configure(const Config& config);

    // Called from the script thread at DetectorHz. nowMs is a monotonic tick count.
    SignalSnapshot poll(int playerPedHandle, int playerIdHandle, std::uint64_t nowMs);

    const SignalSnapshot& last() const noexcept { return m_last; }

    // Human-readable list of the signals that are currently true, for the log.
    const char* describe(char* buffer, std::size_t bufferSize) const;

private:
    GeneralSettings m_general;
    SignalSettings  m_signals;

    SignalSnapshot m_last;
    std::uint64_t  m_lastPedScanMs   = 0;
    std::uint64_t  m_lastDamageMs    = 0;
    int            m_cachedHostiles  = 0;
    bool           m_warnedNoWanted  = false;
    bool           m_warnedNoDeadEye = false;
};

} // namespace drs

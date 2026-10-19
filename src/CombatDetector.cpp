#include "CombatDetector.h"
#include "GameApi.h"
#include "Logger.h"

#include <cstdio>
#include <cstring>

namespace drs {

void CombatDetector::configure(const Config& config)
{
    m_general = config.general();
    m_signals = config.signals();

    m_lastPedScanMs  = 0;
    m_lastDamageMs   = 0;
    m_cachedHostiles = 0;

    if (m_signals.wantedByLaw && !game::wantedCheckAvailable() && !m_warnedNoWanted)
    {
        m_warnedNoWanted = true;
        DRS_INFO("detector: WantedByLaw is on in the config but the underlying check is "
                 "not available on this build; the signal will always read false");
    }
    if (m_signals.deadEye && !game::deadEyeCheckAvailable() && !m_warnedNoDeadEye)
    {
        m_warnedNoDeadEye = true;
        DRS_INFO("detector: DeadEye is on in the config but the underlying check is "
                 "not available on this build; the signal will always read false");
    }
}

SignalSnapshot CombatDetector::poll(int playerPedHandle, int playerIdHandle,
                                    std::uint64_t nowMs)
{
    SignalSnapshot snapshot;

    if (playerPedHandle == 0)
    {
        m_last = snapshot;
        return snapshot;
    }

    if (m_signals.playerShooting)
    {
        snapshot.shooting = game::isPedShooting(playerPedHandle);
    }
    if (m_signals.melee)
    {
        snapshot.melee = game::isPedInMeleeCombat(playerPedHandle);
    }
    if (m_signals.playerAiming)
    {
        snapshot.aiming = game::isPlayerFreeAiming(playerIdHandle) ||
                          game::isPlayerTargettingAnything(playerIdHandle);
    }

    if (m_signals.recentDamage)
    {
        if (game::hasEntityBeenDamagedByAnyPed(playerPedHandle))
        {
            m_lastDamageMs = nowMs;
            // Clearing is what makes this edge-triggered. Without it the flag
            // stays set and the player is "in combat" until the next load.
            game::clearEntityDamageFlag(playerPedHandle);
        }
        const std::uint64_t memoryMs =
            static_cast<std::uint64_t>(m_general.damageMemorySeconds * 1000.0f);
        snapshot.recentDamage = (m_lastDamageMs != 0) && (nowMs - m_lastDamageMs <= memoryMs);
    }

    if (m_signals.hostileNearby)
    {
        const std::uint64_t scanIntervalMs =
            (m_general.pedScanHz > 0)
                ? static_cast<std::uint64_t>(1000 / m_general.pedScanHz)
                : 500ull;

        // The ped sweep is the expensive signal, so it runs on its own, slower
        // clock and the result is reused in between.
        if (m_lastPedScanMs == 0 || nowMs - m_lastPedScanMs >= scanIntervalMs)
        {
            m_lastPedScanMs  = nowMs;
            m_cachedHostiles = game::hostilePedsNearPlayer(playerPedHandle,
                                                           m_general.threatRadius,
                                                           m_general.maxPedsScanned);
        }
        snapshot.hostileCount  = m_cachedHostiles;
        snapshot.hostileNearby = (m_cachedHostiles > 0);
    }

    if (m_signals.wantedByLaw && game::wantedCheckAvailable())
    {
        snapshot.wanted = game::isPlayerWantedByLaw(playerIdHandle);
    }
    if (m_signals.deadEye && game::deadEyeCheckAvailable())
    {
        snapshot.deadEye = game::isDeadEyeActive(playerIdHandle);
    }

    m_last = snapshot;
    return snapshot;
}

const char* CombatDetector::describe(char* buffer, std::size_t bufferSize) const
{
    if (buffer == nullptr || bufferSize == 0)
    {
        return "";
    }
    buffer[0] = '\0';

    auto append = [&](const char* tag) {
        if (buffer[0] != '\0')
        {
            strncat_s(buffer, bufferSize, "+", _TRUNCATE);
        }
        strncat_s(buffer, bufferSize, tag, _TRUNCATE);
    };

    if (m_last.shooting)      { append("shooting"); }
    if (m_last.melee)         { append("melee"); }
    if (m_last.recentDamage)  { append("damaged"); }
    if (m_last.hostileNearby) { append("hostile"); }
    if (m_last.wanted)        { append("wanted"); }
    if (m_last.deadEye)       { append("deadeye"); }
    if (m_last.aiming)        { append("aiming"); }
    if (buffer[0] == '\0')
    {
        strncat_s(buffer, bufferSize, "none", _TRUNCATE);
    }
    return buffer;
}

} // namespace drs

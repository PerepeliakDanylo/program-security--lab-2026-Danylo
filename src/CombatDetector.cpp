#include "CombatDetector.h"
#include "GameApi.h"
#include "Logger.h"

#include <chrono>
#include <cstdio>
#include <cstring>

namespace drs {

namespace {

// 1.2.1: how long one shot counts, for PlayerShooting and for "a shot keeps the
// fight on". A shot is an instant; 1.2.0 counted it for exactly one poll (250 ms
// at DetectorHz = 4), so with shots further apart than that the state went
// COMBAT -> COOLDOWN between two shots and COOLDOWN -> COMBAT on the next one,
// four or five times a second in the overlay and two log lines per shot (1.2.0
// run 1 log, 17:44 and 17:45). Values were never affected - COOLDOWN keeps the
// COMBAT values - but the state the player sees must not flicker. Two seconds
// bridge the gap between aimed shots of any hand-held gun, bolt-action rifles
// included, and delay the start of the cooldown after the LAST shot by at most
// that much.
constexpr std::uint64_t kShotHoldMs = 2000;

} // namespace

void CombatDetector::configure(const Config& config)
{
    m_general = config.general();
    m_signals = config.signals();

    m_lastPedScanMs  = 0;
    m_lastDamageMs   = 0;
    m_lastAttackMs   = 0;
    m_lastShotMs     = 0;
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

    DRS_INFO("detector: shooting %d, aiming %d, melee %d, damage %d, hostile %d (nearest %d "
             "within %.0f m), wanted %d, dead eye %d, attacking people %d, shots keep a fight "
             "on %d",
             m_signals.playerShooting ? 1 : 0, m_signals.playerAiming ? 1 : 0,
             m_signals.melee ? 1 : 0, m_signals.recentDamage ? 1 : 0,
             m_signals.hostileNearby ? 1 : 0, m_general.maxPedsScanned,
             static_cast<double>(m_general.threatRadius),
             m_signals.wantedByLaw ? 1 : 0, m_signals.deadEye ? 1 : 0,
             m_signals.attackingHumans ? 1 : 0, m_signals.shootingSustainsCombat ? 1 : 0);
}

void CombatDetector::sampleTick(int playerPedHandle, int playerIdHandle, std::uint64_t nowMs)
{
    // Every frame. A shot is visible to IS_PED_SHOOTING for only a few frames;
    // 1.1 asked four times a second and most shots fell between two questions.
    if (playerPedHandle == 0)
    {
        return;
    }
    if (!m_signals.playerShooting && !m_signals.attackingHumans &&
        !m_signals.shootingSustainsCombat)
    {
        return;
    }
    if (!game::isPedShooting(playerPedHandle))
    {
        return;
    }

    m_lastShotMs = nowMs;

    // Who was the shot aimed at? Asked only in the frames where the player is
    // actually firing, so these natives are not on the per-frame budget.
    if (m_signals.attackingHumans &&
        game::isPlayerTargetingLivingHuman(playerIdHandle, playerPedHandle))
    {
        if (m_lastAttackMs == 0)
        {
            DRS_DEBUG("detector: shot at a person");
        }
        m_lastAttackMs = nowMs;
    }
}

SignalSnapshot CombatDetector::poll(int playerPedHandle, int playerIdHandle,
                                    std::uint64_t nowMs, bool inFight)
{
    SignalSnapshot snapshot;

    // A shot in the last kShotHoldMs (1.2.1; 1.2.0: a shot since the last poll).
    const bool shot = (m_lastShotMs != 0) && (nowMs - m_lastShotMs <= kShotHoldMs);

    if (playerPedHandle == 0)
    {
        m_last = snapshot;
        return snapshot;
    }

    const std::uint64_t memoryMs =
        static_cast<std::uint64_t>(m_general.damageMemorySeconds * 1000.0f);

    if (m_signals.playerShooting)
    {
        snapshot.shooting = shot;
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
        snapshot.recentDamage = (m_lastDamageMs != 0) && (nowMs - m_lastDamageMs <= memoryMs);
    }

    // 1.2: a shot at a person is a fight, whatever PlayerShooting says. It lasts
    // DamageMemorySeconds after the last such shot, then the normal cooldown.
    if (m_signals.attackingHumans)
    {
        snapshot.attacking = (m_lastAttackMs != 0) && (nowMs - m_lastAttackMs <= memoryMs);
    }

    // 1.2: while a fight is on (COMBAT or COOLDOWN), the player's own shots keep
    // it on. In CALM they never start one - shooting at game stays calm.
    if (m_signals.shootingSustainsCombat)
    {
        snapshot.sustainedByShot = inFight && shot;
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
            m_lastPedScanMs = nowMs;
            // Timed, so the log shows whether a hitch is this scan.
            const auto scanStart = std::chrono::steady_clock::now();
            m_cachedHostiles = game::hostilePedsNearPlayer(playerPedHandle,
                                                           m_general.threatRadius,
                                                           m_general.maxPedsScanned);
            const double scanMs = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - scanStart).count();
            if (scanMs >= 2.0)   // log only when it actually cost something
            {
                DRS_INFO("ped scan: %d hostile(s), %.1f ms", m_cachedHostiles, scanMs);
            }
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

    if (m_last.shooting)        { append("shooting"); }
    if (m_last.attacking)       { append("attacking"); }
    if (m_last.sustainedByShot) { append("shot"); }
    if (m_last.melee)           { append("melee"); }
    if (m_last.recentDamage)    { append("damaged"); }
    if (m_last.hostileNearby)   { append("hostile"); }
    if (m_last.wanted)          { append("wanted"); }
    if (m_last.deadEye)         { append("deadeye"); }
    if (m_last.aiming)          { append("aiming"); }
    if (buffer[0] == '\0')
    {
        strncat_s(buffer, bufferSize, "none", _TRUNCATE);
    }
    return buffer;
}

} // namespace drs

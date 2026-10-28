// GameApi.cpp — the SDK boundary.
//
// ============================================================================
//  READ BEFORE BUILDING
//
//  Every native called in this file was checked against the rdr3 native
//  database (https://alloc8or.re/rdr3/nativedb/ — rdr3, NOT rdr2, that URL does
//  not exist) and is recorded in docs/NATIVES.md with its hash and exact
//  signature. The natives added in 1.2 (section 3.6 there) were checked on
//  2026-10-24 against the generated natives.h this project builds with. The
//  expected number of compile errors here is therefore zero.
//
//  If one does appear, it means the natives.h you generated differs from what
//  was checked. Procedure, in this order:
//   1. Look the native up in your generated inc/natives.h.
//   2. Fix the call and update the row in docs/NATIVES.md, including the date.
//   3. Only if the native is genuinely absent: set its DRS_HAVE_* switch to 0,
//      write the entry in docs/UNVERIFIED.md, and leave that signal off in the
//      shipped INI.
//
//  Do NOT "fix" a compile error by inventing a hash and calling nativeInit /
//  nativeCall directly. A wrong hash compiles cleanly and does nothing, which is
//  exactly the failure this file is structured to prevent.
// ============================================================================

#include "GameApi.h"
#include "Logger.h"
#include "MemScan.h"

#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

// --- SDK ---------------------------------------------------------------------
// Three third-party headers, NOT in this repository; docs/BUILD.md section 2
// says which archive each one comes from. The build refuses to configure until
// all three are present, so a missing header is one clear message instead of a
// wall of compiler errors.
//
//   inc/main.h      Alexander Blade SDK        (scriptRegister, nativeInit, ...)
//   inc/types.h     Alexander Blade SDK        (Ped, Hash, Vector3, ...)
//   inc/natives.h   generated at https://alloc8or.re/rdr3/nativedb/
//
// The .lib is linked from ScriptHook V2 2.0 while the headers come from the 2019
// SDK. That combination is intentional: V2 keeps the same API architecture, and
// every function taken from main.h is a dllimport declaration, so a symbol that
// V2 does not export fails at link time by name instead of failing silently.
//
// natives.h comes from the live database and NOT from the 2019 SDK archive on
// purpose: the SDK copy was generated for build 1207, and the natives this
// plugin needs for Dead Eye, the law system and on-screen text are either
// unnamed placeholders or dead nullsubs in that copy.
//
// NativeShim.h is ours and MUST be included between types.h and natives.h; it
// supplies invoke<>() and the handle typedefs the generated header assumes.
// nativeCaller.h from the SDK is deliberately NOT used — see NativeShim.h.
#include "inc/main.h"
#include "inc/types.h"
#include "NativeShim.h"
#include "inc/natives.h"

// --- capability switches -----------------------------------------------------
// There is no DRS_HAVE_GAME_VERSION switch any more: the build number is read
// from the executable's own version resource in GameBuild.cpp, so it needs no
// SDK support and cannot be unavailable.
#ifndef DRS_HAVE_WANTED
#define DRS_HAVE_WANTED 1         // LAW::IS_LAW_INCIDENT_ACTIVE, verified 2026-09-28
#endif
#ifndef DRS_HAVE_DEADEYE
#define DRS_HAVE_DEADEYE 1        // PLAYER::_IS_SPECIAL_ABILITY_ACTIVE, verified
#endif
#ifndef DRS_HAVE_ONLINE_CHECK
#define DRS_HAVE_ONLINE_CHECK 1
#endif
#ifndef DRS_HAVE_ENTITY_COORDS
#define DRS_HAVE_ENTITY_COORDS 1
#endif
#ifndef DRS_HAVE_DRAW_TEXT
#define DRS_HAVE_DRAW_TEXT 1      // UIDEBUG::_BG_*, confirmed in game 2026-10-19
#endif

namespace drs {
namespace game {

namespace {

bool       g_initialised = false;
KeyHandler g_keyHandler  = nullptr;

// Adapter between the SDK's keyboard callback shape and our narrow one.
// Only key-down transitions are forwarded, and only the virtual key code:
// the handler is not allowed to do anything that would need more.
void __stdcall keyboardTrampoline(DWORD key, WORD /*repeats*/, BYTE /*scanCode*/,
                                  BOOL /*isExtended*/, BOOL /*isWithAlt*/,
                                  BOOL wasDownBefore, BOOL isUpNow)
{
    if (g_keyHandler != nullptr && isUpNow == FALSE && wasDownBefore == FALSE)
    {
        g_keyHandler(static_cast<int>(key));
    }
}

float distanceSquared(const Vector3& a, const Vector3& b)
{
    const float dx = a.x - b.x;
    const float dy = a.y - b.y;
    const float dz = a.z - b.z;
    return dx * dx + dy * dy + dz * dz;
}

// A person the player is attacking: exists, is a ped, is human, is not the
// player, and is either alive or was killed by the player - a one-shot kill can
// mark the target dead in the very frame the shot is seen, and that is still an
// attack on a person. Animals are left out on purpose: shooting a deer is the one
// situation this mod must keep calm.
//   PED::GET_PED_SOURCE_OF_DEATH 0x93C8B64DEB84728C Entity (Ped)
bool isHumanVictim(Entity entity, int playerPedHandle)
{
    if (entity == 0 || entity == playerPedHandle)
    {
        return false;
    }
    if (ENTITY::DOES_ENTITY_EXIST(entity) == 0)
    {
        return false;
    }
    if (ENTITY::IS_ENTITY_A_PED(entity) == 0)
    {
        return false;
    }
    if (PED::IS_PED_HUMAN(entity) == 0)
    {
        return false;
    }
    if (ENTITY::IS_ENTITY_DEAD(entity) == 0)
    {
        return true;
    }
    return PED::GET_PED_SOURCE_OF_DEATH(entity) == playerPedHandle;
}

// The ped pool has no documented upper bound for story mode; 1024 handles is
// far above anything RDR2 streams in at once and costs 4 KB, once.
constexpr int kPedBufferSize = 1024;

struct NearPed
{
    float distanceSquared = 0.0f;
    int   handle          = 0;
};

} // namespace

void registerScript(void* module, void (*entryPoint)())
{
    scriptRegister(static_cast<HMODULE>(module), entryPoint);
}

void unregisterScript(void* module)
{
    scriptUnregister(static_cast<HMODULE>(module));
}

void registerKeyboardHandler(KeyHandler handler)
{
    g_keyHandler = handler;
    keyboardHandlerRegister(&keyboardTrampoline);
}

void unregisterKeyboardHandler()
{
    keyboardHandlerUnregister(&keyboardTrampoline);
    g_keyHandler = nullptr;
}

void initialise()
{
    if (g_initialised)
    {
        return;
    }
    g_initialised = true;

    DRS_INFO("game api: online check %s, wanted signal %s, dead eye signal %s, "
             "on-screen text %s",
             DRS_HAVE_ONLINE_CHECK ? "available" : "UNAVAILABLE",
             DRS_HAVE_WANTED       ? "available" : "UNAVAILABLE",
             DRS_HAVE_DEADEYE      ? "available" : "UNAVAILABLE",
             DRS_HAVE_DRAW_TEXT    ? "available" : "UNAVAILABLE");
}

void waitTicks(std::uint32_t milliseconds)
{
    scriptWait(static_cast<DWORD>(milliseconds));
}

bool isGameplayReady()
{
    // CAMERA::IS_SCREEN_FADED_IN    0x37F9A426FBCF4AF2  BOOL ()
    // DLC::GET_IS_LOADING_SCREEN_ACTIVE 0x71D4BF5890659B0C BOOL ()
    // Both recorded in docs/NATIVES.md 3.5. A wrong answer here only delays the
    // start of the scan (Script caps the wait at 120 s); nothing is written.
    return CAMERA::IS_SCREEN_FADED_IN() != 0 && DLC::GET_IS_LOADING_SCREEN_ACTIVE() == 0;
}

int playerId()
{
    return PLAYER::PLAYER_ID();
}

int playerPed()
{
    return PLAYER::PLAYER_PED_ID();
}

bool isPedShooting(int ped)
{
    return PED::IS_PED_SHOOTING(ped) != 0;
}

bool isPedReloading(int ped)
{
    return PED::IS_PED_RELOADING(ped) != 0;
}

bool isPedInMeleeCombat(int ped)
{
    return PED::IS_PED_IN_MELEE_COMBAT(ped) != 0;
}

bool isPlayerFreeAiming(int player)
{
    return PLAYER::IS_PLAYER_FREE_AIMING(player) != 0;
}

bool isPlayerTargettingAnything(int player)
{
    return PLAYER::IS_PLAYER_TARGETTING_ANYTHING(player) != 0;
}

bool isPlayerTargetingLivingHuman(int player, int playerPedHandle)
{
    // PLAYER::GET_ENTITY_PLAYER_IS_FREE_AIMING_AT 0xA6817C110B830EAD BOOL (Player, Entity&)
    // PLAYER::GET_PLAYER_TARGET_ENTITY            0xAE663DDD99C8A670 BOOL (Player, Entity&)
    // Free aim covers the crosshair; the target entity covers soft lock-on. The
    // generated header takes the out parameter by reference (no &).
    Entity aimed = 0;
    if (PLAYER::GET_ENTITY_PLAYER_IS_FREE_AIMING_AT(player, aimed) != 0 &&
        isHumanVictim(aimed, playerPedHandle))
    {
        return true;
    }
    Entity locked = 0;
    if (PLAYER::GET_PLAYER_TARGET_ENTITY(player, locked) != 0 &&
        isHumanVictim(locked, playerPedHandle))
    {
        return true;
    }
    return false;
}

bool hasEntityBeenDamagedByAnyPed(int entity)
{
    return ENTITY::HAS_ENTITY_BEEN_DAMAGED_BY_ANY_PED(entity) != 0;
}

void clearEntityDamageFlag(int entity)
{
    ENTITY::CLEAR_ENTITY_LAST_DAMAGE_ENTITY(entity);
}

bool onlineCheckAvailable()
{
#if DRS_HAVE_ONLINE_CHECK
    return true;
#else
    return false;
#endif
}

bool isOnlineSession()
{
#if DRS_HAVE_ONLINE_CHECK
    return NETWORK::NETWORK_IS_SESSION_ACTIVE() != 0;
#else
    return false;
#endif
}

bool wantedCheckAvailable()
{
#if DRS_HAVE_WANTED
    return true;
#else
    return false;
#endif
}

bool isPlayerWantedByLaw(int player)
{
#if DRS_HAVE_WANTED
    // RDR2 has its own law system in the LAW namespace, and this is the one
    // native there that answers the question directly as a boolean.
    //
    // PLAYER::GET_PLAYER_WANTED_LEVEL still exists and still reads, but the
    // GTA-style family around it is hollow on this build: the native database
    // marks SET_PLAYER_WANTED_LEVEL and CLEAR_PLAYER_WANTED_LEVEL as "nullsub,
    // doesn't do anything". Reading a number maintained by a system whose
    // setters do nothing is not a signal worth trusting.
    return LAW::IS_LAW_INCIDENT_ACTIVE(player) != 0;
#else
    (void)player;
    return false;   // unknown must never force COMBAT
#endif
}

bool deadEyeCheckAvailable()
{
#if DRS_HAVE_DEADEYE
    return true;
#else
    return false;
#endif
}

bool isDeadEyeActive(int player)
{
#if DRS_HAVE_DEADEYE
    // _ACTIVE, not _ENABLED. The neighbouring _IS_SPECIAL_ABILITY_ENABLED answers
    // "does this player have Dead Eye unlocked", which is true for most of the
    // game and would pin the mod into COMBAT permanently.
    return PLAYER::_IS_SPECIAL_ABILITY_ACTIVE(player) != 0;
#else
    (void)player;
    return false;
#endif
}

int hostilePedsNearPlayer(int playerPedHandle, float radius, int maxNearest)
{
    if (maxNearest <= 0)
    {
        return 0;
    }

    // Two buffers for the life of the plugin: this runs at PedScanHz and must
    // not allocate (NFR-01).
    static int     handles[kPedBufferSize];
    static NearPed nearby[kPedBufferSize];

    // The WHOLE list, every time. worldGetAllPeds fills the array in pool
    // order, not by distance: 1.1 asked for MaxPedsScanned (32) entries and so
    // never saw a hostile that happened to sit in pool slot 33 or later - which
    // is why a spawned enemy was sometimes not detected at all in a busy area.
    const int found = worldGetAllPeds(handles, kPedBufferSize);
    if (found <= 0)
    {
        return 0;
    }
    const int count = (found < kPedBufferSize) ? found : kPedBufferSize;

#if DRS_HAVE_ENTITY_COORDS
    const Vector3 playerPosition = ENTITY::GET_ENTITY_COORDS(playerPedHandle, TRUE, FALSE);
    const float   radiusSquared  = radius * radius;
#else
    (void)radius;
#endif

    int nearCount = 0;
    for (int i = 0; i < count; ++i)
    {
        const int candidate = handles[i];
        if (candidate == 0 || candidate == playerPedHandle)
        {
            continue;
        }
        if (ENTITY::DOES_ENTITY_EXIST(candidate) == 0)
        {
            continue;
        }

        // Distance first: in a town most of the list is far away, and one
        // coordinate read is cheaper than the checks that follow.
        float d2 = 0.0f;
#if DRS_HAVE_ENTITY_COORDS
        const Vector3 position = ENTITY::GET_ENTITY_COORDS(candidate, TRUE, FALSE);
        d2 = distanceSquared(playerPosition, position);
        if (!(d2 <= radiusSquared))   // also rejects NaN
        {
            continue;
        }
#endif
        if (ENTITY::IS_ENTITY_DEAD(candidate) != 0)
        {
            continue;
        }
        nearby[nearCount].distanceSquared = d2;
        nearby[nearCount].handle          = candidate;
        ++nearCount;
    }

    // Only the nearest maxNearest are asked the combat question. nth_element is
    // linear and allocation-free; the order inside the kept part is irrelevant.
    int evaluate = nearCount;
    if (nearCount > maxNearest)
    {
        std::nth_element(nearby, nearby + maxNearest, nearby + nearCount,
                         [](const NearPed& a, const NearPed& b) {
                             return a.distanceSquared < b.distanceSquared;
                         });
        evaluate = maxNearest;
    }

    int hostiles = 0;
    for (int i = 0; i < evaluate; ++i)
    {
        // The direction matters: "is this ped fighting the player", not the
        // reverse. IS_PED_IN_COMBAT(a, b) answers "is a in combat with b", and
        // its second parameter is a Ped handle, never a boolean.
        if (PED::IS_PED_IN_COMBAT(nearby[i].handle, playerPedHandle) != 0)
        {
            ++hostiles;
        }
    }

    return hostiles;
}

std::uint32_t currentWeaponHash(int ped)
{
    Hash weapon = 0;
    // Note there is no & on `weapon`. The generated natives.h declares the out
    // parameter as `Hash&` and takes the address itself; the 2019 SDK header
    // declared it as `Hash*`. Passing &weapon here compiles against the wrong
    // one of the two and writes the weapon hash over a pointer.
    WEAPON::GET_CURRENT_PED_WEAPON(ped, weapon, TRUE, 0, FALSE);
    return static_cast<std::uint32_t>(weapon);
}

bool isWeaponAGun(std::uint32_t weaponHash)
{
    // WEAPON::IS_WEAPON_A_GUN 0x705BE297EEBDB95D BOOL (Hash)
    // "Returns true if CWeaponInfoFlags::Flags::Gun is set."
    if (weaponHash == 0u)
    {
        return false;
    }
    return WEAPON::IS_WEAPON_A_GUN(static_cast<Hash>(weaponHash)) != 0;
}

bool weaponLabel(std::uint32_t weaponHash, char* out, std::size_t capacity)
{
    // WEAPON::_GET_WEAPON_NAME 0x89CF5FF3D363311E const char* (Hash)
    // The returned pointer belongs to the game. It is copied out at once through
    // a guarded read, so even a wrong pointer can only produce "no label".
    if (out == nullptr || capacity == 0)
    {
        return false;
    }
    out[0] = '\0';
    if (weaponHash == 0u)
    {
        return false;
    }
    const char* label = WEAPON::_GET_WEAPON_NAME(static_cast<Hash>(weaponHash));
    if (MemScan::readCString(label, out, capacity) == 0)
    {
        return false;
    }
    return std::strcmp(out, "WNS_INVALID") != 0;
}

bool drawTextAvailable()
{
#if DRS_HAVE_DRAW_TEXT
    return true;
#else
    return false;
#endif
}

void drawDebugText(const char* text, float x, float y)
{
#if DRS_HAVE_DRAW_TEXT
    if (text == nullptr)
    {
        return;
    }

    // RDR2 has no GTA-style text command chain: BEGIN_TEXT_COMMAND_*,
    // SET_TEXT_SCALE, SET_TEXT_CENTRE and friends do not exist in the native
    // database at all, and HUD::_DISPLAY_TEXT / HUD::_SET_TEXT_COLOR are marked
    // "nullsub, does nothing since build 1436". The live path is UIDEBUG, and
    // its text argument must come from VAR_STRING rather than being a plain
    // pointer — that requirement is documented on the native itself.
    //
    // Call order and VAR_STRING flags confirmed in game on 1.0.1491.50
    // (2026-10-19). The text lives for one frame, so the caller draws it every
    // frame (Overlay.h).
    UIDEBUG::_BG_SET_TEXT_SCALE(0.0f, 0.5f);
    UIDEBUG::_BG_SET_TEXT_COLOR(255, 255, 255, 255);
    UIDEBUG::_BG_DISPLAY_TEXT(MISC::VAR_STRING(10, "LITERAL_STRING", text), x, y);
#else
    (void)text; (void)x; (void)y;
#endif
}

} // namespace game
} // namespace drs

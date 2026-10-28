// GameApi.h — the ONLY place in this plugin that talks to the game.
//
// Everything that depends on the ScriptHookRDR2 SDK lives behind this interface,
// for one reason: the SDK headers and the native names are the part of this
// project that cannot be verified from a desk. Isolating them means
//
//   * Config, Logger, MemScan and WeaponPatcher compile with zero SDK headers
//     and can be built and reasoned about on their own;
//   * when a native turns out to be named differently in RDR2, exactly one file
//     changes, and the compiler points at the line.
//
// That last point is deliberate policy, not laziness: natives are called through
// the SDK's own natives.h by NAME. A native that does not exist in RDR2 is a
// compile error here, instead of a call that silently does nothing in game —
// which is the single most common way a mod like this fails.
//
// Every function below returns a safe, conservative answer if its native is not
// available: false for "is something happening", 0 for counts. A signal that
// cannot be evaluated must never be able to force the mod into COMBAT.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace drs {
namespace game {

// --- SDK registration -------------------------------------------------------
// main.cpp goes through these so it needs no SDK header of its own.
// `module` is the plugin's HMODULE as an opaque pointer.
void registerScript(void* module, void (*entryPoint)());
void unregisterScript(void* module);

// The handler is called on the game's INPUT thread. It must only set flags.
using KeyHandler = void (*)(int virtualKey);
void registerKeyboardHandler(KeyHandler handler);
void unregisterKeyboardHandler();

// Called once from the script thread before anything else.
void initialise();

// scriptWait. The only place the plugin yields.
void waitTicks(std::uint32_t milliseconds);

// True once the loading screen is gone and the screen has faded in. Used only to
// decide when to start the one-off memory scan (Script::waitForGameplay).
bool isGameplayReady();

// The game's build number is deliberately NOT here. It comes from the running
// executable's own version resource, in GameBuild.h, and not from the SDK —
// see the header comment there for why the SDK's getGameVersion() cannot
// answer the question [Versions] actually asks.

int playerId();
int playerPed();

bool isPedShooting(int ped);
bool isPedReloading(int ped);
bool isPedInMeleeCombat(int ped);

bool isPlayerFreeAiming(int player);
bool isPlayerTargettingAnything(int player);

// True when the entity the player is free-aiming at, or has locked on to, is a
// human ped other than the player that is alive or was killed by the player (a
// one-shot kill can mark the target dead in the frame the shot is seen). Animals
// never count. Called only on ticks where the player is shooting
// (CombatDetector::sampleTick), so its natives are not on every frame.
bool isPlayerTargetingLivingHuman(int player, int playerPed);

bool hasEntityBeenDamagedByAnyPed(int entity);
void clearEntityDamageFlag(int entity);

// True only if the plugin can positively determine that a multiplayer session is
// active. "Unknown" is reported as false, and the caller logs that the check is
// unavailable rather than pretending the game is single player.
bool isOnlineSession();
bool onlineCheckAvailable();

bool isPlayerWantedByLaw(int player);
bool wantedCheckAvailable();

bool isDeadEyeActive(int player);
bool deadEyeCheckAvailable();

// Counts peds that are in combat AGAINST the player, within `radius`. The whole
// ped list is read every time (1.1 read only the first MaxPedsScanned entries of
// the pool, in pool order, and missed hostiles whenever more peds were loaded -
// in a camp or a town); `maxNearest` then limits how many of the NEAREST peds
// are asked the combat question. Direction of the test: does the other ped fight
// the player, not the other way round.
int hostilePedsNearPlayer(int playerPed, float radius, int maxNearest);

// Hash of the weapon currently in the player's hands, 0 if unavailable.
// This is the PRIMARY hand (attach point 0) - the right hand.
std::uint32_t currentWeaponHash(int ped);

// 1.2.1: the weapon in the SECONDARY hand (attach point 1,
// WEAPON_ATTACH_POINT_HAND_SECONDARY) - the left-hand gun when dual wielding.
// 0 if the game reports none.
std::uint32_t secondaryWeaponHash(int ped);

// 1.2.1: true when a weapon OBJECT is attached to the secondary hand. Guards the
// dual-wield readout against a hash the game may report for a hand that is in
// fact empty.
bool weaponObjectInSecondaryHand(int ped);

// WEAPON::IS_WEAPON_A_GUN - true if the weapon info carries the Gun flag.
bool isWeaponAGun(std::uint32_t weaponHash);

// 1.2.1: revolver or pistol, by the game's own weapon class
// (WEAPON::IS_WEAPON_REVOLVER / WEAPON::IS_WEAPON_PISTOL). The only guns that can
// be dual wielded.
bool isSidearm(std::uint32_t weaponHash);

// 1.2.1: a hand-held firearm: IS_WEAPON_A_GUN AND one of the six firearm classes
// (revolver, pistol, repeater, rifle, shotgun, sniper rifle). IS_WEAPON_A_GUN
// alone also answers true for the vehicle-damage pseudo-weapons
// WEAPON_RAMMED_BY_CAR and WEAPON_RUN_OVER_BY_CAR (1.2.0 logs), which 1.2.0 then
// adopted as "unlisted guns".
bool isHandheldFirearm(std::uint32_t weaponHash);

// WEAPON::_GET_WEAPON_NAME - the weapon's text label, e.g. "WNS_REVOLVER_CATTLEMAN"
// ("WNS_INVALID" for an unknown hash). Copied into `out` through a guarded read.
// Returns false if no usable label came back.
bool weaponLabel(std::uint32_t weaponHash, char* out, std::size_t capacity);

// On-screen text, used only by the optional debug overlay.
void drawDebugText(const char* text, float x, float y);
bool drawTextAvailable();

} // namespace game
} // namespace drs

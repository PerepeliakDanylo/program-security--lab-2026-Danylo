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

// Counts peds that are in combat AGAINST the player, within `radius`, looking at
// no more than `maxPeds` candidates. Note the direction of the test: the
// question is whether the other ped fights the player, not the other way round.
int hostilePedsNearPlayer(int playerPed, float radius, int maxPeds);

// Hash of the weapon currently in the player's hands, 0 if unavailable.
std::uint32_t currentWeaponHash(int ped);

// On-screen text, used only by the optional debug overlay.
void drawDebugText(const char* text, float x, float y);
bool drawTextAvailable();

} // namespace game
} // namespace drs

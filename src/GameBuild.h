// GameBuild.h — which build of the game we are running inside.
//
// Why this is NOT part of GameApi and NOT taken from the SDK
// ---------------------------------------------------------
// The obvious source is ScriptHook's getGameVersion(). It is the wrong source,
// for a reason that is visible in the SDK headers themselves:
//
//   * Alexander Blade's SDK 1.0.1207.73 declares
//         enum eGameVersion { VER_AUTO, VER_1_0_1207_60_RGS, VER_1_0_1207_69_RGS, ... }
//   * ScriptHookRDR2 V2 1.1.1 declares
//         enum eGameVersion { VER_AUTO, VER_1_0_1491_18_RGS, VER_1_0_1491_18_STEAM, ... }
//
// Both are ordinals of a list that is frozen at the moment the SDK was released,
// and neither list contains build 1491.50. A function that returns "2" cannot be
// compared against a "1.0.1491.50" written by a player in [Versions], and on a
// build the SDK has never heard of it returns VER_UNK.
//
// The game executable already carries its own version, in the VS_VERSIONINFO
// resource of the running image — the exact four numbers Windows shows in
// Properties -> Details -> File version. That is read here: no SDK, no disk I/O,
// no version.lib, no guessing, and it keeps working after a game patch that the
// SDK does not know about yet.
//
// No dependency on the ScriptHookRDR2 SDK.

#pragma once

#include <string>

namespace drs {

// Four-part file version of the running executable, e.g. "1.0.1491.50".
// Empty string means "could not be determined" — callers must treat that as
// unknown, never as a match. Computed once and cached.
std::string gameBuildVersion();

// True when the string a player wrote in [Versions] Supported names the build
// that is actually running.
//
// Both the full form and the short form are accepted, because both are in use:
// the launcher and the mod scene say "1491.50", Windows file properties say
// "1.0.1491.50". A shorter configured value matches only on a dot boundary, so
// "91.50" does NOT match "1.0.1491.50" — a substring test would have.
bool gameBuildMatches(const std::string& reported, const std::string& configured);

} // namespace drs

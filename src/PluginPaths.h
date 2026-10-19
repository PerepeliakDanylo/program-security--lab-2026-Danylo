// PluginPaths.h — where the plugin's own files live.
//
// The value returned here contains the player's Windows account name. It is used
// to open files and is NEVER passed to the logger or to any player-facing text.
// Requirement NFR-12 / privacy policy section 7: file NAME only in every message.
//
// No dependency on the ScriptHookRDR2 SDK.

#pragma once

#include <string>

namespace drs {

// Directory of the loaded plugin DLL, with a trailing backslash.
// Empty string if it could not be determined — callers must handle that by
// disabling the feature that needed it, not by falling back to the CWD.
std::wstring pluginDirectory();

// Full path for a file that belongs to the plugin. Any directory part of
// fileName is stripped first, so a config key can never redirect a write.
std::wstring pluginFilePath(const std::string& fileName);

std::wstring widenUtf8(const std::string& narrow);
std::string  stripDirectory(const std::string& raw, const char* fallback);

} // namespace drs

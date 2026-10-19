#include "GameBuild.h"

#include <windows.h>
#include <winver.h>     // VS_FIXEDFILEINFO, VS_VERSION_INFO. Declarations only:
                        // nothing here calls GetFileVersionInfo, so the plugin
                        // still links against kernel32 alone (no version.lib).

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace drs {

namespace {

// The signature the resource compiler writes at the head of VS_FIXEDFILEINFO.
constexpr std::uint32_t kFixedFileInfoSignature = 0xFEEF04BDu;

std::string formatVersion(DWORD versionMs, DWORD versionLs)
{
    char buffer[48] = {};
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "%u.%u.%u.%u",
                static_cast<unsigned>(HIWORD(versionMs)),
                static_cast<unsigned>(LOWORD(versionMs)),
                static_cast<unsigned>(HIWORD(versionLs)),
                static_cast<unsigned>(LOWORD(versionLs)));
    return std::string(buffer);
}

// Reads the version resource of the main module — the game executable, because
// GetModuleHandleW(nullptr) is RDR2.exe and not this plugin.
//
// The resource is walked by hand instead of through VerQueryValue for two
// reasons: the bytes are already mapped into the process (no file is opened, so
// nothing can fail on a locked or moved executable), and it avoids a link-time
// dependency for four numbers.
std::string readVersionFromRunningImage()
{
    const HMODULE module = GetModuleHandleW(nullptr);
    if (module == nullptr)
    {
        return std::string();
    }

    const HRSRC found = FindResourceW(module, MAKEINTRESOURCEW(VS_VERSION_INFO), RT_VERSION);
    if (found == nullptr)
    {
        return std::string();
    }

    const DWORD size = SizeofResource(module, found);
    if (size < sizeof(VS_FIXEDFILEINFO))
    {
        return std::string();
    }

    const HGLOBAL loaded = LoadResource(module, found);
    if (loaded == nullptr)
    {
        return std::string();
    }

    const auto* bytes = static_cast<const std::uint8_t*>(LockResource(loaded));
    if (bytes == nullptr)
    {
        return std::string();
    }

    // VS_VERSIONINFO starts with a variable-length UTF-16 key ("VS_VERSION_INFO")
    // and is then padded to a 4-byte boundary, so the offset of the fixed part is
    // not a constant. Scanning for the signature on DWORD alignment is what the
    // layout guarantees, and the buffer is bounded by SizeofResource.
    for (DWORD offset = 0; offset + sizeof(VS_FIXEDFILEINFO) <= size; offset += sizeof(DWORD))
    {
        VS_FIXEDFILEINFO info = {};
        std::memcpy(&info, bytes + offset, sizeof(info));
        if (info.dwSignature == kFixedFileInfoSignature)
        {
            return formatVersion(info.dwFileVersionMS, info.dwFileVersionLS);
        }
    }

    return std::string();
}

} // namespace

std::string gameBuildVersion()
{
    static const std::string cached = readVersionFromRunningImage();
    return cached;
}

bool gameBuildMatches(const std::string& reported, const std::string& configured)
{
    if (reported.empty() || configured.empty())
    {
        return false;
    }
    if (reported == configured)
    {
        return true;
    }
    if (configured.size() >= reported.size())
    {
        return false;
    }

    // Tail match, but only starting right after a dot: "1491.50" matches
    // "1.0.1491.50", "91.50" does not.
    const std::size_t start = reported.size() - configured.size();
    return reported[start - 1] == '.' &&
           reported.compare(start, configured.size(), configured) == 0;
}

} // namespace drs

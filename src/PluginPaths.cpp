#include "PluginPaths.h"

#include <windows.h>

namespace drs {

std::wstring widenUtf8(const std::string& narrow)
{
    if (narrow.empty())
    {
        return std::wstring();
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, narrow.c_str(),
                                           static_cast<int>(narrow.size()), nullptr, 0);
    if (needed <= 0)
    {
        return std::wstring();
    }
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, narrow.c_str(), static_cast<int>(narrow.size()),
                        &wide[0], needed);
    return wide;
}

std::string stripDirectory(const std::string& raw, const char* fallback)
{
    std::string name = raw;
    const std::size_t slash = name.find_last_of("\\/:");
    if (slash != std::string::npos)
    {
        name = name.substr(slash + 1);
    }
    if (name.empty())
    {
        name = fallback;
    }
    return name;
}

std::wstring pluginDirectory()
{
    HMODULE self = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&pluginDirectory),
                            &self))
    {
        return std::wstring();
    }

    wchar_t buffer[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(self, buffer, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
    {
        return std::wstring();
    }

    std::wstring path(buffer, length);
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
    {
        return std::wstring();
    }
    return path.substr(0, slash + 1);
}

std::wstring pluginFilePath(const std::string& fileName)
{
    const std::wstring directory = pluginDirectory();
    if (directory.empty())
    {
        return std::wstring();
    }
    return directory + widenUtf8(stripDirectory(fileName, "DynamicReloadSpeed.log"));
}

} // namespace drs

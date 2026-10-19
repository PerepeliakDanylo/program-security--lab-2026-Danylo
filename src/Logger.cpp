#include "Logger.h"
#include "PluginPaths.h"

#include <windows.h>

#include <cstring>
#include <ctime>

namespace drs {

LogLevel parseLogLevel(const std::string& text, LogLevel fallback)
{
    if (_stricmp(text.c_str(), "off") == 0)   { return LogLevel::Off; }
    if (_stricmp(text.c_str(), "error") == 0) { return LogLevel::Error; }
    if (_stricmp(text.c_str(), "info") == 0)  { return LogLevel::Info; }
    if (_stricmp(text.c_str(), "debug") == 0) { return LogLevel::Debug; }
    return fallback;
}

const char* logLevelName(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Off:   return "off";
    case LogLevel::Error: return "error";
    case LogLevel::Info:  return "info";
    case LogLevel::Debug: return "debug";
    }
    return "info";
}

Logger& Logger::instance()
{
    static Logger logger;
    return logger;
}

Logger::~Logger()
{
    shutdown();
}

void Logger::configure(const std::string& fileName, LogLevel level, std::uint32_t maxSizeMb)
{
    if (maxSizeMb == 0u)
    {
        maxSizeMb = 32u;
    }

    // Re-configuring with the same file must NOT reopen it: the file is opened
    // truncating, and reopening would throw away everything written before the
    // config was read - which is exactly the part that explains why the config
    // was read the way it was.
    if (m_enabled && m_file != nullptr && fileName == m_openFileName &&
        level != LogLevel::Off)
    {
        if (m_level != level)
        {
            info("log level changed from %s to %s", logLevelName(m_level),
                 logLevelName(level));
            const bool nowDebug = (level == LogLevel::Debug);
            m_level = level;
            if (nowDebug)
            {
                info("log level is 'debug': this file will grow fast, switch back to "
                     "'info' when done");
            }
        }
        m_maxBytes = static_cast<std::uint64_t>(maxSizeMb) * 1024ull * 1024ull;
        return;
    }

    shutdown();

    m_level            = level;
    m_sizeLimitReached = false;
    m_bytesWritten     = 0;
    m_maxBytes         = static_cast<std::uint64_t>(maxSizeMb) * 1024ull * 1024ull;

    if (level == LogLevel::Off)
    {
        m_enabled = false;
        m_openFileName.clear();
        return;
    }

    const std::wstring full = pluginFilePath(fileName);
    if (full.empty())
    {
        m_enabled = false;
        return;
    }

    // "w" and not "a": one file per session keeps it readable. A player who wants
    // the previous session's log renames the file before launching.
    //
    // Plain narrow text mode, NOT "w, ccs=UTF-8". A ccs= flag switches the stream
    // into Unicode mode, where narrow functions (fputs/fprintf) are an invalid
    // parameter: the CRT calls __fastfail and the game dies with 0xC0000409 and
    // no dialog. Every line we write is already ASCII/UTF-8 bytes, so plain "w"
    // produces a valid UTF-8 file (without BOM).
    m_file = nullptr;
    if (_wfopen_s(&m_file, full.c_str(), L"w") != 0 || m_file == nullptr)
    {
        // Rule 1: a logging failure disables logging, nothing else.
        m_file    = nullptr;
        m_enabled = false;
        return;
    }

    m_enabled      = true;
    m_openFileName = fileName;

    if (m_level == LogLevel::Debug)
    {
        info("log level is 'debug': this file will grow fast, switch back to 'info' when done");
    }
}

void Logger::shutdown()
{
    if (m_file != nullptr)
    {
        std::fflush(m_file);
        std::fclose(m_file);
        m_file = nullptr;
    }
    m_enabled = false;
}

void Logger::writeLine(LogLevel level, const char* format, va_list args)
{
    if (!m_enabled || m_file == nullptr || m_sizeLimitReached)
    {
        return;
    }
    if (static_cast<int>(level) > static_cast<int>(m_level))
    {
        return;
    }

    SYSTEMTIME now = {};
    GetLocalTime(&now);

    char body[1024] = {};
    const int bodyLength = _vsnprintf_s(body, sizeof(body), _TRUNCATE, format, args);
    if (bodyLength < 0)
    {
        strncpy_s(body, sizeof(body), "<log line too long>", _TRUNCATE);
    }

    char line[1152] = {};
    const int lineLength = _snprintf_s(line, sizeof(line), _TRUNCATE,
                                       "[%02u:%02u:%02u.%03u] [%-5s] %s\n",
                                       now.wHour, now.wMinute, now.wSecond, now.wMilliseconds,
                                       logLevelName(level), body);
    if (lineLength <= 0)
    {
        return;
    }

    if (m_bytesWritten + static_cast<std::uint64_t>(lineLength) > m_maxBytes)
    {
        m_sizeLimitReached = true;
        const char* stop = "log size limit reached\n";
        std::fputs(stop, m_file);
        std::fflush(m_file);
        return;
    }

    if (std::fputs(line, m_file) == EOF)
    {
        // Writing failed mid-session: same rule as failing to open.
        shutdown();
        return;
    }

    m_bytesWritten += static_cast<std::uint64_t>(lineLength);
    std::fflush(m_file);
}

void Logger::error(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    writeLine(LogLevel::Error, format, args);
    va_end(args);
}

void Logger::info(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    writeLine(LogLevel::Info, format, args);
    va_end(args);
}

void Logger::debug(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    writeLine(LogLevel::Debug, format, args);
    va_end(args);
}

} // namespace drs

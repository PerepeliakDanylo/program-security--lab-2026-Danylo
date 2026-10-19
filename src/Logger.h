// Logger.h — timestamped file log, flushed after every line.
//
// Three rules that are not negotiable and are the reason this class exists at all:
//
//  1. A logging failure is NEVER an error of the mod. The game folder can be
//     read-only, or the file can be held open by something else. In that case the
//     logger switches itself off for the session, silently and permanently, and
//     must not touch the plugin's error counter.
//  2. Absolute paths are never written. The path to the game folder contains the
//     player's Windows account name — the only piece of private data this mod can
//     leak. File NAME only, everywhere, including error messages.
//  3. Flush after every line. A log that is lost when another mod crashes the game
//     is worthless exactly when it matters.
//
// No dependency on the ScriptHookRDR2 SDK.

#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>

namespace drs {

enum class LogLevel : int
{
    Off   = 0,
    Error = 1,
    Info  = 2,
    Debug = 3
};

LogLevel parseLogLevel(const std::string& text, LogLevel fallback);
const char* logLevelName(LogLevel level);

class Logger
{
public:
    static Logger& instance();

    // fileName is a bare file name, never a path. The file is created next to the
    // plugin DLL. Calling configure() twice closes and reopens.
    void configure(const std::string& fileName, LogLevel level, std::uint32_t maxSizeMb);
    void shutdown();

    void error(const char* format, ...);
    void info(const char* format, ...);
    void debug(const char* format, ...);

    bool isEnabled() const noexcept { return m_enabled; }
    LogLevel level() const noexcept { return m_level; }

    // True once the size cap was hit. Exposed only so the overlay can say so.
    bool sizeLimitReached() const noexcept { return m_sizeLimitReached; }

private:
    Logger() = default;
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void writeLine(LogLevel level, const char* format, va_list args);

    std::FILE*    m_file             = nullptr;
    std::string   m_openFileName;
    LogLevel      m_level            = LogLevel::Info;
    bool          m_enabled          = false;
    bool          m_sizeLimitReached = false;
    std::uint64_t m_bytesWritten     = 0;
    std::uint64_t m_maxBytes         = 32ull * 1024ull * 1024ull;
};

} // namespace drs

#define DRS_ERROR(...) ::drs::Logger::instance().error(__VA_ARGS__)
#define DRS_INFO(...)  ::drs::Logger::instance().info(__VA_ARGS__)
#define DRS_DEBUG(...) ::drs::Logger::instance().debug(__VA_ARGS__)

#include "Overlay.h"
#include "GameApi.h"
#include "Logger.h"

#include <cstdio>
#include <cstring>

namespace drs {

namespace {

constexpr float kLeft        = 0.02f;
constexpr float kFirstLine   = 0.02f;
constexpr float kSecondLine  = 0.05f;

} // namespace

Overlay& Overlay::instance()
{
    static Overlay overlay;
    return overlay;
}

void Overlay::configure(const Config& config)
{
    m_enabled = config.debug().onScreenState;

    // Force a re-format on the next update(): the version or state may be shown
    // for the first time, and a stale cache from before a config re-read must
    // never survive it.
    m_lastState    = nullptr;
    m_lastHostiles = -1;
    m_lastCooldown = -2;

    if (m_enabled && !game::drawTextAvailable() && !m_warned)
    {
        m_warned = true;
        DRS_INFO("overlay: OnScreenState = 1 but on-screen text is not available in "
                 "this build of the plugin, so nothing will be drawn. The state is "
                 "still written to the log on every transition.");
    }
}

void Overlay::setDetail(const char* text)
{
    if (text == nullptr || text[0] == '\0')
    {
        m_detail[0] = '\0';
        return;
    }
    if (std::strcmp(text, m_detail) != 0)
    {
        strncpy_s(m_detail, sizeof(m_detail), text, _TRUNCATE);
    }
}

void Overlay::update(const char* stateName, int hostileCount, int cooldownTenths,
                     const char* version)
{
    if (!m_enabled || !game::drawTextAvailable() || stateName == nullptr)
    {
        return;
    }

    const bool changed = (stateName != m_lastState) ||
                         (hostileCount != m_lastHostiles) ||
                         (cooldownTenths != m_lastCooldown);
    if (changed)
    {
        m_lastState    = stateName;
        m_lastHostiles = hostileCount;
        m_lastCooldown = cooldownTenths;

        if (cooldownTenths >= 0)
        {
            _snprintf_s(m_text, sizeof(m_text), _TRUNCATE,
                        "Dynamic Reload %s  |  %s %d.%ds  |  hostiles: %d",
                        version, stateName, cooldownTenths / 10, cooldownTenths % 10,
                        hostileCount);
        }
        else
        {
            _snprintf_s(m_text, sizeof(m_text), _TRUNCATE,
                        "Dynamic Reload %s  |  %s  |  hostiles: %d",
                        version, stateName, hostileCount);
        }
    }

    // Re-issued every frame: immediate-mode text lives for one frame only.
    game::drawDebugText(m_text, kLeft, kFirstLine);
    if (m_detail[0] != '\0')
    {
        game::drawDebugText(m_detail, kLeft, kSecondLine);
    }
}

} // namespace drs

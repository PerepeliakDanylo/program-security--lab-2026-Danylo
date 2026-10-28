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
constexpr float kThirdLine   = 0.08f;

// Copies text into a line buffer; nullptr or "" clears it. strcmp first, so an
// unchanged line costs one comparison and no copy.
void setLine(char* line, std::size_t size, const char* text)
{
    if (text == nullptr || text[0] == '\0')
    {
        line[0] = '\0';
        return;
    }
    if (std::strcmp(text, line) != 0)
    {
        strncpy_s(line, size, text, _TRUNCATE);
    }
}

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
    setLine(m_detail, sizeof(m_detail), text);
}

void Overlay::setSecondHand(const char* text)
{
    setLine(m_secondHand, sizeof(m_secondHand), text);
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
    if (m_secondHand[0] != '\0')
    {
        game::drawDebugText(m_secondHand, kLeft, kThirdLine);
    }
}

} // namespace drs

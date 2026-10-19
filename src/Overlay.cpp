#include "Overlay.h"
#include "GameApi.h"
#include "Logger.h"

#include <cstdio>

namespace drs {

Overlay& Overlay::instance()
{
    static Overlay overlay;
    return overlay;
}

void Overlay::configure(const Config& config)
{
    m_enabled = config.debug().onScreenState;

    if (m_enabled && !game::drawTextAvailable() && !m_warned)
    {
        m_warned = true;
        DRS_INFO("overlay: OnScreenState = 1 but the on-screen text natives are not "
                 "confirmed for this build yet, so nothing will be drawn. The state "
                 "is still written to the log on every transition.");
    }
}

void Overlay::update(const char* stateName, int hostileCount, const char* version)
{
    if (!m_enabled || !game::drawTextAvailable())
    {
        return;
    }

    char text[128] = {};
    _snprintf_s(text, sizeof(text), _TRUNCATE,
                "Dynamic Reload %s  |  %s  |  hostiles: %d",
                version, stateName, hostileCount);
    game::drawDebugText(text, 0.02f, 0.02f);
}

} // namespace drs

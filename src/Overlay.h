// Overlay.h — optional on-screen state readout. Off by default.
//
// It shows the state name, the plugin version and the hostile count. It never
// shows a file path, an address, or anything else that would leak where the game
// is installed — a screenshot of the overlay is something players post publicly.

#pragma once

#include "Config.h"

namespace drs {

class Overlay
{
public:
    static Overlay& instance();

    void configure(const Config& config);
    void update(const char* stateName, int hostileCount, const char* version);

private:
    Overlay() = default;

    bool m_enabled  = false;
    bool m_warned   = false;
};

} // namespace drs

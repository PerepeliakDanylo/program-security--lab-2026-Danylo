// Overlay.h — optional on-screen state readout. Off by default (OnScreenState).
//
// It shows the plugin version, the state name (with the remaining cooldown while
// in COOLDOWN) and the hostile count. It never shows a file path, an address, or
// anything else that would leak where the game is installed — a screenshot of
// the overlay is something players post publicly.
//
// RDR2's UIDEBUG text is immediate-mode: a string drawn once stays on screen for
// exactly one frame. update() is therefore called on EVERY script tick (and in the
// start-up wait loops), not at the detector rate — drawing it at 4 Hz is what made
// the 1.0 overlay flicker. To keep the hot path cheap (NFR-01), the text is
// re-formatted only when one of its inputs changes; every other frame just
// re-issues the cached string.

#pragma once

#include "Config.h"

namespace drs {

class Overlay
{
public:
    static Overlay& instance();

    void configure(const Config& config);

    // stateName must be a string literal or otherwise outlive the call.
    // cooldownTenths < 0 means "no cooldown to show".
    void update(const char* stateName, int hostileCount, int cooldownTenths,
                const char* version);

private:
    Overlay() = default;

    bool m_enabled = false;
    bool m_warned  = false;

    // Cache: the inputs the current m_text was formatted from.
    const char* m_lastState     = nullptr;
    int         m_lastHostiles  = -1;
    int         m_lastCooldown  = -2;
    char        m_text[128]     = {};
};

} // namespace drs

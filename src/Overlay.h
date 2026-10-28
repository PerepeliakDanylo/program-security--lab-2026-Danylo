// Overlay.h — optional on-screen state readout. Off by default (OnScreenState).
//
// Line 1: plugin version, state name (with the remaining cooldown while in
// COOLDOWN) and the hostile count. Line 2 (1.2): the weapon in the player's
// hands and the reload rate the plugin has put there - or "not managed" - so a
// weapon that does not switch can be identified on the spot; with two identical
// guns drawn it ends in "x2" (1.2.1). Line 3 (1.2.1): the left-hand gun when two
// DIFFERENT guns are dual wielded; line 2 is then the right hand. No line ever
// shows a file path, an address, or anything else that would leak where the game
// is installed: a screenshot of the overlay is something players post publicly.
//
// RDR2's UIDEBUG text is immediate-mode: a string drawn once stays on screen for
// exactly one frame. update() is therefore called on EVERY script tick (and in the
// start-up wait loops), not at the detector rate - drawing it at 4 Hz is what made
// the 1.0 overlay flicker. To keep the hot path cheap (NFR-01), the text is
// re-formatted only when one of its inputs changes; every other frame just
// re-issues the cached strings.

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

    // Second line. nullptr or "" hides it. Copied; cheap when unchanged.
    void setDetail(const char* text);

    // Third line (1.2.1), the left-hand gun. Same rules as setDetail().
    void setSecondHand(const char* text);

private:
    Overlay() = default;

    bool m_enabled = false;
    bool m_warned  = false;

    // Cache: the inputs the current m_text was formatted from.
    const char* m_lastState     = nullptr;
    int         m_lastHostiles  = -1;
    int         m_lastCooldown  = -2;
    char        m_text[128]     = {};
    char        m_detail[128]   = {};
    char        m_secondHand[128] = {};
};

} // namespace drs

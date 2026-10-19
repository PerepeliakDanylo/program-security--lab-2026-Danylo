// main.cpp — DLL entry point and nothing else.
//
// Note there is no SDK header here. Registration goes through GameApi so that
// the single file which depends on ScriptHookRDR2 stays the single file which
// depends on ScriptHookRDR2.
//
// DllMain does the absolute minimum the Windows loader allows: no file I/O, no
// memory scanning, no waiting on anything. All real work happens on the script
// thread that ScriptHook creates for us.

#include "GameApi.h"
#include "Logger.h"
#include "Script.h"

#include <windows.h>

namespace {

HMODULE g_module = nullptr;

void scriptMain()
{
    drs::Script::instance().run();
}

void keyHandler(int virtualKey)
{
    drs::Script::instance().onKeyDown(virtualKey);
}

} // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        g_module = module;
        DisableThreadLibraryCalls(module);
        drs::game::registerScript(module, &scriptMain);
        drs::game::registerKeyboardHandler(&keyHandler);
        break;

    case DLL_PROCESS_DETACH:
        // Last chance to put the game's values back. If this path is reached
        // because the process is terminating, restoring is pointless but
        // harmless; if it is reached because an ASI loader unloads us, it is the
        // difference between a clean game and a game left in slow-reload mode.
        drs::game::unregisterKeyboardHandler();
        drs::Script::instance().onUnload();
        drs::game::unregisterScript(module);
        break;

    default:
        break;
    }
    return TRUE;
}

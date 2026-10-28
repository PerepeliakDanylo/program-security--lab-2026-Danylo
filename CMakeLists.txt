cmake_minimum_required(VERSION 3.21)

project(DynamicReloadSpeed VERSION 1.2.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# RDR2 Dynamic Reload — ASI plugin
#
# Build:
#   cmake -B build -G "Visual Studio 17 2022" -A x64
#   cmake --build build --config Release
#
# Result: build/Release/DynamicReloadSpeed.asi
#
# Prerequisites:
#   * Visual Studio 2022 Build Tools with the C++ workload, plus a Windows SDK.
#   * Four third-party files: three headers in  <this folder>/inc  and one import
#     library in  <this folder>/lib . They come from three different archives —
#     docs/BUILD.md section 2 says which file comes from where and why. None of
#     them is redistributed with this repository.
# ---------------------------------------------------------------------------

if(NOT WIN32)
    message(FATAL_ERROR "This plugin targets Windows x64 only.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Configure with -A x64: RDR2 is a 64-bit process.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static runtime: a player must not have to install a Visual C++ redistributable
# to use a game mod (NFR-08).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(DRS_SOURCES
    src/main.cpp
    src/Script.cpp
    src/CombatDetector.cpp
    src/WeaponPatcher.cpp
    src/MemScan.cpp
    src/Config.cpp
    src/Logger.cpp
    src/Overlay.cpp
    src/GameApi.cpp
    src/GameBuild.cpp
    src/PluginPaths.cpp
)

set(DRS_HEADERS
    src/Script.h
    src/CombatDetector.h
    src/WeaponPatcher.h
    src/MemScan.h
    src/Config.h
    src/Logger.h
    src/Overlay.h
    src/GameApi.h
    src/GameBuild.h
    src/NativeShim.h
    src/PluginPaths.h
    src/WeaponTable.h
    src/Joaat.h
)

add_library(DynamicReloadSpeed SHARED ${DRS_SOURCES} ${DRS_HEADERS})

target_include_directories(DynamicReloadSpeed PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# These two must match DynamicReloadSpeed.vcxproj exactly, or the two build paths
# stop being equivalent. NOMINMAX is not cosmetic: <windows.h> is included before
# <algorithm> in Script.cpp and WeaponPatcher.cpp, and without it the function-like
# macro max(a,b) mangles every std::max( call site into a syntax error (C2589).
# The .vcxproj already had both; CMake did not, so the CMake path - the one
# docs/BUILD.md calls primary - was the only one that failed.
#
# UNICODE/_UNICODE are here for the same reason and were missed the same way.
# The .vcxproj sets <CharacterSet>Unicode</CharacterSet>, which defines both;
# CMake did not. This is not only about which A/W function name a bare API call
# resolves to - it also changes MACRO CONSTANTS. RT_VERSION expands to
# MAKEINTRESOURCE(16), and MAKEINTRESOURCE is MAKEINTRESOURCEW only when UNICODE
# is defined. Without it RT_VERSION has type LPSTR, while GameBuild.cpp:45 passes
# it to FindResourceW, whose third parameter is LPCWSTR -> C2664, CMake path only.
# Checking that the code calls explicit *W functions is NOT enough to rule this
# class out; the constants must match too.
target_compile_definitions(DynamicReloadSpeed PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

# Structured exception handling is used in MemScan to survive a page being
# freed underneath a read. /EHa is required for __try together with C++ objects
# elsewhere in the same translation unit set.
target_compile_options(DynamicReloadSpeed PRIVATE
    /W4
    /permissive-
    /EHa
    /utf-8
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Release>:/GL>
)

target_link_options(DynamicReloadSpeed PRIVATE
    $<$<CONFIG:Release>:/LTCG>
)

# --- ScriptHookRDR2 SDK -----------------------------------------------------
set(DRS_SCRIPTHOOK_LIB "${CMAKE_CURRENT_SOURCE_DIR}/lib/ScriptHookRDR2.lib"
    CACHE FILEPATH "Full path to ScriptHookRDR2.lib from the ScriptHook SDK")

if(NOT EXISTS "${DRS_SCRIPTHOOK_LIB}")
    message(FATAL_ERROR
        "ScriptHookRDR2.lib not found at ${DRS_SCRIPTHOOK_LIB}.\n"
        "Copy it there, or configure with -DDRS_SCRIPTHOOK_LIB=<full path>.")
endif()

# The .lib is checked above; these three headers are checked here — four files in
# total. Each message names the archive it comes from: the archives are different
# and mixing them up is the likeliest mistake here.
# nativeCaller.h is deliberately absent from this list: src/NativeShim.h replaces
# it, because the SDK version cannot compile invoke<void>. See NativeShim.h.
set(DRS_SDK_HEADERS
    "main.h|Alexander Blade SDK 1.0.1207.73, inc/main.h (fallback: ScriptHook V2 1.1.1, sdk/main.h)"
    "types.h|Alexander Blade SDK 1.0.1207.73, inc/types.h"
    "natives.h|generated at https://alloc8or.re/rdr3/nativedb/ -> Generate natives.h"
)

set(DRS_MISSING_HEADERS "")
foreach(entry IN LISTS DRS_SDK_HEADERS)
    string(REPLACE "|" ";" parts "${entry}")
    list(GET parts 0 header_name)
    list(GET parts 1 header_origin)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/inc/${header_name}")
        string(APPEND DRS_MISSING_HEADERS "\n  inc/${header_name}   <- ${header_origin}")
    endif()
endforeach()

if(NOT DRS_MISSING_HEADERS STREQUAL "")
    message(FATAL_ERROR
        "Missing third-party header(s) under ${CMAKE_CURRENT_SOURCE_DIR}/inc:"
        "${DRS_MISSING_HEADERS}\n"
        "See docs/BUILD.md section 2. These files are not redistributed here.")
endif()

target_link_libraries(DynamicReloadSpeed PRIVATE "${DRS_SCRIPTHOOK_LIB}")

# --- output name ------------------------------------------------------------
set_target_properties(DynamicReloadSpeed PROPERTIES
    OUTPUT_NAME "DynamicReloadSpeed"
    PREFIX ""
    SUFFIX ".asi"
)

# --- packaging convenience --------------------------------------------------
add_custom_command(TARGET DynamicReloadSpeed POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:DynamicReloadSpeed>/package"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:DynamicReloadSpeed>"
            "$<TARGET_FILE_DIR:DynamicReloadSpeed>/package/DynamicReloadSpeed.asi"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/dist/DynamicReloadSpeed.ini"
            "$<TARGET_FILE_DIR:DynamicReloadSpeed>/package/DynamicReloadSpeed.ini"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/dist/README.txt"
            "$<TARGET_FILE_DIR:DynamicReloadSpeed>/package/README.txt"
    # dist/README.txt describes the archive as four items including a presets\
    # folder, so the packaging step has to produce exactly that. Without this
    # line the documented layout could not be reproduced by the documented build.
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/dist/presets"
            "$<TARGET_FILE_DIR:DynamicReloadSpeed>/package/presets"
    COMMENT "Collecting the release layout in package/"
)

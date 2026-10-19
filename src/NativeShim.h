// NativeShim.h — the glue that makes the generated natives.h compile.
//
// This file is OURS. It is not part of any SDK and must not be replaced by a
// vendor file, because it exists precisely to fix three things the vendor files
// get wrong when combined:
//
//  1. natives.h generated at https://alloc8or.re/rdr3/nativedb/ has NO includes
//     of its own. It needs the types and an invoke<>() already in scope.
//
//  2. That natives.h calls invoke<void>(...) in ~4000 places. The nativeCaller.h
//     shipped in Alexander Blade's 2019 SDK cannot compile a single one of them:
//     its body ends in
//         return *reinterpret_cast<R*>(nativeCall());
//     which is ill-formed for R = void. The 2019 natives.h dodged this by using
//     invoke<Void> with a capital V (typedef DWORD Void), a trick the generated
//     header does not use. `if constexpr` below is the fix.
//
//  3. The generated natives.h uses handle types that the 2019 types.h never
//     had — AnimScene, Prompt, ItemSet, Volume and friends. Missing even one is
//     a compile error, because every native body in that header is a real
//     function that gets type-checked whether or not the plugin calls it.
//
// Consequence for the build: DO NOT put nativeCaller.h into inc/ and do not
// include it. It would collide with invoke() below and reintroduce problem 2.
//
// If a future regeneration of natives.h names a handle type that is not in the
// list below, the compiler will say so by name, and the fix is one more typedef
// here — never an edit to the vendor header.

#pragma once

#include "inc/main.h"    // nativeInit, nativePush64, nativeCall
#include "inc/types.h"   // Ped, Player, Entity, Hash, Vector3, Any, ...

#include <type_traits>

// --- handle types the generated natives.h needs and the 2019 types.h lacks ---
// All of them are script handles, i.e. plain 32-bit integers, exactly like the
// handle typedefs already in types.h.
typedef int AnimScene;
typedef int Item;
typedef int ItemSet;
typedef int PersChar;
typedef int PopZone;
typedef int Promise;
typedef int Prompt;
typedef int PropSet;
typedef int Volume;

// --- native invocation -------------------------------------------------------
// Argument marshalling is per 64-bit slot, little endian, which is what the RAGE
// native ABI expects. A type wider than a slot is a compile error rather than a
// silently truncated argument.

template <typename T>
static inline void drsNativePush(T value)
{
    static_assert(sizeof(T) <= sizeof(UINT64),
                  "native argument does not fit in one 64-bit slot");
    UINT64 slot = 0;
    *reinterpret_cast<T*>(&slot) = value;
    nativePush64(slot);
}

static inline void drsPushArgs()
{
}

template <typename T, typename... Ts>
static inline void drsPushArgs(T arg, Ts... args)
{
    drsNativePush(arg);
    drsPushArgs(args...);
}

// The name `invoke` is fixed: the generated natives.h calls it by that name.
template <typename R, typename... Ts>
static inline R invoke(UINT64 hash, Ts... args)
{
    nativeInit(hash);
    drsPushArgs(args...);

    if constexpr (std::is_void_v<R>)
    {
        nativeCall();
    }
    else
    {
        return *reinterpret_cast<R*>(nativeCall());
    }
}

// Joaat.h — RAGE joaat hashing, compile-time where possible.
//
// The engine hashes the LOWERCASED name. "WEAPON_RIFLE_VARMINT" and
// "weapon_rifle_varmint" must therefore produce the same value; if they do not,
// the resolver will never find anything and every log line will say
// "hash not found in memory".
//
// No dependency on the ScriptHookRDR2 SDK. Header-only on purpose so the hash of
// a literal is a compile-time constant and costs nothing at run time.

#pragma once

#include <cstdint>
#include <cstddef>

namespace drs {

constexpr std::uint32_t joaatLowerChar(char c) noexcept
{
    return (c >= 'A' && c <= 'Z')
        ? static_cast<std::uint32_t>(c - 'A' + 'a')
        : static_cast<std::uint32_t>(static_cast<unsigned char>(c));
}

// Jenkins one-at-a-time over the lowercased string. Unsigned overflow is
// well defined in C++, which is exactly the behaviour RAGE relies on.
constexpr std::uint32_t joaat(const char* text) noexcept
{
    std::uint32_t hash = 0u;
    for (; text && *text != '\0'; ++text)
    {
        hash += joaatLowerChar(*text);
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}

constexpr std::uint32_t joaat(const char* text, std::size_t length) noexcept
{
    std::uint32_t hash = 0u;
    for (std::size_t i = 0; i < length; ++i)
    {
        hash += joaatLowerChar(text[i]);
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}

// User-defined literal so "weapon_rifle_varmint"_joaat is a constant.
constexpr std::uint32_t operator""_joaat(const char* text, std::size_t length) noexcept
{
    return joaat(text, length);
}

} // namespace drs

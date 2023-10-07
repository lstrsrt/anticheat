#pragma once

#include <array>

#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>

struct AutoVirtualAlloc
{
    explicit AutoVirtualAlloc(SIZE_T size, DWORD protect_flags = PAGE_READWRITE, HANDLE process = ::GetCurrentProcess())
        : m_process(process)
    {
        if (m_memory = ::VirtualAllocEx(process, nullptr, size, MEM_RESERVE | MEM_COMMIT, protect_flags))
            m_free = true;
    }

    ~AutoVirtualAlloc()
    {
        if (m_free)
            ::VirtualFreeEx(m_process, m_memory, 0, MEM_RELEASE);
    }

    operator void*() { return m_memory; }
    operator bool() { return m_memory; }

    HANDLE m_process{};
    LPVOID m_memory{};
    bool m_free{};
};

struct AutoVirtualProtect
{
    explicit AutoVirtualProtect(LPVOID addr, SIZE_T size, DWORD flags)
        : m_address(addr), m_size(size)
    {
        ::VirtualProtect(m_address, m_size, flags, &m_flags);
    }

    ~AutoVirtualProtect()
    {
        ::VirtualProtect(m_address, m_size, m_flags, &m_flags);
    }

    LPVOID m_address{};
    SIZE_T m_size{};
    DWORD m_flags{};
};

template<size_t len>
struct StringLiteral
{
    size_t m_length = len - 1;
    std::array<char, len - 1> m_value{ };

    consteval StringLiteral(const char(&str)[len])
    {
        for (size_t i{ }; i < len - 1; i++)
            m_value[i] = str[i];
    }
};

static consteval bool IsHexChar(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
}

static consteval int HexCharToInt(char c)
{
    return (c > '9') ? (c & ~0x20) - 'A' + 10 : (c - '0');
}

static consteval int MakeHexDigits(char a, char b)
{
    return 16 * HexCharToInt(a) + HexCharToInt(b);
}

template<StringLiteral str>
struct Pattern
{
    struct Length
    {
        static consteval auto Get()
        {
            size_t ret{ };
            bool was_digit{ };

            for (size_t i{ }; i < str.m_length; i++) {
                if (IsHexChar(str.m_value[i])) {
                    if (!was_digit)
                        ret++;
                    was_digit = true;
                } else if (str.m_value[i] == '?') {
                    ret++;
                    was_digit = false;
                } else if (str.m_value[i] == ' ')
                    was_digit = false;

            }
            return ret;
        }
    };

    static consteval auto Value()
    {
        constexpr auto len = Length::Get();
        static_assert(len > 0);
        std::array<int, len> ret{ };

        for (size_t i{ }, j{ }; i < str.m_length; i++) {
            if (str.m_value[i] == ' ')
                continue;
            if (IsHexChar(str.m_value[i])) {
                i++;
                if (j < len) {
                    if (IsHexChar(str.m_value[i]))
                        ret[j++] = MakeHexDigits(str.m_value[i - 1], str.m_value[i]);
                }
            } else if (str.m_value[i] == '?')
                ret[j++] = -1;
        }
        return ret;
    }
};

#define PATTERN(str) Pattern<str>::Value()

/*
*  Basic logger with formatting and file output.
*  Allocates and attaches a console in DLL builds.
*/

#pragma once

#include <chrono>
#include <format>
#include <fstream>
#include <iostream>

#ifdef _DEBUG
#define LOG_SUCCESS(fmt, ...) logger::Add<logger::Level::Success>(fmt, __VA_ARGS__)
#define LOG_INFO(fmt, ...) logger::Add<logger::Level::Info>(fmt, __VA_ARGS__)
#define LOG_ERROR(fmt, ...) logger::Add<logger::Level::Error>(fmt, __VA_ARGS__)
#define LOG_RAW(fmt, ...) logger::Add<logger::Level::Raw>(fmt, __VA_ARGS__)
#else
#define LOG_SUCCESS(...) {}
#define LOG_INFO(...) {}
#define LOG_ERROR(...) {}
#define LOG_RAW(...) {}
#endif

struct AutoCriticalSection
{
    AutoCriticalSection(CRITICAL_SECTION* cs)
        : m_crit_sec(cs)
    {
        RtlEnterCriticalSection(m_crit_sec);
    }

    ~AutoCriticalSection()
    {
        RtlLeaveCriticalSection(m_crit_sec);
    }

    CRITICAL_SECTION* m_crit_sec{};
};

namespace logger {

    inline HANDLE console{};
    inline std::wstring file{};
    inline CRITICAL_SECTION crit_sec{};

    enum class Level
    {
        Success,
        Info,
        Error,
        Raw
    };

    template<Level lvl>
    void PrintLogLevel()
    {
        std::cout << "[ ";
        switch (lvl)
        {
        case Level::Success:
            SetConsoleTextAttribute(console, FOREGROUND_GREEN);
            std::cout << '+';
            break;
        case Level::Info:
            SetConsoleTextAttribute(console, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << '*';
            break;
        case Level::Error:
            SetConsoleTextAttribute(console, FOREGROUND_RED);
            std::cout << '!';
            break;
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << " ] ";
    }

    inline void PrintTime()
    {
        const auto time = ch::system_clock::to_time_t(ch::system_clock::now());
        std::tm tm{};
        localtime_s(&tm, &time);
        std::cout << std::put_time(&tm, "[%T] ");
    }

    template<class C, class... Args>
    void AddImpl(std::basic_string_view<C> fmt, std::basic_ofstream<C, std::char_traits<C>> os, Args&&... args)
    {
        constexpr bool wide = std::same_as<C, wchar_t>;
        if constexpr (sizeof...(args) > 0)
        {
            if constexpr (wide)
            {
                const auto& str = std::vformat(fmt, std::make_wformat_args(std::forward<decltype(args)>(args)...));
                std::wcout << str << '\n';
                if (os)
                    os << str << '\n';
            }
            else
            {
                const auto& str = std::vformat(fmt, std::make_format_args(std::forward<decltype(args)>(args)...));
                std::cout << str << '\n';
                if (os)
                    os << str << '\n';
            }
        }
        else
        {
            if constexpr (wide)
            {
                std::wcout << fmt << '\n';
                if (os)
                    os << fmt << '\n';
            }
            else
            {
                std::cout << fmt << '\n';
                if (os)
                    os << fmt << '\n';
            }
        }
    }

    template<Level lvl, class... Args>
    void Add(std::string_view fmt, Args&&... args)
    {
#ifdef _DEBUG
        AutoCriticalSection lk{ &crit_sec };
        if constexpr (lvl != Level::Raw)
        {
            PrintLogLevel<lvl>();
            PrintTime();
        }
        AddImpl<char>(fmt, std::ofstream{ file, std::ios::out | std::ios::app }, std::forward<decltype(args)>(args)...);
#endif
    }

    template<Level lvl, class... Args>
    void Add(std::wstring_view fmt, Args&&... args)
    {
#ifdef _DEBUG
        AutoCriticalSection lk{ &crit_sec };
        if constexpr (lvl != Level::Raw)
        {
            PrintLogLevel<lvl>();
            PrintTime();
        }
        AddImpl<wchar_t>(fmt, std::wofstream{ file, std::ios::out | std::ios::app }, std::forward<decltype(args)>(args)...);
#endif
    }

    inline void Start(std::wstring_view console_title, std::wstring_view log_name)
    {
#ifdef _DEBUG
#ifdef AC_DLL
        AllocConsole();
        AttachConsole(ATTACH_PARENT_PROCESS);
        freopen_s(( FILE** )stdout, "CONOUT$", "w", stdout);
#endif
        console = GetStdHandle(STD_OUTPUT_HANDLE);
        file = log_name;
        RtlInitializeCriticalSection(&crit_sec);
        SetConsoleTitle(console_title.data());
        LOG_SUCCESS("Logger initialized.");
#endif
    }

    inline void End()
    {
#ifdef _DEBUG
#ifdef AC_DLL
        if (stdout && stdout != INVALID_HANDLE_VALUE)
            fclose(stdout);
        if (stdin && stdin != INVALID_HANDLE_VALUE)
            fclose(stdin);
#endif
        RtlDeleteCriticalSection(&crit_sec);
#endif
    }

}

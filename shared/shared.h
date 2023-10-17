#pragma once

#include "config.h"

#ifdef __cplusplus
#define MAYBE_UNUSED [[maybe_unused]]
#define NORETURN [[noreturn]]
#else
#define MAYBE_UNUSED
#define NORETURN __declspec(noreturn)
#endif
#define INTERNAL static

#ifdef _DEBUG
#define DEBUG_STR(x) TEXT(x)
#else
#define DEBUG_STR(x) TEXT("")
#endif

#ifdef AC_LOG_VERBOSE
#define VERBOSE(x) (x)
#else
#define VERBOSE(x)
#endif

// Suppresses C4390 on macros that expand to nothing
#define EMPTY_STATEMENT (( void )0)

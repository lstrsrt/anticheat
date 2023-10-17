#pragma once

#ifdef _M_IX86
#define AC_X86
#elif defined(_M_AMD64)
#define AC_X64
#else
#error Unsupported architecture
#endif

#ifdef __cplusplus
#define AC_API extern "C"
#include <cwchar>
#include <cstring>
#else
#define AC_API
#include <wchar.h>
#include <string.h>
#endif

#include "../shared/config.h"

typedef enum _AC_Result
{
    AC_RSuccess = 0,
    AC_RFailure,
    AC_RInvalidParam1,
    AC_RInvalidParam2,
    AC_RInvalidCall,
} AC_Result;

typedef enum _AC_DetectionType
{
    AC_DSuspiciousDll = 1,
    AC_DSuspiciousThread,
    AC_DProtectionChanged,
    AC_DSectionModified,
    AC_DDebuggerAttached,
    AC_DInvalidTimeout,
    AC_DSuspiciousCall,
    AC_DAttemptedDllLoad,
    AC_DFunctionHooked,
    AC_DSuspiciousMapping,
} AC_DetectionType;

typedef enum _AC_IpAddressType
{
    AC_Ipv4,
    AC_Ipv6
} AC_IpAddressType;

typedef unsigned int AC_Hash32;
typedef unsigned long long AC_Hwid;

typedef struct _AC_IpAddress
{
    AC_IpAddressType m_type;
    const wchar_t* m_value;
    const wchar_t* m_adapter_name;
} AC_IpAddress;

typedef struct _AC_Client
{
    const wchar_t* m_computer_name;
    const wchar_t* m_username;
    AC_IpAddress* m_ip_addresses;
    unsigned int m_ip_count;
    AC_Hwid m_hwid;
} AC_Client;

typedef struct _AC_Address
{
    void* m_ptr;
    void* m_section; // IMAGE_SECTION_HEADER*
    void* m_module; // IMAGE_NT_HEADERS*
} AC_Address;

typedef struct _AC_Hook
{
    AC_Address* m_unique_callers;
    unsigned int m_unique_caller_count;
    unsigned int m_total_call_count;
} AC_Hook;

typedef void(*AC_InitCallback)(const AC_Client*);
typedef void(*AC_HookCallback)(const AC_Hook*, AC_Hash32);
typedef void(*AC_ScanCallback)();
typedef void(*AC_DetectionCallback)(AC_DetectionType, const AC_Client*);

#define AC_HK_NT_PROTECT_VIRTUAL_MEMORY 3178862886U
#define AC_HK_NT_CREATE_THREAD_EX       3976565978U
#define AC_HK_RTL_CREATE_USER_THREAD    2264831878U
#define AC_HK_NT_SUSPEND_THREAD         2106449073U
#define AC_HK_NT_TERMINATE_THREAD       1568514654U
#define AC_HK_NT_SET_CONTEXT_THREAD     3932281316U
#define AC_HK_NT_CREATE_SECTION         1012527970U
#define AC_HK_NT_MAP_VIEW_OF_SECTION    3419005358U
#define AC_HK_BASE_THREAD_INIT_THUNK    2158639706U

/*
* AC_Initialize
*    Initializes main control structures and starts protection threads.
*    The following modules will always be protected
*    even if AC_ProtectModule was never called:
*        ntdll.dll
*        kernel32.dll
*        the module that called AC_Initialize
*
* Return values
*    AC_RSuccess       - Success.
*    AC_RInvalidParam1 - Invalid message address.
*    AC_RInvalidCall   - Function was called more than once.
*    AC_RFailure       - Unspecified failure.
*/
AC_API AC_Result
AC_Initialize();

#ifdef _DEBUG
/*
* AC_End
*    Resets internal structures and terminates protection threads.
*    Afterwards, calling AC_Initialize is allowed again.
*
*    This function is meant for testing and is not exported in Release mode.
*
* Return values
*    AC_RSuccess       - Success.
*    AC_RInvalidCall   - Function was called more than once.
*/
AC_API AC_Result
AC_End();
#endif

/*
* AC_ProtectModule
*    Adds a module to the protection list.
*    Call before AC_Initialize.
*    The module must already be loaded.
*
* Parameters
*    name - Null-terminated module name (length must be shorter than MAX_PATH).
*           Passing NULL protects the calling module.
*
* Return values
*    AC_RSuccess       - Success.
*    AC_RInvalidParam1 - Invalid name.
*    AC_RInvalidCall   - Function was called more than once for the same module
*                        or after AC_Initialize.
*    AC_RFailure       - The module does not exist or is not loaded.
*/
AC_API AC_Result
AC_ProtectModule(const wchar_t* name);

/*
* AC_BlacklistModule
*    Blacklists a module by name.
*
* Parameters
*    name - Null-terminated module name (length must be shorter than MAX_PATH).
*
* Return values
*    AC_RSuccess       - Success.
*    AC_RInvalidParam1 - Invalid name.
*    AC_RInvalidCall   - Function was called more than once for the same module.
*/
AC_API AC_Result
AC_BlacklistModule(const wchar_t* name);

/*
* AC_SetBaseTimeout
*    Sets base timeout between scans in ms.
*    The final timeout is randomized every scan within a 8191ms range.
*    To prevent overflow, passing < 8191 or >= UINT_MAX - 8191 is not allowed.
*    Default timeout is 60s in Release and 10s in Debug mode.
*
* Parameters
*    timeout - Timeout in ms. Passing 0 resets to the default value.
*
* Return values
*    AC_RSuccess       - Success.
*    AC_RInvalidParam1 - timeout is invalid (see above).
*/
AC_API AC_Result
AC_SetBaseTimeout(unsigned int timeout);

/*
* AC_GetClient
*    Retrieves information about the local client.
*
* Return values
*    Pointer to constant AC_Client structure.
*/
AC_API const AC_Client*
AC_GetClient();

/*
* AC_Confirm
*     Confirms connection to the game.
*     The return value of this function should always be checked.
*
* Return values
*     AC_RSuccess      - Success.
*     AC_RFailure      - An error occurred.
*/
AC_API AC_Result
AC_Confirm();

/*
* AC_RegisterHookCallback
*    Registers a function callback to be executed after initialization.
*
* Parameters
*    function - Address of the callback.
*
* Return values
*    AC_RSuccess       - Success.
*    AC_RInvalidParam1 - Invalid callback address.
*/
AC_API AC_Result
AC_RegisterInitCallback(AC_InitCallback function);

/*
* AC_RegisterHookCallback
*    Registers a function callback to be executed when a hook is called.
*
* Parameters
*    function - Address of the callback.
*
* Return values
*    AC_RSuccess       - Success.
*    AC_RInvalidParam1 - Invalid callback address.
*/
AC_API AC_Result
AC_RegisterHookCallback(AC_HookCallback function);

/*
* AC_RegisterScanCallback
*    Registers a function callback to be executed after a scan.
*
* Parameters
*    function - Address of the callback.
*
* Return values
*    AC_RSuccess        - Success.
*    AC_RInvalidParam1  - Invalid function address.
*/
AC_API AC_Result
AC_RegisterScanCallback(AC_ScanCallback function);

/*
* AC_RegisterDetectionCallback
*    Registers a function callback to be executed after a detection.
*
* Parameters
*    function - Address of the callback.
*
* Return values
*    AC_RSuccess       - Success.
*    AC_RInvalidParam1 - Invalid function address.
*/
AC_API AC_Result
AC_RegisterDetectionCallback(AC_DetectionCallback function);

/*
* AC_ResultToString
*    Converts an AC_Result to a C string.
*
* Parameters
*    result - Result code.
*
* Return values
*    Null-terminated C string translation of the AC_Result code.
*    If result is invalid or has no string associated with it,
*    a placeholder string is returned instead.
*/
AC_API const char*
AC_ResultToString(AC_Result result);

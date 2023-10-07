#include "../anticheat/api.h"

// #define C_TESTING

#include <Windows.h>
#ifdef C_TESTING
#include <stdio.h>
#else
#include <cstdio>
#endif

DECLSPEC_NOINLINE static void
SampleFunction(int x)
{
    printf("%d\n", x);
}

static void
OnHook(const AC_Hook* data, AC_Hash32 name)
{
    switch (name)
    {
    case AC_HK_BASE_THREAD_INIT_THUNK:
    //    printf("BaseThreadInitThunk (%u)\n", data->m_total_call_count);
    //    for (size_t i = 0; i < data->m_unique_caller_count; i++) {
    //        auto caller = data->m_unique_callers[i];
    //        CHAR name[128]{};
    //        GetModuleFileNameA(( HMODULE )caller.m_module, name, sizeof(name));
    //        printf("Source: 0x%p (%s)\n", caller.m_ptr, name);
    //    }
        break;
    default:
        break;
    }
}

int
main()
{
    AC_RegisterHookCallback(OnHook);
    AC_SetBaseTimeout(9000);

    AC_Initialize();

    const AC_Client* client = AC_GetClient();
    // wprintf(L"%s\n", client->m_computer_name);
    // wprintf(L"%s\n", client->m_username);
    // for (size_t i = 0; i < client->m_ip_count; i++)
    // {
    //     AC_IpAddress* address = &client->m_ip_addresses[i];
    //     if (address->m_type == AC_Ipv6)
    //         wprintf(L"%s %s\n", address->m_adapter_name, address->m_value);
    // }

    MessageBoxA(NULL, "Test", "Hello", MB_OK);

    if (AC_Confirm() != AC_RSuccess)
        return 1;

    // int i = 10;
    while (1) // (i--)
    {
        SampleFunction(12345);
        Sleep(1000);
    }

#ifdef _DEBUG
    AC_End();
#endif
}

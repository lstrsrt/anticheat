#include <string_view>
#include <thread>
#include <vector>

#include "util.hh"
#include "../shared/detours/detours.h"

#include <ProcessSnapshot.h>

//#define CREATE_OWN_THREAD

template<class T>
T GetModuleExport(PCWSTR module_name, PCSTR export_name);

static void(__cdecl* real_sample_function)(int);
static void __cdecl HkSampleFunction(int x)
{
    return real_sample_function(1337);
}

static auto real_message_box_a = &MessageBoxA;
static auto WINAPI HkMessageBoxA(HWND wnd, LPCSTR text, LPCSTR caption, UINT type) -> int
{
    // static auto original = GetModuleExport<decltype(MessageBoxA)*>(L"user32.dll", "MessageBoxA");
    return real_message_box_a(wnd, "Hooked!", "Test", MB_YESNO);
}

static auto GetNtHeaders(void* base) -> IMAGE_NT_HEADERS*
{
    if (!base)
        return nullptr;

    const auto nt = ( IMAGE_NT_HEADERS* )(( BYTE* )base + (( IMAGE_DOS_HEADER* )base)->e_lfanew);
    if (!nt)
        return nullptr;

    return nt;
}

static auto GetImageImportDescriptor(void* base) -> IMAGE_IMPORT_DESCRIPTOR*
{
    const auto nt_headers = GetNtHeaders(base);
    if (!nt_headers)
        return nullptr;

    const auto opt_header = &nt_headers->OptionalHeader;
    if (opt_header->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return nullptr;

    const auto dir_addr = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    return reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<UINT_PTR>(base) + dir_addr);
}

static void PatchImportAddressTable(IMAGE_IMPORT_DESCRIPTOR* import_desc, std::string_view import_name, const void* new_addr)
{
    const auto base_address = reinterpret_cast<UINT_PTR>(GetModuleHandle(nullptr));
    auto thunk_data = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<BYTE*>(base_address) + import_desc->OriginalFirstThunk);
    size_t index{};

    for (size_t i{}; thunk_data->u1.Function; i++) {
        char* cur_fn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base_address + static_cast<UINT_PTR>(thunk_data->u1.AddressOfData))->Name;
        if (!import_name.compare(cur_fn)) {
            auto table = reinterpret_cast<UINT_PTR*>(base_address + import_desc->FirstThunk);
            AutoVirtualProtect vp{ &table[i], sizeof(&table[i]), PAGE_READWRITE };
            table[i] = reinterpret_cast<UINT_PTR>(new_addr);
            return;
        }
        thunk_data++;
    }
}

static void HookImport(PCSTR dll_name, PCSTR fn_name, const void* hook_addr)
{
    const auto base_address = GetModuleHandle(nullptr);
    auto import_desc = GetImageImportDescriptor(base_address);

    while (import_desc->Name) {
        auto cur_dll = reinterpret_cast<char*>(base_address) + import_desc->Name;
        if (!_stricmp(dll_name, cur_dll)) { // Case insensitive
            PatchImportAddressTable(import_desc, fn_name, hook_addr);
            return;
        }
        import_desc++;
    }
}

template<class T>
static bool WriteMemory(HANDLE process, PVOID address, const T* data, SIZE_T size = sizeof(T))
{
    return WriteProcessMemory(process, address, data, size, nullptr);
}

template<size_t len> requires(len > 0)
static auto FindByteSignature(void* base, size_t end, const std::array<int, len>& sig) -> void*
{
    auto bytes = static_cast<uint8_t*>(base);
    for (size_t i{}; i < end - len; i++) {
        for (size_t j{}; j < len; j++) {
            if (bytes[i + j] != sig[j] && sig[j] != -1)
                break;
            if (j + 1 == len)
                return reinterpret_cast<void*>(&bytes[i]);
        }
    }
    return nullptr;
}

template<class T = void*>
static T GetModuleExport(PCWSTR module_name, PCSTR export_name)
{
    auto mod = GetModuleHandle(module_name);
    if (mod)
        return ( T )GetProcAddress(mod, export_name);
    return T();
}

struct AutoDetourTransaction
{
    explicit AutoDetourTransaction()
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
    }

    ~AutoDetourTransaction()
    {
        DetourTransactionCommit();
    }
};

static void SetFunctionDetour(PVOID address, PVOID original, bool enable = true)
{
    if (enable)
        DetourAttach(( PVOID* )original, address);
    else
        DetourDetach(( PVOID* )original, address);
}

// https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
void RemapNtdll()
{
    HANDLE process = GetCurrentProcess();
    MODULEINFO module_info{};
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (!ntdll)
        return;

    K32GetModuleInformation(process, ntdll, &module_info, sizeof(module_info));

    WCHAR sys_dir[MAX_PATH]{};
    GetSystemDirectory(sys_dir, MAX_PATH);
    wcscat_s(sys_dir, L"\\ntdll.dll");
    HANDLE file = CreateFile(sys_dir, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

    HANDLE mapping = CreateFileMapping(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!mapping)
        return;
    PVOID mapping_addr = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

    PVOID base = ( PVOID )module_info.lpBaseOfDll;
    PIMAGE_DOS_HEADER dos_hdr = ( PIMAGE_DOS_HEADER )base;
    PIMAGE_NT_HEADERS nt_hdrs = ( PIMAGE_NT_HEADERS )(( DWORD_PTR )base + dos_hdr->e_lfanew);

    for (WORD i = 0; i < nt_hdrs->FileHeader.NumberOfSections; i++) {
        auto sec = ( PIMAGE_SECTION_HEADER )(( DWORD_PTR )IMAGE_FIRST_SECTION(nt_hdrs) + (( DWORD_PTR )IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp(( char* )sec->Name, ( char* )".text")) {

            DWORD old = 0;

            // make writable
            VirtualProtect(
                ( PVOID )(( DWORD_PTR )base + ( DWORD_PTR )sec->VirtualAddress),
                sec->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &old
            );

            // copy over contents
            memcpy(
                ( PVOID )(( DWORD_PTR )base + ( DWORD_PTR )sec->VirtualAddress),
                ( PVOID )(( DWORD_PTR )mapping_addr + ( DWORD_PTR )sec->VirtualAddress),
                sec->Misc.VirtualSize
            );

            // restore protection
            VirtualProtect(
                ( PVOID )(( DWORD_PTR )base + ( DWORD_PTR )sec->VirtualAddress),
                sec->Misc.VirtualSize,
                old,
                &old
            );
        }
    }

    CloseHandle(process);
    CloseHandle(file);
    CloseHandle(mapping);
    FreeLibrary(ntdll);
}

void KillAnticheatThreads()
{
    HPSS snap{};
    if (::PssCaptureSnapshot(::GetCurrentProcess(), PSS_CAPTURE_THREADS, 0, &snap) != ERROR_SUCCESS)
        return;

    PSS_THREAD_INFORMATION info{};
    if (::PssQuerySnapshot(snap, PSS_QUERY_THREAD_INFORMATION, &info, sizeof(info)) != ERROR_SUCCESS)
        return;

    HPSSWALK marker{};
    if (::PssWalkMarkerCreate(nullptr, &marker) != ERROR_SUCCESS)
        return;

    auto function = DetourFindFunction("target.exe", "ThreadStartRoutine");
    PSS_THREAD_ENTRY entry{};
    while (::PssWalkSnapshot(snap, PSS_WALK_THREADS, marker, &entry, sizeof(entry)) == ERROR_SUCCESS) {
        // Skip our thread
        const auto tid = entry.ThreadId;
        if (tid == ::GetCurrentThreadId())
            continue;
        const auto handle = ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_TERMINATE, false, tid);
        if (handle) {
            ::SuspendThread(handle);
            if (entry.Win32StartAddress == function)
                ::TerminateThread(handle, EXIT_SUCCESS);
            else
                ::ResumeThread(handle);
            ::CloseHandle(handle);
        }
    }

    ::PssWalkMarkerFree(marker);
    ::PssFreeSnapshot(::GetCurrentProcess(), snap);
}

struct Cheat
{
    static void Init(LPVOID instance)
    {
        // these are prevented in release mode
        // RemapNtdll();
        // KillAnticheatThreads();

        {
            AutoDetourTransaction dt{};
            real_sample_function = (decltype(real_sample_function))::DetourFindFunction("target.exe", "SampleFunction");
            ULONG old_protect{};
            SetFunctionDetour(&HkSampleFunction, &real_sample_function);
            // SetFunctionDetour(&HkMessageBoxA, &real_message_box_a);
        }

        HookImport("user32.dll", "MessageBoxA", &HkMessageBoxA);

#ifdef CREATE_OWN_THREAD
        while (1)
            Sleep(500);

        FreeLibraryAndExitThread(( HMODULE )instance, EXIT_SUCCESS);
#endif
    }
};

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
    _In_ HANDLE Process,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_opt_ ULONG ZeroBits,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ SIZE_T CommittedStackSize,
    _In_ PUSER_THREAD_START_ROUTINE StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE Thread,
    _Out_opt_ PCLIENT_ID ClientId
);

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

static auto CreateFakeThread(PVOID start, PVOID param) -> HANDLE
{
    auto fake_start = GetModuleExport<LPTHREAD_START_ROUTINE>(L"ntdll.dll", "RtlUserThreadStart");
    auto create_thread = GetModuleExport<decltype(RtlCreateUserThread)*>(L"ntdll.dll", "RtlCreateUserThread");

    // auto thread = CreateThread(nullptr, 0, fake_start, param, CREATE_SUSPENDED, nullptr);

    HANDLE thread{};
    if (0 > create_thread(GetCurrentProcess(), nullptr, true /* suspended */, 0, 0, 0,
        ( PUSER_THREAD_START_ROUTINE )fake_start, param, &thread, nullptr)) {
        return nullptr;
    }

    // auto create_thread = GetModuleExport<decltype(ZwCreateThreadEx)*>(L"ntdll.dll", "ZwCreateThreadEx");
    // HANDLE thread{};
    // if (0 > create_thread(&thread, MAXIMUM_ALLOWED, nullptr, GetCurrentProcess(), fake_start, param,
    //     CREATE_SUSPENDED, 0, 0, 0, nullptr)) {
    //     return nullptr;
    // }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    GetThreadContext(thread, &ctx);
#ifdef _M_IX86
    ctx.Eip = ( DWORD )start;
    ctx.Eax = ( DWORD )start;
#else
    // ctx.Rip = ( DWORD64 )start;
    ctx.Rcx = ( DWORD64 )start;
#endif
    SetThreadContext(thread, &ctx);
    ResumeThread(thread);
    return thread;
}

BOOL WINAPI DllMain(HMODULE instance, DWORD call_reason, LPVOID reserved)
{
    if (call_reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        MessageBoxA(nullptr, "Injected", "Cheat", MB_OK);
#ifdef CREATE_OWN_THREAD
        if (auto thread = CreateFakeThread(&Cheat::Init, instance))
            CloseHandle(thread);
#else
        Cheat::Init(instance);
#endif
    } else if (call_reason == DLL_PROCESS_DETACH) {
        AutoDetourTransaction dt{};
        SetFunctionDetour(&HkSampleFunction, &real_sample_function, false);
        // SetFunctionDetour(&HkMessageBoxA, &real_message_box_a, false);
    }

    return TRUE;
}

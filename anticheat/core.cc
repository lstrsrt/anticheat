#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Dbghelp.lib")
#ifndef AC_DLL
#pragma comment(lib, "shared.lib")
#endif

#include "core.hh"

#ifdef AC_DRIVER
#include "../driver/driver.h"
#endif

#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <SoftPub.h>

#if defined(AC_DRIVER) && !defined(AC_X64)
#error Driver unsupported on this platform, do not define AC_DRIVER
#endif

#define DO_ONCE() { static bool once = false; if (once) return Unexpected(); else once = true; }

using IndexVector = std::vector<size_t>;

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

namespace g
{
    std::vector<PCWSTR> dll_blacklist = {
        L"cheat.dll",
        L"hack.dll",
        L"trainer.dll",
        L"aimbot.dll",
        // Used to prevent remapping to overwrite hooks
        L"ntdll.dll",
        L"kernel32.dll"
    };
    static PVOID dll_notify_cookie;
    static AC_Client client;

#ifdef AC_DRIVER
    static Driver driver(L"ACDriver");
    static SC_HANDLE service_manager;
#endif
}

namespace callbacks
{
    AC_HookCallback on_hook;
    static AC_InitCallback on_init;
    static AC_DetectionCallback on_detection;
    static AC_ScanCallback on_scan;
}

struct AutoLdrLock
{
    explicit AutoLdrLock()
    {
        ULONG disp{};
        LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, &disp, &m_cookie);
        if (disp == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED)
            LOG_ERROR("Couldn't acquire ldr lock"); // nonfatal
    }

    ~AutoLdrLock()
    {
        if (m_cookie)
            LdrUnlockLoaderLock(0, m_cookie);
    }

    PVOID m_cookie{};
};

INTERNAL LDR_DATA_TABLE_ENTRY*
FindLdrEntry(std::wstring_view module_name)
{
    UNICODE_STRING base_name{};
    RtlInitUnicodeString(&base_name, module_name.data());

    PVOID base{};
    if (NT_SUCCESS(LdrGetDllHandleByName(&base_name, nullptr, &base)))
    {
        LDR_DATA_TABLE_ENTRY* entry{};
        if (NT_SUCCESS(LdrFindEntryForAddress(base, &entry)))
            return entry;
        return nullptr;
    }

    return nullptr;
}

// Placeholder
NORETURN INTERNAL void
ExitWithMessage(PCSTR msg)
{
    MessageBoxA(nullptr, msg, "Error", MB_OK);

#ifdef AC_DRIVER
    g::driver.Unload();
#endif

    ExitProcess(EXIT_FAILURE);
}

template<std::integral C = char>
INTERNAL C*
NewHeapString(const C* src, size_t length)
{
    auto str = new C[length];

    if constexpr (std::same_as<C, char>)
        strncpy(str, src, length);
    else if (std::same_as<C, wchar_t>)
        wcsncpy(str, src, length);

    return str;
}

INTERNAL inline Module&
Self()
{
    return ac_ctrl.m_self;
}

INTERNAL std::optional<std::wstring>
GetModuleBaseName(HMODULE handle)
{
    WCHAR module_name[MAX_PATH]{};

    if (!GetModuleFileName(handle, module_name, MAX_PATH))
        return std::nullopt;

    return { wcsrchr(module_name, L'\\') + 1 };
}

std::optional<Module>
AddressToModule(ULONG_PTR address)
{
    for (auto& mod : ac_ctrl.m_loaded)
    {
        if (mod.ContainsAddress(address))
            return mod;
    }

    return std::nullopt;
}

std::optional<std::wstring>
AddressToModuleName(PVOID address)
{
    PVOID base{};

    if (!RtlPcToFileHeader(address, &base))
        return std::nullopt;

    return GetModuleBaseName(( HMODULE )base);
}

IMAGE_SECTION_HEADER*
AddressToSection(PVOID address, PVOID base)
{
    auto nt = RtlImageNtHeader(base);
    if (!nt)
        return nullptr;

    IMAGE_SECTION_HEADER* ret{};
    WalkSections(nt, [&](IMAGE_SECTION_HEADER* section)
    {
        auto start = ( ULONG_PTR )base + section->VirtualAddress;
        auto end = start + section->SizeOfRawData;
        if (( ULONG_PTR )address >= start && ( ULONG_PTR )address < end)
        {
            ret = section;
            return false;
        }
        return true;
    });

    return ret;
}

std::string
GetSectionName(IMAGE_SECTION_HEADER* section)
{
#ifdef _RELEASE
    return ""; // Not needed in release
#else
    char section_name[IMAGE_SIZEOF_SHORT_NAME + 1]{};
    strncpy_s(section_name, ( const char* )(section->Name), IMAGE_SIZEOF_SHORT_NAME);
    return { section_name };
#endif
}

bool
IsWithinTextSection(const Module& mod, PVOID address)
{
    if (auto text = mod.FindSection(".text"_hash))
    {
        auto start = ( PVOID )(mod.Base() + text->VirtualAddress);
        auto end = ( PVOID )(( ULONG_PTR )start + text->SizeOfRawData);
        if (address >= start || address < end)
            return true;
    }

    return false;
}

bool
IsWithinAnyTextSection(PVOID address)
{
    for (const auto& mod : ac_ctrl.m_loaded)
    {
        if (IsWithinTextSection(mod, address))
            return true;
    }

    return false;
}

INTERNAL std::wstring
GetRegistryString(HKEY key, std::wstring_view sub_key, std::wstring_view value)
{
    WCHAR buf[256]{};
    auto size = ( ULONG )std::size(buf);

    if (RegGetValue(key, sub_key.data(), value.data(), RRF_RT_REG_SZ, nullptr, buf, &size) == ERROR_SUCCESS)
        return { buf };

    return {};
}

// https://github.com/winsiderss/systeminformer/blob/master/phlib/verify.c#L164
INTERNAL bool
IsCertificateChainedToMicrosoft(PCCERT_CONTEXT certificate, HCERTSTORE sibling_store)
{
    if (!certificate || !sibling_store)
        return false;

    bool status = false;
    HCERTSTORE crypt_store{};
    CERT_CHAIN_POLICY_PARA policy_para = { sizeof(CERT_CHAIN_POLICY_PARA) };
    CERT_CHAIN_POLICY_STATUS policy_status = { sizeof(CERT_CHAIN_POLICY_STATUS) };
    CERT_CHAIN_PARA chain_para = { sizeof(CERT_CHAIN_PARA) };
    PCCERT_CHAIN_CONTEXT chain_context{};

    if (crypt_store = CertOpenStore(CERT_STORE_PROV_COLLECTION, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0))
    {
        if (CertAddStoreToCollection(crypt_store, sibling_store, 0, 0))
        {
            if (CertGetCertificateChain(HCCE_CURRENT_USER, certificate, 0, crypt_store,
                &chain_para, 0, 0, &chain_context))
            {
                if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, chain_context,
                    &policy_para, &policy_status))
                {
                    status = (policy_status.dwError == ERROR_SUCCESS);
                }

                if (chain_context)
                    CertFreeCertificateChain(chain_context);
            }
        }
        CertCloseStore(crypt_store, 0);
    }

    return status;
}

// https://github.com/winsiderss/systeminformer/blob/master/phlib/verify.c#L138
INTERNAL PCRYPT_PROVIDER_SGNR
GetCryptProviderSignerFromChain(PCRYPT_PROVIDER_DATA provider_data, ULONG signer_index)
{
    if (!provider_data || signer_index >= provider_data->csSigners)
        return nullptr;

    return &provider_data->pasSigners[signer_index];
}

INTERNAL bool
IsFileSigned(PCWSTR file_path, bool signed_by_microsoft = true)
{
    using WTGetSignatureInfo = HRESULT(WINAPI*)(
        _In_opt_ PCWSTR file_name,
        _In_opt_ HANDLE file_handle,
        _In_ SIGNATURE_INFO_FLAGS flags,
        _Inout_ PSIGNATURE_INFO info,
        _Out_ PVOID cert_context,
        _Out_ PHANDLE state_data
        );

    WINTRUST_FILE_INFO trust_file = { sizeof(trust_file) };
    trust_file.pcwszFilePath = file_path;

    WINTRUST_DATA trust_data = { sizeof(trust_data) };
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust_data.dwUnionChoice = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_SAFER_FLAG | WTD_DISABLE_MD2_MD4;
    trust_data.pFile = &trust_file;

    static const auto wintrust = LoadLibraryExA("wintrust.dll", nullptr,
        LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_REQUIRE_SIGNED_TARGET);
    if (!wintrust)
    {
        LOG_ERROR("Couldn't load wintrust.dll!");
        return false;
    }

    static const auto wt_get_signature_info = ( WTGetSignatureInfo )GetProcAddress(wintrust, "WTGetSignatureInfo");
    if (!wt_get_signature_info)
    {
        LOG_ERROR("Couldn't find WTGetSignatureInfo!");
        return false;
    }

    SIGNATURE_INFO signature_info = { sizeof(signature_info) };
    PVOID cert_context{};
    HANDLE trust_state_data{};

    if (SUCCEEDED(wt_get_signature_info(
        file_path,
        nullptr,
        ( SIGNATURE_INFO_FLAGS )(SIF_AUTHENTICODE_SIGNED | SIF_CATALOG_SIGNED | SIF_BASE_VERIFICATION),
        &signature_info,
        &cert_context,
        &trust_state_data)))
    {
        trust_data.hWVTStateData = trust_state_data;
    }

    GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    bool is_signed = (WinVerifyTrust(( HWND )INVALID_HANDLE_VALUE, &guid, &trust_data) == ERROR_SUCCESS);

    if (is_signed && signed_by_microsoft)
    {
        auto prov_data = ( CRYPT_PROVIDER_DATA* )trust_data.hWVTStateData;
        if (!prov_data)
            return false;

        auto prov_signer = GetCryptProviderSignerFromChain(prov_data, 0);
        if (!prov_signer)
            return false;

        auto crypt_store_handle = CertOpenStore(CERT_STORE_PROV_MSG, prov_data->dwEncoding, 0, 0, prov_data->hMsg);
        if (!crypt_store_handle)
            return false;

        is_signed = IsCertificateChainedToMicrosoft(prov_signer->pasCertChain->pCert, crypt_store_handle);

        if (cert_context)
            CertFreeCertificateContext(( PCCERT_CONTEXT )cert_context);
    }

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(( HWND )INVALID_HANDLE_VALUE, &guid, &trust_data);

    return is_signed;
}

Module::Module(std::wstring_view name)
    : m_name(name), m_ldr_entry(FindLdrEntry(m_name)),
    m_base(m_ldr_entry->DllBase), m_nt_headers(RtlImageNtHeader(m_base)),
    m_timestamp(m_ldr_entry->LoadTime.QuadPart),
    m_signed(IsFileSigned(m_ldr_entry->FullDllName.Buffer))
{
}

Module::Module(PVOID base)
    : m_base(base)
{
    // different order, so initialize here
    m_name = GetModuleBaseName(m_handle).value();
    m_ldr_entry = FindLdrEntry(m_name);
    m_nt_headers = RtlImageNtHeader(m_base);
    m_timestamp = m_ldr_entry->LoadTime.QuadPart;
    m_signed = IsFileSigned(m_ldr_entry->FullDllName.Buffer);
}

Module::Module(LDR_DATA_TABLE_ENTRY* ldr_entry)
    : m_name(ldr_entry->BaseDllName.Buffer), m_ldr_entry(ldr_entry),
    m_base(ldr_entry->DllBase), m_nt_headers(RtlImageNtHeader(m_base)),
    m_timestamp(m_ldr_entry->LoadTime.QuadPart),
    m_signed(IsFileSigned(m_ldr_entry->FullDllName.Buffer))
{
}

IMAGE_SECTION_HEADER*
Module::FindSection(Hash32 hashed_name) const
{
    IMAGE_SECTION_HEADER* ret{};

    WalkSections(m_nt_headers, [&](IMAGE_SECTION_HEADER* section)
    {
        if (Hash(GetSectionName(section)) == hashed_name)
        {
            ret = section;
            return false;
        }
        return true;
    });

    return ret;
}

INTERNAL std::vector<Import> ScanImportAddressTable(const Module&);

// TODO - not all sections always exist, find more elegant design

ProtectedModule::ProtectedModule(LDR_DATA_TABLE_ENTRY* ldr_entry)
    : Module(ldr_entry),
    m_text_section(FindSection(".text"_hash)),
    m_rdata_section(FindSection(".rdata"_hash)),
    m_idata_section(FindSection(".idata"_hash))
{
    LOG_INFO(L"{}: loaded at base address {}", m_name, m_base);

#ifdef AC_LOG_VERBOSE
    WalkSections(m_nt_headers, [&](IMAGE_SECTION_HEADER* section)
    {
        LOG_RAW("\t\t Found section {}", GetSectionName(section));
        return true;
    });
#endif

    // TODO - section could have been patched earlier
    m_text_section.m_old_pages = m_text_section.Scan(Base<BYTE*>());
    m_rdata_section.m_old_pages = m_rdata_section.Scan(Base<BYTE*>());
    m_idata_section.m_old_pages = m_idata_section.Scan(Base<BYTE*>());
    m_old_iat = ScanImportAddressTable(*this);
}

std::vector<Page>
Section::Scan(BYTE* module_base) const
{
    if (!m_header)
        return {};

    static const auto page_size = []
    {
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        return info.dwPageSize;
    }();

    const auto section_end = m_header->VirtualAddress + m_header->Misc.VirtualSize;
    const auto first_page = AlignDown(m_header->VirtualAddress, page_size);
    const auto last_page = AlignUp(section_end, page_size);
    const auto page_count = (last_page - first_page) / page_size;

    std::vector<Page> pages{};

    for (size_t i = 0; i < page_count; i++)
    {
        const auto offset = ( ULONG )(first_page + (( ULONG64 )i * page_size));
        const auto rel_offset = ( ULONG_PTR )i * page_size;
        const auto address = module_base + offset;

        MEMORY_BASIC_INFORMATION mem_info{};
        if (!QueryMemory(NtCurrentProcess(), ( PVOID )address, MemoryBasicInformation, &mem_info))
        {
            LogWindowsError("Error querying memory at address {}", ( PVOID )address);
            continue;
        }

        if (mem_info.Protect == PAGE_EXECUTE_READWRITE)
            LOG_RAW(L"\t\t {} ({}): page has been made RWX!", mem_info.BaseAddress, m_name.c_str());

        const auto crc = MakeChecksum(address, std::min(page_size, section_end - offset));
        pages.push_back(Page{ mem_info.BaseAddress, mem_info.Protect, rel_offset, crc });
    }

#ifdef AC_LOG_VERBOSE
    for (const auto& page : pages)
        LOG_RAW("\t\t Checksum for page {} (+{:#x}): {}", page.m_address, page.m_offset, page.m_checksum);
#endif
    LOG_RAW(L"\t\t Scanned section {} ({} pages)", m_name.c_str(), page_count);

    return pages;
}

INTERNAL void
WalkImportAddressTable(const Module& mod, const std::predicate<const Import&> auto&& callback)
{
    if (!mod.m_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        return;

    auto import_desc = mod.GetDirectoryEntry<IMAGE_IMPORT_DESCRIPTOR*>(IMAGE_DIRECTORY_ENTRY_IMPORT);

    while (import_desc && import_desc->Name)
    {
        auto thunk = ( IMAGE_THUNK_DATA* )(mod.Base<BYTE*>() + import_desc->OriginalFirstThunk);
        auto first = ( IMAGE_THUNK_DATA* )(mod.Base<BYTE*>() + import_desc->FirstThunk);
        auto cur_dll = mod.Base<char*>() + import_desc->Name;

        while (thunk->u1.Ordinal)
        {
            auto addr = first->u1.Function;
            auto first8 = *( ULONG64* )addr; // First 8 bytes are used to check for detours

            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
            {
                auto ordinal = IMAGE_ORDINAL(thunk->u1.Ordinal);
                Import imp{ cur_dll, ( ULONG )ordinal, addr, first8 };
                if (!callback(imp))
                    return;
            }
            else
            {
                char* name = (( IMAGE_IMPORT_BY_NAME* )(mod.Base() + thunk->u1.AddressOfData))->Name;
                Import imp{ cur_dll, name, addr, first8 };
                if (!callback(imp))
                    return;
            }
            thunk++, first++;
        }
        import_desc++;
    }
}

INTERNAL std::vector<Import>
ScanImportAddressTable(const Module& mod)
{
    std::vector<Import> iat{};

    WalkImportAddressTable(mod, [&](const Import& imp)
    {
        iat.push_back(imp);
        return true;
    });

    LOG_RAW("\t\t IAT: {} entries", iat.size());
    return iat;
}

INTERNAL NTSTATUS NTAPI
ThreadStartRoutine(PVOID param)
{
    const auto ctx = ( AC_Thread* )param;
    LARGE_INTEGER timeout{};

    while (NtWaitForSingleObject(ctx->m_exit_event, false, &timeout) != WAIT_OBJECT_0)
    {
        ctx->m_function();

        if (callbacks::on_scan)
            callbacks::on_scan();

        ctx->CheckedWait();
    }

    NtClose(ctx->m_exit_event);
    NtClose(ctx->m_handle);
    return STATUS_SUCCESS;
}

bool
IsFileBlacklisted(PCWSTR file, bool is_full_path)
{
    const auto base_name = is_full_path ? wcsrchr(file, L'\\') + 1 : file;

    for (const auto dll : g::dll_blacklist)
    {
        if (!_wcsicmp(base_name, dll))
            return true;
    }

    return false;
}

inline void
ReportDetection(AC_DetectionType type, DetectionArg arg)
{
    if (callbacks::on_detection)
        callbacks::on_detection(type, &g::client);

#ifdef _DEBUG
    try
    {
        switch (type)
        {
        case AC_DSuspiciousDll:
            LOG_ERROR(L"Suspicious DLL was loaded! Name: {}", std::get<std::wstring>(arg));
            break;
        case AC_DSuspiciousThread:
            LOG_ERROR("Suspicious thread is being executed! ID: {}", std::get<size_t>(arg));
            break;
        case AC_DProtectionChanged:
            LOG_ERROR("Page protection was changed! Delta: {}", std::get<size_t>(arg));
            break;
        case AC_DSectionModified:
            LOG_ERROR("Section checksums have changed! Delta: {}", std::get<size_t>(arg));
            break;
        case AC_DDebuggerAttached:
            LOG_ERROR("Debugger was found!");
            break;
        case AC_DInvalidTimeout:
            LOG_ERROR("Invalid timeout length! Value: {}", std::get<size_t>(arg));
            break;
        case AC_DSuspiciousCall:
            LOG_ERROR("Suspicious call to hooked function!");
            break;
        case AC_DAttemptedDllLoad:
            LOG_ERROR("DLL injection was attempted!");
            break;
        case AC_DFunctionHooked:
            LOG_ERROR("Function in protected module hooked! Name: {}", std::get<std::string>(arg));
            break;
        case AC_DSuspiciousMapping:
            LOG_ERROR("Suspicious mapping found!");
            break;
        }
    }
    catch (const std::bad_variant_access& ex)
    {
        // should never happen
        LOG_ERROR("Detection: {} Caught: {}", ( LONG )type, ex.what());
    }
#else
    const auto s = std::format("An error occurred! Code: {:#010x}", ( ULONG )type);
    ExitWithMessage(s.c_str());
#endif
}

INTERNAL void CALLBACK
DllNotificationCallback(ULONG reason, LDR_DLL_NOTIFICATION_DATA* data, PVOID)
{
    if (reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
    {
        auto name = data->Loaded.BaseDllName->Buffer;
        VERBOSE(LOG_INFO(L"Loaded {}", name));

        ac_ctrl.AddLoaded(data->Loaded.DllBase);

        if (IsFileBlacklisted(name, false))
            ReportDetection(AC_DSuspiciousDll, name);
    }
    else
    {
        auto name = data->Unloaded.BaseDllName->Buffer;
        VERBOSE(LOG_INFO(L"Unloaded {}", name));

        auto iter = rg::find(ac_ctrl.m_loaded, name, &Module::m_name);
        if (iter != ac_ctrl.m_loaded.cend())
            ac_ctrl.m_loaded.erase(iter);
    }
}

void
AC_Thread::Initialize(MAYBE_UNUSED PCWSTR name, void(*function)())
{
    HANDLE thread{};
    auto flags = THREAD_CREATE_FLAGS_CREATE_SUSPENDED; // Start suspended so we can initialize the rest
#ifdef _RELEASE
    flags |= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE;
#endif
    if (!NT_SUCCESS(NtCreateThreadEx(&thread, MAXIMUM_ALLOWED, nullptr, NtCurrentProcess(),
        ThreadStartRoutine, this, flags, 0, 0, 0, nullptr)))
    {
        LogWindowsError("Couldn't create scanner thread!");
        return;
    }

    m_handle = thread;
    m_id = GetThreadId(thread);
    m_exit_event = CreateEvent(nullptr, true, false, nullptr);
    m_function = function;

#ifdef _DEBUG
    THREAD_NAME_INFORMATION name_info{};
    RtlInitUnicodeString(&name_info.ThreadName, name);
    NtSetInformationThread(thread, ThreadNameInformation, &name_info, sizeof(name_info));
    LOG_INFO(L"Starting thread \"{}\" ({})", name, m_id);
#endif

    NtResumeThread(thread, nullptr);
}

static constexpr ULONG max_timeout_offset = 0x1fff;

void
AC_Thread::CheckedWait() const
{
    ULONG timeout = s_timeout;
#ifdef _RELEASE
    const auto random_offset = ( ULONG )(ReadTimeStampCounter() & max_timeout_offset);
    if ((random_offset >> 3) & 1)
        timeout -= random_offset;
    else
        timeout += random_offset;
#endif

    Timer timer;

    if (WaitForSingleObject(m_exit_event, ( ULONG )timeout) == WAIT_OBJECT_0)
        return;

    // Check the elapsed time.
    // If it's too low, the timeout was patched/bypassed.
    // if it's too high, it might have been held up by a breakpoint.
    // Deviations within a small range are allowed.

    const auto elapsed = timer.Elapsed<ch::milliseconds>();
    const auto timeout_ms = ch::milliseconds(timeout);
    if (elapsed < timeout_ms - 1s || elapsed > timeout_ms + 1s)
        ReportDetection(AC_DInvalidTimeout, ( size_t )elapsed.count()); // can't be negative
}

INTERNAL void
PerformDebuggingChecks()
{
    if (NtCurrentPeb()->BeingDebugged)
        ReportDetection(AC_DDebuggerAttached);

    // Could check parent process... this is dependent on the launcher the game uses
    // PROCESS_BASIC_INFORMATION info{};
    // QueryProcess(NtCurrentProcess(), ProcessBasicInformation, info);
    // info.InheritedFromUniqueProcessId;

    HANDLE debug_port{};
    QueryProcess(NtCurrentProcess(), ProcessDebugPort, debug_port);
    if (debug_port && debug_port != INVALID_HANDLE_VALUE)
        ReportDetection(AC_DDebuggerAttached);

    ULONG debug_flags{};
    QueryProcess(NtCurrentProcess(), ProcessDebugFlags, debug_flags);
    if (!debug_flags)
        ReportDetection(AC_DDebuggerAttached);

    HANDLE debug_obj{};
    QueryProcess(NtCurrentProcess(), ProcessDebugObjectHandle, debug_obj);
    if (debug_obj && debug_obj != INVALID_HANDLE_VALUE)
    {
        ReportDetection(AC_DDebuggerAttached);
#ifdef _RELEASE
        // Try to detach from debugger
        NtRemoveProcessDebug(NtCurrentProcess(), debug_obj);
#endif
        NtClose(debug_obj);
    }

    // Some ways to check for a kernel debugger (these don't do anything)

    SYSTEM_KERNEL_DEBUGGER_INFORMATION kd_info{};
    if (NT_SUCCESS(NtQuerySystemInformation(SystemKernelDebuggerInformation, &kd_info,
        sizeof(kd_info), nullptr)))
    {
        if (!kd_info.KernelDebuggerNotPresent || kd_info.KernelDebuggerEnabled)
        {
            // Kernel debugger
        }
    }

    auto status = NtSystemDebugControl(SysDbgCheckLowMemory, nullptr, 0, nullptr, 0, nullptr);
    if (status != STATUS_DEBUGGER_INACTIVE)
    {
        // Kernel debugger
        if (status != STATUS_ACCESS_DENIED)
        {
            // User debugger
        }
    }

    if (USER_SHARED_DATA->KdDebuggerEnabled)
    {
        // Kernel debugger
    }

    // win11
    // BOOLEAN b{};
    // RtlGetSystemGlobalData(GlobalDataIdKdDebuggerEnabled, &b, sizeof(b));
}

bool
IsOwnThread(ULONG id)
{
    return id == ac_ctrl.m_scanner.m_id;
}

bool
IsOwnThread(HANDLE handle)
{
    return NT_SUCCESS(NtCompareObjects(handle, ac_ctrl.m_scanner));
}

INTERNAL void
VerifyModuleHeader(PVOID alloc_base, ULONG tid)
{
    // Check if the module has been loaded legitimately
    const auto& mod = rg::find(ac_ctrl.m_loaded, alloc_base, &Module::m_base);
    if (mod == ac_ctrl.m_loaded.cend())
        return ReportDetection(AC_DSuspiciousThread, tid);

    // Don't use m_nt_headers here, get a new copy instead
    const auto nt = RtlImageNtHeader(mod->m_base);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        ReportDetection(AC_DSuspiciousDll, mod->m_name);

    // Check if the headers occur more than once
    IndexVector indices{};
    for (size_t i = 0; i < ac_ctrl.m_loaded.size(); i++)
    {
        const auto& mod = ac_ctrl.m_loaded[i];
        if (CompareNtHeaders(mod.m_nt_headers, nt))
            indices.push_back(i);
    }

    if (indices.size() > 1)
    {
        // Drop the module that was loaded first (should be the real one)
        // TODO - check m_timestamp?
        for (const auto i : std::views::drop(indices, 1))
            ReportDetection(AC_DSuspiciousDll, ac_ctrl.m_loaded[i].m_name);
    }
}

INTERNAL void
CheckThread(ULONG tid, PVOID start_addr)
{
    // Attempt to get the module name based on the thread's start address
    // (this should only fail when the module has been unlinked from the Ldr module list)
    const auto name = AddressToModuleName(start_addr);
    if (!name)
        ReportDetection(AC_DSuspiciousThread, tid);

    // Check if the page belongs to a section that has been mapped with SEC_IMAGE
    MEMORY_BASIC_INFORMATION mem_info{};
    if (!QueryMemory(NtCurrentProcess(), start_addr, MemoryBasicInformation, &mem_info))
    {
        // This seems very bad... do more here?
        LogWindowsError("Couldn't query thread start address");
        return;
    }

    if (mem_info.Type != MEM_IMAGE)
        ReportDetection(AC_DSuspiciousThread, tid);

    MEMORY_IMAGE_INFORMATION mem_image_info{};
    if (QueryMemory(NtCurrentProcess(), start_addr, MemoryImageInformation, &mem_image_info))
    {
        // Not sure if this ever happens but doesn't hurt to check
        if (mem_info.AllocationBase != mem_image_info.ImageBase)
            ReportDetection(AC_DSuspiciousThread, tid);
    }

    VerifyModuleHeader(mem_info.AllocationBase, tid);

    LOG_RAW(L"Thread {} Start {} ({})", tid, start_addr, name.value_or(L"Unknown"));
}

#ifdef AC_PSS_THREAD_ITER
#include <ProcessSnapshot.h>
#endif

INTERNAL void
CheckActiveThreads()
{
#ifdef AC_PSS_THREAD_ITER
    // TODO - error logging
    HPSS snap{};
    if (PssCaptureSnapshot(NtCurrentProcess(), PSS_CAPTURE_THREADS, 0, &snap) != ERROR_SUCCESS)
        return;

    PSS_THREAD_INFORMATION info{};
    if (PssQuerySnapshot(snap, PSS_QUERY_THREAD_INFORMATION, &info, sizeof(info)) != ERROR_SUCCESS)
        return;

    HPSSWALK marker{};
    if (PssWalkMarkerCreate(nullptr, &marker) != ERROR_SUCCESS)
        return;

    PSS_THREAD_ENTRY entry{};
    while (PssWalkSnapshot(snap, PSS_WALK_THREADS, marker, &entry, sizeof(entry)) == ERROR_SUCCESS)
    {
        // Skip our threads
        const auto tid = entry.ThreadId;
        if (IsOwnThread(tid))
            continue;

        CheckThread(tid, entry.Win32StartAddress);
    }

    PssWalkMarkerFree(marker);
    PssFreeSnapshot(NtCurrentProcess(), snap);
#else
    HANDLE thread{}, next_thread{};
    if (!NT_SUCCESS(NtGetNextThread(NtCurrentProcess(), nullptr, THREAD_QUERY_INFORMATION,
        0, 0, &thread)))
    {
        LogWindowsError("Couldn't enumerate first thread");
        return;
    }

    const auto get_next_thread = [&]() -> bool
    {
        const auto status = NtGetNextThread(NtCurrentProcess(), thread, THREAD_QUERY_INFORMATION,
            0, 0, &next_thread);

        NtClose(thread);

        if (NT_SUCCESS(status))
            thread = next_thread;
        else if (status == STATUS_NO_MORE_ENTRIES)
            return false;
        else
            LogWindowsError("Couldn't enumerate a thread");

        return true;
    };

    while (1)
    {
        THREAD_BASIC_INFORMATION thread_info{};
        NtQueryInformationThread(thread, ThreadBasicInformation, &thread_info,
            sizeof(thread_info), nullptr);

        const auto tid = HandleToUlong(thread_info.ClientId.UniqueThread);
        if (IsOwnThread(tid))
        {
            if (!get_next_thread())
                return;
            continue;
        }

        ULONG_PTR start_addr{};
        if (!NT_SUCCESS(NtQueryInformationThread(thread, ThreadQuerySetWin32StartAddress, &start_addr,
            sizeof(start_addr), nullptr)))
        {
            LogWindowsError("Couldn't get thread start address");
            continue;
        }

        CheckThread(tid, ( PVOID )start_addr);

        if (!get_next_thread())
            return;
    }
#endif
}

INTERNAL void
ComparePages(const ProtectedModule& mod, const Section& section)
{
    // Check if section exists
    if (!section.m_header)
        return;

    // Repeat scan and compare against section.m_old_pages
    const auto new_pages = section.Scan(mod.Base<BYTE*>());

    IndexVector crc_mismatches, prot_mismatches;
    for (size_t i = 0; i < new_pages.size(); i++)
    {
        Page old_page = section.m_old_pages[i],
            new_page = new_pages[i];

        if (old_page.m_checksum != new_page.m_checksum)
            crc_mismatches.push_back(i);
        if (old_page.m_protect_flags != new_page.m_protect_flags)
            prot_mismatches.push_back(i);
    }

    if (!prot_mismatches.size())
    {
        LOG_SUCCESS(L"{}: {} protection is unchanged :)", mod.m_name, section.m_name.c_str());
    }
    else
    {
        ReportDetection(AC_DProtectionChanged, prot_mismatches.size());
        LOG_INFO(L"{} {} protection changes:", mod.m_name, section.m_name.c_str());
        for (size_t i : prot_mismatches)
        {
            const auto& page = new_pages[i];
            LOG_RAW("\t\t {}: {:#x} => {:#x}", page.m_address, page.m_protect_flags,
                section.m_old_pages[i].m_protect_flags);
        }
    }

    if (!crc_mismatches.size())
    {
        LOG_SUCCESS(L"{}: {} checksums are unchanged :)", mod.m_name, section.m_name.c_str());
    }
    else
    {
        ReportDetection(AC_DSectionModified, crc_mismatches.size());
        LOG_INFO(L"{} {} checksum changes:", mod.m_name, section.m_name.c_str());
        for (size_t i : crc_mismatches)
        {
            const auto& page = new_pages[i];
            LOG_RAW("\t\t {}: {} => {}", page.m_address, page.m_checksum,
                section.m_old_pages[i].m_checksum);
        }
    }
}

// TODO - add support for more jump types
INTERNAL ULONG_PTR
ResolveJump(BYTE* code)
{
    if (*code == 0xe9)
    {
        static constexpr ULONG jmp_size_e9 = 5;
        auto rip = ( ULONG_PTR )code + jmp_size_e9;
        auto offset = ( LONG_PTR )(*( LONG* )(code + 1));
        return rip + offset;
    }
    else if (*code == 0xff)
    {
        if (*(code + 1) != 0x25)
            return 0;
#ifdef AC_X64
        // RIP-relative jump on x64
        static constexpr ULONG jmp_size_ff = 6;
        auto rip = ( ULONG_PTR )code + jmp_size_ff;
        auto offset = ( LONG_PTR )(*( LONG* )(code + 2));
        return *( ULONG_PTR* )(rip + offset);
#else
        // Absolute jump on x86
        return *( ULONG_PTR* )(code + 2);
#endif
    }
    // unimplemented
    return 0;
}

INTERNAL void
CompareIat(const ProtectedModule& mod)
{
    const auto new_iat = ScanImportAddressTable(mod);
    size_t mismatches{};

    const auto is_jump = [](BYTE code) -> bool
    {
        // just the supported ones
        return code == 0xe9 || code == 0xff;
    };

    for (size_t i = 0; i < mod.m_old_iat.size(); i++)
    {
        const auto& original_entry = mod.m_old_iat[i];
        const auto& new_entry = new_iat[i];

        // First, check if the address has been replaced
        if (original_entry.m_address != new_entry.m_address)
        {
            mismatches++;
            const auto name = AddressToModuleName(( PVOID )original_entry.m_address);
            const auto new_name = AddressToModuleName(( PVOID )new_entry.m_address);
            if (original_entry.m_import_by_name)
            {
                LOG_INFO("{}!{}: {:#x} => {:#x}", original_entry.m_module_name, original_entry.m_name,
                    original_entry.m_address, new_entry.m_address, WideStringToString(new_name.value_or(L"Unknown")));
                ReportDetection(AC_DFunctionHooked, std::format("{}!{}", original_entry.m_module_name, original_entry.m_name));
            }
            else
            {
                LOG_INFO("{} Ordinal {}: {:#x} => {:#x} ({})", original_entry.m_module_name, original_entry.m_ordinal,
                    original_entry.m_address, new_entry.m_address, WideStringToString(new_name.value_or(L"Unknown")));
                ReportDetection(AC_DFunctionHooked, std::format("{} Ordinal {}", original_entry.m_module_name, original_entry.m_ordinal));
            }
        }

        // The import may also have been detoured
        // !! This code is somewhat unfinished

        if (original_entry.m_first8 != new_entry.m_first8)
        {
            auto code = ( BYTE* )new_entry.m_address;
            if (!is_jump(*code))
                continue;

            // Recursively follow jumps
            auto dest = ResolveJump(code);
            while (dest && is_jump(*( BYTE* )dest))
                dest = ResolveJump(( BYTE* )dest);

            // Not supported?
            if (!dest)
                continue;

            // Allow jumps to ourselves and signed modules
            bool in_trusted_module{};
            for (const auto& loaded : ac_ctrl.m_loaded)
            {
                if (loaded.ContainsAddress(dest) && (loaded.m_signed || loaded == Self()))
                {
                    in_trusted_module = true;
                    break;
                }
            }
            if (in_trusted_module)
                continue;

            mismatches++;
            auto name = AddressToModuleName(( PVOID )dest);
            if (original_entry.m_import_by_name)
            {
                LOG_INFO("{}!{}: Detoured => {:#} ({})", original_entry.m_module_name, original_entry.m_name,
                    dest, WideStringToString(name.value_or(L"Unknown")));
                ReportDetection(AC_DFunctionHooked, std::format("{}!{}", original_entry.m_module_name, original_entry.m_name));
            }
            else
            {
                LOG_INFO("{} Ordinal {}: Detoured => {:#} ({})", original_entry.m_module_name, original_entry.m_ordinal,
                    dest, WideStringToString(name.value_or(L"Unknown")));
                ReportDetection(AC_DFunctionHooked, std::format("{} Ordinal {}", original_entry.m_module_name, original_entry.m_ordinal));
            }
        }
    }

    if (!mismatches)
        LOG_SUCCESS(L"{}: IAT addresses are equal :)", mod.m_name);
}

INTERNAL void
PerformIntegrityChecks()
{
    LOG_INFO("Running scan...");

    for (const auto& mod : ac_ctrl.m_protected)
    {
        ComparePages(mod, mod.m_text_section);
        ComparePages(mod, mod.m_rdata_section);
        ComparePages(mod, mod.m_idata_section);
        CompareIat(mod);
    }

    CheckActiveThreads();
    PerformDebuggingChecks();
}

// Small note: heap allocs like this are never freed because all of them are global
// and meant to be available until the process ends
// (at which point the OS already does all the necessary cleanup)
INTERNAL AC_IpAddress*
NewIpAddress(AC_IpAddressType type, PCWSTR ip, PCWSTR name)
{
    auto addr = new AC_IpAddress();

    addr->m_type = type;
    addr->m_value = NewHeapString(ip, wcslen(ip) + 1);
    addr->m_adapter_name = NewHeapString(name, wcslen(name) + 1);

    return addr;
}

INTERNAL void
CollectIpAddresses(std::vector<AC_IpAddress*>& ipv4_vec, std::vector<AC_IpAddress*>& ipv6_vec)
{
    IP_ADAPTER_ADDRESSES* adapter_addresses{};
    ULONG size = 15000, tries = 3, ret{};

    while (tries--)
    {
        adapter_addresses = ( IP_ADAPTER_ADDRESSES* )malloc(size);
        ret = GetAdaptersAddresses(
            AF_UNSPEC, // INET and INET6
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            adapter_addresses,
            &size
        );

        if (ret == ERROR_BUFFER_OVERFLOW)
        {
            free(adapter_addresses);
            adapter_addresses = nullptr;
        }
        else if (ret == ERROR_SUCCESS)
        {
            break;
        }
        else
        {
            LogWindowsError("Couldn't retrieve IP addresses");
            return;
        }
    }

    if (!tries)
    {
        LOG_ERROR("Couldn't retrieve IP addresses");
        if (adapter_addresses)
            free(adapter_addresses);
        return;
    }

    for (auto adapter = adapter_addresses; adapter; adapter = adapter->Next)
    {
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        for (auto address = adapter->FirstUnicastAddress; address; address = address->Next)
        {
            auto sockaddr = address->Address.lpSockaddr;
            switch (sockaddr->sa_family)
            {
            case AF_INET:
            {
                WCHAR buf[INET_ADDRSTRLEN]{};
                auto addr = ( SOCKADDR_IN* )sockaddr;
                RtlIpv4AddressToString(&addr->sin_addr, buf);
                ipv4_vec.push_back(NewIpAddress(AC_Ipv4, buf, adapter->FriendlyName));
                break;
            }
            case AF_INET6:
            {
                WCHAR buf[INET6_ADDRSTRLEN]{};
                auto addr = ( SOCKADDR_IN6* )sockaddr;
                RtlIpv6AddressToString(&addr->sin6_addr, buf);
                std::wstring str{ buf };
                if (str.starts_with(L"fe"))
                {
                    const auto c = str[2];
                    if (c == '8' || c == '9' || c == 'a' || c == 'b')
                        continue; // link-local
                }
                else if (str.starts_with(L"2001:0:"))
                {
                    continue; // special use
                }
                ipv6_vec.push_back(NewIpAddress(AC_Ipv6, str.c_str(), adapter->FriendlyName));
                break;
            }
            default:
                break;
            }
        }
    }

    if (adapter_addresses)
        free(adapter_addresses);
}

// Not very accurate, should be combined with other info
INTERNAL AC_Hwid
GenerateHardwareId()
{
    AC_Hwid id{};

    auto value = GetRegistryString(HKEY_LOCAL_MACHINE, L"SYSTEM\\HardwareConfig\\Current", L"SystemProductName");
    if (!value.empty())
        id = Hash(value);

    value = GetRegistryString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"Identifier");
    if (!value.empty())
    {
        UINT64 high = Hash(value);
        high <<= 32;
        id |= high;
    }

    return id;
}

INTERNAL void
ClientInitialize()
{
    WCHAR buf[UNLEN + 1]{};
    auto size = ( ULONG )std::size(buf);
    GetComputerName(buf, &size);
    LOG_RAW(L"Computer name: {}", buf);
    g::client.m_computer_name = NewHeapString(buf, size + 1);

    // reinit size from previous call
    size = ( ULONG )std::size(buf);
    GetUserName(buf, &size);
    LOG_RAW(L"User name: {}", buf);
    g::client.m_username = NewHeapString(buf, size /* \0 is included this time... */);

    std::vector<AC_IpAddress*> ipv4, ipv6;
    CollectIpAddresses(ipv4, ipv6);

    g::client.m_ip_count = ( ULONG )(ipv4.size() + ipv6.size());
    g::client.m_ip_addresses = new AC_IpAddress[g::client.m_ip_count];

#pragma warning(disable: 6386)
    size_t i = 0;
    for (const auto ip : ipv4)
        g::client.m_ip_addresses[i++] = *ip;
    for (const auto ip : ipv6)
        g::client.m_ip_addresses[i++] = *ip;
#pragma warning(default: 6386)

    g::client.m_hwid = GenerateHardwareId();
}

INTERNAL void
EnableMitigationPolicies()
{
    PROCESS_MITIGATION_ASLR_POLICY aslr{};
    aslr.EnableBottomUpRandomization = true;
    aslr.EnableHighEntropy = true;
    if (!SetProcessMitigationPolicy(ProcessASLRPolicy, &aslr, sizeof(aslr)))
        LOG_ERROR("Could not enable ASLR");

    PROCESS_MITIGATION_DEP_POLICY dep{};
    dep.Enable = true;
    dep.Permanent = true;
    if (!SetProcessMitigationPolicy(ProcessDEPPolicy, &dep, sizeof(dep)))
        LOG_ERROR("Could not enable DEP");

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY image_load{};
    image_load.PreferSystem32Images = true;
    if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &image_load, sizeof(image_load)))
        LOG_ERROR("Could not enable ImageLoadPolicy mitigation");

#ifdef _RELEASE
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic_code{};
    dynamic_code.ProhibitDynamicCode = true;
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamic_code, sizeof(dynamic_code)))
        LOG_ERROR("Could not enable DynamicCodePolicy mitigation");
#endif
}

#ifdef AC_DRIVER

INTERNAL bool
IsElevated()
{
    bool ret{};
    HANDLE token{};

    if (OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &token))
    {
        TOKEN_ELEVATION elevation;
        ULONG size = sizeof(elevation);
        if (NT_SUCCESS(NtQueryInformationToken(token, TokenElevation, &elevation, size, &size)))
            ret = !!elevation.TokenIsElevated;
    }

    if (token)
        NtClose(token);

    return ret;
}

void
Driver::WaitOnState(ULONG state) const
{
    while (1)
    {
        auto cur_state = GetState();

        if (cur_state == state || !cur_state /* shouldn't happen, but don't spin forever */)
            return;

        Sleep(100);
    }
}

ULONG
Driver::GetState() const
{
    SERVICE_STATUS status{};

    if (!QueryServiceStatus(m_service, &status))
        return 0;

    return status.dwCurrentState;
}

AC_Result
Driver::Load(const fs::path& driver_path, std::wstring_view display_name, std::wstring_view device)
{
    // If we're not elevated, CreateService will fail
    if (!IsElevated())
    {
        LOG_ERROR("Couldn't start driver (process is not elevated)");
        CloseServiceHandle(g::service_manager);
        return AC_RFailure;
    }

    // Already loaded?
    if (GetState() != SERVICE_STOPPED)
        return AC_RInvalidCall;

    // Sanity check the path
    if (!fs::exists(driver_path) || !fs::is_regular_file(driver_path)
        || !driver_path.has_extension() || driver_path.extension() != ".sys")
    {
        LOG_ERROR(L"Driver is not at {}", driver_path.wstring());
        return AC_RFailure;
    }

    // TODO - surround driver_path with quotes if path has spaces
    auto service = CreateService(g::service_manager, m_name.c_str(), display_name.data(), SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driver_path.wstring().c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);

    // Either we newly created it or it's not the first time
    if (service || GetLastError() == ERROR_SERVICE_EXISTS)
    {
        if (service)
            CloseServiceHandle(service); // ???
        service = OpenService(g::service_manager, m_name.c_str(), SERVICE_ALL_ACCESS);
    }

    bool success{};
    if (service)
    {
        if (success = StartService(service, 0, nullptr))
            LOG_SUCCESS("Started kernel driver");
        else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
            LOG_INFO("Kernel driver is already running");
        else
            LogWindowsError("Couldn't start kernel driver");

        m_service = service;
    }

    WaitOnState(SERVICE_RUNNING);

    if (success)
    {
        m_handle = CreateFile(device.data(), GENERIC_ALL,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (m_handle == INVALID_HANDLE_VALUE)
        {
            LOG_ERROR("Couldn't open I/O handle to driver");
            return AC_RFailure;
        }
    }

    return AC_RSuccess;
}

AC_Result
Driver::Unload()
{
    if (GetState() != SERVICE_RUNNING)
        return AC_RInvalidCall;

    SERVICE_STATUS status;
    ControlService(m_service, SERVICE_CONTROL_STOP, &status);

    WaitOnState(SERVICE_STOPPED);

    CloseServiceHandle(m_service);
    NtClose(m_handle);

    // TODO - return something else if driver is already unloaded etc
    return AC_RSuccess;
}

AC_API AC_Result
AC_LoadDriver()
{
    // Note: the driver is unsigned which would cause problems in real usage

    if (!g::service_manager)
        g::service_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);

    if (!g::service_manager)
    {
        LOG_ERROR("Couldn't open service manager");
        return AC_RFailure;
    }

    // Do the actual work
    const auto ret = g::driver.Load(
        fs::current_path() / "driver.sys",
        L"Anticheat Driver",
        L"\\\\?\\GLOBALROOT\\Device\\ACDriver"
    );

    if (ret != AC_RSuccess)
        return ret;

    // Send a protect request immediately afterwards to affirm connection
    // and set our process to be protected.
    // After this, no other process should be able to make IOCTLs to the driver
    KProtectRequest request;
    request.pid = HandleToUlong(NtCurrentProcessId());
    request.result = 0;

    g::driver.Call(IOCTL_PROTECT_REQUEST, &request);

    if (NT_SUCCESS(request.result))
        LOG_SUCCESS("Driver successfully received protection request");
    else
        LOG_ERROR("Driver did not acknowledge protection request");

    return ret;
}

AC_API AC_Result
AC_UnloadDriver()
{
    AC_Result ret = AC_RFailure;

    if (g::driver.m_service)
        ret = g::driver.Unload();

    if (g::service_manager)
        CloseServiceHandle(g::service_manager);

    return ret;
}

#endif

VOID NTAPI
LdrEnumCallback(LDR_DATA_TABLE_ENTRY* module_info, PVOID, BOOLEAN*)
{
    VERBOSE(LOG_RAW(
        L"Name: {} Flags: {:#x} Base: {} Reason: {}",
        module_info->BaseDllName.Buffer,
        module_info->Flags,
        module_info->DllBase,
        ( ULONG )module_info->LoadReason)
    );
    ac_ctrl.AddLoaded(module_info);
}

INTERNAL void
EarlyInitialize()
{
    DO_ONCE();

    logger::Start(L"Anticheat", L"ac_log.txt");

    Self() = Module(( PVOID )&__ImageBase);

    EnableMitigationPolicies();

    LOG_RAW("=== Debug info ===");
    LOG_RAW(L"Working directory: {}", fs::current_path().wstring());

    // Try to read the boot options for test signing and kernel debug mode
    WCHAR buf[256]{};
    auto size = ( ULONG )std::size(buf);
    if (RegGetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", L"SystemStartOptions",
        RRF_RT_REG_SZ, nullptr, buf, &size) == ERROR_SUCCESS)
    {
        // Normalize
        for (size_t i = 0; i < size; i++)
            buf[i] = towlower(buf[i]);

        // Potentially inform about issues
        if (wcsstr(buf, L"testsigning"))
        {
            LOG_RAW("Test signing enabled");
#ifdef _RELEASE
            ExitWithMessage("Please disable driver test signing mode");
#endif
        }
        if (wcsstr(buf, L"debug"))
        {
            LOG_RAW("KD enabled");
#ifdef _RELEASE
            ExitWithMessage("Please disable kernel debugging");
#endif
        }
    }

    ClientInitialize();

    LOG_RAW("==================");
}

AC_API const AC_Client*
AC_GetClient()
{
    return &g::client;
}

AC_API AC_Result
AC_BlacklistModule(const wchar_t* name)
{
    if (!name || wcslen(name) >= MAX_PATH)
        return AC_RInvalidParam1;

    if (RangeContains(g::dll_blacklist, name))
        return AC_RInvalidCall;

    g::dll_blacklist.push_back(name);
    return AC_RSuccess;
}

AC_API AC_Result
AC_Confirm()
{
    if (!ac_ctrl.m_scanner.IsAlive())
        return AC_RFailure;

#ifdef AC_DRIVER
    SERVICE_STATUS status;
    // TODO - wrapper function
    if (g::driver.m_service && QueryServiceStatus(g::driver.m_service, &status))
    {
        if (status.dwCurrentState != SERVICE_RUNNING)
            return AC_RFailure;
    }
#endif

    return AC_RSuccess;
}

template<class F>
INTERNAL AC_Result
SetCallback(F& type, F function)
{
    if (!function)
        return AC_RInvalidParam1;

    type = function;
    return AC_RSuccess;
}

AC_API AC_Result
AC_RegisterInitCallback(AC_InitCallback function)
{
    return SetCallback(callbacks::on_init, function);
}

AC_API AC_Result
AC_RegisterHookCallback(AC_HookCallback function)
{
    return SetCallback(callbacks::on_hook, function);
}

AC_API AC_Result
AC_RegisterScanCallback(AC_ScanCallback function)
{
    return SetCallback(callbacks::on_scan, function);
}

AC_API AC_Result
AC_RegisterDetectionCallback(AC_DetectionCallback function)
{
    return SetCallback(callbacks::on_detection, function);
}

AC_API AC_Result
AC_SetBaseTimeout(unsigned int timeout)
{
    if (!timeout)
    {
        AC_Thread::s_timeout = AC_Thread::s_default_timeout;
        return AC_RSuccess;
    }

    if (timeout < max_timeout_offset || timeout >= UINT_MAX - max_timeout_offset)
        return AC_RInvalidParam1;

    AC_Thread::s_timeout = timeout;
    return AC_RSuccess;
}

AC_API AC_Result
AC_ProtectModule(const wchar_t* name)
{
    if (ac_ctrl.m_initialized)
        return AC_RInvalidCall;

    if (name)
    {
        if (wcslen(name) >= MAX_PATH)
            return AC_RInvalidParam1;

        return ac_ctrl.AddProtected(name);
    }

    return ac_ctrl.AddProtected({});
}

AC_Result
AC_Ctrl::AddProtected(std::wstring_view name)
{
    if (auto entry = FindLdrEntry(name))
    {
        if (!RangeContains(m_loaded, entry, &Module::m_ldr_entry))
        {
            m_protected.push_back(ProtectedModule(entry));
            return AC_RSuccess;
        }
        return AC_RInvalidCall;
    }
    return AC_RFailure;
}

AC_API AC_Result
AC_Initialize()
{
    if (ac_ctrl.m_initialized)
        return AC_RInvalidCall;

    EarlyInitialize();

#ifdef _RELEASE
    NtSetInformationThread(NtCurrentThread(), ThreadHideFromDebugger, nullptr, 0);
#endif

    // Always protect the current module
    ac_ctrl.AddProtected(Self().m_name);

    // Store all currently loaded modules
#pragma warning(disable: 6387)
    LdrEnumerateLoadedModules(false, LdrEnumCallback, nullptr);
#pragma warning(default: 6387)

    ac_ctrl.m_initialized = true;

    static const auto ldr_register_dll_notification = ac_ctrl.m_ntdll.GetExport<
        decltype(LdrRegisterDllNotification)*>("LdrRegisterDllNotification");
    if (!ldr_register_dll_notification ||
        !NT_SUCCESS(ldr_register_dll_notification(0, DllNotificationCallback, nullptr, &g::dll_notify_cookie)))
    {
        LogWindowsError("Couldn't register DLL notification callback");
        return AC_RFailure;
    }

    hooks::Set(true);

    // After our hooks are set, also protect these system modules
    ac_ctrl.AddProtected(L"ntdll.dll");
    ac_ctrl.AddProtected(L"kernel32.dll");

    ac_ctrl.m_scanner.Initialize(DEBUG_STR("Scanner"), PerformIntegrityChecks);

#if defined(_DEBUG) && !defined(AC_DLL)
    InjectDll(InjectionMethod::ManualMap, NtCurrentProcess(), fs::current_path() / "cheat.dll");
    Sleep(500);
#endif

    if (callbacks::on_init)
        callbacks::on_init(&g::client);

    return AC_RSuccess;
}

AC_API AC_Result
AC_End()
{
    if (!ac_ctrl.m_initialized)
        return AC_RInvalidCall;

    ac_ctrl.m_scanner.Exit();

    if (const auto ldr_unregister_dll_notification = ac_ctrl.m_ntdll.GetExport<decltype(LdrUnregisterDllNotification)*>(
        "LdrUnregisterDllNotification"))
    {
        ldr_unregister_dll_notification(g::dll_notify_cookie);
    }

#ifdef AC_DRIVER
    AC_UnloadDriver();
#endif

    hooks::Set(false);
    logger::End();

    ac_ctrl = AC_Ctrl();

    return AC_RSuccess;
}

#ifdef AC_DLL
BOOL WINAPI
DllMain(HMODULE instance, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Creating a thread just to initialize is not really a good idea
        // but in practice AC_Initialize would be called by the game
        HANDLE thread{};
        if (NT_SUCCESS(RtlCreateUserThread(NtCurrentProcess(), nullptr, false, 0, 0, 0,
            ( PUSER_THREAD_START_ROUTINE )AC_Initialize, nullptr, &thread, nullptr)))
        {
            NtClose(thread);
        }
        break;
    }
    case DLL_PROCESS_DETACH:
        hooks::Set(false);
        logger::End();
        break;
    default:
        break;
    }
    return true;
}
#endif

AC_API const char*
AC_ResultToString(AC_Result result)
{
    switch (result)
    {
    case AC_RSuccess:       return "Success";
    case AC_RFailure:       return "Unspecified Failure";
    case AC_RInvalidParam1: return "Invalid Parameter 1";
    case AC_RInvalidParam2: return "Invalid Parameter 2";
    case AC_RInvalidCall:   return "Invalid Call";
    default:                return "Unknown";
    }
}

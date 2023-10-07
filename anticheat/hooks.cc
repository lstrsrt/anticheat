#include "core.hh"

#include <intrin.h>

struct AutoDetourTransaction
{
    explicit AutoDetourTransaction()
    {
        DetourTransactionBegin();
        DetourUpdateThread(NtCurrentThread());
    }

    ~AutoDetourTransaction()
    {
        DetourTransactionCommit();
    }
};

INTERNAL bool
SetFunctionDetour(PVOID address, PVOID original, bool enable)
{
    if (enable)
        return DetourAttach(( PVOID* )original, address) == NO_ERROR;
    else
        return DetourDetach(( PVOID* )original, address) == NO_ERROR;
}

struct WatchedThread
{
    HANDLE m_handle{};
    PVOID m_parameter{}; // always null if added from NtSuspendThread hook
    ULONG m_id{};
    ULONG_PTR m_start_address{};
};

namespace g
{
    extern std::vector<PCWSTR> dll_blacklist;
}

namespace callbacks
{
    extern AC_HookCallback on_hook;
}

static std::vector<WatchedThread> thread_watchlist;

struct HookInternal : AC_Hook
{
    std::vector<AC_Address> m_addresses{};
};

INTERNAL inline void
PlaceThreadOnWatchlist(HANDLE handle, PVOID parameter, ULONG id, ULONG_PTR start_address)
{
    if (!RangeContains(thread_watchlist, handle, &WatchedThread::m_handle))
        thread_watchlist.push_back(WatchedThread(handle, parameter, id, start_address));
}

//
// Thread creation callbacks, used in NtCreateThreadEx and RtlCreateUserThread
//

INTERNAL bool
PreCreateThread(PVOID start_address)
{
    if (!IsWithinAnyTextSection(start_address))
    {
        LOG_ERROR("Attempt to start thread with invalid executable address!");
        ReportDetection(AC_DSuspiciousThread, size_t(0));
#ifdef _RELEASE
        return false;
#endif
    }
    return true;
}

INTERNAL void NTAPI
OnThreadCreateApc(ULONG_PTR)
{
    // TODO
}

INTERNAL void
PostCreateThread(HANDLE thread, PVOID parameter, PVOID start_address, bool suspended)
{
    if (suspended)
    {
        const auto tid = GetThreadId(thread);
        LOG_INFO("Suspended thread {} was created. Start {}", tid, ( PVOID )start_address);
        PlaceThreadOnWatchlist(thread, parameter, tid, ( ULONG_PTR )start_address);
    }

    QueueUserAPC(&OnThreadCreateApc, thread, 0);
    NtTestAlert();
}

INTERNAL void
OnHookEntryEx(PCWSTR name, Hash32 hash, HookInternal* stats, PVOID caller)
{
    VERBOSE(LOG_RAW(L"[ H ] {}", name));

    stats->m_total_call_count++;

    PVOID base{};
    RtlPcToFileHeader(caller, &base);

    if (!RangeContains(stats->m_addresses, caller, &AC_Address::m_ptr))
    {
        VERBOSE(LOG_INFO(
            L"New return address for {}: {} ({})",
            name,
            caller,
            AddressToModuleName(caller).value_or(L"Unknown"))
        );

        stats->m_addresses.push_back(AC_Address(caller, AddressToSection(caller, base), base));
        stats->m_unique_callers = stats->m_addresses.data();
        stats->m_unique_caller_count++;
    }

    if (callbacks::on_hook)
        callbacks::on_hook(stats, hash);

    if (!base)
        ReportDetection(AC_DSuspiciousCall);
}

#define OnHookEntry(name) \
    static constexpr auto hash = Hash(name); \
    OnHookEntryEx(DEBUG_STR(name), hash, &stats, _ReturnAddress())

namespace hooks
{
    namespace nt_protect_virtual_memory
    {
        static auto original = &NtProtectVirtualMemory;
        static HookInternal stats{};

        NTSTATUS NTAPI Hook(HANDLE process_handle, PVOID* base_address, PSIZE_T region_size,
            ULONG new_protect, PULONG old_protect)
        {
            OnHookEntry("NtProtectVirtualMemory");

#ifdef _DEBUG
            const auto protect_to_string = [](ULONG prot) -> PCSTR
            {
                switch (prot)
                {
                case PAGE_NOACCESS: return "PAGE_NOACCESS";
                case PAGE_READONLY: return "PAGE_READONLY";
                case PAGE_READWRITE: return "PAGE_READWRITE";
                case PAGE_WRITECOPY: return "PAGE_WRITECOPY";
                case PAGE_EXECUTE: return "PAGE_EXECUTE";
                case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
                case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
                case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
                case PAGE_GUARD: return "PAGE_GUARD";
                case PAGE_NOCACHE: return "PAGE_NOCACHE";
                case PAGE_WRITECOMBINE: return "PAGE_WRITECOMBINE";
                default: return "unknown";
                }
            };
#endif

            if (!base_address || !region_size)
                return original(process_handle, base_address, region_size, new_protect, old_protect);

            if (NtCompareObjects(process_handle, NtCurrentProcess()) == STATUS_NOT_SAME_OBJECT)
                return original(process_handle, base_address, region_size, new_protect, old_protect);

            // Is this a module and is it stored in our list?
            const auto address = *base_address;
            const auto target = AddressToModule(( ULONG_PTR )address);
            if (!target)
                return original(process_handle, base_address, region_size, new_protect, old_protect);

            const auto section = AddressToSection(address, target->m_base);
            if (!section)
                return STATUS_CONFLICTING_ADDRESSES; // ???

            const auto section_name = GetSectionName(section);
            VERBOSE(LOG_INFO("Protect attempt: {}!{} (size {}, section {}): {} ({:#x})",
                WideStringToString(target->m_name).c_str(),
                address,
                *region_size,
                section_name,
                protect_to_string(new_protect),
                new_protect)
            );

            // Non-protected modules are exempt
            if (!RangeContains(ac_ctrl.m_protected, target.value()))
                return original(process_handle, base_address, region_size, new_protect, old_protect);

            // In general, disallow changing pages to RWX
            if (new_protect & PAGE_EXECUTE_READWRITE)
            {
                LOG_INFO("RWX: {} (size {}, section {})",
                    address,
                    *region_size,
                    section_name
                );
#ifdef _RELEASE
                return STATUS_INVALID_PAGE_PROTECTION;
#endif
            }

            // Disallow code and import modifications
            const auto section_hash = Hash(section_name);
            if (section_hash == ".text"_hash || section_hash == ".rdata"_hash || section_hash == ".idata"_hash)
            {
#ifdef _RELEASE
                return STATUS_INVALID_PAGE_PROTECTION;
#endif
            }

            return original(process_handle, base_address, region_size, new_protect, old_protect);
        }
    }

    namespace nt_create_thread_ex
    {
        static auto original = &NtCreateThreadEx;
        static HookInternal stats{};

        NTSTATUS NTAPI Hook(PHANDLE thread, ACCESS_MASK desired_access, POBJECT_ATTRIBUTES object_attributes,
            HANDLE process, PVOID start_address, PVOID argument, ULONG create_flags, SIZE_T zero_bits,
            SIZE_T stack_size, SIZE_T max_stack_size, PPS_ATTRIBUTE_LIST attribute_list)
        {
            OnHookEntry("NtCreateThreadEx");

            if (!PreCreateThread(start_address))
                return STATUS_INVALID_HANDLE;

            const auto status = original(thread, desired_access, object_attributes, process, start_address,
                argument, create_flags, zero_bits, stack_size, max_stack_size, attribute_list);

            if (!NT_SUCCESS(status))
                return status;

            PostCreateThread(*thread, argument, start_address, create_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED);

            return status;
        }
    }

    namespace rtl_create_user_thread
    {
        static auto original = &RtlCreateUserThread;
        static HookInternal stats{};

        NTSTATUS NTAPI Hook(HANDLE process, PSECURITY_DESCRIPTOR thread_security_descriptor, BOOLEAN create_suspended,
            ULONG zero_bits, SIZE_T max_stack_size, SIZE_T committed_stack_size, PUSER_THREAD_START_ROUTINE start_address,
            PVOID parameter, PHANDLE thread, PCLIENT_ID client_id)
        {
            OnHookEntry("RtlCreateUserThread");

            if (!PreCreateThread(start_address))
                return STATUS_INVALID_HANDLE;

            const auto status = original(process, thread_security_descriptor, create_suspended, zero_bits,
                max_stack_size, committed_stack_size, start_address, parameter, thread, client_id);

            if (!NT_SUCCESS(status))
                return status;

            PostCreateThread(*thread, parameter, start_address, create_suspended);

            return status;
        }
    }

    namespace nt_suspend_thread
    {
        static auto original = &NtSuspendThread;
        static HookInternal stats{};

        NTSTATUS NTAPI Hook(HANDLE thread, PULONG prev_suspend_count)
        {
            OnHookEntry("NtSuspendThread");

            // Don't allow anyone to suspend our threads (doesn't trigger a detection for now)
            const auto tid = GetThreadId(thread);
            if (IsOwnThread(thread))
            {
                LOG_INFO("Someone is trying to suspend an AC thread");
#ifdef _RELEASE
                return STATUS_INVALID_HANDLE;
#endif
            }

            ULONG_PTR start_addr{};
            if (NT_SUCCESS(NtQueryInformationThread(thread, ThreadQuerySetWin32StartAddress, &start_addr,
                sizeof(start_addr), nullptr)))
            {
                PlaceThreadOnWatchlist(thread, nullptr, tid, start_addr);
            }

            return original(thread, prev_suspend_count);
        }
    }

    namespace nt_terminate_thread
    {
        static auto original = &NtTerminateThread;
        static HookInternal stats{};

        NTSTATUS NTAPI Hook(HANDLE thread, NTSTATUS exit_status)
        {
            OnHookEntry("NtTerminateThread");

            if (IsOwnThread(thread))
            {
                LOG_INFO("Someone is trying to terminate an AC thread");
#ifdef _RELEASE
                return STATUS_ACCESS_DENIED;
#endif
            }

            return original(thread, exit_status);
        }
    }

    namespace nt_set_context_thread
    {
        static auto original = &NtSetContextThread;
        static HookInternal stats{};

        NTSTATUS NTAPI Hook(HANDLE thread_handle, PCONTEXT context)
        {
            OnHookEntry("NtSetContextThread");

            // Returns false if the new address is outside of the module associated with start_address
            const auto check_address = [&](ULONG_PTR address, ULONG_PTR start_address) -> bool
            {
                if (!address)
                    return true;

                MEMORY_BASIC_INFORMATION mem_info{};
                if (!QueryMemory(NtCurrentProcess(), ( PVOID )address, MemoryBasicInformation, &mem_info))
                    return true;

                if (mem_info.Protect & PAGE_EXECUTE_MASK)
                {
                    auto original_mod = AddressToModule(start_address);
                    auto mod = AddressToModule(address);

                    if (!mod || mod.value() != original_mod)
                    {
                        ReportDetection(AC_DSuspiciousThread, GetThreadId(thread_handle));
#ifdef _RELEASE
                        return false;
#endif
                    }
                }

                return true;
            };

            if (!thread_handle || !context)
                return original(thread_handle, context);

            const auto thread = rg::find(thread_watchlist, thread_handle, &WatchedThread::m_handle);
            if (thread == thread_watchlist.cend())
                return original(thread_handle, context);

            //
            // Check EIP/RIP for obvious reasons, as well as EAX/RCX, used for the thread start address.
            //

            if (context->ContextFlags & CONTEXT_CONTROL)
            {
#ifdef AC_X64
                if (!check_address(context->Rip, thread->m_start_address))
#else
                if (!check_address(context->Eip, thread->m_start_address))
#endif
                    return STATUS_INVALID_HANDLE;
            }

            if (context->ContextFlags & CONTEXT_INTEGER)
            {
#ifdef AC_X64
                if (!check_address(context->Rcx, thread->m_start_address))
#else
                if (!check_address(context->Eax, thread->m_start_address))
#endif
                    return STATUS_INVALID_HANDLE;
            }

            return original(thread_handle, context);
        }
    }

    namespace nt_create_section
    {
        static auto original = &NtCreateSection;
        static HookInternal stats{};

        NTSTATUS NTAPI Hook(PHANDLE section_handle, ACCESS_MASK desired_access, POBJECT_ATTRIBUTES object_attributes,
            PLARGE_INTEGER max_size, ULONG section_page_protection, ULONG allocation_attributes, HANDLE file_handle)
        {
            OnHookEntry("NtCreateSection");

            // TODO - investigate these cases
            if (section_page_protection & PAGE_EXECUTE_READWRITE)
                LOG_INFO("RWX section created");

            if (!(allocation_attributes & SEC_IMAGE))
            {
                return original(section_handle, desired_access, object_attributes, max_size,
                    section_page_protection, allocation_attributes, file_handle);
            }

            WCHAR file_path[MAX_PATH]{};
            if (GetFinalPathNameByHandle(file_handle, file_path, ( DWORD )std::size(file_path), FILE_NAME_NORMALIZED)
                <= std::size(file_path))
            {
                if (IsFileBlacklisted(file_path, true))
                {
                    ReportDetection(AC_DAttemptedDllLoad, file_path);
#ifdef _RELEASE
                    return STATUS_CONFLICTING_ADDRESSES;
#endif
                }
            }

            // Audit every new image that gets mapped by looking at its PE headers
            BYTE dos_buf[sizeof(IMAGE_DOS_HEADER)]{};
            DWORD read{};

            if (ReadFile(file_handle, dos_buf, sizeof(IMAGE_DOS_HEADER), &read, nullptr))
            {
                auto dos = ( IMAGE_DOS_HEADER* )dos_buf;
                BYTE nt_buf[sizeof(IMAGE_NT_HEADERS)]{};
                SetFilePointer(file_handle, dos->e_lfanew, nullptr, 0);

                if (ReadFile(file_handle, nt_buf, sizeof(IMAGE_NT_HEADERS), &read, nullptr))
                {
                    auto nt = ( IMAGE_NT_HEADERS* )nt_buf;
                    if (CompareNtHeaders(ac_ctrl.m_ntdll.m_nt_headers, nt) ||
                        CompareNtHeaders(ac_ctrl.m_kernel32.m_nt_headers, nt))
                    {
                        // Someone is trying to map ntdll/kernel32 with a changed name
                        // This is probably to overwrite our hooks, so block it here
                        ReportDetection(AC_DSuspiciousMapping);
#ifdef _RELEASE
                        return STATUS_INVALID_PAGE_PROTECTION;
#endif
                    }
                }
            }

            return original(section_handle, desired_access, object_attributes, max_size,
                section_page_protection, allocation_attributes, file_handle);
        }
    }

    namespace nt_map_view_of_section
    {
        static auto original = &NtMapViewOfSection;
        static HookInternal stats{};

        NTSTATUS NTAPI Hook(HANDLE section_handle, HANDLE process_handle, PVOID* base_address, ULONG_PTR zero_bits,
            SIZE_T commit_size, PLARGE_INTEGER section_offset, PSIZE_T view_size, SECTION_INHERIT inherit_disposition,
            ULONG allocation_type, ULONG win32_protect)
        {
            OnHookEntry("NtMapViewOfSection");

            if (NtCompareObjects(process_handle, NtCurrentProcess()) == STATUS_NOT_SAME_OBJECT)
            {
                return original(section_handle, process_handle, base_address, zero_bits, commit_size,
                    section_offset, view_size, inherit_disposition, allocation_type, win32_protect);
            }

            // TIB stores the path if this is a standard DLL load
            if (const auto dll_path = ( wchar_t* )NtCurrentTeb()->NtTib.ArbitraryUserPointer)
            {
                if (IsFileBlacklisted(dll_path, true))
                {
                    ReportDetection(AC_DAttemptedDllLoad, dll_path);
#ifdef _RELEASE
                    return STATUS_CONFLICTING_ADDRESSES;
#endif
                }
            }

            return original(section_handle, process_handle, base_address, zero_bits, commit_size,
                section_offset, view_size, inherit_disposition, allocation_type, win32_protect);
        }
    }

    static const PVOID disallowed_addresses[] = {
        LoadLibraryA,
        LoadLibraryW,
        LoadLibraryExA,
        LoadLibraryExW,
        LdrLoadDll
    };

    namespace base_thread_init_thunk
    {
        using Type = void(__fastcall*)(BOOL, PVOID, PVOID);
        static Type original{};
        static HookInternal stats{};

        void __fastcall Hook(BOOL is_initial_thread, PVOID start_address, PVOID param)
        {
            OnHookEntry("BaseThreadInitThunk");

            for (const auto address : disallowed_addresses)
            {
                if (start_address == address)
                {
                    ReportDetection(AC_DAttemptedDllLoad);
#ifdef _RELEASE
                    // Prevent execution by passing a function that returns immediately
                    return original(is_initial_thread, +[] { return; }, param);
#else
                    break;
#endif
                }
            }

            return original(is_initial_thread, start_address, param);
        }
    }

    void Set(bool enable)
    {
        AutoDetourTransaction dt{};
        SetFunctionDetour(nt_protect_virtual_memory::Hook, &nt_protect_virtual_memory::original, enable);
        SetFunctionDetour(nt_create_thread_ex::Hook, &nt_create_thread_ex::original, enable);
        SetFunctionDetour(rtl_create_user_thread::Hook, &rtl_create_user_thread::original, enable);
        SetFunctionDetour(nt_suspend_thread::Hook, &nt_suspend_thread::original, enable);
        SetFunctionDetour(nt_terminate_thread::Hook, &nt_terminate_thread::original, enable);
        SetFunctionDetour(nt_set_context_thread::Hook, &nt_set_context_thread::original, enable);
        SetFunctionDetour(nt_create_section::Hook, &nt_create_section::original, enable);
        SetFunctionDetour(nt_map_view_of_section::Hook, &nt_map_view_of_section::original, enable);
        if (FindFunction("kernel32", "BaseThreadInitThunk", base_thread_init_thunk::original))
            SetFunctionDetour(base_thread_init_thunk::Hook, &base_thread_init_thunk::original, enable);
    }

}

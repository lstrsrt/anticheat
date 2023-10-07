// Injection routines used for debugging.

#include "core.hh"

#pragma region manual_map

struct MappingContext
{
    inline explicit MappingContext(uint8_t* image_base, IMAGE_OPTIONAL_HEADER* opt_header)
        : image_base(image_base), opt_header(*opt_header)
    {
    }

    uint8_t* image_base{};
    IMAGE_OPTIONAL_HEADER opt_header{};

    decltype(LoadLibraryA)* load_library{ LoadLibraryA };
    decltype(GetProcAddress)* get_proc_address{ GetProcAddress };
};

INTERNAL DWORD
SectionPermissionsToProtectFlags(DWORD permissions)
{
    if (permissions & IMAGE_SCN_CNT_CODE || permissions & IMAGE_SCN_MEM_EXECUTE)
    {
        if (permissions & IMAGE_SCN_MEM_WRITE)
            return PAGE_EXECUTE_READWRITE;
        if (permissions & IMAGE_SCN_MEM_READ)
            return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (permissions & IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
        return PAGE_READWRITE;
    if (permissions & IMAGE_SCN_MEM_READ)
        return PAGE_READONLY;
    return PAGE_NOACCESS;
}

INTERNAL bool
ProtectMemory(HANDLE process, LPVOID address, SIZE_T size, DWORD protect_flags)
{
    SIZE_T region_size = size;
    ULONG _;
    return NT_SUCCESS(NtProtectVirtualMemory(process, &address, &region_size, protect_flags, &_));
}

INTERNAL void __stdcall Shellcode(MappingContext*);

INTERNAL bool
ManualMap(HANDLE process, const fs::path& dll_path)
{
    std::ifstream file{ dll_path, std::ios::binary | std::ios::ate };
    if (!file)
        return false;

    const auto file_size = file.tellg();
    AutoVirtualAlloc disk_image{ ( SIZE_T )file_size };
    auto image_data = ( BYTE* )disk_image.m_memory;

    file.seekg(0, std::ios::beg);
    file.read(( char* )image_data, file_size);

    if ((( IMAGE_DOS_HEADER* )image_data)->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto nt_headers = RtlImageNtHeader(image_data);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        return false;

    auto opt_header = &nt_headers->OptionalHeader;
    AutoVirtualAlloc image{ opt_header->SizeOfImage, PAGE_READWRITE, process };
    if (!image)
        return false;

    auto image_base = ( BYTE* )image.m_memory;
    if (!ProtectMemory(process, image_base, opt_header->SizeOfImage, PAGE_EXECUTE_READWRITE))
        return false;

    if (!WriteMemory(process, image_base, image_data, sizeof(IMAGE_NT_HEADERS)))
        return false;

    WalkSections(nt_headers, [&](IMAGE_SECTION_HEADER* section)
    {
        if (!WriteMemory(process, image_base + section->VirtualAddress, image_data + section->PointerToRawData, section->SizeOfRawData))
            LogWindowsError("Couldn't map section");
        return true;
    });

    AutoVirtualAlloc mapping_ctx{ sizeof(MappingContext), PAGE_READWRITE, process };
    if (!mapping_ctx)
        return false;

    MappingContext ctx{ image_base, opt_header };
    if (!WriteMemory(process, mapping_ctx, &ctx))
        return false;

    static constexpr auto shellcode_size = 0x1000; // Allocate 1 page
    AutoVirtualAlloc shellcode{ shellcode_size, PAGE_EXECUTE_READWRITE, process };
    if (!shellcode)
        return false;

    if (!WriteMemory(process, shellcode, Shellcode, shellcode_size))
        return false;

    // FIXME
    HANDLE thread{};
    if (!NT_SUCCESS(RtlCreateUserThread(process, nullptr, false, 0, 0, 0,
        ( PUSER_THREAD_START_ROUTINE )Shellcode /* shellcode.m_memory */,
        mapping_ctx, &thread, nullptr))
        || !thread)
    {
        LogWindowsError("Couldn't create thread");
        return false;
    }

    NtWaitForSingleObject(thread, false, nullptr);

    image.m_free = false;
    return true;
}

#pragma runtime_checks("", off)

#define GetImageDirEntry(type, ctx, entry) reinterpret_cast<type*>(ctx->image_base + ctx->opt_header.DataDirectory[entry].VirtualAddress)

struct IMAGE_RELOCATION_ENTRY
{
    WORD Offset : 12;
    WORD Type : 4;
};
static_assert(sizeof(IMAGE_RELOCATION_ENTRY) == sizeof(WORD));

#ifdef AC_X64
#define IMAGE_RELOCATION_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_RELOCATION_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

INTERNAL void
ProcessRelocations(MappingContext* ctx, BYTE* location_delta)
{
    const auto reloc_dir_size = ctx->opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!reloc_dir_size)
        return;

    auto reloc = GetImageDirEntry(IMAGE_BASE_RELOCATION, ctx, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    const auto last_reloc = ( IMAGE_BASE_RELOCATION* )(( UINT_PTR )reloc + reloc_dir_size);

    while (reloc && reloc < last_reloc && reloc->SizeOfBlock)
    {
        const auto entry_count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
        auto info = ( IMAGE_RELOCATION_ENTRY* )(reloc + 1);
        for (SIZE_T i = 0; i < entry_count; i++, info++)
        {
            if (info->Type == IMAGE_RELOCATION_TYPE)
            {
                auto patch = ( UINT_PTR* )(ctx->image_base + reloc->VirtualAddress +
                    info->Offset);
                *patch += ( UINT_PTR )location_delta;
            }
        }
        reloc = ( IMAGE_BASE_RELOCATION* )(( BYTE* )reloc + reloc->SizeOfBlock);
    }
}

INTERNAL void
ResolveImports(MappingContext* ctx)
{
    if (!ctx->opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        return;

    auto import_desc = GetImageDirEntry(IMAGE_IMPORT_DESCRIPTOR, ctx, IMAGE_DIRECTORY_ENTRY_IMPORT);

    while (import_desc && import_desc->Name)
    {
        auto thunk = ( IMAGE_THUNK_DATA* )(ctx->image_base + import_desc->OriginalFirstThunk);
        auto first = ( IMAGE_THUNK_DATA* )(ctx->image_base + import_desc->FirstThunk);
        auto cur_dll = ( char* )(ctx->image_base + import_desc->Name);
        auto dll = ctx->load_library(cur_dll);

        while (thunk->u1.Ordinal)
        {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
            {
                auto ordinal = IMAGE_ORDINAL(thunk->u1.Ordinal);
                first->u1.Function = ( ULONG_PTR )ctx->get_proc_address(dll, ( char* )ordinal);
            }
            else
            {
                char* name = (( IMAGE_IMPORT_BY_NAME* )(ctx->image_base + thunk->u1.AddressOfData))->Name;
                first->u1.Function = ( ULONG_PTR )ctx->get_proc_address(dll, name);
            }
            thunk++, first++;
        }
        import_desc++;
    }
}

INTERNAL void
ExecuteTlsCallbacks(MappingContext* ctx)
{
    if (!ctx->opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
        return;

    auto tls = GetImageDirEntry(IMAGE_TLS_DIRECTORY, ctx, IMAGE_DIRECTORY_ENTRY_TLS);
    auto callback = ( PIMAGE_TLS_CALLBACK* )tls->AddressOfCallBacks;

    while (callback && *callback)
    {
        (*callback)(ctx->image_base, DLL_PROCESS_ATTACH, nullptr);
        callback++;
    }
}

INTERNAL void __stdcall
Shellcode(MappingContext* ctx)
{
    if (auto location_delta = ctx->image_base - ctx->opt_header.ImageBase)
        ProcessRelocations(ctx, location_delta);

    ResolveImports(ctx);
    ExecuteTlsCallbacks(ctx);

    using DllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

    auto dll_main = ( DllMain )(ctx->image_base + ctx->opt_header.AddressOfEntryPoint);
    dll_main(( HINSTANCE )ctx->image_base, DLL_PROCESS_ATTACH, nullptr);
}

#pragma runtime_checks("", restore)

#pragma endregion

INTERNAL bool InjectViaRemoteThread(HANDLE process, const fs::path& dll_path)
{
    const auto path_size = dll_path.string().length();

    AutoVirtualAlloc path_location{ path_size, PAGE_READWRITE, process };
    if (!path_location)
    {
        LOG_ERROR("Couldn't allocate memory to write path location in process\n");
        return false;
    }

    if (!WriteMemory(process, path_location, dll_path.string().c_str(), path_size))
    {
        LOG_ERROR("Couldn't write path location to process memory\n");
        return false;
    }

    const auto kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32)
    {
        LOG_ERROR("Couldn't get handle of kernel32.dll\n");
        return false;
    }

    const auto load_library = ( void* )GetProcAddress(kernel32, "LoadLibraryA");
    if (!load_library)
    {
        LOG_ERROR("Couldn't get address of LoadLibraryA\n");
        return false;
    }

    AutoHandle thread = CreateRemoteThread(process, nullptr, 0, ( LPTHREAD_START_ROUTINE )load_library,
        path_location, 0, nullptr
    );

    if (!thread)
    {
        LOG_ERROR("Couldn't create remote thread\n");
        return false;
    }
    WaitForSingleObject(thread, INFINITE);

    return true;
}

bool InjectDll(InjectionMethod method, HANDLE process, const fs::path& dll_path)
{
    switch (method) {
    case InjectionMethod::Direct:
        return !!::LoadLibraryExA(dll_path.string().c_str(), nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    case InjectionMethod::RemoteThread:
        return InjectViaRemoteThread(process, dll_path);
    case InjectionMethod::ManualMap:
        return ManualMap(process, dll_path);
    default:
        return false;
    }
}

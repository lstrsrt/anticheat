// For internal use only, do not include outside!

#pragma once

#include <array>
#include <bitset>
#include <filesystem>
#include <random>
#include <ranges>
#include <string>
#include <variant>
#include <vector>

namespace ch = std::chrono;
namespace fs = std::filesystem;
namespace rg = std::ranges;
using namespace std::chrono_literals;

#define NOMINMAX
#define PHNT_VERSION PHNT_THRESHOLD
#define PHNT_NO_INLINE_INIT_STRING
#include <phnt/phnt_windows.h>
#include <phnt/phnt.h>

#include <detours/detours.h>

#include "api.h"
#include "logger.hh"
#include "../shared/shared.h"

#pragma region utils

#ifdef _RELEASE
[[noreturn]]
#endif
inline void Unexpected()
{
#ifdef _DEBUG
#ifdef _MSC_VER
    __debugbreak();
#else
    __builtin_debugtrap();
#endif
#else
    terminate();
#endif
}

using Hash32 = AC_Hash32;

template<class T>
concept StringLike = requires(T t)
{
    t.data();
    t.substr();
};

using Crc32 = uint_fast32_t;

template<std::integral C = char>
constexpr Hash32
Hash(const C* str)
{
    constexpr Hash32 basis = 0x811c9dc5;
    constexpr Hash32 prime = 0x1000193;

    const auto len = [str]()
    {
        size_t i{};
        while (str[i])
            i++;
        return i;
    }();

    auto hash = basis;
    for (size_t i = 0; i < len; i++)
    {
        hash ^= str[i];
        hash *= prime;
    }
    return hash;
}

template<class T>
Crc32
MakeChecksum(const T* data, size_t size = sizeof(T))
{
    static constexpr Crc32 lookup_table[]{
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
        0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
        0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
        0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
        0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
        0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
        0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
        0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
        0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
        0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
        0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
        0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
        0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
        0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
        0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
        0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
        0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
        0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
        0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
        0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
        0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
        0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
        0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
        0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
        0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
        0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
        0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
        0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
        0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
        0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
        0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
        0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
        0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
        0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
        0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
        0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
        0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
        0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
        0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    };

    Crc32 crc = UINT32_MAX;
    auto byte = ( const uint8_t* )data;
    while (size--)
        crc = (crc >> 8) ^ lookup_table[(crc & UINT8_MAX) ^ *byte++];
    return ~crc;
}

constexpr ULONG_PTR
AlignDown(ULONG_PTR value, ULONG_PTR align)
{
    return value & ~(align - 1);
};

constexpr ULONG_PTR
AlignUp(ULONG_PTR value, ULONG_PTR align)
{
    return (value + align - 1) & ~(align - 1);
};

template<StringLike S = std::string_view>
constexpr Hash32
Hash(const S& str)
{
    return Hash(str.data());
}

namespace hash_literals
{
    constexpr auto operator""_hash(const char* str, size_t)
    {
        return Hash(str);
    }

    constexpr auto operator""_hash(const wchar_t* str, size_t)
    {
        return Hash(str);
    }
}

struct Timer
{
    inline explicit Timer()
    {
        Restart();
    }

    template<class T>
    T Elapsed() const
    {
        return ch::duration_cast<T>(ch::system_clock::now() - m_start);
    }

    inline void Restart()
    {
        m_start = ch::system_clock::now();
    }

    ch::system_clock::time_point m_start;
};

using namespace hash_literals;

inline std::string
WideStringToString(std::wstring_view wstr)
{
    const auto len = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), ( int )wstr.size(), nullptr, 0, nullptr, nullptr);
    if (!len)
        return {};

    std::string str{};
    str.reserve(len);

    if (!WideCharToMultiByte(CP_UTF8, 0, wstr.data(), ( int )wstr.size(), str.data(), len, nullptr, nullptr))
        return {};

    return str;
}

inline std::wstring
StringToWideString(std::string_view str)
{
    const auto len = MultiByteToWideChar(CP_UTF8, 0, str.data(), ( int )str.size(), nullptr, 0);
    if (!len)
        return {};

    std::wstring wstr{};
    wstr.reserve(len);

    if (!MultiByteToWideChar(CP_UTF8, 0, str.data(), ( int )str.size(), wstr.data(), len))
        return {};

    return wstr;
}

#define RangeContains(range, object, ... /* proj */) \
    (rg::find(range, object, __VA_ARGS__) != range.cend())

#pragma endregion

#pragma region windows

template<class T>
bool
WriteMemory(HANDLE process, PVOID address, T* data, SIZE_T size = sizeof(T))
{
    return NT_SUCCESS(NtWriteVirtualMemory(process, address, ( PVOID )data, size, nullptr));
}

template<class T>
bool
QueryMemory(HANDLE process, PVOID address, MEMORY_INFORMATION_CLASS info_class, T* info, SIZE_T size = sizeof(T))
{
    return NT_SUCCESS(NtQueryVirtualMemory(process, address, info_class, ( PVOID )info, size, nullptr));
}

template<class T>
bool
QueryProcess(HANDLE process, PROCESSINFOCLASS info_class, T& data)
{
    return NT_SUCCESS(NtQueryInformationProcess(process, info_class, &data, sizeof(data), nullptr));
}

#ifdef _DEBUG
inline void
LogWindowsError()
{
    // these don't seem to work
    // auto nt_status = RtlGetLastNtStatus();
    // auto win32_status = RtlGetLastWin32Error();

    LOG_ERROR("Error: {} ({})", GetLastError(), std::system_category().message(GetLastError()));
}

inline void
LogWindowsError(std::string_view msg, auto&&... args)
{
    LogWindowsError();
    LOG_ERROR(msg, std::forward<decltype(args)>(args)...);
}
#else
#define LogWindowsError(...) EMPTY_STATEMENT
#endif

inline bool
CompareNtHeaders(IMAGE_NT_HEADERS* lhs, IMAGE_NT_HEADERS* rhs)
{
    // Doing a full memcmp is probably a bad idea since only one field would have to be changed to make it fail.
    // Instead, only check two fields that should be unique and are important to the OS.
    return lhs->OptionalHeader.AddressOfEntryPoint == rhs->OptionalHeader.AddressOfEntryPoint &&
        lhs->OptionalHeader.SizeOfCode == rhs->OptionalHeader.SizeOfCode;
}

struct Module;

IMAGE_SECTION_HEADER* AddressToSection(PVOID address, PVOID base);
std::optional<Module> AddressToModule(ULONG_PTR address);
std::optional<std::wstring> AddressToModuleName(PVOID address);

std::string GetSectionName(IMAGE_SECTION_HEADER* section);

bool IsWithinTextSection(const Module& mod, PVOID address);
bool IsWithinAnyTextSection(PVOID address);

bool IsOwnThread(ULONG id);
bool IsOwnThread(HANDLE handle);

void
WalkSections(IMAGE_NT_HEADERS* nt, const std::predicate<IMAGE_SECTION_HEADER*> auto&& function)
{
    auto section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!function(section))
            return;
        section++;
    }
}

template<class F>
inline PVOID
FindFunction(PCSTR module_name, PCSTR function_name, F& function)
{
    function = ( F )DetourFindFunction(module_name, function_name);
    return ( PVOID )function;
}

struct AutoHandle
{
    AutoHandle(HANDLE handle)
        : m_handle(handle)
    {
    }

    ~AutoHandle()
    {
        if (m_handle && m_handle != INVALID_HANDLE_VALUE)
            NtClose(m_handle);
    }

    operator HANDLE() { return m_handle; }
    operator bool() const { return m_handle && m_handle != INVALID_HANDLE_VALUE; }

    HANDLE m_handle{};
};

struct AutoVirtualAlloc
{
    explicit AutoVirtualAlloc(SIZE_T size, DWORD protect = PAGE_READWRITE, HANDLE process = NtCurrentProcess())
        : m_process(process)
    {
        SIZE_T region_size = size;
        if (NT_SUCCESS(NtAllocateVirtualMemory(process, &m_memory, 0, &region_size, MEM_RESERVE | MEM_COMMIT, protect)))
            m_free = true;
    }

    ~AutoVirtualAlloc()
    {
        if (m_free)
        {
            SIZE_T region_size{};
            NtFreeVirtualMemory(m_process, &m_memory, &region_size, MEM_RELEASE);
        }
    }

    operator void*() { return m_memory; }
    operator bool() const { return m_memory; }

    HANDLE m_process{};
    LPVOID m_memory{};
    bool m_free{};
};

#pragma endregion

#pragma region impl

struct Page
{
    PVOID m_address{};
    ULONG m_protect_flags{};
    ULONG_PTR m_offset{}; // Offset from section start
    Crc32 m_checksum{};
};

struct Import
{
    inline explicit Import(std::string_view module_name, char* name, ULONG_PTR address, ULONGLONG first8)
        : m_module_name(module_name), m_import_by_name(true), m_name(name), m_address(address), m_first8(first8)
    {
    }

    inline explicit Import(std::string_view module_name, DWORD ordinal, ULONG_PTR address, ULONGLONG first8)
        : m_module_name(module_name), m_ordinal(ordinal), m_address(address), m_first8(first8)
    {
    }

    std::string m_module_name{};
    bool m_import_by_name{};
    union
    {
        char* m_name;
        DWORD m_ordinal;
    };
    ULONG_PTR m_address{};
    ULONGLONG m_first8{};
};

struct Section
{
    constexpr explicit Section() = default;

    inline explicit Section(IMAGE_SECTION_HEADER* header)
        : m_header(header), m_name(header ? StringToWideString(GetSectionName(m_header)) : L"")
    {
    }

    std::vector<Page> Scan(BYTE* module_base) const;

    IMAGE_SECTION_HEADER* m_header{};
    std::wstring m_name{};           // Has to be a wstring for logging...
    std::vector<Page> m_old_pages{}; // Pages on first scan
};

struct Module
{
    constexpr explicit Module() = default;
    explicit Module(std::wstring_view name);
    explicit Module(PVOID base);
    explicit Module(LDR_DATA_TABLE_ENTRY* ldr_entry);

    inline bool operator==(const Module& rhs) const
    {
        return Base() == rhs.Base();
    }

    template<class T = ULONG_PTR>
    T Base() const
    {
        return ( T )m_base;
    }

    template<class T> requires std::is_pointer_v<T>
    T GetExport(std::string_view name) const
    {
        ANSI_STRING proc{};
        RtlInitAnsiString(&proc, name.data());
        PVOID addr{};
        LdrGetProcedureAddress(m_handle, &proc, 0, &addr);
        return ( T )addr;
    }

    template<class T> requires std::is_pointer_v<T>
    T GetDirectoryEntry(USHORT entry) const
    {
        ULONG _;
        return ( T )(RtlImageDirectoryEntryToData(m_base, true, entry, &_));
    }

    inline ULONG_PTR End() const
    {
        return Base() + m_nt_headers->OptionalHeader.SizeOfImage;
    }

    inline bool ContainsAddress(ULONG_PTR address) const
    {
        return address >= Base() && address < End();
    }

    IMAGE_SECTION_HEADER* FindSection(Hash32 hashed_name) const;

    std::wstring m_name{};
    LDR_DATA_TABLE_ENTRY* m_ldr_entry{};
    union
    {
        HMODULE m_handle{};
        PVOID m_base;
    };
    IMAGE_NT_HEADERS* m_nt_headers{};
    LONG64 m_timestamp{}; // not used yet
    bool m_signed{};
};

struct ProtectedModule : Module
{
    explicit ProtectedModule(LDR_DATA_TABLE_ENTRY* ldr_entry);

    Section m_text_section{};
    Section m_rdata_section{};
    Section m_idata_section{};
    std::vector<Import> m_old_iat{};
};

struct Driver
{
    std::wstring m_name{};
    HANDLE m_handle{};
    SC_HANDLE m_service{};

    explicit Driver(std::wstring_view name)
        : m_name(name)
    {

    }

    AC_Result Load(const fs::path& driver_path, std::wstring_view display_name, std::wstring_view device);
    AC_Result Unload();

    template<class T>
    bool Call(ULONG request, T* buffer, ULONG buffer_size = sizeof(T)) const
    {
        ULONG _;
        return DeviceIoControl(m_handle, request, ( PVOID )buffer, buffer_size,
            ( PVOID )buffer, buffer_size, &_, nullptr);
    }

    ULONG GetState() const; // SERVICE_*
    void WaitOnState(ULONG state) const;
};

struct AC_Thread
{
    constexpr explicit AC_Thread() = default;

    void Initialize(MAYBE_UNUSED PCWSTR name, void(*function)());

    inline void Exit()
    {
        // Cancels CheckedWait and causes ThreadStartRoutine to return.
        SetEvent(m_exit_event);
    }

    inline bool IsAlive()
    {
        DWORD exit_code{};
        if (GetExitCodeThread(m_handle, &exit_code))
            return exit_code == STATUS_PENDING;
        return false;
    }

    void CheckedWait() const;

    operator HANDLE() { return m_handle; }

    static constexpr ULONG s_default_timeout =
#ifdef _DEBUG
        10000;
#else
        60000;
#endif
    static inline ULONG s_timeout{ s_default_timeout };

    HANDLE m_handle{};
    ULONG m_id{};
    HANDLE m_exit_event{};
    void(*m_function)(){};
};

struct AC_Ctrl
{
    explicit AC_Ctrl() = default;

    inline Module& AddLoaded(PVOID base)
    {
        if (!RangeContains(m_loaded, base, &Module::m_base))
            m_loaded.push_back(Module(base));
        return m_loaded.back();
    }

    inline Module& AddLoaded(LDR_DATA_TABLE_ENTRY* entry)
    {
        if (!RangeContains(m_loaded, entry, &Module::m_ldr_entry))
            m_loaded.push_back(Module(entry));
        return m_loaded.back();
    }

    AC_Result AddProtected(std::wstring_view name);

    Module m_self{};
    Module m_ntdll{ L"ntdll.dll" };
    Module m_kernel32{ L"kernel32.dll" };

    AC_Thread m_scanner{};

    std::vector<Module> m_loaded{};
    std::vector<ProtectedModule> m_protected{};

    bool m_initialized{};
} inline ac_ctrl;

bool IsFileBlacklisted(PCWSTR file, bool is_full_path);

using DetectionArg = std::variant<std::monostate, std::string, std::wstring, size_t>;
void ReportDetection(AC_DetectionType type, DetectionArg arg = std::monostate{});

namespace hooks
{
    void Set(bool enable);
}

#pragma endregion

#pragma region debug

enum class InjectionMethod
{
    Direct,
    RemoteThread,
    ManualMap,
};

bool InjectDll(InjectionMethod method, HANDLE process, const fs::path& dll_path);

#pragma endregion

#pragma region windows_defs

enum SIGNATURE_STATE
{
    SIGNATURE_STATE_UNSIGNED_MISSING,
    SIGNATURE_STATE_UNSIGNED_UNSUPPORTED,
    SIGNATURE_STATE_UNSIGNED_POLICY,
    SIGNATURE_STATE_INVALID_CORRUPT,
    SIGNATURE_STATE_INVALID_POLICY,
    SIGNATURE_STATE_VALID,
    SIGNATURE_STATE_TRUSTED,
    SIGNATURE_STATE_UNTRUSTED
};

enum SIGNATURE_INFO_TYPE
{
    SIT_UNKNOWN,
    SIT_AUTHENTICODE,
    SIT_CATALOG
};

enum SIGNATURE_INFO_FLAGS
{
    SIF_NONE = 0,
    SIF_AUTHENTICODE_SIGNED = 1,
    SIF_CATALOG_SIGNED = 2,
    SIF_VERSION_INFO = 4,
    SIF_CHECK_OS_BINARY = 0x800,
    SIF_BASE_VERIFICATION = 0x1000,
    SIF_CATALOG_FIRST = 0x2000,
    SIF_MOTW = 0x4000
};

typedef struct SIGNATURE_INFO
{
    ULONG cbSize;
    SIGNATURE_STATE nSignatureState;
    SIGNATURE_INFO_TYPE nSignatureType;
    ULONG dwSignatureInfoAvailability;
    ULONG dwInfoAvailability;
    PWSTR pszDisplayName;
    ULONG cchDisplayName;
    PWSTR pszPublisherName;
    ULONG cchPublisherName;
    PWSTR pszMoreInfoURL;
    ULONG cchMoreInfoURL;
    PBYTE prgbHash;
    ULONG cbHash;
    BOOL fOSBinary;
} *PSIGNATURE_INFO;

#pragma endregion

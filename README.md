# anticheat
Implements game-agnostic methods to check for and prevent
library injections, memory manipulation and hidden code execution,
using a scanner thread and native Windows hooks.

Can be compiled as a static or dynamic library (define AC_DLL in config.h).
Both x86 and x64 are supported.

Optionally on x64, a kernel mode driver with additional protection mechanisms
can be compiled and loaded (define AC_DRIVER).
This requires the [Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).
Otherwise, the driver can be excluded from compilation in the project settings.

## usage
Compile as a .lib, link against it and call `AC_Initialize` on program startup.
To load the driver, call `AC_LoadDriver` (remember to call `AC_End` or `AC_UnloadDriver` later).
All other calls are optional and documented in api.h.

For testing, start target.exe in Debug mode. Once the anticheat has initialized,
it will load cheat.dll. The cheat will hook `SampleFunction` and `MessageBoxA`,
which should be detected on the second scan.

## notes
This is a research project for educational purposes only. It is incompatible with
most antivirus software and does not implement an online component or
other more advanced means of protection.

## dependencies

[detours](https://github.com/microsoft/Detours)\
[phnt](https://github.com/winsiderss/phnt)

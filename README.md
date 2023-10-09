# anticheat
Implements game-agnostic methods to check for and prevent
library injections, memory manipulation and hidden code execution,
using a scanner thread and native Windows hooks.

Can be compiled as a static or dynamic library (define AC_DLL in api.h).
Both x86 and x64 are supported.

## usage
Compile as a .lib, link against it and call `AC_Initialize` on program startup.
All other calls are optional and documented in api.h.

For testing, start target.exe in Debug mode. Once the anticheat has initialized,
it will load cheat.dll. The cheat will hook `SampleFunction` and `MessageBoxA`,
which should be detected on the second scan.

## notes
This is a research/educational project. It is most likely incompatible with
antivirus software. It is also easily bypassed since it does not have a
driver or online component and attempts to be non-invasive
(i.e. does not inject itself into external processes).

## dependencies

[detours](https://github.com/microsoft/Detours)\
[phnt](https://github.com/winsiderss/phnt)

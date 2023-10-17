#pragma once

// Compile as a DLL to inject into a game and test with a real cheat
// Note: set the project property "Configuration Type" to "Dynamic Library (.dll)"
// #define AC_DLL

// Load driver from usermode (x64 only). Remember to call AC_End so it can be unloaded and
// all handles are closed as appropriate!
// Note: if you don't have the WDK, you can disable compiling the driver in project settings
#define AC_DRIVER

// Log as much as possible
// Only has an effect in Debug configurations
// #define AC_LOG_VERBOSE

// Use alternative thread iteration method
// #define AC_PSS_THREAD_ITER

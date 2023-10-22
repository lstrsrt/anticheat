#pragma once

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#endif

#define GENERATE_IOCTL(code) CTL_CODE(FILE_DEVICE_UNKNOWN, (1 << 11) | code, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTL_PROTECT_REQUEST GENERATE_IOCTL(0x123)
typedef struct KProtectRequest
{
    ULONG pid;
    NTSTATUS result;
} KProtectRequest;

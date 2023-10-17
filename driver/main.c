#include "driver.h"
#include "../shared/shared.h"

#ifdef ALLOC_PRAGMA
#define CODE_SEG(name) __declspec(code_seg(name))
#else
#define CODE_SEG(name)
#endif

#ifdef DBG
#define LOG_SUCCESS(fmt, ...) DbgPrint("[+] " fmt "\n", __VA_ARGS__)
#define LOG_ERROR(fmt, ...) DbgPrint("[!] " fmt "\n", __VA_ARGS__)
#define LOG_INFO(fmt, ...) DbgPrint("[*] " fmt "\n", __VA_ARGS__)
#else
#define LOG_SUCCESS(...) EMPTY_STATEMENT
#define LOG_ERROR(...) EMPTY_STATEMENT
#define LOG_INFO(...) EMPTY_STATEMENT
#endif

#define RelativeMs(ms) (0 - (( INT64 )ms * 10000))
#define SystemProcessId (UlongToHandle(4)) // PsGetProcessId(PsInitialSystemProcess)

static BOOLEAN g_running;
static PDRIVER_OBJECT g_driver;
static PDEVICE_OBJECT g_device;
static PEPROCESS g_target;

static BOOLEAN g_process_callback;
static BOOLEAN g_thread_callback;
static BOOLEAN g_image_load_callback;
static PVOID g_handle_cookie;

INTERNAL VOID
ThreadCreationCallback(_In_ HANDLE process_id, _In_ HANDLE thread_id, _In_ BOOLEAN create)
{
    if (!create)
        return;

    if (process_id == SystemProcessId)
        return;

    if (g_target && process_id != PsGetProcessId(g_target))
        return;

    // TODO
}

INTERNAL VOID
ImageLoadCallback(_In_opt_ PUNICODE_STRING image_name, _In_ HANDLE process_id, _In_ PIMAGE_INFO image_info)
{
    if (g_target && process_id != PsGetProcessId(g_target))
        return;

    // TODO
}

#define PROCESS_CREATE_THREAD        0x0002
#define PROCESS_VM_OPERATION         0x0008
#define PROCESS_VM_READ              0x0010
#define PROCESS_VM_WRITE             0x0020
#define PROCESS_SUSPEND_RESUME       0x0800
#define PROCESS_DENIED_ACCESS_MASK   \
    (PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME)

#define THREAD_DENIED_ACCESS_MASK    (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT)

INTERNAL OB_PREOP_CALLBACK_STATUS
HandlePreOperationCallback(_In_ PVOID registration_context, _Inout_ POB_PRE_OPERATION_INFORMATION info)
{
    // Do nothing about kernel handles (for now)
    if (!info || info->KernelHandle)
        return OB_PREOP_SUCCESS;

    PEPROCESS process;
    ACCESS_MASK denied_access;

    // Ignore everything but handle operations for processes/threads
    if (info->ObjectType == *PsProcessType)
    {
        process = ( PEPROCESS )info->Object;
        denied_access = PROCESS_DENIED_ACCESS_MASK;
    }
    else if (info->ObjectType == *PsThreadType)
    {
        process = PsGetThreadProcess(( PETHREAD )info->Object);
        denied_access = THREAD_DENIED_ACCESS_MASK;
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    // Filter operations unrelated to our process
    if (process != g_target)
        return OB_PREOP_SUCCESS;

    // Filter operations from the target process
    if (PsGetCurrentProcess() == g_target)
        return OB_PREOP_SUCCESS;

    if (info->Operation == OB_OPERATION_HANDLE_CREATE)
        ClearFlag(info->Parameters->CreateHandleInformation.DesiredAccess, denied_access);
    else // OB_OPERATION_HANDLE_DUPLICATE:
        ClearFlag(info->Parameters->DuplicateHandleInformation.DesiredAccess, denied_access);

    return OB_PREOP_SUCCESS;
}

CODE_SEG("PAGE") INTERNAL FORCEINLINE NTSTATUS
FinalizeIrp(_In_ PIRP irp, _In_ ULONG_PTR info)
{
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
// Dispatch routines
//

CODE_SEG("PAGE") INTERNAL NTSTATUS
DispatchGeneric(_In_ PDEVICE_OBJECT device, _In_ PIRP irp)
{
    PAGED_CODE();

    // Common stub for major functions we don't handle
    // Call the generic completion routine and leave

    return FinalizeIrp(irp, 0);
}

CODE_SEG("PAGE") INTERNAL NTSTATUS
DispatchIoctl(PDEVICE_OBJECT device, PIRP irp)
{
    PAGED_CODE();

    ULONG_PTR io_size = 0;

    // Block other processes from sending IOCTLs after target process has been initialized
    if (IoGetRequestorProcess(irp) != g_target)
        return FinalizeIrp(irp, io_size);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    io_size = max(
        stack->Parameters.DeviceIoControl.InputBufferLength,
        stack->Parameters.DeviceIoControl.OutputBufferLength
    );

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_PROTECT_REQUEST:
    {
        LOG_INFO("Received IOCTL_PROTECT_REQUEST");

        KProtectRequest* request = irp->AssociatedIrp.SystemBuffer;
        request->result = PsLookupProcessByProcessId(UlongToHandle(request->pid), &g_target);
        if (NT_SUCCESS(request->result))
            LOG_SUCCESS("Set target process to PID %u", request->pid);
        else
            LOG_ERROR("Couldn't find process associated with PID %u", request->pid);
        break;
    }
    default:
        break;
    }

    return FinalizeIrp(irp, io_size);
}

CODE_SEG("PAGE") INTERNAL VOID
DriverUnload(PDRIVER_OBJECT driver)
{
    PAGED_CODE();

    LOG_INFO("Unloading driver...");

    g_running = FALSE;

    if (g_target)
        ObDereferenceObject(g_target);

    if (g_device)
        IoDeleteDevice(g_device);

    if (g_thread_callback)
        PsRemoveCreateThreadNotifyRoutine(ThreadCreationCallback);

    if (g_image_load_callback)
        PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);

    if (g_handle_cookie)
        ObUnRegisterCallbacks(g_handle_cookie);
}

CODE_SEG("INIT") NTSTATUS
DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path)
{
    LOG_INFO("Driver started!");

    g_running = TRUE;

    driver->DriverUnload = DriverUnload;
    driver->MajorFunction[IRP_MJ_CREATE] = DispatchGeneric;
    driver->MajorFunction[IRP_MJ_CLOSE] = DispatchGeneric;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, L"\\Device\\ACDriver");
    NTSTATUS status = IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &g_device);
    if (NT_SUCCESS(status))
    {
        LOG_SUCCESS("Created device object");
        g_driver = g_device->DriverObject;
        SetFlag(g_device->Flags, DO_BUFFERED_IO);
        ClearFlag(g_device->Flags, DO_DEVICE_INITIALIZING);
    }
    else
    {
        LOG_ERROR("Couldn't create device object");
    }

    RTL_OSVERSIONINFOW version;
    version.dwOSVersionInfoSize = sizeof(version);
    status = RtlGetVersion(&version);
    if (NT_SUCCESS(status))
    {
        LOG_INFO("Running on Windows %lu.%lu (%lu)", version.dwMajorVersion,
            version.dwMinorVersion, version.dwBuildNumber);
    }

    status = PsSetCreateThreadNotifyRoutine(ThreadCreationCallback);
    if (NT_SUCCESS(status))
    {
        g_thread_callback = TRUE;
        LOG_SUCCESS("Registered thread creation callback");
    }
    else
    {
        LOG_ERROR("Couldn't register thread creation callback");
    }

    if (NT_SUCCESS(PsSetLoadImageNotifyRoutine(ImageLoadCallback)))
    {
        g_image_load_callback = TRUE;
        LOG_SUCCESS("Registered image load callback");
    }
    else
    {
        LOG_ERROR("Couldn't register image load callback");
    }

    if (ObGetFilterVersion() >= OB_FLT_REGISTRATION_VERSION)
    {
        OB_CALLBACK_REGISTRATION callback_reg;
        callback_reg.Version = OB_FLT_REGISTRATION_VERSION;
        callback_reg.OperationRegistrationCount = 1;
        RtlInitUnicodeString(&callback_reg.Altitude, L"329410");
        callback_reg.RegistrationContext = NULL;

        OB_OPERATION_REGISTRATION op_reg[1];
        op_reg[0].ObjectType = PsProcessType;
        op_reg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        op_reg[0].PreOperation = HandlePreOperationCallback;
        op_reg[0].PostOperation = NULL;

        callback_reg.OperationRegistration = op_reg;

        status = ObRegisterCallbacks(&callback_reg, &g_handle_cookie);
        if (NT_SUCCESS(status))
            LOG_SUCCESS("Registered handle operation callback");
        else
            LOG_ERROR("Couldn't register handle operation callback");
    }

    return status;
}

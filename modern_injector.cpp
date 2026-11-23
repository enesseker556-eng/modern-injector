#pragma warning(push)
#pragma warning(disable: 2059)
#pragma warning(disable: 2238)
#pragma warning(disable: 2143)
#pragma warning(disable: 4616)
#pragma warning(disable: 4214)
#pragma warning(disable: 4201)
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#pragma warning(pop)

#define DEVICE_NAME     L"\\Device\\ModernInjector"
#define SYMLINK_NAME    L"\\DosDevices\\ModernInjector"
#define IOCTL_INJECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define POOL_TAG        'DLLX'
#define MAX_DLL_SIZE    (32 * 1024 * 1024) // 32 MB güvenlik ust siniri

typedef struct {
    ULONG TargetPid;
    WCHAR DllPath[260];
} InjectionRequest;

static const UCHAR XOR_KEY = 0x5A;
static BOOLEAN g_UseXor = FALSE; // Diskteki DLL XOR sifreliyse TRUE yap

void XorBuffer(PUCHAR buffer, SIZE_T size, UCHAR key) {
    for (SIZE_T i = 0; i < size; i++) {
        buffer[i] ^= key;
    }
}

NTSTATUS BuildNtFilePath(const WCHAR* userPath, UNICODE_STRING* outNtPath) {
    RtlInitEmptyUnicodeString(outNtPath, NULL, 0);

    WCHAR fullPath[300] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    // Kullanici "C:\..." gonderirse "\??\C:\..." formatina cevir
    if (userPath[0] != L'\0' && userPath[1] == L':') {
        status = RtlStringCbPrintfW(fullPath, sizeof(fullPath), L"\\??\\%ws", userPath);
    }
    else {
        status = RtlStringCbPrintfW(fullPath, sizeof(fullPath), L"%ws", userPath);
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }

    SIZE_T charCount = wcslen(fullPath);
    USHORT byteLen = (USHORT)(charCount * sizeof(WCHAR));
    PWCHAR buf = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, byteLen + sizeof(WCHAR), POOL_TAG);
    if (!buf) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(buf, fullPath, byteLen + sizeof(WCHAR));
    outNtPath->Buffer = buf;
    outNtPath->Length = byteLen;
    outNtPath->MaximumLength = byteLen + sizeof(WCHAR);
    return STATUS_SUCCESS;
}

NTSTATUS ValidateAndInspectPe(PUCHAR dllData, SIZE_T dllSize) {
    if (!dllData || dllSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        KdPrint(("ModernInjector: Invalid DOS signature\n"));
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (dosHeader->e_lfanew < 0 ||
        (SIZE_T)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > dllSize) {
        KdPrint(("ModernInjector: Invalid e_lfanew offset\n"));
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)(dllData + dosHeader->e_lfanew);
    if (ntHeaders64->Signature != IMAGE_NT_SIGNATURE) {
        KdPrint(("ModernInjector: Invalid NT signature\n"));
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    KdPrint(("ModernInjector: Valid PE detected. ImageBase=0x%llX, EntryPoint=0x%X, Sections=%u\n",
        ntHeaders64->OptionalHeader.ImageBase,
        ntHeaders64->OptionalHeader.AddressOfEntryPoint,
        ntHeaders64->FileHeader.NumberOfSections));

    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION irpStack;
    NTSTATUS status;
    ULONG_PTR bytesReturned;
    ULONG inLen;
    InjectionRequest* request;
    PEPROCESS targetProcess;
    UNICODE_STRING ntPath;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    FILE_STANDARD_INFORMATION fileInfo;
    SIZE_T dllSize;
    PUCHAR dllData;

    irpStack = IoGetCurrentIrpStackLocation(irp);
    status = STATUS_INVALID_DEVICE_REQUEST;
    bytesReturned = 0;

    if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_INJECT_DLL) {
        inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
        request = (InjectionRequest*)irp->AssociatedIrp.SystemBuffer;

        if (!request || inLen < sizeof(InjectionRequest)) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Cleanup;
        }

        request->DllPath[RTL_NUMBER_OF(request->DllPath) - 1] = L'\0';
        if (request->TargetPid == 0 || request->DllPath[0] == L'\0') {
            status = STATUS_INVALID_PARAMETER;
            goto Cleanup;
        }

        targetProcess = NULL;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->TargetPid, &targetProcess);
        if (!NT_SUCCESS(status)) {
            KdPrint(("ModernInjector: Failed to find PID %u (0x%X)\n", request->TargetPid, status));
            goto Cleanup;
        }

        status = BuildNtFilePath(request->DllPath, &ntPath);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(targetProcess);
            goto Cleanup;
        }

        InitializeObjectAttributes(&objAttr, &ntPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        fileHandle = NULL;
        ioStatus.Information = 0;
        ioStatus.Status = 0;
        status = ZwCreateFile(
            &fileHandle,
            GENERIC_READ,
            &objAttr,
            &ioStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        ExFreePool(ntPath.Buffer);

        if (!NT_SUCCESS(status)) {
            KdPrint(("ModernInjector: ZwCreateFile failed (0x%X)\n", status));
            ObDereferenceObject(targetProcess);
            goto Cleanup;
        }
        memset(&fileInfo, 0, sizeof(fileInfo));
        status = ZwQueryInformationFile(fileHandle, &ioStatus, &fileInfo, sizeof(fileInfo), FileStandardInformation);
        if (!NT_SUCCESS(status) || fileInfo.EndOfFile.QuadPart <= 0 ||
            (ULONGLONG)fileInfo.EndOfFile.QuadPart > MAX_DLL_SIZE) {
            KdPrint(("ModernInjector: Invalid file size or query failed (0x%X)\n", status));
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            goto Cleanup;
        }

        dllSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;
        dllData = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, dllSize, POOL_TAG);
        if (!dllData) {
            ZwClose(fileHandle);
            ObDereferenceObject(targetProcess);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus, dllData, (ULONG)dllSize, NULL, NULL);
        ZwClose(fileHandle);

        if (NT_SUCCESS(status)) {
            if (g_UseXor) {
                XorBuffer(dllData, dllSize, XOR_KEY);
            }
            status = ValidateAndInspectPe(dllData, dllSize);
        }

        ExFreePool(dllData);
        ObDereferenceObject(targetProcess);
    }

Cleanup:
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

void DriverUnload_Handler(PDRIVER_OBJECT drvObj) {
    UNICODE_STRING symLinkLocal;
    RtlInitUnicodeString(&symLinkLocal, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLinkLocal);
    if (drvObj->DeviceObject) {
        IoDeleteDevice(drvObj->DeviceObject);
    }
    KdPrint(("ModernInjector unloaded\n"));
}

NTSTATUS IrpCreateClose_Handler(PDEVICE_OBJECT DevObj, PIRP irp) {
    UNREFERENCED_PARAMETER(DevObj);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);

    UNICODE_STRING deviceName, symLink;
    PDEVICE_OBJECT deviceObject = NULL;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    NTSTATUS status = IoCreateDevice(driverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateClose_Handler;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateClose_Handler;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    driverObject->DriverUnload = DriverUnload_Handler;

    KdPrint(("ModernInjector loaded\n"));
    return STATUS_SUCCESS;
}
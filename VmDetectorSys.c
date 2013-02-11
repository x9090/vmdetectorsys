#include "VmDetectorSys.h"

#define MAX_PATH 256

/*
	VmDetectorSys - Main file
	This file contains a very simple implementation of a WDM driver. Note that it does not support all
	WDM functionality, or any functionality sufficient for practical use. The only thing this driver does
	perfectly, is loading and unloading.

	To install the driver, go to Control Panel -> Add Hardware Wizard, then select "Add a new hardware device".
	Select "manually select from list", choose device category, press "Have Disk" and enter the path to your
	INF file.
	Note that not all device types (specified as Class in INF file) can be installed that way.

	To start/stop this driver, use Windows Device Manager (enable/disable device command).

	If you want to speed up your driver development, it is recommended to see the BazisLib library, that
	contains convenient classes for standard device types, as well as a more powerful version of the driver
	wizard. To get information about BazisLib, see its website:
		http://bazislib.sysprogs.org/
*/

void	 SetDebugBreak();
void	 VmDetectorSysUnload(IN PDRIVER_OBJECT DriverObject);
BOOLEAN	 VmDetectorPatchStorageProperty();
BOOLEAN  VmDetectorPatchVmDiskReg();
NTSTATUS VmDetectorSysDispatchIOControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS VmDetectorSysCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS VmDetectorSysDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS VmDetectorSysAddDevice(IN PDRIVER_OBJECT  DriverObject, IN PDEVICE_OBJECT  PhysicalDeviceObject);
NTSTATUS VmDetectorSysPnP(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

typedef struct _deviceExtension
{
	PDEVICE_OBJECT DeviceObject;
	PDEVICE_OBJECT TargetDeviceObject;
	PDEVICE_OBJECT PhysicalDeviceObject;
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymlinkName;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// {3e58af2a-ce92-42f1-a508-7290a9408b66}
static const GUID GUID_VmDetectorSysInterface = {0x3E58AF2A, 0xce92, 0x42f1, {0xa5, 0x8, 0x72, 0x90, 0xa9, 0x40, 0x8b, 0x66 } };

#ifdef __cplusplus
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath);
#endif

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	unsigned i;
	NTSTATUS			status;
	PDEVICE_OBJECT		DeviceObject;
	PDEVICE_EXTENSION	pDeviceExtension;
	UNICODE_STRING		usDevName;
	UNICODE_STRING		usSymlinkName;
	BOOLEAN				bFix;

	DbgPrint("[DriverEntry] Called DriverEntry!\n");
	
	// Initialize driver's device name
	RtlInitUnicodeString(&usDevName, SYS_DEVICE_NAME);

	// Create driver's device object
	status = IoCreateDevice(
		DriverObject, 
		sizeof(DEVICE_EXTENSION), 
		&usDevName, 
		FILE_DEVICE_UNKNOWN, 
		FILE_DEVICE_SECURE_OPEN, FALSE,
		&DeviceObject);

	// Determine if the device object created successfully
	if (!NT_SUCCESS(status)){
		DbgPrint("[DriverEntry] Failed to create device object.\n");
		return status;
	}

	// Set the device's flag
	DeviceObject->Flags |= DO_DIRECT_IO;

	// Get device extension
	pDeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	// Set the device object extension's device object
	pDeviceExtension->DeviceObject = DeviceObject;

	// Set the device object extension's device name
	pDeviceExtension->usDeviceName = usDevName;

	// Create symbolic link
	RtlInitUnicodeString(&usSymlinkName, SYS_SYMBOL_NAME);
	pDeviceExtension->usSymlinkName = usSymlinkName;
	status = IoCreateSymbolicLink(&usSymlinkName, &usDevName);

	// Determine if symbolic link created successfully
	if (!NT_SUCCESS(status)){
		DbgPrint("[DriverEntry] Failed to create symbolic link.\n");
		IoDeleteDevice(DeviceObject);
		return status;
	}


	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = 0;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = VmDetectorSysCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = VmDetectorSysCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VmDetectorSysDispatchIOControl;

	DriverObject->DriverUnload = VmDetectorSysUnload;
	DriverObject->DriverStartIo = NULL;

	//bFix = VmDetectorPatchVmDiskReg();

	return STATUS_SUCCESS;
}

void VmDetectorSysUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING usSymbolicName;
	PDEVICE_EXTENSION DeviceExtension;

	DbgPrint("[DriverUnload] Called DriverUnload\n");

	DeviceExtension = DriverObject->DeviceObject->DeviceExtension;

	usSymbolicName = DeviceExtension->usSymlinkName;

	// Delete the symbolic name
	IoDeleteSymbolicLink(&usSymbolicName);

	// Delete the device object
	IoDeleteDevice(DeviceExtension->DeviceObject);
}

NTSTATUS VmDetectorSysCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS VmDetectorSysDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PDEVICE_EXTENSION deviceExtension = NULL;
	
	IoSkipCurrentIrpStackLocation(Irp);
	deviceExtension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;
	return IoCallDriver(deviceExtension->TargetDeviceObject, Irp);
}


NTSTATUS VmDetectorSysIrpCompletion(
					  IN PDEVICE_OBJECT DeviceObject,
					  IN PIRP Irp,
					  IN PVOID Context
					  )
{
	PKEVENT Event = (PKEVENT) Context;

	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

	return(STATUS_MORE_PROCESSING_REQUIRED);
}

NTSTATUS VmDetectorSysDispatchIOControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION pIoCurrentStack;
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN bResult;
	int dwOutputBufferLength;
	int dwInputBufferLength;
	ULONG info = 0;
	PCHAR pBuf=NULL;
	PCHAR pFileNameBuf=NULL;
	bResult = FALSE;

	KdPrint(("[DBG] VmDetectorSysDispatchIOControl => called.\n"));

	pIoCurrentStack = IoGetCurrentIrpStackLocation(Irp);

	dwInputBufferLength  = pIoCurrentStack->Parameters.DeviceIoControl.InputBufferLength;
	dwOutputBufferLength = pIoCurrentStack->Parameters.DeviceIoControl.OutputBufferLength;

	// Irp->MdlAddress is an output buffer address
	if (Irp->MdlAddress)
	{
		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => user address: 0x%08x\n", MmGetMdlVirtualAddress(Irp->MdlAddress)));
		pBuf = (PCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	}

	switch(pIoCurrentStack->Parameters.DeviceIoControl.IoControlCode)
	{

	case IOCTL_VMDETECTORSYS_DEVMODEL_FIX:

		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => IOCTL_VMDETECTORSYS_DEVMODEL_FIX control code executed\n"));
		bResult = VmDetectorPatchStorageProperty();
		if (bResult && dwOutputBufferLength == sizeof(dwOutputBufferLength))
			*pBuf = bResult;
		info = dwOutputBufferLength;
		break;

	case IOCTL_VMDETECTORSYS_VMDISKREG_FIX:

		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => IOCTL_VMDETECTORSYS_VMDISKREG_FIX control code executed\n"));
		bResult = VmDetectorPatchVmDiskReg();
		if (bResult && dwOutputBufferLength == sizeof(dwOutputBufferLength))
			*pBuf = bResult;
		info = dwOutputBufferLength;
		break;

	// Initialize hook to RDTSC interrupt handler
	case IOCTL_VMDETECTORSYS_RTDSC_HOOK:

		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => IOCTL_VMDETECTORSYS_RTDSC_HOOK control code executed\n"));
		bResult = RDTSEMU_initializeHooks(g_ullRdtscValue, g_ulRdtscValue, g_bRtdscMethodIncreasing, g_tempexclusionfilelist, g_countfilename);
		if (bResult && dwOutputBufferLength == sizeof(dwOutputBufferLength))
			*pBuf = bResult;
		info = dwOutputBufferLength;
		break;

	// Set constant value to RDTSC
	case IOCTL_RDTSCEMU_METHOD_ALWAYS_CONST:

		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => IOCTL_RDTSCEMU_METHOD_ALWAYS_CONST control code executed\n"));
		if (dwInputBufferLength == sizeof(ULONG))
		{
			g_bRtdscMethodIncreasing = FALSE;
			g_ulRdtscValue = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
		}
		else 
			status = STATUS_INVALID_PARAMETER;
		info = dwInputBufferLength;
		break;

	// Set delta value to RDTSC
	case IOCTL_RDTSCEMU_METHOD_INCREASING:

		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => IOCTL_RDTSCEMU_METHOD_INCREASING control code executed\n"));
		if (dwInputBufferLength == sizeof(ULONG))
		{
			__asm
			{
				push	eax
				push	ecx
				push	edx
				rdtsc
				lea		ecx, g_ullRdtscValue
				mov		dword ptr [ecx], eax
				mov		dword ptr [ecx+4], edx
				pop		edx
				pop		ecx
				pop		eax
			}
			// set delta
			g_ulRdtscValue = *(PULONG)(Irp->AssociatedIrp.SystemBuffer);
			g_bRtdscMethodIncreasing = TRUE;
		}
		else 
			status = STATUS_INVALID_PARAMETER;
		info = dwInputBufferLength;
		break;

	// Get the number of exclusion file names
	case IOCTL_VMDETECTORSYS_SEND_COUNT_FN:
		
		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => IOCTL_VMDETECTORSYS_SEND_COUNT_FN control code executed\n"));
		g_countfilename = *(int*)Irp->AssociatedIrp.SystemBuffer;
		if (g_countfilename < 0)
			KdPrint(("[DBG] VmDetectorSysDispatchIOControl => IOCTL_VMDETECTORSYS_SEND_COUNT_FN - g_countfilename count 0?\n"));
		else
		{
			g_exclusionfilelist = (PCHAR*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PCHAR)*g_countfilename, 'vmde');
			g_tempexclusionfilelist = g_exclusionfilelist;
		}
		info = dwInputBufferLength;
		break;

	// Get list of exclusion file names from vmdetector.ini
	case IOCTL_VMDETECTORSYS_SEND_FN_EXCLUSION:

		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => IOCTL_VMDETECTORSYS_SEND_FN_EXCLUSION control code executed\n"));
		pFileNameBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("[IOCTL_VMDETECTORSYS_SEND_FN_EXCLUSION] Exclusion file name: %s\n", pFileNameBuf);
		if (strlen(pFileNameBuf) >= (size_t)dwInputBufferLength)
		{	
			PCHAR pBuf = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, dwInputBufferLength+1, 'vmde'); // Include terminating null character
			RtlZeroMemory(pBuf, dwInputBufferLength+1);
			RtlCopyMemory(pBuf, pFileNameBuf, dwInputBufferLength);
			*g_exclusionfilelist = pBuf;
			g_exclusionfilelist++;
		}
		info = dwInputBufferLength;
		break;

	default:
		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => Invalid control code\n"));
		status = STATUS_INVALID_PARAMETER;
	}

	// Important to set the Status
	Irp->IoStatus.Status = status;

	// Important to set the Information
	Irp->IoStatus.Information = info;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

BOOLEAN VmDetectorPatchStorageProperty()
{
	PCHAR				pVendorId;
	PDEVICE_OBJECT		pDevObj;
	PFILE_OBJECT		DR0_FileObject;
	PDEVICE_OBJECT		DR0_DeviceObject;
	UNICODE_STRING		DR0_DeviceName; 
	UNICODE_STRING		FltDrvName;
	WCHAR				wFltDriverName[MAX_PATH*2] = {0};
	WCHAR				*wDr0DevName=L"\\Device\\Harddisk0\\DR0";


	// Get the lowest device object (ATAPI) from DR0 devstack
	RtlInitUnicodeString(&DR0_DeviceName, wDr0DevName);

	// Get DR0 device object
	IoGetDeviceObjectPointer(&DR0_DeviceName, FILE_READ_ATTRIBUTES, &DR0_FileObject, &DR0_DeviceObject);
	DR0_DeviceObject = DR0_FileObject->DeviceObject;

	// Get lowest device object (ATAPI/SCSI)
	pDevObj = IoGetDeviceAttachmentBaseRef(DR0_FileObject->DeviceObject);

	pVendorId = (PCHAR)pDevObj->DeviceExtension;

	FltDrvName = pDevObj->DriverObject->DriverName;

	memcpy(wFltDriverName, FltDrvName.Buffer, FltDrvName.Length);

	KdPrint(("[DBG] VmDetectorPatchStorageProperty => Filter driver name %ws\n", wFltDriverName));

	
	// ATAPI: atapi!DevObject->DeviceExtension + 0xD1
	// SCSI: vmscsi!DevObject->DeviceExtension + 0x126
	if (wcscmp(_wcslwr(wFltDriverName), L"\\driver\\atapi") == 0)
		pVendorId = (PCHAR)pVendorId+0xD1;
	else if (wcscmp(_wcslwr(wFltDriverName), L"\\driver\\vmscsi") == 0)
		pVendorId = (PCHAR)pVendorId+0x126;

	KdPrint(("[DBG] VmDetectorPatchStorageProperty => Lowest device object of DR0 0x%08X\n", pDevObj));
	KdPrint(("[DBG] VmDetectorPatchStorageProperty => Device Model: %s\n", pVendorId));

	if(strcmp(pVendorId, "VMware Virtual IDE Hard Drive") == 0)
	{
		memcpy(pVendorId, "VMw@re Virtu@l IDE H@rd Driv3", 29);
		memcpy(pVendorId+31, "__________", 10);
		memcpy(pVendorId+42, "12345678", 8);
		memcpy(pVendorId+51, "01234567890123456789012345678901234678", 38);
		ObDereferenceObject(pDevObj);
		ObDereferenceObject(DR0_FileObject);
		return TRUE;
	}
	else if(strstr(pVendorId, "VMware, VMware Virtual") != NULL)
	{
		strncpy(pVendorId, "VMw@re, VMw@re Virtu@l", 22);
		ObDereferenceObject(pDevObj);
		ObDereferenceObject(DR0_FileObject);
		return TRUE;
	}

	ObDereferenceObject(pDevObj);
	ObDereferenceObject(DR0_FileObject);

	return FALSE;
}

BOOLEAN VmDetectorPatchVmDiskReg()
{
	PKEY_VALUE_FULL_INFORMATION pvfi;
	OBJECT_ATTRIBUTES	oaRegistryKey;
	OBJECT_ATTRIBUTES	oaValueName;
	UNICODE_STRING		usRegistryKey;
	UNICODE_STRING		usValueName;
	WCHAR		*wStrNewData = L"IDE\\DiskVMw@re_Virtu@l_ID3_H@rd_Driv3___________0123456789\\0123456789012345678901234567890123456789";
	NTSTATUS	status;
	HANDLE		hKey;
	ULONG		ulSize;

	DbgPrint("Called VmDetectorPatchVmDiskReg\n");

	RtlInitUnicodeString(&usRegistryKey, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum");
	RtlInitUnicodeString(&usValueName, L"0");

	InitializeObjectAttributes(&oaRegistryKey, &usRegistryKey, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL );
	InitializeObjectAttributes(&oaValueName, &usValueName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenKey(&hKey, KEY_READ, &oaRegistryKey);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[VmDetectorPatchVmDiskReg] Error ZwOpenKey %#x\n", status);
		return FALSE;
	}

	KdPrint(("[VmDetectorPatchVmDiskReg] Open key successfully!\n"));

	status = ZwQueryValueKey(
		hKey,
		&usValueName,
		KeyValueFullInformation,
		NULL,
		0,
		&ulSize);

	if (status == STATUS_BUFFER_TOO_SMALL)
	{
		pvfi = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulSize, 'vmd');

		status = ZwQueryValueKey(
			hKey,
			&usValueName,
			KeyFullInformation,
			pvfi,
			ulSize,
			&ulSize);
	}

	if (!NT_SUCCESS(status))
	{	
		DbgPrint("[VmDetectorPatchVmDiskReg] Error ZwQueryValueKey %#x\n", status);
		return FALSE;
	}

	KdPrint(("[VmDetectorPatchVmDiskReg] Query key successfully!\n"));

	if (wcsstr(pvfi->Name, L"VMware"))
	{
		status = ZwSetValueKey(
			hKey,
			&usValueName,
			0,
			REG_SZ,
			wStrNewData,
			wcslen(wStrNewData)*2+2);

		if (!NT_SUCCESS(status))
		{	
			DbgPrint("[VmDetectorPatchVmDiskReg] Error ZwSetValueKey %#x\n", status);
			return FALSE;
		}

		KdPrint(("[VmDetectorPatchVmDiskReg] ZwSetValueKey successfully!\n"));
		ExFreePoolWithTag(pvfi, 'vmd');
		ZwClose(hKey);
		return TRUE;
	}

	ExFreePoolWithTag(pvfi, 'vmd');
	ZwClose(hKey);
	return FALSE;
}

VOID SetDebugBreak()
{
	if (DEBUG)
	{
		__asm {
			int 3
		}
	}
}
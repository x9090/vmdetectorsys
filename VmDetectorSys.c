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

VOID	 SetDebugBreak();
VOID	 VmDetectorSysUnload(IN PDRIVER_OBJECT DriverObject);
VOID     VMDetectorRenameKey();
BOOLEAN  VmDetectorPatchScsiSymLink();
BOOLEAN	 VmDetectorPatchStorageProperty();
BOOLEAN  VmDetectorPatchVmDiskReg();
BOOLEAN  VmDetectorPatchVmKernelModulesName(IN PDRIVER_OBJECT DriverObject);
NTSTATUS VmDetectorSysDispatchIOControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS VmDetectorSysCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS VmDetectorSysDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS VmDetectorSysAddDevice(IN PDRIVER_OBJECT  DriverObject, IN PDEVICE_OBJECT  PhysicalDeviceObject);
NTSTATUS VmDetectorSysPnP(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

// Undocumented native APIs
ZWQUERYDIRECTORYOBJECT ZwQueryDirectoryObject = NULL;
ZWOPENDIRECTORYOBJECT ZwOpenDirectoryObject = NULL;
ZWRENAMEKEY _ZwRenameKey = NULL;

// Device extension specific to the driver
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

BOOLEAN ResolveNativeAPIs()
{
	// Initialize necessary native APIs

	if (ZwQueryDirectoryObject == NULL)
	{
		UNICODE_STRING routineName;

		RtlInitUnicodeString(&routineName, L"ZwQueryDirectoryObject");
		ZwQueryDirectoryObject = (ZWQUERYDIRECTORYOBJECT)MmGetSystemRoutineAddress(&routineName);

		if (ZwQueryDirectoryObject == NULL)
			return FALSE;
	}

	if (ZwOpenDirectoryObject == NULL)
	{
		UNICODE_STRING routineName;

		RtlInitUnicodeString(&routineName, L"ZwOpenDirectoryObject");
		ZwOpenDirectoryObject = (ZWOPENDIRECTORYOBJECT)MmGetSystemRoutineAddress(&routineName);

		if (ZwOpenDirectoryObject == NULL)
			return FALSE;
	}

	if (_ZwRenameKey == NULL)
	{
		// TODO: Ugly hack :(
		//       It is not possible to export the function using handy MmGetSystemRoutineAddress
		if (g_OsMajorVersion == 6 && g_OsMinorVersion == 1)
			_ZwRenameKey = (ZWRENAMEKEY)SYSTEMSERVICE(SYSCALL_ZWRENAMEKEY_WIN7);

		if (_ZwRenameKey == NULL)
			return FALSE;
	}

	return TRUE;
}

VOID GetOSVersion ()
/*++

Reference: sfilter

Routine Description:

    This routine reads the current OS version using the correct routine based
    on what routine is available.

Arguments:

    None.
    
Return Value:

    None.

--*/
{
	UNICODE_STRING functionName;
	RTLGETVERSION RtlGetVersion;

	RtlInitUnicodeString( &functionName, L"RtlGetVersion" );

	RtlGetVersion = (RTLGETVERSION)MmGetSystemRoutineAddress( &functionName );

    if (NULL != RtlGetVersion) {

        RTL_OSVERSIONINFOW versionInfo;
        NTSTATUS status;

        //
        //  VERSION NOTE: RtlGetVersion does a bit more than we need, but
        //  we are using it if it is available to show how to use it.  It
        //  is available on Windows XP and later.  RtlGetVersion and
        //  RtlVerifyVersionInfo (both documented in the IFS Kit docs) allow
        //  you to make correct choices when you need to change logic based
        //  on the current OS executing your code.
        //

        versionInfo.dwOSVersionInfoSize = sizeof( RTL_OSVERSIONINFOW );

        status = RtlGetVersion( &versionInfo );

        ASSERT( NT_SUCCESS( status ) );

        g_OsMajorVersion = versionInfo.dwMajorVersion;
        g_OsMinorVersion = versionInfo.dwMinorVersion;
	}

	return;     
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	unsigned i;
	NTSTATUS			status = STATUS_FAILED_DRIVER_ENTRY;
	PDEVICE_OBJECT		DeviceObject;
	PDEVICE_EXTENSION	pDeviceExtension;
	UNICODE_STRING		usDevName;
	UNICODE_STRING		usSymlinkName;
	BOOLEAN				bFix;

	// Get OS version first
	GetOSVersion();

	DbgPrint("[DriverEntry] Called DriverEntry. Platform=%d.%d\n", g_OsMajorVersion, g_OsMinorVersion);

	if (!ResolveNativeAPIs())
	{
		DbgPrint("[%s] Failed in resolving neccessary native APIs\n", __FUNCTION__);
		return status;
	}

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

	// Test function prototypes here
	//bFix = VmDetectorPatchVmDiskReg();

	// Always do VMware kernel module name patching
	bFix = VmDetectorPatchVmKernelModulesName(DriverObject);

	// Always do VM-identifiable registry keys which
	// cannot be tackled from UM
	// TODO: it might be more elegant to implement CmRegistryCallback
	VMDetectorRenameKey();

	return STATUS_SUCCESS;
}

VOID VmDetectorSysUnload(IN PDRIVER_OBJECT DriverObject)
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

	case IOCTL_VMDETECTORSYS_SCSI_FIX:

		KdPrint(("[DBG] VmDetectorSysDispatchIOControl => IOCTL_VMDETECTORSYS_SCSI_FIX control code executed\n"));
		bResult = VmDetectorPatchScsiSymLink();
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
			g_exclusionfilelist = (PCHAR*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PCHAR)*g_countfilename, SYS_TAG);
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
			PCHAR pBuf = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, dwInputBufferLength+1, SYS_TAG); // Include terminating null character
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

/*
*	Purpose: Rename VBOX PCI key to bypass pafish's vbox_wmi_check_row check
*            example:
*			 * HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE&DEV_CAFE&SUBSYS_00000000&REV_00\3&267a616a&0&20
*			 * HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE&DEV_BEEF&SUBSYS_00000000&REV_00\3&267a616a&0&10
*/
VOID VMDetectorRenameKey()
{
	INT index = 0;
	WCHAR *szListKeys[] = {
		L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE&DEV_CAFE&SUBSYS_00000000&REV_00",
		L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE&DEV_BEEF&SUBSYS_00000000&REV_00",
		NULL
	};


	do
	{
		UNICODE_STRING usRegistryKey;
		OBJECT_ATTRIBUTES oaRegistryKey;
		UNICODE_STRING usNewRegKey;
		NTSTATUS status;
		HANDLE hKey;
		USHORT KeyLength;

		RtlInitUnicodeString(&usRegistryKey, szListKeys[index]);
		InitializeObjectAttributes(&oaRegistryKey, &usRegistryKey, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oaRegistryKey);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[%s] Failed ZwOpenKey %wZ, %#x\n", __FUNCTION__, &usRegistryKey, status));
			break;
		}

		DbgBreakPoint();
		KdPrint(("[%s] Open \"%wZ\" successfully!\n", __FUNCTION__, &usRegistryKey));

		// Initialize the new registry key name
		KeyLength = (USHORT)wcslen(szListKeys[index]);
		usNewRegKey.Length = KeyLength*sizeof(WCHAR);
		usNewRegKey.MaximumLength = (KeyLength + 1)*sizeof(WCHAR);
		usNewRegKey.Buffer = ExAllocatePoolWithTag(NonPagedPool, usNewRegKey.MaximumLength, SYS_TAG);
		if (usNewRegKey.Buffer == NULL)
			break;
		RtlSecureZeroMemory(usNewRegKey.Buffer, usNewRegKey.MaximumLength);

		// Set new registry key specifically
		switch (index)
		{
		case 0:
			RtlStringCchCopyW(usNewRegKey.Buffer, KeyLength + 1, L"VEN_80EE&DEV_C@FE&SUBSYS_00000000&REV_00");
			break;
		case 1:
			RtlStringCchCopyW(usNewRegKey.Buffer, KeyLength + 1, L"VEN_80EE&DEV_B33F&SUBSYS_00000000&REV_00");
			break;
		default:
			break;
		}
		
		// Rename registry key
		if (!NT_SUCCESS((status = _ZwRenameKey(hKey, &usNewRegKey))))
			KdPrint(("[%s] Failed ZwRenameKey \"%wZ\", %#x\n", __FUNCTION__, &usNewRegKey, status));
		else
		{
			KdPrint(("[%s] Renamed key \"%wZ\"!\n", __FUNCTION__, &usNewRegKey));
			ZwFlushKey(hKey);
		}

		ExFreePoolWithTag(usNewRegKey.Buffer, SYS_TAG);
		ZwClose(hKey);
		index++;
	} while (szListKeys[index] != NULL);

	return;
}

BOOLEAN VmDetectorPatchScsiSymLink()
{
	BOOLEAN bResult = FALSE;
	UNICODE_STRING usSymLink, usGlobal;
	OBJECT_ATTRIBUTES oaSymLink, oaGlobal;
	HANDLE DirectoryHandle = NULL, LinkHandle = NULL;
	POBJECT_DIRECTORY ObjDir = NULL;
	POBJECT_HEADER ObjHeader;
	PWCHAR ObjName;
	POBJECT_HEADER_NAME_INFO  NameInfo;
	POBJECT_DIRECTORY_INFORMATION DirectoryInfo = NULL;
	ULONG Skip, ResultLength;
	NTSTATUS Status;
	BOOLEAN First = TRUE;
	ULONG ScsiType = SCSI_VMWARE;

	DirectoryInfo = ExAllocatePoolWithTag(PagedPool, 1024 * sizeof(WCHAR), SYS_TAG);

	if (DirectoryInfo == NULL)
	{
		return bResult;
	}

	RtlInitUnicodeString(&usGlobal, L"\\Global??");
	InitializeObjectAttributes(&oaGlobal, &usGlobal, OBJ_CASE_INSENSITIVE, NULL, NULL);

	do 
	{
		// VMware symbolic link
		RtlInitUnicodeString(&usSymLink, SCSI_VM_SYMBOL_NAME);
		InitializeObjectAttributes(&oaSymLink, &usSymLink, OBJ_CASE_INSENSITIVE, NULL, NULL);
		Status = ZwOpenSymbolicLinkObject(&LinkHandle, SYMBOLIC_LINK_ALL_ACCESS, &oaSymLink);
		if (NT_SUCCESS(Status))
			ScsiType = SCSI_VMWARE;

		// VBox symbolic link
		if (!LinkHandle)
		{
			RtlInitUnicodeString(&usSymLink, IDE_VBOX_SYMBOL_NAME);
			InitializeObjectAttributes(&oaSymLink, &usSymLink, OBJ_CASE_INSENSITIVE, NULL, NULL);
			Status = ZwOpenSymbolicLinkObject(&LinkHandle, SYMBOLIC_LINK_ALL_ACCESS, &oaSymLink);
			if (NT_SUCCESS(Status))
				ScsiType = SCSI_VBOX;
		}

		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] Cannot find any VMware/VBox symbolic link, status=0x%lx\n", __FUNCTION__, Status));
			break;
		}

		Status = ObReferenceObjectByHandle(LinkHandle, DIRECTORY_ALL_ACCESS, NULL, KernelMode, (PVOID *)&ObjDir, NULL);

		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] Failed to get directory object, status=0x%lx\n", Status));
			break;
		}

		// Get the object header from the object directory
		ObjHeader = OBJECT_TO_OBJECT_HEADER(ObjDir);

		// Get the object name which is located at OBJECT_HEADER - 0x10
		NameInfo = OBJECT_HEADER_TO_NAME_INFO(ObjHeader);
		ObjName = NameInfo->Name.Buffer;

		// Check if the SCSI symbolic name contains VM string
		WCHAR wObjName[MAX_PATH*sizeof(WCHAR)];
		PWCHAR pszScsiSymbolName;

		RtlSecureZeroMemory(wObjName, sizeof(wObjName));
		RtlCopyMemory(wObjName, ObjName, NameInfo->Name.Length);
		pszScsiSymbolName = _wcslwr(wObjName);
		if (ScsiType == SCSI_VMWARE && wcsstr(_wcslwr(pszScsiSymbolName), L"vmware"))
		{ 
			*(ObjName + 11) = '3'; *(ObjName + 17) = '@';
			*(ObjName + 30) = '@'; *(ObjName + 39) = '@';
			*(ObjName + 48) = 'Z'; *(ObjName + 66) = 'F';
			bResult = TRUE;
		}
		else if (ScsiType == SCSI_VBOX && wcsstr(_wcslwr(pszScsiSymbolName), L"vbox"))
		{
			*(ObjName + 10) = '0'; *(ObjName + 48) = 'X';
			bResult = TRUE;
		}

		//Status = ZwOpenDirectoryObject(&DirectoryHandle, SYMBOLIC_LINK_ALL_ACCESS, &oaGlobal);

		//if (!NT_SUCCESS(Status))
		//{
		//	KdPrint(("[%s] ZwOpenDirectoryObject failed, status=%lx\n", __FUNCTION__, Status));
		//	break;
		//}

		//ULONG Count = 0;
		//while (NT_SUCCESS(Status))
		//{
		//	Status = ZwQueryDirectoryObject(DirectoryHandle, DirectoryInfo, 1024 * sizeof(WCHAR), FALSE, First, &Skip, &ResultLength);
		//	First = FALSE;

		//	if (NT_SUCCESS(Status))
		//	{
		//		// TODO: Do something here
		//		PWCHAR SymName;
		//		DirectoryInfo[Count].Name.Buffer[DirectoryInfo[Count].Name.Length / sizeof(WCHAR)] = 0;
		//		SymName = DirectoryInfo[Count].Name.Buffer;
		//	}
		//}

	} while (FALSE);

	if (ObjDir != NULL)
		ObDereferenceObject(ObjDir);
	if (DirectoryHandle != NULL)
		ZwClose(DirectoryHandle);
	if (LinkHandle != NULL)
		ZwClose(LinkHandle);
	if (DirectoryInfo != NULL)
		ExFreePoolWithTag(DirectoryInfo, SYS_TAG);

	return bResult;
}
BOOLEAN VmDetectorPatchStorageProperty()
{
	PCHAR				pVendorIdVbox;
	PCHAR				pVendorId;
	PDEVICE_OBJECT		pDevObj;
	PFILE_OBJECT		DR0_FileObject;
	PDEVICE_OBJECT		DR0_DeviceObject;
	UNICODE_STRING		DR0_DeviceName; 
	UNICODE_STRING		FltDrvName;
	WCHAR				wFltDriverName[MAX_PATH*sizeof(WCHAR)] = {0};
	WCHAR				*wDr0DevName=L"\\Device\\Harddisk0\\DR0";


	// Get the lowest device object (ATAPI) from DR0 devstack
	RtlInitUnicodeString(&DR0_DeviceName, wDr0DevName);

	// Get DR0 device object
	IoGetDeviceObjectPointer(&DR0_DeviceName, FILE_READ_ATTRIBUTES, &DR0_FileObject, &DR0_DeviceObject);
	DR0_DeviceObject = DR0_FileObject->DeviceObject;

	// Get lowest device object (ATAPI/SCSI)
	pDevObj = IoGetDeviceAttachmentBaseRef(DR0_FileObject->DeviceObject);

	pVendorId = (PCHAR)pDevObj->DeviceExtension;
	pVendorIdVbox = pVendorId;

	FltDrvName = pDevObj->DriverObject->DriverName;

	memcpy(wFltDriverName, FltDrvName.Buffer, FltDrvName.Length);

	KdPrint(("[DBG] VmDetectorPatchStorageProperty => Filter driver name %ws\n", wFltDriverName));

	// TODO: Use documented data structure nt!_DEVICE_NODE to get the vendor ID
	// ATAPI: atapi!DevObject->DeviceExtension + 0xD1
	// SCSI: vmscsi!DevObject->DeviceExtension + 0x126
	// LSI_SAS: DevObject->DeviceObjectExtension->DeviceNode (type nt!_DEVICE_NODE contains "InstancePath" field)
	//          The actual driver that is responsible to format and return this data is 
	//          from storport.sys (refer to storport_6.1.7601.17514.idb "RaGetUnitStorageDeviceProperty")
	//			storport!DevObject->DeviceExtension+0x28->0x10
	if (wcscmp(_wcslwr(wFltDriverName), L"\\driver\\atapi") == 0)
	{
		pVendorId = (PCHAR)pVendorId + 0xD1;
		// Otherwise it should be located at VBox offset
		if (strlen(pVendorId) == 0)
			pVendorId = (PCHAR)pVendorIdVbox + 0x2b5;
	}
	else if (wcscmp(_wcslwr(wFltDriverName), L"\\driver\\vmscsi") == 0)
	{
		pVendorId = (PCHAR)pVendorId + 0x126;
	}
	else if (wcscmp(_wcslwr(wFltDriverName), L"\\driver\\lsi_sas") == 0) // Windows 7 VM
	{
		PULONG pDevExtVendorData = NULL;
		pDevExtVendorData = *(PULONG*)((PCHAR)pVendorId + 0x28);
		pVendorId = (PCHAR)pDevExtVendorData + 0x8;
	}

	KdPrint(("[DBG] VmDetectorPatchStorageProperty => Lowest device object of DR0 0x%08X\n", pDevObj));
	KdPrint(("[DBG] VmDetectorPatchStorageProperty => Device Model: %s\n", pVendorId));

	// On Windows XP
	// atapi.sys
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
	else if (strcmp(pVendorId, "VBOX HARDDISK") == 0)
	{
		memcpy(pVendorId, "MYB0X DISKKKK", 13);
		memcpy(pVendorId + 24, "X.0", 3);
		memcpy(pVendorId + 803, "MYB0X DISKKKK", 13);
		memcpy(pVendorId + 827, "X.0", 3);
		ObDereferenceObject(pDevObj);
		ObDereferenceObject(DR0_FileObject);
		return TRUE;
	}
	// On Windows XP
	// scsi.sys
	else if(strstr(pVendorId, "VMware, VMware Virtual") != NULL)
	{
		strncpy(pVendorId, "VMw@re, VMw@re Virtu@l", 22);
		ObDereferenceObject(pDevObj);
		ObDereferenceObject(DR0_FileObject);
		return TRUE;
	}
	// On Windows 7
	// storport.sys
	else if (strstr(pVendorId, "VMware, VMware Virtual S1.0") != NULL)
	{
		strncpy(pVendorId, "VMw@re, VMw@re Virtua@l Sx.x", 28);
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
	PKEY_VALUE_FULL_INFORMATION pvfi = NULL;
	OBJECT_ATTRIBUTES	oaRegistryKey;
	OBJECT_ATTRIBUTES	oaValueName;
	UNICODE_STRING		usRegistryKey;
	UNICODE_STRING		usValueName;
	WCHAR		*wStrNewData = NULL;
	NTSTATUS	status;
	HANDLE		hKey;
	ULONG		ulSize;
	BOOLEAN		bResult = FALSE;

	DbgPrint("Called VmDetectorPatchVmDiskReg\n");


	RtlInitUnicodeString(&usRegistryKey, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum");
	RtlInitUnicodeString(&usValueName, L"0");


	InitializeObjectAttributes(&oaRegistryKey, &usRegistryKey, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL );
	InitializeObjectAttributes(&oaValueName, &usValueName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenKey(&hKey, KEY_READ, &oaRegistryKey);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[VmDetectorPatchVmDiskReg] Error ZwOpenKey %#x\n", status);
		return bResult;
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
		pvfi = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulSize, SYS_TAG);

		if (pvfi == NULL)
			return bResult;

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
		return bResult;
	}

	KdPrint(("[VmDetectorPatchVmDiskReg] Query key successfully!\n"));

	if (wcsstr(pvfi->Name, L"VMware"))
	{
		wStrNewData = L"IDE\\DiskVMw@re_Virtu@l_ID3_H@rd_Driv3___________0123456789\\0123456789012345678901234567890123456789";
		status = ZwSetValueKey(
			hKey,
			&usValueName,
			0,
			REG_SZ,
			wStrNewData,
			wcslen(wStrNewData)*2+2);

		if (!NT_SUCCESS(status))
		{	
			DbgPrint("[VmDetectorPatchVmDiskReg] Error ZwSetValueKey (VMWARE) %#x\n", status);
			return bResult;
		}

		bResult = TRUE;
		KdPrint(("[VmDetectorPatchVmDiskReg] ZwSetValueKey (VMWARE) successfully!\n"));
	}
	else if (wcsstr(pvfi->Name, L"VBOX"))
	{
		wStrNewData = L"IDE\\DiskMYBOX___________0123456789\\0123456789012345678901234567890123456789";
		status = ZwSetValueKey(
			hKey,
			&usValueName,
			0,
			REG_SZ,
			wStrNewData,
			wcslen(wStrNewData) * 2 + 2);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("[VmDetectorPatchVmDiskReg] Error ZwSetValueKey (VBOX) %#x\n", status);
			return FALSE;
		}

		bResult = TRUE;
		KdPrint(("[VmDetectorPatchVmDiskReg] ZwSetValueKey (VBOX) successfully!\n"));
	}


	ExFreePoolWithTag(pvfi, SYS_TAG);
	ZwClose(hKey);
	return bResult;
}

BOOLEAN VmDetectorPatchVmKernelModulesName(PDRIVER_OBJECT DriverObject)
{
	BOOLEAN	result1, result2 = FALSE;
	PLDR_DATA_TABLE_ENTRY CurrentLdrEntry;
	PLIST_ENTRY	Head;
	PLIST_ENTRY	Entry;

	KdPrint(("[%s] Entry point\n", __FUNCTION__));

	if (IS_WINDOWSXP())
	{
		KdPrint(("[%s] Is WINXP\n", __FUNCTION__));
	}
	else if (IS_WINDOWS7_OR_LATER())
	{
		KdPrint(("[%s] Is WIN7\n", __FUNCTION__));
	}

	Entry = ((PLIST_ENTRY)DriverObject->DriverSection)->Flink;

	Head = Entry;

	do{
		UNICODE_STRING usModuleName;
		UNICODE_STRING usFullModuleName;
		ULONG	ulBaseAddress;

		CurrentLdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		usFullModuleName = CurrentLdrEntry->FullDllName;
		usModuleName = CurrentLdrEntry->BaseDllName;
		ulBaseAddress = (ULONG)CurrentLdrEntry->DllBase;

		if (usModuleName.Length > 0 && usModuleName.MaximumLength > 0 && usModuleName.Buffer != NULL)
		{
			KdPrint(("[%s] Full modulename: %wZ, module: %wZ, Imgae base address: 0x%08x, CurrentLdrEntry: 0x%08x\n", __FUNCTION__, &usFullModuleName, &usModuleName, ulBaseAddress, CurrentLdrEntry));

			// Find module name that starts with "vm" and replaced them	with "xx"		
			{
				WCHAR wModuleName[MAX_PATH*sizeof(WCHAR)] = {0};

				wcsncpy(wModuleName, usModuleName.Buffer, usModuleName.MaximumLength);
					
				// Convert the first character to lower case
				if (wModuleName[0] <= 'Z' && wModuleName[0] >= 'A')
					wModuleName[0] -= ('Z' - 'z');

				if (wModuleName[1] <= 'Z' && wModuleName[1] >= 'A')
					wModuleName[1] -= ('Z' - 'z');

				if (wModuleName[0] == 'v' && wModuleName[1] == 'm')
				{
					wModuleName[0] = 'x';
					wModuleName[1] = 'x';

					wcsncpy(usModuleName.Buffer, wModuleName, 2);

					RtlSecureZeroMemory(wModuleName, sizeof(wModuleName));

					result1 = TRUE; 
				}

				// Patch the string in FullModuleName too
				{
					WCHAR moduleNameBuffer[MAX_PATH*sizeof(WCHAR)] = {0};
					WCHAR *wTemp = NULL;

					// Copy the full module name into a temporary buffer according to UNICODE_STRING.Length (note: the length is counted based as wide character)
					wcsncpy(moduleNameBuffer, usFullModuleName.Buffer, usFullModuleName.MaximumLength/sizeof(WCHAR));
					
					// Get the module name only without file path
					wTemp = wcsrchr(moduleNameBuffer, L'\\');

					if (wTemp != NULL)
					{
						ULONG dwPathLen = (ULONG)(wTemp+1 - moduleNameBuffer);

						// Is integer overflow?
						ASSERT((int)(usFullModuleName.MaximumLength/sizeof(WCHAR) - dwPathLen) > 0);

						// Get the full module name without file path
						wcsncpy(wModuleName, wTemp+1, (usFullModuleName.MaximumLength/sizeof(WCHAR) - dwPathLen));

						// Convert the first character to lower case
						if (wModuleName[0] <= 'Z' && wModuleName[0] >= 'A')
							wModuleName[0] -= ('Z' - 'z');

						if (wModuleName[1] <= 'Z' && wModuleName[1] >= 'A')
							wModuleName[1] -= ('Z' - 'z');

						if (wModuleName[0] == 'v' && wModuleName[1] == 'm')
						{
							wModuleName[0] = 'x';
							wModuleName[1] = 'x';

							wcsncpy(usFullModuleName.Buffer+dwPathLen, wModuleName, 2);

							result2 = TRUE; 
						}
					}

				}
			}
		}

		// Next module
		Entry = CurrentLdrEntry->InLoadOrderLinks.Flink;

	}while(Entry != Head);

	return result1&result2?TRUE:FALSE;
}

VOID __declspec(naked) SetDebugBreak()
{
	__asm {
		pushad
		mov ebx, DEBUG
		xor eax, eax
		cmp eax, ebx
		jz quit
		int 3
quit:
		popad
		retn
	}
}
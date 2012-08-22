#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#define IOCTL_VMDETECTORSYS_DEVMODEL_FIX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_VMDISKREG_FIX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_RTDSC_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)


#include <ntddk.h>
#include <ntdef.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include "RDTSCEmu.h"

BOOLEAN g_bRtdscMethodIncreasing = FALSE;
ULONGLONG g_ullRdtscValue = 0;
ULONG g_ulRdtscValue = 0;

NTKERNELAPI
	PDEVICE_OBJECT
	IoGetDeviceAttachmentBaseRef(__in PDEVICE_OBJECT DeviceObject);


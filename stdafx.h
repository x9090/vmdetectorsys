#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#define IOCTL_VMDETECTORSYS_DEVMODEL_FIX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_VMDISKREG_FIX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)

#ifdef __cplusplus
extern "C" 
{

#endif

#include <ntddk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>


NTKERNELAPI
	PDEVICE_OBJECT
	IoGetDeviceAttachmentBaseRef(__in PDEVICE_OBJECT DeviceObject);

#ifdef __cplusplus
}
#endif

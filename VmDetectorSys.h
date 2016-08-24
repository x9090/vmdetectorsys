#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#ifdef _DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

// To avoid python.h explicitly linking debug version of python27_d.lib
// error LNK1104: cannot open file 'python27_d.lib'
// Add  'MS_NO_COREDLL' to preprocessor definition
// Ref: http://guangboo.org/2013/01/17/solution-link-errorcannot-open-file-python27_dlib

#ifdef _WINXP
#define WINXP
#endif

#define SYS_TAG 'vmde'
#define SYSCALL_ZWRENAMEKEY_WIN7	0x122
#define SYS_DEVICE_NAME L"\\Device\\iminnocent"
#define SYS_SYMBOL_NAME L"\\??\\iminnocent"
#define SCSI_VM_SYMBOL_NAME L"\\??\\scsi#disk&ven_vmware_&prod_vmware_virtual_s#5&1982005&0&000000#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
#define IDE_VBOX_SYMBOL_NAME L"\\??\\ide#diskvbox_harddisk___________________________1.0_____#5&394c0ad3&0&0.0.0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
#define IOCTL_VMDETECTORSYS_DEVMODEL_FIX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_VMDISKREG_FIX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_RTDSC_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_SEND_FN_EXCLUSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_IN_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_SEND_COUNT_FN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_IN_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_SCSI_FIX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)

//
//  Ref: sfilter
//  Here is what the major and minor versions should be for the various OS versions:
//
//  OS Name                                 MajorVersion    MinorVersion
//  ---------------------------------------------------------------------
//  Windows 2000                             5                 0
//  Windows XP                               5                 1
//  Windows Server 2003                      5                 2
//

#define IS_WINDOWS2000() \
	((g_OsMajorVersion == 5) && (g_OsMinorVersion == 0))

#define IS_WINDOWSXP() \
	((g_OsMajorVersion == 5) && (g_OsMinorVersion == 1))

#define IS_WINDOWSXP_OR_LATER() \
	(((g_OsMajorVersion == 5) && (g_OsMinorVersion >= 1)) || \
	(g_OsMajorVersion > 5))

#define IS_WINDOWSSRV2003_OR_LATER() \
	(((g_OsMajorVersion == 5) && (g_OsMinorVersion >= 2)) || \
	(g_OsMajorVersion > 5))

#define IS_WINDOWS7_OR_LATER() \
	(((g_OsMajorVersion == 6) && (g_OsMinorVersion >= 1)) || \
	(g_OsMajorVersion > 6))


#include <ntddk.h>
#include <ntdef.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <Ntstrsafe.h>
#include "RDTSCEmu.h"
#include "VmDetectorUtils.h"
#include "NtObStruc.h"

BOOLEAN		g_bRtdscMethodIncreasing = FALSE;
ULONGLONG	g_ullRdtscValue = 0;
ULONG		g_ulRdtscValue = 0;
PCHAR		*g_exclusionfilelist = NULL;
extern PCHAR *g_tempexclusionfilelist = NULL;
extern int	g_countfilename = 0;

//
//  Ref: sfilter
//  MULTIVERSION NOTE: For this version of the driver, we need to know the
//  current OS version while we are running to make decisions regarding what
//  logic to use when the logic cannot be the same for all platforms.  We
//  will look up the OS version in DriverEntry and store the values
//  in these global variables.
//

extern ULONG g_OsMajorVersion;
extern ULONG g_OsMinorVersion;

//////////////////////////////////////////////////////////////////////////
// Enumeration
//////////////////////////////////////////////////////////////////////////
typedef enum _SCSI_VM_TYPE
{
	SCSI_VMWARE = 1,
	SCSI_VBOX = 2,
}SCSI_VM_TYPE;

//////////////////////////////////////////////////////////////////////////
// Data structures
//////////////////////////////////////////////////////////////////////////
#if defined(WIN7)
typedef struct _LDR_DATA_TABLE_ENTRY							// 24 elements, 0xE0 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;          // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;        // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;// 2 elements, 0x10 bytes (sizeof)
	/*0x030*/     VOID*        DllBase;
	/*0x038*/     VOID*        EntryPoint;
	/*0x040*/     ULONG32      SizeOfImage;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _UNICODE_STRING FullDllName;           // 3 elements, 0x10 bytes (sizeof)
	/*0x058*/     struct _UNICODE_STRING BaseDllName;           // 3 elements, 0x10 bytes (sizeof)
	/*0x068*/     ULONG32      Flags;
	/*0x06C*/     UINT16       LoadCount;
	/*0x06E*/     UINT16       TlsIndex;
	union                                                    // 2 elements, 0x10 bytes (sizeof)
	{
			/*0x070*/     struct _LIST_ENTRY HashLinks;              // 2 elements, 0x10 bytes (sizeof)
		struct														 // 2 elements, 0x10 bytes (sizeof)
		{
			/*0x070*/     VOID*        SectionPointer;
			/*0x078*/             ULONG32      CheckSum;
			/*0x07C*/             UINT8        _PADDING1_[0x4];
		};
	};
	union                                                    // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x080*/         ULONG32      TimeDateStamp;
		/*0x080*/         VOID*        LoadedImports;
	};
	/*0x088*/     struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	/*0x090*/     VOID*        PatchInformation;
	/*0x098*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x10 bytes (sizeof)
	/*0x0A8*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x10 bytes (sizeof)
	/*0x0B8*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x10 bytes (sizeof)
	/*0x0C8*/     VOID*        ContextInformation;
	/*0x0D0*/     UINT64       OriginalBase;
	/*0x0D8*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#elif defined(WINXP)
typedef struct _LDR_DATA_TABLE_ENTRY               // 18 elements, 0x50 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;           // 2 elements, 0x8 bytes (sizeof)
	/*0x008*/     struct _LIST_ENTRY InMemoryOrderLinks;         // 2 elements, 0x8 bytes (sizeof)
	/*0x010*/     struct _LIST_ENTRY InInitializationOrderLinks; // 2 elements, 0x8 bytes (sizeof)
	/*0x018*/     VOID*        DllBase;
	/*0x01C*/     VOID*        EntryPoint;
	/*0x020*/     ULONG32      SizeOfImage;
	/*0x024*/     struct _UNICODE_STRING FullDllName;            // 3 elements, 0x8 bytes (sizeof)
	/*0x02C*/     struct _UNICODE_STRING BaseDllName;            // 3 elements, 0x8 bytes (sizeof)
	/*0x034*/     ULONG32      Flags;
	/*0x038*/     UINT16       LoadCount;
	/*0x03A*/     UINT16       TlsIndex;
	union                                          // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x03C*/         struct _LIST_ENTRY HashLinks;              // 2 elements, 0x8 bytes (sizeof)
		struct                                     // 2 elements, 0x8 bytes (sizeof)
		{
			/*0x03C*/             VOID*        SectionPointer;
			/*0x040*/             ULONG32      CheckSum;
		};
	};
	union                                          // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x044*/         ULONG32      TimeDateStamp;
		/*0x044*/         VOID*        LoadedImports;
	};
	/*0x048*/     VOID*        EntryPointActivationContext;
	/*0x04C*/     VOID*        PatchInformation;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#endif

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	unsigned long *ServiceTableBase;
	unsigned long *ServiceCounterTableBase;
	unsigned long NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *pServiceDescriptorTableEntry;

// Helper macros
__declspec(dllimport) ServiceDescriptorTableEntry KeServiceDescriptorTable;
#define SYSTEMSERVICE(_syscall) KeServiceDescriptorTable.ServiceTableBase[_syscall]

//////////////////////////////////////////////////////////////////////////
// Undocumented function prototype
//////////////////////////////////////////////////////////////////////////

NTKERNELAPI
	PDEVICE_OBJECT
	IoGetDeviceAttachmentBaseRef(__in PDEVICE_OBJECT DeviceObject);

typedef NTSTATUS(NTAPI *ZWQUERYDIRECTORYOBJECT)(
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL);

typedef NTSTATUS(NTAPI*ZWOPENDIRECTORYOBJECT)(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(NTAPI*ZWRENAMEKEY)(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING NewName);
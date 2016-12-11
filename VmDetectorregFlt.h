#ifndef VMDETECTORREGFLT_H
#define VMDETECTORREGFLT_H
#ifdef _DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdmsec.h>

//////////////////////////////////////////////////////////////////////////
// Macros
//////////////////////////////////////////////////////////////////////////

//
// Logging macros
//
#define InfoPrint(str, ...)                 \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_INFO_LEVEL,           \
               "%s: "##str"\n",             \
               __FUNCTION__,                \
               __VA_ARGS__)

#define ErrorPrint(str, ...)                \
    DbgPrintEx(DPFLTR_DEFAULT_ID,           \
               DPFLTR_ERROR_LEVEL,          \
               "%s: %d: "##str"\n",         \
               __FUNCTION__,                \
               __LINE__,                    \
               __VA_ARGS__)

//
// Pool tags
//

#define REGFLTR_CONTEXT_POOL_TAG          '0tfR'
#define REGFLTR_CAPTURE_POOL_TAG          '1tfR'
#define REGFLTR_ALLOCATE_POOL_TAG         'vmde'

//
// Common
//
#define CALLBACK_LOW_ALTITUDE      L"990000"
#define CALLBACK_ALTITUDE          L"380010"
#define CALLBACK_HIGH_ALTITUDE     L"380020"

#define MAX_ALTITUDE_BUFFER_LENGTH 10
#define MAX_UNICODE_DATA_OFFSET 256
#define MAX_UNICODE_DATA_LENGTH 256 * sizeof(WCHAR)
//
// VM strings
//
#define STR_VMWARE L"VMWARE"
#define STR_VIRTUAL L"VIRTUALBOX"
#define STR_VBOX L"VBOX"

//////////////////////////////////////////////////////////////////////////
// Data structures
//////////////////////////////////////////////////////////////////////////
//
// The context data structure for the registry callback. It will be passed 
// to the callback function every time it is called. 
//

typedef struct _REGFLT_CALLBACK_CONTEXT {

    //
    // Records the current ProcessId to filter out registry operation from
    // other processes.
    //
    HANDLE ProcessId;

    //
    // Records the altitude that the callback was registered at
    //
    UNICODE_STRING Altitude;
    WCHAR AltitudeBuffer[MAX_ALTITUDE_BUFFER_LENGTH];

    //
    // Records the cookie returned by the registry when the callback was 
    // registered
    //
    LARGE_INTEGER Cookie;

    //
    // Number of pre-notifications received
    //
    LONG PreNotificationCount;

    //
    // Number of post-notifications received
    //
    LONG PostNotificationCount;

} REGFLT_CALLBACK_CONTEXT, *PREGFLT_CALLBACK_CONTEXT;


/////////////////////////////////////////////////////////////////////////
// Prototypes
//////////////////////////////////////////////////////////////////////////
//
// The registry and transaction callback routines
//

EX_CALLBACK_FUNCTION VmDetectorRegFilterCallback;

LPCWSTR
GetNotifyClassString(
    _In_ REG_NOTIFY_CLASS NotifyClass
    );

NTSTATUS
RegisterRegFltCallback(
    _In_ PDEVICE_OBJECT DeviceObject
    );

NTSTATUS 
UnRegisterFltCallback(
    _In_ PDEVICE_OBJECT DeviceObject
    );

PVOID
CreateCallbackContext(
    _In_ PCWSTR AltitudeString
    );

VOID
DeleteCallbackContext(
    _In_ PREGFLT_CALLBACK_CONTEXT CallbackCtx
    );

#endif
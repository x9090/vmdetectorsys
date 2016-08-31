//
// Object Manager types
//


typedef struct _OBJECT_DUMP_CONTROL {
	PVOID Stream;
	ULONG Detail;
} OB_DUMP_CONTROL, *POB_DUMP_CONTROL;

typedef VOID(*OB_DUMP_METHOD)(
	IN PVOID Object,
	IN POB_DUMP_CONTROL Control OPTIONAL
	);

typedef enum _OB_OPEN_REASON {
	ObCreateHandle,
	ObOpenHandle,
	ObDuplicateHandle,
	ObInheritHandle,
	ObMaxOpenReason
} OB_OPEN_REASON;


typedef NTSTATUS(*OB_OPEN_METHOD)(
	IN OB_OPEN_REASON OpenReason,
	IN PEPROCESS Process OPTIONAL,
	IN PVOID Object,
	IN ACCESS_MASK GrantedAccess,
	IN ULONG HandleCount
	);

typedef BOOLEAN(*OB_OKAYTOCLOSE_METHOD)(
	IN PEPROCESS Process OPTIONAL,
	IN PVOID Object,
	IN HANDLE Handle,
	IN KPROCESSOR_MODE PreviousMode
	);

typedef VOID(*OB_CLOSE_METHOD)(
	IN PEPROCESS Process OPTIONAL,
	IN PVOID Object,
	IN ACCESS_MASK GrantedAccess,
	IN ULONG_PTR ProcessHandleCount,
	IN ULONG_PTR SystemHandleCount
	);

typedef VOID(*OB_DELETE_METHOD)(
	IN  PVOID   Object
	);

typedef NTSTATUS(*OB_PARSE_METHOD)(
	IN PVOID ParseObject,
	IN PVOID ObjectType,
	IN OUT PACCESS_STATE AccessState,
	IN KPROCESSOR_MODE AccessMode,
	IN ULONG Attributes,
	IN OUT PUNICODE_STRING CompleteName,
	IN OUT PUNICODE_STRING RemainingName,
	IN OUT PVOID Context OPTIONAL,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
	OUT PVOID *Object
	);

typedef NTSTATUS(*OB_SECURITY_METHOD)(
	IN PVOID Object,
	IN SECURITY_OPERATION_CODE OperationCode,
	IN PSECURITY_INFORMATION SecurityInformation,
	IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN OUT PULONG CapturedLength,
	IN OUT PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
	IN POOL_TYPE PoolType,
	IN PGENERIC_MAPPING GenericMapping
	);

typedef NTSTATUS(*OB_QUERYNAME_METHOD)(
	IN PVOID Object,
	IN BOOLEAN HasObjectName,
	OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
	IN ULONG Length,
	OUT PULONG ReturnLength,
	IN KPROCESSOR_MODE Mode
	);

//
// Executive Pushlock
//
#undef EX_PUSH_LOCK
#undef PEX_PUSH_LOCK
typedef struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONG_PTR Locked : 1;
			ULONG_PTR Waiting : 1;
			ULONG_PTR Waking : 1;
			ULONG_PTR MultipleShared : 1;
			ULONG_PTR Shared : sizeof(ULONG_PTR) * 8 - 4;
		};
		ULONG_PTR Value;
		PVOID Ptr;
	};
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

//
// Object Type Structure
//

typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;
	BOOLEAN UseDefaultObject;
	BOOLEAN CaseInsensitive;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	BOOLEAN MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	OB_DUMP_METHOD DumpProcedure;
	OB_OPEN_METHOD OpenProcedure;
	OB_CLOSE_METHOD CloseProcedure;
	OB_DELETE_METHOD DeleteProcedure;
	OB_PARSE_METHOD ParseProcedure;
	OB_SECURITY_METHOD SecurityProcedure;
	OB_QUERYNAME_METHOD QueryNameProcedure;
	OB_OKAYTOCLOSE_METHOD OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

#define OBJECT_LOCK_COUNT 4

// XP
#if !defined(_NT_VISTA)
typedef struct _OBJECT_TYPE{
	ERESOURCE Mutex;
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;            // Copy from object header for convenience
	PVOID DefaultObject;
	ULONG Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
	ULONG Key;
	ERESOURCE ObjectLocks[OBJECT_LOCK_COUNT];
}OBJECT_TYPE, *POBJECT_TYPE;
#else // Vista and above
typedef struct _OBJECT_TYPE {
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	PVOID DefaultObject;
	ULONG Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
	ERESOURCE Mutex;
	EX_PUSH_LOCK TypeLock;
	ULONG Key;
	EX_PUSH_LOCK ObjectLocks[32];
	LIST_ENTRY CallbackList;
} OBJECT_TYPE, *POBJECT_TYPE;
#endif

//
// Object Directory Structure
//

#define NUMBER_HASH_BUCKETS 37
#define OBJ_INVALID_SESSION_ID 0xFFFFFFFF

typedef struct _OBJECT_DIRECTORY {
	struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[NUMBER_HASH_BUCKETS];
	EX_PUSH_LOCK Lock;
	struct _DEVICE_MAP *DeviceMap;
	ULONG SessionId;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;
// end_ntosp

//
// Object Directory Entry Structure
//
typedef struct _OBJECT_DIRECTORY_ENTRY {
	struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
	PVOID Object;
	ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;


//
// Symbolic Link Object Structure
//

typedef struct _OBJECT_SYMBOLIC_LINK {
	LARGE_INTEGER CreationTime;
	UNICODE_STRING LinkTarget;
	UNICODE_STRING LinkTargetRemaining;
	PVOID LinkTargetObject;
	ULONG DosDeviceDriveIndex;  // 1-based index into KUSER_SHARED_DATA.DosDeviceDriveType
} OBJECT_SYMBOLIC_LINK, *POBJECT_SYMBOLIC_LINK;


//
// Device Map Structure
//

typedef struct _DEVICE_MAP {
	POBJECT_DIRECTORY DosDevicesDirectory;
	POBJECT_DIRECTORY GlobalDosDevicesDirectory;
	ULONG ReferenceCount;
	ULONG DriveMap;
	UCHAR DriveType[32];
} DEVICE_MAP, *PDEVICE_MAP;

extern PDEVICE_MAP ObSystemDeviceMap;

//
// Object Handle Count Database
//

typedef struct _OBJECT_HANDLE_COUNT_ENTRY {
	PEPROCESS Process;
	ULONG HandleCount;
} OBJECT_HANDLE_COUNT_ENTRY, *POBJECT_HANDLE_COUNT_ENTRY;

typedef struct _OBJECT_HANDLE_COUNT_DATABASE {
	ULONG CountEntries;
	OBJECT_HANDLE_COUNT_ENTRY HandleCountEntries[1];
} OBJECT_HANDLE_COUNT_DATABASE, *POBJECT_HANDLE_COUNT_DATABASE;

//
// Object Header Structure
//
// The SecurityQuotaCharged is the amount of quota charged to cover
// the GROUP and DISCRETIONARY ACL fields of the security descriptor
// only.  The OWNER and SYSTEM ACL fields get charged for at a fixed
// rate that may be less than or greater than the amount actually used.
//
// If the object has no security, then the SecurityQuotaCharged and the
// SecurityQuotaInUse fields are set to zero.
//
// Modification of the OWNER and SYSTEM ACL fields should never fail
// due to quota exceeded problems.  Modifications to the GROUP and
// DISCRETIONARY ACL fields may fail due to quota exceeded problems.
//
//


typedef struct _OBJECT_CREATE_INFORMATION {
	ULONG Attributes;
	HANDLE RootDirectory;
	PVOID ParseContext;
	KPROCESSOR_MODE ProbeMode;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG SecurityDescriptorCharge;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION;

// begin_ntosp
typedef struct _OBJECT_CREATE_INFORMATION *POBJECT_CREATE_INFORMATION;;

#if _WIN32_WINNT <= _WIN32_WINNT_WS03 
typedef struct _OBJECT_HEADER {
	LONG_PTR PointerCount;
	union {
		LONG_PTR HandleCount;
		PVOID NextToFree;
	};
	POBJECT_TYPE Type;
	UCHAR NameInfoOffset;
	UCHAR HandleInfoOffset;
	UCHAR QuotaInfoOffset;
	UCHAR Flags;

	union {
		POBJECT_CREATE_INFORMATION ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};

	PSECURITY_DESCRIPTOR SecurityDescriptor;
	QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;
// end_ntosp
#else
	typedef struct _OBJECT_HEADER
	{
		LONG32 PointerCount;
		union
		{
			LONG32 HandleCount;
			PVOID  NextToFree;
		};
		struct _EX_PUSH_LOCK Lock;
		UINT8 TypeIndex;
		UINT8 TraceFlags;
		UINT8 InfoMask;
		UINT8 Flags;
		union
		{
			POBJECT_CREATE_INFORMATION ObjectCreateInfo;
			PVOID QuotaBlockCharged;
		};
		PVOID SecurityDescriptor;
		struct _QUAD Body;
	}OBJECT_HEADER, *POBJECT_HEADER;
#endif
typedef struct _OBJECT_HEADER_QUOTA_INFO {
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG SecurityDescriptorCharge;
	PEPROCESS ExclusiveProcess;
#ifdef _WIN64
	ULONG64  Reserved;   // Win64 requires these structures to be 16 byte aligned.
#endif
} OBJECT_HEADER_QUOTA_INFO, *POBJECT_HEADER_QUOTA_INFO;

typedef struct _OBJECT_HEADER_HANDLE_INFO {
	union {
		POBJECT_HANDLE_COUNT_DATABASE HandleCountDataBase;
		OBJECT_HANDLE_COUNT_ENTRY SingleEntry;
	};
} OBJECT_HEADER_HANDLE_INFO, *POBJECT_HEADER_HANDLE_INFO;

// begin_ntosp
typedef struct _OBJECT_HEADER_NAME_INFO {
	POBJECT_DIRECTORY Directory;
	UNICODE_STRING Name;
	ULONG QueryReferences;
#if DBG
	ULONG Reserved2;
	LONG DbgDereferenceCount;
#ifdef _WIN64
	ULONG64  Reserved3;   // Win64 requires these structures to be 16 byte aligned.
#endif
#endif
} OBJECT_HEADER_NAME_INFO, *POBJECT_HEADER_NAME_INFO;
// end_ntosp

typedef struct _OBJECT_HEADER_CREATOR_INFO {
	LIST_ENTRY TypeList;
	HANDLE CreatorUniqueProcess;
	USHORT CreatorBackTraceIndex;
	USHORT Reserved;
} OBJECT_HEADER_CREATOR_INFO, *POBJECT_HEADER_CREATOR_INFO;

#define OB_FLAG_NEW_OBJECT              0x01
#define OB_FLAG_KERNEL_OBJECT           0x02
#define OB_FLAG_CREATOR_INFO            0x04
#define OB_FLAG_EXCLUSIVE_OBJECT        0x08
#define OB_FLAG_PERMANENT_OBJECT        0x10
#define OB_FLAG_DEFAULT_SECURITY_QUOTA  0x20
#define OB_FLAG_SINGLE_HANDLE_ENTRY     0x40
#define OB_FLAG_DELETED_INLINE          0x80

// begin_ntosp
#define OBJECT_TO_OBJECT_HEADER( o ) \
	CONTAINING_RECORD( (o), OBJECT_HEADER, Body )
// end_ntosp

#define OBJECT_HEADER_TO_EXCLUSIVE_PROCESS( oh ) ((oh->Flags & OB_FLAG_EXCLUSIVE_OBJECT) == 0 ? \
NULL : (((POBJECT_HEADER_QUOTA_INFO)((PCHAR)(oh) - (oh)->QuotaInfoOffset))->ExclusiveProcess))



//
// Object Lookup Context
//
typedef struct _OBP_LOOKUP_CONTEXT
{
	POBJECT_DIRECTORY Directory;
	PVOID Object;
	ULONG HashValue;
	USHORT HashIndex;
	BOOLEAN DirectoryLocked;
	ULONG LockStateSignature;
} OBP_LOOKUP_CONTEXT, *POBP_LOOKUP_CONTEXT;

// begin_ntosp
#if _WIN32_WINNT <= _WIN32_WINNT_WS03 
FORCEINLINE
POBJECT_HEADER_NAME_INFO
OBJECT_HEADER_TO_NAME_INFO_EXISTS(IN POBJECT_HEADER ObjectHeader)
{
	ASSERT(ObjectHeader->NameInfoOffset != 0);
	return (POBJECT_HEADER_NAME_INFO)((PUCHAR)ObjectHeader -
		ObjectHeader->NameInfoOffset);
}

FORCEINLINE
POBJECT_HEADER_NAME_INFO
OBJECT_HEADER_TO_NAME_INFO(IN POBJECT_HEADER ObjectHeader)
{
	POBJECT_HEADER_NAME_INFO nameInfo;

	if (ObjectHeader->NameInfoOffset != 0) {
		nameInfo = OBJECT_HEADER_TO_NAME_INFO_EXISTS(ObjectHeader);
		__assume(nameInfo != NULL);
	}
	else {
		nameInfo = NULL;
	}

	return nameInfo;
}
#else
FORCEINLINE
POBJECT_HEADER_NAME_INFO
OBJECT_HEADER_TO_NAME_INFO(IN POBJECT_HEADER ObjectHeader)
{
	return (POBJECT_HEADER_NAME_INFO)((PUCHAR)ObjectHeader - 0x10);
}
#endif

////////////////////////////////////////////////////
// From ReactOS: 
// - reactos\include\ndk\obtypes.h
////////////////////////////////////////////////////
typedef struct _OBJECT_DIRECTORY_INFORMATION
{
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

// end_ntosp
#include "VmDetectorregFlt.h"
#include "VmDetectorUtils.h"

// Device extension specific to the driver
// Must be sync with VmDetectorSys.h
typedef struct _deviceExtension
{
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_OBJECT TargetDeviceObject;
    PDEVICE_OBJECT PhysicalDeviceObject;
    UNICODE_STRING usDeviceName;
    UNICODE_STRING usSymlinkName;
    PREGFLT_CALLBACK_CONTEXT pRegFltCallbackCtx;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

/*++

Routine Description:

    Converts from NotifyClass to a string

Arguments:

    NotifyClass - value that identifies the type of registry operation that
        is being performed

Return Value:

    Returns a string of the name of NotifyClass.

--*/
LPCWSTR
GetNotifyClassString(
    _In_ REG_NOTIFY_CLASS NotifyClass
    )
{
    switch (NotifyClass) {
    case RegNtPreDeleteKey:                 return L"RegNtPreDeleteKey";
    case RegNtPreSetValueKey:               return L"RegNtPreSetValueKey";
    case RegNtPreDeleteValueKey:            return L"RegNtPreDeleteValueKey";
    case RegNtPreSetInformationKey:         return L"RegNtPreSetInformationKey";
    case RegNtPreRenameKey:                 return L"RegNtPreRenameKey";
    case RegNtPreEnumerateKey:              return L"RegNtPreEnumerateKey";
    case RegNtPreEnumerateValueKey:         return L"RegNtPreEnumerateValueKey";
    case RegNtPreQueryKey:                  return L"RegNtPreQueryKey";
    case RegNtPreQueryValueKey:             return L"RegNtPreQueryValueKey";
    case RegNtPreQueryMultipleValueKey:     return L"RegNtPreQueryMultipleValueKey";
    case RegNtPreKeyHandleClose:            return L"RegNtPreKeyHandleClose";
    case RegNtPreCreateKeyEx:               return L"RegNtPreCreateKeyEx";
    case RegNtPreOpenKeyEx:                 return L"RegNtPreOpenKeyEx";
    case RegNtPreFlushKey:                  return L"RegNtPreFlushKey";
    case RegNtPreLoadKey:                   return L"RegNtPreLoadKey";
    case RegNtPreUnLoadKey:                 return L"RegNtPreUnLoadKey";
    case RegNtPreQueryKeySecurity:          return L"RegNtPreQueryKeySecurity";
    case RegNtPreSetKeySecurity:            return L"RegNtPreSetKeySecurity";
    case RegNtPreRestoreKey:                return L"RegNtPreRestoreKey";
    case RegNtPreSaveKey:                   return L"RegNtPreSaveKey";
    case RegNtPreReplaceKey:                return L"RegNtPreReplaceKey";

    case RegNtPostDeleteKey:                return L"RegNtPostDeleteKey";
    case RegNtPostSetValueKey:              return L"RegNtPostSetValueKey";
    case RegNtPostDeleteValueKey:           return L"RegNtPostDeleteValueKey";
    case RegNtPostSetInformationKey:        return L"RegNtPostSetInformationKey";
    case RegNtPostRenameKey:                return L"RegNtPostRenameKey";
    case RegNtPostEnumerateKey:             return L"RegNtPostEnumerateKey";
    case RegNtPostEnumerateValueKey:        return L"RegNtPostEnumerateValueKey";
    case RegNtPostQueryKey:                 return L"RegNtPostQueryKey";
    case RegNtPostQueryValueKey:            return L"RegNtPostQueryValueKey";
    case RegNtPostQueryMultipleValueKey:    return L"RegNtPostQueryMultipleValueKey";
    case RegNtPostKeyHandleClose:           return L"RegNtPostKeyHandleClose";
    case RegNtPostCreateKeyEx:              return L"RegNtPostCreateKeyEx";
    case RegNtPostOpenKeyEx:                return L"RegNtPostOpenKeyEx";
    case RegNtPostFlushKey:                 return L"RegNtPostFlushKey";
    case RegNtPostLoadKey:                  return L"RegNtPostLoadKey";
    case RegNtPostUnLoadKey:                return L"RegNtPostUnLoadKey";
    case RegNtPostQueryKeySecurity:         return L"RegNtPostQueryKeySecurity";
    case RegNtPostSetKeySecurity:           return L"RegNtPostSetKeySecurity";
    case RegNtPostRestoreKey:               return L"RegNtPostRestoreKey";
    case RegNtPostSaveKey:                  return L"RegNtPostSaveKey";
    case RegNtPostReplaceKey:               return L"RegNtPostReplaceKey";

    case RegNtCallbackObjectContextCleanup: return L"RegNtCallbackObjectContextCleanup";

    default:
        return L"Unsupported REG_NOTIFY_CLASS";
    }
}

WCHAR *GetKeyNameByUnicodeString(PUNICODE_STRING pusKeyName)
{
    WCHAR *KeyName = NULL;
    
    ASSERT(pusKeyName);

    KeyName = ExAllocatePoolWithTag(NonPagedPool, pusKeyName->MaximumLength, REGFLTR_ALLOCATE_POOL_TAG);

    if (!KeyName)
    {
        ErrorPrint("ExAllocatePoolWithTag failed\n");
        return KeyName;
    }

    RtlSecureZeroMemory(KeyName, pusKeyName->MaximumLength);
    RtlCopyMemory(KeyName, pusKeyName->Buffer, pusKeyName->Length);
    return KeyName;
}

BOOLEAN IsKeyNameContainVMString(WCHAR *KeyName)
{
    if (wcsistr(KeyName, STR_VMWARE) ||
        wcsistr(KeyName, STR_VIRTUAL) ||
        wcsistr(KeyName, STR_VBOX))
        return TRUE;
    else
        return FALSE;
}

BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING pRegistryPath, PVOID pRegistryObject)
{
    BOOLEAN foundCompleteName = FALSE;

    /* Check to see if everything is valid */
    if ((!MmIsAddressValid(pRegistryObject)) || (pRegistryObject == NULL))
    {
        return FALSE;
    }

   
    /* Query the object manager in the kernel for the complete name */
    NTSTATUS status;
    ULONG returnedLength;
    PUNICODE_STRING	pObjectName = NULL;

    status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        pObjectName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, REGFLTR_ALLOCATE_POOL_TAG);
        status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength);
        if (NT_SUCCESS(status))
        {
            RtlUnicodeStringCopy(pRegistryPath, pObjectName);
            foundCompleteName = TRUE;
        }
        ExFreePoolWithTag(pObjectName, REGFLTR_ALLOCATE_POOL_TAG);
    }

    return foundCompleteName;
}


/*++

Routine Description:

    This is the registry callback we'll register to intercept all registry
    operations.

Arguments:

    CallbackContext - The value that the driver passed to the Context parameter
        of CmRegisterCallbackEx when it registers this callback routine.

    Argument1 - A REG_NOTIFY_CLASS typed value that identifies the type of
        registry operation that is being performed and whether the callback
        is being called in the pre or post phase of processing.

    Argument2 - A pointer to a structure that contains information specific
        to the type of the registry operation.The structure type depends
        on the REG_NOTIFY_CLASS value of Argument1.Refer to MSDN for the
        mapping from REG_NOTIFY_CLASS to REG_XXX_KEY_INFORMATION.

Return Value :

    Status returned from the helper callback routine or STATUS_SUCCESS if
    the registry operation did not originate from this process.

--*/
NTSTATUS
VmDetectorRegFilterCallback(
    _In_     PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{

    NTSTATUS Status = STATUS_SUCCESS;
    PREG_PRE_CREATE_KEY_INFORMATION PreCreateInfo;
    PREG_CREATE_KEY_INFORMATION_V1 PreCreateInfoEx;
    PREG_QUERY_KEY_INFORMATION PreQueryKeyInfo;
    PREG_QUERY_VALUE_KEY_INFORMATION PreQueryValueKeyInfo, PostQueryValueKeyInfo;
    PREG_ENUMERATE_KEY_INFORMATION PreEnumKeyInfo;
    PREG_ENUMERATE_VALUE_KEY_INFORMATION PreEnumValueKeyInfo;
    PREG_POST_OPERATION_INFORMATION PostInfo;
    UNICODE_STRING Name;
    PVOID KeyValueInfo = NULL;
    PVOID KeyValueData = NULL;
    WCHAR *wValueName = NULL;
    WCHAR *wKeyName = NULL;
    WCHAR *wValueData = NULL;
    INT MaxDataLen, DataLen, MaxValueLen, ValueLen;
    KEY_INFORMATION_CLASS KeyInfoClass;
    KEY_VALUE_INFORMATION_CLASS KeyValueInfoClass;
    REG_NOTIFY_CLASS NotifyClass;
    PREGFLT_CALLBACK_CONTEXT CallbackCtx;
   
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    CallbackCtx = (PREGFLT_CALLBACK_CONTEXT)CallbackContext;
    NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;


    InfoPrint("Callback: Altitude-%S, NotifyClass-%S.", CallbackCtx->AltitudeBuffer, GetNotifyClassString(NotifyClass));

    //
    // Invoke a helper method depending on the value of CallbackMode in 
    // CallbackCtx.
    //

    if (Argument2 == NULL) {

        //
        // This should never happen but the sal annotation on the callback 
        // function marks Argument 2 as opt and is looser than what 
        // it actually is.
        //

        ErrorPrint("Callback: Argument 2 unexpectedly 0. Filter will "
            "abort and return success.");
        return STATUS_SUCCESS;
    }

    UNREFERENCED_PARAMETER(CallbackCtx);

    try
    {
        RtlSecureZeroMemory(&Name, sizeof(UNICODE_STRING));
        /* Allocate a large 64kb string ... maximum path name allowed in windows */
        Name.Length = 0;
        Name.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
        Name.Buffer = ExAllocatePoolWithTag(NonPagedPool, Name.MaximumLength, REGFLTR_ALLOCATE_POOL_TAG);
        RtlSecureZeroMemory(Name.Buffer, Name.MaximumLength);

        switch (NotifyClass) {

        case RegNtPreCreateKey:
        case RegNtPreOpenKey:
            PreCreateInfo = (PREG_PRE_CREATE_KEY_INFORMATION)Argument2;
            wKeyName = GetKeyNameByUnicodeString(PreCreateInfo->CompleteName);
            //
            // Only intercept the operation if the key being created has the 
            // vmware/vbox/virtual string.
            //
            if (wKeyName && IsKeyNameContainVMString(wKeyName))
            {
                //
                // By returning an error status, we block the operation.
                //
                KdPrint(("RegNtPreCreateKey: Key %wZ blocked\n", PreCreateInfo->CompleteName));
                Status = STATUS_NOT_FOUND;
            }
            break;
        case RegNtPreCreateKeyEx:
        case RegNtPreOpenKeyEx:
            PreCreateInfoEx = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;

            if (!GetRegistryObjectCompleteName(&Name, PreCreateInfoEx->RootObject))
            {
                ErrorPrint("RegNtPreOpenKeyEx: Failed to get key name\n");
            }
            else
            {
                RtlUnicodeStringCatString(&Name, L"\\");
                RtlUnicodeStringCat(&Name, PreCreateInfoEx->RemainingName);

                //
                // Only intercept the operation if the key being created has the 
                // vmware/vbox/virtual string.
                //
                wKeyName = GetKeyNameByUnicodeString(&Name);
                if (wKeyName && IsKeyNameContainVMString(wKeyName))
                {
                    //
                    // By returning an error status, we block the operation.
                    //
                    KdPrint(("RegNtPreOpenKeyEx: key %wZ blocked\n", &Name));
                    Status = STATUS_NOT_FOUND;
                }
            }
            break;

        //case RegNtPreEnumerateKey:

        //    PreEnumKeyInfo = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
        //    KeyInfoClass = PreEnumKeyInfo->KeyInformationClass;

        //    if (!GetRegistryObjectCompleteName(&Name, PreEnumKeyInfo->Object))
        //    {
        //        ErrorPrint("RegNtPreEnumerateKey: Failed to get key name\n");
        //    }
        //    else
        //    {
        //        wKeyName = GetKeyNameByUnicodeString(&Name);

        //        if (wKeyName && IsKeyNameContainVMString(wKeyName))
        //        {
        //            //
        //            // By returning an error status, we block the operation.
        //            //
        //            KdPrint(("RegNtPreEnumerateKey: Key %wZ blocked\n", &Name));
        //            Status = STATUS_NOT_FOUND;
        //        }
        //    }
        //    break;

        //case RegNtEnumerateValueKey:

        //    PreEnumValueKeyInfo = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
        //    KeyValueInfoClass = PreEnumValueKeyInfo->KeyValueInformationClass;

        //    /* Inspect the key */
        //    if (!GetRegistryObjectCompleteName(&Name, PreEnumValueKeyInfo->Object))
        //    {
        //        ErrorPrint("RegNtEnumerateValueKey: Failed to get key name\n");
        //    }
        //    else
        //    {
        //        PVOID KeyValueinfo = PreEnumValueKeyInfo->KeyValueInformation;
        //        wKeyName = GetKeyNameByUnicodeString(&Name);

        //        if (wKeyName && IsKeyNameContainVMString(wKeyName))
        //        {
        //            //
        //            // By returning an error status, we block the operation.
        //            //
        //            KdPrint(("RegNtEnumerateValueKey: Key %wZ blocked\n", &Name));
        //            Status = STATUS_NOT_FOUND;
        //        }
        //    }

        //    /* Inspect value data */
        //    if (KeyValueInfoClass == KeyValueFullInformation)
        //    {
        //        PKEY_VALUE_FULL_INFORMATION KeyValueFullinfo = (PKEY_VALUE_FULL_INFORMATION)PreEnumValueKeyInfo->KeyValueInformation;
        //        
        //        // Sanity checks
        //        if (!KeyValueFullinfo || KeyValueFullinfo->DataOffset == 0 || KeyValueFullinfo->NameLength == 0 || KeyValueFullinfo->DataLength == 0)
        //            break;
        //       
        //        INT ValueLen = KeyValueFullinfo->NameLength + sizeof(WCHAR);
        //        INT DataLen = KeyValueFullinfo->DataLength + sizeof(WCHAR);

        //        // FIXME: Is there a more elegant way to know this structure is not properly setup?
        //        if (ValueLen > MAX_UNICODE_DATA_LENGTH || DataLen > MAX_UNICODE_DATA_LENGTH)
        //            break;

        //        if (KeyValueFullinfo->DataOffset > MAX_UNICODE_DATA_OFFSET)
        //            break;

        //        WCHAR *Value = ExAllocatePoolWithTag(NonPagedPool, ValueLen, REGFLTR_ALLOCATE_POOL_TAG);
        //        WCHAR *ValueData = ExAllocatePoolWithTag(NonPagedPool, DataLen, REGFLTR_ALLOCATE_POOL_TAG);
        //        
        //        ASSERT(Value != NULL);
        //        ASSERT(ValueData != NULL);

        //        RtlSecureZeroMemory(Value, ValueLen);
        //        RtlSecureZeroMemory(ValueData, DataLen);
        //        RtlCopyMemory(Value, KeyValueFullinfo->Name, KeyValueFullinfo->NameLength);
        //        RtlCopyMemory(ValueData, (PCHAR)KeyValueFullinfo + KeyValueFullinfo->DataOffset, KeyValueFullinfo->DataLength);

        //        if (IsKeyNameContainVMString(ValueData))
        //        {
        //            KdPrint(("RegNtEnumerateValueKey->KeyValueFullInformation: Key %wZ, Value: %ws, Data: %ws blocked\n", &Name, Value, ValueData));
        //            Status = STATUS_NOT_FOUND;
        //        }
        //        ExFreePoolWithTag(Value, REGFLTR_ALLOCATE_POOL_TAG);
        //        ExFreePoolWithTag(ValueData, REGFLTR_ALLOCATE_POOL_TAG);
        //    }
        //    break;

        //case RegNtPreQueryKey:
        //    PreQueryKeyInfo = (PREG_QUERY_KEY_INFORMATION)Argument2;
        //    KeyInfoClass = PreQueryKeyInfo->KeyInformationClass;

        //    if (!GetRegistryObjectCompleteName(&Name, PreQueryKeyInfo->Object))
        //    {
        //        ErrorPrint("RegNtPreQueryKey: Failed to get key name\n");
        //    }
        //    else
        //    {
        //        PVOID KeyInfo = PreQueryKeyInfo->KeyInformation;
        //        wKeyName = GetKeyNameByUnicodeString(&Name);
        //            
        //        if (wKeyName && IsKeyNameContainVMString(wKeyName))
        //        {
        //            //
        //            // By returning an error status, we block the operation.
        //            //
        //            InfoPrint("RegNtPreQueryKey: Key %wZ blocked.", &Name);
        //            Status = STATUS_NOT_FOUND;
        //        }
        //    }
        //    break;

        case RegNtPreQueryValueKey:
            PreQueryValueKeyInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
            KeyValueInfoClass = PreQueryValueKeyInfo->KeyValueInformationClass;

            if (PreQueryValueKeyInfo->ValueName == NULL || PreQueryValueKeyInfo->ValueName->MaximumLength == 0)
                break;

            wValueName = ExAllocatePoolWithTag(NonPagedPool, PreQueryValueKeyInfo->ValueName->MaximumLength + sizeof(WCHAR), REGFLTR_ALLOCATE_POOL_TAG);
            ASSERT(wValueName != NULL);

            // Get the registry value 
            RtlSecureZeroMemory(wValueName, PreQueryValueKeyInfo->ValueName->MaximumLength + sizeof(WCHAR));
            RtlCopyMemory(wValueName, PreQueryValueKeyInfo->ValueName->Buffer, PreQueryValueKeyInfo->ValueName->Length);

            /* Inspect the key */
            if (!GetRegistryObjectCompleteName(&Name, PreQueryValueKeyInfo->Object))
            {
                ErrorPrint("RegNtPreQueryValueKey: Failed to get key name\n");
            }
            else
            {
                KeyValueInfo = PreQueryValueKeyInfo->KeyValueInformation;
                RtlUnicodeStringCatString(&Name, L"\\");
                RtlUnicodeStringCat(&Name, PreQueryValueKeyInfo->ValueName);

                wKeyName = GetKeyNameByUnicodeString(&Name);

                if (wKeyName && IsKeyNameContainVMString(wKeyName))
                {
                    //
                    // By returning an error status, we block the operation.
                    //
                    KdPrint(("RegNtPreQueryValueKey: Key %wZ blocked\n", &Name));
                    Status = STATUS_NOT_FOUND;
                }
            }

            /* Inspect value data */
            DataLen = MaxDataLen = 0;
            if (KeyValueInfoClass == KeyValueFullInformation)
            {
                PKEY_VALUE_FULL_INFORMATION KeyValueFullinfo = (PKEY_VALUE_FULL_INFORMATION)PreQueryValueKeyInfo->KeyValueInformation;

                if (!KeyValueFullinfo || KeyValueFullinfo->DataOffset == 0 || KeyValueFullinfo->NameLength == 0 || KeyValueFullinfo->DataLength == 0)
                    break;

                MaxDataLen = KeyValueFullinfo->DataLength + sizeof(WCHAR);

                // FIXME: Is there a more elegant way to know this structure is not properly setup?
                if (MaxDataLen > MAX_UNICODE_DATA_LENGTH)
                    break;

                if (KeyValueFullinfo->DataOffset > MAX_UNICODE_DATA_OFFSET)
                    break;

                KeyValueData = (PCHAR)KeyValueFullinfo + KeyValueFullinfo->DataOffset;
                DataLen = KeyValueFullinfo->DataLength;
            }
                
            else if (KeyValueInfoClass == KeyValuePartialInformation)
            {
                PKEY_VALUE_PARTIAL_INFORMATION KeyValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)PreQueryValueKeyInfo->KeyValueInformation;

                // Some sanity checks
                if (!KeyValuePartialInfo || KeyValuePartialInfo->DataLength == 0)
                    break;

                // Only null-terminated string value data
                if (KeyValuePartialInfo->Type != REG_SZ && KeyValuePartialInfo->Type != REG_MULTI_SZ)
                    break;

                MaxDataLen = KeyValuePartialInfo->DataLength + sizeof(WCHAR);

                // FIXME: Is there a more elegant way to know this structure is not properly setup?
                if (MaxDataLen > MAX_UNICODE_DATA_LENGTH)
                    break;

                KeyValueData = (PVOID)KeyValuePartialInfo->Data;
                DataLen = KeyValuePartialInfo->DataLength;
            }// End inspecting key and value data


            // Get value data
            if (DataLen != 0 && MaxDataLen != 0)
            {
                wValueData = ExAllocatePoolWithTag(NonPagedPool, MaxDataLen, REGFLTR_ALLOCATE_POOL_TAG);
                ASSERT(wValueData != NULL);

                RtlSecureZeroMemory(wValueData, DataLen);
                RtlCopyMemory(wValueData, KeyValueData, DataLen);

                //
                // Only intercept the operation if the key being created has the 
                // vmware/vbox/virtual string.
                // 
                if (IsKeyNameContainVMString(wValueData))
                {
                    KdPrint(("RegNtPostQueryValueKey: Key %wZ, Value: %ws, Data: %ws blocked\n", &Name, wValueName, wValueData));
                    Status = STATUS_NOT_FOUND;
                }
            }
            break;

        case RegNtPostQueryValueKey:
            PostInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
            PostQueryValueKeyInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)PostInfo->PreInformation;
            KeyValueInfoClass = PostQueryValueKeyInfo->KeyValueInformationClass;

            if (PostQueryValueKeyInfo->ValueName == NULL || PostQueryValueKeyInfo->ValueName->MaximumLength == 0)
                break;

            wValueName = ExAllocatePoolWithTag(NonPagedPool, PostQueryValueKeyInfo->ValueName->MaximumLength + sizeof(WCHAR), REGFLTR_ALLOCATE_POOL_TAG);
            ASSERT(wValueName != NULL);

            // Get the registry value 
            RtlSecureZeroMemory(wValueName, PostQueryValueKeyInfo->ValueName->MaximumLength + sizeof(WCHAR));
            RtlCopyMemory(wValueName, PostQueryValueKeyInfo->ValueName->Buffer, PostQueryValueKeyInfo->ValueName->Length);

            /* Inspect the key */
            if (!GetRegistryObjectCompleteName(&Name, PostQueryValueKeyInfo->Object))
            {
                ErrorPrint("PostQueryValueKeyInfo: Failed to get key name\n");
            }
            else
            {
                KeyValueInfo = PostQueryValueKeyInfo->KeyValueInformation;
                RtlUnicodeStringCatString(&Name, L"\\");
                RtlUnicodeStringCat(&Name, PostQueryValueKeyInfo->ValueName);

                wKeyName = GetKeyNameByUnicodeString(&Name);

                if (wKeyName && IsKeyNameContainVMString(wKeyName))
                {
                    //
                    // By returning an error status, we block the operation.
                    //
                    KdPrint(("RegNtPostQueryValueKey: Key %wZ blocked\n", &Name));
                    Status = STATUS_CALLBACK_BYPASS;
                    // In post operation, we need to specific the return value in PostInfo structure
                    PostInfo->ReturnStatus = STATUS_NOT_FOUND;
                }
            }
            /* Inspect value data */
            DataLen = MaxDataLen = 0;
            if (KeyValueInfoClass == KeyValueFullInformation)
            {
                PKEY_VALUE_FULL_INFORMATION KeyValueFullinfo = (PKEY_VALUE_FULL_INFORMATION)PostQueryValueKeyInfo->KeyValueInformation;
                 
                // Some sanity checks
                if (!KeyValueFullinfo || KeyValueFullinfo->DataOffset == 0 || KeyValueFullinfo->NameLength == 0 || KeyValueFullinfo->DataLength == 0)
                    break;

                MaxDataLen = KeyValueFullinfo->DataLength + sizeof(WCHAR);

                // FIXME: Is there a more elegant way to know this structure is not properly setup?
                if (MaxDataLen > MAX_UNICODE_DATA_LENGTH)
                    break;

                if (KeyValueFullinfo->DataOffset > MAX_UNICODE_DATA_OFFSET)
                    break;

                KeyValueData = (PCHAR)KeyValueFullinfo + KeyValueFullinfo->DataOffset;
                DataLen = KeyValueFullinfo->DataLength;
            }
            else if (KeyValueInfoClass == KeyValuePartialInformation)
            {
                PKEY_VALUE_PARTIAL_INFORMATION KeyValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)PostQueryValueKeyInfo->KeyValueInformation;

                // Some sanity checks
                if (!KeyValuePartialInfo || KeyValuePartialInfo->DataLength == 0)
                    break;

                // Only null-terminated string value data
                if (KeyValuePartialInfo->Type != REG_SZ && KeyValuePartialInfo->Type != REG_MULTI_SZ)
                    break;

                MaxDataLen = KeyValuePartialInfo->DataLength + sizeof(WCHAR);

                // FIXME: Is there a more elegant way to know this structure is not properly setup?
                if (MaxDataLen > MAX_UNICODE_DATA_LENGTH)
                    break;

                KeyValueData = (PVOID)KeyValuePartialInfo->Data;
                DataLen = KeyValuePartialInfo->DataLength;

            }
            // End inspecting key and value data

            // Get value data
            if (DataLen != 0 && MaxDataLen != 0)
            {
                wValueData = ExAllocatePoolWithTag(NonPagedPool, MaxDataLen, REGFLTR_ALLOCATE_POOL_TAG);
                ASSERT(wValueData != NULL);

                RtlSecureZeroMemory(wValueData, DataLen);
                RtlCopyMemory(wValueData, KeyValueData, DataLen);

                //
                // Only intercept the operation if the key being created has the 
                // vmware/vbox/virtual string.
                // 
                if (IsKeyNameContainVMString(wValueData))
                {
                    KdPrint(("RegNtPostQueryValueKey: Key %wZ, Value: %ws, Data: %ws blocked\n", &Name, wValueName, wValueData));
                    Status = STATUS_CALLBACK_BYPASS;
                    // In post operation, we need to specific the return value in PostInfo structure
                    PostInfo->ReturnStatus = STATUS_NOT_FOUND;
                }
            }
            break;

        default:
            //
            // Do nothing for other notifications
            //
            break;
        }
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        ASSERT(FALSE);
    }

    // Free up resources
    if (wValueData)
    {
        ExFreePoolWithTag(wValueData, REGFLTR_ALLOCATE_POOL_TAG);
        wValueData = NULL;
    }

    if (wValueName)
    {
        ExFreePoolWithTag(wValueName, REGFLTR_ALLOCATE_POOL_TAG);
        wValueName = NULL;
    }

    if (wKeyName)
    {
        ExFreePoolWithTag(wKeyName, REGFLTR_ALLOCATE_POOL_TAG);
        wKeyName = NULL;
    }

    if (Name.Buffer)
    {
        ExFreePoolWithTag(Name.Buffer, REGFLTR_ALLOCATE_POOL_TAG);
        Name.Buffer = NULL;
    }

    return Status;

}

/*++

Routine Description:

    Utility method to create a callback context. Callback context
    should be freed using DeleteCallbackContext.

Arguments:

    AltitudeString - a string with the altitude the callback will be
        registered at

Return Value:

    Pointer to the allocated and initialized callback context

--*/
PVOID
CreateCallbackContext(
    _In_ PCWSTR AltitudeString
    )
{

    PREGFLT_CALLBACK_CONTEXT CallbackCtx = NULL;
    NTSTATUS Status;
    BOOLEAN Success = FALSE;

    CallbackCtx = (PREGFLT_CALLBACK_CONTEXT)ExAllocatePoolWithTag(
                    PagedPool,
                    sizeof(REGFLT_CALLBACK_CONTEXT),
                    REGFLTR_CONTEXT_POOL_TAG);

    if (CallbackCtx == NULL) {
        ErrorPrint("Failed due to insufficient resources.");
        goto Exit;
    }

    RtlZeroMemory(CallbackCtx, sizeof(REGFLT_CALLBACK_CONTEXT));

    CallbackCtx->ProcessId = PsGetCurrentProcessId();

    Status = RtlStringCbPrintfW(CallbackCtx->AltitudeBuffer,
        MAX_ALTITUDE_BUFFER_LENGTH * sizeof(WCHAR),
        L"%s",
        AltitudeString);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("RtlStringCbPrintfW failed. Status 0x%x", Status);
        goto Exit;
    }

    RtlInitUnicodeString(&CallbackCtx->Altitude, CallbackCtx->AltitudeBuffer);

    Success = TRUE;

Exit:

    if (Success == FALSE) {
        if (CallbackCtx != NULL) {
            ExFreePoolWithTag(CallbackCtx, REGFLTR_CONTEXT_POOL_TAG);
            CallbackCtx = NULL;
        }
    }

    return CallbackCtx;

}

/*++

Routine Description:

    Utility method to delete a callback context.

Arguments:

    CallbackCtx - the callback context to insert

Return Value:

    None

--*/
VOID
DeleteCallbackContext(
    _In_ PREGFLT_CALLBACK_CONTEXT CallbackCtx
    )
{

    if (CallbackCtx != NULL) {
        ExFreePoolWithTag(CallbackCtx, REGFLTR_CONTEXT_POOL_TAG);
    }

}

/*++

Routine Description:

    Registers a callback with the specified callback mode and altitude

Arguments:

    DeviceObject - The device object receiving the request.

Return Value:

    Status from CmRegisterCallbackEx

--*/
NTSTATUS
RegisterRegFltCallback(
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PREGFLT_CALLBACK_CONTEXT CallbackCtx = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);

    KdPrint(("[%s] Entry point\n", __FUNCTION__));

    //
    // Create the callback context from the specified callback mode and altitude
    //

    CallbackCtx = CreateCallbackContext(CALLBACK_HIGH_ALTITUDE);

    if (CallbackCtx == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    // 
    // Save the callback context in device extension of the target driver
    //

    //
    // Register the callback
    //

    Status = CmRegisterCallbackEx(VmDetectorRegFilterCallback,
        &CallbackCtx->Altitude,
        DeviceObject->DriverObject,
        (PVOID)CallbackCtx,
        &CallbackCtx->Cookie,
        NULL);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmRegisterCallback failed. Status 0x%x", Status);
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(Status)) {
        ErrorPrint("RegisterCallback failed. Status 0x%x", Status);
        if (CallbackCtx != NULL) {
            DeleteCallbackContext(CallbackCtx);
        }
    }
    else {
        InfoPrint("RegisterCallback succeeded");
    }

    return Status;
}



/*++

Routine Description:

    Unregisters a callback with the specified cookie and clean up the
    callback context.

Arguments:

    DeviceObject - The device object receiving the request.

Return Value:

    Status from CmUnRegisterCallback

--*/
NTSTATUS
UnRegisterFltCallback(
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PREGFLT_CALLBACK_CONTEXT CallbackCtx;

    UNREFERENCED_PARAMETER(DeviceObject);

    CallbackCtx = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->pRegFltCallbackCtx;
    ASSERT(CallbackCtx);

    //
    // Unregister the callback with the cookie
    //
    Status = CmUnRegisterCallback(CallbackCtx->Cookie);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmUnRegisterCallback failed. Status 0x%x", Status);
        goto Exit;
    }

    //
    // Free the callback context buffer
    //

    if (CallbackCtx != NULL) {
        DeleteCallbackContext(CallbackCtx);
    }

Exit:

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("UnRegisterCallback failed. Status 0x%x", Status);
    }
    else {
        InfoPrint("UnRegisterCallback succeeded");
    }
    InfoPrint("");

    return Status;

}
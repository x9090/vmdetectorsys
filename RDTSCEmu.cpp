///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2009 - <company name here>
///
/// Original filename: RDTSCEmu.c
/// Project          : RDTSCEmu
/// Date of creation : 2009-01-01
/// Author(s)        : Jan Newger
/// Ref				 : http://newgre.net/node/65
///
/// Purpose          : Turns RDTS into a priv. instruction; fakes return values
///
/// Revisions:
///  0000 [2009-01-01] Initial revision.
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifdef __cplusplus
extern "C" {
#endif
#include <Fltkernel.h>
#ifdef __cplusplus
}; // extern "C"
#endif

#include <stdlib.h>
#include "VmDetectorSys.h"
#include "RDTSCEmu.h"
#include "distorm\distorm.h"
#include "HookInt.h"

#pragma comment(lib, "distorm\\distorm.lib")

#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif

#ifdef __cplusplus
}; // anonymous namespace
#endif

// mov eax, cr4
#define CR4_TO_EAX		__asm _emit 0x0F \
						__asm _emit 0x20 \
						__asm _emit 0xE0

// mov cr4, eax
#define EAX_TO_CR4		__asm _emit 0x0F \
						__asm _emit 0x22 \
						__asm _emit 0xE0

// Set TSD
#define SET_TSD_EAX		__asm or	eax, 4

// Unset TSD
#define CLR_TSD_EAX		__asm and	eax, 0xFFFFFFFB

#define ENABLE_TSD		CR4_TO_EAX	\
						SET_TSD_EAX \
						EAX_TO_CR4

#define CLEAR_TSD		CR4_TO_EAX	\
						CLR_TSD_EAX \
						EAX_TO_CR4

#define MAX_CPUS		(32)
#define MAX_INSTR		(15)

// MSR index to Time-stamp counter (TSC)
// Ref: https://github.com/ianw/vmware-workstation-7/blob/master/vmmon-only/include/x86msr.h
#define MSR_TSC 0x10

// valid for all exceptions with an associated error code (see Intel manuals Vol.3A, 5.13)
typedef struct
{
	ULONG errorCode;
	ULONG eip;
	ULONG cs;
	ULONG eflags;
	ULONG esp;
	ULONG ss;
} STACK_WITHERR;

// integer register context and segment selectors
typedef struct
{
	ULONG gs;
	ULONG fs;
	ULONG es;
	ULONG ds;
	ULONG edi;
	ULONG esi;
	ULONG ebp;
	ULONG esp;
	ULONG ebx;
	ULONG edx;
	ULONG ecx;
	ULONG eax;	
} CTX_SEL;

// represents the stack layout at interrupt handler entry after all registers and segment
// selectors have been saved
typedef struct  
{
	CTX_SEL context;
	STACK_WITHERR origHandlerStack;
} STACK_WITHCTX, *PSTACK_WITHCTX;

UINT_PTR origHandlers[MAX_CPUS];
ERESOURCE g_ResourceEx;
BOOLEAN g_bRdtscHookedInstalled = FALSE;
INT g_NumberOfExclusionFile = 0;

FORCEINLINE 
VOID __declspec(naked) SetRDTSCValue(ULONGLONG *RdtscHolder)
{
	__asm
	{
		push    ebp
		mov     ebp, esp
		push	eax
		push	ecx
		push	edx
		mov     ecx, MSR_TSC
		rdmsr
		lea     ecx, RdtscHolder
		mov     ecx, [ecx]
		mov     dword ptr[ecx], eax
		mov     dword ptr[ecx + 4], edx
		pop     edx
		pop     ecx
		pop	    eax
		mov     esp, ebp
		pop	    ebp
		retn
	}
}

// returns length of instruction if it has been identified as RDTSC
ULONG isRDTSC(PVOID address)
{
	int RDTSCInstLen = 2;
	__try
	{
		_DecodedInst instructions[MAX_INSTR];
		unsigned int instructionCount;
		_DecodeResult res = distorm_decode(0, (const unsigned char*)address, RDTSCInstLen, Decode32Bits, instructions, MAX_INSTR, &instructionCount);
		if (res)
		{
			return strcmp((const char*)instructions->mnemonic.p, "RDTSC") ? 0 : instructions->size;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return 0;
}

VOID enterCriticalRegion(KIRQL OldIrql)
{
	if (OldIrql >= DISPATCH_LEVEL)
		KeLowerIrql(APC_LEVEL);
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceEx, TRUE);
}

VOID leaveCriticalRegion(KIRQL OldIrql)
{
	if (KeGetCurrentIrql() == APC_LEVEL)
		KeRaiseIrql(OldIrql, &OldIrql);
	ExReleaseResourceLite(&g_ResourceEx);
	KeLeaveCriticalRegion();
}

// performs the actual emulation
// return false if original handler should be executed, true otherwise
ULONG randomnum = 0;
ULONGLONG g_currentReadRdtsc = 0;
ULONGLONG g_previousReadRdtsc = 0;
BOOLEAN __stdcall hookImplementation(PSTACK_WITHCTX stackLayout)
{
	int index;
	CHAR ImageName[_MAX_PATH];

	KIRQL OldIrql = KeGetCurrentIrql();
	enterCriticalRegion(OldIrql);
	if (MmIsAddressValid((PVOID)stackLayout->origHandlerStack.eip))
	{
		if (ULONG length = isRDTSC((PVOID)stackLayout->origHandlerStack.eip))
		{
			PUNICODE_STRING pImageName = GetProcessNameByPid(PsGetCurrentProcessId());
			//ANSI_STRING asImageName;

			// Return true to tell it is RDTSC instruction
			if (pImageName == NULL)
			{
				leaveCriticalRegion(OldIrql);
				return true;
			}

			// Process the exclusion first
			if (g_NumberOfExclusionFile > 0)
			{
				// Always initialize g_tempexclusionfilelist. When there is another thread executing this function,
				// the previous thread hasn't finished executing yet.
				// This caused g_tempexclusionfilelist always in an invalid pointer location
				// Get exclusive access to shared exclusion list
				g_tempexclusionfilelist = g_pExclusionList;
				RtlSecureZeroMemory(ImageName, _MAX_PATH);
				wcstombs(ImageName, pImageName->Buffer, _MAX_PATH);
				for (index=0; index < g_NumberOfExclusionFile;  index++)
				{
					__try{
						if (*g_tempexclusionfilelist == NULL || !MmIsAddressValid(*g_tempexclusionfilelist))
						{
							KdPrint(("[DBG] Exclusion list is empty.\n"));
							break;
						}
						else if (strstr(_strlwr(ImageName), _strlwr(*g_tempexclusionfilelist)) != NULL)
						{
							KdPrint(("[DBG] Excluded %wZ\n", pImageName));
							// Free allocated pool memory by kernel
							ExFreePoolWithTag(pImageName, SYS_TAG);
							pImageName = NULL;
							// We do not tamper the original value of EAX and EDX
							stackLayout->origHandlerStack.eip += length;
							leaveCriticalRegion(OldIrql);
							return true;
						}
						g_tempexclusionfilelist++;
					}
					__except(EXCEPTION_EXECUTE_HANDLER){
						KdPrint(("[DBG] Exclusion file list address: 0x%08x\n", g_pExclusionList));
						KdPrint(("[DBG] Current pointer to file list address: 0x%08x\n", g_tempexclusionfilelist));
						break;
					}
				}
			}
			DbgPrint("[%s] PID: %d (%wZ) called interrupt handler\n", __FUNCTION__, PsGetCurrentProcessId(), pImageName);

			// Free allocated pool memory by kernel
			if (pImageName != NULL)
				ExFreePoolWithTag(pImageName, SYS_TAG);
			
			// Other settings specified in vmdetector.ini will be processed here
			if (g_RTDSCEmuMethodIncreasing)
			{
				static ULONG seed = 0x666;
				ULONGLONG ulRealRdtscDelta = 0;

				// Get random number that is consistent through all subsequent RDTSC call
				if (g_RTDSCEmuDelta && randomnum == 0) 
					randomnum = RtlRandomEx(&seed) % g_RTDSCEmuDelta;

				// To circumvent the situation when there is a Sleep call
				// we need to check the delta RDTSC value to see if it's greater
				// than 0x00000001`00000000
				SetRDTSCValue(&g_currentReadRdtsc);
				ulRealRdtscDelta = g_currentReadRdtsc - g_previousReadRdtsc;
				KdPrint(("[%s] Current RDTSC: 0x%I64x, Previous RDTSC: 0x%I64x. Real RDTSC delta value : 0x%I64x\n", __FUNCTION__, g_currentReadRdtsc, g_previousReadRdtsc, ulRealRdtscDelta));
				g_previousReadRdtsc = g_currentReadRdtsc;

				// Get new lowest significant bytes of rdtsc value				
				g_RTDSCEmuRdtscvalue = g_RTDSCEmuRdtscvalue + (ULONG)randomnum;

				// There is probably Sleep call that caused a significant delta value
				// Let's adjust highest significant bit of RDTSC as well
				if ((ulRealRdtscDelta >> 32) >= 1)
				{
					// Cast 32-bit int to 64-bit int
					ULONGLONG ullrandomnum = randomnum;
					// Get new highest significant bytes of rdtsc value	
					g_RTDSCEmuRdtscvalue = g_RTDSCEmuRdtscvalue + (ullrandomnum << 32);
				}

				KdPrint(("[%s] g_RTDSCEmuDelta: 0x%x, randomnum: 0x%x, new rdtsc: 0x%I64x\n", __FUNCTION__, g_RTDSCEmuDelta, randomnum, g_RTDSCEmuRdtscvalue));

				stackLayout->context.eax = (ULONG)g_RTDSCEmuRdtscvalue;
				stackLayout->context.edx = (ULONG)(g_RTDSCEmuRdtscvalue >> 32);
			}
			else
			{
				stackLayout->context.eax = stackLayout->context.edx = g_RTDSCEmuConstValue;
			}
			// #GP is a fault, so the CPU would restart the faulting instruction
			// since we "handled" this exception, we need to skip it
			stackLayout->origHandlerStack.eip += length;
			leaveCriticalRegion(OldIrql);
			return true;
		}
	}
	leaveCriticalRegion(OldIrql);
	return false;
}

// stack layout at handler entry is reflected via the
// STACK_WITHERR structure (see Intel manuals Vol.3A, 5.12.1)
// after registers and segment selectors have been saved, the stack layout
// is equivalent to the STACK_WITHCTX structure
VOID __declspec(naked) hookStub()
{
	__asm
	{
		pushad
		push	ds
		push    es
		push    fs
		push    gs
		// set kernel mode selectors
		mov     ax, 0x23
		mov     ds, ax
		mov     es, ax
		mov     gs, ax
		mov     ax, 0x30
		mov     fs, ax

		push	esp
		call	hookImplementation
		cmp		al, 0
		jz		oldHandler // Not rdtsc

		pop		gs
		pop		fs
		pop		es
		pop		ds
		popad	
		// we need to remove the error code manually (see Intel manuals Vol.3A, 5.13)
		add		esp, 4
		iretd
		
		// just call first original handler
		oldHandler:
		//int		3
		pop		gs
		pop		fs
		pop		es
		pop		ds
		popad
		jmp		dword ptr [origHandlers]
	}
}

#ifdef __cplusplus
extern "C" {
#endif
BOOLEAN RDTSEMU_initializeHooks(ULONGLONG ullRtdscValue, ULONG ulRtdscValue, BOOLEAN bRtdscMethodIncreasing, PCHAR *pExclusionList, int CountExclusionFilename)
{

	KdPrint(("[%s] Entered\n", __FUNCTION__));
	if (ZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING routineName; 
		
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess"); 
		ZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS) MmGetSystemRoutineAddress(&routineName); 
		if (ZwQueryInformationProcess == NULL) 
		{	
			DbgPrint("[%s] Failed to get ZwQueryInformationProcess function address\n", __FUNCTION__);
			return false; 
		}
	}
	// Make sure either IOCTL_RDTSCEMU_METHOD_ALWAYS_CONST or IOCTL_RDTSCEMU_METHOD_INCREASING ctlcode has been sent 
	if (ullRtdscValue > 0 || ulRtdscValue > 0)
	{
		// Initialize the global variables
		g_RTDSCEmuMethodIncreasing = bRtdscMethodIncreasing;

		if (bRtdscMethodIncreasing)
		{
			g_RTDSCEmuRdtscvalue = ullRtdscValue;
			g_RTDSCEmuDelta = ulRtdscValue;
			if (g_previousReadRdtsc == 0)
				g_previousReadRdtsc = g_RTDSCEmuRdtscvalue;
		}
		else
			g_RTDSCEmuConstValue = ulRtdscValue;

		// Initialize exclusion parameters
		if (CountExclusionFilename > 0 && MmIsAddressValid(pExclusionList) && MmIsAddressValid(*pExclusionList))
		{
			g_tempexclusionfilelist = pExclusionList;
			g_pExclusionList = pExclusionList;
			g_NumberOfExclusionFile = CountExclusionFilename;
			g_exclusionparamset = true;
		}
		// Ref: http://newgre.net/node/65
		// Enable "timestamp disable" flag at CR4 ->
		// Call RDTSC from UM -> raised #GP (general protection fault) exception ->
		// IDT handler@#13 will be triggered ->
		// Call our replaced IDT handler -> *END*
		// load CR4 register into EAX, set TSD flag and update CR4 from EAX
		if (!g_bRdtscHookedInstalled)
		{
			for (CCHAR i = 0; i < KeNumberProcessors; ++i)
			{
				switchToCPU(i);
				hookInterrupt(hookStub, 0xD, &origHandlers[i]);
				ENABLE_TSD;
			}
			ExInitializeResourceLite(&g_ResourceEx);
			g_bRdtscHookedInstalled = TRUE;
		}
		return true;
	}
	else
		return false;
}

VOID RDTSEMU_removeHooks()
{
	if (g_bRdtscHookedInstalled)
	{
		for (CCHAR i = 0; i < KeNumberProcessors; ++i)
		{
			switchToCPU(i);
			CLEAR_TSD;
			hookInterrupt((PVOID)origHandlers[i], 0xD, NULL);
		}
		ExDeleteResourceLite(&g_ResourceEx);
	}
}

// Call ExFreePoolWithTag to free pImagePath
// Ref: http://www.osronline.com/showthread.cfm?link=183409
PUNICODE_STRING GetProcessNameByPid(HANDLE pid)
{
	HANDLE hProcessHandle;
	PEPROCESS pEproc = NULL;
	PUNICODE_STRING pImagePath = NULL;
	const ULONG uImageMaxPath = sizeof(UNICODE_STRING) + _MAX_PATH;
	ULONG retlen;
	ULONG ulBufferLength;
	WCHAR wImageNameBuffer[uImageMaxPath];
	NTSTATUS status = PsLookupProcessByProcessId(pid, &pEproc);

	if (status != STATUS_SUCCESS)
		return NULL;

	__try{

		status = ObOpenObjectByPointer(pEproc, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, NULL, KernelMode, &hProcessHandle);

		ObDereferenceObject(pEproc);

		if (!NT_SUCCESS(status))
			return NULL;

		RtlZeroMemory(wImageNameBuffer, uImageMaxPath);

		status = ZwQueryInformationProcess(hProcessHandle, ProcessImageFileName, &wImageNameBuffer, uImageMaxPath, &retlen);

		if (!NT_SUCCESS(status))
			return NULL;

		ZwClose(hProcessHandle);

		pImagePath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, retlen, SYS_TAG);

		if (pImagePath == NULL)
			return NULL;

		RtlSecureZeroMemory(pImagePath, retlen);
		pImagePath->Length = *(USHORT*)wImageNameBuffer;
		pImagePath->MaximumLength = *(USHORT*)wImageNameBuffer+2;
		pImagePath->Buffer = (PWCHAR)((PUCHAR)pImagePath + 0x8);
		RtlCopyUnicodeString(pImagePath, (UNICODE_STRING*)wImageNameBuffer);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		__asm{
			int 3
		}
		KdPrint(("[DBG] pImagePath: 0x%08x\n", pImagePath));
		KdPrint(("[DBG] wImageNameBuffer: 0x%08x\n", wImageNameBuffer));
	}

	return pImagePath;

}
#ifdef __cplusplus
}; // extern "C"
#endif

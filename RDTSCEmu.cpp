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

#define _MAX_PATH		1024
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

// returns length of instruction if it has been identified as RDTSC
ULONG isRDTSC(PVOID address)
{
	__try
	{
		_DecodedInst instructions[MAX_INSTR];
		unsigned int instructionCount;
		_DecodeResult res = distorm_decode(0, (const unsigned char*)address, MAX_INSTR, Decode32Bits, instructions, MAX_INSTR, &instructionCount);
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

// performs the actual emulation
// return false if original handler should be executed, true otherwise
ULONG randomnum = 0;
BOOLEAN __stdcall hookImplementation(PSTACK_WITHCTX stackLayout)
{
	
	PUNICODE_STRING pImageName = GetProcessNameByPid(PsGetCurrentProcessId());
	ANSI_STRING asImageName; 
	int index;

	// Always initialize g_tempexclusionfilelist. When there is another thread executing this function,
	// the previous thread hasn't finished executing yet.
	// This caused g_tempexclusionfilelist always in an invalid pointer location
	g_tempexclusionfilelist = g_pExclusionList;

	if (MmIsAddressValid((PVOID)stackLayout->origHandlerStack.eip))
	{
		if (ULONG length = isRDTSC((PVOID)stackLayout->origHandlerStack.eip))
		{
			// Process the exclusion first
			if (g_countfilename > 0)
			{
				RtlUnicodeStringToAnsiString(&asImageName, pImageName, TRUE);
				for (index=0; index < g_countfilename;  index++)
				{
					__try{
						if (strstr(_strlwr(asImageName.Buffer), _strlwr(*g_tempexclusionfilelist)) != NULL)
						{
							KdPrint(("[DBG] Excluded %wZ\n", pImageName));
							// Free ANSI string allocated by kernel
							RtlFreeAnsiString(&asImageName);
							// Free allocated pool memory by kernel
							ExFreePoolWithTag(pImageName, 'vmde');
							// We do not tamper the original value of EAX and EDX
							stackLayout->origHandlerStack.eip += length;
							return true;
						}
						g_tempexclusionfilelist++;
					}
					__except(EXCEPTION_EXECUTE_HANDLER){
						KdPrint(("[DBG] Exclusion file list address: 0x%08x\n", g_pExclusionList));
						KdPrint(("[DBG] Current pointer to file list address: 0x%08x\n", g_tempexclusionfilelist));
						KdPrint(("[DBG] asImageName.Buffer address: 0x%08x\n", asImageName.Buffer));
						break;
					}
				}
				// Free ANSI string allocated by kernel
				RtlFreeAnsiString(&asImageName);
			}

			DbgPrint("[hookImplementation] PID: %d (%wZ) called interrupt handler\n", PsGetCurrentProcessId(), pImageName);

			// Free allocated pool memory by kernel
			ExFreePoolWithTag(pImageName, 'vmde');
			
			// Other settings specified in vmdetector.ini will be processed here
			if (g_RTDSCEmuMethodIncreasing)
			{
				static ULONG seed = 0x666;
				ULONG edx = (ULONG)(g_RTDSCEmuRdtscvalue >> 32);

				// Get random number that is consistent through all subsequent RDTSC call
				if (g_RTDSCEmuDelta && randomnum == 0) 
					randomnum = RtlRandomEx(&seed) % g_RTDSCEmuDelta;

				// Get new lowest significant bytes of rdtsc value				
				g_RTDSCEmuRdtscvalue = g_RTDSCEmuRdtscvalue + (ULONG)randomnum;
				// Cast 32-bit int to 64-bit int
				ULONGLONG ullrandomnum = randomnum;
				// Get new highest significant bytes of rdtsc value	
				g_RTDSCEmuRdtscvalue = g_RTDSCEmuRdtscvalue + (ullrandomnum << 32);

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

			return true;
		}
	}
	
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
	
	if (ZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING routineName; 
		
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess"); 
		ZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS) MmGetSystemRoutineAddress(&routineName); 
		if (ZwQueryInformationProcess == NULL) 
		{	
			DbgPrint("[RDTSEMU_initializeHooks] Failed to get ZwQueryInformationProcess function address\n");
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
		}
		else
			g_RTDSCEmuConstValue = ulRtdscValue;

		// Initialize exclusion parameters
		if (CountExclusionFilename > 0 && MmIsAddressValid(pExclusionList) && MmIsAddressValid(*pExclusionList))
		{
			g_tempexclusionfilelist = pExclusionList;
			g_pExclusionList = pExclusionList;
			g_countfilename = CountExclusionFilename;
			g_exclusionparamset = true;
		}
		// Ref: http://newgre.net/node/65
		// Enable "timestamp dsiable" flag at CR4 ->
		// Call RDTSC from UM -> raised #GP (general protection fault) exception ->
		// IDT handler@#13 will be triggered ->
		// Call our replaced IDT handler -> *END*
		// load CR4 register into EAX, set TSD flag and update CR4 from EAX
		for (CCHAR i=0; i<KeNumberProcessors; ++i)
		{
			switchToCPU(i);
			hookInterrupt(hookStub, 0xD, &origHandlers[i]);
			ENABLE_TSD;
		}
		return true;
	}
	else
		return false;
}

VOID RDTSEMU_removeHooks()
{
	for (CCHAR i=0; i<KeNumberProcessors; ++i)
	{
		switchToCPU(i);
		CLEAR_TSD;
		hookInterrupt((PVOID)origHandlers[i], 0xD, NULL);
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

		if (status != STATUS_SUCCESS)
			return NULL;

		RtlZeroMemory(wImageNameBuffer, uImageMaxPath);

		status = ZwQueryInformationProcess(hProcessHandle, ProcessImageFileName, &wImageNameBuffer, uImageMaxPath, &retlen);

		if (status != STATUS_SUCCESS)
			return NULL;

		ZwClose(hProcessHandle);

		pImagePath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, retlen, 'vmde');

		if (pImagePath == NULL)
			return NULL;

		pImagePath->Length = *(USHORT*)wImageNameBuffer;
		pImagePath->MaximumLength = *(USHORT*)wImageNameBuffer+2;

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

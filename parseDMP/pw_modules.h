#ifndef	_PW_MODULES_H_
#define _PW_MODULES_H_

#include "all.h"
#include <Winldap.h>
#include <Winber.h>

#include <dbghelp.h>
#include <io.h>
#include <fcntl.h>
#include <userenv.h>
#include "pw_string.h"

//asn1
BOOL pw_m_asn1_init();
void pw_m_asn1_term();

//crypto
typedef struct _MPW_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY];
} MPW_HARD_KEY, * PMPW_HARD_KEY;

typedef struct _MPW_BCRYPT_KEY {
	ULONG size;
	ULONG tag;
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	MPW_HARD_KEY hardkey;
} MPW_BCRYPT_KEY, * PMPW_BCRYPT_KEY;

//crypto system

#define SHA_DIGEST_LENGTH	20

typedef struct _SHA_CTX {
	BYTE buffer[64];
	DWORD state[5];
	DWORD count[2];
	DWORD unk[6];
} SHA_CTX, * PSHA_CTX;

typedef struct _SHA_DIGEST {
	BYTE digest[SHA_DIGEST_LENGTH];
} SHA_DIGEST, * PSHA_DIGEST;

EXTERN_C VOID WINAPI A_SHAInit(PSHA_CTX pCtx);
EXTERN_C VOID WINAPI A_SHAUpdate(PSHA_CTX pCtx, LPCVOID data, DWORD cbData);
EXTERN_C VOID WINAPI A_SHAFinal(PSHA_CTX pCtx, PSHA_DIGEST pDigest);

//mini

typedef struct _PW_M_MINIDUMP_HANDLE {
	HANDLE hFileMapping;
	LPVOID pMapViewOfFile;
} PW_M_MINIDUMP_HANDLE, * PPW_M_MINIDUMP_HANDLE;

BOOL pw_m_minidump_open(IN HANDLE hFile, OUT PPW_M_MINIDUMP_HANDLE* hMinidump);
BOOL pw_m_minidump_close(IN PPW_M_MINIDUMP_HANDLE hMinidump);
BOOL pw_m_minidump_copy(IN PPW_M_MINIDUMP_HANDLE hMinidump, OUT VOID* Destination, IN VOID* Source, IN SIZE_T Length);

LPVOID pw_m_minidump_RVAtoPTR(IN PPW_M_MINIDUMP_HANDLE hMinidump, RVA64 rva);
LPVOID pw_m_minidump_stream(IN PPW_M_MINIDUMP_HANDLE hMinidump, MINIDUMP_STREAM_TYPE type, OUT OPTIONAL DWORD* pSize);
LPVOID pw_m_minidump_remapVirtualMemory64(IN PPW_M_MINIDUMP_HANDLE hMinidump, IN VOID* Source, IN SIZE_T Length);


//memory

typedef enum _PW_M_MEMORY_TYPE
{
	PW_M_MEMORY_TYPE_OWN,
	PW_M_MEMORY_TYPE_PROCESS_DMP,
} PW_M_MEMORY_TYPE;

typedef struct _PW_M_MEMORY_HANDLE_PROCESS_DMP
{
	PPW_M_MINIDUMP_HANDLE hMinidump;
} PW_M_MEMORY_HANDLE_PROCESS_DMP, * PPW_M_MEMORY_HANDLE_PROCESS_DMP;

typedef struct _PW_M_MEMORY_HANDLE {
	PW_M_MEMORY_TYPE type;
	union {
		PPW_M_MEMORY_HANDLE_PROCESS_DMP pHandleProcessDmp;
	};
} PW_M_MEMORY_HANDLE, * PPW_M_MEMORY_HANDLE;
extern PW_M_MEMORY_HANDLE PW_M_MEMORY_GLOBAL_OWN_HANDLE;

typedef struct _PW_M_MEMORY_ADDRESS {
	LPVOID address;
	PPW_M_MEMORY_HANDLE hMemory;
} PW_M_MEMORY_ADDRESS, * PPW_M_MEMORY_ADDRESS;

typedef struct _PW_M_MEMORY_RANGE {
	PW_M_MEMORY_ADDRESS pw_m_memoryAdress;
	SIZE_T size;
} PW_M_MEMORY_RANGE, * PPW_M_MEMORY_RANGE;

typedef struct _PW_M_MEMORY_SEARCH {
	PW_M_MEMORY_RANGE pw_m_memoryRange;
	LPVOID result;
} PW_M_MEMORY_SEARCH, * PPW_M_MEMORY_SEARCH;

BOOL pw_m_memory_copy(OUT PPW_M_MEMORY_ADDRESS Destination, IN PPW_M_MEMORY_ADDRESS Source, IN SIZE_T Length);
BOOL pw_m_memory_search(IN PPW_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PPW_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst);

BOOL pw_m_memory_open(IN PW_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PPW_M_MEMORY_HANDLE* hMemory);
PPW_M_MEMORY_HANDLE pw_m_memory_close(IN PPW_M_MEMORY_HANDLE hMemory);


//patch

typedef struct _PW_M_PATCH_PATTERN {
	DWORD Length;
	BYTE* Pattern;
} PW_M_PATCH_PATTERN, * PPW_M_PATCH_PATTERN;

typedef struct _PW_M_PATCH_OFFSETS {
	LONG off0;

	LONG off1;

	LONG off2;

	LONG off3;

	LONG off4;

	LONG off5;

	LONG off6;

	LONG off7;

	LONG off8;

	LONG off9;

} PW_M_PATCH_OFFSETS, * PPW_M_PATCH_OFFSETS;

typedef struct _PW_M_PATCH_GENERIC {
	DWORD MinBuildNumber;
	PW_M_PATCH_PATTERN Search;
	PW_M_PATCH_PATTERN Patch;
	PW_M_PATCH_OFFSETS Offsets;
} PW_M_PATCH_GENERIC, * PPW_M_PATCH_GENERIC;

PPW_M_PATCH_GENERIC pw_m_patch_getGenericFromBuild(PPW_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber);


//process

#if !defined(__MACHINE)
#define __MACHINE(X)	X;
#endif
#if !defined(__MACHINEX86)
#define __MACHINEX86	__MACHINE
#endif

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	MPW_SystemPowerInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	MPW_SystemMmSystemRangeStart = 50,
	SystemIsolatedUserModeInformation = 165
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef LONG KPRIORITY;

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS* PVM_COUNTERS;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef enum _KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	MaximumWaitReason
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD {
#if !defined(_M_X64)
	LARGE_INTEGER KernelTime;
#endif
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG State;
	KWAIT_REASON WaitReason;
#if defined(_M_X64) 
	LARGE_INTEGER unk;
#endif
} SYSTEM_THREAD, * PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE ParentProcessId;
	ULONG HandleCount;
	LPCWSTR Reserved2[2];
	ULONG PrivatePageCount;
	VM_COUNTERS VirtualMemoryCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD Threads[ANYSIZE_ARRAY];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModulevector;
	LIST_ENTRY InMemoryOrderModulevector;
	LIST_ENTRY InInitializationOrderModulevector;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	struct BitField {
		BYTE ImageUsesLargePages : 1;
		BYTE SpareBits : 7;
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

} PEB, * PPEB;

#if defined(_M_X64)
typedef struct _LSA_UNICODE_STRING_F32 {
	USHORT Length;
	USHORT MaximumLength;
	DWORD  Buffer;
} LSA_UNICODE_STRING_F32, * PLSA_UNICODE_STRING_F32;

typedef LSA_UNICODE_STRING_F32 UNICODE_STRING_F32, * PUNICODE_STRING_F32;

typedef struct _LDR_DATA_TABLE_ENTRY_F32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	DWORD DllBase;
	DWORD EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING_F32 FullDllName;
	UNICODE_STRING_F32 BaseDllName;
	/// ...
} LDR_DATA_TABLE_ENTRY_F32, * PLDR_DATA_TABLE_ENTRY_F32;

typedef struct _PEB_LDR_DATA_F32 {
	ULONG Length;
	BOOLEAN Initialized;
	DWORD SsHandle;
	LIST_ENTRY32 InLoadOrderModulevector;
	LIST_ENTRY32 InMemoryOrderModulevector;
	LIST_ENTRY32 InInitializationOrderModulevector;
} PEB_LDR_DATA_F32, * PPEB_LDR_DATA_F32;

typedef struct _PEB_F32 {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	struct BitField_F32 {
		BYTE ImageUsesLargePages : 1;
		BYTE SpareBits : 7;
	};
	DWORD Mutant;
	DWORD ImageBaseAddress;
	DWORD Ldr;
	/// ...
} PEB_F32, * PPEB_F32;
#endif

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) \
    { sizeof(OBJECT_ATTRIBUTES), NULL, RTL_CONST_CAST(PUNICODE_STRING)(n), a, NULL, NULL }

#define RTL_INIT_OBJECT_ATTRIBUTES(n, a) RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)


typedef NTSTATUS(WINAPI* PNTQUERYSYSTEMINFORMATIONEX) (SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength);

typedef struct _PW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION {
	PW_M_MEMORY_ADDRESS DllBase;
	ULONG SizeOfImage;
	ULONG TimeDateStamp;
	PCUNICODE_STRING NameDontUseOutsideCallback;
} PW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION, * PPW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION;


typedef BOOL(CALLBACK* PPW_M_PROCESS_ENUM_CALLBACK) (PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);


typedef BOOL(CALLBACK* PPW_M_MODULE_ENUM_CALLBACK) (PPW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
NTSTATUS pw_m_process_getVeryBasicModuleInformations(PPW_M_MEMORY_HANDLE memory, PPW_M_MODULE_ENUM_CALLBACK callBack, PVOID pvArg);


BOOL pw_m_process_getUnicodeString(IN PUNICODE_STRING string, IN PPW_M_MEMORY_HANDLE source);
BOOL pw_m_process_getSid(IN PSID* pSid, IN PPW_M_MEMORY_HANDLE source);



#endif
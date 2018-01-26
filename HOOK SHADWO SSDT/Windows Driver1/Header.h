#ifndef HEADER_H
#define HEADER_H

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>

typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;						//ServiceTable���ĸ�Ԫ��

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef UINT_PTR(*NTUSERQUERYWINDOW)(
	IN ULONG WindowHandle,
	IN ULONG TypeInformation);									//�������û��Ҫhook�����������ж���ǰ��hwnd��������Ľ���pid

typedef NTSTATUS(*NTUSERBUILDdHWNDLIST)(
	IN HDESK hdesk,
	IN HWND hwndNext,
	IN BOOL fEnumChildren,
	IN DWORD idThread,
	IN UINT cHwndMax,
	OUT HWND *phwndFirst,
	OUT PUINT pcHwndNeeded);									//r3����EnumWindows�����������Ҫ���������������ʾ�Ĵ���

typedef NTSTATUS
(*ZWQUERYSYSTEMINFORMATION)(
__in ULONG SystemInformationClass,
__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
__in ULONG SystemInformationLength,
__out_opt PULONG ReturnLength
);

//�����¼�����
extern UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);;

#endif
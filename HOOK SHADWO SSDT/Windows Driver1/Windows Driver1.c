#include "Header.h"

ULONG old_NtUserQueryWindow = 0;
ULONG old_NtUserBuildHwndList = 0;

ULONG CalcPid = 0;
PEPROCESS Csrss = NULL;

PServiceDescriptorTableEntry_t KeShadowSSDT;					//Shadow SSDT

NTSTATUS MyNtUserBuildHwndList(
	IN HDESK hdesk,
	IN HWND hwndNext,
	IN BOOL fEnumChildren,
	IN DWORD idThread,
	IN UINT cHwndMax,
	OUT HWND *phwndFirst,
	OUT PUINT pcHwndNeeded)
{
	ULONG CurrentPid;

	NTSTATUS status;

	ULONG i = 0;

	ULONG j = 0;

	status = ((NTUSERBUILDdHWNDLIST)(old_NtUserBuildHwndList))(
			hdesk,
			hwndNext,
			fEnumChildren,
			idThread,
			cHwndMax,
			phwndFirst,
			pcHwndNeeded);

	if (!NT_SUCCESS(status))
		return status;

	while (i < *pcHwndNeeded)
	{
		CurrentPid = ((NTUSERQUERYWINDOW)(old_NtUserQueryWindow))((ULONG)phwndFirst[i], 0);

		//这里最初犯了一个错误，这个所有的句柄数组并不是仅仅包括主窗口句柄，还有可能是主窗口句柄的子句柄，因此一定要循环到最后，否则有可能存在你的子窗口句柄没有屏蔽处理的情况
		if (CurrentPid == CalcPid)										//如果当前的窗口句柄是想要屏蔽的
		{
			j = i;														

			while (j < *pcHwndNeeded - 1)								//就把后面所有句柄都往前移动一个格子，然后把所有句柄的数量减一
			{
				phwndFirst[j] = phwndFirst[j + 1];
				++j;
			}

			(*pcHwndNeeded)--;

			phwndFirst[*pcHwndNeeded] = NULL;

			--i;														//因为我们强制的把后面所有标号都往前位移了一下，因此这里需要减一次i来平衡一下（比如原本处理第5个，发现第5个需要屏蔽，因此从5开始后面每次都向前移动移位，实际上5是以前的6）
		}
		++i;
	}

	return status;
}

/*获取SHADOW SSDT表的基址*/
ULONG GetShadowTable()
{
	UNICODE_STRING n_AddServiceTable;

	ULONG KeServiceDescriptorTableShadow = 0;

	ULONG u_AddServiceTable;				//拿一下这个函数，然后通过硬编码找Shadow SSDT函数地址了。

	UCHAR *b0, *b1, *b2, *b3;

	ULONG i;

	RtlInitUnicodeString(&n_AddServiceTable, L"KeAddSystemServiceTable");

	u_AddServiceTable = (ULONG)MmGetSystemRoutineAddress(&n_AddServiceTable);

	//KdPrint(("KeAddSystemServiceTable Address is %x\n", u_AddServiceTable));

	for (i = u_AddServiceTable; i < u_AddServiceTable + 500; ++i)
	{
		b0 = (UCHAR*)i;
		b1 = (UCHAR*)(i + 1);
		b2 = (UCHAR*)(i + 2);
		b3 = (UCHAR*)(i + 3);

		//这里原本应该用MmIsAddressValid判断地址是否有效，太麻烦了，懒得写了
		if (*b0 == 0x75 && *b1 == 0x51 && *b2 == 0x8d && *b3 == 0x88)				//win7 *32硬编码找出来的，但是SHADOW SSDT表的第一项是SSDT因此实际上还需要加一个SSDT的地址
		{
			KeServiceDescriptorTableShadow = *(ULONG*)(b0 + 4);
			break;
		}
	}
	//KdPrint(("KeServiceDescriptorTableShadow Address is %x\n", KeServiceDescriptorTableShadow));

	return KeServiceDescriptorTableShadow;
}

void PageProtectOff()
{
	_asm
	{
		cli;
		mov eax, cr0;
		and eax, not 10000h;
		mov cr0, eax;
	}
}

void PageProtectOn()
{
	_asm
	{
		mov eax, cr0;
		or eax, 10000h;
		mov cr0, eax;
		sti;
	}
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KAPC_STATE ApcState;

	if (CalcPid != 0 && Csrss != NULL)
	{
		PageProtectOff();
		KeStackAttachProcess(Csrss, &ApcState);
		KeShadowSSDT->ServiceTableBase[323] = old_NtUserBuildHwndList;
		KeUnstackDetachProcess(&ApcState);
		PageProtectOn();
	}

	KdPrint(("Unload Success!\n"));
}

//找到calc的pid和csrss的eprocess
BOOLEAN FindCalc()
{
	UNICODE_STRING n_ZwQuersySystemInformation;
	ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
	SYSTEM_PROCESS_INFORMATION *ProcessInformation;
	SYSTEM_PROCESS_INFORMATION *temp;
	ULONG_PTR RetLength;
	PEPROCESS TempProcess;
	NTSTATUS status;

	RtlInitUnicodeString(&n_ZwQuersySystemInformation, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&n_ZwQuersySystemInformation);

	if (ZwQuerySystemInformation == NULL)
	{
		KdPrint(("Get Function Fail!"));
		return FALSE;
	}

	status = ZwQuerySystemInformation(5, NULL, 0, &RetLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		KdPrint(("ZwQuerySystemInformation Fail!\n"));
		return FALSE;
	}

	ProcessInformation = (SYSTEM_PROCESS_INFORMATION *)ExAllocatePoolWithTag(NonPagedPool, RetLength, 'ytz');
	status = ZwQuerySystemInformation(5, ProcessInformation, RetLength, &RetLength);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwQuerySystemInformation Fail!\n"));
		return FALSE;
	}

	temp = ProcessInformation;
	while (TRUE)
	{
		if (temp->NextEntryDelta == 0)
			break;

		if (temp->ProcessId == 0 || temp->ProcessId == 4)				//0和4是Idle和System，直接跳过
		{
			temp = (SYSTEM_PROCESS_INFORMATION *)((char*)temp + temp->NextEntryDelta);
			continue;
		}

		status = PsLookupProcessByProcessId((HANDLE)temp->ProcessId, &TempProcess);
		if (!NT_SUCCESS(status))
		{
			temp = (SYSTEM_PROCESS_INFORMATION *)((char*)temp + temp->NextEntryDelta);
			continue;
		}

		ObDereferenceObject(TempProcess);

		if (strstr(PsGetProcessImageFileName(TempProcess), "csrss"))
			Csrss = TempProcess;

		if (strstr(PsGetProcessImageFileName(TempProcess), "calc"))
			CalcPid = temp->ProcessId;

		temp = (SYSTEM_PROCESS_INFORMATION *)((char*)temp + temp->NextEntryDelta);
	}

	ExFreePoolWithTag(ProcessInformation, 'ytz');

	if (Csrss == NULL || CalcPid == 0)
	{
		if (Csrss == NULL)
			KdPrint(("没找到csrss！\n"));
		if (CalcPid == 0)
			KdPrint(("没找到calc！\n"));

		return FALSE;
	}

	return TRUE;
}

/*隐藏窗口*/
VOID HideWindow()
{
	ULONG t = GetShadowTable();

	ULONG i = 0;

	KAPC_STATE ApcState;

	if (t == 0)
		return;

	KeShadowSSDT = (PServiceDescriptorTableEntry_t)t + 1;								//知识点知识点，Shadow Table是在KeServiceDescriptorTableShadow的第二个数组，第一个依然是SSDT

	//KdPrint(("ShadowSSDT Base is %x\n", (ULONG)KeShadowSSDT->ServiceTableBase));

	PageProtectOff();

	KeStackAttachProcess(Csrss, &ApcState);

	old_NtUserQueryWindow = (ULONG)KeShadowSSDT->ServiceTableBase[515];

	old_NtUserBuildHwndList = (ULONG)KeShadowSSDT->ServiceTableBase[323];

	KeShadowSSDT->ServiceTableBase[323] = (ULONG)MyNtUserBuildHwndList;

	KeUnstackDetachProcess(&ApcState);

	PageProtectOn();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));

	if (!FindCalc())
		return STATUS_UNSUCCESSFUL;
	
	HideWindow();

	DriverObject->DriverUnload = Unload;

	return STATUS_SUCCESS;
}
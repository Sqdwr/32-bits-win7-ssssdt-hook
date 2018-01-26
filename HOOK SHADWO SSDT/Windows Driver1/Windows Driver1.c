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

		//�����������һ������������еľ�����鲢���ǽ������������ھ�������п����������ھ�����Ӿ�������һ��Ҫѭ������󣬷����п��ܴ�������Ӵ��ھ��û�����δ�������
		if (CurrentPid == CalcPid)										//�����ǰ�Ĵ��ھ������Ҫ���ε�
		{
			j = i;														

			while (j < *pcHwndNeeded - 1)								//�ͰѺ������о������ǰ�ƶ�һ�����ӣ�Ȼ������о����������һ
			{
				phwndFirst[j] = phwndFirst[j + 1];
				++j;
			}

			(*pcHwndNeeded)--;

			phwndFirst[*pcHwndNeeded] = NULL;

			--i;														//��Ϊ����ǿ�ƵİѺ������б�Ŷ���ǰλ����һ�£����������Ҫ��һ��i��ƽ��һ�£�����ԭ�������5�������ֵ�5����Ҫ���Σ���˴�5��ʼ����ÿ�ζ���ǰ�ƶ���λ��ʵ����5����ǰ��6��
		}
		++i;
	}

	return status;
}

/*��ȡSHADOW SSDT��Ļ�ַ*/
ULONG GetShadowTable()
{
	UNICODE_STRING n_AddServiceTable;

	ULONG KeServiceDescriptorTableShadow = 0;

	ULONG u_AddServiceTable;				//��һ�����������Ȼ��ͨ��Ӳ������Shadow SSDT������ַ�ˡ�

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

		//����ԭ��Ӧ����MmIsAddressValid�жϵ�ַ�Ƿ���Ч��̫�鷳�ˣ�����д��
		if (*b0 == 0x75 && *b1 == 0x51 && *b2 == 0x8d && *b3 == 0x88)				//win7 *32Ӳ�����ҳ����ģ�����SHADOW SSDT��ĵ�һ����SSDT���ʵ���ϻ���Ҫ��һ��SSDT�ĵ�ַ
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

//�ҵ�calc��pid��csrss��eprocess
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

		if (temp->ProcessId == 0 || temp->ProcessId == 4)				//0��4��Idle��System��ֱ������
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
			KdPrint(("û�ҵ�csrss��\n"));
		if (CalcPid == 0)
			KdPrint(("û�ҵ�calc��\n"));

		return FALSE;
	}

	return TRUE;
}

/*���ش���*/
VOID HideWindow()
{
	ULONG t = GetShadowTable();

	ULONG i = 0;

	KAPC_STATE ApcState;

	if (t == 0)
		return;

	KeShadowSSDT = (PServiceDescriptorTableEntry_t)t + 1;								//֪ʶ��֪ʶ�㣬Shadow Table����KeServiceDescriptorTableShadow�ĵڶ������飬��һ����Ȼ��SSDT

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
#include "pack.h"
//����������ݶκϲ���һ��
#pragma comment(linker, "/merge:.data=.text")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
 void packStart();
PACKINFO g_PackInfo = {(DWORD)packStart};
DWORD GetImportantModule()
{
	DWORD dwBase = 0;
	_asm
	{
		mov eax,DWORD ptr fs:[0x30]
		mov eax, DWORD ptr [eax + 0xC]
		mov eax,DWORD ptr [eax + 0x1C]
		mov eax,[eax]
		mov eax,DWORD ptr[eax + 0x8]
		mov dwBase,eax
	}
	return dwBase;
}
DWORD MyGetProcAddress(DWORD hModule, LPCSTR funName)
{
	//��ȡDOSͷNtͷ
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + hModule);
	//��ȡ������
	DWORD exportTableVa = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(exportTableVa + hModule);
	//�ҵ��������Ʊ���ű���ַ��
	DWORD* nameTable = (DWORD*)(exportTable->AddressOfNames + hModule);
	DWORD* funTable = (DWORD*)(exportTable->AddressOfFunctions + hModule);
	WORD* numberTable = (WORD*)(exportTable->AddressOfNameOrdinals + hModule);
	for (int i = 0; i < exportTable->NumberOfNames; i++)
	{
		char* name = (char*)(nameTable[i] + hModule);
		if (!strcmp(name, funName))
		{
			return funTable[numberTable[i]] + hModule;
		}
	}
	return 0;
}
void GetFunctions()
{
	//1����ȡkernel32����kernelbaseģ��
	DWORD pKernelBase = GetImportantModule();
	//��ȡLoadLibraryExA
	MyGetProcAddress(pKernelBase, "Load");
}
BOOL DecodeSections()
{
	int key = 0x51;
	return true;
}
_declspec(naked) void packStart()
{

}
#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>
DWORD g_Var = 0x12345678;
int main()
{
	const char* fileName = R"(C:\Users\stdio\source\repos\PECon\Debug\PEDll.dll)";
	HMODULE hmodule = LoadLibraryA(fileName);
	FARPROC farproc = GetProcAddress(hmodule, (LPCSTR)2);

	return 0;
}
#include "dll.h"
#pragma comment(linker, "/INCLUDE:__tls_used")//��֪��������Ҫʹ��TLS
DWORD g_var = 0x12345678;
__declspec(thread) int g_tls = 0x1234;
__declspec(thread) int g_tls2 = 0x110;
//TLS�ص�����
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Context)
{
	_asm
	{
		mov eax, 110
	}
}
void NTAPI TlsCallback2(PVOID DllHandle, DWORD Reason, PVOID Context)
{
	_asm
	{
		mov eax, 0x110
	}
}
//����TLS�ص��������飬�������.data��
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK pTlsCallbacks[] = { TlsCallback, TlsCallback2 };
#pragma data_seg()
int Add(int a, int b)
{
	g_tls++;
	g_var = 0x110;
	return a + b;
}
int Sub(int a, int b)
{
	return a - b;
}
int Mul(int a, int b)
{
	return a * b;
}
int Div(int a, int b)
{
	return a / b;
}
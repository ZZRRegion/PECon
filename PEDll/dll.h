#pragma once
#include<Windows.h>
EXTERN_C
{
int Add(int a, int b);
int Sub(int a, int b);
int Mul(int a, int b);
int Div(int a, int b);
typedef struct _PACKINFO {
	DWORD oldOEP = 0x110;
	DWORD newOPE = 0x55aa;
}PACKINFO, * PPACKINFO;
}


EXTERN_C
{
	_declspec(dllexport) PACKINFO g_packInfo;
}

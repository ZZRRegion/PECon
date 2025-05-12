#include "dll.h"
#pragma comment(linker, "/INCLUDE:__tls_used")//告知链接器需要使用TLS
DWORD g_var = 0x12345678;
int Add(int a, int b)
{
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
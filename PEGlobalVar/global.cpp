#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>
DWORD g_Var = 0x12345678;
int main()
{
	printf("Addr -> 0x%08x\r\n", &g_Var);
	printf("Data -> 0x%08x\r\n", g_Var);

	return 0;
}
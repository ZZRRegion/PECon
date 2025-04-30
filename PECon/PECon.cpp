#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<stdio.h>
/*
	DOS
	DOS STUB
	NT(PE SIGN / FILE HEADER / OPTION HEADER)
	SECTION
	DIRECTORY(EXPORT / IMPORT / IAT / RELOCATION)
*/

// ==============================================
VOID HexAscii(const BYTE* data, SIZE_T offset, SIZE_T length)
{
	char ascii[17] = {};
	ascii[16] = '\0';
	printf("%08X | ", offset);
	for (size_t i = 0; i < 16; i++)
	{
		if (i < length)
		{
			printf("%02X ", data[i]);
			ascii[i] = isprint(data[i]) ? data[i] : '.';
		}
		else
		{
			printf("  ");
			ascii[i] = ' ';
		}
	}
	printf(" |%s|\n",ascii);
}
VOID HexDump(CONST CHAR* fileName)
{
	//二进制方式打开文件
	FILE* pFile = fopen(fileName, "rb");
	if (!pFile)
	{
		printf("fopen failed -> %s\r\n", fileName);
		return;
	}
	BYTE buffer[16] = {};
	SIZE_T byteRead = 0;
	SIZE_T offset = 0;
	while ((byteRead = fread(buffer, 1, sizeof(buffer), pFile)) > 0)
	{
		HexAscii(buffer, offset, byteRead);
		offset += byteRead;
	}
}
// ==============================================
int main()
{
	const char* fileName = R"(C:\Users\stdio\source\repos\Project1\Project1\pe.exe)";
	HexDump(fileName);
	return 0;
}


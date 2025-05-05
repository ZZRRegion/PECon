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

#define CON_GREEN 2
#define CON_RED	  4
#define CON_WHITE 7

#define CLR_RESET	"\x1b[0m"
#define CLR_TITLE	"\x1b[1;33m"  	// 黄色
#define CLR_MENU	"\x1b[1;36m"	// 青色
#define CLR_INPUT	"\x1b[1;32m"	// 绿色
#define CLR_ERROR	"\x1b[1;31m"	// 红色
#define CLR_INFO	"\x1b[1;37m"	// 白色

#define PRINT_TITLE(fmt, ...) printf(CLR_TITLE fmt CLR_RESET,##__VA_ARGS__)
#define PRINT_MENU(fmt, ...) printf(CLR_MENU fmt CLR_RESET,##__VA_ARGS__)
#define PRINT_INPUT(fmt, ...) printf(CLR_INPUT fmt CLR_RESET,##__VA_ARGS__)
#define PRINT_ERROR(fmt, ...) printf(CLR_ERROR fmt CLR_RESET,##__VA_ARGS__)
#define PRINT_INFO(fmt, ...) printf(CLR_INFO fmt CLR_RESET,##__VA_ARGS__)

// ==============================================
BOOL IsPEFile(const char* fileName)
{
	FILE* file = fopen(fileName, "rb");
	if (!file) return false;

	WORD dosSignature = NULL;
	if (fread(&dosSignature, sizeof(WORD), 1, file) != 1)
	{
		fclose(file);
		return false;
	}
	if (dosSignature != IMAGE_DOS_SIGNATURE)
	{
		fclose(file);
		return false;
	}
	fclose(file);
	return true;
}
ULONGLONG GetFileSizeByPtr(FILE* pFile)
{
	ULONGLONG size = 0;
	fseek(pFile, 0, SEEK_END);
	size = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	return size;
}
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
void SetConsoleColor(WORD color)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole != INVALID_HANDLE_VALUE)
	{
		SetConsoleTextAttribute(hConsole, color);
	}
}
void CompareFileByBin(const char* file1path, const char* file2path)
{
	FILE* pFile1 = NULL;
	FILE* pFile2 = NULL;
	ULONGLONG dwFileSize1 = NULL;
	ULONGLONG dwFileSize2 = NULL;
	PUCHAR szBuffer1 = nullptr;
	PUCHAR szBuffer2 = nullptr;
	ULONGLONG dwOffset = NULL;
	DWORD dwDifferences = NULL;

	// 检查是否为PE格式文件
	if (!IsPEFile(file1path) || !IsPEFile(file2path))
	{
		SetConsoleColor(CON_RED);
		printf("错误：不是有效的PE文件\n");
		SetConsoleColor(CON_WHITE);
		return;
	}

	// 二进制方式打开文件
	pFile1 = fopen(file1path, "rb");
	if (pFile1 == NULL)
	{
		SetConsoleColor(CON_RED);
		printf("错误：无法打开文件%s\r\n", file1path);
		SetConsoleColor(CON_WHITE);
		return;
	}

	pFile2 = fopen(file2path, "rb");
	if (pFile2 == NULL)
	{
		SetConsoleColor(CON_RED);
		printf("错误：无法打开文件%s\r\n", file2path);
		SetConsoleColor(CON_WHITE);
		return;
	}
	// 获取文件大小
	dwFileSize1 = GetFileSizeByPtr(pFile1);
	dwFileSize2 = GetFileSizeByPtr(pFile2);

	SetConsoleColor(CON_GREEN);
	printf("文件信息\r\n");
	SetConsoleColor(CON_WHITE);
	printf("文件1大小：%lld Byte\r\n", dwFileSize1);
	printf("文件2大小：%lld Byte\r\n", dwFileSize2);

	//分配缓冲区
	szBuffer1 = (PUCHAR)malloc(USN_PAGE_SIZE);
	szBuffer2 = (PUCHAR)malloc(USN_PAGE_SIZE);
	if (!szBuffer1 || !szBuffer2)
	{
		SetConsoleColor(CON_RED);
		printf("错误：分配内存失败\r\n");
		SetConsoleColor(CON_WHITE);
		goto CLEAN;
	}
	SetConsoleColor(CON_GREEN);
	printf("开始比对\r\n");
	SetConsoleColor(CON_WHITE);
	printf("  偏移量   | 文件1 | 文件2 | ASCII\n");
	printf("----------------------------------\n");
	// 循环读取并比较文件内容
	while (1)
	{
		SIZE_T byteRead1 = fread(szBuffer1, 1, USN_PAGE_SIZE, pFile1);
		SIZE_T byteRead2 = fread(szBuffer2, 1, USN_PAGE_SIZE, pFile2);

		if (byteRead1 == 0 && byteRead2 == 0) break;
		if (byteRead1 != byteRead2)
		{
			SetConsoleColor(CON_RED);
			printf("警告：文件长度不相等 OFFSET -> 0x%08llx\r\n", dwOffset + (byteRead1 < byteRead2 ? byteRead1 : byteRead2));
			SetConsoleColor(CON_WHITE);
			break;
		}
		for (size_t i = 0; i < byteRead1 && i < byteRead2; i++)
		{
			if (szBuffer1[i] != szBuffer2[i])
			{
				SetConsoleColor(CON_RED);
				printf("0x%08llX | 0x%02X  | 0x%02X  | %c - %c \r\n",
					dwOffset + i, szBuffer1[i], szBuffer2[i],
					(szBuffer1[i] >= 32 && szBuffer1[i] <= 126) ? szBuffer1[i] : '.',
					(szBuffer2[i] >= 32 && szBuffer2[i] <= 126) ? szBuffer2[i] : '.');
				SetConsoleColor(CON_WHITE);
				dwDifferences++;
			}
		}
		dwOffset += byteRead1;
	}
	printf("----------------------------------\n");
	SetConsoleColor(CON_GREEN);
	printf("比对成功 差异数量为 -> %d\r\n", dwDifferences);
	SetConsoleColor(CON_WHITE);
	// 清理资源
CLEAN:
	fclose(pFile1);
	fclose(pFile2);
	if (szBuffer1 != NULL) free(szBuffer1);
	if (szBuffer2 != NULL) free(szBuffer2);
}
// =======================================================
VOID ShowMenu()
{
	PRINT_TITLE("==== PE File Analysis Tool ====\n\n");

	PRINT_MENU("命令列表:\n");
	PRINT_MENU("    load		- 加载PE文件\n");
	PRINT_MENU("    info		- 显示PE基本信息\n");
	PRINT_MENU("    dos			- 显示DOS数据\n");
	PRINT_MENU("    nt			- 显示NT数据\n");
	PRINT_MENU("    section		- 显示SECTION数据\n");
	PRINT_MENU("    import		- 显示IMPORT数据\n");
	PRINT_MENU("    export		- 显示EXPORT\n");
	PRINT_MENU("    relocation		- 显示RELOCATION数据\n");
	PRINT_MENU("    clear		- 清屏\n");
	PRINT_MENU("    help		- 获取帮助\n");
	PRINT_MENU("    exit		- 退出程序\n");

	PRINT_INFO("请输入命令> ");
}
// =======================================================

int main()
{
	//DUMP
	{
		/*const char* fileName = R"(C:\Users\stdio\source\repos\Project1\Project1\pe.exe)";
		HexDump(fileName);*/
	}
	{
		ShowMenu();
		return 0;
	}
	// CMP
	{
		char file1Path[MAX_PATH] = {};
		char file2Path[MAX_PATH] = {};
		SetConsoleColor(CON_GREEN);
		printf("PE文件二进制对比工具\r\n");
		SetConsoleColor(CON_WHITE);
		
		printf("请输入第一个PE文件的完整路径：");
		if (fgets(file1Path, MAX_PATH, stdin) != NULL)
		{
			file1Path[strcspn(file1Path, "\n")] = 0;
		}

		printf("请输入第二个PE文件的完整路径：");
		if (fgets(file2Path, MAX_PATH, stdin) != NULL)
		{
			file2Path[strcspn(file2Path, "\n")] = 0;
		}

		CompareFileByBin(file1Path, file2Path);
	}
	return 0;
}


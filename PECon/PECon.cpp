#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<stdio.h>
#include<time.h>
#include<DbgHelp.h>
#include<list>
#include<filesystem>
#include<TlHelp32.h>
#include<Psapi.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(linker, "/INCLUDE:__tls_used")//告知链接器需要使用TLS
#include "../PEDll/dll.h"
#pragma comment(lib, "../Debug/PEDll.lib")
//#pragma comment(linker, "/DELAYLOAD:PEDll.dll") //项目属性->链接器->输入->延迟加载的DLL填写PEDll.dll
__declspec(thread) int g_tls = 0x1234;
__declspec(thread) int g_tls2 = 0x110;
//TLS回调函数
void static NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Context)
{
	_asm
	{
		mov eax,110
	}
}
void static NTAPI TlsCallback2(PVOID DllHandle, DWORD Reason, PVOID Context)
{
	_asm
	{
		mov eax, 0x110
	}
}
//声明TLS回调函数数组，必须放在.data节
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK pTlsCallbacks[] = { TlsCallback, TlsCallback2};
#pragma data_seg()
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
const DWORD CMDLINEMAX = MAX_PATH * 2;
CHAR cmdLine[CMDLINEMAX] = {};
HANDLE g_hFile = INVALID_HANDLE_VALUE;
DWORD g_dwFileSize = 0;
PBYTE g_lpFileBuffer = nullptr;
PIMAGE_DOS_HEADER g_pDosHeader = nullptr;
PIMAGE_NT_HEADERS g_pNtHeaders = nullptr;
PIMAGE_SECTION_HEADER g_pSectionHeader = nullptr;
char fileName[MAX_PATH] = {};
char g_SectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
char g_SectionName2[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
// ==============================================
VOID ShowMenu();
VOID ProcessCommand();
DWORD RvaToFoa(DWORD dwRva);
DWORD FoaToRva(DWORD dwFoa);
void CmdLoad(CONST CHAR* param);
void CmdInfo(CONST CHAR* param);
void CmdDos(CONST CHAR* param);
void CmdNt(CONST CHAR* param);
void CmdSection(CONST CHAR* param);
void CmdString(CONST CHAR* param);
void CmdImport(CONST CHAR* param);
void CmdExport(CONST CHAR* param);
void CmdResource(CONST CHAR* param);
void CmdException(CONST CHAR* param);
void CmdSecurity(CONST CHAR* param);
void CmdDebug(CONST CHAR* param);
void CmdGetExportFuncAddrByName(CONST CHAR* param);
void CmdGetExportFuncAddrByIndex(CONST CHAR* param);
void CmdRelocation(CONST CHAR* param);
void CmdRelocColor(CONST CHAR* param);
void CmdTLS(CONST CHAR* param);
void CmdLoadConfig(CONST CHAR* param);
void CmdDelayImport(CONST CHAR* param);
void CmdIAT(CONST CHAR* param);
void CmdRvaToFoa(CONST CHAR* param);
void CmdFoaToRva(CONST CHAR* param);
void CmdClear(CONST CHAR* param);
void CmdHelp(CONST CHAR* param);
void CmdCmp(CONST CHAR* param);
void CmdDump(CONST CHAR* param);
void CmdExit(CONST CHAR* param);
void CmdRead(CONST CHAR* param);
void CmdReadStr(CONST CHAR* param);
void CmdShellCode(CONST CHAR* param);
void FreeLoadedFile();
bool ReadFileMemory(const char* file, PBYTE buff, DWORD length);
const char* GetSectionName(PIMAGE_SECTION_HEADER pSection, bool first = true);
const char* GetSectionNameByRVA(DWORD dwRva, bool first = true);
// ==============================================
typedef void (*CmdHandler)(CONST CHAR* param);
CmdHandler FindCmdHandler(CONST CHAR* cmd);
typedef struct
{
	CONST CHAR* cmd;
	CmdHandler handler;
}CmdEntry;

static const CmdEntry CMD_TABLE[] =
{
	{"load",			CmdLoad},
	{"info",			CmdInfo},
	{"dos",				CmdDos},
	{"nt",				CmdNt},
	{"section",			CmdSection},
	{"string",          CmdString},
	{"import",			CmdImport},
	{"export",			CmdExport},
	{"resource",        CmdResource},
	{"exception",       CmdException},
	{"security",        CmdSecurity},
	{"relocation",		CmdRelocation},
	{"debug",           CmdDebug},
	{"getprocname",		CmdGetExportFuncAddrByName},
	{"getprocindex",	CmdGetExportFuncAddrByIndex},
	{"reloc-color",     CmdRelocColor},
	{"tls",             CmdTLS},		
	{"loadconfig",      CmdLoadConfig},
	{"delayimport",     CmdDelayImport},
	{"iat",             CmdIAT},
	{"rva",				CmdRvaToFoa },
	{"foa",				CmdFoaToRva},
	{"clear",			CmdClear},
	{"help",			CmdHelp},
	{"cmp",             CmdCmp},
	{"dump",            CmdDump},
	{"exit",			CmdExit},
	{"read",			CmdRead},
	{"readStr",			CmdReadStr},
	{"shellcode",       CmdShellCode},
	{nullptr, nullptr}
};
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
		if (i == 7)
		{
			printf("- ");
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
	system("cls");
	PRINT_TITLE("==== PE File Analysis Tool ====\n\n");

	PRINT_MENU("命令列表:\n");
	PRINT_MENU("\tload\t\t- 加载PE文件\n");
	PRINT_MENU("\tinfo\t\t- 显示PE基本信息\n");
	PRINT_MENU("\tdos\t\t- 显示DOS数据\n");
	PRINT_MENU("\tnt\t\t- 显示NT数据\n");
	PRINT_MENU("\tsection\t\t- 显示SECTION数据\n");
	PRINT_MENU("\tstring\t\t- 显示字符串\n");
	PRINT_MENU("\timport\t\t- 显示IMPORT数据\n");
	PRINT_MENU("\texport\t\t- 显示EXPORT\n");
	PRINT_MENU("\tresource\t- 显示资源\n");
	PRINT_MENU("\texception\t- 显示异常表\n");
	PRINT_MENU("\tsecurity\t- 显示\n");
	PRINT_MENU("\tdebug\t\t-> 调试\n");
	PRINT_MENU("\tgetprocname\t- 查找指定函数名称地址RVA\n");
	PRINT_MENU("\tgetprocindex\t- 查找指定函数序号地址RVA\n");
	PRINT_MENU("\trelocation\t- 显示RELOCATION数据\n");
	PRINT_MENU("\treloc-color\t- 显示RELOCATION数据\n");
	PRINT_MENU("\ttls\t\t- 显示TLS数据\n");
	PRINT_MENU("\tloadconfig\t- 显示LoadConfig数据\n");
	PRINT_MENU("\tdelayimport\t- 显示延迟导入表数据\n");
	PRINT_MENU("\trva\t\t- RVA->FOA\n");
	PRINT_MENU("\tfoa\t\t- FOA->RVA\n");
	PRINT_MENU("\tclear\t\t- 清屏\n");
	PRINT_MENU("\thelp\t\t- 获取帮助\n");
	PRINT_MENU("\tcmp\t\t- 二进制比较文件\n");
	PRINT_MENU("\tdump\t\t- dump进程文件 dump 1234 //PID\n");
	PRINT_MENU("\texit\t\t- 退出程序\n");
	PRINT_MENU("\tshellcode\t- 更改OPE先执行函数\n");
	PRINT_MENU("当前加载文件：%s\n", fileName);
	PRINT_INFO("请输入命令> ");
}

VOID ProcessCommand()
{
	ZeroMemory(cmdLine, CMDLINEMAX);
	CHAR cmd[32] = {};
	CHAR param[0xff] = {};
	if (fgets(cmdLine, CMDLINEMAX, stdin))
	{
		size_t len = strlen(cmdLine);
		if (len > 0 && cmdLine[len - 1] == '\n')
		{
			cmdLine[len - 1] = '\0';
		}

		int parsed = sscanf(cmdLine, "%31s %255s[^\n]", cmd, param);
		/*if (parsed > 0)
		{
			PRINT_INFO("Command	->	%s \n", cmd);
			if (parsed == 2)
			{
				PRINT_INFO("Param	->	%s \n", param);
			}
		}*/
	}

	CmdHandler handler = FindCmdHandler(cmd);
	if (handler)
	{
		handler(param);
	}
	else if (cmd[0] != '\0')
	{
		PRINT_ERROR("\n错误 -> 未知指令\r\n");
	}
}
DWORD RvaToFoa(DWORD dwRva)
{
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'命令加载\n");
		return 0;
	}
	if (dwRva < g_pNtHeaders->OptionalHeader.SizeOfHeaders)
	{
		return dwRva;
	}

	for (size_t i = 0; i < g_pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		// IMAGEBASE
		// VIRTUALADDRESS
		// RVA
		// FOA
		PIMAGE_SECTION_HEADER pSection = g_pSectionHeader + i;
		DWORD dwStartRva = pSection->VirtualAddress;
		DWORD dwEndRva = pSection->VirtualAddress + pSection->Misc.VirtualSize;
		if (dwRva >= dwStartRva && dwRva < dwEndRva)
		{
			DWORD dwOffset = dwRva - dwStartRva;
			return pSection->PointerToRawData + dwOffset;
		}
	}
	return 0;
}
DWORD FoaToRva(DWORD dwFoa)
{
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'命令加载\n");
		return 0;
	}
	if (dwFoa < g_pNtHeaders->OptionalHeader.SizeOfHeaders)
	{
		return dwFoa;
	}

	for (size_t i = 0; i < g_pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		// IMAGEBASE
		// VIRTUALADDRESS
		// RVA
		// FOA
		PIMAGE_SECTION_HEADER pSection = g_pSectionHeader + i;
		DWORD dwStartFoa = pSection->PointerToRawData;
		DWORD dwEndFoa = pSection->PointerToRawData + pSection->SizeOfRawData;
		if (dwFoa >= dwStartFoa && dwFoa < dwEndFoa)
		{
			DWORD dwOffset = dwFoa - dwStartFoa;
			return pSection->VirtualAddress + dwOffset;
		}
	}
	return 0;
}
DWORD GetExportFuncAddrByName(CONST CHAR* funcName);
DWORD GetExportFuncAddrByIndex(DWORD dwIndex);
DWORD GetExportNameByFuncAddr(DWORD dwFuncRva);
// =======================================================

int main()
{
	const char* file = R"(C:\Users\stdio\source\repos\PECon\Debug\PEDll.dll)";
	//file = "D:\\DriverDevelop\\InstDrv\\InstDrv.exe";
	//file = R"(C:\Users\stdio\source\repos\PECon\PECon\SocketTool.exe)";
	//file = R"(D:\Soft\SocketTool.exe)";
	file = R"(C:\Users\stdio\Desktop\SocketTool.exe)";
	CmdLoad(file);
	while(1)
	{
		//D:\DriverDevelop\InstDrv\InstDrv.exe
		ShowMenu();
		ProcessCommand();
		system("pause");
	}
	
	return 0;
}

void CmdLoad(const CHAR* param)
{
	// 参数校验
	if (param == nullptr || *param == '\0')
	{
		PRINT_ERROR("错误	->	请指定PE文件路径\r\n");
		return;
	}
	// 释放数据
	FreeLoadedFile();
	// 打开文件
	g_hFile = CreateFileA(
		param,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (g_hFile == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("错误	->	无法打开文件[%s] (错误码：%d)\r\n", param, GetLastError());
		return;
	}
	// 文件大小
	LARGE_INTEGER liFileSize = {};
	if (!GetFileSizeEx(g_hFile, &liFileSize) || liFileSize.QuadPart == 0)
	{
		PRINT_ERROR("错误	->	获取文件大小失败 （错误码：%d)\r\n", GetLastError());
		FreeLoadedFile();
		return;
	}
	g_dwFileSize = (DWORD)liFileSize.QuadPart;
	// 申请内存
	g_lpFileBuffer = (PBYTE)malloc(g_dwFileSize);
	if (!g_lpFileBuffer)
	{
		PRINT_ERROR("错误	->	内存申请失败（大小：%d)\r\n", g_dwFileSize);
		FreeLoadedFile();
		return;
	}
	// 获取数据
	DWORD dwByteRead = 0;
	if (!ReadFile(g_hFile, g_lpFileBuffer, g_dwFileSize, &dwByteRead, NULL) || dwByteRead != g_dwFileSize)
	{
		PRINT_ERROR("错误	->	文件读取失败 （读取：%d/%d bytes)\r\n", dwByteRead, g_dwFileSize);
		FreeLoadedFile();
		return;
	}

	// DOS
	g_pDosHeader = (PIMAGE_DOS_HEADER)g_lpFileBuffer;
	if (g_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("错误	->	无效的DOS签名（0x%03X)\r\n", g_pDosHeader->e_magic);
		FreeLoadedFile();
		return;
	}

	// NT
	DWORD dwNtHeaderOffset = g_pDosHeader->e_lfanew;
	if (dwNtHeaderOffset < sizeof(IMAGE_DOS_HEADER) || dwNtHeaderOffset + sizeof(IMAGE_NT_HEADERS) > g_dwFileSize)
	{
		PRINT_ERROR("错误	->	无效的NT偏移（0x%08X)\r\n", dwNtHeaderOffset);
		FreeLoadedFile();
		return;
	}

	g_pNtHeaders = (PIMAGE_NT_HEADERS)(g_lpFileBuffer + dwNtHeaderOffset);
	if (g_pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("错误	->	无效的PE签名（0x%08X)\r\n", g_pNtHeaders->Signature);
		FreeLoadedFile();
		return;
	}

	WORD opHeaderMagic = g_pNtHeaders->OptionalHeader.Magic;
	if (opHeaderMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && opHeaderMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		PRINT_ERROR("错误	->	不支持的OPTION->MAGIC（0x%04X)\r\n", opHeaderMagic);
		FreeLoadedFile();
		return;
	}
	// SECTION
	DWORD dwSectionHeaderOffset = dwNtHeaderOffset +
		sizeof(DWORD) +
		IMAGE_SIZEOF_FILE_HEADER +
		g_pNtHeaders->FileHeader.SizeOfOptionalHeader;

	g_pSectionHeader = (PIMAGE_SECTION_HEADER)(g_lpFileBuffer + dwSectionHeaderOffset);
	strcpy_s(fileName, param);
	//释放资源
	CloseHandle(g_hFile);
	g_hFile = INVALID_HANDLE_VALUE;

	//输出信息
	PRINT_INFO("成功加载PE文件	->	%s \r\n", param);
	PRINT_INFO("文件大小	->	0x%08x \r\n", g_dwFileSize);
}

void CmdInfo(const CHAR* param)
{
	PRINT_INFO("%s \r\n", param);
}

void CmdDos(const CHAR* param)
{
	if (g_pDosHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'命令加载PE文件\r\n");
		return;
	}
	if (g_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PRINT_ERROR("错误	->	无效的DOS签名（Expected:0x5a4d / Actual:0x%04x\r\n", g_pDosHeader->e_magic);
		return;
	}

	PRINT_TITLE("\n==== DOS Header Infomation ====\n\n");
	
	PRINT_ERROR("	0000h	e_magic			->		0x%04x		//EXE标志(MZ)\r\n", g_pDosHeader->e_magic);
	PRINT_INFO("	0002h	e_cblp			->		0x%04x		//文件最后页的字节数\r\n", g_pDosHeader->e_cblp);
	PRINT_INFO("	0004h	e_cp			->		0x%04x		//文件总页数\r\n", g_pDosHeader->e_cp);
	PRINT_INFO("	0006h	e_crlc			->		0x%04x		//重定位的条目数\r\n", g_pDosHeader->e_crlc);
	PRINT_INFO("	0008h	e_cparhdr		->		0x%04x		//头部大小(段落)\r\n", g_pDosHeader->e_cparhdr);
	PRINT_INFO("	000Ah	e_minalloc		->		0x%04x		//所需最小的附加段\r\n", g_pDosHeader->e_minalloc);
	PRINT_INFO("	000Ch	e_maxalloc		->		0x%04x		//所需最大的附加段\r\n", g_pDosHeader->e_maxalloc);
	PRINT_INFO("	000Eh	e_ss			->		0x%04x		//初始的SS值\r\n", g_pDosHeader->e_ss);
	PRINT_INFO("	0010h	e_sp			->		0x%04x		//初始的SP值\r\n", g_pDosHeader->e_sp);
	PRINT_INFO("	0012h	e_csum			->		0x%04x		//检验和\r\n", g_pDosHeader->e_csum);
	PRINT_INFO("	0014h	e_ip			->		0x%04x		//初始的IP值\r\n", g_pDosHeader->e_ip);
	PRINT_INFO("	0016h	e_cs			->		0x%04x		//初始的CS值\r\n", g_pDosHeader->e_cs);
	PRINT_INFO("	0018h	e_lfarlc		->		0x%04x		//重定位表的偏移\r\n", g_pDosHeader->e_lfarlc);
	PRINT_INFO("	001Ah	e_ovno			->		0x%04x		//覆盖号\r\n", g_pDosHeader->e_ovno);
	PRINT_INFO("	001Ch	e_res[4]		->		0x%04x		//保留字\r\n", g_pDosHeader->e_res[0]);
	PRINT_INFO("	0024h	e_oemid			->		0x%04x		//OEM表示\r\n", g_pDosHeader->e_oemid);
	PRINT_INFO("	0026h	e_oeminfo		->		0x%04x		//OEM信息\r\n", g_pDosHeader->e_oeminfo);
	PRINT_INFO("	0028h	e_res2[10]		->		0x%04x		//保留字\r\n", g_pDosHeader->e_res2[0]);
	PRINT_ERROR("	003Ch	e_lfanew		->		0x%08x	//PE头相对于文件的偏移地址\r\n\n", g_pDosHeader->e_lfanew);
}

void CmdNt(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'命令加载PE文件\r\n");
		return;
	}
	if (g_pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		PRINT_ERROR("错误	->	无效的NT签名（Expected:0x00004550 / Actual:0x%08x\r\n", g_pNtHeaders->Signature);
		return;
	}
	PRINT_TITLE("\n==== Nt Header Infomation ====\n\n");

	PRINT_INFO("--------------\r\n");
	PRINT_INFO("1.Signature\r\n");
	PRINT_INFO("--------------\n\n");
	PRINT_ERROR(" 0000h	Signature	->	0x%08x	//PE文件签名\r\n", g_pNtHeaders->Signature);
	PRINT_INFO("\n");

	PRINT_INFO("--------------\r\n");
	PRINT_INFO("2.FileHeader\r\n");
	PRINT_INFO("--------------\n\n");
	/*
		WORD    Machine;  IMAGE_FILE_MACHINE_I386
		WORD    NumberOfSections;
		DWORD   TimeDateStamp;
		DWORD   PointerToSymbolTable;
		DWORD   NumberOfSymbols;
		WORD    SizeOfOptionalHeader;
		WORD    Characteristics;  IMAGE_FILE_32BIT_MACHINE
	*/
	PIMAGE_FILE_HEADER pFileHeader = &g_pNtHeaders->FileHeader;
	const char* machineType = "UNKNOW";
	switch (pFileHeader->Machine)
	{
	case IMAGE_FILE_MACHINE_I386: machineType = "x86"; break;
	case IMAGE_FILE_MACHINE_AMD64: machineType = "x64"; break;
	}
	PRINT_ERROR("	0000h	Machine					->		0x%04X	运行平台:%s\r\n", pFileHeader->Machine, machineType);
	PRINT_ERROR("	0002h	NumberOfSections			->		0x%04X	节区数量\r\n", pFileHeader->NumberOfSections);
	time_t time = (time_t)pFileHeader->TimeDateStamp;
	tm localTime = {0};
	localtime_s(&localTime, &time);
	CHAR timeBuffer[0xFF] = {0};
	strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &localTime);
	PRINT_INFO("	0004h	TimeDateStamp				->		0x%08X	时间戳:%s\r\n", pFileHeader->TimeDateStamp, timeBuffer);
	PRINT_ERROR("	00010h	SizeOfOptionalHeader			->		0x%04X	可选头字节数\r\n", pFileHeader->SizeOfOptionalHeader);
	PRINT_INFO("	00012h	Characteristics				->		0x%04X	文件特性\r\n", pFileHeader->Characteristics);
	
	struct CharacteristicsFlag
	{
		WORD flag;
		const char* desc;
	};
	CharacteristicsFlag flags[] =
	{
		{IMAGE_FILE_RELOCS_STRIPPED					  ,"// Relocation info stripped from file."},
		{IMAGE_FILE_EXECUTABLE_IMAGE				  ,"// File is executable  (i.e. no unresolved external references)."},
		{IMAGE_FILE_LINE_NUMS_STRIPPED				  ,"// Line nunbers stripped from file."},
		{IMAGE_FILE_LOCAL_SYMS_STRIPPED				  ,"// Local symbols stripped from file."},
		{IMAGE_FILE_AGGRESIVE_WS_TRIM				  ,"// Aggressively trim working set"},
		{IMAGE_FILE_LARGE_ADDRESS_AWARE				  ,"// App can handle >2gb addresses"},
		{IMAGE_FILE_BYTES_REVERSED_LO				  ,"// Bytes of machine word are reversed."},
		{IMAGE_FILE_32BIT_MACHINE					  ,"// 32 bit word machine."},
		{IMAGE_FILE_DEBUG_STRIPPED					  ,"// Debugging info stripped from file in .DBG file"},
		{IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP			  ,"// If Image is on removable media, copy and run from the swap file."},
		{IMAGE_FILE_NET_RUN_FROM_SWAP				  ,"// If Image is on Net, copy and run from the swap file."},
		{IMAGE_FILE_SYSTEM							  ,"// System File."},
		{IMAGE_FILE_DLL								  ,"// File is a DLL."},
		{IMAGE_FILE_UP_SYSTEM_ONLY					  ,"// File should only be run on a UP machine"},
		{IMAGE_FILE_BYTES_REVERSED_HI				  ,"// Bytes of machine word are reversed."},
	};
	for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++)
	{
		if (pFileHeader->Characteristics & flags[i].flag)
		{
			PRINT_INFO("		FLAG -> 0x%04x	INFO -> %s\r\n", flags[i].flag, flags[i].desc);
		}
	}
	PRINT_INFO("\n");

	PRINT_INFO("--------------\r\n");
	PRINT_INFO("3.OptionHeader\r\n");
	PRINT_INFO("--------------\n\n");
	

	PRINT_TITLE("\n==== Nt Option Header Infomation ====\n\n");
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_pNtHeaders->OptionalHeader;
	
	const char* szMagic = "UNKNOW";
	switch (pOptionalHeader->Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC: szMagic = "PE32 (32bit)"; break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC: szMagic = "PE32+(64bit)"; break;
	}
	PRINT_ERROR("	00014h	Magic			->	0x%04X		表示文件类型：%s\r\n", pOptionalHeader->Magic, szMagic);
	PRINT_INFO("	00014h	MajorLinkerVersion	->	%d		链接器的主版本号\r\n", pOptionalHeader->MajorLinkerVersion);
	PRINT_INFO("	00014h	MinorLinkerVersion	->	%d		链接器的次版本号\r\n", pOptionalHeader->MinorLinkerVersion);
	PRINT_ERROR("	00014h	SizeOfCode		->	0x%04X		所有代码节的总大小（通常位.text段）文件对齐后的大小\r\n", pOptionalHeader->SizeOfCode);
	PRINT_INFO("	00014h	SizeOfInitializedData	->	0x%08X	已初始化数据的节的总大小（如.data段)\r\n", pOptionalHeader->SizeOfInitializedData);
	PRINT_INFO("	00014h	SizeOfUninitializedData	->	0x%04X		未初始化数据的节的总大小（如.bss段）\r\n", pOptionalHeader->SizeOfUninitializedData);
	PRINT_ERROR("	00014h	AddressOfEntryPoint	->	0x%08X	程序入口点（RVA地址），指向main或DllMain\r\n", pOptionalHeader->AddressOfEntryPoint);
	PRINT_INFO("	00014h	BaseOfCode		->	0x%08X	代码段的起始RVA\r\n", pOptionalHeader->BaseOfCode);
	PRINT_INFO("	00014h	BaseOfData		->	0x%08X	数据段的起始RVA\r\n", pOptionalHeader->BaseOfData);
	
	PRINT_ERROR("	00014h	ImageBase		->	0x%08X	文件加载到内存时的首选基地址（如0x400000）\r\n", pOptionalHeader->ImageBase);
	PRINT_ERROR("	00014h	SectionAlignment	->	0x%08X	内存中段的对齐粒度（通常0x1000即4KB)\r\n", pOptionalHeader->SectionAlignment);
	PRINT_ERROR("	00014h	FileAlignment		->	0x%08X	文件中段的对齐粒度（通常0x200即512字节）\r\n", pOptionalHeader->FileAlignment);
	PRINT_ERROR("	00014h	SizeOfImage		->	0x%08X	整个PE文件映射到内存后的总大小\r\n", pOptionalHeader->SizeOfImage);
	PRINT_ERROR("	00014h	SizeOfHeaders		->	0x%08X	所有头结构（DOS+PE头+节表）的总大小（按FileAlign对齐）\r\n", pOptionalHeader->SizeOfHeaders);
	const char* szSubsystem = "UNKNOW";
	switch (pOptionalHeader->Subsystem)
	{
	case IMAGE_SUBSYSTEM_WINDOWS_GUI: szSubsystem = "GUI"; break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI: szSubsystem = "CUI"; break;
	}
	PRINT_ERROR("	00014h	Subsystem		->	0x%04X		子系统:%s\r\n", pOptionalHeader->Subsystem,szSubsystem);
	PRINT_ERROR("	00014h	DllCharacteristics	->	0x%08X	特性\r\n", pOptionalHeader->DllCharacteristics);
	struct DllCharacteristicsFlag
	{
		WORD flag;
		const char* desc;
	};
	DllCharacteristicsFlag dllFlags[] =
	{
		{IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA   		  ,"// Image can handle a high entropy 64-bit virtual address space."}				,
		{ IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 				  ,"// DLL can move." }															,
		{ IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    		  ,"// Code Integrity Image" }														,
		{ IMAGE_DLLCHARACTERISTICS_NX_COMPAT    				  ,"// Image is NX compatible" }												,
		{ IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 				  ,"// Image understands isolation and doesn't want it" }						,
		{ IMAGE_DLLCHARACTERISTICS_NO_SEH       				  ,"// Image does not use SEH.  No SE handler may reside in this image" }		,
		{ IMAGE_DLLCHARACTERISTICS_NO_BIND      				  ,"// Do not bind this image." }												,
		{ IMAGE_DLLCHARACTERISTICS_APPCONTAINER 				  ,"// Image should execute in an AppContainer" }								,
		{ IMAGE_DLLCHARACTERISTICS_WDM_DRIVER   				  ,"// Driver uses WDM model" }													,
		{ IMAGE_DLLCHARACTERISTICS_GUARD_CF     				  ,"// Image supports Control Flow Guard."}										,
		{IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE			  ,"TERMINAL_SERVER_AWARE"}
	};
	for (size_t i = 0; i < sizeof(dllFlags) / sizeof(dllFlags[0]); i++)
	{
		if (pOptionalHeader->DllCharacteristics & dllFlags[i].flag)
		{
			PRINT_INFO("  FLAG 0x%04x info->%s\r\n", dllFlags[i].flag, dllFlags[i].desc);
		}
	}
	PRINT_ERROR("NumberOfRvaAndSizes->0x%08X\t//数据目录数量\r\n", pOptionalHeader->NumberOfRvaAndSizes);

	for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		if (pOptionalHeader->DataDirectory[i].VirtualAddress != 0)
		{
			PIMAGE_SECTION_HEADER pSection = ImageRvaToSection(g_pNtHeaders, g_lpFileBuffer, pOptionalHeader->DataDirectory[i].VirtualAddress);
			const char* szDataDirectory = "UNKNOW";
			switch (i)
			{
				 case IMAGE_DIRECTORY_ENTRY_EXPORT        : szDataDirectory = "Export Directory"; break;
				 case IMAGE_DIRECTORY_ENTRY_IMPORT: szDataDirectory = "Import Directory"; break;
				 case IMAGE_DIRECTORY_ENTRY_RESOURCE: szDataDirectory = "Resource Directory"; break;
				 case IMAGE_DIRECTORY_ENTRY_EXCEPTION: szDataDirectory = "Exception Directory"; break;
				 case IMAGE_DIRECTORY_ENTRY_SECURITY: szDataDirectory = "Security Directory"; break;
				 case IMAGE_DIRECTORY_ENTRY_BASERELOC: szDataDirectory = "Base Relocation Table"; break;
				 case IMAGE_DIRECTORY_ENTRY_DEBUG: szDataDirectory = "Debug Directory"; break;
				 case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: szDataDirectory = "Architecture Specific Data"; break;
				 case IMAGE_DIRECTORY_ENTRY_GLOBALPTR: szDataDirectory = "RVA of GP"; break;
				 case IMAGE_DIRECTORY_ENTRY_TLS: szDataDirectory = "TLS Directory"; break;
				 case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: szDataDirectory = "Load Configuration Directory"; break;
				 case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: szDataDirectory = "Bound Import Directory in headers"; break;
				 case IMAGE_DIRECTORY_ENTRY_IAT: szDataDirectory = "Import Address Table"; break;
				 case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: szDataDirectory = "Delay Load Import Descriptors"; break;
				 case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: szDataDirectory = "COM Runtime descriptor";break;


			}
			PRINT_INFO("%d\tVA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t%s\t%s\r\n",
				i,
				pOptionalHeader->DataDirectory[i].VirtualAddress,
				pOptionalHeader->DataDirectory[i].VirtualAddress + pOptionalHeader->DataDirectory[i].Size,
				RvaToFoa(pOptionalHeader->DataDirectory[i].VirtualAddress),
				RvaToFoa(pOptionalHeader->DataDirectory[i].VirtualAddress) + pOptionalHeader->DataDirectory[i].Size,
				pOptionalHeader->DataDirectory[i].Size,
				GetSectionName(pSection),
				szDataDirectory);
		}
	}
}

void CmdSection(const CHAR* param)
{
	/*
	typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
	*/
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	PRINT_TITLE("\n==== Section Header Information ===\n\n");
	struct SectionFlag
	{
		DWORD flag;
		CONST CHAR* desc;
	};
	SectionFlag scnFlags[] =
	{
		{IMAGE_SCN_CNT_CODE              , "Section contains code."},
		{IMAGE_SCN_CNT_INITIALIZED_DATA  , "Section contains initialized data."},
		{IMAGE_SCN_CNT_UNINITIALIZED_DATA, "Section contains uninitialized data."},
		{IMAGE_SCN_LNK_NRELOC_OVFL       , "Section contains extended relocations."},
		{IMAGE_SCN_MEM_DISCARDABLE       , "Section can be discarded."},
		{IMAGE_SCN_MEM_NOT_CACHED        , "Section is not cachable."},
		{IMAGE_SCN_MEM_NOT_PAGED         , "Section is not pageable."},
		{IMAGE_SCN_MEM_SHARED			 , "Section is shareable."},
		{IMAGE_SCN_MEM_EXECUTE			 , "Section is executable."},
		{IMAGE_SCN_MEM_READ				 , "Section is readable."},
		{IMAGE_SCN_MEM_WRITE             , "Section is writeable."}
	};
	DWORD totalVirtualSize = 0;
	DWORD totalRawSize = 0;
	PRINT_TITLE("#\tName\t\tVSize\t\tVA\t\t\tSizeData\tPData\t\t\t属性\n");
	for (size_t i = 0; i < g_pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSection = g_pSectionHeader + i;
		PRINT_INFO("%d\t%-8s\t%08x\t%08x~%08x\t%08x\t%08x~%08x\t%08x\n", 
			i, 
			GetSectionName(pSection),
			pSection->Misc.VirtualSize,
			pSection->VirtualAddress + pSection->Misc.VirtualSize,
			pSection->VirtualAddress,
			pSection->SizeOfRawData,
			pSection->PointerToRawData,
			pSection->PointerToRawData + pSection->SizeOfRawData,
			pSection->Characteristics);
		totalVirtualSize += pSection->Misc.VirtualSize;
		totalRawSize += pSection->SizeOfRawData;
		/*for (size_t i = 0; i < sizeof(scnFlags) / sizeof(scnFlags[0]); i++)
		{
			if (pSection->Characteristics & scnFlags[i].flag)
			{
				PRINT_ERROR("\tFLAG->0x%08x\tINFO->%s\n", scnFlags[i].flag, scnFlags[i].desc);
			}
		}*/
	}
	PRINT_INFO("\nSummary\n");
	PRINT_INFO("Total Section:%d\n", g_pNtHeaders->FileHeader.NumberOfSections);
	PRINT_INFO("Total Virtual Size:%d\n", totalVirtualSize);
	PRINT_INFO("Total Raw Size:%d\n", totalRawSize);
}
void CmdString(const CHAR* param)
{
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	PRINT_TITLE("\n==== 字符串 ====\n");
	PRINT_INFO("ImageBase->%08x\n", g_pNtHeaders->OptionalHeader.ImageBase);
	PRINT_INFO("#\t%-6s%-10s%-10s%-8sSize\t字符串\n", "FOA", "RVA", "VA", "节区");
	PBYTE stringStart = nullptr;
	DWORD index = 0;
	const int BUFFERLENGTH = 50;
	char* buffer = new char[BUFFERLENGTH];
	for (DWORD i = 0; i < g_dwFileSize; i++)
	{
		PBYTE current = g_lpFileBuffer + i;
		if (isprint(*current) || *current == '\t')
		{
			if (!stringStart)
			{
				stringStart = current;
			}
		}
		else
		{
			//字符串结束
			if (stringStart)
			{
				size_t length = current - stringStart;
				if (length >= 5)
				{
					ZeroMemory(buffer, BUFFERLENGTH);
					memcpy_s(buffer, BUFFERLENGTH - 1, stringStart, length > BUFFERLENGTH - 1 ? BUFFERLENGTH - 1 : length);
					ZeroMemory(g_SectionName, IMAGE_SIZEOF_SHORT_NAME + 1);
					strcpy_s(g_SectionName, IMAGE_SIZEOF_SHORT_NAME, "PE头");
					DWORD offset = (stringStart - g_lpFileBuffer);
					DWORD imageBase = g_pNtHeaders->OptionalHeader.ImageBase;
					DWORD va = imageBase + offset;
					DWORD dwRva = offset;
					if (offset > g_pNtHeaders->OptionalHeader.SizeOfHeaders)
					{
						dwRva = FoaToRva(offset);
						if (dwRva > 0)
						{
							PIMAGE_SECTION_HEADER pSection = ImageRvaToSection(g_pNtHeaders, g_lpFileBuffer, dwRva);
							GetSectionName(pSection);
							va = imageBase + dwRva;
						}
					}
					
					PRINT_INFO("%d\t%04x  %08x  %08x  %-8s%02x\t%s\n",
						index++, 
						offset, 
						dwRva,
						va, 
						g_SectionName,
						length, 
						buffer);
				}
				stringStart = nullptr;
			}
		}
	}
}
DWORD GetThunkDataLength(DWORD thunkAddr)
{
	if (thunkAddr == 0)
		return 0;
	PIMAGE_THUNK_DATA pData = (PIMAGE_THUNK_DATA)(g_lpFileBuffer + RvaToFoa(thunkAddr));
	DWORD length = 0;
	while (pData->u1.AddressOfData)
	{
		length += sizeof(IMAGE_THUNK_DATA);
		pData++;
	}
	return length;
}
void CmdImport(const CHAR* param)
{
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	/*
	typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
	} IMAGE_IMPORT_DESCRIPTOR;

		typedef struct _IMAGE_THUNK_DATA32 {
		union {
			DWORD ForwarderString;      // PBYTE
			DWORD Function;             // PDWORD
			DWORD Ordinal;
			DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
		} u1;
	} IMAGE_THUNK_DATA32;
	typedef struct _IMAGE_IMPORT_BY_NAME {
		WORD    Hint;
		CHAR   Name[1];
	} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
	*/
	
	IMAGE_DATA_DIRECTORY dir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (dir.VirtualAddress == 0 || dir.Size == 0)
	{
		PRINT_ERROR("错误\t->\t无导入表\r\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(dir.VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(g_lpFileBuffer + dwFoa);
	PRINT_TITLE("==============导入表信息==============\n");
	PRINT_INFO("VA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t%s\n",
		dir.VirtualAddress,
		dir.VirtualAddress + dir.Size,
		dwFoa,
		dwFoa + dir.Size,
		dir.Size,
		GetSectionNameByRVA(dir.VirtualAddress));
	if (*param == 0)
	{
		PRINT_ERROR("#  OriFirThk %-8s  OriFOA    OriFOAEnd Name      FirThk    %-8s  FOA       FEnd      名称\n",
			"节区", "节区");
	}
	int index = 0;
	while (pImport->OriginalFirstThunk != 0 || pImport->FirstThunk != 0)
	{
		PBYTE name = g_lpFileBuffer + RvaToFoa(pImport->Name);
		if (*param == 0)
		{
			PRINT_INFO("%-3d%08X  %-8s  %08X  %08X  %08X  %08X  %-8s  %08X  %08X  %s\n",
				index++,
				pImport->OriginalFirstThunk,
				GetSectionNameByRVA(pImport->OriginalFirstThunk),
				RvaToFoa(pImport->OriginalFirstThunk),
				RvaToFoa(pImport->OriginalFirstThunk) + GetThunkDataLength(pImport->OriginalFirstThunk),
				pImport->Name,
				pImport->FirstThunk,
				GetSectionNameByRVA(pImport->FirstThunk, false),
				RvaToFoa(pImport->FirstThunk),
				RvaToFoa(pImport->FirstThunk) + GetThunkDataLength(pImport->FirstThunk),
				name);
		}
		else if (strcmp(param, (const CHAR*)name) == 0)
		{
			PIMAGE_THUNK_DATA pINT = nullptr;
			PIMAGE_THUNK_DATA pIAT = nullptr;
			PIMAGE_THUNK_DATA pData = nullptr;
			if (pImport->OriginalFirstThunk)
			{
				DWORD dwINTFoa = RvaToFoa(pImport->OriginalFirstThunk);
				if (dwINTFoa)
				{
					pINT = (PIMAGE_THUNK_DATA)(g_lpFileBuffer + dwINTFoa);
				}
			}
			if (pImport->FirstThunk)
			{
				DWORD dwIATFoa = RvaToFoa(pImport->FirstThunk);
				if (dwIATFoa)
				{
					pIAT = (PIMAGE_THUNK_DATA)(g_lpFileBuffer + dwIATFoa);
				}
			}
			if (pINT != nullptr)
			{
				pData = pINT;
			}
			else if (pIAT != nullptr)
			{
				pData = pIAT;
			}
			else
			{
				pImport++;
				continue;
			}
			PRINT_INFO("\n导入函数列表\n");
			PRINT_INFO("序号\tThunkRva\t节区\t\tFOA\t\tOrdinal\t\tHint\t名称\n");
			PRINT_INFO("----------------------------------------------\n");
			for (size_t j = 0; pData->u1.AddressOfData != 0; j++, pData++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pData->u1.Ordinal))
				{
					WORD ordinal = IMAGE_ORDINAL(pData->u1.Ordinal);
					PRINT_INFO("%d\t\t\t\t\t\t\t%08x\n", j, ordinal);
				}
				else
				{
					DWORD dwNameFoa = RvaToFoa(pData->u1.AddressOfData);
					if (dwNameFoa)
					{
						PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(g_lpFileBuffer + dwNameFoa);
						PRINT_INFO("%d\t%08x\t%-8s\t%08x\t\t\t%04x\t%-25s\n",
							j,
							pData->u1.AddressOfData,
							GetSectionNameByRVA(pData->u1.AddressOfData),
							dwNameFoa,
							pImportName->Hint,
							pImportName->Name);
					}
				}
			}
			PRINT_INFO("\n");
		}
		
		pImport++;
	}

}

void CmdExport(const CHAR* param)
{
	//IMAGE_DIRECTORY_ENTRY_EXPORT
	/*
	typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
	} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
	*/
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	PRINT_TITLE("\n==== Export Information ====\n");
	IMAGE_DATA_DIRECTORY exportDir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDir.VirtualAddress == 0 || exportDir.Size == 0)
	{
		PRINT_ERROR("错误	->	当前PE文件无导出表结构\r\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(exportDir.VirtualAddress);
	PRINT_INFO("VA->0x%08X~%08x\tFOA->%08x~%08x\tSize->0x%08X  节区->%s\n\n", 
		exportDir.VirtualAddress,
		exportDir.VirtualAddress + exportDir.Size,
		dwFoa,
		dwFoa + exportDir.Size,
		exportDir.Size,
		GetSectionNameByRVA(exportDir.VirtualAddress));
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + dwFoa);
	PRINT_INFO("0000h	Name\t\t\t->0x%08X  FOA->%08x  节区->%s\tDLL名称->%s\n", 
		pExport->Name, 
		RvaToFoa(pExport->Name), 
		GetSectionNameByRVA(pExport->Name),
		g_lpFileBuffer + RvaToFoa(pExport->Name));
	PRINT_INFO("0000h	Base\t\t\t->0x%08X\t//导出函数的起始序号\n", pExport->Base);
	PRINT_INFO("0000h	NumberOfFunctions\t->0x%08X\t//导出函数的数量(最大的导出序号-最小的导出序号+1)\n", pExport->NumberOfFunctions);
	PRINT_INFO("0000h	NumberOfNames\t\t->0x%08X\t//函数名称导出的数量\n", pExport->NumberOfNames);
	PRINT_INFO("0000h	AddressOfFunctions\t->0x%08X  FOA->%08x  节区->%s  //导出函数地址表(RVA)4字节数组(为NumOfFun)\n", 
		pExport->AddressOfFunctions, 
		RvaToFoa(pExport->AddressOfFunctions),
		GetSectionNameByRVA(pExport->AddressOfFunctions));
	PRINT_INFO("0000h	AddressOfNames\t\t->0x%08X  FOA->%08x  节区->%s  //导出函数名称表(RVA)4字节数组(为NumOfNam)\n", 
		pExport->AddressOfNames, 
		RvaToFoa(pExport->AddressOfNames),
		GetSectionNameByRVA(pExport->AddressOfNames));
	PRINT_INFO("0000h	AddressOfNameOrdinals\t->0x%08X  FOA->%08x  节区->%s  //名称序号表2字节数组(为NumOfNam)\n", 
		pExport->AddressOfNameOrdinals, 
		RvaToFoa(pExport->AddressOfNameOrdinals),
		GetSectionNameByRVA(pExport->AddressOfNameOrdinals));
	dwFoa = RvaToFoa(pExport->AddressOfFunctions);
	DWORD* pFunctions = (DWORD*)(g_lpFileBuffer + dwFoa);
	dwFoa = RvaToFoa(pExport->AddressOfNames);
	DWORD* pName = (DWORD*)(g_lpFileBuffer + dwFoa);
	dwFoa = RvaToFoa(pExport->AddressOfNameOrdinals);
	WORD* pOrd = (WORD*)(g_lpFileBuffer + dwFoa);
	PRINT_ERROR("=========================导出函数=====================\n");
	PRINT_ERROR("Ordinal\tRVA\t\tFOA\t\t节区\tNameRva\t\tNameFOA\t\t节区\tName\n");
	for (size_t i = 0; i < pExport->NumberOfFunctions; i++)
	{
		DWORD name = NULL;
		PRINT_INFO("%04x\t%08x\t%08x\t%-8s", 
			i + pExport->Base, 
			pFunctions[i], 
			RvaToFoa(pFunctions[i]), 
			GetSectionNameByRVA(pFunctions[i]));
		if (pFunctions[i] != 0)
		{
			for (size_t j = 0; j < pExport->NumberOfNames; j++)
			{
				if (pOrd[j] == i)//判断名称序号是否等于地址的序号
				{
					name = pName[j];
					break;
				}
			}
		}
		if (name != 0)
		{
			PRINT_INFO("%08x\t%08x\t%s\t%s\n", name, RvaToFoa(name), GetSectionNameByRVA(name), (const char*)(g_lpFileBuffer + RvaToFoa(name)));
		}
		else
		{
			PRINT_INFO("%08x\t%08x\t%s\t%s\n", name, 0, GetSectionNameByRVA(name), "<NO NAME>");
		}
	}
}

void CmdResource(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	IMAGE_DATA_DIRECTORY resDir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if (resDir.VirtualAddress == 0 || resDir.Size == 0)
	{
		PRINT_ERROR("错误\t->当前PE文件无资源表\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(resDir.VirtualAddress);
	PRINT_TITLE("\n==== 资源表 ====\n");
	PRINT_INFO("VA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t节区->%s\n",
		resDir.VirtualAddress,
		resDir.VirtualAddress + resDir.Size,
		dwFoa,
		dwFoa + resDir.Size,
		resDir.Size,
		GetSectionNameByRVA(resDir.VirtualAddress));
}

void CmdException(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	IMAGE_DATA_DIRECTORY exceptionDir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (exceptionDir.VirtualAddress == 0 || exceptionDir.Size == 0)
	{
		PRINT_ERROR("错误\t->当前PE文件无异常表\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(exceptionDir.VirtualAddress);
	PRINT_TITLE("\n==== 异常表 ====\n");
	PRINT_INFO("VA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t%s\n",
		exceptionDir.VirtualAddress,
		exceptionDir.VirtualAddress + exceptionDir.Size,
		dwFoa,
		dwFoa + exceptionDir.Size,
		exceptionDir.Size,
		GetSectionNameByRVA(exceptionDir.VirtualAddress));
}

void CmdSecurity(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	IMAGE_DATA_DIRECTORY securityDir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	if (securityDir.VirtualAddress == 0 || securityDir.Size == 0)
	{
		PRINT_ERROR("错误\t->当前PE文件无security表\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(securityDir.VirtualAddress);
	PRINT_TITLE("\n==== security表 ====\n");
	PRINT_INFO("VA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t%s\n",
		securityDir.VirtualAddress,
		securityDir.VirtualAddress + securityDir.Size,
		dwFoa,
		dwFoa + securityDir.Size,
		securityDir.Size,
		GetSectionNameByRVA(securityDir.VirtualAddress));
}

void CmdDebug(CONST CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	IMAGE_DATA_DIRECTORY debugDir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	if (debugDir.VirtualAddress == 0 || debugDir.Size == 0)
	{
		PRINT_ERROR("错误\t->当前PE文件无debug表\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(debugDir.VirtualAddress);
	PRINT_TITLE("\n==== debug表 ====\n");
	PRINT_INFO("VA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t%s\n",
		debugDir.VirtualAddress,
		debugDir.VirtualAddress + debugDir.Size,
		dwFoa,
		dwFoa + debugDir.Size,
		debugDir.Size,
		GetSectionNameByRVA(debugDir.VirtualAddress));
	PIMAGE_DEBUG_DIRECTORY pDebug = (PIMAGE_DEBUG_DIRECTORY)(g_lpFileBuffer + dwFoa);
	DWORD entry_count = debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
	PRINT_TITLE("#\tType\t\tSizeOfData\tAddressOfRawData\tPointerToRawData\n");
	for (size_t i = 0; i < entry_count; i++)
	{
		PIMAGE_DEBUG_DIRECTORY p = pDebug + i;
		PRINT_INFO("%d\t%08x\t%08x\t%08x\t\t%08x\n",
			i,
			p->Type,
			p->SizeOfData,
			p->AddressOfRawData,
			p->PointerToRawData);
		if (p->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
		{

		}
	}
}

void CmdGetExportFuncAddrByName(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	if (param == NULL || *param == '\0')
	{
		PRINT_ERROR("错误	->	请输入指定格式地址（格式：Add )\r\n");
		PRINT_ERROR("示例	->	getprocname Add\r\n");
		return;
	}
	DWORD dwFuncRva = GetExportFuncAddrByName(param);
	if (dwFuncRva == 0)
	{
		PRINT_ERROR("错误\t->\t未找到指定函数[%s]\r\n", param);
		return;
	}
	DWORD dwFuncFoa = RvaToFoa(dwFuncRva);
	PRINT_INFO("\n函数信息\n");
	PRINT_INFO("名称\t->%s\n", param);
	PRINT_INFO("RVA\t->0x%08x\r\n", dwFuncRva);
	PRINT_INFO("FOA\t->0x%08x\r\n", dwFuncFoa);
	PRINT_INFO("节区\t->%s\n", GetSectionNameByRVA(dwFuncRva));
}

void CmdGetExportFuncAddrByIndex(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
	}
	if (param == NULL || *param == '\0')
	{
		PRINT_ERROR("错误	->	请输入指定格式地址（格式：getprocindex )\r\n");
		PRINT_ERROR("示例	->	getprocindex 2\r\n");
		return;
	}
	DWORD index = 0;
	if (sscanf(param, "%d", &index) != 1)
	{
		PRINT_ERROR("错误	->	无效的地址格式\r\n");
		PRINT_ERROR("示例	->	getprocindex 1\r\n");
		return;
	}
	DWORD dwFuncRva = GetExportFuncAddrByIndex(index);
	if (dwFuncRva == 0)
	{
		PRINT_ERROR("错误\t->\t未找到函数序号[%d]\r\n", index);
		return;
	}
	DWORD dwFuncFoa = RvaToFoa(dwFuncRva);
	DWORD dwFuncName = GetExportNameByFuncAddr(dwFuncRva);
	PRINT_INFO("\n函数信息\n");
	if (dwFuncName > 0)
	{
		PRINT_INFO("名称\t->%s\n", g_lpFileBuffer + RvaToFoa(dwFuncName));
	}
	else
	{
		PRINT_INFO("名称\t-><NO NAME>\n");
	}
	PRINT_INFO("RVA\t->0x%08x\r\n", dwFuncRva);
	PRINT_INFO("FOA\t->0x%08x\r\n", dwFuncFoa);
	PRINT_INFO("节区\t->%s\n", GetSectionNameByRVA(dwFuncRva));
}

void CmdRelocation(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误\t->\t请先使用'load'命令加载PE文件\r\n");
		return;
	}
	//导出表判断
	IMAGE_DATA_DIRECTORY dir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (dir.VirtualAddress == 0 || dir.Size == 0)
	{
		PRINT_ERROR("错误\t->\t当前PE文件不存在重定位表\r\n");
		return;
	}
	DWORD dwBaseRelocFoa = RvaToFoa(dir.VirtualAddress);
	if (dwBaseRelocFoa == 0)
	{
		PRINT_ERROR("错误\t->\t重定位结构RVA转换FOA失败\r\n");
		return;
	}
	PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(g_lpFileBuffer + dwBaseRelocFoa);
	
	PRINT_TITLE("\n==== Relocation Table Information ====\n");
	PRINT_INFO("VA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t%s\n",
		dir.VirtualAddress,
		dir.VirtualAddress + dir.Size,
		dwBaseRelocFoa,
		dwBaseRelocFoa + dir.Size,
		dir.Size,
		GetSectionNameByRVA(dir.VirtualAddress));
	while (pRelocBlock->VirtualAddress != 0
		&& pRelocBlock->SizeOfBlock != 0)
	{
		DWORD entryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD pEntry = (PWORD)((BYTE*)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
		PRINT_INFO("----------------------------------------------------------------\n");
		PRINT_INFO("BlockBack\t->\t0x%08x\r\n", pRelocBlock->VirtualAddress);
		PRINT_INFO("BlockSize\t->\t0x%08x\r\n", pRelocBlock->SizeOfBlock);
		PRINT_INFO("BlockCount\t->\t%d\r\n", entryCount);
		PIMAGE_SECTION_HEADER pSection = ImageRvaToSection(g_pNtHeaders, g_lpFileBuffer, pRelocBlock->VirtualAddress);
		PRINT_INFO("节区\t\t->\t%s\r\n\n", GetSectionName(pSection));
		PRINT_INFO("序号\tTypeOffset\t类型\t\tRVA地址\t\tFOA地址\n");
		PRINT_INFO("----------------------------------------------------------------\n");
		for (size_t i = 0; i < entryCount; i++)
		{
			WORD entry = pEntry[i];
			BYTE type = (entry >> 12) & 0xF;
			WORD offset = entry & 0xFFF;
			DWORD rva = pRelocBlock->VirtualAddress + offset;
			DWORD foa = RvaToFoa(rva);
			if (type == IMAGE_REL_BASED_HIGHLOW)
			{
				PRINT_INFO("%d\t%04x\t\tHIGHLOW\t\t%08x\t%08x\n", i, entry, rva, foa);
			}
			else if (type == IMAGE_REL_BASED_ABSOLUTE)
			{
				PRINT_INFO("%d\t%04x\t\tABS\t\t%08x\t%08x\n", i, entry, rva, foa);
			}
			else
			{
				PRINT_INFO("%d\t0x%04x\t\t%x\t\t0x%08x\t%08x\n", i, entry, type, rva, foa);
			}
		}
		PRINT_INFO("----------------------------------------------------------------\n");
		pRelocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocBlock + pRelocBlock->SizeOfBlock);
	}
}

void CmdRelocColor(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误\t->\t请先使用'load'命令加载PE文件\r\n");
		return;
	}
	if (param == NULL || *param == '\0')
	{
		PRINT_ERROR("错误	->	请输入指定格式地址（格式：1000 / 0x1000)\r\n");
		PRINT_ERROR("示例	->	reloc-color 1000 / reloc-color 0x1000\r\n");
		return;
	}
	DWORD dwRva = 0;
	if (sscanf(param, "0x%x", &dwRva) != 1 && sscanf(param, "%x", &dwRva) != 1)
	{
		PRINT_ERROR("错误	->	无效的地址格式\r\n");
		PRINT_ERROR("示例	->	reloc-color 1000 / reloc-color 0x1000\r\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(dwRva);
	//重定位表判断
	IMAGE_DATA_DIRECTORY dir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (dir.VirtualAddress == 0 || dir.Size == 0)
	{
		PRINT_ERROR("错误\t->\t当前PE文件不存在重定位表\r\n");
		return;
	}
	DWORD dwBaseRelocFoa = RvaToFoa(dir.VirtualAddress);
	if (dwBaseRelocFoa == 0)
	{
		PRINT_ERROR("错误\t->\t重定位结构RVA转换FOA失败\r\n");
		return;
	}
	PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(g_lpFileBuffer + dwBaseRelocFoa);
	std::list<DWORD> relocAddrs;
	while (pRelocBlock->VirtualAddress != 0
		&& pRelocBlock->SizeOfBlock != 0)
	{
		PIMAGE_SECTION_HEADER pSection = ImageRvaToSection(g_pNtHeaders, g_lpFileBuffer, pRelocBlock->VirtualAddress);
		if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
		{
			DWORD entryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD pEntry = (PWORD)((BYTE*)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
			for (size_t i = 0; i < entryCount; i++)
			{
				WORD entry = pEntry[i];
				BYTE type = (entry >> 12) & 0xF;
				WORD offset = entry & 0xFFF;
				DWORD rva = pRelocBlock->VirtualAddress + offset;
				DWORD foa = RvaToFoa(rva);
				if (type == IMAGE_REL_BASED_HIGHLOW)
				{
					relocAddrs.push_back(foa);
				}
				else if (type == IMAGE_REL_BASED_ABSOLUTE)
				{
				}
				else
				{
				}
			}
		}
		pRelocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocBlock + pRelocBlock->SizeOfBlock);
	}
	PRINT_INFO("重定位数量：%d\n", relocAddrs.size());
	const int LENGTH = 0xFF;
	for (size_t i = 0; i < LENGTH / 16; i++)
	{
		PDWORD data = (PDWORD)(g_lpFileBuffer + dwFoa + 16 * i);
		DWORD offset = dwFoa + i * 16;
		int length = 16;
		printf("%08X | ", offset);
		for (size_t i = 0; i < 16 / sizeof(DWORD); i++)
		{
			printf("%08X ", data[i]);
		}
		printf("\n");
	}
}

void CmdTLS(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误\t->\t请先使用'load'命令加载PE文件\r\n");
		return;
	}
	IMAGE_DATA_DIRECTORY tlsDir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDir.VirtualAddress == 0 || tlsDir.Size == 0)
	{
		PRINT_ERROR("错误\t->\t当前PE文件不存在TLS表\r\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(tlsDir.VirtualAddress);
	PRINT_INFO("TLS\tVA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t%s\n", 
		tlsDir.VirtualAddress, 
		tlsDir.VirtualAddress + tlsDir.Size,
		dwFoa,
		dwFoa + tlsDir.Size,
		tlsDir.Size,
		GetSectionNameByRVA(tlsDir.VirtualAddress));
	PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)(g_lpFileBuffer + dwFoa);
	PRINT_TITLE("\n==== TLS Table Info ====\n");
	PRINT_INFO("StartAddressOfRawData\t->%08x\t%s\n", 
		pTls->StartAddressOfRawData,
		GetSectionNameByRVA(pTls->StartAddressOfRawData - g_pNtHeaders->OptionalHeader.ImageBase));
	PRINT_INFO("EndAddressOfRawData\t->%08x\t%s\n", 
		pTls->EndAddressOfRawData, 
		GetSectionNameByRVA(pTls->EndAddressOfRawData - g_pNtHeaders->OptionalHeader.ImageBase));
	PRINT_INFO("AddressOfIndex\t\t->%08x\t%s\n", 
		pTls->AddressOfIndex, 
		GetSectionNameByRVA(pTls->AddressOfIndex - g_pNtHeaders->OptionalHeader.ImageBase));
	PRINT_INFO("AddressOfCallBacks\t->%08x\t%s\n", 
		pTls->AddressOfCallBacks, 
		GetSectionNameByRVA(pTls->AddressOfCallBacks - g_pNtHeaders->OptionalHeader.ImageBase));
	PDWORD pCall = (PDWORD)(g_lpFileBuffer + RvaToFoa(pTls->AddressOfCallBacks - g_pNtHeaders->OptionalHeader.ImageBase));
	PRINT_TITLE("\t序号\tVA\t\tFOA\t\t节区\n");
	int index = 0;
	while (*pCall != 0)
	{
		DWORD addr = *pCall;
		PRINT_ERROR("\t%d\t%08x\t%08x\t%s\n", 
			index++, 
			addr, 
			RvaToFoa(addr - g_pNtHeaders->OptionalHeader.ImageBase),
			GetSectionNameByRVA(addr - g_pNtHeaders->OptionalHeader.ImageBase));
		pCall++;
	}
	PRINT_INFO("SizeOfZeroFill\t\t->%08x\n", pTls->SizeOfZeroFill);
	PRINT_INFO("Characteristics\t\t->%08x\n", pTls->Characteristics);
}

void CmdLoadConfig(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误\t->\t请先使用'load'命令加载PE文件\r\n");
		return;
	}
	IMAGE_DATA_DIRECTORY loadConfigDir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	if (loadConfigDir.VirtualAddress == 0 || loadConfigDir.Size == 0)
	{
		PRINT_ERROR("错误\t->\t当前PE文件不存在加载配置表\r\n");
		return;
	}
	DWORD dwRva = RvaToFoa(loadConfigDir.VirtualAddress);
	PIMAGE_SECTION_HEADER pSection = ImageRvaToSection(g_pNtHeaders, g_lpFileBuffer, loadConfigDir.VirtualAddress);
	PRINT_TITLE("\n==== LOAD_CONFIG Info ====\n");
	PRINT_INFO("VA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t节区:%s\n", 
		loadConfigDir.VirtualAddress, 
		loadConfigDir.VirtualAddress + loadConfigDir.Size,
		dwRva,
		dwRva + loadConfigDir.Size,
		loadConfigDir.Size,
		GetSectionName(pSection));
	PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY)(g_lpFileBuffer + RvaToFoa(loadConfigDir.VirtualAddress));

}

void CmdDelayImport(const CHAR* param)
{
	int add = Add(1, 2);
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误\t->\t请先使用'load'命令加载PE文件\r\n");
		return;
	}
	IMAGE_DATA_DIRECTORY delayImportDir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (delayImportDir.VirtualAddress == 0 || delayImportDir.Size == 0)
	{
		PRINT_ERROR("错误\t->\t当前PE无延迟导入表\n");
		return;
	}
	DWORD dwRva = RvaToFoa(delayImportDir.VirtualAddress);
	PIMAGE_SECTION_HEADER pSection = ImageRvaToSection(g_pNtHeaders, g_lpFileBuffer, delayImportDir.VirtualAddress);
	PRINT_INFO("VA->%08x~%08x\tFOA->%08x~%08x\tSize->%08x\t节区:%s\n", 
		delayImportDir.VirtualAddress, 
		delayImportDir.VirtualAddress + delayImportDir.Size,
		dwRva,
		dwRva + delayImportDir.Size,
		delayImportDir.Size,
		GetSectionName(pSection));
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayload = (PIMAGE_DELAYLOAD_DESCRIPTOR)(g_lpFileBuffer + dwRva);
	PRINT_TITLE("\n==== 延迟导入表 ====\n");
	int index = 0;
	while (pDelayload->DllNameRVA != 0)
	{
		PRINT_INFO("序号\t\t\t->%d\n", index++);
		PRINT_INFO("AllAttributes\t\t->%08x\t//保留字段，通常为0\n", pDelayload->Attributes.AllAttributes);
		PRINT_INFO("DllNameRVA\t\t->%08x\tFOA->%08x\t%s\t//指向以NULL结尾的DLL名称字符串的RVA\n",
			pDelayload->DllNameRVA, 
			RvaToFoa(pDelayload->DllNameRVA),
			g_lpFileBuffer + RvaToFoa(pDelayload->DllNameRVA));
		PRINT_INFO("ModuleHandleRVA\t\t->%08x\tFOA->%08x\t//指向存储DLL模块句柄的RVA，由加载器在加载DLL后填充\n", 
			pDelayload->ModuleHandleRVA,
			RvaToFoa(pDelayload->ModuleHandleRVA));
		PRINT_INFO("ImportAddressTableRVA\t->%08x\tFOA->%08x\t//导入地址表的RVA，初始时包含函数名或序号，加载后会被替换为实际函数地址\n", 
			pDelayload->ImportAddressTableRVA,
			RvaToFoa(pDelayload->ImportAddressTableRVA));
		PRINT_INFO("ImportNameTableRVA\t->%08x\tFOA->%08x\t//导入名称表的RVA，包含函数名或序号信息\n", 
			pDelayload->ImportNameTableRVA,
			RvaToFoa(pDelayload->ImportNameTableRVA));
		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(g_lpFileBuffer + RvaToFoa(pDelayload->ImportNameTableRVA));
		PRINT_INFO("\n导入函数列表\n");
		PRINT_INFO("序号\tThunkRva\tOrdinal\t\tHint\t名称\n");
		PRINT_INFO("----------------------------------------------\n");
		for (size_t j = 0; pINT->u1.AddressOfData != 0; j++, pINT++)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
			{
				WORD ordinal = IMAGE_ORDINAL(pINT->u1.Ordinal);
				PRINT_INFO("%d\t\t\t%08x\n", j, ordinal);
			}
			else
			{
				DWORD dwNameFoa = RvaToFoa(pINT->u1.AddressOfData);
				if (dwNameFoa)
				{
					PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(g_lpFileBuffer + dwNameFoa);
					PRINT_INFO("%d\t%08x\t\t\t%04x\t%-25s\n",
						j,
						pINT->u1.AddressOfData,
						pImportName->Hint,
						pImportName->Name);
				}
			}
		}
		PRINT_INFO("BoundImportAddressTableRVA\t->%08x\t//可选的绑定导入地址表RVA，用于存储绑定信息\n", pDelayload->BoundImportAddressTableRVA);
		PRINT_INFO("UnloadInformationTableRVA\t->%08x\t//卸载信息表RVA，包含卸载DLL所需的信息\n", pDelayload->UnloadInformationTableRVA);
		PRINT_INFO("TimeDateStamp\t\t\t->%08x\t//DLL的时间戳，用于验证预绑定信息的有效性\n", pDelayload->TimeDateStamp);
		pDelayload++;
	}
}

void CmdIAT(const CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误\t->\t请先使用'load'命令加载PE文件\r\n");
		return;
	}
	IMAGE_DATA_DIRECTORY iatDir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	if (iatDir.VirtualAddress == 0 || iatDir.Size == 0)
	{
		PRINT_ERROR("错误\t->\t当前PE无IAT表\n");
		return;
	}
	PRINT_TITLE("\n==== IAT表 ====\n");
	DWORD dwFoa = RvaToFoa(iatDir.VirtualAddress);
	PRINT_INFO("VA->%08X~%08x\tFOA->%08x~%08x\tSize->%08x\t节区:%s\n", 
		iatDir.VirtualAddress, 
		iatDir.VirtualAddress + iatDir.Size,
		dwFoa,
		dwFoa + iatDir.Size,
		iatDir.Size,
		GetSectionNameByRVA(iatDir.VirtualAddress));
	PRINT_INFO("序号\tRVA\t\tFOA\t\tHint\t名称\n");
	PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(g_lpFileBuffer + dwFoa);
	for (size_t i = 0; i < iatDir.Size / sizeof(DWORD); i++)
	{
		if (IMAGE_SNAP_BY_ORDINAL(pThunk[i].u1.Ordinal))
		{
			WORD ordinal = IMAGE_ORDINAL(pThunk[i].u1.Ordinal);
			PRINT_INFO("%d\t\t\t\t\t%08x\n", i, ordinal);
		}
		else
		{
			DWORD dwNameFoa = RvaToFoa(pThunk[i].u1.AddressOfData);
			if (dwNameFoa)
			{
				PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(g_lpFileBuffer + dwNameFoa);
				PRINT_INFO("%d\t%08x\t%08x\t%04x\t%-25s\n",
					i,
					pThunk[i].u1.AddressOfData,
					dwNameFoa,
					pImportName->Hint,
					pImportName->Name);
			}
		}
	}
}

void CmdRvaToFoa(const CHAR* param)
{
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'命令加载PE文件\r\n");
		return;
	}
	if (param == NULL || *param == '\0')
	{
		PRINT_ERROR("错误	->	请输入指定格式地址（格式：1000 / 0x1000)\r\n");
		PRINT_ERROR("示例	->	rva 1000 / rva 0x1000\r\n");
		return;
	}
	DWORD dwRva = 0;
	if (sscanf(param, "0x%x", &dwRva) != 1 && sscanf(param, "%x", &dwRva) != 1)
	{
		PRINT_ERROR("错误	->	无效的地址格式\r\n");
		PRINT_ERROR("示例	->	rva 1000 / rva 0x1000\r\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(dwRva);
	if (dwFoa == 0)
	{
		PRINT_ERROR("错误	->	地址转换失败\r\n");
		return;
	}
	PRINT_INFO("\n地址转换结果：\n");
	PRINT_INFO("RVA:0x%08X	->	FOA:0x%08X\n\n", dwRva, dwFoa);

	for (size_t i = 0; i < g_pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSection = g_pSectionHeader + i;
		DWORD dwStartRva = pSection->VirtualAddress;
		DWORD dwEndRva = pSection->VirtualAddress + pSection->Misc.VirtualSize;

		if (dwRva >= dwStartRva && dwRva < dwEndRva)
		{
			PRINT_INFO("所属节区：%s\n", GetSectionName(pSection));
			PRINT_INFO("节区RVA范围：0x%08X - 0x%08X\n", dwStartRva, dwEndRva);
			PRINT_INFO("节区FOA范围：0x%08X - 0x%08X\n", pSection->PointerToRawData, pSection->PointerToRawData + pSection->SizeOfRawData);
		}
	}
}

void CmdFoaToRva(const CHAR* param)
{
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'命令加载PE文件\r\n");
		return;
	}
	if (param == NULL || *param == '\0')
	{
		PRINT_ERROR("错误	->	请输入指定格式地址（格式：1000 / 0x1000)\r\n");
		PRINT_ERROR("示例	->	foa 1000 / foa 0x1000\r\n");
		return;
	}
	DWORD dwFoa = 0;
	if (sscanf(param, "0x%x", &dwFoa) != 1 && sscanf(param, "%x", &dwFoa) != 1)
	{
		PRINT_ERROR("错误	->	无效的地址格式\r\n");
		PRINT_ERROR("示例	->	foa 1000 / foa 0x1000\r\n");
		return;
	}
	DWORD dwRva = FoaToRva(dwFoa);
	if (dwRva == 0)
	{
		PRINT_ERROR("错误	->	地址转换失败\r\n");
		return;
	}
	PRINT_INFO("\n地址转换结果：\n");
	PRINT_INFO("FOA:0x%08X	->	RVA:0x%08X\n\n", dwFoa, dwRva);

	for (size_t i = 0; i < g_pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSection = g_pSectionHeader + i;
		DWORD dwStartRva = pSection->VirtualAddress;
		DWORD dwEndRva = pSection->VirtualAddress + pSection->Misc.VirtualSize;

		if (dwRva >= dwStartRva && dwRva < dwEndRva)
		{
			PRINT_INFO("所属节区：%s\n", GetSectionName(pSection));
			PRINT_INFO("节区RVA范围：0x%08X - 0x%08X\n", dwStartRva, dwEndRva);
			PRINT_INFO("节区FOA范围：0x%08X - 0x%08X\n", pSection->PointerToRawData, pSection->PointerToRawData + pSection->SizeOfRawData);
		}
	}
}

void CmdClear(const CHAR* param)
{
}

void CmdHelp(const CHAR* param)
{
}

void CmdCmp(const CHAR* param)
{
	char cmd[MAX_PATH] = {};
	char file1[MAX_PATH] = {};
	char file2[MAX_PATH] = {};
	PBYTE file1buff = nullptr;
	PBYTE file2buff = nullptr;
	if (sscanf(cmdLine, "%31s %255s %255s", cmd, file1, file2) == 3)
	{
		if (!std::filesystem::exists(file1))
		{
			PRINT_ERROR("文件->%s不存在\n", file1);
			return;
		}
		if (!std::filesystem::exists(file2))
		{
			PRINT_ERROR("文件->%s不存在\n", file2);
			return;
		}
		PRINT_TITLE("开始比较文件 %s和%s\n", file1, file2);
		DWORD file1Size = std::filesystem::file_size(file1);
		file1buff = (PBYTE)malloc(file1Size);
		if (file1buff == nullptr)
		{
			PRINT_ERROR("申请内存失败\n");
			return;
		}
		DWORD file2Size = std::filesystem::file_size(file2);
		file2buff = (PBYTE)malloc(file2Size);
		if (file2buff == nullptr)
		{
			PRINT_ERROR("申请内存失败\n");
			return;
		}
		if (!ReadFileMemory(file1, file1buff, file1Size))
		{
			PRINT_ERROR("读取文件失败:%s\n", file1);
			goto end;
		}
		if (!ReadFileMemory(file2, file2buff, file2Size))
		{
			PRINT_ERROR("读取文件失败:%s\n", file2);
			goto end;
		}
		PRINT_INFO("文件1长度：%d\t文件2长度:%d\n", file1Size, file2Size);
		for (int i = 0; i < min(file1Size, file2Size); i++)
		{
			if (file1buff[i] != file2buff[i])
			{
				PRINT_INFO("%08x\t%02x<=>%02x\n", i, file1buff[i], file2buff[i]);
			}
		}
	}
	else
	{
		PRINT_ERROR("错误 示例：cmp xxx\\xxx.exe xxx\\xxx.exe");
	}
end:
	if (file1buff)
	{
		free(file1buff);
		file1buff = nullptr;
	}
	if (file2buff)
	{
		free(file2buff);
		file2buff = nullptr;
	}
}

void CmdDump(const CHAR* param)
{
	DWORD pid = 0;
	if (sscanf(param, "%d", &pid) == 1)
	{
		PRINT_TITLE("开始dump进程：%d\n", pid);
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (hProcess == INVALID_HANDLE_VALUE)
		{
			PRINT_ERROR("打开进程失败！\n");
			return;
		}
		HMODULE hMods[1024] = {};
		DWORD cbNeeded = 0;
		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			//取第一个
			std::string fileName(MAX_PATH, 0);
			DWORD len = GetModuleFileNameExA(hProcess, hMods[0], fileName.data(), MAX_PATH);
			DWORD fileSize = std::filesystem::file_size(fileName);
			PRINT_INFO("文件大小：%d\t进程文件：%s\n", fileSize, fileName.c_str());

			std::string name = std::filesystem::path(fileName).filename().string();
			IMAGE_DOS_HEADER dos = {};
			if (!ReadProcessMemory(hProcess, (LPCVOID)hMods[0], &dos, sizeof(IMAGE_DOS_HEADER), nullptr))
			{
				PRINT_ERROR("读取进程dos头内存失败\n");
				return;
			}
			IMAGE_NT_HEADERS nt = {};
			if (!ReadProcessMemory(hProcess, (LPCVOID)((PBYTE)hMods[0] + dos.e_lfanew), &nt, sizeof(nt), nullptr))
			{
				PRINT_ERROR("读取进程NT头内存失败\n");
				return;
			}
			DWORD sizeOfImage = nt.OptionalHeader.SizeOfImage;
			PRINT_INFO("进程主模块映像大小：%08x\n", sizeOfImage);
			PBYTE buff = (PBYTE)malloc(sizeOfImage);
			if (buff == nullptr)
			{
				PRINT_ERROR("申请内存失败！大小：%d\n", sizeOfImage);
				return;
			}
			if (!ReadProcessMemory(hProcess, (LPCVOID)hMods[0], buff, sizeOfImage, nullptr))
			{
				PRINT_ERROR("读取进程模块内存失败，大小：%08x\n", sizeOfImage);
				return;
			}
			PRINT_TITLE("\n==== PE信息 ====\n");
			PRINT_INFO("NumberOfSections\t->%04x\n", nt.FileHeader.NumberOfSections);
			PRINT_INFO("ImageBase\t\t->%08x\n", nt.OptionalHeader.ImageBase);
			PRINT_INFO("AddressOfEntryPoint\t->%08x\n", nt.OptionalHeader.AddressOfEntryPoint);
			PRINT_INFO("SectionAlignment\t->%08x\n", nt.OptionalHeader.SectionAlignment);
			PRINT_INFO("FileAlignment\t\t->%08x\n", nt.OptionalHeader.FileAlignment);
			PRINT_INFO("SizeOfImage\t\t->%08x\n", nt.OptionalHeader.SizeOfImage);
			PRINT_TITLE("\n==== 数据目录 ====\n");
			for (size_t i = 0; i < nt.OptionalHeader.NumberOfRvaAndSizes; i++)
			{
				IMAGE_DATA_DIRECTORY dir = nt.OptionalHeader.DataDirectory[i];
				if (dir.VirtualAddress > 0 && dir.Size > 0)
				{
					PRINT_INFO("%d\tVirtualAddress->%08x\tSize->%08x\n", i, dir.VirtualAddress, dir.Size);
				}
			}
			PRINT_TITLE("\n==== 节区 ====\n");
			PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(buff + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS));
			DWORD fileBuffSize = pSection[nt.FileHeader.NumberOfSections - 1].PointerToRawData + pSection[nt.FileHeader.NumberOfSections - 1].SizeOfRawData;
			PRINT_INFO("dump文件大小：%d\n", fileBuffSize);
			PBYTE fileBuff = (PBYTE)malloc(fileBuffSize);
			if (fileBuff == nullptr)
			{
				PRINT_ERROR("申请内存失败！%d\n", fileBuffSize);
				return;
			}
			ZeroMemory(fileBuff, fileBuffSize);
			memcpy_s(fileBuff, nt.OptionalHeader.SizeOfHeaders, buff, nt.OptionalHeader.SizeOfHeaders);
			for (size_t i = 0; i < nt.FileHeader.NumberOfSections; i++)
			{
				PRINT_INFO("%-8s\tPointerToRawData->%08x\tSizeOfRawData->%08x\n", GetSectionName(pSection), pSection[i].PointerToRawData, pSection[i].SizeOfRawData);
				if (pSection[i].SizeOfRawData > 0)
				{
					memcpy_s(fileBuff + pSection[i].PointerToRawData, pSection[i].SizeOfRawData, buff + pSection[i].VirtualAddress, pSection[i].SizeOfRawData);
				}
			}
			FILE* file = nullptr;
			fopen_s(&file, name.c_str(), "wb");
			if (file == nullptr)
			{
				printf("打开写入文件失败！%s\n", name.c_str());
				return;
			}
			fwrite(fileBuff, 1, fileBuffSize, file);
			fclose(file);
		end:
			if (fileBuff != nullptr)
			{
				free(fileBuff);
				fileBuff = nullptr;
			}
			if (buff != nullptr)
			{
				free(buff);
				buff = nullptr;
			}
		}
		else
		{
			PRINT_ERROR("EnumProcessModules fail->%d\n", GetLastError());
		}
		CloseHandle(hProcess);
	}
	else
	{
		PRINT_ERROR("错误 示例 dump 1234 //进程id");
		return;
	}
}

void CmdExit(const CHAR* param)
{
}

void CmdRead(const CHAR* param)
{
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'命令加载PE文件\r\n");
		return;
	}
	if (param == NULL || *param == '\0')
	{
		PRINT_ERROR("错误	->	请输入指定格式地址（格式：1000 / 0x1000)\r\n");
		PRINT_ERROR("示例	->	rva 1000 / rva 0x1000\r\n");
		return;
	}
	DWORD dwRva = 0;
	if (sscanf(param, "0x%x", &dwRva) != 1 && sscanf(param, "%x", &dwRva) != 1)
	{
		PRINT_ERROR("错误	->	无效的地址格式\r\n");
		PRINT_ERROR("示例	->	rva 1000 / rva 0x1000\r\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(dwRva);
	const int LENGTH = 0xFF;
	for (size_t i = 0; i < LENGTH / 16; i++)
	{
		HexAscii(g_lpFileBuffer + dwFoa + 16 * i, dwRva + 16 * i, 16);
	}
}

void CmdReadStr(const CHAR* param)
{
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'命令加载PE文件\r\n");
		return;
	}
	if (param == NULL || *param == '\0')
	{
		PRINT_ERROR("错误	->	请输入指定格式地址（格式：1000 / 0x1000)\r\n");
		PRINT_ERROR("示例	->	rva 1000 / rva 0x1000\r\n");
		return;
	}
	DWORD dwRva = 0;
	if (sscanf(param, "0x%x", &dwRva) != 1 && sscanf(param, "%x", &dwRva) != 1)
	{
		PRINT_ERROR("错误	->	无效的地址格式\r\n");
		PRINT_ERROR("示例	->	rva 1000 / rva 0x1000\r\n");
		return;
	}
	DWORD dwFoa = RvaToFoa(dwRva);
	PBYTE str = g_lpFileBuffer + dwFoa;
	PRINT_INFO("字符：%s\n", str);
}
bool WriteFile(const char* fileName, PBYTE data, DWORD length)
{
	FILE* file = nullptr;
	fopen_s(&file, fileName, "wb");
	if (file == nullptr)
	{
		PRINT_ERROR("打开文件失败:%s->%d\n", fileName, GetLastError());
		return false;
	}
	fwrite(data, 1, length, file);
	fclose(file);
	return true;
}
void CmdShellCode(CONST CHAR* param)
{
	if (g_pNtHeaders == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'命令加载PE文件\r\n");
		return;
	}
	PRINT_TITLE("\n==== shellcode ====\n");
	PIMAGE_SECTION_HEADER pSection = g_pSectionHeader;
	DWORD dwFoa = 0;
	DWORD length = 0;
	const DWORD MAXZERO = 16 * 4;
	PBYTE startData = nullptr;
	for (size_t i = 0; i < g_pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			PRINT_INFO("节区->%s\n", GetSectionName(pSection));
			for (PBYTE data = (g_lpFileBuffer + pSection->PointerToRawData); data < (g_lpFileBuffer + pSection->PointerToRawData + pSection->SizeOfRawData); data++)
			{
				if (*data == 0)
				{
					length++;
					if (length >= MAXZERO)
					{
						startData = data - length;
						break;
					}
				}
				else
				{
					length = 0;
				}
			}
			break;
		}
	}
	if (startData)
	{
		DWORD insertAddr = startData - g_lpFileBuffer;
		if (insertAddr % 16)
		{
			insertAddr = (insertAddr / 16 + 1) * 16;
		}
		DWORD dwRva = FoaToRva(insertAddr);
		DWORD va = g_pNtHeaders->OptionalHeader.ImageBase + dwRva;
		PRINT_INFO("写入起始RVA->%08x\tFOA->%08x\n", dwRva, insertAddr);
		//以下完成如下指令
		// Invoke MessageBoxA(NULL, NULL, NULL, NULL);
		// jmp OPE
		char shellcode[] = {
			0x6A, 0x00, //push 0
			0x6A, 0x00, //push 0
			0x6A, 0x00, //push 0
			0x6A, 0x00, //push 0
			0xE8, 0x5F, 0x88, 0xC4, 0x75, //call MessageBoxA
			0xE9, 0x4E, 0xFE, 0xFF, 0xFF  // JMP OEP
		};
		//0x76101A50为MessageBoxA的VA地址
		DWORD messageBoxAAddr = (DWORD)&MessageBoxA;
		//8为前面占用的4个push 0,5为call指令长度
		DWORD callAddr = messageBoxAAddr - va - 8 - 5;
		memcpy_s(shellcode + 9, 4, &callAddr, 4);
		DWORD oep = g_pNtHeaders->OptionalHeader.ImageBase + g_pNtHeaders->OptionalHeader.AddressOfEntryPoint;
		// 13为前面占用，5为jmp指令长度
		DWORD jmpAddr = oep - va - 13 - 5;
		memcpy_s(shellcode + 14, 4, &jmpAddr, 4);
		//更改OEP
		PRINT_INFO("更改OEP：%08x->%08x\n", g_pNtHeaders->OptionalHeader.AddressOfEntryPoint, dwRva);
		g_pNtHeaders->OptionalHeader.AddressOfEntryPoint = dwRva;
		//写入到文件内存中
		PRINT_INFO("写入执行代码\n");
		for (size_t i = 0; i < sizeof(shellcode); i++)
		{
			if (i % 16 == 0)
			{
				PRINT_INFO("\n");
			}
			PRINT_INFO("%02x ", (BYTE)shellcode[i]);
		}
		PRINT_INFO("\n");
		memcpy_s(g_lpFileBuffer + insertAddr, sizeof(shellcode), shellcode, sizeof(shellcode));
		std::string newFileName = std::filesystem::path(fileName).parent_path().append("wo.exe").string();
		WriteFile(newFileName.c_str(), g_lpFileBuffer, g_dwFileSize);
		PRINT_INFO("已重新写入文件：%s\n", newFileName.c_str());
	}
	else
	{
		PRINT_ERROR("未找到合适的位置插入shellcode\n");
	}
}

void FreeLoadedFile()
{
	if (g_lpFileBuffer)
	{
		free(g_lpFileBuffer);
		g_lpFileBuffer = nullptr;
	}

	if (g_hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_hFile);
		g_hFile = INVALID_HANDLE_VALUE;
	}

	g_dwFileSize = 0;
	g_pDosHeader = nullptr;
	g_pNtHeaders = nullptr;
	g_pSectionHeader = nullptr;
	ZeroMemory(fileName, sizeof(fileName));
}

bool ReadFileMemory(const char* fileName, PBYTE buff, DWORD length)
{
	FILE* file = nullptr;
	fopen_s(&file, fileName, "rb");
	if (file == nullptr)
	{
		return false;
	}
	fread(buff, 1, length, file);
	fclose(file);
	return true;
}

const char* GetSectionName(PIMAGE_SECTION_HEADER pSection, bool first)
{
	if (first)
	{
		ZeroMemory(g_SectionName, IMAGE_SIZEOF_SHORT_NAME);
		if (pSection)
		{
			memcpy_s(g_SectionName, IMAGE_SIZEOF_SHORT_NAME, pSection->Name, IMAGE_SIZEOF_SHORT_NAME);
		}
		return g_SectionName;
	}
	else
	{
		ZeroMemory(g_SectionName2, IMAGE_SIZEOF_SHORT_NAME);
		if (pSection)
		{
			memcpy_s(g_SectionName2, IMAGE_SIZEOF_SHORT_NAME, pSection->Name, IMAGE_SIZEOF_SHORT_NAME);
		}
		return g_SectionName2;
	}
}
const char* GetSectionNameByRVA(DWORD dwRva, bool first)
{
	PIMAGE_SECTION_HEADER pSection = ImageRvaToSection(g_pNtHeaders, g_lpFileBuffer, dwRva);
	return GetSectionName(pSection, first);
}
const char* GetSectionNameByFOA(DWORD dwFoa, bool first)
{
	DWORD rva = FoaToRva(dwFoa);
	return GetSectionNameByRVA(rva, first);
}
CmdHandler FindCmdHandler(const CHAR* cmd)
{
	for (CONST CmdEntry* entry = CMD_TABLE; entry->cmd != nullptr; entry++)
	{
		if (strcmp(cmd, entry->cmd) == 0)
		{
			return entry->handler;
		}
	}
	return nullptr;
}

DWORD GetExportFuncAddrByName(const CHAR* funcName)
{
	if (!g_pNtHeaders || !funcName) return 0;
	IMAGE_DATA_DIRECTORY dir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir.VirtualAddress || !dir.Size) return 0;

	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + RvaToFoa(dir.VirtualAddress));
	PDWORD pAddressOfFunctions = (PDWORD)(g_lpFileBuffer + RvaToFoa(pExportTable->AddressOfFunctions));
	PDWORD pAddressOfNames = (PDWORD)(g_lpFileBuffer + RvaToFoa(pExportTable->AddressOfNames));
	PWORD pAddressOfNameOrdinals = (PWORD)(g_lpFileBuffer + RvaToFoa(pExportTable->AddressOfNameOrdinals));

	for (size_t i = 0; i < pExportTable->NumberOfNames; i++)
	{
		DWORD dwNameFoa = RvaToFoa(pAddressOfNames[i]);
		if (dwNameFoa == 0) continue;

		PCHAR szName = (PCHAR)(g_lpFileBuffer + dwNameFoa);
		if (strcmp(szName, funcName) == 0)
		{
			WORD index = pAddressOfNameOrdinals[i];
			return pAddressOfFunctions[index];
		}
	}
	return 0;
}

DWORD GetExportFuncAddrByIndex(DWORD dwIndex)
{
	if (!g_pNtHeaders) return 0;
	IMAGE_DATA_DIRECTORY dir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir.VirtualAddress || !dir.Size) return 0;

	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + RvaToFoa(dir.VirtualAddress));
	PDWORD pAddressOfFunctions = (PDWORD)(g_lpFileBuffer + RvaToFoa(pExportTable->AddressOfFunctions));
	PDWORD pAddressOfNames = (PDWORD)(g_lpFileBuffer + RvaToFoa(pExportTable->AddressOfNames));
	PWORD pAddressOfNameOrdinals = (PWORD)(g_lpFileBuffer + RvaToFoa(pExportTable->AddressOfNameOrdinals));

	DWORD index = dwIndex - pExportTable->Base;
	if (index >= pExportTable->NumberOfFunctions)
		return 0;
	if (index < 0) return 0;

	return pAddressOfFunctions[index];
}

DWORD GetExportNameByFuncAddr(DWORD dwFuncRva)
{
	if (!g_pNtHeaders) return 0;
	IMAGE_DATA_DIRECTORY dir = g_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir.VirtualAddress || !dir.Size) return 0;

	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + RvaToFoa(dir.VirtualAddress));
	PDWORD pAddressOfFunctions = (PDWORD)(g_lpFileBuffer + RvaToFoa(pExportTable->AddressOfFunctions));
	PDWORD pAddressOfNames = (PDWORD)(g_lpFileBuffer + RvaToFoa(pExportTable->AddressOfNames));
	PWORD pAddressOfNameOrdinals = (PWORD)(g_lpFileBuffer + RvaToFoa(pExportTable->AddressOfNameOrdinals));

	for (size_t i = 0; i < pExportTable->NumberOfFunctions; i++)
	{
		if (pAddressOfFunctions[i] == dwFuncRva)
		{
			for (size_t j = 0; j < pExportTable->NumberOfNames; j++)
			{
				if (pAddressOfNameOrdinals[j] == i)
				{
					return pAddressOfNames[j];
				}
			}
		}
	}
	return 0;
}

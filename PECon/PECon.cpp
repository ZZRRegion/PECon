#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<stdio.h>
#include<time.h>

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
HANDLE g_hFile = INVALID_HANDLE_VALUE;
DWORD g_dwFileSize = 0;
PBYTE g_lpFileBuffer = nullptr;
PIMAGE_DOS_HEADER g_pDosHeader = nullptr;
PIMAGE_NT_HEADERS g_pNtHeaders = nullptr;
PIMAGE_SECTION_HEADER g_pSectionHeader = nullptr;
char fileName[MAX_PATH] = {};
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
void CmdImport(CONST CHAR* param);
void CmdExport(CONST CHAR* param);
void CmdRelocation(CONST CHAR* param);
void CmdRvaToFoa(CONST CHAR* param);
void CmdFoaToRva(CONST CHAR* param);
void CmdClear(CONST CHAR* param);
void CmdHelp(CONST CHAR* param);
void CmdExit(CONST CHAR* param);
void CmdRead(CONST CHAR* param);
void CmdReadStr(CONST CHAR* param);
void FreeLoadedFile();
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
	{"load",		CmdLoad},
	{"info",		CmdInfo},
	{"dos",			CmdDos},
	{"nt",			CmdNt},
	{"section",		CmdSection},
	{"import",		CmdImport},
	{"export",		CmdExport},
	{"relocation",	CmdRelocation},
	{"rva",			CmdRvaToFoa },
	{"foa",			CmdFoaToRva},
	{"clear",		CmdClear},
	{"help",		CmdHelp},
	{"exit",		CmdExit},
	{"read",        CmdRead},
	{"readStr",     CmdReadStr},
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
	PRINT_MENU("    load		- 加载PE文件\n");
	PRINT_MENU("    info		- 显示PE基本信息\n");
	PRINT_MENU("    dos			- 显示DOS数据\n");
	PRINT_MENU("    nt			- 显示NT数据\n");
	PRINT_MENU("    section		- 显示SECTION数据\n");
	PRINT_MENU("    import		- 显示IMPORT数据\n");
	PRINT_MENU("    export		- 显示EXPORT\n");
	PRINT_MENU("    relocation		- 显示RELOCATION数据\n");
	PRINT_MENU("    rva		- RVA	->	FOA\n");
	PRINT_MENU("    foa		- FOA	->	RVA\n");
	PRINT_MENU("    clear		- 清屏\n");
	PRINT_MENU("    help		- 获取帮助\n");
	PRINT_MENU("    exit		- 退出程序\n");
	PRINT_MENU("当前加载文件：%s\n", fileName);
	PRINT_INFO("请输入命令> ");
}
VOID ProcessCommand()
{
	CHAR cmdLine[0xFF] = {};
	CHAR cmd[32] = {};
	CHAR param[0xff] = {};
	if (fgets(cmdLine, 0xff, stdin))
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
		DWORD dwStartRva = g_pSectionHeader[i].VirtualAddress;
		DWORD dwEndRva = g_pSectionHeader[i].VirtualAddress + g_pSectionHeader[i].Misc.VirtualSize;
		if (dwRva >= dwStartRva && dwRva < dwEndRva)
		{
			DWORD dwOffset = dwRva - dwStartRva;
			return g_pSectionHeader[i].PointerToRawData + dwOffset;
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
		DWORD dwStartFoa = g_pSectionHeader[i].PointerToRawData;
		DWORD dwEndFoa = g_pSectionHeader[i].PointerToRawData + g_pSectionHeader[i].SizeOfRawData;
		if (dwFoa >= dwStartFoa && dwFoa < dwEndFoa)
		{
			DWORD dwOffset = dwFoa - dwStartFoa;
			return g_pSectionHeader[i].VirtualAddress + dwOffset;
		}
	}
	return 0;
}
// =======================================================

int main()
{
	const char* file = R"(C:\Users\stdio\source\repos\PECon\Debug\PEDll.dll)";
	//fileName = "D:\\DriverDevelop\\InstDrv\\InstDrv.exe";
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
	PRINT_ERROR("	00014h	NumberOfRvaAndSizes	->	0x%08X	目录数量\r\n", pOptionalHeader->NumberOfRvaAndSizes);

	for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		if (pOptionalHeader->DataDirectory[i].VirtualAddress != 0)
		{
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
			PRINT_INFO("		VirtualAddress		->	0x%08x	Size->0x%08x	%s\r\n",
				pOptionalHeader->DataDirectory[i].VirtualAddress,
				pOptionalHeader->DataDirectory[i].Size,
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
	for (size_t i = 0; i < g_pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSection = &g_pSectionHeader[i];
		CHAR szName[9] = {};
		memcpy(szName, pSection->Name, IMAGE_SIZEOF_SHORT_NAME);
		PRINT_INFO("===================================%s========================================\n", szName);
		PRINT_INFO("	0004h	Name		->	%s		//节区名称\r\n", szName);
		PRINT_INFO("	0004h	VirtualSize	->	0x%08x	//RVA大小\r\n", pSection->Misc.VirtualSize);
		PRINT_INFO("	0004h	VirtualAddress	->	0x%08x	//RVA起始\r\n", pSection->VirtualAddress);
		PRINT_INFO("	0004h	SizeOfRawData	->	0x%08x	//FOA大小\r\n", pSection->SizeOfRawData);
		PRINT_INFO("	0004h	PointerToRawData->	0x%08x	//FOA起始\r\n", pSection->PointerToRawData);
		PRINT_INFO("	0004h	Characteristics	->	0x%08x	//节区属性\r\n", pSection->Characteristics);
		for (size_t i = 0; i < sizeof(scnFlags) / sizeof(scnFlags[0]); i++)
		{
			if (pSection->Characteristics & scnFlags[i].flag)
			{
				PRINT_ERROR("		FLAG->0x%08x	INFO->%s\n", scnFlags[i].flag, scnFlags[i].desc);
			}
		}
		PRINT_INFO("================================================================================\n");
	}
	PRINT_INFO("\nSummary\n");
	PRINT_INFO("Total Section:%d\n", g_pNtHeaders->FileHeader.NumberOfSections);

	DWORD totalVirtualSize = 0;
	DWORD totalRawSize = 0;
	for (size_t i = 0; i < g_pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		totalVirtualSize += g_pSectionHeader[i].Misc.VirtualSize;
		totalRawSize += g_pSectionHeader[i].SizeOfRawData;
	}

	PRINT_INFO("Total Virtual Size:%d\n", totalVirtualSize);
	PRINT_INFO("Total Raw Size:%d\n", totalRawSize);

}			 
void CmdImport(const CHAR* param)
{
	if (g_pSectionHeader == nullptr)
	{
		PRINT_ERROR("错误	->	请先使用'load'加载PE文件\r\n");
		return;
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
	PRINT_INFO("VirtualAddress->0x%08X	Size->0x%08X\n\n", exportDir.VirtualAddress, exportDir.Size);
	DWORD dwFoa = RvaToFoa(exportDir.VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + dwFoa);
	dwFoa = RvaToFoa(pExport->Name);
	const char* szName = (const char*)(g_lpFileBuffer + dwFoa);
	PRINT_INFO("0000h	Name			->	0x%08X	DLL名称：%s\n", pExport->Name, szName);
	PRINT_INFO("0000h	Base			->	0x%08X	//导出函数的起始序号\n", pExport->Base);
	PRINT_INFO("0000h	NumberOfFunctions	->	0x%08X	//导出函数的数量(最大的导出序号-最小的导出序号+1)\n", pExport->NumberOfFunctions);
	PRINT_INFO("0000h	NumberOfNames		->	0x%08X	//函数名称导出的数量\n", pExport->NumberOfNames);
	PRINT_INFO("0000h	AddressOfFunctions	->	0x%08X	//导出函数地址表(RVA)指向4字节的数组(大小为NumOfFun)\n", pExport->AddressOfFunctions);
	PRINT_INFO("0000h	AddressOfNames		->	0x%08X\n", pExport->AddressOfNames);
	PRINT_INFO("0000h	AddressOfNameOrdinals	->	0x%08X\n", pExport->AddressOfNameOrdinals);


}

void CmdRelocation(const CHAR* param)
{
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
		DWORD dwStartRva = g_pSectionHeader[i].VirtualAddress;
		DWORD dwEndRva = g_pSectionHeader[i].VirtualAddress + g_pSectionHeader[i].Misc.VirtualSize;

		if (dwRva >= dwStartRva && dwRva < dwEndRva)
		{
			PRINT_INFO("所属节区：%s\n", g_pSectionHeader[i].Name);
			PRINT_INFO("节区RVA范围：0x%08X - 0x%08X\n", dwStartRva, dwEndRva);
			PRINT_INFO("节区FOA范围：0x%08X - 0x%08X\n", g_pSectionHeader[i].PointerToRawData, g_pSectionHeader[i].PointerToRawData + g_pSectionHeader[i].SizeOfRawData);
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
		DWORD dwStartRva = g_pSectionHeader[i].VirtualAddress;
		DWORD dwEndRva = g_pSectionHeader[i].VirtualAddress + g_pSectionHeader[i].Misc.VirtualSize;

		if (dwRva >= dwStartRva && dwRva < dwEndRva)
		{
			PRINT_INFO("所属节区：%s\n", g_pSectionHeader[i].Name);
			PRINT_INFO("节区RVA范围：0x%08X - 0x%08X\n", dwStartRva, dwEndRva);
			PRINT_INFO("节区FOA范围：0x%08X - 0x%08X\n", g_pSectionHeader[i].PointerToRawData, g_pSectionHeader[i].PointerToRawData + g_pSectionHeader[i].SizeOfRawData);
		}
	}
}

void CmdClear(const CHAR* param)
{
}

void CmdHelp(const CHAR* param)
{
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

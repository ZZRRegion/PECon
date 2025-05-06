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

// ==============================================

void CmdLoad(CONST CHAR* param);
void CmdInfo(CONST CHAR* param);
void CmdDos(CONST CHAR* param);
void CmdNt(CONST CHAR* param);
void CmdSection(CONST CHAR* param);
void CmdImport(CONST CHAR* param);
void CmdExport(CONST CHAR* param);
void CmdRelocation(CONST CHAR* param);
void CmdClear(CONST CHAR* param);
void CmdHelp(CONST CHAR* param);
void CmdExit(CONST CHAR* param);

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
	{"clear",		CmdClear},
	{"help",		CmdHelp},
	{"exit",		CmdExit},
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
	PRINT_MENU("    clear		- 清屏\n");
	PRINT_MENU("    help		- 获取帮助\n");
	PRINT_MENU("    exit		- 退出程序\n");

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
// =======================================================

int main()
{
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
	PRINT_ERROR("	0000h	Machine					->		0x%04X	运行平台\r\n", pFileHeader->Machine);
	PRINT_ERROR("	0002h	NumberOfSections			->		0x%04X	节区数量\r\n", pFileHeader->NumberOfSections);
	PRINT_INFO("	0004h	TimeDateStamp				->		0x%08X	时间戳\r\n", pFileHeader->TimeDateStamp);
	/*time_t time = (time_t)pFileHeader->TimeDateStamp;
	tm localTime = {0};
	localtime_s(&localTime, &time);
	CHAR timeBuffer[0xFF] = {0};
	strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%s", &localTime);
	PRINT_INFO("	0004h	TimeDateStamp	->	%s\r\n", timeBuffer);*/
	PRINT_ERROR("	00010h	SizeOfOptionalHeader			->		0x%04X	可选头字节数\r\n", pFileHeader->SizeOfOptionalHeader);
	PRINT_INFO("	00012h	Characteristics				->		0x%04X	文件特性\r\n", pFileHeader->Characteristics);
	PRINT_INFO("\n");

	PRINT_INFO("--------------\r\n");
	PRINT_INFO("3.OptionHeader\r\n");
	PRINT_INFO("--------------\n\n");
	

	PRINT_TITLE("\n==== Nt Option Header Infomation ====\n\n");
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_pNtHeaders->OptionalHeader;
	/*
	WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	*/
	PRINT_INFO("	00014h	Magic	->	0x%04X	表示文件类型：0x010B(32位PE),0x020B(64位PE)\r\n", pOptionalHeader->Magic);
	PRINT_INFO("	00014h	MajorLinkerVersion	->	%d	链接器的主版本号\r\n", pOptionalHeader->MajorLinkerVersion);
	PRINT_INFO("	00014h	MinorLinkerVersion	->	%d	链接器的次版本号\r\n", pOptionalHeader->MinorLinkerVersion);
	PRINT_INFO("	00014h	SizeOfCode	->	0x%04X	所有代码节的总大小（通常位.text段）文件对齐后的大小\r\n", pOptionalHeader->SizeOfCode);
	PRINT_INFO("	00014h	SizeOfInitializedData	->	0x%08X	已初始化数据的节的总大小（如.data段)\r\n", pOptionalHeader->SizeOfInitializedData);
	PRINT_INFO("	00014h	SizeOfUninitializedData	->	0x%04X	未初始化数据的节的总大小（如.bss段）\r\n", pOptionalHeader->SizeOfUninitializedData);
	PRINT_INFO("	00014h	AddressOfEntryPoint	->	0x%08X	程序入口点（RVA地址），指向main或DllMain\r\n", pOptionalHeader->AddressOfEntryPoint);
	PRINT_INFO("	00014h	BaseOfCode	->	0x%08X	代码段的起始RVA\r\n", pOptionalHeader->BaseOfCode);
	PRINT_INFO("	00014h	BaseOfData	->	0x%08X	数据段的起始RVA\r\n", pOptionalHeader->BaseOfData);
	
	PRINT_INFO("	00014h	ImageBase	->	0x%08X	文件加载到内存时的首选基地址（如0x400000）\r\n", pOptionalHeader->ImageBase);
	PRINT_INFO("	00014h	SectionAlignment	->	0x%08X	内存中段的对齐粒度（通常0x1000即4KB)\r\n", pOptionalHeader->SectionAlignment);
	PRINT_INFO("	00014h	FileAlignment	->	0x%08X	文件中段的对齐粒度（通常0x200即512字节）\r\n", pOptionalHeader->FileAlignment);
	PRINT_INFO("	00014h	SizeOfImage	->	0x%08X	整个PE文件映射到内存后的总大小\r\n", pOptionalHeader->SizeOfImage);
	PRINT_INFO("	00014h	SizeOfHeaders	->	0x%08X	所有头结构（DOS+PE头+节表）的总大小（按FileAlign对齐）\r\n", pOptionalHeader->SizeOfHeaders);
	PRINT_INFO("	00014h	ImageBase	->	0x%08X	文件加载到内存时的首选基地址（如0x400000）\r\n", pOptionalHeader->ImageBase);
	PRINT_INFO("	00014h	ImageBase	->	0x%08X	文件加载到内存时的首选基地址（如0x400000）\r\n", pOptionalHeader->ImageBase);
	PRINT_INFO("	00014h	ImageBase	->	0x%08X	文件加载到内存时的首选基地址（如0x400000）\r\n", pOptionalHeader->ImageBase);

}

void CmdSection(const CHAR* param)
{
}

void CmdImport(const CHAR* param)
{
}

void CmdExport(const CHAR* param)
{
}

void CmdRelocation(const CHAR* param)
{
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

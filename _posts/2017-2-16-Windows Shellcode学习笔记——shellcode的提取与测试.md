---
layout: post
title: Windows Shellcode学习笔记——shellcode的提取与测试
---


## 0x00 前言
---

之前在[《Windows Shellcode学习笔记——通过VisualStudio生成shellcode》](https://3gstudent.github.io/3gstudent.github.io/Windows-Shellcode%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0-%E9%80%9A%E8%BF%87VisualStudio%E7%94%9F%E6%88%90shellcode/)介绍了使用C++编写（不使用内联汇编），实现动态获取API地址并调用，对其反汇编提取shellcode的方法，并开源了测试代码。

接下来在对shellcode进行提取的过程中，发现了当时开源代码的一些bug，所以本文着重解决测试代码的bug，并介绍使用C++开发shellcode需要考虑的一些问题。


存在bug的测试代码下载地址：

https://github.com/3gstudent/Shellcode-Generater/blob/master/shellcode.cpp


## 0x01 简介
---

简单的shellcode提取流程：

- 使用c++开发代码
- 更改VisualStudio编译配置
- 生成exe
- 在IDA下打开生成的exe，获得机器码


由于是动态获取API地址并调用，所以为了保证shellcode的兼容性，代码中不能出现固定地址，并且要尽量避免使用全局变量，如果代码中包含子函数，根据调用方式，还有注意各个函数之间的排列顺序（起始函数放于最前）


## 0x02 Bug修复
---

配置三个编译选项:release、禁用优化、禁用/GS

将代码编译，然后使用IDA提取机器码作为shellcode

在实际调试过程中，发现代码存在bug：


### 1、代码中应合理处理全局变量

在代码中使用全局变量

```
FARPROC(WINAPI* GetProcAddressAPI)(HMODULE, LPCSTR);
HMODULE(WINAPI* LoadLibraryWAPI)(LPCWSTR);
```

在编译后会成为一个固定地址，导致shellcode无法兼容不同环境

最简单直接的方式是在shellcode中尽量避免全局变量

### 2、函数声明方式需要修改

修改全局变量后，以下代码需要修改：

```
MESSAGEBOXA_INITIALIZE MeassageboxA_MyOwn = reinterpret_cast<MESSAGEBOXA_INITIALIZE>(GetProcAddressAPI(LoadLibraryWAPI(struser32), MeassageboxA_api));
MeassageboxA_MyOwn(NULL, NULL, NULL, 0);
```

需要全部换成typedef的函数声明方式

### 3、函数调用顺序
 

如果使用以下方式加载shellcode：

```
(*(int(*)()) sc)();	
```

起始函数的定义应该位于这段shellcode的最前面（和函数声明的顺序无关）

**注：**

shellcode如果包含子函数，应该保证各个函数放在一段连续的地址中，并且起始函数置于最前面，这样在提取机器码后，可以直接加载起始函数执行shellcode

综上，给出新的完整代码：

```
#include <windows.h>
#include <Winternl.h>
#pragma optimize( "", off ) 
void shell_code();
HANDLE GetKernel32Handle();
BOOL __ISUPPER__(__in CHAR c);
CHAR __TOLOWER__(__in CHAR c);
UINT __STRLEN__(__in LPSTR lpStr1);
UINT __STRLENW__(__in LPWSTR lpStr1);
LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2);
INT __STRCMPI__(__in LPSTR lpStr1, __in LPSTR lpStr2);
INT __STRNCMPIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2, __in DWORD dwLen);
LPVOID __MEMCPY__(__in LPVOID lpDst, __in LPVOID lpSrc, __in DWORD dwCount);

typedef FARPROC(WINAPI* GetProcAddressAPI)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryWAPI)(LPCWSTR);
typedef ULONG (WINAPI *MESSAGEBOXAPI)(HWND, LPWSTR, LPWSTR, ULONG);


void shell_code() {

	LoadLibraryWAPI	loadlibrarywapi = 0;
	GetProcAddressAPI getprocaddressapi=0;
	MESSAGEBOXAPI messageboxapi=0;

	wchar_t struser32[] = { L'u', L's', L'e', L'r', L'3',L'2', L'.', L'd', L'l', L'l', 0 };
	char MeassageboxA_api[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };

	HANDLE hKernel32 = GetKernel32Handle();
	if (hKernel32 == INVALID_HANDLE_VALUE) {
		return;
	}
	LPBYTE lpBaseAddr = (LPBYTE)hKernel32;
	PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER)lpBaseAddr;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(lpBaseAddr + lpDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddr + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD pNameArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfNames);
	LPDWORD pAddrArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfFunctions);
	LPWORD pOrdArray = (LPWORD)(lpBaseAddr + pExportDir->AddressOfNameOrdinals);
	CHAR strLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0x0 };
	CHAR strGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };

	for (UINT i = 0; i < pExportDir->NumberOfNames; i++) {
		LPSTR pFuncName = (LPSTR)(lpBaseAddr + pNameArray[i]);
		if (!__STRCMPI__(pFuncName, strGetProcAddress)) {
			getprocaddressapi=(GetProcAddressAPI)(lpBaseAddr + pAddrArray[pOrdArray[i]]);
		}
		else if (!__STRCMPI__(pFuncName, strLoadLibraryA)) {
			loadlibrarywapi=(LoadLibraryWAPI) (lpBaseAddr + pAddrArray[pOrdArray[i]]);
		}
		if (getprocaddressapi != nullptr && loadlibrarywapi != nullptr) {				
			messageboxapi=(MESSAGEBOXAPI)getprocaddressapi(loadlibrarywapi(struser32), MeassageboxA_api);
			messageboxapi(NULL, NULL, NULL, 0);
			return;
		}
	}
}

inline BOOL __ISUPPER__(__in CHAR c) {
	return ('A' <= c) && (c <= 'Z');
};
inline CHAR __TOLOWER__(__in CHAR c) {
	return __ISUPPER__(c) ? c - 'A' + 'a' : c;
};

UINT __STRLEN__(__in LPSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != 0x0)
		i++;
	return i;
}

UINT __STRLENW__(__in LPWSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != L'\0')
		i++;
	return i;
}

LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2)
{
	CHAR c = __TOLOWER__(((PCHAR)(lpStr2++))[0]);
	if (!c)
		return lpStr1;
	UINT dwLen = __STRLENW__(lpStr2);
	do
	{
		CHAR sc;
		do
		{
			sc = __TOLOWER__(((PCHAR)(lpStr1)++)[0]);
			if (!sc)
				return NULL;
		} while (sc != c);
	} while (__STRNCMPIW__(lpStr1, lpStr2, dwLen) != 0);
	return (lpStr1 - 1); // FIXME -2 ?
}

INT __STRCMPI__(
	__in LPSTR lpStr1,
	__in LPSTR lpStr2)
{
	int  v;
	CHAR c1, c2;
	do
	{
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		// The casts are necessary when pStr1 is shorter & char is signed 
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != '\0') && (c2 != '\0'));
	return v;
}

INT __STRNCMPIW__(
	__in LPWSTR lpStr1,
	__in LPWSTR lpStr2,
	__in DWORD dwLen)
{
	int  v;
	CHAR c1, c2;
	do {
		dwLen--;
		c1 = ((PCHAR)lpStr1++)[0];
		c2 = ((PCHAR)lpStr2++)[0];
		/* The casts are necessary when pStr1 is shorter & char is signed */
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != 0x0) && (c2 != 0x0) && dwLen > 0);
	return v;
}

LPSTR __STRCAT__(
	__in LPSTR	strDest,
	__in LPSTR strSource)
{
	LPSTR d = strDest;
	LPSTR s = strSource;
	while (*d) d++;
	do { *d++ = *s++; } while (*s);
	*d = 0x0;
	return strDest;
}

LPVOID __MEMCPY__(
	__in LPVOID lpDst,
	__in LPVOID lpSrc,
	__in DWORD dwCount)
{
	LPBYTE s = (LPBYTE)lpSrc;
	LPBYTE d = (LPBYTE)lpDst;
	while (dwCount--)
		*d++ = *s++;
	return lpDst;
}

HANDLE GetKernel32Handle() {
	HANDLE hKernel32 = INVALID_HANDLE_VALUE;
#ifdef _WIN64
	PPEB lpPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB lpPeb = (PPEB)__readfsdword(0x30);
#endif
	PLIST_ENTRY pListHead = &lpPeb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pListEntry = pListHead->Flink;
	WCHAR strDllName[MAX_PATH];
	WCHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', L'\0' };

	while (pListEntry != pListHead) {
		PLDR_DATA_TABLE_ENTRY pModEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (pModEntry->FullDllName.Length) {
			DWORD dwLen = pModEntry->FullDllName.Length;
			__MEMCPY__(strDllName, pModEntry->FullDllName.Buffer, dwLen);
			strDllName[dwLen / sizeof(WCHAR)] = L'\0';
			if (__STRSTRIW__(strDllName, strKernel32)) {
				hKernel32 = pModEntry->DllBase;
				break;
			}
		}
		pListEntry = pListEntry->Flink;
	}
	return hKernel32;
}

int main()
{
	printf("1");
	shell_code();
	printf("2");
	return 0;
}
```

## 0x03 Shellcode提取
---

将以上代码编译成exe后使用IDA打开，查看Function Window，找到各子函数起始地址


如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-16/2-1.png)



可以看到各个函数保存在一段连续的地址，并且shellcode起始函数位于最开始


双击第一个函数shell_code(void)，进入IDA文本视图，可查看shell_code(void)函数具体在exe文件中的位置为`00000400`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-16/2-2.png)

查看main函数在exe文件中的位置为`00000A00`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-16/2-3.png)


结合c代码的结构，推断出在exe文件中的偏移范围`00000400-00000A00`即为我们需要的机器码

使用十六进制编辑器将其中的机器码提取并保存到文件中，文件中的内容即我们需要的shellcode


当然，以上手动提取机器码并保存到文件的功能可通过程序自动实现，完整代码如下：



```
#include <stdafx.h>
#include <windows.h>
#include <Winternl.h>
#pragma optimize( "", off ) 
void shell_code();
HANDLE GetKernel32Handle();
BOOL __ISUPPER__(__in CHAR c);
CHAR __TOLOWER__(__in CHAR c);
UINT __STRLEN__(__in LPSTR lpStr1);
UINT __STRLENW__(__in LPWSTR lpStr1);
LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2);
INT __STRCMPI__(__in LPSTR lpStr1, __in LPSTR lpStr2);
INT __STRNCMPIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2, __in DWORD dwLen);
LPVOID __MEMCPY__(__in LPVOID lpDst, __in LPVOID lpSrc, __in DWORD dwCount);

typedef FARPROC(WINAPI* GetProcAddressAPI)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryWAPI)(LPCWSTR);
typedef ULONG (WINAPI *MESSAGEBOXAPI)(HWND, LPWSTR, LPWSTR, ULONG);


void shell_code() {

	LoadLibraryWAPI	loadlibrarywapi = 0;
	GetProcAddressAPI getprocaddressapi=0;
	MESSAGEBOXAPI messageboxapi=0;

	wchar_t struser32[] = { L'u', L's', L'e', L'r', L'3',L'2', L'.', L'd', L'l', L'l', 0 };
	char MeassageboxA_api[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };

	HANDLE hKernel32 = GetKernel32Handle();
	if (hKernel32 == INVALID_HANDLE_VALUE) {
		return;
	}
	LPBYTE lpBaseAddr = (LPBYTE)hKernel32;
	PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER)lpBaseAddr;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(lpBaseAddr + lpDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddr + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD pNameArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfNames);
	LPDWORD pAddrArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfFunctions);
	LPWORD pOrdArray = (LPWORD)(lpBaseAddr + pExportDir->AddressOfNameOrdinals);
	CHAR strLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0x0 };
	CHAR strGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };

	for (UINT i = 0; i < pExportDir->NumberOfNames; i++) {
		LPSTR pFuncName = (LPSTR)(lpBaseAddr + pNameArray[i]);
		if (!__STRCMPI__(pFuncName, strGetProcAddress)) {
			getprocaddressapi=(GetProcAddressAPI)(lpBaseAddr + pAddrArray[pOrdArray[i]]);
		}
		else if (!__STRCMPI__(pFuncName, strLoadLibraryA)) {
			loadlibrarywapi=(LoadLibraryWAPI) (lpBaseAddr + pAddrArray[pOrdArray[i]]);
		}
		if (getprocaddressapi != nullptr && loadlibrarywapi != nullptr) {				
			messageboxapi=(MESSAGEBOXAPI)getprocaddressapi(loadlibrarywapi(struser32), MeassageboxA_api);
			messageboxapi(NULL, NULL, NULL, 0);
			return;
		}
	}
}

inline BOOL __ISUPPER__(__in CHAR c) {
	return ('A' <= c) && (c <= 'Z');
};
inline CHAR __TOLOWER__(__in CHAR c) {
	return __ISUPPER__(c) ? c - 'A' + 'a' : c;
};

UINT __STRLEN__(__in LPSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != 0x0)
		i++;
	return i;
}

UINT __STRLENW__(__in LPWSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != L'\0')
		i++;
	return i;
}

LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2)
{
	CHAR c = __TOLOWER__(((PCHAR)(lpStr2++))[0]);
	if (!c)
		return lpStr1;
	UINT dwLen = __STRLENW__(lpStr2);
	do
	{
		CHAR sc;
		do
		{
			sc = __TOLOWER__(((PCHAR)(lpStr1)++)[0]);
			if (!sc)
				return NULL;
		} while (sc != c);
	} while (__STRNCMPIW__(lpStr1, lpStr2, dwLen) != 0);
	return (lpStr1 - 1); // FIXME -2 ?
}

INT __STRCMPI__(
	__in LPSTR lpStr1,
	__in LPSTR lpStr2)
{
	int  v;
	CHAR c1, c2;
	do
	{
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		// The casts are necessary when pStr1 is shorter & char is signed 
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != '\0') && (c2 != '\0'));
	return v;
}

INT __STRNCMPIW__(
	__in LPWSTR lpStr1,
	__in LPWSTR lpStr2,
	__in DWORD dwLen)
{
	int  v;
	CHAR c1, c2;
	do {
		dwLen--;
		c1 = ((PCHAR)lpStr1++)[0];
		c2 = ((PCHAR)lpStr2++)[0];
		/* The casts are necessary when pStr1 is shorter & char is signed */
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != 0x0) && (c2 != 0x0) && dwLen > 0);
	return v;
}

LPSTR __STRCAT__(
	__in LPSTR	strDest,
	__in LPSTR strSource)
{
	LPSTR d = strDest;
	LPSTR s = strSource;
	while (*d) d++;
	do { *d++ = *s++; } while (*s);
	*d = 0x0;
	return strDest;
}

LPVOID __MEMCPY__(
	__in LPVOID lpDst,
	__in LPVOID lpSrc,
	__in DWORD dwCount)
{
	LPBYTE s = (LPBYTE)lpSrc;
	LPBYTE d = (LPBYTE)lpDst;
	while (dwCount--)
		*d++ = *s++;
	return lpDst;
}

HANDLE GetKernel32Handle() {
	HANDLE hKernel32 = INVALID_HANDLE_VALUE;
#ifdef _WIN64
	PPEB lpPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB lpPeb = (PPEB)__readfsdword(0x30);
#endif
	PLIST_ENTRY pListHead = &lpPeb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pListEntry = pListHead->Flink;
	WCHAR strDllName[MAX_PATH];
	WCHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', L'\0' };

	while (pListEntry != pListHead) {
		PLDR_DATA_TABLE_ENTRY pModEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (pModEntry->FullDllName.Length) {
			DWORD dwLen = pModEntry->FullDllName.Length;
			__MEMCPY__(strDllName, pModEntry->FullDllName.Buffer, dwLen);
			strDllName[dwLen / sizeof(WCHAR)] = L'\0';
			if (__STRSTRIW__(strDllName, strKernel32)) {
				hKernel32 = pModEntry->DllBase;
				break;
			}
		}
		pListEntry = pListEntry->Flink;
	}
	return hKernel32;
}
void __declspec(naked) END_SHELLCODE(void) {}
int main()
{
	shell_code();

	FILE *output_file;
	fopen_s(&output_file,"shellcode.bin", "wb");
	fwrite(shell_code, (int)END_SHELLCODE - (int)shell_code, 1, output_file);
	fclose(output_file);
	return 0;
}
```

**注：**

打开文件需要以"wb"模式打开二进制文件 
如果以"w"模式，写入文件的过程中，0A字符会被替换为0D0A,导致shellcode出现问题



## 0x04 Shellcode测试
---


使用以下代码可读取文件中保存的shellcode，加载并测试其功能：

```
#include <windows.h>
size_t GetSize(char * szFilePath)
{
	size_t size;
	FILE* f = fopen(szFilePath, "rb");
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	rewind(f);
	fclose(f);
	return size;
}
unsigned char* ReadBinaryFile(char *szFilePath, size_t *size)
{
	unsigned char *p = NULL;
	FILE* f = NULL;
	size_t res = 0;
	*size = GetSize(szFilePath);
	if (*size == 0) return NULL;		
	f = fopen(szFilePath, "rb");
	if (f == NULL)
	{
		printf("Binary file does not exists!\n");
		return 0;
	}
	p = new unsigned char[*size];
	rewind(f);
	res = fread(p, sizeof(unsigned char), *size, f);
	fclose(f);
	if (res == 0)
	{
		delete[] p;
		return NULL;
	}
	return p;
}
int main(int argc, char* argv[])
{
	char *szFilePath="c:\\test\\shellcode.bin";
	unsigned char *BinData = NULL;
	size_t size = 0;	
	BinData = ReadBinaryFile(szFilePath, &size);
	void *sc = VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (sc == NULL)	
		return 0;	
	memcpy(sc, BinData, size);
	(*(int(*)()) sc)();	
	return 0;
}
```


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


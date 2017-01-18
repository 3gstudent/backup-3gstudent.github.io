---
layout: post
title: Windows Shellcode学习笔记——通过VisualStudio生成shellcode
---

## 0x00 前言
---

shellcode是一段机器码，常用作漏洞利用中的载荷(也就是payload)

在渗透测试中，最简单高效的方式是通过metasploit生成shellcode，然而在某些环境下，需要定制开发自己的shellcode，所以需要对shellcode的开发作进一步研究


## 0x01 简介
---

编写Shellcode的基本方式有3种：

- 直接编写十六进制操作码
- 采用C或者Delphi这种高级语言编写程序，编译后，对其反汇编进而获得十六进制操作码
- 编写汇编程序，将该程序汇编，然后从二进制中提取十六进制操作码


本文将介绍如何通过Visual Studio编写c代码来生成shellcode，具体包含以下三部分内容：

- 利用vc6.0的DEBUG模式获取shellcode
- 测试Shellcode自动生成工具——ShellcodeCompiler
- 使用C++编写(不使用内联汇编)，实现动态获取API地址并调用，对其反汇编可提取出shellcode


## 0x02 利用vc6.0的DEBUG模式获取shellcode
---

**注：**

本节参考爱无言的《挖0day》附录部分


**测试系统：**

Windows XP

### 1、编写弹框测试程序并提取汇编代码

代码如下：

```
#include "stdafx.h"
#include <windows.h>
int main(int argc, char* argv[])
{
	MessageBoxA(NULL,NULL,NULL,0);
	return 0;
}
```


在`MessageBoxA(NULL,NULL,NULL,0);`处，按F9下断点

debug模式按F5开始调试，跳到断点


按`Alt+8`将当前C代码转为汇编代码,如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-1-18/2-2.png)


```
00401028   mov         esi,esp
0040102A   push        0
0040102C   push        0
0040102E   push        0
00401030   push        0
00401032   call        dword ptr [__imp__MessageBoxA@16 (0042528c)]
```

call是一条间接内存调用指令，实际使用需要真正的内存地址


按`Alt+6`打开查看内存数据的Memory窗口，跳到位置`0x0042528c`，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-1-18/2-3.png)

```
0042528C  EA 07 D5 77 00 00 00  ..誻...
```

取前4字节，倒序排列(内存中数据倒着保存):
`77D507EA`

call命令的实际地址为`0x77D507EA`

MessageBoxA函数位于user32.dll中，调用时需要提前加载user32.dll

### 2、编写内联汇编程序并提取机器码

新建工程，使用内联汇编加载上述代码：


```
#include "stdafx.h"
#include <windows.h>
int main(int argc, char* argv[])
{
	LoadLibrary("user32.dll");
	_asm
	{	
		push        0
		push        0
		push        0
		push        0
		mov eax,0x77D507EA
		call eax
	}
	return 0;
}
```


编译执行，成功弹框

在push 0处按F9下断点，F5进入调试模式跳至断点处


按`Alt+8`将当前VC代码转为汇编代码，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-1-18/2-4.png)


```
12:           push        0
0040103C   push        0
13:           push        0
0040103E   push        0
14:           push        0
00401040   push        0
15:           push        0
00401042   push        0
16:           mov eax,0x77D507EA
00401044   mov         eax,77D507EAh
17:           call eax
00401049   call        eax
```


接着提取上述代码在内存中的数据，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-1-18/2-5.png)

范围是0040103C - 0040104A

**注：**

call  eax的地址为00401049，表示起始地址，完整代码的长度需要+1 

按`Alt+6`打开查看内存数据的Memory窗口

跳到0x0040103C，内容如下：

`0040103C  6A 00 6A 00 6A 00 6A 00 B8 EA 07 D5 77 FF D0  j.j.j.j.戈.誻..`

截取0040103C - 0040104A的内容如下：

`6A 00 6A 00 6A 00 6A 00 B8 EA 07 D5 77 FF D0`

这段机器码就是接来下要使用的shellcode

### 3、编写加载shellcode的测试程序

```
#include "stdafx.h"
#include <windows.h>
int main(int argc, char* argv[])
{
	LoadLibrary("user32.dll");
	char shellcode[]="\x6A\x00\x6A\x00\x6A\x00\x6A\x00\xB8\xEA\x07\xD5\x77\xFF\xD0";
	((void(*)(void))&shellcode)();

	return 0;
}
```

成功执行shellcode

**注：**

由于Win7系统引入了ASLR机制，因此我们不能在shellcode中使用固定的内存地址，上述方法在Win7下不通用


## 0x03 Shellcode自动生成工具——ShellcodeCompiler
---

**下载地址：**

https://github.com/NytroRST/ShellcodeCompiler

**特点：**

- c++开发
- 开源工具
- 借助NASM
- 可实现封装api，转换为bin格式的shellcode和asm汇编代码


实际测试：

Source.txt内容如下：

```
function MessageBoxA("user32.dll");
function ExitProcess("kernel32.dll");
MessageBoxA(0,"This is a MessageBox example","Shellcode Compiler",0);
ExitProcess(0);
```


cmd下运行：

`ShellcodeCompiler.exe -r Source.txt -o Shellcode.bin -a Assembly.asm`

**注：**

ShellcodeCompiler.exe和文件夹NASM放于同级目录

执行后shellcode保存在Shellcode.bin文件中


为便于测试生成的shellcode，可在生成过程中加入`-t`参数执行一次shellcode

我参考ShellcodeCompiler的代码将其执行shellcode的功能提取出来，实现了读取文件并加载文件中的shellcode，完整代码如下：

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
	// Get size and allocate space
	*size = GetSize(szFilePath);
	if (*size == 0) return NULL;		
	f = fopen(szFilePath, "rb");
	if (f == NULL)
	{
		printf("Binary file does not exists!\n");
		return 0;
	}
	p = new unsigned char[*size];
	// Read file
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
	char *szFilePath=argv[1];  
	unsigned char *BinData = NULL;
	size_t size = 0;	
	BinData = ReadBinaryFile(szFilePath, &size);
	void *sc = VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (sc == NULL)
	{		
		return 0;
	}
	memcpy(sc, BinData, size);
	(*(int(*)()) sc)();
	return 0;
}
```


## 0x04 C++编写(不使用内联汇编)，实现动态获取API地址并调用，对其反汇编可提取出shellcode
---

对于ShellcodeCompiler，最大的不足是使用了内联汇编，vc在64位下默认不支持内联汇编，所以该方法无法生成64位shellcode

**注：**

delphi支持64位的内联汇编

vc在64位下虽然不能直接使用内联汇编，但是可以将程序段全部放到一个asm文件下进行编译

X64上恢复VS关键字__asm的方法可参照：

http://bbs.pediy.com/showthread.php?p=1260419


那么，想要开发一个64位的shellcode，最直接的方式就是不使用内联汇编，纯c++编写，实现动态获取API地址并调用，最后对其反汇编进而得到shellcode

**好处如下：**

便于调试，源代码的可读性大大增强

但是，我在网上并没有找到现成的代码，于是根据原理尝试自己实现

**注：**

1、编写shellcode需要实现以下步骤：

- 获取kernel32.dll基地址
- 定位GetProcAddress函数地址
- 使用GetProcAddress确定LoadLibrary函数地址
- 使用LoadLibrary加载DLL文件
- 使用GetProcAddress查找某个函数的地址（例如MessageBox）
- 指定函数参数
- 调用函数

2、另一个参考资料：

http://bbs.pediy.com/showthread.php?t=203140

参考资料通过c++实现了加载一个第三方dll

以此为参考进行修改，实现我们想要的功能：

`实现动态获取API地址并调用`

完整代码已上传至github：

https://github.com/3gstudent/Shellcode-Generater

**特点：**

- 支持x86和x64
- 纯c++实现，动态获取GetProcAddress和LoadLibrary函数的地址


编译前对VisualStudio做如下配置：

> 1、使用Release模式。近来编译器的Debug模式可能产生逆序的函数，并且会插入许多与位置相关的调用。
> 
> 2、禁用优化。编译器会默认优化那些没有使用的函数，而那可能正是我们所需要的。
> 
> 3、禁用栈缓冲区安全检查（/Gs)。在函数头尾所调用的栈检查函数，存在于二进制文件的某个特定位置，导致输出的函数不能重定位，这对shellcode是无意义的


接着在IDA下打开生成的exe获得机器码即可


## 0x05 补充
---

接下来研究的内容：

- 在X64上恢复VS关键字__asm后，如何获取64位shellcode



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

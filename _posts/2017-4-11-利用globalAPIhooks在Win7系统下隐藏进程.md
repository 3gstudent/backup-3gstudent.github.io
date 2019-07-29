---
layout: post
title: 利用globalAPIhooks在Win7系统下隐藏进程
---


## 0x00 前言
---

在之前的文章[《Powershell tricks::Hide Process by kd.exe》](https://3gstudent.github.io/3gstudent.github.io/Powershell-tricks-Hide-Process-by-kd.exe/)介绍过通过kd.exe隐藏进程的技巧，最大的缺点是需要开启Local kernel debugging模式，等待重启才能生效
这次介绍另外一个隐藏进程的方法——利用global API hooks
优点是即时生效，不需要等待系统重启


## 0x01 简介
---

本文将要参照Sergey Podobry的文章，对该方法进行介绍，分析实际测试中需要注意的细节，并补全在64位下具体的参数设置

**参考链接：**

https://www.codeproject.com/articles/49319/easy-way-to-set-up-global-api-hooks?display=print

https://github.com/subTee/AppInitGlobalHooks-Mimikatz

## 0x02 原理
---

在用户层，通过global API hooks将测试dll注入到系统的所有进程，实现对指定进程的隐藏

### hook方式

修改注册表键值AppInit_DLLs

**位置：**

`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`

**参数说明：**

**LoadAppInit_DLLs:**

(REG_DWORD)	Value that globally enables or disables AppInit_DLLs.	
- 0x0 – AppInit_DLLs are disabled.
- 0x1 – AppInit_DLLs are enabled.

**AppInit_DLLs:**

(REG_SZ)
Space - or comma -separated list of DLLs to load. The complete path to the DLL should be specified using short file names.	C:\PROGRA~1\Test\Test.dll

**RequireSignedAppInit_DLLs:**

(REG_DWORD)	Require code-signed DLLs.	

- 0x0 – Load any DLLs.
- 0x1 – Load only code-signed DLLs.

### 代码实现

通过Mhook library实现API hooking

**优点：**

- 开源
- 支持x86和x64
- 使用简便

**参考地址：**

http://codefromthe70s.org/mhook22.aspx

## 0x03 实际测试
---

**测试环境：**

Win7x86

### 1.设置注册表键值AppInit_DLLs

**参照代码：**

https://github.com/subTee/AppInitGlobalHooks-Mimikatz/blob/master/AppInit.reg


.reg文件如下：

```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows]
"AppInit_DLLs"="C:\\Tools\\AppInitHookx64.dll,C:\\Tools\\AppInitHook.dll"
"LoadAppInit_DLLs"=dword:00000001
"RequireSignedAppInit_DLLs"=dword:00000000
```

表示

- AppInit_DLLs are enabled
- Load any DLLs，do not need code-signed DLLs
- DLL path：C:\\Tools\\AppInitHookx64.dll,C:\\Tools\\AppInitHook.dll

**注：**

设置的路径不能存在空格，否则失效



### 2.编译生成AppInitHook.dll并放在C:\Tools下

参照工程：

https://github.com/subTee/AppInitGlobalHooks-Mimikatz


### 3.运行mimikatz.exe

任务管理器进程列表不存在mimikatz.exe

Process Explorer不存在mimikatz.exe

Tasklist.exe不存在mimikatz.exe

**注：**

此处没有完全隐藏进程，是将进程名设置为conhost.exe，这是因为mimikatz是控制台应用程序

如果换成putty.exe或calc.exe这种Win32项目，则不存在这个问题，能够完全隐藏进程

使用Process Explorer查看新建的进程，均加载了AppInitHook.dll，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-11/2-1.png)

**注：**

管理员权限运行Process Explorer，可查看高权限进程加载的dll


### 4.Win7x64测试

64位系统同32位系统的区别在注册表也有所体现

**注：**

详情可参考之前的文章《关于32位程序在64位系统下运行中需要注意的重定向问题》

64位程序对应注册表位置：

`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\`

32位程序对应注册表位置：

`HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\`

所以，如果要hook 64位系统下的所有进程(32位和64位)，需要修改两处注册表键值

64位的注册表键值位置：

`[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Windows]`

32位的注册表键值位置：

`[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows]`

具体修改代码已上传至github，地址如下：

https://github.com/3gstudent/AppInitGlobalHooks-Mimikatz/blob/master/AppInit64.reg

修改后使用Process Explorer查看如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-11/2-2.png)

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-11/2-3.png)

成功注入32位和64位进程

## 0x04 补充
---

该方法只支持Win7 和 Windows Server 2008 R2，不支持更高版本如Win8、Server2012

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-11/2-4.png)

如上图，在Win8系统，虽然成功加载AppInitHook.dll，但是无法隐藏进程

**原因如下：**

从Win8系统开始，微软对AppInit_DLLs做了限制：bios中默认开启的secure boot将会禁用AppInit_DLLs，使其失效

详情可参照：

https://msdn.microsoft.com/en-us/library/windows/desktop/dn280412(v=vs.85).aspx


## 0x05 防御
---

只针对Win7 和 Windows Server 2008 R2及以下系统

**1.查看注册表键值**

`[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Windows]`

`[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows]`

AppInit_DLLs项有无可疑dll路径

**2.通过Process Explorer查看进程有无加载可疑的dll**


## 0x06 小结
---

本文对利用global API hooks在Win7系统下隐藏进程的方法做了介绍，结合利用思路，帮助大家对这种利用方式进行更好的防御

当然，利用global API hooks能做的还有更多


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

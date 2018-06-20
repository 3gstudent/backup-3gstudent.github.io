---
layout: post
title: 通过COM组件IFileOperation越权复制文件
---


## 0x00 前言
---

在之前的文章[《Empire中的Invoke-WScriptBypassUAC利用分析》](https://3gstudent.github.io/3gstudent.github.io/Empire%E4%B8%AD%E7%9A%84Invoke-WScriptBypassUAC%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)曾介绍过一个越权复制文件的方法，在普通用户的权限下，利用wusa能够将cab文件释放至管理员权限的文件夹，进一步可以实现文件名劫持和UAC绕过。

但该功能在Win10下被取消，那么有没有更为通用的方法呢？

本文将要介绍一个适用于Win7-Win10的方法——利用COM组件IFileOperation

## 0x01 简介
---

- 利用原理
- 三种实现思路
- 实例代码
- 实际测试
- 利用分析

## 0x02 利用原理
---

**注：**

该方法学习自Defcon 25中的workshop，Ruben Boonen 《UAC 0day, all day!》

ppt下载地址：

https://github.com/FuzzySecurity/DefCon25/blob/master/DefCon25_UAC-0day-All-Day_v1.2.pdf


利用COM组件IFileOperation越权复制文件的前提：

- Win7以后的系统
- 可信路径下的可信文件(例如explorer.exe，powershell.exe)

所以有以下三种实现思路：

### 1、dll劫持或是dll注入

由于可信路径下的可信文件一般都是在需要管理员权限的路径下，所以普通用户权限下基本无法实现dll劫持

可行的方法是dll注入

例如explorer.exe，在普通用户权限就可以对其进行dll注入

### 2、修改PEB结构，欺骗PSAPI，调用COM组件IFileOperation

COM组件通过Process Status API (PSAPI)读取进程PEB结构中的Commandline来识别它们正在运行的进程

如果将进程的Path改成可信文件(如explorer.exe)，就能够欺骗PSAPI，调用COM组件IFileOperation实现越权复制

### 3、通过可信文件直接调用COM组件IFileOperation

例如powershell.exe为可信文件，并且能够直接调用COM组件IFileOperation

## 0x03 实现方法1：dll注入explorer.exe
---

具体实现分为如下两段：

1. 将dll注入到进程explorer.exe
2. dll实现调用COM组件IFileOperation复制文件

github已经有一个完整的实现代码，因此可以参考该工程对其分析，工程地址：

https://github.com/hjc4869/UacBypass

(1)工程UacBypassTest实现了dll注入到进程explorer.exe

去掉不必要的功能，只保留将UacBypass.dll注入到进程explorer.exe的功能：

删除Line 58即可

(2)工程UacBypass实现了调用COM组件IFileOperation复制文件

该工程编译后生成文件UacBypass.dll，实现了将同级目录下的ntwdblib.dll复制到`C:\windows\System32`下

#### 实际测试：

运行UacBypassTest.exe，将UacBypass.dll注入到进程explorer.exe，成功实现越权文件复制


## 0x04 实现方法2：修改PEB结构，欺骗PSAPI，调用COM组件IFileOperation
---

参考工程UacBypass，将dll转为exe，添加头文件，修复bug，可供参考的完整代码：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/IFileOperation.cpp

实现了将`c:\6\ntwdblib.dll`复制到`c:\windows\system32`下

**代码分析：**

成功的前提是指定了该COM组件的属性(需要提升权限)

官方文档地址：

https://msdn.microsoft.com/en-us/library/bb775799.aspx

代码位置：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/IFileOperation.cpp#L14

属性说明：

- FOF_NOCONFIRMATION :不弹出确认框
- FOF_SILENT:不弹框
- FOFX_SHOWELEVATIONPROMPT:需要提升权限
- FOFX_NOCOPYHOOKS:不使用copy hooks
- FOFX_REQUIREELEVATION:默认需要提升权限
- FOF_NOERRORUI:报错不弹框

#### 实际测试：

直接运行exe，会弹出UAC的确认框，提示权限不够，如果选择允许，能够实现文件复制


接下来需要添加修改PEB结构的功能，为了欺骗PSAPI，共需要修改以下位置：

- _RTL_USER_PROCESS_PARAMETERS中的ImagePathName
- _LDR_DATA_TABLE_ENTRY中的FullDllName
- _LDR_DATA_TABLE_ENTRY中的BaseDllName

**注：**

不需要修改_RTL_USER_PROCESS_PARAMETERS中的`CommandLine`，该属性能够通过Process Explorer查看，为了更具有欺骗性，可以选择将其修改

我在这里参考了UACME中`supMasqueradeProcess()`的实现代码，地址如下：

https://github.com/hfiref0x/UACME/blob/143ead4db6b57a84478c9883023fbe5d64ac277b/Source/Akagi/sup.c#L947

我做了以下修改：

- 不使用ntdll.lib文件(安装DDK后包含)，改为通过ntdll获得NTAPI
- 提取关键代码
- 修复bug
- 添加调用COM组件IFileOperation复制文件的功能
- ...

更多细节可参考开源的代码，地址如下：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/MasqueradePEB.cpp

代码实现了修改当前进程的PEB结构，欺骗PSAPI，将其识别为explorer.exe，接着调用COM组件IFileOperation实现文件复制

#### 实际测试：

当前进程被修改为explorer.exe，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-15/2-1.png)

文件复制成功，并且没有弹出UAC的确认框，实现了越权复制文件

## 0x05 实现方法3：通过powershell.exe调用COM组件IFileOperation
---

先通过c#编译一个COM组件实现调用COM组件IFileOperation复制文件，接着通过powershell来调用这个COM组件

### 1、编写COM组件

代码参考地址：

https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC/FileOperations/FileOperations

编译成功后生成FileOperation.dll

**注：**

Ruben Boonen(b33f@FuzzySecurity)参考的源工程：

https://github.com/mlaily/MSDNMagazine2007-.NET-Matters-IFileOperation-in-Windows-Vista

他在此基础上做了修改(修改类名等)，使得powershell能够直接调用COM组件，这个功能很棒

### 2、通过powershell来调用这个COM组件

有以下两种方式：

(1) [System.Reflection.Assembly]::LoadFile($Path)

直接加载文件

(2) [Reflection.Assembly]::Load($bytes)

将文件压缩为字符串保存在数组中，可参考Matthew Graeber的方法，地址如下：

http://www.exploit-monday.com/2012/12/in-memory-dll-loading.html

能够直接输出可供使用的powershell代码

**注：**

两种方式的比较在之前的文章[《利用Assembly Load & LoadFile绕过Applocker的分析总结》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8Assembly-Load-&-LoadFile%E7%BB%95%E8%BF%87Applocker%E7%9A%84%E5%88%86%E6%9E%90%E6%80%BB%E7%BB%93/)有过介绍

方法3完整的实现代码可参考：

https://github.com/FuzzySecurity/PowerShell-Suite/blob/ebbb8991a8a051b48c05ce676524a1ba787dbf0c/Bypass-UAC/Bypass-UAC.ps1#L1082

#### 实际测试：

执行powershell脚本，加载COM组件IFileOperation，由于powershell.exe为可信进程，所以不会弹出UAC的确认框，成功实现越权复制文件

## 0x06 利用分析
---

COM组件IFileOperation适用于Win7-Win10，所以越权复制的方法也是可用的

对于explorer.exe，加载高权限的COM组件不会弹出UAC的对话框。

本文已经实现了模拟explorer.exe的方法，那么是否有其他可用的COM组件呢？又能完成哪些“提权操作呢”?

## 0x07 小结
---

本文介绍了通过COM组件IFileOperation越权复制文件的三种方法，整理并开发了实现代码，可用于直接测试

最后感谢Ruben Boonen(b33f@FuzzySecurity)在研究上对我的帮助


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




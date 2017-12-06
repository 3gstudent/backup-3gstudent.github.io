---
layout: post
title: CIA Vault7 RDB中的Windows后门利用方法分析
---

## 0x00 前言
---

在上篇文章[《CIA Hive测试指南——源代码获取与简要分析》](https://3gstudent.github.io/3gstudent.github.io/CIA-Hive%E6%B5%8B%E8%AF%95%E6%8C%87%E5%8D%97-%E6%BA%90%E4%BB%A3%E7%A0%81%E8%8E%B7%E5%8F%96%E4%B8%8E%E7%AE%80%E8%A6%81%E5%88%86%E6%9E%90/)对维基解密公布的代号为`Vault 8`的文档进行了研究，简要分析服务器远程控制工具`Hive`

本文将要继续对维基解密公布的CIA相关资料进行分析，介绍`Vault 7`中`Remote Development Branch (RDB)`中提到的Windows后门利用方法

资料地址：

https://wikileaks.org/ciav7p1/cms/page_2621760.html

## 0x01 简介
---

本文将要分析以下后门利用方法：

- VBR Persistence
- Image File Execution Options
- OCI.DLL Service Persistence
- Shell Extension Persistence
- Windows FAX DLL Injection

## 0x02 VBR Persistence
---

用于在Windows系统的启动过程中执行后门，能够hook内核代码

VBR全称`Volume Boot Record` (also known as the Partition Boot Record) 

对应工具为`Stolen Goods 2.0`(未公开)

Stolen Goods的说明文档地址：

https://wikileaks.org/vault7/document/StolenGoods-2_0-UserGuide/

**特点：**

- 能够在Windows启动过程中加载驱动(驱动无需签名)
- 适用WinXP(x86)、Win7(x86/x64)

该方法取自https://github.com/hzeroo/Carberp

**注：**

https://github.com/hzeroo/Carberp内包含的源码值得深入研究

## 0x03 Image File Execution Options
---

通过配置注册表实现执行程序的重定向

修改方式(劫持notepad.exe)：

注册表路径：

`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`

新建项`notepad.exe`

新建字符串值,名称：`notepad.exe`，路径`"C:\windows\system32\calc.exe"`

对应cmd命令为：

```
reg add "hklm\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\calc.exe" /f
```

启动notepad.exe，实际执行的程序为`"C:\windows\system32\calc.exe"`

**注：**

通常情况下，修改该位置的注册表会被杀毒软件拦截

## 0x04 OCI.DLL Service Persistence
---

利用MSDTC服务加载dll，实现自启动

Shadow Force曾经在域环境中使用过的一个后门，通过说明文档猜测CIA也发现了该方法可以在非域环境下使用

我在之前的文章介绍过这种利用方法，地址为：

https://3gstudent.github.io/Use-msdtc-to-maintain-persistence/

我的文章使用的方法是将dll保存在`C:\Windows\System32\`下

CIA使用的方法是将dll保存在`C:\Windows\System32\wbem\`下

这两个位置都可以，MSDTC服务在启动时会依次查找以上两个位置


## 0x05 Shell Extension Persistence
---

通过COM dll劫持explorer.exe的启动过程

该思路我在之前的文章也有过介绍，地址如下：

https://3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-explorer.exe/

**注：**

该方法曾被多个知名的恶意软件使用过，例如`COMRAT`、`ZeroAccess rootkit`和`BBSRAT`


## 0x06 Windows FAX DLL Injection
---

通过DLL劫持，劫持Explorer.exe对fxsst.dll的加载

Explorer.exe在启动时会加载`c:\Windows\System32\fxsst.dll`(服务默认开启，用于传真服务)

将payload.dll保存在`c:\Windows\fxsst.dll`，能够实现dll劫持，劫持Explorer.exe对fxsst.dll的加载

较早公开的利用方法，参考链接如下：

https://room362.com/post/2011/2011-06-27-fxsstdll-persistence-the-evil-fax-machine/

## 0x07 小结
---

本文对Vault7中`Remote Development Branch (RDB)`中提到的Windows后门利用方法进行了分析，可以看到，这部分内容会借鉴已公开的利用方法

我对已公开的Windows后门利用方法做了一个系统性的搜集(也包括我自己公开的方法)，地址如下：

https://github.com/3gstudent/Pentest-and-Development-Tips/blob/master/README.md#tips-30-windows-persistence

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





---
layout: post
title: 渗透技巧——通过SAM数据库获得本地用户hash
---


## 0x00 前言
---

在渗透测试中，获得了Windows系统的访问权限后，通常会使用mimikatz的`sekurlsa::logonpasswords`命令尝试读取进程lsass的信息来获取当前登录用户的密码信息，但想要全面获取系统中的密码信息，还要对SAM数据库中保存的信息进行提取，导出当前系统中所有本地用户的hash。

## 0x01 简介
---

本文将要介绍以下内容：

- 通过SAM数据库获得用户hash的多种方法
- 原理分析

## 0x02 通过SAM数据库获得用户hash的方法
---

### 1、在线读取SAM数据库

读取当前系统的SAM数据库文件，获得系统所有本地用户的hash

#### (1) mimikatz

```
privilege::debug
token::elevate
lsadump::sam
```

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-8/2-1.png)

#### (2) pwdump7

下载地址：

http://passwords.openwall.net/b/pwdump/pwdump7.zip

管理员权限执行，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-8/2-2.png)

#### (3) powershell

下载地址：

https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-PowerDump.ps1

管理员权限执行，测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-8/2-3.png)

### 2、离线读取SAM数据库

获取当前系统的SAM数据库文件，在另一系统下进行读取

导出SAM数据库文件有以下两种实现方法：

#### (1) 保存注册表

管理员权限

```
reg save HKLM\SYSTEM SystemBkup.hiv
reg save HKLM\SAM SamBkup.hiv
```

#### (2) 复制文件

```
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SAM
```

默认无法被复制，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-8/2-4.png)

需要借助NinjaCopy，作者Joe Bialek，参考下载地址：

https://github.com/3gstudent/NinjaCopy

导出SAM数据库文件后，在另一系统，可通过以下方式导出用户hash：

#### (1) mimikatz

```
lsadump::sam /sam:SamBkup.hiv /system:SystemBkup.hiv
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-8/3-1.png)

**注：**

mimikatz的官方说明有问题，地址如下：

https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump

导出命令：

```
lsadump::sam SystemBkup.hiv SamBkup.hiv
```

会报错，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-8/3-2.png)

可用的命令由@我爱这个世界提供


### 补充：

以下工具在读取Win7系统的SAM数据库文件会报错

#### (1) Pwdump7

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-8/3-3.png)

#### (2) Pwdump5

下载地址：

http://passwords.openwall.net/b/pwdump/pwdump5.zip

读取结果不正确，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-8/3-4.png)

#### (3) cain

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-8/3-5.png)


## 0x03 原理分析
---

### 1、读取HKLM\SYSTEM，获得syskey

读取注册表项`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`下的键值`JD`、`Skew1`、`GBG`和`Data`中的内容，拼接成syskey

代码可参考：

https://github.com/johannwmeyer/quarkspwdump/blob/a68aa6330f37eb8d00055c73e6a4e3cb52bcdd6d/src/crypt.cpp#L222

https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c#L219

完整计算代码可参考：

https://raw.githubusercontent.com/3gstudent/Writeup/master/getsyskey.cpp

(Steal from http://www.zcgonvh.com/post/ntds_dit_pwd_dumper.html)


### 2、使用syskey解密HKLM\SAM

读取注册表项`HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users`下每个用户中F项和V项的内容，使用syskey进行一系列的解密

详细解密过程可参考如下链接：

http://www.xfocus.net/articles/200306/550.html


综上，想要通过SAM数据库获得用户hash，需要获得两个文件：HKLM\SYSTEM和HKLM\SAM

最直接的导出方式是读取当前系统下的注册表HKLM\SYSTEM和HKLM\SAM，但需要获得system权限

从admin切换到system权限的方法可参考之前的文章：[《渗透技巧——从Admin权限切换到System权限》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E4%BB%8EAdmin%E6%9D%83%E9%99%90%E5%88%87%E6%8D%A2%E5%88%B0System%E6%9D%83%E9%99%90/)


## 0x04 小节
---

本文介绍了通过SAM数据库获得所有用户hash的多种方法，关键在于读取HKLM\SYSTEM和HKLM\SAM


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)












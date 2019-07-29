---
layout: post
title: Process Doppelganging利用介绍
---


## 0x00 前言
---

在最近的BlackHat Europe 2017，Tal Liberman和Eugene Kogan介绍了一种新的代码注入技术——`Process Doppelgänging`

据说这种利用方式支持所有Windows系统，能够绕过绝大多数安全产品的检测

于是，本文将要根据开源代码，编写程序，实现Process Doppelgänging，测试功能，分析利用思路

参考地址：

https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf

## 0x01 简介
---

本文将要介绍以下内容：

- 原理
- 开源代码
- 修复方法
- 实际测试
- 利用思路
- 防御检测

## 0x02 Process Doppelgänging原理
---

原理上类似于Process Hollowing，但是更加高级：

- 不需要使用傀儡进程
- 不需要特殊的内存操作，例如SuspendProcess和NtUnmapViewOfSection

**注：**

关于Process Hollowing的介绍，可参考之前的文章[《傀儡进程的实现与检测》](https://3gstudent.github.io/3gstudent.github.io/%E5%82%80%E5%84%A1%E8%BF%9B%E7%A8%8B%E7%9A%84%E5%AE%9E%E7%8E%B0%E4%B8%8E%E6%A3%80%E6%B5%8B/)

### 实现思路：

#### 1.打开一个正常文件，创建transaction

关于NTFS transaction，可参考：

http://www.ntfs.com/transaction.htm

#### 2.在这个transaction内填入payload，payload作为进程被启动

目前为止，杀毒软件无法对填入的payload进行扫描

#### 3.回滚transaction

相当于还原transaction，清理痕迹


### 对应程序实现过程：

#### 1.创建transaction

关键函数：

- NtCreateTransaction

#### 2.在这个transaction内填入payload

关键函数：

- CreateFileTransacted
- NtCreateSection

#### 3.payload作为进程被启动

关键函数：

- NtCreateProcessEx
- NtCreateThreadEx

#### 4.回滚transaction

关键函数：

- NtRollbackTransaction

当然，还涉及到payload的写入，申请内存、PE文件结构等，这里暂不介绍，可直接参考POC源码

对于Native API的使用，可参考之前的文章[《渗透技巧——"隐藏"注册表的创建》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%9A%90%E8%97%8F-%E6%B3%A8%E5%86%8C%E8%A1%A8%E7%9A%84%E5%88%9B%E5%BB%BA/)和[《渗透技巧——"隐藏"注册表的更多测试》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%9A%90%E8%97%8F-%E6%B3%A8%E5%86%8C%E8%A1%A8%E7%9A%84%E6%9B%B4%E5%A4%9A%E6%B5%8B%E8%AF%95/)

**注：**

Win10 RS3前的Win10系统，使用该方法会蓝屏，原因在于NtCreateProcessEx函数传入的空指针，细节可参考：

https://bugs.chromium.org/p/project-zero/issues/detail?id=852


## 0x03 开源POC
---

目前， 已公开的POC有两个

### 1、processrefund

地址：

https://github.com/Spajed/processrefund

目前仅支持64位Windows系统

编译工具：VS2015，安装sdk

**实际测试：**

Win7 x64

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-19/2-1.png)

**注：**

如果选择system32下的calc.exe，会提示权限不够

启动进程calc.exe，但实际上执行MalExe.exe，弹出对话框

进程calc.exe的图标和描述都是正常的calc.exe，数字签名也正常，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-19/2-2.png)

### 2、hfiref0x的POC

https://gist.github.com/hfiref0x/a9911a0b70b473281c9da5daea9a177f

仅有一个c文件，缺少头文件ntos.h

可供参考的位置：

https://github.com/hfiref0x/UACME/blob/master/Source/Shared/ntos.h

但是还需要作二次修改

为了更加了解细节，决定不使用ntdll.lib文件(安装DDK后包含)，改为通过ntdll获得Native API(当然，代码量也会增加)

以自己的方式重写一个ntos.h，并对原POC的inject.c作修改

开源地址如下：

https://github.com/3gstudent/Inject-dll-by-Process-Doppelganging

编译工具：VS2012

支持32位Windows系统

**实际测试：**

Win7 x86

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-19/2-3.png)

**注：**

如果选择system32下的calc.exe，会提示权限不够

综上，我们可以看到，Process Doppelgänging在利用效果上和Process Hollowing类似：启动一个正常进程(正常的图标、签名、描述)，在这个进程中执行payload

Process Doppelgänging在利用上的一个缺点： 需要替换文件，所以在替换system32下的文件时，会提示权限不够(管理员权限无法修改该路径下的文件)

## 0x04 利用思路
---

在上节我们测试了两个POC，对Process Doppelgänging有了一些认识

而在实际利用中，需要对POC作进一步修改，利用思路如下：

将读取payload的功能去掉，改为使用Buffer存储(可进行压缩编码减小长度)

执行时读取Buffer，解密执行

这样能进一步隐藏payload，实现payload的"无文件"(payload保存在exp中，不需要写入硬盘)

## 0x05 检测
---

Process Doppelgänging并不是能绕过所有的杀毒软件，几个关键函数的调用还是会被拦截(例如NtCreateThreadEx)，并且进程的内存同PE文件存在差异

## 0x06 小结
---

本文介绍了Process Doppelgänging的原理，根据开源代码，编写程序，实现Windows x86和x64系统下的利用，测试功能，分析利用思路，介绍检测方法



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


---
layout: post
title: Windows XML Event Log (EVTX)单条日志清除（四）——通过注入获取日志文件句柄删除当前系统单条日志记录
---

## 0x00 前言
---

Windows XML Event Log (EVTX)单条日志清除系列文章的第四篇，介绍第二种删除当前系统单条日志记录的方法：获得日志服务Eventlog对应进程中指定日志文件的句柄，通过Dll注入获得该句柄的操作权限，利用该句柄实现日志文件的修改

## 0x01 简介
---

本文将要介绍以下内容：

- 利用思路
- 程序实现
- 枚举日志服务Eventlog对应进程的所有句柄，获得指定日志文件的句柄
- 通过Dll注入获得该句柄的操作权限
- 进程间消息传递的方法

## 0x02 利用思路
---

系统启动日志服务Eventlog后，会以独占模式打开日志文件，导致其他进程无法打开该日志文件，也就无法进行修改操作

那么，如果我们通过Dll注入进入进程的内存，接着获得指定日志文件的句柄，能否获得该日志文件的操作权限呢？

## 0x03 枚举日志服务Eventlog对应进程的所有句柄，获得指定日志文件的句柄
---

### 1、利用工具processhacker获得指定日志文件的句柄

下载地址：

https://processhacker.sourceforge.io/

#### (1)获得日志服务Eventlog对应进程的pid

执行如下powershell代码：

```
Get-WmiObject -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId
```

#### (2)运行processhacker

根据pid找到进程，查看`Properties`->`Handles`

能够获得当前进程的所有句柄信息

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-6-19/2-1.png)

可以看到`C:\Windows\System32\winevt\Logs\Security.evtx`对应的Handle值为`0x1c8`

### 2、通过c++程序实现获得指定日志文件的句柄

查看processhacker的源码，寻找实现方法

代码位置：

https://github.com/processhacker/processhacker/blob/e2d793289dede80f6e3bda26d6478dc58b20b7f8/ProcessHacker/hndlprv.c#L307

获得参考资料：

> * On Windows 8 and later, NtQueryInformationProcess with ProcessHandleInformation is the most efficient method.
> * On Windows XP and later, NtQuerySystemInformation with SystemExtendedHandleInformation.
> * Otherwise, NtQuerySystemInformation with SystemHandleInformation can be used.

于是，挑选第三个方法尝试实现

**注：**

经测试，第三个方法适用于Win7和更新版本的操作系统

利用NtQuerySystemInformation查询SystemHandleInformation能够获得所有进程的句柄信息

挑选出日志进程中的所有句柄

接着通过NtDuplicateObject获取句柄的名称和具体的数值信息

最后筛选出想要查找的句柄，输出Handle值

完整实现代码已开源，下载地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/GetPIDandHandle(evtx).cpp

代码实现了根据输入的关键词进行搜索，获得对应的句柄名称和Handle值

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-6-19/2-2.png)

成功获得日志服务Eventlog对应进程的pid，security.evtx对应的Handle值为`0x1c8`

## 0x04 通过Dll注入获得该句柄的操作权限
---

通过NtCreateThreadEx + LdrLoadDll实现Dll注入的代码可参考：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/NtCreateThreadEx%20%2B%20LdrLoadDll.cpp

**注:**

注入成功后需要FreeDll

注入成功后，使用获得到的Handle值作为函数CreateFileMapping()的第一个参数，创建一个文件映射内核对象

然后调用函数MapViewOfFile()将文件数据映射到进程的地址空间

接下来修改内存中的数据，删除单条日志记录

最后调用函数FlushViewOfFile()，将内存数据写入磁盘

## 0x05 进程间消息传递的方法
---

在实际使用过程中，整个实现日志记录删除功能的代码要放在Dll中，而通过CreateRemoteThread无法向Dll传入参数，这就导致无法删除指定EventlogRecordId的日志

这里可以借助进程间的消息传递

实现方法有多种，例如信号、管道、消息队列和共享内存，甚至是读写文件

由于在**0x04**部分使用了函数CreateFileMapping()创建一个文件映射内核对象，所以进程间消息传递也使用内存映射的方式

创建一个共享内存，代码可参考：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/OpenFileMapping.cpp

代码中创建了两个内存映射对象，并且指定了函数CreateFileMapping()的访问权限为允许任何人访问该对象，即函数CreateFileMapping()的第二个参数

通常情况下，该值设置为NULL，表示默认访问权限，但在注入的Dll中必须设置为允许任何人访问该对象，否则提示拒绝访问

**原因如下：**

Dll注入svchost.exe后，权限为System，默认访问权限无法访问由用户创建的内存映射文件对象，必须指定为允许任何人访问该对象

当然，如果是两个用户权限的进程进行消息传递，函数CreateFileMapping()的第二个参数为NULL即可

读取指定共享内存，代码可参考：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/OpenFileMapping.cpp

代码中读取这两个内存映射对象，添加了数据类型转换的功能(字符串转int)

## 0x06 程序实现流程
---

### 1、自己解析格式，实现日志删除

删除的关键代码如下：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordofFile.cpp`

代码实现了删除文件`c:\test\Setup.evtx`中的一条日志(EventRecordID=14)，新文件保存为`c:\test\SetupNew.evtx`

整个实现流程分成两部分：

- 启动程序
- 注入的Dll

#### 1.启动程序(Loader-rewriting.cpp)

代码地址：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/Loader-rewriting.cpp`

流程如下：

1. 获得日志服务Eventlog对应进程的pid
2. 枚举日志服务Eventlog对应进程的的所有句柄，获得指定日志文件的句柄
3. 创建两个内存映射，用于向dll传递日志文件的句柄和需要删除日志的EventRecordID
4. 向日志服务Eventlog对应的进程注入Dll
5. 释放Dll
6. 关闭内存映射

#### 2.注入的Dll(Dll-rewriting.cpp)

代码地址：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/Dll-rewriting.cpp`

流程如下：

1. 分别从两个内存映射读取消息，将读取到的内容从字符串转换成int类型，获得日志文件的句柄及需要删除日志的EventRecordID
2. 调用函数CreateFileMapping()，传入日志文件的句柄，创建一个文件映射内核对象
3. 调用函数MapViewOfFile()将文件数据映射到进程的地址空间
4. 修改内存数据，删除指定日志
5. 调用函数FlushViewOfFile()，将内存数据写入磁盘
6. 关闭日志文件的内存映射

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-6-19/3-1.png)

### 2、使用WinAPI EvtExportLog，过滤出想要删除的内容

可供参考的代码：

https://github.com/360-A-Team/EventCleaner/blob/master/EventCleaner/EventCleaner.cpp#L528

我按照这个思路写的代码：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordofFileEx.cpp`

代码实现了调用Windows API EvtExportLog对日志文件进行筛选，去除指定日志后，将剩下的日志内容保存为新文件temp.evtx

整个实现流程分成三部分：

- 日志删除程序
- 启动程序
- 注入的Dll

#### 1.日志删除程序(DeleteRecord-EvtExportLog.cpp)

代码地址：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecord-EvtExportLog.cpp`

流程如下：

1. 指定日志文件和需要删除日志的EventRecordID
2. 生成新的日志文件temp.evtx

#### 2.启动程序(Loader-EvtExportLog.cpp)

代码地址：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/Loader-EvtExportLog.cpp`

流程如下：

1. 获得日志服务Eventlog对应进程的pid
2. 枚举日志服务Eventlog对应进程的的所有句柄，获得指定日志文件的句柄
3. 创建三个内存映射，用于向dll传递日志文件的句柄、新日志文件的长度和新日志文件的内容
4. 向日志服务Eventlog对应的进程注入Dll
5. 释放Dll
6. 关闭内存映射

#### 3.注入的Dll(Dll-EvtExportLog.cpp)

代码地址：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/Dll-EvtExportLog.cpp`

流程如下：

1. 从第一个内存映射获得日志文件的句柄，将读取到的内容从字符串转换成int类型
2. 从第二个内存映射获得新日志文件的长度
3. 根据新日志文件的长度调整内存映射的读取长度，从第三个内存映射获得新日志文件的内容
4. 调用函数CreateFileMapping()，传入日志文件的句柄，创建一个文件映射内核对象
5. 调用函数MapViewOfFile()将文件数据映射到进程的地址空间
6. 修改内存数据，覆盖为新日志文件的内容
7. 调用函数FlushViewOfFile()，将内存数据写入磁盘
8. 关闭日志文件的内存映射

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-6-19/3-2.png)


**注:**

对于以上两种方法，删除`setup.evtx`是没有问题的，删除`system.evtx`和`security.evtx`会存在因为竞争条件导致删除失败的情况

## 0x07 小结
---

本文介绍了第二种删除当前系统单条日志记录的方法：获得日志服务Eventlog对应进程中指定日志文件的句柄，通过Dll注入获得权限，利用该句柄实现日志文件的修改
某些情况下，dll注入会失败，那么是否还有删除当前系统单条日志记录的方法呢？下一篇文章将会介绍

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







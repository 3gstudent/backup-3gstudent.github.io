---
layout: post
title: Windows XML Event Log (EVTX)单条日志清除（五）——通过DuplicateHandle获取日志文件句柄删除当前系统单条日志记录
---



## 0x00 前言
---

Windows单条日志清除系列文章的第五篇，介绍第三种删除当前系统单条日志记录的方法：枚举当前系统的所有进程，获得指定日志文件的句柄，通过DuplicateHandle复制句柄，获得权限，利用该句柄实现日志文件的修改

## 0x01 简介
---

本文将要介绍以下内容：

- 利用思路
- 程序实现
- 枚举所有进程，获得指定文件句柄
- 通过DuplicateHandle复制句柄
- 开源实现代码

## 0x02 利用分析
---

上篇文章[《Windows XML Event Log (EVTX)单条日志清除（四）——通过注入获取日志文件句柄删除当前系统单条日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E5%9B%9B-%E9%80%9A%E8%BF%87%E6%B3%A8%E5%85%A5%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)提到，某些条件下，高版本的Windows系统不允许注入保护进程svchost.exe，而我们又不想停掉日志服务，那么该怎么办呢？

我在之前的文章[《渗透技巧——Windows系统的文件恢复与删除》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E7%B3%BB%E7%BB%9F%E7%9A%84%E6%96%87%E4%BB%B6%E6%81%A2%E5%A4%8D%E4%B8%8E%E5%88%A0%E9%99%A4/)曾涉及到解决方法，可以尝试通过DuplicateHandle复制句柄，将“伪句柄”转换成实句柄，获得日志文件的操作权限

## 0x03 枚举所有进程，获得指定文件句柄
---

思路如下：

- 使用内核API NtQuerySystemInformation查询SystemHandleInformation，获得所有进程的句柄
- 筛选出类型为文件的句柄
- 如果无法打开句柄对应的进程，留下标志位，不再重复打开该进程
- 过滤出有可能导致挂起的句柄，利用API WaitForSingleObject进行判断
- 通过NtDuplicateObject获取句柄的名称和具体的数值信息，筛选出指定句柄

代码参考地址：

[https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnumerateProcess%26GetFile'sHandle%26CloseHandle(Win7).cpp](https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnumerateProcess%26GetFile'sHandle%26CloseHandle(Win7).cpp)

代码适用于Win7和更高版本的操作系统，并提供了是否选择关闭句柄的功能

当然，也可以先枚举服务信息，找到日志服务对应的进程，缩小查询范围，再获得日志文件的句柄，思路如下：

- 枚举服务信息，找到日志服务对应的进程
- 使用内核API NtQuerySystemInformation查询SystemHandleInformation，获得所有进程的句柄
- 筛选出日志服务对应进程中的句柄
- 通过NtDuplicateObject获取句柄的名称和具体的数值信息，筛选出指定句柄

在效率上会更高，不会遇到有可能导致挂起的句柄

代码参考地址：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/GetPIDandHandle(evtx).cpp

代码实现了自动获得日志服务的进程，缩小查询范围，获得日志文件的句柄

## 0x04 通过DuplicateHandle复制句柄
---

通过枚举进程获得了日志文件的句柄后，发现这是一个“伪句柄”，原因如下：

获取句柄的具体内容需要调用NtDuplicateObject

DuplicateObject的函数原型：

```
BOOL WINAPI DuplicateHandle(
  _In_  HANDLE   hSourceProcessHandle,
  _In_  HANDLE   hSourceHandle,
  _In_  HANDLE   hTargetProcessHandle,
  _Out_ LPHANDLE lpTargetHandle,
  _In_  DWORD    dwDesiredAccess,
  _In_  BOOL     bInheritHandle,
  _In_  DWORD    dwOptions
);
```

官方说明文档：

https://msdn.microsoft.com/en-us/library/ms724251(VS.85).aspx

第7个参数dwOptions，可以为两个值：

- DUPLICATE_CLOSE_SOURCE,0x00000001,Closes the source handle. This occurs regardless of any error status returned.
- DUPLICATE_SAME_ACCESS,0x00000002,Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.

另一参考文档：

https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-zwduplicateobject

获得参考信息：

> DUPLICATE_SAME_ATTRIBUTES	Instead of using the HandleAttributes parameter, copy the attributes from the source handle to the target handle.

参考资料中并未提到DUPLICATE_SAME_ATTRIBUTES的值，这里猜测为0

**注：**

如果读者有更好的答案和解释，希望能够告诉我

为了保证我们在调用NtDuplicateObject遍历句柄时不会影响到系统的其他句柄，这里先将dwOptions设置为`DUPLICATE_SAME_ATTRIBUTES`(即0)，只获得句柄的属性

参数如下：

```
NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)
```

找到指定的日志文件句柄后，下一步将要对日志文件进行操作，这里需要将dwOptions设置为`DUPLICATE_SAME_ACCESS`，代表完全复制

用法如下：

```
NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, DUPLICATE_SAME_ACCESS)
```

dupHandle和源句柄具有相同的权限，对日志文件进行操作时，向CreateFileMapping传入dupHandle即可

```
CreateFileMapping(dupHandle, NULL, PAGE_READWRITE, 0, 0, NULL);
```

余下日志删除操作的部分可参考之前的系列文章

完整代码已开源，包括两种删除日志的方法：

### 1、自己解析格式，实现日志删除

地址如下：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordbyGetHandle.cpp`

代码实现了获得指定日志文件的句柄，通过该句柄获得日志文件的操作权限，能够删除指定evtx文件的单条日志

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-6-19/4-1.png)

### 2、使用WinAPI EvtExportLog，过滤出想要删除的内容

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordbyGetHandleEx.cpp`

代码实现了读取指定路径下的日志文件内容，用来覆盖系统日志

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-6-19/4-2.png)

通常做法是先将日志线程挂起，使得系统无法继续收集日志，代码地址如下：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/SuspendorResumeTid.cpp`

接着读取系统日志内容，删除指定日志，将新日志保存，代码如下：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecord-EvtExportLog.cpp`

最后使用DeleteRecordbyGetHandleEx读取新日志，覆盖系统日志，实现日志删除

**注:**

对于以上两种方法，删除`setup.evtx`是没有问题的，删除`system.evtx`和`security.evtx`会存在因为竞争条件导致删除失败的情况

## 0x05 小结
---

本文介绍了第三种删除当前系统单条日志记录的方法：枚举当前系统的所有进程，获得指定日志文件的句柄，通过DuplicateHandle复制句柄，获得权限，利用该句柄实现日志文件的修改

优点是不需要注入进程svchost.exe，也就不需要考虑保护进程的注入绕过，并且不需要考虑进程间的信息传递，效率更高


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




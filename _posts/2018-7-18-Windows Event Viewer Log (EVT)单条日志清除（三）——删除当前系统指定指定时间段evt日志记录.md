---
layout: post
title: Windows Event Viewer Log (EVT)单条日志清除（三）——删除当前系统指定指定时间段evt日志记录
---


## 0x00 前言
---

Windows Event Viewer Log (EVT)单条日志清除系列文章的第三篇，介绍删除当前系统指定时间段evt日志记录的方法和详细测试过程，说明无法修改日志数量的原因，最后开源查询日志内容和修改日志内容的实现代码

## 0x01 简介
---

本文将要介绍以下内容：

- XP系统下枚举系统所有句柄的方法
- 筛选日志文件句柄的条件
- XP下Dll注入的实例代码
- 实际测试过程
- 无法修改日志数量的原因
- 日志查询的程序实现细节
- 日志修改的程序实现细节


## 0x02 XP系统下枚举系统所有句柄
---

之前的文章[《Windows单条日志清除（五）——通过DuplicateHandle获取日志文件句柄删除当前系统单条日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%94-%E9%80%9A%E8%BF%87DuplicateHandle%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)介绍了Win8及以上系统的实现方法：

1. 利用NtQuerySystemInformation查询SystemHandleInformation能够获得所有进程的句柄信息
2. 通过NtDuplicateObject获取句柄的名称和具体的数值信息
3. 筛选出想要查找的句柄
4. 通过DuplicateHandle复制句柄
5. 获得修改日志文件的权限


在XP系统下，无法使用NtQuerySystemInformation查询SystemHandleInformation获得进程的句柄信息

参考processhacker的源码，寻找实现方法

代码位置：

https://github.com/processhacker/processhacker/blob/e2d793289dede80f6e3bda26d6478dc58b20b7f8/ProcessHacker/hndlprv.c#L307

获得参考资料：

> On Windows 8 and later, NtQueryInformationProcess with ProcessHandleInformation is the most efficient method.
> On Windows XP and later, NtQuerySystemInformation with SystemExtendedHandleInformation.
> Otherwise, NtQuerySystemInformation with SystemHandleInformation can be used.

尝试第二种，使用NtQuerySystemInformation查询SystemExtendedHandleInformation

**注：**

第二种方法支持WinXP及更高版本的系统


## 0x03 筛选出指定日志文件的句柄
---

### 1、筛选出类型为文件的句柄

```
ObjectTypeNumber = 0x1c
```

**注：**

Win8及更高版本的系统，`ObjectTypeNumber = 0x1e`

WinXP和Win7系统，`ObjectTypeNumber = 0x1c`


### 2、过滤出有可能导致挂起的句柄

通过API WaitForSingleObject进行判断

否则将导致进程挂起

### 3、缩小范围，指定文件属性

日志文件的属性固定，`handle->GrantedAccess = 0x0012019f`


完整实现代码已开源，下载地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/GetPIDandHandle(evt).cpp


代码实现了根据输入的关键词进行搜索，获得对应的句柄名称和Handle值


## 0x04 日志删除的实现方法1：通过Dll注入获得句柄操作权限
---

向系统进程注入dll，dll文件即可获取日志文件的句柄

接下来的操作为：

1. 调用函数CreateFileMapping()创建一个文件映射内核对象
2. 调用函数MapViewOfFile()将文件数据映射到进程的地址空间
3. 修改内存中的数据，删除指定日志记录
4. 调用函数FlushViewOfFile()，将内存数据写入磁盘
5. 清除内存映射对象

完整的实现过程可参考之前介绍删除evtx文件单条日志的文章[《Windows XML Event Log (EVTX)单条日志清除（四）——通过注入获取日志文件句柄删除当前系统单条日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E5%9B%9B-%E9%80%9A%E8%BF%87%E6%B3%A8%E5%85%A5%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

xp系统下无法使用NtCreateThreadEx + LdrLoadDll的方式注入dll，可以直接调用CreateRemoteThread

实现代码可参考：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/CreateRemoteThread.cpp


## 0x05 日志删除的实现方法2：通过DuplicateHandle获得句柄操作权限
---

参考之前的文章[《Windows XML Event Log (EVTX)单条日志清除（五）——通过DuplicateHandle获取日志文件句柄删除当前系统单条日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%94-%E9%80%9A%E8%BF%87DuplicateHandle%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

筛选出句柄后，再次调用NtDuplicateObject获得实句柄，对日志文件进行删除操作

同样，需要以下操作：

1. 调用函数CreateFileMapping()创建一个文件映射内核对象
2. 调用函数MapViewOfFile()将文件数据映射到进程的地址空间
3. 修改内存中的数据，删除指定日志记录
4. 调用函数FlushViewOfFile()，将内存数据写入磁盘
5. 清除内存映射对象

日志删除部分可参考之前的文章[《Windows Event Viewer Log (EVT)单条日志清除（二）——程序实现删除evt文件指定时间段的日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-Event-Viewer-Log-(EVT)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%8C-%E7%A8%8B%E5%BA%8F%E5%AE%9E%E7%8E%B0%E5%88%A0%E9%99%A4evt%E6%96%87%E4%BB%B6%E6%8C%87%E5%AE%9A%E6%97%B6%E9%97%B4%E6%AE%B5%E7%9A%84%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

这里给出一个完整的实现代码：

`https://github.com/3gstudent/Eventlogedit-evt--General/blob/master/evtDeleteRecordbyGetHandle.cpp`

代码实现了删除指定evt文件中，某一时间段的多条日志，并且生成调试文件sys2.evt和sys3.evt

sys2.evt保存删除日志后的数组内容

sys3.evt保存映射到内存中的内容

程序执行后，sys2.evt和sys3.evt成功删除指定日志，但是当前系统的日志文件产生错误

为了对比测试，我将删除的时间段调整为当前日志以外的数值，即不会删除任何日志，程序执行后，当前系统的日志文件正常

更进一步，只要不改变日志的个数，修改日志的内容，当前系统的日志文件仍正常

这里得出一个结论：**无法通过获得日志文件句柄修改内存数据的方式改变日志的数目**

同样，通过ProcessHacker直接修改内存文件的File header也无法改变日志的数目

编写程序验证，通过API GetNumberOfEventLogRecords查询日志个数

c代码如下：

```
#include <windows.h>
#pragma comment(lib,"Advapi32.lib") 

int main(int argc, char *argv[])
{
	HANDLE hEventLog = NULL;

	hEventLog = OpenEventLog(NULL, argv[1]);
	if (NULL == hEventLog)
	{
		printf("OpenEventLog failed with 0x%x.\n", GetLastError());
		goto cleanup;
	}

	DWORD NumberOfRecords = 0;
	BOOL flag = GetNumberOfEventLogRecords(hEventLog, &NumberOfRecords);

	if (NULL == flag)
	{
		printf("GetNumberOfEventLogRecords failed with 0x%x.\n", GetLastError());
		goto cleanup;
	}
	printf("%d\n", NumberOfRecords);

cleanup:

	if (hEventLog)
		CloseEventLog(hEventLog);

}
```

cmd：

```
GetNumberOfEventLogRecords.exe system
```

获得日志个数

通过ProcessHacker直接修改内存文件`File header`的`Last (newest) record number`和`End of file record`的`Last (newest) record number`

再次执行程序获得日志个数，发现获得的日志个数不变

验证结论，修改内存中的日志内容无法更改实际的日志个数

## 0x06 日志查询和日志修改的程序实现细节

日志查询的代码如下：

`https://github.com/3gstudent/Eventlogedit-evt--General/blob/master/evtQueryRecordbyGetHandle.cpp`

代码实现了遍历日志，显示每个日志的信息

日志修改的代码如下：

`https://github.com/3gstudent/Eventlogedit-evt--General/blob/master/evtModifyRecordbyGetHandle.cpp`

代码实现了修改指定日志的信息


## 0x07 小结
---

本文介绍了删除当前系统指指定时间段evt日志记录的两种方法:通过Dll注入和通过DuplicateHandle分别获得句柄操作权限，利用该句柄实现日志文件的修改

删除方式不是简单的覆盖，而是完全的删除某段时间的日志，evtx文件的日志删除也可以参考这种方法，只是实现上相对复杂一些，后续会更新evtx的实现代码


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



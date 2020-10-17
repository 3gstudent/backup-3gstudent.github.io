---
layout: post
title: 渗透技巧——获得Exchange GlobalAddressList的方法
---


## 0x00 前言
---

Exchange GlobalAddressList(全局地址列表)包含Exchange组织中所有邮箱用户的邮件地址，只要获得Exchange组织内任一邮箱用户的凭据，就能够通过GlobalAddressList导出其他邮箱用户的邮件地址。

本文将要介绍在渗透测试中不同条件下获得Exchange GlobalAddressList的常用方法，分享程序实现的细节，最后介绍禁用GlobalAddressList的方法

## 0x01 简介
---

本文将要介绍以下内容：

- 获得Exchange GlobalAddressList的方法
- 程序实现
- 禁用GlobalAddressList的方法

## 0x02 获得Exchange GlobalAddressList的方法
---

### 1.通过Outlook Web Access(OWA)

需要获得邮件用户的明文口令，登录OWA后，选择联系人->`All Users`

### 2.通过Exchange Web Service(EWS)

对于Exchange 2013及更高版本，可以使用FindPeople操作

参考资料：

https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/findpeople-operation?redirectedfrom=MSDN

这里需要注意，FindPeople操作时必须指定搜索条件，无法通过通配符直接获取所有结果

变通的解决方法：

遍历26个字母a-z，以此作为搜索条件，能够覆盖所有结果

对于Exchange2010及更低版本，只能使用ResolveName操作

参考资料：

https://docs.microsoft.com/en-us/dotnet/api/microsoft.exchange.webservices.data.exchangeservice.resolvename?redirectedfrom=MSDN&view=exchange-ews-api

这里需要注意，ResolveName操作每次最多只能获得100个结果，如果GlobalAddressList中的邮箱用户大于100，那么无法直接获得完整结果

变通的解决方法：

使用ResolveName操作时加入搜索条件，确保每次获得的结果能够少于100，接着通过多次搜索实现对全部结果的覆盖

通常使用的方法：

搜索条件为任意两个字母的组合，例如aa、ab、ac....zz，总共搜索26*26=676次，一般情况下能够覆盖所有结果

### 3.通过Outlook客户端使用的协议(MAPI OVER HTTP和RPC over HTTP)

登录用户，选择`联系人`->`通讯簿`

Outlook客户端通常使用的协议为RPC、RPC over HTTP(也称作Outlook Anywhere)和MAPI over HTTP

使用[ruler](https://github.com/sensepost/ruler)能够通过MAPI OVER HTTP(暂不支持RPC over HTTP)读取GlobalAddressList

**注：**

MAPI over HTTP是Exchange Server 2013 Service Pack 1 (SP1)中实现的新传输协议，用来替代RPC OVER HTTP(也称作Outlook Anywhere)

Exchange2013默认没有启用MAPI OVER HTTP，而是使用的RPC OVER HTTP，需要手动开启

Exchange2016默认启用MAPI OVER HTTP

通过RPC over HTTP读取GlobalAddressList可使用ptswarm的[Exchanger.py](https://github.com/ptswarm/impacket)

参考资料：

https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/

流程如下：

#### (1)列出AddressList

命令示例：

```
python exchanger.py 192.168.1.1/test1:DomainUser123!@test.com nspi list-tables
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-7-11/4-1.png)

从图中可以获得`All Users`对应的guid为`5cb80229-e2b4-4447-b224-dc2c12098835`

#### (2)读取AddressList

命令示例：

```
python exchanger.py 192.168.1.1/test1:DomainUser123!@test.com nspi dump-tables -guid 5cb80229-e2b4-4447-b224-dc2c12098835
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-7-11/4-2.png)

### 4.通过Offline Address Book (OAB)

流程如下：

#### (1)读取Autodiscover配置信息

访问的URL：`https://<domain>/autodiscover/autodiscover.xml`

**注：**

需要发送特定的POST包，详情可参考文章《渗透基础——Exchange Autodiscover的使用》

从配置信息中获得OABUrl

#### (2)读取OAB文件列表

访问的URL：`OABUrl/oab.xml`

返回结果中包括多个OAB文件的列表，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-7-11/3-1.png)

找到其中`Default Global Address List`对应的lzx文件名称，lzx文件名称为`4667c322-5c08-4cda-844a-253ff36b4a6a-data-5.lzx`

#### (3)下载lzx文件

访问的URL：`OABUrl/xx.lzx`

对应上面的示例，lzx文件的下载地址为：`https://192.168.1.1/OAB/9e3fa457-ebf1-40e4-b265-21d09a62872b/4667c322-5c08-4cda-844a-253ff36b4a6a-data-5.lzx`

#### (4)对lzx文件解码，还原出Default Global Address List

这里需要使用工具[oabextract](https://github.com/kyz/libmspack)

下载后需要进行安装

编译好可在Kali下直接使用的版本下载地址：http://x2100.icecube.wisc.edu/downloads/python/python2.6.Linux-x86_64.gcc-4.4.4/bin/oabextract

将lzx文件转换为oab文件的命令示例：

```
oabextract 4667c322-5c08-4cda-844a-253ff36b4a6a-data-5.lzx gal.oab
```

提取出GAL的命令示例：

```
strings gal.oab|grep SMTP
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-7-11/3-2.png)

### 5.通过LDAP

需要能够访问域控制器的LDAP服务(389端口)

通常Exchange邮箱用户同域用户存在对应关系，所以可以根据域用户的信息获得Exchange邮箱用户的信息

#### (1)从域外进行查询

需要获得域用户的明文口令

Kali系统通过ldapsearch获取所有用户邮件地址的命令示例：

```
ldapsearch -x -H ldap://192.168.1.1:389 -D "CN=testa,CN=Users,DC=test,DC=com" -w DomainUser123! -b "DC=test,DC=com" |grep mail:
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-7-11/1-1.png)

Windows系统通过[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)获取所有用户邮件地址的命令示例：

```
$uname="testa"                                                      
$pwd=ConvertTo-SecureString "DomainUser123!" -AsPlainText –Force                   
$cred=New-Object System.Management.Automation.PSCredential($uname,$pwd)        
Get-NetUser -Domain test.com -DomainController 192.168.1.1 -ADSpath "LDAP://DC=test,DC=com" -Credential $cred | fl mail
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-7-11/1-2.png)

Windows系统通过C#实现：

通过调用命名空间System.DirectoryServices能够很容易实现相同的操作，代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/ListUserMailbyLDAP.cs

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-7-11/1-3.png)

#### (2)从域内进行查询

从域外查询的方法均适用，此时不需要域用户的凭据

还可以使用PSSession连接Exchange服务器后，通过Exchange Management Shell进行查询

命令示例：

```
$User = "test\administrator"
$Pass = ConvertTo-SecureString -AsPlainText DomainAdmin123! -Force
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $User,$Pass
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://Exchange01.test.com/PowerShell/ -Authentication Kerberos -Credential $Credential
Import-PSSession $Session -AllowClobber
Get-Mailbox|fl PrimarySmtpAddress
Remove-PSSession $Session
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-7-11/1-4.png)

## 0x03 通过Exchange Web Service(EWS)获得GlobalAddressList的实现代码
---

### 1.Powershell

需要明文口令

https://github.com/dafthack/MailSniper

需要PowerShell version 3.0

支持FindPeople操作和ResolveName操作

**注：**

FindPeople操作通过owa实现

ResolveName操作通过ews实现

### 2.Python

需要明文口令或NTLM hash

#### (1)FindPeople操作

参考资料：

https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/findpeople-operation?redirectedfrom=MSDN

只能在Exchange Server 2013或更高版本使用

XML格式示例：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
      <m:FindPeople>
         <m:IndexedPageItemView BasePoint="Beginning" MaxEntriesReturned="999999" Offset="0"/>
         <m:ParentFolderId>
            <t:DistinguishedFolderId Id="directory"/>
         </m:ParentFolderId>
         <m:QueryString>test</m:QueryString>
      </m:FindPeople>
  </soap:Body>
</soap:Envelope>
```

搜索字符串`test`，这里指定最大查询结果数量999999

为了能够覆盖所有结果，搜索字符串需要遍历26个字母a-z，获得返回结果后进行去重处理

完整的代码可参考我在[ewsManage](https://github.com/3gstudent/Homework-of-Python/blob/master/ewsManage.py)新增的findallpeople功能

#### (2)ResolveName操作

XML格式示例：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:ResolveNames ReturnFullContactData="false" SearchScope="ContactsActiveDirectory">
      <m:UnresolvedEntry>test</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>
</soap:Envelope>
```

搜索字符串`test`，这里返回的查询结果最多为100

为了能够覆盖所有结果，搜索条件为任意两个字母的组合，例如aa、ab、ac....zz，总共搜索26*26=676次，一般情况下能够覆盖所有结果，获得返回结果后进行去重处理

这里需要注意，如果某个搜索条件获得的返回结果为100，代表这个搜索条件的结果可能不完整(实际大于100，只获得了100)，需要再次进行划分，进行第三级的遍历。返回结果可通过读取返回内容的`TotalItemsInView`项获得

完整的代码可参考我在[ewsManage](https://github.com/3gstudent/Homework-of-Python/blob/master/ewsManage.py)新增的resolveallname功能

## 0x04 禁用GlobalAddressList的方法
---

可以选择指定用户是否在GlobalAddressList中隐藏

### 1.通过Exchange admin center(EAC)

使用Exchange管理员登录Exchange Control Panel(ECP)

选择指定用户，选择`general`，选中`Hide from address lists`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-7-11/2-1.png)

### 2.通过Exchange Management Shell

隐藏指定用户的命令：

```
Set-MailContact -HiddenFromAddressListsEnabled $true -Identity test1
```

隐藏所有用户的命令：

```
Get-MailContact | Set-MailContact -HiddenFromAddressListsEnabled $true
```

## 0x05 小结
---

本文介绍了不同条件下获得Exchange GlobalAddressList的常用方法，编写程序分别实现通过ews的FindPeople操作和ResolveName操作导出GlobalAddressList，在最后介绍了禁用GlobalAddressList的方法。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






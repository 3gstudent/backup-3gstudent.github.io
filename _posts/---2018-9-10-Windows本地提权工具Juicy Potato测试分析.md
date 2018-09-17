---
layout: post
title: Windows本地提权工具Juicy Potato测试分析
---


## 0x00 前言
---

Juicy Potato是一款Windows系统的本地提权工具，是在工具RottenPotatoNG的基础上做了扩展，适用条件更广

利用的前提是获得了SeImpersonate或者SeAssignPrimaryToken权限，通常在webshell下使用

那么，Juicy Potato的使用方法有哪些，有哪些限制条件呢？本文将对其进行测试，根据原理分析限制条件

Juicy Potato的下载地址：

https://github.com/ohpe/juicy-potato

## 0x01 简介
---

本将要介绍以下内容：

- 实现原理
- 对RottenPotatoNG的扩展
- 枚举可用COM对象的方法
- 使用方法
- 限制条件
- 防御思路

## 0x02 实现原理
---

参考资料：

https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/

根据个人理解介绍实现原理

需要理解的几个知识：

1. 使用DCOM时，如果以服务的方式远程连接，那么权限为System，例如BITS服务
2. 使用DCOM可以通过TCP连接到本机的一个端口，发起NTLM认证，该认证可以被重放
3. LocalService用户默认具有SeImpersonate和SeAssignPrimaryToken权限
4. 开启SeImpersonate权限后，能够在调用CreateProcessWithToken时，传入新的Token创建新的进程
5. 开启SeAssignPrimaryToken权限后，能够在调用CreateProcessAsUser时，传入新的Token创建新的进程

Juicy Potato的实现流程如下：

#### 1、加载COM，发出请求，权限为System

在指定ip和端口的位置尝试加载一个COM对象

RottenPotatoNG使用的COM对象为BITS，CLSID为`{4991d34b-80a1-4291-83b6-3328366b9097}`

可供选择的COM对象不唯一，Juicy Potato提供了多个，详细列表可参考如下地址：

https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md

#### 2、回应步骤1的请求，发起NTLM认证

正常情况下，由于权限不足，当前权限不是System，无法认证成功

#### 3、针对本地端口，同样发起NTLM认证，权限为当前用户

由于权限为当前用户，所以NTLM认证能够成功完成

RottenPotatoNG使用的135端口

Juicy Potato支持指定任意本地端口，但是RPC一般默认为135端口，很少被修改

#### 4、分别拦截两个NTLM认证的数据包，替换数据，通过NTLM重放使得步骤1(权限为System)的NTLM认证通过，获得System权限的Token

重放时需要注意NTLM认证的NTLM Server Challenge不同，需要修正

#### 5、利用System权限的Token创建新进程

如果开启SeImpersonate权限，调用CreateProcessWithToken，传入System权限的Token，创建的进程为System权限

或者

如果开启SeAssignPrimaryToken权限，调用CreateProcessAsUser，传入System权限的Token，创建的进程为System权限

**注：**

详细说明可参考之前的文章《渗透技巧——Windows Token九
种权限的利用》


**利用的关键：**

当前用户支持SeImpersonate或者SeAssignPrimaryToken权限

以下用户具有该权限：

- 本地管理员组成员和本地服务帐户
- 由服务控制管理器启动的服务
- 由组件对象模型 (COM) 基础结构启动的并配置为在特定帐户下运行的COM服务器

针对提权的话，主要是第三类用户，常见的为LocalService用户，例如IIS和者sqlserver的用户


## 0x03 枚举可用COM对象的方法
---

Juicy Potato提供了枚举可用COM对象的方法，步骤如下：

#### 1、获得可用CLSID的列表

使用GetCLSID.ps1，地址如下：

https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1

**注：**

使用时同级目录下需要包含支持文件`.\utils\Join-Object.ps1`


执行成功后生成文件`CLSID.list`和`CLSID.csv`

#### 2、使用批处理调用juicypotato.exe逐个测试CLSID

批处理地址如下：

https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat

juicypotato.exe的参数如下：

```
juicypotato.exe -z -l !port! -c %%i >> result.log
```

-z表示测试模式，只验证Token，不使用Token创建进程

-l为端口，起始为1000，每次循环加1

-c为从文件CLSID.list获得的CLSID

Juicy Potato已经测试了如下Windows系统：

- Windows 7 Enterprise
- Windows 8.1 Enterprise
- Windows 10 Enterprise
- Windows 10 Professional
- Windows Server 2008 R2 Enterprise
- Windows Server 2012 Datacenter
- Windows Server 2016 Standard


我在测试的过程中，在Server2012下执行GetCLSID.ps1时会报错，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-9-1/4-1.png)

出错在位置在`.\utils\Join-Object.ps1`


这里给出一种修改方法：

#### 1、枚举所有满足条件的CLSID

powershell代码如下：

```
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
$CLSID = Get-ItemProperty HKCR:\clsid\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}} | where-object {$_.appid -ne $null}
foreach($a in $CLSID)
{
	Write-Host $a.CLSID
}
```

可以选择将结果保存为`CLSID.list`

#### 2、使用批处理调用juicypotato.exe逐个验证

地址如下：

https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat

bat脚本不需要做修改

## 0x04 使用方法
---

### 1、查看当前用户权限，是否符合要求

```
whoami /priv
```

如果开启SeImpersonate权限，juicypotato的参数可以使用`-t t`

如果开启SeAssignPrimaryToken权限，juicypotato的参数可以使用`-t u`

如果均开启，可以选择`-t *`

如果均未开启，那么无法提权

### 2、查看RPC默认端口是否为135

如果被修改(例如为111)，juicypotato的参数可以使用`-n 111`

如果系统禁用了RPC，并不是一定无法提权，需要满足如下条件：

找到另一系统，能够以当前用户的权限进行远程RPC登录，此时juicypotato的参数可以使用`-k <ip>`

例如Win7、WIn8系统，默认配置下，允许135端口的入站规则即可进行远程RPC登录

添加防火墙规则允许135端口入站的命令如下：

```
netsh advfirewall firewall add rule name="135" protocol=TCP dir=in localport=135 action=allow
```

也可以选择将防火墙关闭，可参考绕过UAC关闭防火墙的代码：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/DisableFirewall.cpp


### 3、根据操作系统选择可用的CLSID

参考列表

https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md

例如测试系统Server2012，选择CLSID为`{8BC3F05E-D86B-11D0-A075-00C04FB68820}`


### 4、选择一个系统未占用的端口作为监听端口

例如，最终参数如下：

```
JuicyPotato.exe -t t -p c:\windows\system32\cmd.exe -l 1111 -c {8BC3F05E-D86B-11D0-A075-00C04FB68820}
```

表示开启SeImpersonate权限创建进程，监听端口1111，使用的CLSID为`{8BC3F05E-D86B-11D0-A075-00C04FB68820}`


## 0x05 限制条件
---

经过以上的分析，Juicy Potato的限制条件如下：

- 需要支持SeImpersonate或者SeAssignPrimaryToken权限
- 开启DCOM
- 本地支持RPC或者远程服务器支持PRC并能成功登录
- 能够找到可用的COM对象

## 0x06 防御思路
---

站在防御的角度，服务器禁用DCOM，禁用RPC，或者为每一个COM对象配置属性均不现实

针对Juicy Potato的关键在于权限的控制，阻止攻击者获得SeImpersonate或者SeAssignPrimaryToken权限


## 0x07 补充
---

更多学习资料：

https://bugs.chromium.org/p/project-zero/issues/detail?id=325&redir=1

## 0x08 小结
---

本文对Juicy Potato进行测试，总结使用方法，同RottenPotatoNG进行比较，分析原理，找到限制条件和防御思路


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)









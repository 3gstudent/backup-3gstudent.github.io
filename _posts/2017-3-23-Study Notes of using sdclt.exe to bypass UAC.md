---
layout: post
title: Study Notes of using sdclt.exe to bypass UAC
---

## 0x00 前言
---

Matt Nelson‏ @enigma0x3在最近的文章中公开了一个绕过Win10 UAC的技巧，通过修改HKCU下的注册表键值实现对UAC的绕过，文章地址如下：

https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/

https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/

## 0x01 简介
---

本文将对其进行测试，分享测试心得，整理该方法的攻防技巧



## 0x02 原理
---


**Sigcheck**

可用来查看exe文件的清单(manifest)

**下载地址：**

https://technet.microsoft.com/en-us/sysinternals/bb897441.aspx

在Win10环境下，cmd下运行：

`sigcheck.exe -m c:\windows\system32\sdclt.exe`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-0.png)

level="requireAdministrator"

true代表可自动提升权限

在Win7环境下，同样使用Sigcheck查看sdclt.exe

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-01.png)

level="asInvoker"表示不会提升权限，这也就是不支持Win7的原因

接下来，使用ProcessMonitor监控sdclt.exe的启动过程，查找是否会调用其他程序


## 0x03 实际测试
---

测试环境： Win 10 x64

**注：**

该方法只在Win10下测试成功

cmd下输入：

`sdclt.exe`

正常启动，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-1.png)

使用ProcessMonitor查看启动过程

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-2.png)

启动sdclt.exe的过程中会以High权限查找注册表键值`HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`

如果手动修改该注册表键值，填入参数，那么就能够实现UAC的绕过

**绕过方法如下：**

新建注册表键值：

`HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`

并将默认值设置为`cmd.exe`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-3.png)

再次启动sdclt.exe，发现转而去执行cmd.exe，并且实现了对UAC的绕过，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-4.png)

**注：**

启动的exe不能加参数，否则失败

例如填入C:\Windows\System32\cmd.exe /c calc.exe，无法实现利用

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-5.png)

在实际利用的过程中，如果需要加参数，可通过先将参数写入脚本，再加载脚本的方式进行利用

为了更好的隐蔽，实现“无文件”利用，可以尝试寻找sdclt.exe是否存在支持传入参数的命令


Matt Nelson‏ @enigma0x3的第二篇文章就是解决了这个问题，文章地址如下：

https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/


修改注册表，劫持`/kickoffelev`传入的参数，实现“无文件”利用


**具体方法如下：**

新建注册表键值：

`HKCU:\Software\Classes\exefile\shell\runas\command\`

新建项`isolatedCommand`，类型`REG_SZ`，内容作为启动参数，可设置为`notepad.exe`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-6.png)

接着在cmd下输入：

`sdclt.exe /KickOffElev`

成功执行参数，启动notetad.exe，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-7.png)

参数换成regedit.exe，启动过程并未被UAC拦截，成功绕过

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-23/2-8.png)

但是通过创建注册表键值exefile\shell\runas\command\会影响其他正常exe程序的启动，所以在利用上需要先创建键值，执行sdclt.exe，之后再删除该键值

整个过程通过powershell实现，完整POC可参考：

https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-SDCLTBypass.ps1

## 0x04 防御和检测
---

**防御：**

UAC权限设置为“Always Notify”，那么该方法将会失效

**检测：**

监控注册表键值：

`HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`

`HKCU:\Software\Classes\exefile\shell\runas\command\`



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




---
layout: post
title: Study Notes of using SilentCleanup to bypass UAC
---


## 0x00 前言
---

最近我在James Forshaw‏的博客学到了一个Win10下绕过UAC的技巧，该方法通过脚本实现，并且目前微软还未对该绕过方法进行修复（预计在Win10 RS3修复）。经过我的学习测试，该方法同样适用于Win8，并且文中介绍的绕过思路很值得学习，因此整理成文，分享给大家。

文章地址如下：

https://tyranidslair.blogspot.co.uk/2017/05/exploiting-environment-variables-in.html


## 0x01 简介
---

本文将要介绍以下内容：

- 绕过思路
- 利用方法
- 防御检测

## 0x02 绕过思路
---

在之前文章也分享过一些绕过UAC思路的心得，可参考以下文章：

https://3gstudent.github.io/3gstudent.github.io/Study-Notes-of-using-sdclt.exe-to-bypass-UAC/

https://3gstudent.github.io/3gstudent.github.io/Study-Notes-Weekly-No.1(Monitor-WMI_ExportsToC++_Use-DiskCleanup-bypass-UAC)/

个人认为寻找绕过UAC的方法可分为以下两个步骤：

1、寻找权限控制不严格的程序

通常具有以下特点：

- 以普通用户权限启动程序
- 程序默认以高权限启动，通常标记为Highest

2、该程序启动过程是否可被劫持

- 启动路径是否可被劫持
- 启动过程加载的问题（如dll）是否可被劫持


## 0x03 利用方法
---


对应到James Forshaw‏的方法，也是优先寻找权限控制不严格的程序——计划任务中的SilentCleanup

**注：**

 Matt Nelson之前也介绍过一个利用SilentCleanup绕过UAC的方法，目前已被修复，文章地址如下：

 https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/

**计划任务中的SilentCleanup：**

- 普通用户权限即可启动
- 启动后自动提升为高权限

通过Powershell可以获取更多细节,代码如下：

```
$task = Get-ScheduledTask SilentCleanup
$task.Principal
```

**注：**

Win7默认powershell版本2.0，不支持Get-ScheduledTask操作

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-21/2-1.png)

Authenticated Users表示普通用户权限即可启动

RunLevel为Highest表示以高权限启动

查看启动参数，powershell代码如下：

`$task.Actions[0]`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-21/2-2.png)

启动参数为`%windir%\system32\cleanmgr.exe`

这里存在一个可供利用的地方——`环境变量%windir%`


**注：**

可通过`set windir`查看环境变量%windir%

%windir%默认指向c:\Windows

如果修改当前系统环境变量，指向其他路径，那么这里就实现了一个劫持

**例如：**

将%windir%设置为c:\test

在c:\test\system32\下将payload.exe保存为cleanmgr.exe

那么在启动计划任务SilentCleanup时，就会以高权限启动payload.exe，实现了UAC绕过

**更直接的利用方法：**

将%windir%设置为`cmd /K`，那么在启动计划任务SilentCleanup时会弹出cmd.exe

**注:**

cmd后面需要加参数，否则由于参数问题导致无法正常启动

/k表示弹出的cmd.exe在执行代码后不退出

为了增加隐蔽性（很多程序在启动时需要调用环境变量%windir%），在执行cmd的需要同时删除新添加的注册表键值`windir`，可以使用如下代码：

```
reg add hkcu\Environment /v windir /d "cmd /K reg delete hkcu\Environment /v windir /f && REM "
schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```


**注：**

以上代码来自于https://gist.github.com/tyranid/729b334bf9dc0f38184dbd47ae3f52d0#file-disk_cleanup_uac_bypass-bat

将环境变量设置为`cmd /K reg delete hkcu\Environment /v windir /f && REM`，那么在启动计划任务SilentCleanup时会弹出cmd.exe，接着执行删除注册表键值的命令：`reg delete hkcu\Environment /v windir /f`

完整操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-21/3-1.gif)

**注:**

参数如果换成`/a`，那么cmd.exe在执行后面的命令后会立即退出



## 0x04 防御检测
---

### 1、防御

修改计划任务SilentCleanup的启动参数，将环境变量去掉，换成`c:\Windows`，锁定路径

**管理员权限：**

```
$action = New-ScheduledTaskAction -Execute $env:windir\System32\cleanmgr.exe -Argument "/autoclean /d $env:systemdrive"
Set-ScheduledTask SilentCleanup -TaskPath \Microsoft\Windows\DiskCleanup -Action $action
```

**注：**

以上代码来自于https://gist.github.com/tyranid/9ef39228ba0acc6aa4039d2218006546#file-fix_diskclean_uac_bypass-ps1

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-21/4-1.png)

计划任务SilentCleanup的启动参数被修改为`c:\windows\system32\cleanmgr.exe`，无法通过修改环境变量%windir%对其劫持

### 2、检测

通过powershell寻找计划任务中是否还存在可供利用的服务，代码如下：

```
$tasks = Get-ScheduledTask | 
    Where-Object { $_.Principal.RunLevel -ne "Limited" -and 
                   $_.Principal.LogonType -ne "ServiceAccount" -and 
                   $_.State -ne "Disabled" -and 
                   $_.Actions[0].CimClass.CimClassName -eq "MSFT_TaskExecAction" }
```

**注：**

以上代码来自于https://gist.github.com/tyranid/92e1c7074a9a7b0d5d021e9218e34fe7#file-get_scheduled_tasks-ps1


如下图，可供利用的服务一共有四个，经测试，其他三个无法实际利用，只有SilentCleanup有效

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-21/4-2.png)

## 0x05 补充
---

该方法同样适用于Win8环境，完整操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-21/5-1.gif)

Win7系统不包含计划任务SilentCleanup，因此无法利用

## 0x06 小结
---

本文介绍了通过计划任务SilentCleanup绕过UAC的方法，该方法仅需要通过脚本向当前用户注册表写入键值即可，简单有效。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




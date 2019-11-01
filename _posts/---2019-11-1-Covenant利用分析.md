---
layout: post
title: Covenant利用分析
---


## 0x00 前言
---

Covenant是一个.NET开发的C2(command and control)框架，使用.NET Core的开发环境，不仅支持Linux，MacOS和Windows，还支持docker容器。

最特别的地方是支持动态编译，能够将输入的C#代码上传至C2 Server，获得编译后的文件并使用Assembly.Load()从内存进行加载。

本文仅在技术研究的角度，介绍Covenant的细节，分析特点。

## 0x01 简介
---

本文将要介绍以下内容：

- Covenant的启动方法
- Covenant的功能介绍
- Covenant的优点
- Covenant的检测

## 0x02 Covenant的启动方法
---

### 1.Windows系统

需要装对应版本的.NET Core、ASP.NET Core和SDK

经测试，Covenant需要.NET Core 2.2.0、ASP.NET Core 2.2.0和SDK 2.2.101，其他版本会报错

下载地址：

https://dotnet.microsoft.com/download/thank-you/dotnet-sdk-2.2.101-windows-x64-installer

https://dotnet.microsoft.com/download/thank-you/dotnet-runtime-2.2.0-windows-x64-installer

https://dotnet.microsoft.com/download/thank-you/dotnet-runtime-2.2.0-windows-x64-asp.net-core-runtime-installer

安装Git for Windows

https://github.com/git-for-windows/git/releases/download/v2.23.0.windows.1/Git-2.23.0-64-bit.exe

下载并启动：

```
git clone --recurse-submodules https://github.com/cobbr/Covenant
cd Covenant/Covenant
dotnet build
dotnet run
```

访问https://localhost:7443进入控制面板，第一次使用时需要注册用户

这里可以注册多个用户，实现团队协作

**注：**

Elite是与Covenant服务器进行交互的命令行程序，目前已经临时弃用，地址：

https://github.com/cobbr/Elite

## 0x03 Covenant的功能介绍
---

Covenant支持的功能可参考：

https://github.com/cobbr/Covenant/wiki

这里只介绍个人认为比较重要的部分

### 1.Listeners

只支持HTTP协议，可以指定url和通信消息的格式

选择`Listeners`->`Profiles`，默认包括两个配置模板，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-1/2-1.png)

配置模板中可以设置多个HttpUrls，Grunt在回连的时候会从HttpUrls中随机选择

**注：**

Grunt用作部署到目标，作为被控制端

HttpRequest和HttpResponse的内容都可以指定

配置模板对应源码文件的位置： `.\Covenant\Covenant\Data\Profiles`

### 2.Launchers

用于启动Grunt，包括以下9种启动方式:

#### (1)Binary

.NET程序集，格式为exe文件

#### (2)PowerShell

命令行下通过Powershell启动Grunt

将.NET程序集保存在数组，通过Assembly.Load()在内存进行加载

代码示例：

```
[Reflection.Assembly]::Load(Data).EntryPoint.Invoke(0,$a.ToArray())
```

#### (3)MSBuild

命令行下通过msbuild启动Grunt

启动命令示例：

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe GruntStager.xml
```

将.NET程序集保存在数组，通过Assembly.Load()在内存进行加载

代码示例：

```
System.Reflection.Assembly.Load(oms.ToArray()).EntryPoint.Invoke(0, new object[] { new string[]{ } });
```

关于msbuild的用法可参考之前的文章[《Use MSBuild To Do More》](https://3gstudent.github.io/3gstudent.github.io/Use-MSBuild-To-Do-More/)

#### (4)InstallUtil

命令行下通过InstallUtil启动Grunt

**注：**

我在测试的时候这里产生了bug，生成的文件名称为`GruntStager.xml`，里面保存了base64加密的.NET程序集

按照我理解的InstallUtil的用法，这里应该生成一个.cs文件

查看Covenant的源码，生成模板的源码位置：`.\Covenant\Covenant\Models\Launchers\InstallUtilLauncher.cs`

对应的链接：

https://github.com/cobbr/Covenant/blob/master/Covenant/Models/Launchers/InstallUtilLauncher.cs

模板中包括.cs文件的内容，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-1/2-2.png)

这里可以将`CodeTemplate`的内容另存为.cs文件，并把其中的`"{{GRUNT_IL_BYTE_STRING}}"`替换成base64加密的.NET程序集，最终保存成test.cs

启动命令示例：

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out::file.dll test.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U file.dll
```

#### (5)Wmic

启动命令示例：

```
wmic os get /format:"file.xsl"
```

**注：**

Covenant在此处提示这个方法也许无法在Windows 10和Windows Server 2016下使用

将.NET程序集保存在数组，通过DotNetToJScript的方法在内存进行加载

代码示例：

```
var o = delegate.DynamicInvoke(array.ToArray()).CreateInstance('Grunt.GruntStager');
```

关于Wmic的用法可参考之前的文章[《利用wmic调用xsl文件的分析与利用》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8wmic%E8%B0%83%E7%94%A8xsl%E6%96%87%E4%BB%B6%E7%9A%84%E5%88%86%E6%9E%90%E4%B8%8E%E5%88%A9%E7%94%A8/)

#### (6)Regsvr32

启动命令示例：

```
regsvr32 /u /s /i:file.sct scrobj.dll
```

**注：**

Covenant在此处提示这个方法也许无法在Windows 10和Windows Server 2016下使用

将.NET程序集保存在数组，通过DotNetToJScript的方法在内存进行加载

关于Regsvr32的用法可参考之前的文章《Use SCT to Bypass Application Whitelisting Protection》

#### (7)Mshta

启动命令示例：

```
mshta file.hta
```

**注：**

Covenant在此处提示这个方法也许无法在Windows 10和Windows Server 2016下使用

将.NET程序集保存在数组，通过DotNetToJScript的方法在内存进行加载

关于Mshta的用法可参考之前的文章[《渗透技巧——从github下载文件的多种方法》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E4%BB%8Egithub%E4%B8%8B%E8%BD%BD%E6%96%87%E4%BB%B6%E7%9A%84%E5%A4%9A%E7%A7%8D%E6%96%B9%E6%B3%95/)

#### (8)Cscript

启动命令示例：

```
cscript file.js
```

这里借助了DotNetToJScript，其他内容同上

#### (9)Wscript

启动命令示例：

```
wscript file.js
```

这里借助了DotNetToJScript，其他内容同上

以上9种启动方式都可选择以下两个模板：

#### (1)GruntHTTP

使用HTTP协议同C2 server进行通信

执行后反弹连接至C2 server

可设置以下参数：

- ValidateCert
- UseCertPinning
- Delay
- JitterPercent
- ConnectAttempts
- KillDate
- DotNetFrameworkVersion

#### (2)GruntSMB

使用命名管道，不直接同C2 server进行通信，而是在各个Grunts之间进行通信

执行后在本机创建命名管道，可通过其他的Grunt进行远程连接

这里多了一个配置参数：

```
SMBPipeName
```

使用示例：

GruntSMB为内网使用，可通过其他的Grunt进行激活，激活方式：

`Grunt:<id>`->`Task`->`Connect`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-1/2-3.png)

### 3.Grunts

所有Grunts的列表，可向Grunt发送控制命令

#### (1)Info

包括Grunt的基本信息

#### (2)Interact

命令行的控制页面

#### (3)Task

Grunt支持的功能，内置了多个开源工具：

- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
- [SharpDump](https://github.com/GhostPack/SharpDump)
- [SharpSploit](https://github.com/cobbr/SharpSploit)
- [SharpUp](https://github.com/GhostPack/SharpUp)
- [SharpWMI](https://github.com/GhostPack/SharpWMI)

#### (4)Taskings

记录每条命令的执行情况

### 4.Templates

Grunt的模板文件，默认包含了GruntHTTP和GruntSMB

这里可以修改模板文件或者添加新的模板文件

### 5.Tasks

Task的模板文件，作为Grunt支持的功能，内置了多个开源工具：

- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
- [SharpDump](https://github.com/GhostPack/SharpDump)
- [SharpSploit](https://github.com/cobbr/SharpSploit)
- [SharpUp](https://github.com/GhostPack/SharpUp)
- [SharpWMI](https://github.com/GhostPack/SharpWMI)

这里可以修改模板文件或者添加新的模板文件

### 6.Taskings

记录所有Grunts的命令执行情况

### 7.Graph

图形化页面，展示Grunt和Listener的连接关系

### 8.Data

展示从Grunt获得的有价值信息

### 9.Users

管理登录用户，用作团队协作

## 0x04 Covenant的优点
---

### 1.C2 Server支持多平台

C2 Server不仅支持Linux，MacOS和Windows，还支持docker容器

### 2.扩展性高

可自定义通信协议，自定义启动方式，自定义功能等

### 3.扩展的功能可直接在内存执行

通过动态编译，C2 Server能够对代码进行动态编译后发送至目标并使用Assembly.Load()从内存进行加载

### 4.支持内网通信，统一流量出口

在内网各个被控制端之间通过命名管道进行通信，统一流量出口，隐藏通信通道

### 5.便于团队协作

支持多用户，能够共享资源

## 0x05 Covenant的检测
---

### 1.检测.NET程序集的运行

因为需要使用Rosyln C＃编译器，所以会引用Microsoft.CodeAnalysis程序集

这里可以尝试从指定进程中收集.NET事件，参考脚本：

https://gist.github.com/cobbr/1bab9e175ebbc6ff93cc5875c69ecc50

### 2.检测命名管道的使用

检测命令管道远程连接的流量

命令管道远程连接会产生Event ID 18的日志，参考地址：

https://github.com/hunters-forge/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-18.md

### 3.HTTP通信流量

默认的通信模板存在特征，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-1/3-1.png)

## 0x06 小结
---

本文介绍了Covenant的细节，分析特点，Covenant的可扩展性很高，能够很方便的做二次开发。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






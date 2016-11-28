---
layout: post
title: Study Notes of using dnx.exe / rcsi.exe to bypass Decvice Guard UMCI
---


## 0x00 前言
---

在Windows 10 Enterprise和Server 2016引入的新功能Decvice Guard是一种白名单机制，可用来阻止未授权的代码执行。

简单的理解，只要是不包含微软数字签名的程序，均无法用来执行代码。

然而，如果能够找到带有微软签名的程序，那么就能绕过Decvice Guard对应用程序的拦截，实现代码执行。

目前已知的方法有：

 **1、WinDbg/CDB**

可用来执行shell code

作者：Matt Graeber@mattifestation

地址：http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html

 **2、CSI.exe**

可用来执行c#代码

作者：Casey Smith@subTee

地址：https://twitter.com/subTee/status/796737674954608641

 **3、dnx.exe**

可用来执行c#代码

作者：Matt Nelson@enigma0x3

地址：https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/

 **4、rcsi.exe**

可用来执行c#代码

作者：Matt Nelson@enigma0x3

地址：https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/

## 0x01 简介
---

Matt Nelson@enigma0x3在最近分享了他绕过Decvice Guard的两种方法，这是继Matt Graeber@mattifestation和Casey Smith@subTee后的第三和第四种绕过方法，本文将重现这两个过程，完成他留给读者的两个作业，优化dnx.exe的环境搭建步骤，分享学习心得。

**链接如下：**

https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/

https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/

## 0x02 dnx.exe
---

dnx.exe内置于.NET Execution environment，包含数字签名，可用来执行c#代码

首先搭建dnx.exe的使用环境

**参考资料：**

https://blogs.msdn.microsoft.com/sujitdmello/2015/04/23/step-by-step-installation-instructions-for-getting-dnx-on-your-windows-machine/

资料显示需要powershell v4.0和安装Visual C++ 2013 redistributable package，实际测试"print helloworld"并不需要这些条件，同时配置步骤也可以简化，以下为简化的配置步骤：


测试系统：Win8 x86 


### 1、下载并安装Microsoft .NET Framework 4.5.2：

**下载地址：**

https://www.microsoft.com/zh-CN/download/confirmation.aspx?id=42643


### 2、安装DNVM

**cmd：**

```
powershell -NoProfile -ExecutionPolicy unrestricted -Command "&{$Branch='’'dev';iex ((new-object net.webclient).DownloadString('https://raw.githubusercontent.com/aspnet/Home/dev/dnvminstall.ps1'))}"
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/1-1.png)



### 3、安装DNX

`打开新的cmd`

**cmd：**

```
dnvm list 
```

输入y，安装dnx

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/1-2.png)



**cmd:**

```
dnvm install latest -Unstable -Persistent
```

**cmd:**

```
dnx
```

将会看到dnx的操作说明

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/1-3.png)




### 4、更新DNX和DNVM bits

**cmd:**

```
dnvm upgrade
dnvm update-self
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/1-4.png)



### 5、配置Package

`新建文件夹test`

**cmd：**

```
cd c:\test
dnu restore -s https://www.myget.org/F/aspnetvnext
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/1-5.png)


**注：**

在`C:\Windows\System32`直接输入`dnu restore -s https://www.myget.org/F/aspnetvnext`会报错，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/1-6.png)



### 6、添加脚本文件

新建文件Program.cs，内容如下：

```
using System;
public class Program
{
    public static void Main()
    {
        Console.WriteLine("Hello World");
    }
}
```


**注：**

class名必须为Program，否则报错


新建文件project.json，内容如下：

```
{
    "dependencies":{

    },
    "commands":{
        "test":"test"
    },
    "frameworks":{
        "dnx451":{},
        "dnxcore50":{
            "dependencies":{
                "System.Console":"4.0.0-beta-*"
            }
        }
    }
}
```

**注：**

project.json中"commands"内的"test"需要同文件夹名称test对应

**注：**

中文系统的浏览器复制https://blogs.msdn.microsoft.com/sujitdmello/2015/04/23/step-by-step-installation-instructions-for-getting-dnx-on-your-windows-machine/中的示例代码为unicode格式，直接使用会报错，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/1-7.png)

需要将其中的Unicode字符转化


### 7、测试脚本

**cmd:**

```
dnu restore 
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/1-8.png)


**cmd:**

```
dnx test
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/1-9.png)


**注:**

如果仅测试上述代码，只需完成步骤3即可


### 8、Win10 Device Guard测试

dnx.exe测试成功后，接下来需要找到dnx.exe在Win10上使用需要包含哪些支持文件，最直观的方法可借助于ProcessMonitor

使用ProcessMonitor获取dnx.exe在运行时的操作，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/2-1.png)

找到关键目录：

`C:\Users\a\.dnx\runtimes\dnx-clr-win-x86.1.0.0-rc1-update2\bin\`


经实际测试，在Win10上使用，只需要该目录下的部分文件，大小为`7.44MB`

**注：**

这是Matt Nelson@enigma0x3留给读者的作业


文件列表如下：

- dnx.clr.dll
- dnx.exe
- dnx.onecore.dll
- Microsoft.CodeAnalysis.CSharp.dll
- Microsoft.CodeAnalysis.dll
- Microsoft.Dnx.ApplicationHost.dll
- Microsoft.Dnx.Compilation.Abstractions.dll
- Microsoft.Dnx.Compilation.CSharp.Abstractions.dll
- Microsoft.Dnx.Compilation.CSharp.Common.dll
- Microsoft.Dnx.Compilation.CSharp.dll
- Microsoft.Dnx.Compilation.dll
- Microsoft.Dnx.Host.Clr.dll
- Microsoft.Dnx.Host.dll
- Microsoft.Dnx.Loader.dll
- Microsoft.Dnx.Runtime.dll
- Microsoft.Extensions.PlatformAbstractions.dll
- System.Collections.Immutable.dll
- System.Reflection.Metadata.dll
- vcruntime140.dll(也可忽略，但会报错，不影响代码执行)


该目录下的这些文件不需要：

- dnu.cmd
- dnx.win32.dll
- Microsoft.Dnx.Compilation.DesignTime.dll
- Microsoft.Dnx.DesignTimeHost.Abstractions.dll
- Microsoft.Dnx.dll
- Microsoft.Dnx.Host.Mono.dll
- Microsoft.Dnx.Runtime.Internals.dll


如图，由于dnx.exe包含微软的签名证书，所以在Device Guard UMCI(user mode code integrity)开启的环境中仍具有执行权限

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/2-2.png)


绕过成功

## 0x03 rcsi.exe
---

rcsi.exe内置于Microsoft "Roslyn" CTP中，包含微软数字签名

Microsoft "Roslyn" CTP下载地址：
https://www.microsoft.com/en-us/download/details.aspx?id=34685&tduid=(24d3dfde6075d394de05e49e871fa656)(256380)(2459594)(TnL5HPStwNw-qGm27mnsJb9VbqZPmTLajQ)()

安装前提：
- 安装Visual Studio 2012
- 安装VS2012 SDK 

### 1、实际测试
测试系统：Win8.1 x86
安装Visual Studio 2012、VS2012 SDK、Microsoft "Roslyn" CTP

### 2、执行代码
rcsi.exe的路径为：

`C:\Program Files\Microsoft Roslyn CTP\Binaries`

新建文件test.csx，内容如下：

```
using System;
Console.WriteLine("Hello World");
Console.ReadLine();
```

**cmd:**

```
"C:\Program Files\Microsoft Roslyn CTP\Binaries\rcsi.exe" test.csx
```

如图，成功执行C#代码

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/3-1.png)

rcsi.exe同csi.exe类似，可以用来执行c#代码，不同点在于csi.exe支持交互，而rcsi.exe不能

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/3-2.png)


### 3、Win10 Device Guard测试

rcsi.exe在Win10上运行同样需要支持文件
同样使用ProcessMonitor获取rcsi.exe在运行时的操作，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/3-3.png)




找到rcsi.exe需要的支持文件如下：

- C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Roslyn.Compilers.CSharp\v4.0_1.2.0.0__31bf3856ad364e35\Roslyn.Compilers.CSharp.dll
- C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Roslyn.Compilers\v4.0_1.2.0.0__31bf3856ad364e35\Roslyn.Compilers.dll


**注：**

这也是Matt Nelson@enigma0x3留给读者的作业



在Win10下测试成功，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-25/3-4.png)




## 0x04 防御
---

参照Matt Graeber的方法，更新Device Guard Bypass Mitigation Rules，可分别拦截利用WinDbg/CDB、csi.exe、dnx.exe和rcsi.exe的代码执行


参考地址如下：

http://www.exploit-monday.com/2016/09/using-device-guard-to-mitigate-against.html



## 0x05 小结
---

本文对dnx.exe和rcsi.exe的利用方法做了介绍，截至目前共有四种绕过Device Guard的方法，相信未来会有更多的方法被发现，与此同时，防御手段也需要随之升级。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



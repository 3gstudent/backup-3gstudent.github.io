---
layout: post
title: 渗透测试中的ClickOnce
---

## 0x00 前言
---

最近Casey Smith@subTee在《Mimikatz Delivery via ClickOnce with URL Parameters》中介绍了如何在ClickOnce程序中传入URL参数，实现执行mimikatz的技巧，并分享了一个POC

我对此很感兴趣，于是做了进一步的学习和研究

本文将会记录学习心得，介绍ClickOnce的使用方法，总结基于ClickOnce的攻击技巧和防御措施

**博客地址：**

http://subt0x10.blogspot.com/2016/12/mimikatz-delivery-via-clickonce-with.html

**POC地址：**

https://gist.github.com/subTee/bd446efeacf656c67f5c17ca0787f15b


## 0x01 简介
---

**ClickOnce：**

ClickOnce 是一种部署技术，使用该技术可创建自行更新的基于Windows的应用程序，这些应用程序可以通过最低程度的用户交互来安装和运行

使用用ClickOnce主要解决了程序部署中的几个问题：

- 更新应用程序的困难
使用 Microsoft Windows Installer 部署，每次应用程序更新时，用户都必须重新安装整个应用程序；使用 ClickOnce 部署，则可以自动提供更新。只有更改过的应用程序部分才会被下载，然后会从新的并行文件夹重新安装完整的、更新后的应用程序。

- 对用户的计算机的影响
使用 Windows Installer 部署时，应用程序通常依赖于共享组件，这便有可能发生版本冲突；而使用 ClickOnce 部署时，每个应用程序都是独立的，不会干扰其他应用程序。

- 安全权限
Windows Installer 部署要求管理员权限并且只允许受限制的用户安装；而 ClickOnce 部署允许非管理用户安装应用程序并仅授予应用程序所需要的那些代码访问安全权限


简单理解，ClickOnce部署的优点：

- 简化安装和更新应用程序的过程
- 可以自动更新
- 支持从Web更新
- 更安全，仅授予应用程序所必需的权限，通常为Intranet区域

详细介绍可参考如下链接：

https://msdn.microsoft.com/zh-cn/cn/library/142dbbz4(v=vs.90).aspx


ClickOnce安装成功后，会在开始菜单下保存该安装程序


接下来介绍如何开发ClickOnce程序并在网站上发布

## 0x02 使用ClickOnce的常规方法
---

### 1、配置Web服务器

测试系统：Windows Server 2008 R2

**1.安装Web服务器（IIS）**

在"服务器管理器"-"角色"-"添加角色"-选择"Web服务器（IIS）"进行安装
	
在"开始"-"管理工具"-"Internet信息服务（IIS）管理器"打开IIS，点击"浏览网站"，看是否正常显示
	
用http访问Windows Server 2008 Web服务器的IP地址，看是否正常显示
	
若以上测试通过，则说明IIS已安装成功且能正常使用

**2.添加虚拟目录**

设置别名：`publich`

设置物理路径：`c:\publish`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/2-1.png)
	

访问该虚拟目录:

`http://192.168.81.140/publish/`


报错：

```
HTTP 错误 403.14 - Forbidden
Web 服务器被配置为不列出此目录的内容。
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/2-2.png)


**3.启用目录浏览**

打开IIS管理器，切换到功能试图，找到目录浏览，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/2-3.png)

在目录浏览的操作界面下选择启用，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/2-4.png)

此时，文件能够正常访问，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/2-5.png)


### 2、开发ClickOnce程序

**1.新建标准c#工程**

添加测试代码：

`System.Diagnostics.Process.Start("calc.exe");`

**2.找到项目-属性-发布**

如下图，设置发布文件夹位置，选择立即发布

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/3-1.png)

C:\1下生成三个文件，分别为：
- setup.exe
- ConsoleApplication3.application
- Application Files

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/3-2.png)

安装成功后，在开始菜单自动生成快捷方式，文件夹名称为ClickOnce程序中发布者的名称

安装文件保存在`%USERPROFILE%\Local Settings\Apps\2.0`下

程序安装列表中也会存在，可在此处卸载ClickOnce

**3.在IIS服务器上发布**

将步骤2新生成的三个文件复制到`c:\pubish`下

**4.测试**

在另一台测试主机访问该Web目录，点击提示安全警告，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/3-3.png)

选择运行，接着提示安全警告，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/3-4.png)

选择运行，执行setup.exe，弹出计算器，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/3-5.png)

**注：**

在发布项下有多个选择可供选择，用来指定安装模式、应用程序文件、系统必备组件、更新选项等

## 0x03 基于ClickOnce的攻击技巧
---

基于ClickOnce的特性，最常见的利用方式为钓鱼攻击，所以接下来整理一下在钓鱼攻击中ClickOnce都有哪些利用方法

### 1、增加权限

在用户看来，更新程序的过程常常需要管理员的权限，所以在运行更新程序的过程中，如果程序弹框提示需要管理员权限，用户往往会选择同意，触发的payload随即获得了管理员权限

### 2、利用自动更新功能替换payload

ClickOnce支持自动更新功能，在运行时可检查新版本并自动更新

**注:**

ClickOnce安装成功后，会在开始菜单下保存该安装程序

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-1.png)

### 开启自动更新的步骤：

**1.指定更新网址**

设置"安装文件夹URL"，填入IIS服务器的下载地址就好，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-2.png)

**注：**

IIS服务器上不需要安装Visual Studio

**2.设定自动更新**

选择更新选项，启用"应用程序应该检查更新"，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-3.png)

**3.指定版本号**

如下图，选定"随每次发布自动递增修订号"

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-4.png)

**4.测试**

在IIS发布初始版本

测试主机下载安装

启用"应用程序应该检查更新"后，安装后的ClickOnce在每次运行时会访问服务器检查是否有更新，如果服务器有更新，会弹出更新对话框

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-5.png)

点击确定后，安装程序更新为新版本，成功实现替换payload


### 3、将url参数作为payload执行


测试之前，Visual Studio需要作如下设置：

**1.需要支持ClickOnce**

安装Visual Studio的过程需要选择该项

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-6.png)

否则在"using System.Deployment.Application;"时会报错，提示如下：

`命名空间“System.Deployment”中不存在类型或命名空间名“Application”(是否缺少程序集引用?)	`



**2.添加引用**

在项目工程中添加引用"System.Deployment"，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-7.png)

在项目工程中添加引用"System.Web"

否则报错，提示如下：

`当前上下文中不存在名称“HttpUtility”`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-8.png)


**3.设置"允许向应用程序传递URL参数"**

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-9.png)

否则，无法向ClickOnce传入参数


测试代码如下：

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Deployment.Application;
using System.Web;
using System.Collections.Specialized;
namespace ConsoleApplication3
{
    class Program
    {
        static void Main(string[] args)
        {
            try
               {
                   NameValueCollection nvc = GetQueryStringParameters();

                   foreach (string key in nvc)
                   {
                       Console.WriteLine(nvc[key]);
                       Console.ReadLine();
                   }
               }
               catch
               {
                   Console.WriteLine("No Params");
                   Console.ReadLine();
               }
           }
           public static NameValueCollection GetQueryStringParameters()
           {
               NameValueCollection col = new NameValueCollection();
               if (ApplicationDeployment.IsNetworkDeployed)
               {
                   string queryString = ApplicationDeployment.CurrentDeployment.ActivationUri.Query;
                   col = HttpUtility.ParseQueryString(queryString);
               }
               return col;
           }      
    }
}
```

**注：**

测试代码选自https://gist.github.com/subTee/bd446efeacf656c67f5c17ca0787f15b



将新的ClickOnce程序发布

**注：**

只需要将.application和Application Files上传至网站就好，不需要提供setup.exe


测试主机在IE浏览器访问如下URL：

`http://192.168.81.140/publish/ConsoleApplication3.application?N=TEST`

程序自动识别参数并解析输出，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/4-92.png)



### 4、结合网站的重定向功能，触发不同的payload

网站的重定向可导致URL的参数不同，这样就可以实现触发不同的payload

细节略

可参考https://blog.netspi.com/all-you-need-is-one-a-clickonce-love-story/



## 0x04 钓鱼攻击的缺陷:
---

不同系统.net版本不同，所以钓鱼利用场景受限

系统在执行ClickOnce程序的过程会检查数字签名验证发布者，否则会提示安装包不可信


## 0x05 防御
---

### 1、对ClickOnce程序提高警惕，识别真伪

运行特殊后缀名的程序(如.application)就会对ClickOnce程序进行安装，不需要setup.exe，用户需要对此提高警惕

### 2、禁用特殊后缀名,如.application

不同.net版本生成的ClickOnce程序后缀名存在差异，如下链接有更详细的关于ClickOnce程序后缀名的介绍：
https://robindotnet.wordpress.com/2010/06/12/mime-types-for-clickonce-deployment/


## 0x06 检测
---

### 1、安装ClickOnce程序后，会在注册表留下痕迹

注册表位置：

`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/5-1.png)

### 2、安装ClickOnce程序后，会在如下目录保存文件：

`%USERPROFILE%\Local Settings\Apps\2.0`

测试主机上的路径为：

`C:\Users\a\Local Settings\Apps\2.0`

每个ClickOnce程序都有一个特殊名字的文件夹，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-22/5-2.png)


**注：**

删除文件夹将从系统中删除ClickOnce应用程序


### 3、安装程序列表也会存在ClickOnce程序名称

## 0x07 小结
---

通过ClickOnce进行钓鱼，相比于常规的钓鱼方式，由于后缀名不常见，因此欺骗性更高，支持的扩展功能如解析URL参数、自动更新等功能，使得其利用方法更加灵活

但是，只要用户提高警惕，验证ClickOnce程序的数字证书，只运行受信任的程序，就可以防范此类钓鱼方式的攻击

未知攻焉知防，希望本文帮助大家更好的认识这个技术，保护自己的安全

---

参考学习资料：

http://subt0x10.blogspot.com/2016/12/mimikatz-delivery-via-clickonce-with.html

https://blog.netspi.com/all-you-need-is-one-a-clickonce-love-story/

http://www.sixdub.net/?p=555

https://msdn.microsoft.com/en-us/library/t71a733d.aspx

https://www.rsa.com/content/dam/pdfs/a-decade-of-phishing-wp-11-2016.pdf

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


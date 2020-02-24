---
layout: post
title: 通过Boolang语言执行shellcode的利用分析
---


## 0x00 前言
---

在之前的文章[《SILENTTRINITY利用分析》](https://3gstudent.github.io/3gstudent.github.io/SILENTTRINITY%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)学习了C#利用IronPython引擎从内存加载payload的方法，我在byt3bl33d3r的GitHub上又看到了利用Boolang语言执行shellcode的代码，于是对这项技术做了研究。

本文将要介绍Boolang语言的特点和用法，分析通过Boolang语言执行shellcode的优点，给出防御检测的建议。

## 0x01 简介
---

本文将要介绍以下内容：

- Boolang语言简介
- Boolang语言的用法
- 通过Boolang语言执行shellcode的实现代码
- 利用分析
- 防御检测

## 0x02 Boolang语言简介
---

学习资料：

https://github.com/boo-lang/boo

Boolang是面向对象的语言，结合了Python的语法，Ruby的功能以及C＃的速度和安全性

具有如下特点：

- 语法非常接近Python，使用友好
- 静态类型，相比动态类型的Python，更加安全
- 可以扩充编译器，能够在.NET Framework或Mono上运行
- 代码开源

## 0x03 Boolang语言的用法
---

首先需要下载编译后的Boolang文件，地址如下：

https://github.com/boo-lang/boo/releases

文件中包括以下三个可执行程序：

1. booi.exe，用作执行脚本
2. booish.exe，实时编译程序，便于测试代码
3. booc.exe，用作编译脚本

具体用法如下：

### 1.使用booi.exe执行Boolang脚本

test.boo的内容如下：

```
print "Hello, World!"
```

命令如下：

```
booi.exe test.boo
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-2-9/2-1.png)

### 2.使用booish.exe实时编译

启动booish.exe，在命令行输入如下代码：

```
print "Hello, World!"
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-2-9/2-2.png)

### 3.使用booc.exe编译Boolang脚本

test.boo的内容如下：

```
print "Hello, World!"
```

命令如下：

`enter code here`booc -output:test.exe test.boo

生成文件test.exe

### 4.使用booc.exe编译Boolang脚本(使用Boo.Lang.Compiler API)

test.boo的内容如下：

```
import Boo.Lang.Compiler
import Boo.Lang.Compiler.IO
import Boo.Lang.Compiler.Pipelines

compiler = BooCompiler()
compiler.Parameters.Input.Add(StringInput("<script>", "print('Hello!')"))
compiler.Parameters.Pipeline = Run()

compiler.Run()
```

命令如下：

```
booc -output:test.exe test.boo
```

生成文件test.exe

### 5.使用c#调用Boolang脚本

参考资料：

https://github.com/boo-lang/boo/wiki/Scripting-with-the-Boo.Lang.Compiler-API

script.boo的内容如下：

```
static def stringManip(item as string): //static lets us invoke this method without needing to instanize a class.
	return "'${item}'? What the hell are you talking about?"
```

runBoo.cs的内容如下：

```
using System;
using System.Text;
using System.Reflection;

using Boo.Lang.Compiler;
using Boo.Lang.Compiler.IO;
using Boo.Lang.Compiler.Pipelines;
namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            BooCompiler compiler = new BooCompiler();
            compiler.Parameters.Input.Add(new FileInput("script.boo"));
            compiler.Parameters.Pipeline = new CompileToMemory();
            compiler.Parameters.Ducky = true;

            CompilerContext context = compiler.Run();
            //Note that the following code might throw an error if the Boo script had bugs.
            //Poke context.Errors to make sure.
            if (context.GeneratedAssembly != null)
            {
                Type scriptModule = context.GeneratedAssembly.GetType("ScriptModule");
                MethodInfo stringManip = scriptModule.GetMethod("stringManip");
                string output = (string)stringManip.Invoke(null, new object[] { "Tag" } );
                Console.WriteLine(output);
            }
            else
            {
                foreach (CompilerError error in context.Errors)
                    Console.WriteLine(error);
            }
        }
    }
}
```

使用csc.exe编译runBoo.cs，命令如下：

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:Boo.Lang.dll,Boo.Lang.Compiler.dll,Boo.Lang.Parser.dll /t:exe runBoo.cs
```

生成文件runBoo.exe，调用script.boo的命令如下：

```
runBoo.exe script.boo
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-2-9/2-3.png)

**注：**

runBoo.exe的同级目录下需要存在以下三个dll：

- Boo.Lang.dll
- Boo.Lang.Compiler.dll
- Boo.Lang.Parser.dll

这种方法的优点是能将Boolang脚本编译到内存中并运行，对应到上面的示例，runBoo.exe在内存中对script.boo进行编译并运行

## 0x04 通过Boolang语言执行shellcode的实现代码
---

代码来自https://github.com/byt3bl33d3r/OffensiveDLR/

### 1.使用c#调用Boolang脚本

需要使用以下两个代码文件：

#### (1)runBoo.cs

代码地址：

https://github.com/byt3bl33d3r/OffensiveDLR/blob/master/runBoo.cs

同0x04-5中的runBoo.cs结构基本相同

在数组中分别保存了32位和64位的shellcode

命令行第1个参数作为传入的Boolang脚本文件

命令行第2个参数作为注入shellcode的方法

#### (2)shellcode.boo

代码地址：

https://github.com/byt3bl33d3r/OffensiveDLR/blob/master/shellcode.boo

Boolang脚本，支持以下三种注入方法：

- InjectQueueUserAPC，通过QueueUserAPC注入explorer.exe进程
- InjectSelf，通过CreateThread注入当前进程
- InjectRemote，通过CreateRemoteThread注入explorer.exe进程

具体用法如下：

#### (1)使用csc.exe编译runBoo.cs

命令如下：

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:Boo.Lang.Compiler.dll,Boo.Lang.dll,Boo.Lang.Parser.dll /t:exe runBoo.cs
```

生成文件runBoo.exe

#### (2)测试功能

可用命令如下：

1. runBoo.exe shellcode.boo InjectQueueUserAPC
2. runBoo.exe shellcode.boo InjectSelf
3. runBoo.exe shellcode.boo InjectRemote

**注：**

runBoo.exe的同级目录下需要存在以下三个dll：

- Boo.Lang.dll
- Boo.Lang.Compiler.dll
- Boo.Lang.Parser.dll

解决方法1：

使用ILMerge

参考资料：

https://github.com/boo-lang/boo/wiki/Merge-Boo.Lang.dll-into-your-exe-or-dll

### 2.使用Powershell调用Boolang脚本

需要使用以下两个代码文件：

#### (1)Invoke-JumpScare.ps1

代码地址：

https://github.com/byt3bl33d3r/OffensiveDLR/blob/master/Invoke-JumpScare.ps1

功能同runBoo.cs，但是通过反射加载所需的三个dll(Boo.Lang.dll,Boo.Lang.Compiler.dll,Boo.Lang.Parser.dll)，同级目录下不再需要这三个dll文件

不需要使用csc.exe进行编译，不会产生中间文件

**注：**

可以将Boolang脚本的内容保存在变量中，这样不需要额外的Boolang脚本，所有的功能只需要一个Powershell文件即可

#### (2)shellcode.boo

代码地址：

https://github.com/byt3bl33d3r/OffensiveDLR/blob/master/shellcode.boo

内容同上

实际测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-2-9/3-1.png)

## 0x05 利用分析
---

对于byt3bl33d3r开源的代码，相比于开源的Boolang代码，添加了以下功能：

- 支持Powershell调用，省去使用csc.exe编译的步骤，Boolang脚本是动态编译和即时执行的，使用反射加载所需的三个dll，不需要依赖三个dll
- 添加执行shellcode的功能

这种利用方法有如下优点：

使用Boolang语言执行shellcode，启动代码(Powershell脚本)不包括恶意的功能，payload可保存在另一个脚本文件中

简单理解：

通过Boolang语言开发了一个Powershell格式的脚本解释器，能在内存中动态加载另一脚本文件中的代码

## 0x06 防御检测
---

在之前的文章《渗透技巧——Use AutoIt script to create a keylogger》曾介绍过类似的方法，通过脚本解释器启动另一脚本文件中的代码，所以防御检测的方法类似

结合利用方法，我们在检测的时候通常会遇见以下情况：启动程序和payload分离，在静态检测上存在困难

但是这个技术无法绕过对程序行为的检测，所以可以通过检测进程行为的方式进行防御

## 0x07 小结
---

本文介绍了Boolang语言的特点和用法，结合byt3bl33d3r开源的代码，分析通过Boolang语言执行shellcode的优点，给出防御检测的建议


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)














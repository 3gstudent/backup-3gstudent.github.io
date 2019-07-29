---
layout: post
title: An interesting way of bypassing Windows Attachment Manager
---

## 0x00 前言
---

最近看到了一篇文章《Bypassing Windows Attachment Manager》，作者rvrsh3ll@424f424f，文中介绍了他绕过Windows Attachment Manager的思路，很有趣。
恰好我对文中涉及到的ADS和lnk文件利用有过研究，所以，本文将结合我的一些心得，对该绕过方法做拓展介绍，并分享一个我在实际测试过程中发现的有趣问题

相关文章地址如下：

《Bypassing Windows Attachment Manager》：

http://www.rvrsh3ll.net/blog/informational/bypassing-windows-attachment-manager/


我之前的一些研究心得：

[《渗透技巧——快捷方式文件的参数隐藏技巧》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%BF%AB%E6%8D%B7%E6%96%B9%E5%BC%8F%E6%96%87%E4%BB%B6%E7%9A%84%E5%8F%82%E6%95%B0%E9%9A%90%E8%97%8F%E6%8A%80%E5%B7%A7/)

[《Hidden Alternative Data Streams的进阶利用技巧》](https://3gstudent.github.io/3gstudent.github.io/Hidden%20Alternative%20Data%20Streams%E7%9A%84%E8%BF%9B%E9%98%B6%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/)

## 0x01 简介
---

本文将要介绍以下内容：

- Windows Attachment Manager作用
- Windows Attachment Manager实现方式
- Windows Attachment Manager的绕过思路
- 特殊文件的构造
- 实际测试过程中发现的有趣问题


## 0x02 Windows Attachment Manager
---

### 简介

- 自WinXp SP2开始，微软推出的新功能
- 用来防止文件从非信任的途径下载后可以直接执行
- 非信任的途径包括邮件和互联网下载

如果发现文件来自于非信任的途径，那么该文件在打开时会弹框提示用户，需要用户确认才能执行，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/2-1.png)

被标记为High-risk的文件格式如下：

.ade,.adp,.app,.asp,.bas,.bat,.cer,.chm,.cmd,.com,.cpl,.crt,.csh,.exe,.fxp,.hlp,.hta,.inf,.ins,.isp,.its,.js,.jse,.ksh,.lnk,.mad,.maf,.mag,.mam,.maq,.mar,.mas,.mat,.mau,.mav,.maw,.mda,.mdb,.mde,.mdt,.mdw,.mdz,.msc,.msi,.msp,.mst,.ops,.pcd,.pif,.prf,.prg,.pst,.reg,.scf,.scr,.sct,.shb,.shs,.tmp,.url,.vb,.vbe,.vbs,.vsmacros,.vss,.vst,.vsw,.ws,.wsc,.wsf,.wsh

详细资料可参考：

https://support.microsoft.com/en-us/help/883260/information-about-the-attachment-manager-in-microsoft-windows

### 实现方式

不可信的文件在下载时会被添加ADS:Zone.Identifier:$DATA

ADS详细内容如下：

```
[ZoneTransfer]
ZoneId=3
```

也就是说，只要包含`ADS:Zone.Identifier:$DATA`，那么该文件在打开时就会弹框提示用户，需要用户确认才能执行

### 绕过思路


**1、删除文件的ADS，那么在打开该文件的时候就不会弹框**

对于小文件，可以使用Windows默认命令more

对于大文件，可使用工具Streams

**注：**

细节可参考[《Hidden Alternative Data Streams的进阶利用技巧》](https://3gstudent.github.io/3gstudent.github.io/Hidden%20Alternative%20Data%20Streams%E7%9A%84%E8%BF%9B%E9%98%B6%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/)

也可通过界面操作，如下图，选择Unblock

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/2-2.png)

**2、改变传输途径**

如果将文件复制到另一操作系统，原文件的ADS不会保存

也就是说，将之前下载的非信任文件通过可信方式复制到另一操作系统，那么该文件在新系统是不会被标记为“不可信”的

例如：

从互联网下载的文件python-2.7.12.msi，默认被添加ADS:Zone.Identifier:$DATA，打开时会弹框

现在将该文件拖到虚拟机中(该操作被认为是可信方式，不会被添加ADS)，而且原ADS不会保存，所以在打开该文件的过程不会弹框


## 0x03 特殊文件的构造
---

既然不可信的文件在下载时会被添加ADS:Zone.Identifier:$DATA，那么如果是压缩后的文件呢？解压缩后是否还会包含ADS？

测试系统： Win10x64

HTTP服务器： Kali Linux

开启HTTP服务器功能：

`python -m SimpleHTTPServer 80`

**1、尝试.exe+.rar**

使用WinRAR将putty.exe压缩成putty.rar，上传至HTTP服务器

**注：**

Win10系统默认无法解压缩.rar文件，需要手动安装WinRAR

测试系统通过Chrome下载putty.rar，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/3-1.png)

使用WinRAR解压缩并打开文件，未弹框

**结论1：**

.rar内的压缩文件不会被添加ADS

**2、尝试.lnk+.rar**

压缩lnk文件时会直接对lnk指向的源文件压缩，无法压缩lnk文件本身，测试失败


**3、尝试.exe+zip**

使用WinRAR将putty.exe压缩成putty.zip，上传至HTTP服务器

测试系统通过Chrome下载putty.zip

通过Windows Explorer打开zip文件，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/3-2.png)

打开后弹框，提示用户，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/3-3.png)

而使用WinRAR解压缩并打开文件，并未弹框

**结论2：**

Windows Attachment Manager不支持WinRAR这类第三方软件

**4、尝试.exe+cab**

接下来没必要测试需要第三方软件才能使用的压缩格式，应该继续寻找Windows系统默认支持的格式

比如.cab文件

**注：**

cab文件可通过makecab.exe生成，系统默认包含

压缩类型包括：none，mszip，lzx


使用makecab将putty.exe压缩成putty.cab，压缩类型选择lzx，命令如下：

`makecab /d compressiontype=lzx putty.exe putty.cab`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/3-4.png)

上传至HTTP服务器

测试系统通过Chrome下载

解压缩，保存文件，打开，弹框

将文件拖至任一路径，打开，不弹框

完整测试过程如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/2.gif)

gif在线地址：

https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/2.gif

使用Procmon监控两种操作，区别如下图，此处需要继续研究，做更多的测试

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/5-1.png)

**注：**

Win10 Build 14393(1607)及之前版本均存在这个问题,Win10 Build 15063(1703)已经修复该问题

**结论3：**

使用cab压缩文件，接着拖动文件保存，能够绕过Windows Attachment Manager


**5、尝试.lnk+cab**

**注：**

该方法来自rvrsh3ll@424f424f的文章，但我在测试的时候发现了另外一个有趣的问题


使用makecab将test.lnk压缩成test.cab，压缩类型选择lzx，命令如下：

`makecab /d compressiontype=lzx test.lnk test.cab`

**注：**

cab文件能够压缩lnk文件本身，为了增加迷惑性，可以使用以下测试代码：

test.txt中写入如下内容：

`/c start calc.exe`

powershell代码：

```
$file = Get-Content "c:\test\test.txt"
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("c:\test\test.lnk")
$Shortcut.TargetPath = "%SystemRoot%\system32\cmd.exe"
$Shortcut.IconLocation = "%SystemRoot%\System32\Shell32.dll,3"
$Shortcut.Arguments = $file
$Shortcut.Save()
```

生成的lnk文件参数被空格字符填充，实际payload被隐藏，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/3-5.png)


更多细节可参考：

[《渗透技巧——快捷方式文件的参数隐藏技巧》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%BF%AB%E6%8D%B7%E6%96%B9%E5%BC%8F%E6%96%87%E4%BB%B6%E7%9A%84%E5%8F%82%E6%95%B0%E9%9A%90%E8%97%8F%E6%8A%80%E5%B7%A7/)


将test.cab上传至HTTP服务器

测试系统通过Chrome下载


解压缩，保存文件，打开，弹框（同测试4）

将文件拖至任一路径，打开，不弹框（同测试4）

**一个有趣的问题：**

将lnk文件解压缩，保存文件，打开，弹框

接着右键查看lnk文件属性，再次打开lnk文件，不弹框，ADS被清除

完整测试过程如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/1.gif)

gif在线地址：

https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/1.gif


**结论4：**

在某些特殊情况下(Win10 Build 14393(1607)之前的版本)，ADS会清除，导致能够绕过Windows Attachment Manager

**注：**

Win10 Build 10586存在该问题，Win10 Build 14393(1607)修复了该问题




## 0x04 补充
---

Win7系统不存在以上问题，原因：

打开cab文件后，在保存文件时会弹框提示用户(该特性Win10不存在)

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-10/4-1.png)



## 0x05 小结
---

- 不可信的文件在下载时会被添加ADS:Zone.Identifier:$DATA
- 如果将文件复制到另一操作系统，原文件的ADS不会保存
- 相比于rar和zip格式，使用cab格式压缩lnk文件更为合适
- lnk文件欺骗性更高
- Win10 Build 15063(1703)已经修复以上bug

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



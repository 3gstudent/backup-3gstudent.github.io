---
layout: post
title: Use xwizard.exe to load dll
---


## 0x00 前言
---

在之前的[文章](https://3gstudent.github.io/3gstudent.github.io/Use-Excel.Application-object's-RegisterXLL()-method-to-load-dll/)介绍了利用Excel.Application object's RegisterXLL()加载dll的技巧。本文继续，介绍最近学习到的一种更为通用的方法——利用xwizard.exe加载dll。
该方法最大的特点是xwizard.exe自带微软签名，在某种程度上说，能够绕过应用程序白名单的拦截。

参考链接：

http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/

## 0x01 简介
---

本文将要介绍以下内容：

- xwizard.exe简介
- 利用思路
- 实际测试

## 0x02 xwizard.exe简介
---

应该为Extensible wizard的缩写，中文翻译可扩展的向导主机进程，暂时无法获得官方资料

- 支持Win7及以上操作系统
- 位于%windir%\system32\下

双击运行，弹出操作说明，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-3/2-1.png)


支持参数如下：

- xwizard processXMLFile
- xwizard RunWizard
- xwizard RunPropertySheet

**示例：**

- xwizard processXMLFile 1.txt

- xwizard RunWizard /u {11111111-1111-1111-1111-111111111111}

- xwizard RunPropertySheet /u {11111111-1111-1111-1111-111111111111}

**注：**

参数中的GUID长度固定，否则弹框报错，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-3/2-2.png)

## 0x03 利用思路
---

本节对Adam@Hexacorn的思路进行验证，文章地址：

http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/

xwizard.exe的同级目录存在一个特别的文件xwizards.dll

使用IDA查看xwizards.dll的导出函数，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-3/3-1.png)

我们可以看到，xwizards.dll的导出函数名称同xwizard.exe支持的参数名称十分接近

猜测xwizard.exe的功能是通过调用xwizards.dll实现的

使用IDA逆向xwizard.exe来验证我们的判断，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-3/3-2.png)

对于函数LoadLibraryEx，由于未指定dll的绝对路径，使用相对路径，所以搜索顺序为：

1. 进程当前目录
2. 通过SetDllDirectory所设置的路径
3. Windows系统目录+PATH，即c:\windows\system32
4. 16位系统目录，即c:\windows\system
5. Windows目录，即c:\windows
6. PATH环境变量中所列目录

也就是说，如果将xwizard.exe复制到另一任意目录，在该同级目录再保存一个自己编写的xwizards.dll，那么执行xwizard.exe时会优先调用同级目录的xwizards.dll，不再加载%windir%\system32\下的xwizards.dll

这就实现了利用xwizard.exe加载我们自己编写的dll

## 0x04 实际测试
---

测试系统： Win7 x86

### 1、复制xwizard.exe至新目录C:\x

### 2、编写dll

使用vc 6.0，新建dll工程，在`case DLL_PROCESS_ATTACH`下添加弹框代码

过程及优化方法不再赘述，可参考文章[《Use Office to maintain persistence》](https://3gstudent.github.io/3gstudent.github.io/Use-Office-to-maintain-persistence/)

编译好的dll下载地址如下:

https://github.com/3gstudent/test/blob/master/msg.dll

该dll成功加载后会弹框

### 3、测试

直接执行xwizard.exe，没有弹出帮助对话框

使用Process Monitor监控系统，检查xwizard.exe是否正常执行

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-3/4-1.png)

xwizard.exe正常执行，但是没有尝试加载xwizards.dll

再次测试，通过命令行执行，参数如下：

`xwizard processXMLFile 1.txt`

查看Process Monitor输出结果

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-3/4-2.png)

xwizard.exe首先尝试加载`C:\x\xwizards.dll`,加载失败后再尝试加载`C:\windows\system32\xwizards.dll`（再次印证了对dll加载顺序的判断）

接下来，将msg.dll重命名为xwizards.dll，保存在`C:\x`

命令行执行：

`xwizard processXMLFile 1.txt`

成功加载C:\x\xwizards.dll，弹出对话框

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-3/4-3.png)

测试成功


## 0x05 补充
---

64位系统：

`%windir%\system32\`对应64位xwizard.exe，只能加载64位xwizards.dll

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-3/5-1.png)

`%windir%\SysWOW64\`对应32位xwizard.exe，只能加载32位xwizards.dll

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-3/5-2.png)

## 0x06 小结
---

本文介绍了利用xwizard.exe加载dll的技巧，特别的地方在于xwizard.exe包含微软签名，因此在某种程度上说，能够绕过应用程序白名单的拦截。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





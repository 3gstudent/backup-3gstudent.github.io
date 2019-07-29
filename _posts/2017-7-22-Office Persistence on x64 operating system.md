---
layout: post
title: Office Persistence on x64 operating system
---

## 0x00 前言
---

在之前的文章[《Use Office to maintain persistence》](https://3gstudent.github.io/3gstudent.github.io/Use-Office-to-maintain-persistence/)介绍了在Office
软件中植入后门的常用方法，但并不全面，缺少64位系统的测试。而对于64位操作系统，支持32位和64位两个版本的office软件，不同office版本的利用方法是否不同呢？本文将要给出答案。

## 0x01 简介
---

本文将要介绍如下内容：

- 64位系统安装64位Office软件的利用方法
- 64位系统安装32位Office软件的利用方法
- 根据测试结果优化POC

## 0x02 64位系统安装64位Office软件的利用方法
---

测试系统： Win8 x64

开发工具：vs2012

**注：**

32位系统下安装vs2012支持生成64位的dll

默认主要文件安装目录：`C:\Program Files\Microsoft Office`

### 1、Word WLL

32位dll，无法加载

64位dll，成功加载

### 2、Excel XLL

32位dll，无法加载

64位dll，成功加载

**注：**

添加导出函数xlAutoOpen的方法：

**1、使用传统的模块定义文件 (.def)**

新建dll工程，不选择导出符号

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-22/2-1.png)

添加同名文件.def，内容如下：

```
EXPORTS
xlAutoOpen
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-22/2-2.png)

编译成dll，使用IDA查看导出函数

显示正常

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-22/2-3.png)


**2、使用vs2012提供的便捷方法**

新建dll工程，选择导出符号

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-22/2-4.png)

设置导出函数为`xlAutoOpen`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-22/2-5.png)

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-22/2-6.png)

编译成dll，使用IDA查看导出函数

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-22/2-7.png)

导出函数名发生变化，改变为`?xlAutoOpen@@YAXXZ`

Excel无法加载该dll，原因是无法识别该导出函数（函数名发生变化）

**解决方法：**

使用预处理指示符`#pragma`指定链接选项，修正导出函数名称

添加一行代码：

`#pragma comment(linker, "/EXPORT:xlAutoOpen=?xlAutoOpen@@YAXXZ")`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-22/2-8.png)

再次使用IDA查看导出函数，显示正常

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-22/2-9.png)

Excel成功加载该dll，修改成功

**注：**

已将两种方法的vs工程上传至github，地址如下：

https://github.com/3gstudent/Add-Dll-Exports

方法1对应DllExport(Def)

方法2对应DllExport(declspec)

### 3、Excel VBA add-ins

使用32位的模板即可

### 4、PowerPoint VBA add-ins

使用32位的模板即可

**结论：**

如果在64位系统安装了64位的Office软件，那么Word WLL需要使用64位的calc.wll，Excel XLL需要使用64位的calc.xll

## 0x03 64位系统安装32位Office软件的利用方法
---

默认主要文件安装目录：`C:\Program Files (x86)\Microsoft Office`，存在重定向

**注：**

在目录`C:\Program Files\`也会创建Office目录，包含软件版本

也就是说，原POC中判断Microsoft Office版本的代码不需要更改


注册表位置`HKEY_CURRENT_USER\Software\Microsoft\Office\`

并未被重定向至`HKEY_CURRENT_USER\Software\Wow6432Node\Microsoft\Office\`


更多关于32位程序在64位系统下的重定向细节可参考之前的文章《关于32位程序在64位系统下运行中需要注意的重定向问题》


### 1、Word WLL

32位dll，成功加载

64位dll，无法加载

同64位office的结果相反

### 2、Excel XLL

32位dll，成功加载

64位dll，无法加载

同64位office的结果相反

### 3、Excel VBA add-ins

使用32位的模板即可

### 4、PowerPoint VBA add-ins

使用32位的模板即可

**结论：**

在64位系统安装32位Office软件，同32位系统测试结果相同，POC无需修改



## 0x04 优化POC
---

综合以上测试结论，为了使得POC支持64位系统，需要作如下修改：

判断操作系统位数，如果是64位，并且安装64位office软件，方法Word WLL和Excel XLL需要使用64位的dll


代码开发注意的细节(powershell代码)：

### 1、判断操作系统位数

```
if ([Environment]::Is64BitOperatingSystem)
{
    '64-bit'
}
else
{
    '32-bit'
}
```

### 2、判断安装office软件版本

通过查看默认主要安装路径：

32位office： `C:\Program Files (x86)\Microsoft Office`

64位office： `C:\Program Files\Microsoft Office`

判断路径`C:\Program Files\Microsoft Office`是否包含文件夹MEDIA

如果包含，那么为64位office

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

结合POC脚本，变量$OfficePath表示设置的office安装路径，默认路径为`"C:\Program Files\Microsoft Office\"+"Office*"`

为获取路径`C:\Program Files\Microsoft Office\MEDIA`，需要对变量$OfficePath进行字符串截取和拼接，具体代码为：

```
$OfficeMainPath=$OfficePath.Substring(0,$OfficePath.LastIndexOf("\")+1)+"MEDIA"
```

此时，变量$OfficeMainPath代表路径`C:\Program Files\Microsoft Office\MEDIA`

### 3、判断64位系统+64位office，释放对应的64位dll（wll和xll）

依旧是通过变量保存作base64编码后的64位wll和xll

将dll文件作base64编码：

```
$fileContent = [System.IO.File]::ReadAllBytes('calcx64.wll')
$fileContentEncoded = [System.Convert]::ToBase64String($fileContent)| set-content ("calc_x64wllbase64.txt") 

$fileContent = [System.IO.File]::ReadAllBytes('calcx64.xll')
$fileContentEncoded = [System.Convert]::ToBase64String($fileContent)| set-content ("calc_x64xllbase64.txt")
```

释放时先做base64解密

```
$fileContentBytes = [System.Convert]::FromBase64String($fileContent) 
```

最终POC已在github更新，该POC能够区分操作系统和office版本，当遇到64位系统安装64位office的情况时，自动释放64位的dll

POC地址如下：

https://github.com/3gstudent/Office-Persistence

## 0x05 小结
---

本文介绍了64位系统安装不同版本office所对应的不同利用方法，分享了在优化POC时注意的细节，至此完成对该POC的开发，便于测试。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







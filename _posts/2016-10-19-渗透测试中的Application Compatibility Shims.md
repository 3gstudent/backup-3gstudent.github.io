---
layout: post
title: 渗透测试中的Application Compatibility Shims
---


## 0x00 前言
---

Application Compatibility是一个框架，主要用来解决应用程序在新版Windows系统上的兼容性问题。然而在渗透测试中它却有着更多的用处，本文将对公开资料进行整理，介绍在渗透测试中的具体利用技术，帮助大家更好的认识它，防御它。


## 0x01 简介
---

### Shim：

相当于是在应用程序和Windows API之间的逻辑层。

当应用程序创建进程的时候，WindowsLoader首先会检查sysmain.sdb（位于%windir%\AppPatch\），如果存在已注册的sdb文件，IAT将被重定向到Shim，实现功能替换。

本文将介绍以下内容：

- 创建Shim文件
- 实际利用方法
- 相关开源工具
- 检测和防御

## 0x02 创建Shim文件
---

### 1.Microsoft Application Compatibility Toolkit(ACT)

**下载地址：**

https://www.microsoft.com/en-us/download/details.aspx?id=7352

默认修复方式种类个数为365

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/0-1.png)


启动时加入`/x`参数可获得更多修复方式，总数807

如图


![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/0-2.png)

根据提示创建后生成.sdb文件，需要安装使其生效

可在Microsoft Application Compatibility Toolkit中直接选择安装，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/1-1.png)





## 0x03 实际利用方法
---

### 1.Hiding in the Registry

选择`VirtualRegistry`

Command line填入：

```
ADDREDIRECT(HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run^HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunHidden)
```

安装shim

启动regedit

`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`下键值无法查看,如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/0-3.png)


但在cmd下执行如下命令可以查看：

```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/0-4.png)


### 2.Hiding in the File System

选择`CorrectFilePaths`

Command line填入：

```
c:\test\;c:\users
```

Module name 填入`*.exe`,点击add

安装shim

启动cmd.exe，无法查看c:\test下的文件

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/0-5.png)


**注：**

类似的还有`VirtualizeDeleteFile` 和`RedirectShortcut`

### 3.Persistence

可供选择的Fix有：

- InjectDll
- LoadLibraryRedirect
- RedirectShortcut
- RedirectEXE
- ShimViaEAT
- LoadLibraryfromCWD
- Hijacking DLL

### 4.Disable Security Features of the OS

可供选择的Fix有：

- Disable NX
- Disable ASLR
- DisableSEH
- Prevent the Loading of DLLs
- Disable Windows Resource Protection
- Elevate to Administrator
- DisableWindowsDefender
- DisableAdvancedRPCClientHardening


**注：**

以上思路参考自：

http://www.irongeek.com/i.php?page=videos/derbycon3/4206-windows-0wn3d-by-default-mark-baggett

http://sdb.tools/files/paper.pdf


## 0x04 安装和卸载Shim
---

### 1.sdbinst.exe

用来安装和卸载.sdb文件

微软官方提供，默认位于c:\windows\system32下，运行需要管理员权限

**usage:** 

```
 -? - print this help text.
 -p - Allow SDBs containing patches.
 -q - Quiet mode: prompts are auto-accepted.
 -u - Uninstall.
 -g {guid} - GUID of file (uninstall only).
 -n "name" - Internal name of file (uninstall only). 
```

**卸载：**

sdbinst.exe -u -n "name"

安装过程中sdbinst.exe做了如下操作：

在如下注册表位置创建键值保存Shim信息：

- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB

将sdb文件复制到如下文件路径：

- C:\Windows\AppPatch\Custom\
- C:\Windows\AppPatch\Custom\Custom64\ 

添加到已安装的应用程序列表中

依次打开控制面板-程序-程序和功能-卸载程序，可看到安装的Shim名称


### 2.sdb-explorer

**下载地址：**

https://github.com/evil-e/sdb-explorer

同样可用来安装.sdb文件，相比于sdbinst.exe多了如下特征：

- 源代码开源
- 支持In-Memory patch
- 安装过程不将sdb文件复制到C:\Windows\AppPatch\Custom\下
- 安装过程不在已安装的应用程序列表中显示安装的Shim名称


**usage:** 

```
Print full sdb tree
  sdb-explorer.exe -t filename.sdb 

Print patch details
  sdb-explorer.exe [-i] -p filename.sdb (patch | patchid | patchref | patchbin)
     -i - create IDAPython Script (optional)

Print patch details for checksum
  sdb-explorer.exe [-i] -s filename.sdb

Create file containing the leaked memory
  sdb-explorer.exe -l filename.sdb

Print Match Entries
  sdb-explorer.exe -d filename.sdb

Create Patch From file
  sdb-explorer.exe -C config.dat [-o filename.sdb]

Register sdb file
  sdb-explorer.exe -r filename.sdb [-a application.exe]

Display usage
  sdb-explorer.exe -h
```

演示如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/1-2.png)


执行以下命令注册sdb文件：

```
sdb-explorer.exe -r C:\Users\a\Desktop\test1.sdb -a putty.exe
```

**注：**

-a的参数指定程序的名称，不能填入程序的绝对路径

通过sdb-explorer.exe注册的sdb文件无法通过sdbinst.exe来删除，会显示sbd文件不存在，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/1-3.png)

卸载可通过删除注册表键值的方式实现

**注：**

通过sdb-explorer可以创建一个In-Memory patch的shim，接着编译成sdb文件，进而安装使用，关于In-Memory patch的学习心得将在以后分享

**In-Memory patch：**

- 可以替换或写入内存中的某个区域的任意字节
- 可用来绕过应用程序白名单


## 0x05 查看Shim信息
---

### 1.sdb2xml 

从.sdb文件提取出xml格式的数据，可用来分析sdb文件

**作者：**

Heath Stewart 

**下载地址：**

https://blogs.msdn.microsoft.com/heaths/2007/11/03/shim-database-to-xml/

**usage:** 

```
sdb2xml sdb [-out report] [-base64 | -extract] [-?]

  sdb          Path to the shim database to process.
  -base64      Base-64 encode data in the XML report.
  -extract     Extract binary data to current or report directory.
  -out report  Path to the XML file to generate; otherwise, output to console.
```

如图，使用sdb2xml查看test1.sdb文件中的数据

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/2-1.png)


### 2.Compatibility Database Dumper (CDD)

**作者：**

Alex Ionesceu

**usage:** 

```
cdd.exe [-s][-e][-l][-f][-p][-d kernel-mode database file][-a usermode database file]

 -s Show shims
 -e Show executables
 -l Show layers
 -f Show flags
 -p Show patches
 -d Use Blocked Driver Database from this path
 -a Use Application Compatibility Database from this path 
```

**参考地址：**

http://www.alex-ionescu.com/?p=40

但作者Alex Ionescu目前尚未将其开源

### 3.Shim Database Tool (sdb)

**作者：**

Jochen Kalmbach

**下载地址：**

http://blog.kalmbach-software.de/2010/02/22/the-shim-database/

**注：**

该工具源代码开源

**Usage:**  

```
sdb.exe [-noids] [-match] [PathToShimDatabse] [PathToFileName]

 -noids  Will prevent the output of the TagIds
 -match  Will match the provided file with the installed databases
         and displays the activated shims
         In this case 'PathToFileName' is required

NOTE: If no shim database path is provided,
      the default database will be used.
```

从.sdb文件提取出xml格式的数据，演示如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/2-2.png)


显示指定程序是否被添加Shim，如图，找到putty.exe已被添加了一个Shim，guid为`8F9DA6E2-5A7C-41E1-B89F8B72D63DEBA8`

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-19/2-3.png)



## 0x06 检测和防御
---

**禁用Shim的方法：**

- 英文系统：
打开gpedit.msc，选择Administrative Templates-Windows Components-Application Compatibility-Turn off Application Compatibility Engine

- 中文系统：
打开gpedit.msc，选择计算机配置-管理模板-Windows组件-应用程序兼容性-关闭应用程序兼容性引擎

但不建议关闭Shim，原因如下：

- 导致EMET无法使用
- 无法更新补丁

**检测和防御：**

- AutoRuns不会检测到Shim
- Shim的安装需要管理员权限，注意权限控制
- 监控特定注册表键值
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
- 注意系统中未签名的sdb文件
- 使用检测脚本，如https://github.com/securesean/Shim-Process-Scanner和https://github.com/securesean/Shim-Process-Scanner-Lite

## 0x07 小结
---

本文对Application Compatibility Shims在渗透测试中的相关技巧做了整理，希望对大家有所帮助。对于In-Memory patch，值得研究的还有很多，学习心得将在以后分享。

更多关于Shim的研究资料可访问：

http://sdb.tools/index.html

---
**本文参考链接：**

http://blacksunhackers.club/2016/08/post-exploitation-persistence-with-application-shims-intro/

https://www.blackhat.com/docs/asia-14/materials/Erickson/Asia-14-Erickson-Persist-It-Using-And-Abusing-Microsofts-Fix-It-Patches.pdf

http://www.irongeek.com/i.php?page=videos/derbycon3/4206-windows-0wn3d-by-default-mark-baggett

http://sdb.io/erickson-codeblue.pdf


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

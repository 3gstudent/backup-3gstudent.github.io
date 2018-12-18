---
layout: post
title: 渗透技巧——RecentFileCache.bcf和Amcache.hve单条记录的清除
---


## 0x00 前言
---

在上篇文章[《渗透技巧——Windows系统文件执行记录的获取与清除》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E7%B3%BB%E7%BB%9F%E6%96%87%E4%BB%B6%E6%89%A7%E8%A1%8C%E8%AE%B0%E5%BD%95%E7%9A%84%E8%8E%B7%E5%8F%96%E4%B8%8E%E6%B8%85%E9%99%A4/)对Windows主机(Win7及以上系统)常见文件执行记录的位置进行整理，尝试获取并清除单条记录，分析利用思路，总结防御方法。

本文作为后续，详细介绍RecentFileCache.bcf和Amcache.hve单条记录的清除方法

## 0x01 简介
---

- RecentFileCache.bcf格式分析
- 编写程序实现RecentFileCache.bcf的单条记录清除
- Amcache.hve格式分析
- 编写程序实现Amcache.hve的单条记录清除

## 0x02 RecentFileCache.bcf格式分析
---

### 简介

用来跟踪应用程序与不同可执行文件的兼容性问题，能够记录应用程序执行的历史记录

支持Win7(Win8及更高版本的系统不支持)，位置：

```
C:\Windows\AppCompat\Programs\RecentFileCache.bcf
```

### 格式分析

没有找到介绍RecentFileCache.bcf文件格式的资料，但好在格式的规律比较简单

前20字节为文件头部(header)

前16字节为固定格式，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-11-7/2-1.png)

接下来是每条记录的内容，固定格式如下：

- 前4字节表示Unicode记录的长度
- 记录的内容(Unicode格式)
- 结束标志，0x0000

**注：**

Unicode每个字符占用2个字节

下面使用c程序实现RecentFileCache.bcf文件的解析

定义结构体

```
typedef struct _BCF_HEADER {
	ULONG64 Flag1;
	ULONG64 Flag2;
	ULONG Unknown;
} BCFHEADER, *PBCFHEADER;
```


```
typedef struct _BCF_RECORD {
	ULONG Size;
} BCFRECORD, *PBCFRECORD;
```

**注：**

ULONG64为8字节，ULONG为4字节

逐个解析每条记录，通过固定变量Size确定记录长度，进而读取每条记录的内容

完整实现代码已开源，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/ListRecentFileCache.cpp

代码实现了读取RecentFileCache.bcf文件并显示所有记录


## 0x03 RecentFileCache.bcf文件的单条记录清除
---

最简单的方法是将待删除的记录用字符`0x00`覆盖，但是会打乱原有的文件格式

所以这里需要将待删除的记录内容删除，后续的记录补齐空位

在程序实现上，使用新的数组来存储修改后的内容

完整实现代码已开源，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/DeleteRecentFileCache.cpp

代码实现了修改指定的RecentFileCache.bcf文件，删除指定的记录，新文件保存为NewRecentFileCache.bcf

## 0x04 Amcache.hve格式分析
---

### 简介

Windows系统使用Amcache.hve替换RecentFileCache.bcf，能够记录创建时间、上次修改时间、SHA1和一些PE文件头信息

Win8及更高版本的系统使用Amcache.hve替代RecentFileCache.bcf

Win7安装KB2952664后，也会支持Amcache.hve，也就是说，此时RecentFileCache.bcf和Amcache.hve都包含文件执行记录

Amcache.hve采用注册表格式存储信息

注册表文件的格式可参考：

http://www.sentinelchicken.com/data/TheWindowsNTRegistryFileFormat.pdf

附录部分包括详细的文件格式介绍，可为程序实现提供参考

为了提高开发效率，对记录的解析我们可以借助Windows系统下的regedit.exe

通过regedit.exe加载Amcache.hve，即可查看和修改Amcache.hve的信息，方法如下：

选择`HKEY_LOCAL_MACHINE`，选择`File` -> `Load Hive...`，指定名称，即可加载Amcache.hve

查看注册表后发现，文件执行记录以明文保存

修改regedit.exe中Amcache.hve的注册表信息，需要使用System权限，修改后再选择Export，即可实现对Amcache.hve的保存


查看Amcache.hve文件记录的开源powershell脚本，地址如下：

https://github.com/yoda66/GetAmCache/blob/master/Get-Amcache.ps1

脚本流程如下：

- 通过reg load加载Amcache.hve
- 枚举注册表，显示记录信息
- 通过reg unload卸载Amcache.hve


## 0x05 Amcache.hve文件的单条记录清除
---

### 删除思路

删除指定记录的信息，需要删除该记录对应的注册表父项

### 删除方法


#### 1、通过regedit.exe的界面操作

以System权限打开regedit.exe，加载Amcache.hve，编辑注册表，最后选择Export导出新的Amcache.hve

#### 2、脚本实现

流程如下：

- 以system权限通过reg load加载Amcache.hve
- 枚举注册表，匹配待删除的记录
- 获得记录的注册表父项，删除整个注册表键值
- 导出注册表，保存Amcache.hve
- 通过reg unload卸载Amcache.hve

脚本实现的细节：

判断当前权限是不是system：

```
$output = &"whoami"
if($output -notmatch "nt authority\\system")
{
	Write-Error "Script must be run as nt authority\system" -ErrorAction Stop
}
```

加载注册表：

```
reg load HKLM\amcache c:\Windows\AppCompat\Programs\Amcache.hve
```

导出注册表：

```
reg.exe save HKLM\amcache "new.hve" /y
```

卸载注册表：

```
reg.exe unload HKLM\amcache
```

完整实现代码已开源，地址如下：

https://github.com/3gstudent/Homework-of-Powershell/blob/master/Delete-Amcache.ps1

代码实现了删除指定名称的记录，并且能够自动删除多条重复的记录，最终生成新文件new.hve



## 0x06 小结
---

本文介绍了RecentFileCache.bcf和Amcache.hve单条记录的清除方法和程序实现细节。

站在取证的角度，对于RecentFileCache.bcf和Amcache.hve的记录，不能盲目相信


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)













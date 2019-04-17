---
layout: post
title: 渗透技巧——Windows下NTFS文件的时间属性
---


## 0x00 前言
---

在渗透测试中，如果需要在目标系统上释放文件，将会改变父目录的时间属性(AccessTime,LastWriteTime,MFTChangeTime)，如果需要覆盖目标系统上原有的文件，也会改变原有文件的时间属性(CreateTime,AccessTime,LastWriteTime,MFTChangeTime)

站在渗透的角度，需要找到修改文件时间属性的方法，用来消除痕迹

站在取证的角度，通过文件属性的异常能够找到攻击者的入侵痕迹

本文将会介绍修改文件属性的方法和细节，分享实现代码，结合利用思路给出在取证上的建议

## 0x01 简介
---

本文将要介绍以下内容：

- 基本概念
- 读取文件属性的方法
- 修改文件属性的方法
- 分享代码
- 利用思路
- 取证建议

## 0x02 基本概念
---

### 1、NTFS文件系统中的时间属性

包括以下四个：

- CreateTime(Created)
- AccessTime(Accessed)
- LastWriteTime(Modified)
- MFTChangeTime

前三个可通过`右键`->`Properties`获得，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-12-18/5-1.png)

无法直接查看MFTChangeTime

MFTChangeTime记录MFT(Master File Table)的修改时间，如果文件属性变化，就会更新MFTChangeTime

### 2、读取MFTChangeTime的方法

#### (1)通过NtQueryInformationFile读取

**注：**

通过WinAPI GetFileTime无法获得

#### (2)解析NTFS文件格式

Master File Table中的`$STANDARD_INFORMATION`(偏移0x10)和`$FILE_NAME`(偏移0x30)包含完整的文件属性

### 3、Win7系统默认CreateTime和AccessTime保持一致

Win7系统(以及更高版本)默认设置下，禁用了AccessTime的更新

也就是说，只读取文件的操作不会改变文件属性AccessTime，AccessTime同CreateTime保持一致，这是为了减少硬盘的读写

对应注册表位置`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`，键值`NtfsDisableLastAccessUpdate`

数值`1`代表禁用，为默认配置，数值`0`代表开启，修改注册表后重启系统才能生效

### 4、文件属性的变化规律

读取文件：

不会改变文件属性

覆盖文件：

改变4个属性

### 5、文件夹属性的变化规律

新建文件/删除文件/重命名文件：

改变父文件夹的AccessTime，LastWriteTime和MFTChangeTime

读取文件：

不会改变文件属性

覆盖文件：

不会改变文件属性

**注：**

可借助SetMace进行测试，下载地址：

https://github.com/jschicht/SetMace

## 0x03 读取和修改文件属性的方法
---

### 1、使用WinAPI GetFileTime和SetFileTime

能够操作三个文件属性：

- CreateTime(Created)
- AccessTime(Accessed)
- LastWriteTime(Modified)

无法对MFTChangeTime进行操作

#### (1)GetFileTime的使用

通过`GetFileTime()`获得FileTime

通过`FileTimeToSystemTime()`将FileTime转换为SystemTime，即UTC，同一标准

通过`SystemTimeToTzSpecificLocalTime()`将SystemTime转换为LocalTime，即UTC加上时区，考虑时区的影响，同当前系统显示的时间保持一致

#### (2)SetFileTime的使用

通过`sscanf()`将输入的时间数据转换为SystemTime

通过`SystemTimeToFileTime()`将SystemTime转换为FileTime

通过`LocalFileTimeToFileTime()`将FileTime转换为对应UTC的FILETIME，即FILETIME加上时区，考虑时区的影响，同当前系统显示的时间保持一致

实现代码已开源，下载地址：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/FileTimeControl_WinAPI.cpp

代码实现了以下功能：

- 查看文件/文件夹的时间(CreateTime,AccessTime,LastWriteTime)
- 修改文件/文件夹的时间
- 将文件A的时间复制到文件B

### 2、使用NtQueryInformationFile和NtSetInformationFile

能够操作四个文件属性：

- CreateTime(Created)
- AccessTime(Accessed)
- LastWriteTime(Modified)
- MFTChangeTime

我在实现上直接引用了Metasploit中timestomp的代码，地址如下：

https://github.com/rapid7/meterpreter/blob/master/source/extensions/priv/server/timestomp.c

添加了部分功能，下载地址：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/FileTimeControl_NTAPI.cpp

代码实现了以下功能：

- 查看文件的时间(CreateTime,AccessTime,LastWriteTime，MFTChangeTime)
- 修改文件的时间
- 将文件A的时间复制到文件B
- 将时间设置为最小值(1601-01-01 00:00:00)

**注：**

暂时不支持对文件夹的操作

### 3、使用驱动文件

#### (1) SetMace

可供参考的下载地址：

https://github.com/jschicht/SetMace

SetMace能够正常读取文件和文件夹的时间信息(包括MFTChangeTime)

但无法修改时间信息，这是因为自nt6.x开始，Windows禁止加载未经签名的驱动文件，如果能够绕过驱动保护，就能修改时间信息

#### (2) WinHex

付费版的WinHex支持对硬盘文件的写入操作，可以用来修改时间信息

### 补充、文件资源克隆

通过powershell实现自动化调用Resource Hacker，对可执行文件(exe，dll，scr等)的资源信息进行克隆

下载地址：

https://github.com/threatexpress/metatwin

**注：**

这个工具不会修改文件属性

## 0x04 利用思路
---

### 1、在目标系统上释放文件

将会改变父目录的时间属性(AccessTime,LastWriteTime,MFTChangeTime)

可以使用[SetMace](https://github.com/jschicht/SetMace)查看属性的变化

修改文件夹的时间属性可使用0x03中的[FileTimeControl_WinAPI](https://github.com/3gstudent/Homework-of-C-Language/blob/master/FileTimeControl_WinAPI.cpp)，能够修改以下三项内容：

- CreateTime(Created)
- AccessTime(Accessed)
- LastWriteTime(Modified)

想要进一步清除操作痕迹，需要借助WinHex修改Master File Table中的`$STANDARD_INFORMATION`(偏移0x10)和`$FILE_NAME`(偏移0x30)

### 2、覆盖目标系统上原有的文件

将会改变原有文件的时间属性(CreateTime,AccessTime,LastWriteTime,MFTChangeTime)

可以使用FileTimeControl_NTAPI读取和修改时间属性

想要进一步清除操作痕迹，需要借助WinHex修改Master File Table中的`$STANDARD_INFORMATION`(偏移0x10)和`$FILE_NAME`(偏移0x30)

## 0x05 取证建议
---

1、查看文件/文件夹的时间属性MFTChangeTime，位于两个位置：

- Master File Table中的`$STANDARD_INFORMATION`(偏移0x10)
- Master File Table中的`$FILE_NAME`(偏移0x30)

如果MFTChangeTime存在异常(时间晚于其他三个)，一般情况下可认为该文件被非法修改

可使用工具[SetMace](https://github.com/jschicht/SetMace)

## 0x06 小结
---

本文介绍了修改文件属性的方法和细节，分享两个实现代码([FileTimeControl_WinAPI](https://github.com/3gstudent/Homework-of-C-Language/blob/master/FileTimeControl_WinAPI.cpp)和[FileTimeControl_NTAPI](https://github.com/3gstudent/Homework-of-C-Language/blob/master/FileTimeControl_NTAPI.cpp))，结合利用思路给出在取证上的建议

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



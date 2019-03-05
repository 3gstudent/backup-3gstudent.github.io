---
layout: post
title: 渗透技巧——Windows下NTFS文件的USN Journal
---


## 0x00 前言
---

在上篇文章《渗透技巧——Windows下NTFS文件的时间属性》介绍了修改NTFS文件时间属性的方法和细节，以及取证上的建议。
本文将要继续研究NTFS文件另一处记录文件修改时间的位置——USN Journal，同样是分析利用思路，给出取证上的建议。

## 0x01 简介
---

本文将要介绍以下内容：

- 基本概念
- 读取USN Journal的方法
- 利用思路
- 取证建议

## 0x02 USN Journal的基本概念
---

官方文档：

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb742450(v=technet.10)

USN Journal (Update Sequence Number Journal)，也称作Change Journal，用来记录NTFS volume中文件修改的信息，能够提高搜索文件的效率

每个NTFS volume对应一个USN Journal，存储在`NTFS metafile`的`$Extend\$UsnJrnl`中，也就是说，不同的NTFS volume对应的USN Journal不同

USN Journal会记录文件和目录的创建、删除、修改、重命名和加解密操作，每条记录的格式如下：

```
typedef struct {
  DWORD         RecordLength;
  WORD          MajorVersion;
  WORD          MinorVersion;
  DWORDLONG     FileReferenceNumber;
  DWORDLONG     ParentFileReferenceNumber;
  USN           Usn;
  LARGE_INTEGER TimeStamp;
  DWORD         Reason;
  DWORD         SourceInfo;
  DWORD         SecurityId;
  DWORD         FileAttributes;
  WORD          FileNameLength;
  WORD          FileNameOffset;
  WCHAR         FileName[1];
} USN_RECORD_V2, *PUSN_RECORD_V2;
```

官方资料：

https://docs.microsoft.com/en-us/windows/desktop/api/winioctl/ns-winioctl-usn_record_v2

在`NTFS metafile`的`$Extend\$UsnJrnl\$Max`保存USN Journal文件的总大小，如果USN Journal的记录长度超出总大小，会从最初始的记录开始覆盖


## 0x03 读取USN Journal的方法
---

### 1、使用命令fsutil usn

官方文档：

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc788042(v%3dws.10)

#### (1)查看C盘的USN Journal信息

```
fsutil usn queryjournal c:
```

包括以下信息：

- Usn Journal ID
- First Usn
- Next Usn
- Lowest Valid Usn
- Max Usn
- Maximum Size
- Allocation Delta

#### (2)查看C盘所有的USN Journal

```
fsutil usn enumdata 1 0 1 c:
```

包括以下信息：

- File Ref#
- ParentFile Ref#
- Usn
- SecurityId
- Reason
- Name

输出结果不够详细

### 2、使用开源工具

#### (1)导出USN Journal

下载地址：

https://github.com/jschicht/ExtractUsnJrnl

参数如下：

```
ExtractUsnJrnl /DevicePath:c: /OutputPath:c:\test /OutputName:UsnJrnl_vol1.bin
```

#### (2)将USN Journal转为CSV格式输出

下载地址：

https://github.com/jschicht/UsnJrnl2Csv

参数如下：

```
UsnJrnl2Csv /UsnJrnlFile:c:\test\UsnJrnl_vol1.bin /OutputPath:c:\test
```

包括以下信息：

- Offset
- FileName
- USN
- Timestamp
- Reason
- MFTReference
- MFTReferenceSeqNo
- MFTParentReference
- MFTParentReferenceSeqNo
- FileAttributes
- MajorVersion
- MinorVersion
- SourceInfo
- SecurityId

输出结果很完整

### 3、c++实现

我这里写了一个简单的示例代码，下载地址：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnumUsnJournal.cpp

代码实现了枚举C盘的USN Journal，仅输出文件名

## 0x04 利用思路
---

### 1、清除所有USN Journal

#### (1)使用fsutil

```
fsutil usn deletejournal /d c:
```

**注：**

我在测试环境下没有删除成功


#### (2)API

https://docs.microsoft.com/en-us/windows/desktop/api/winioctl/ns-winioctl-delete_usn_journal_data

**注：**

我在测试环境下没有删除成功

### 2、清除单条USN Journal

我还没有找到可用的API接口

唯一的方法是直接修改NTFS文件，但是自nt6.x开始，Windows禁止加载未经签名的驱动文件

这里可以尝试使用付费版的WinHex对NTFS文件进行操作，修改`$Extend\$UsnJrnl`中的内容

也可以尝试绕过驱动保护

$UsnJrnl的内容可参考：

http://forensicinsight.org/wp-content/uploads/2013/07/F-INSIGHT-Advanced-UsnJrnl-Forensics-English.pdf

按照格式读取USN Journal，删除指定USN Journal，再写入磁盘

### 3、暴力覆盖

首先查看磁盘USN Journal文件的总长度

然后通过创建、删除、修改、重命名等操作生成USN Journal的记录，当超过总长度后会覆盖最初始的记录，直至覆盖所有的USN Journal

## 0x05 取证建议
---

#### 1、读取USN Journal，列出所有记录，查找是否存在可疑记录

该方法并非完全可信，攻击者只要能够绕过驱动保护，就能修改USN Journal


#### 2、尝试其他方法

比如从内存中读取$MFT records

https://github.com/jschicht/HexDump

https://github.com/jschicht/MftCarver

Joakim Schicht的github有很多取证的工具值得参考:

https://github.com/jschicht/

## 0x06 小结
---

本文介绍了NTFS文件的USN Journal的利用思路，给出取证上的建议。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


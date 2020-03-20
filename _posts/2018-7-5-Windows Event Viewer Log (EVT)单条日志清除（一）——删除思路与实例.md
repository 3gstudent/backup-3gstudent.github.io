---
layout: post
title: Windows Event Viewer Log (EVT)单条日志清除（一）——删除思路与实例
---



## 0x00 前言
---

Windows Event Viewer Log (EVT)单条日志清除系列文章的第一篇，侧重于介绍evt日志文件的基础知识和删除单条日志的实现思路与实例

Windows Event Viewer Log (EVT)适用于以下Windows系统:

- Windows NT 4
- Windows 2000
- Windows XP
- Windows 2003

**注：**

之前介绍了Windows XML Event Log (EVTX)适用于Win7及更高版本的系统

## 0x01 简介
---

本文将要介绍以下内容：

- evt文件格式
- 删除单条日志的思路
- 删除单条日志的实例

## 0x02 基础知识
---

evt文件格式指Windows Vista之前用于保存系统日志信息的文件，最常见的为XP和Server2003系统

日志文件默认保存位置： `%systemroot%\system32\config`

常见日志文件：

- 应用程序日志：AppEvent.Evt
- 安全日志：SecEvent.Evt
- 系统日志：SysEvent.Evt

### 查看日志的方法

#### (1) 通过界面

`cmd` -> `eventvwr`

#### (2) 通过命令行

查询系统日志并输出详细信息：

```
cscript c:\windows\system32\eventquery.vbs /l system /v
```

查询指定时间(2017.12.05,01:00:00AM至2018.01.02,10:00:00AM)之间的系统日志：

```
cscript c:\windows\system32\eventquery.vbs /l system /fi "Datetime eq 12/05/2017,01:00:00AM-01/02/2018,10:00:00AM"
```


官方参数说明：

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb490900(v=technet.10)

### evt文件格式

参考资料：

https://github.com/libyal/libevt/blob/master/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc

evt文件结构包含三部分：

- file header
- event records
- end of file record
- trailing empty values

**注：**

file header保存evtx文件基本信息，值得注意的是`End of file record offset`，`Last (newest) record number`和`Maximum file size`

event records对应每条日志的内容，值得注意的是`Record number`

end of file record固定结构，值得注意的是`End of file record offset`和`Last (newest) record number`

trailing empty values为尾随空值，用于填充文件长度，内容任意，不会影响evtx文件的有效性

#### (1) file header

格式可参考：

https://github.com/libyal/libevt/blob/master/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc#2-file-header

前48位，没有校验和标志位

以下五项需要配置正确：

- First (oldest) record offset
- End of file record offset
- Last (newest) record number
- First (oldest) record number
- Maximum file size

#### (2) event records

格式可参考：

https://github.com/libyal/libevt/blob/master/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc#3-event-record

修改Record number(即使重复)不影响日志文件的正常识别

#### (3) end of file record

格式可参考：

https://github.com/libyal/libevt/blob/master/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc#4-end-of-file-record

同file header，以下四项需要配置正确：

- First (oldest) record offset
- End of file record offset
- Last (newest) record number
- First (oldest) record number


## 0x03 删除思路
---

由于evt文件不存在校验值，所以我们在删除单条日志时可以使用以下流程：

- 直接删除某条日志的内容
- 后面日志更新Record number(减1)
- 更新file header中的五项
- 同步更新end of file record中的四项

## 0x04 删除实例
---

查看日志：

`cmd` -> `eventvwr`

获得system项下共有9条日志，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-7-5/2-1.png)

选中`System`，右键，选择`Save Log File As...`，将日志文件保存为sys1.evt


**注：**

复制`%systemroot%\system32\config`下的文件SysEvent.Evt，得到的日志文件无法正常打开

原因：

`%systemroot%\system32\config`下evt文件的file header未同步更新，导致打开evt文件时格式出现错误

修复file header后，文件能够正常打开

sys1.evt已上传，下载地址：

`https://github.com/3gstudent/Eventlogedit-evt--General/blob/master/sys1.evt`

在eventvwr中打开该日志，Log Type选择`System`,成功打开

文件包含9条日志，下面尝试删除第5条日志，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-7-5/2-2.png)

### 1、定位第5条日志

搜索`4c664c6505000000`

`4c664c65`为ELF_LOG_SIGNATURE，固定结构

`05000000`为Record number

### 2、删除第5条日志

起始位置为`4c664c6505000000`的之前的4字节

删除长度为`4c664c6505000000`的之前的4字节

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-7-5/3-1.png)

起始位置为`0x320h`

删除长度为`0x00000070h`(即`112`)

**补充：**

通过UltraEdit实现的操作：

选中起始位置为`0x320h`，右键，选择`十六进制插入/删除`

选择`删除`，填入删除字节数`112`

### 3、后面日志更新Record number(减1)

即第6、7、8和9条日志的Record number

### 4、更新file header中的三项

#### (1) End of file record offset

位于File header偏移20的4字节

保存的内容为end of file record的起始地址

两种计算方法：

1. 原偏移地址-第5条日志的长度(112)
2. 定位end of file record，直接获得

新的End of file record offset为`0x00000640h`

#### (2) Last (newest) record number

位于File header偏移24的4字节

数值减1，由`0x0000000A`变为`0x00000009`


#### (3) Maximum file size

位于File header偏移32的4字节

新的Maximum file size为`0x00000668h`

### 5、同步更新end of file record中的两项

- End of file record offset
- Last (newest) record number

修改后保存为新文件sys2.evt

下载地址：

`https://github.com/3gstudent/Eventlogedit-evt--General/blob/master/sys2.evt`

成功删除第5条日志

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-7-5/3-2.png)


## 0x05 小结
---

本文介绍了evt日志文件的基础知识和删除单条日志的实现思路，实例演示如何修改evt文件，隐藏其中一条日志

下一篇将要按照之前的研究思路，介绍如何编写程序实现自动删除指定日期的日志


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





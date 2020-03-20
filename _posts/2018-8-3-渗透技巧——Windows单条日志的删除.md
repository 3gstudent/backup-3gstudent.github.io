---
layout: post
title: 渗透技巧——Windows单条日志的删除
---



## 0x00 前言
---

在之前的文章[《渗透技巧——Windows日志的删除与绕过》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E6%97%A5%E5%BF%97%E7%9A%84%E5%88%A0%E9%99%A4%E4%B8%8E%E7%BB%95%E8%BF%87/)介绍了常见的Windows日志清除与绕过方法，但未提到单条日志的清除。

这一次将要结合刚刚完成的Windows XML Event Log (EVTX)单条日志清除系列文章，介绍在渗透测试中Windows XML Event Log (EVTX)单条日志清除的具体使用方法，同时结合利用思路给出防御建议

Windows XML Event Log (EVTX)单条日志清除系列文章地址：

- 
 [Windows XML Event Log (EVTX)单条日志清除（一）——删除思路与实例](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%80-%E5%88%A0%E9%99%A4%E6%80%9D%E8%B7%AF%E4%B8%8E%E5%AE%9E%E4%BE%8B/)

- 
 [Windows XML Event Log (EVTX)单条日志清除（二）——程序实现删除evtx文件的单条日志记录](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%8C-%E7%A8%8B%E5%BA%8F%E5%AE%9E%E7%8E%B0%E5%88%A0%E9%99%A4evtx%E6%96%87%E4%BB%B6%E7%9A%84%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

- 
 [Windows XML Event Log (EVTX)单条日志清除（三）——通过解除文件占用删除当前系统单条日志记录](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%89-%E9%80%9A%E8%BF%87%E8%A7%A3%E9%99%A4%E6%96%87%E4%BB%B6%E5%8D%A0%E7%94%A8%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

- 
 [Windows XML Event Log (EVTX)单条日志清除（四）——通过注入获取日志文件句柄删除当前系统单条日志记录](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E5%9B%9B-%E9%80%9A%E8%BF%87%E6%B3%A8%E5%85%A5%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

- 
 [Windows XML Event Log (EVTX)单条日志清除（五）——通过DuplicateHandle获取日志文件句柄删除当前系统单条日志记录](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%94-%E9%80%9A%E8%BF%87DuplicateHandle%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)


## 0x01 简介
---

本文将要介绍以下内容：

- 通过命令行获得日志信息
- 通过命令行导出日志文件
- 将修改后的日志文件覆盖系统原文件
- 细节和注意点
- 防御建议


## 0x02 通过命令行获得日志信息
---

### 1、获得Security的最近十条日志

```
wevtutil.exe qe Security /f:text /rd:true /c:10
```

### 2、获得Security的前十条Security日志：

```
wevtutil.exe qe Security /f:text /c:10
```

**注：**

text视图不会输出`EventRecordID`

可以通过查看xml格式获得日志对应的EventRecordID

```
wevtutil.exe qe Security /f:xml /rd:true /c:10
```

**注：**

默认视图为xml，所以命令可以简写为：

```
wevtutil.exe qe Security /rd:true /c:10
```

可参考的官方说明文档：

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732848(v=ws.11)


## 0x03 通过命令行导出日志文件
---

导出的日志文件可以下载到本地打开，后缀名为evtx

### 1、导出Security所有日志并保存为1.evtx

```
wevtutil.exe epl Security 1.evtx
```

### 2、过滤日志并保存

#### (1)删除单条日志并保存

删除Security下的单条日志(EventRecordID=1112)，并保存为1.evtx

```
wevtutil epl Security 1.evtx "/q:*[System [(EventRecordID!=1112)]]"
```

#### (2)删除多条并保存

**1. 根据EventRecordID筛选**

删除Security下的多条日志(EventRecordID为13030、13031和13032)，结果保存为1.evtx

```
wevtutil epl Security 1.evtx "/q:*[System [(EventRecordID>13032) or (EventRecordID<13030)]]"
```

**2. 根据SystemTime筛选**

**注：**

SystemTime需要考虑时区的影响

通过wevtutil查询日志信息，输出格式为text时，时间未考虑时区

通过Windows界面查看日志信息，显示的时间也未考虑时区

通过wevtutil查询日志信息，输出格式为xml时，system time考虑了时区

举例说明：

通过wevtutil查询最近一条日志的时间，输出格式为text，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-3/2-1.png)

时间为`Date: 2018-08-09T20:22:20.558`

通过Windows界面查看最近一条日志的时间，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-3/2-2.png)

时间为`2018-08-09T20:22:20.558`

通过wevtutil查询最近一条日志的时间，输出格式为xml，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-3/2-3.png)

时间为`SystemTime='2018-08-10T03:22:20.558894400Z'`

时间相隔7小时

所以在删除指定日期的日志时，需要查看xml格式，获得SystemTime

删除SystemTime为`2018-08-10T03:20:00`至`2018-08-10T03:21:00`之间的日志，结果保存为1.evtx

```
wevtutil epl Security 1.evtx "/q:*[System [TimeCreated[@SystemTime >'2018-08-10T03:21:00' or @SystemTime <'2018-08-10T03:20:00']]]"
```


## 0x04 将修改后的日志文件覆盖系统原文件
---

删除了某条或是某些条日志后，需要将修改后的日志文件覆盖系统原文件

可采用以下三种方法

### 1、通过解除文件占用

详情可参考[《Windows XML Event Log (EVTX)单条日志清除（三）——通过解除文件占用删除当前系统单条日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%89-%E9%80%9A%E8%BF%87%E8%A7%A3%E9%99%A4%E6%96%87%E4%BB%B6%E5%8D%A0%E7%94%A8%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

实现思路如下：

- 结束日志进程
- 释放日志文件句柄
- 替换日志文件
- 重启日志服务

文中的代码需要作细微修改，修改后的代码可参考：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/DeleteRecordbyTerminateProcess(ReplaceFile).cpp

代码实现了结束日志进程，释放日志文件句柄，替换指定日志文件，最后重启日志服务

### 2、通过注入

详情可参考[《Windows XML Event Log (EVTX)单条日志清除（四）——通过注入获取日志文件句柄删除当前系统单条日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E5%9B%9B-%E9%80%9A%E8%BF%87%E6%B3%A8%E5%85%A5%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

实现思路如下：

#### (1)Loader

- 向日志进程注入dll
- 创建三个内存映射，用于向dll传递日志文件的句柄、新日志文件的长度和新日志文件的内容
- 释放Dll
- 关闭内存映射

可供参考的代码：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/Loader-EvtExportLog.cpp`

#### (2)Dll

- 从内存映射读取内容，获得日志文件句柄和新日志文件的内容
- 调用函数MapViewOfFile()将文件数据映射到进程的地址空间
- 修改内存数据，覆盖为新日志文件的内容
- 调用函数FlushViewOfFile()，将内存数据写入磁盘
- 关闭日志文件的内存映射

可供参考的代码：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/Dll-EvtExportLog.cpp`

### 3、通过DuplicateHandle

详情可参考[《Windows XML Event Log (EVTX)单条日志清除（五）——通过DuplicateHandle获取日志文件句柄删除当前系统单条日志记录》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%94-%E9%80%9A%E8%BF%87DuplicateHandle%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)

实现思路如下：

- 枚举所有进程，获得指定文件句柄
- 通过DuplicateHandle复制句柄
- 调用函数MapViewOfFile()将文件数据映射到进程的地址空间
- 修改内存数据，覆盖为新日志文件的内容
- 调用函数FlushViewOfFile()，将内存数据写入磁盘
- 关闭日志文件的内存映射

可供参考的代码：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordbyGetHandleEx.cpp`


## 0x05 完整实现流程
---

### 1、挂起日志线程，使当前系统不再记录日志

可供参考的代码：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/SuspendorResumeTid.cpp`

代码支持三种操作，分别为suspend、resume和kill

### 2、过滤日志并保存

两种方法

#### (1)通过筛选条件删除指定的日志

方法可参考0x03的内容

优点：

简单高效

缺点：

删除指定日志后，后续日志的EventRecordID没有更新，如果逐个对比日志的EventRecordID，能够找到删除的日志个数和时间范围

#### (2)自己实现

可供参考的代码：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordofFile.cpp`

优点是不留痕迹

缺点是实现较麻烦，需要考虑多种情况多个Chunk

### 3、覆盖系统原日志文件

三种方法：

#### (1)通过解除文件占用

某些情况下，关闭Eventlog进程和重启服务Eventlog会产生日志文件，位于system下，EventID为7034和7036

可选择在日志重启后立即挂起线程，避免日志被记录，可供参考的代码：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/SuspendorResumeTidEx.cpp`

当日志进程不存在时，程序会一直等待

#### (2)通过注入

存在注入失败或者被拦截的情况

存在竞争条件导致删除失败的情况

#### (3)通过DuplicateHandle

存在竞争条件导致删除失败的情况

综上，共介绍了**2*3=6**种删除单条日志的方法

**补充：**

默认配置，powershell v5.0以下，在启动powershell.exe会产生日志，位于`%SystemRoot%\System32\Winevt\Logs\Windows PowerShell.evtx`

日志不记录具体的脚本内容，但包括powershell.exe的启动时间

挂起日志线程不会阻止该日志的产生

能够对该日志实现单条清除

powershell更高版本的日志绕过可参考文章：

https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/

### 4、恢复日志线程，恢复日志记录功能

可供参考的代码：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/SuspendorResumeTid.cpp`


## 0x06 防御建议
---

当攻击者获得了系统的完整权限后，系统的日志记录功能也会失效，可被关闭和修改

因此在取证上，日志不再可信，可以选择将日志定期备份到远程服务器


## 0x07 小结
---

本文介绍了Windows XML Event Log (EVTX)单条日志清除在渗透测试中的具体使用方法，结合利用思路给出防御建议



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



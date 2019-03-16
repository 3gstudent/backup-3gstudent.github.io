---
layout: post
title: 渗透技巧——Windows command line process auditing的绕过
---


## 0x00 前言
---

command line process auditing是Windows的一项功能，开启该功能后，ID为4688的日志将会记录进程创建时的命令行参数

本文将要介绍通过修改进程参数绕过日志记录的方法，测试开源工具SwampThing，分享实现SwampThing的C语言代码，分析利用思路，给出防御建议

SwampThing的地址：

https://github.com/FuzzySecurity/Sharp-Suite/blob/master/SwampThing



## 0x01 简介
---

本文将要介绍以下内容：

- 实现原理
- 开启command line process auditing的方法
- 测试SwampThing
- 通过c++实现SwampThing
- 利用思路
- 防御建议


## 0x02 实现原理
---

方法上同创建傀儡进程类似，区别在于这个方法只修改新进程的CommandLine参数

关于傀儡进程的技术细节，可参考之前的文章: [《傀儡进程的实现与检测》](https://3gstudent.github.io/3gstudent.github.io/%E5%82%80%E5%84%A1%E8%BF%9B%E7%A8%8B%E7%9A%84%E5%AE%9E%E7%8E%B0%E4%B8%8E%E6%A3%80%E6%B5%8B/)

### 实现思路：

1. 通过CreateProcess创建进程，传入参数lpCommandLine，传入参数CREATE_SUSPENDED使进程挂起
2. 修改新进程的Commandline参数
3. 通过ResumeThread唤醒进程，执行新的Commandline参数
4. 如果新进程没有退出，再将Commandline参数还原

在具体实现上，还需要考虑以下问题：

#### 1、进程的选择

启动的进程需要能够加载Commandline参数，例如cmd.exe，powershell.exe，wmic.exe等


#### 2、修改远程进程的Commandline参数

通过NtQueryInformationProcess找到远程进程的基地址，计算偏移获得Commandline参数的位置，再分别通过ReadProcessMemory和WriteProcessMemory对Commandline参数进行读写

补充：

修改当前进程的Commandline参数可参考：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/MasqueradePEBtoCopyfile.cpp

## 0x03 开启command line process auditing
---

官方文档：

https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing

该功能默认关闭，需要手动配置来开启

1、执行gpedit.msc进入组策略

2、开启进程审核功能

英文系统：

Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation

中文系统：

计算机配置 > 策略 > Windows 设置 > 安全设置 > 高级审核配置 > 详细跟踪> 审核创建进程

3、开启事件日志的额外功能，记录命令行参数

英文系统：

Administrative Template > System > Audit Process Creation > Include command line in process creation events

中文系统：

管理模板 > 系统 > 审核创建的进程 > 在创建事件的过程中包含命令行

开启command line process auditing后，在Windows日志的Security分类下，ID为4688的日志记录进程创建信息


实例如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-24/2-1.png)

通过命令行查询ID为4688的日志的命令如下：

```
wevtutil qe security /f:text /q:*[System[(EventID=4688)]]
```

## 0x04 测试SwampThing
---

地址：

https://github.com/FuzzySecurity/Sharp-Suite/blob/master/SwampThing

使用c#编写

编译成功后需要以下三个文件:

- SwampThing.exe
- CommandlLine.dll
- CommandLine.xml

命令行参数如下：

```
SwampThing.exe -l C:\Windows\System32\notepad.exe -f C:\aaa.txt -r C:\bbb.txt
```

启动的notepad.exe将会加载C:\bbb.txt，但通过ProcessExplorer查看notepad.exe进程的参数为C:\aaa.txt

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-24/2-2.png)

开启command line process auditing后，ID为4688的日志记录notepad.exe进程参数为C:\aaa.txt

成功绕过command line process auditing，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-24/2-3.png)

SwampThing在实现上只针对执行后不自动退出的进程(例如notepad.exe)，也就是说，通过ResumeThread唤醒进程后会再次修改进程参数，将其还原

显而易见，对于执行后就退出的进程(例如cmd.exe /c)，通过ResumeThread唤醒进程后，无法再次修改进程参数，将会报错，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-1-24/2-4.png)

## 0x05 通过c++实现SwampThing
---

我通过c++实现了和SwampThing类似的功能，但在细节上有以下不同：

1. 通过ResumeThread唤醒进程后，不再还原进程参数，可适用于cmd.exe /c
2. 修改CreateProcess创建进程的参数，指定pStartupInfo->dwFlags和pStartupInfo->wShowWindow，隐藏启动进程的界面

代码下载地址：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/ProcessCommandlineSpoofing.cpp

代码实现了以下功能：

- 执行命令cmd.exe /c start calc.exe
- 开启command line process auditing后，ID为4688的日志记录的进程参数为cmd.exe /c start notepad.exe


## 0x06 利用思路
---

这个方法可以用来隐藏进程的真实参数

在利用上，还可以选择wmic.exe，正如SwampThing提到的那样——使用wmic来加载一个xsl文件

通过wmic加载xsl文件的方法可参考我之前的两篇文章：[《Use msxsl to bypass AppLocker》](https://3gstudent.github.io/3gstudent.github.io/Use-msxsl-to-bypass-AppLocker/)和[《利用wmic调用xsl文件的分析与利用》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8wmic%E8%B0%83%E7%94%A8xsl%E6%96%87%E4%BB%B6%E7%9A%84%E5%88%86%E6%9E%90%E4%B8%8E%E5%88%A9%E7%94%A8/)

当然，SwampThing和我开源的C代码都需要修改以后才能实现通过wmic加载xsl

## 0x07 防御建议
---

相对于创建傀儡进程，这种方法不需要使用VirtualAllocEx申请新的内存，不需要通过SetThreadContext设置入口点

通过对比PE文件在本地和内存之间是否有区别也无法检测这种方法

在检测上可以尝试查看进程的父进程是否可疑

## 0x08 小结
---

本文介绍了通过修改进程参数绕过command line process auditing的方法，测试开源工具SwampThing，分享实现SwampThing的C语言代码，分析利用思路，最后给出防御建议



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





---
layout: post
title: 对APT34泄露工具的分析——PoisonFrog和Glimpse
---


## 0x00 前言
---

最近APT34的6款工具被泄露，本文仅在技术角度对其中的PoisonFrog和Glimpse进行分析

参考资料：

https://malware-research.org/apt34-hacking-tools-leak/amp/

## 0x01 简介
---

本文将要介绍以下内容：

- 对PoisonFrog的分析
- 对Glimpse的分析
- 小结

## 0x02 对PoisonFrog的分析
---

对应泄露文件的名称为posion frog

包括两部分文件：

- agent，包含文件poisonfrog.ps1，是通过powershell实现的木马程序
- server side，对应木马控制端，使用Node.js开发

### 1、agent实现的功能

#### 1. 在%public%\Public文件夹下释放三个文件

- dUpdater.ps1
- hUpdater.ps1
- UpdateTask.vbs

释放文件的具体功能如下：

(1)dUpdater.ps1

1. 生成一个当前系统的专有标志
2. 读取当前系统的代理设置
3. 通过HTTP协议从c2服务器下载文件
4. 根据下载文件的内容进行下一步操作，包括执行命令，上传文件和下载文件

(2)hUpdater.ps1

1. 生成一个当前计算机的专有标志
2. 创建以下文件夹

- %public%\Public\<id>
- %public%\Public\<id>\reveivebox
- %public%\Public\<id>\sendbox
- %public%\Public\<id>\done

3. 通过DNS A记录从c2服务器接收控制命令
4. 执行命令并回传结果

(3)UpdateTask.vbs

内容如下：

```
command0 = "Powershell.exe -exec bypass -file C:\Users\Public\Public\hUpdater.ps1"
set Shell0 = CreateObject("wscript.shell")
shell0.run command0, 0, false
command1 = "Powershell.exe -exec bypass -file C:\Users\Public\Public\dUpdater.ps1"
set Shell1 = CreateObject("wscript.shell")
shell1.run command1, 0, false
```

用来加载powershell脚本dUpdater.ps1和hUpdater.ps1

#### 2. 创建两个计划任务

- 名称为\UpdateTasks\UpdateTask，每10分钟运行一次，以当前用户权限执行UpdateTask.vbs
- 名称为\UpdateTasks\UpdateTaskHosts，每10分钟运行一次，以System权限执行UpdateTask.vbs

### 2、 对server side的分析

通过Node.js实现

使用时需要先通过npm安装第三方包，具体安装的命令位于文件install_pachages.bat中

index.js为主体程序

考虑到避免被滥用，控制端的代码不做具体分析，也不提供具体搭建的方法

**注：**

我在之前的文章《渗透测试中的Node.js——Downloader的实现》和《渗透测试中的Node.js——利用C++插件隐藏真实代码》曾介绍过Node.js的使用，Node.js的基础知识可以参考这两篇文章

使用Node.js实现server side有以下优点：

- 语法简单易懂
- 轻量又高效
- 可同时部署在Windows和Linux系统

### 3、该工具的公开线索

1. APT34曾利用CVE-2017-11882传播该木马，FireEye对样本进行过分析：

https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html

2. Palo Alto Networks将其命名为Early BondUpdater，对样本的分析资料：

https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild-overview-of-oilrigs-dns-tunneling/


## 0x03 对Glimpse的分析
---

对应泄露文件的名称为Glimpse

包括四部分文件：

- Agent，包含四个文件dns.ps1、dns_main.ps1、refineddns_main.ps1和runner_.vbs
- panel，包含一个c#开发的界面程序，是界面化的木马控制端
- server，是Node.js开发的木马控制端
- Read me.txt，配置说明文档

### 1、agent实现的功能

dns.ps1、dns_main.ps1和refineddns_main.ps1三个文件的功能相同

原始版本为dns_main.ps1

dns.ps1和refineddns_main.ps1只是变量名称替换成了无意义的混淆字符串


dns_main.ps1的功能如下：

1. 创建文件夹%public%\Libraries

2. 判断文件%public%\Libraries\lock是否存在

- 如果不存在，创建文件并写入当前powershell进程的pid
- 如果文件存在，读取文件创建时间，如果距离现在的时间超过10分钟，那么会退出进程并删除lock文件

3. 生成一个当前系统的专有标志，写入文件%public%\Libraries\quid

4. 创建以下文件夹

- %public%\Libraries\files
- %public%\Libraries\<id>
- %public%\Libraries\<id>\reveivebox
- %public%\Libraries\<id>\sendbox
- %public%\Libraries\<id>\done

5. 通过DNS A记录或DNS TXT记录从c2服务器接收控制命令
6. 执行命令并回传结果

### 2、 对server的分析

通过Node.js实现

使用时需要先通过npm安装第三方包，具体安装的命令位于文件Read me.txt中

相比于PoisonFrog，Glimpse在代码结构上做了优化，并且添加了通过DNS TXT记录传输数据的功能

考虑到避免被滥用，控制端的代码不做具体分析，也不提供具体搭建的方法

### 3、该工具的公开线索

1. Palo Alto Networks将其命名为Updated BondUpdater，对样本的分析资料：

https://unit42.paloaltonetworks.com/unit42-oilrig-uses-updated-bondupdater-target-middle-eastern-government/

## 0x04 小结
---

对于PoisonFrog和Glimpse，虽然这次泄露了工具源码，但它们早在2017年已经被捕获样本，也被分析的很清楚，个人认为该工具不存在被大规模滥用的隐患。而使用DNS协议传输数据也是一个很古老的方法，个人认为该工具不会导致恶意软件技术的升级。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)














---
layout: post
title: 内网安全——利用NSA Smbtouch批量检测内网 
---

## 0x00 前言
---

最近，NSA渗透工具被曝光，其中包含多个Windows远程漏洞利用工具，影响很大

本文不会具体介绍这些远程漏洞工具的使用方法，而是站在防御者的角度，介绍如何利用这些工具，更好的去保护自己的内网


## 0x01 简介
---

本文将要介绍以下内容：

- FuzzBunch使用流程
- Smbtouch功能介绍
- 编写python脚本实现批量检测内网是否存在可被SMB和NBT协议攻击的漏洞
- 根据日志掌握内网主机信息

检测的SMB和NBT远程提权漏漏洞列表如下：

- ETERNALBLUE
- ETERNALCHAMPION
- ETERNALROMANCE
- ETERNALSYNERGY

**注：**

个人认为，以上四个漏洞危害最大，尤其适用于内网工作组环境

## 0x02 FuzzBunch
---

FuzzBunch框架，类似于metasploit，包含探测、攻击、利用等各种功能(仅根据目前泄露的资料)

**下载地址：**

https://github.com/fuzzbunch/fuzzbunch

**注：**

fuzzbunch提取自https://github.com/x0rz/EQGRP_Lost_in_Translation


### 1. 配置环境

安装python2.6，参考下载地址：

http://dl.nexiao.com/file.html?url=http%3A//b9.gpxz.net/201402/python-2_gpxz.6_gpxz.6_gpxz.rar


安装pywin32，参考下载地址：

https://sourceforge.net/projects/pywin32/files/pywin32/Build%20221/pywin32-221.win32-py2.6.exe/download

### 2. 添加环境变量 c:\python26

### 3. 执行fb.py进入命令行操作模式

报错

**原因：**

泄露的资料里缺少listeningposts文件夹

**解决办法：**

在shadowbroker-master\windows\下创建个listeningposts文件夹

或者修改fb.py，修改好的文件可在如下链接下载：

https://raw.githubusercontent.com/3gstudent/test/master/fb.py

再次执行fb.py，成功

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/2-1.png)

**注：**

执行start_lp.py可进入界面操作模式，如下图，此处不再过多介绍

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/2-2.png)

### 4. 设置启动参数如下：

```
[?] Default Target IP Address [] : 
[?] Default Callback IP Address [] : 
[?] Use Redirection [yes] : 
[?] Base Log directory [D:\logs] :
```

进入fb的shell后输入use，可获得支持的插件目录：

```
Plugin Category: Touch
======================

  Name                     Versi
  ----                     -----
  Architouch               1.0.0
  Domaintouch              1.1.1
  Eclipsedwingtouch        1.0.4
  Educatedscholartouch     1.0.0
  Emeraldthreadtouch       1.0.0
  Erraticgophertouch       1.0.1
  Esteemaudittouch         2.1.0
  Explodingcantouch        1.2.1
  Iistouch                 1.2.2
  Namedpipetouch           2.0.0
  Printjobdelete           1.0.0
  Printjoblist             1.0.0
  Rpctouch                 2.1.0
  Smbtouch                 1.1.1
  Webadmintouch            1.0.1
  Worldclienttouch         1.0.1


Plugin Category: ImplantConfig
==============================

  Name           Version
  ----           -------
  Darkpulsar     1.1.0
  Mofconfig      1.0.0


Plugin Category: Exploit
========================

  Name                   Version
  ----                   -------
  Easybee                1.0.1
  Easypi                 3.1.0
  Eclipsedwing           1.5.2
  Educatedscholar        1.0.0
  Emeraldthread          3.0.0
  Emphasismine           3.4.0
  Englishmansdentist     1.2.0
  Erraticgopher          1.0.1
  Eskimoroll             1.1.1
  Esteemaudit            2.1.0
  Eternalromance         1.4.0
  Eternalsynergy         1.0.1
  Ewokfrenzy             2.0.0
  Explodingcan           2.0.2
  Zippybeer              1.0.2


Plugin Category: Payload
========================

  Name              Version
  ----              -------
  Doublepulsar      1.3.1
  Jobadd            1.1.1
  Jobdelete         1.1.1
  Joblist           1.1.1
  Pcdlllauncher     2.3.1
  Processlist       1.1.1
  Regdelete         1.1.1
  Regenum           1.1.1
  Regread           1.1.1
  Regwrite          1.1.1
  Rpcproxy          1.0.1
  Smbdelete         1.1.1
  Smblist           1.1.1
  Smbread           1.1.1
  Smbwrite          1.1.1


Plugin Category: Special
========================

  Name                Version
  ----                -------
  Eternalblue         2.2.0
  Eternalchampion     2.0.0
```

插件共分为五大类，分别为：

- Touch         信息探测、漏洞测试
- ImplantConfig 植入工具
- Exploit       漏洞利用
- Payload       Payload
- Special       专用

每一个插件在文件夹下对应三个文件：

- .exe
- .fb
- .xml

例如Special下的Eternalblue-2.2.0，对应shadowbroker-master\windows\specials下的

- Eternalblue-2.2.0.exe
- Eternalblue-2.2.0.fb
- Eternalblue-2.2.0.0.xml

查看文件内容可发现：

- exe能够单独执行(前提是找到需要的dll文件)
- exe读取xml文件中保存的配置参数（需要二次修改）

也就是说，只需要单独的exe和xml配置文件，加上需要的支持文件，就能够执行对应的插件，不需要完全安装FuzzBunch框架

## 0x03 Smbtouch
---

位于Touch类下，文件位于/windows/touches/，用于探测目标主机是否包含SMB和NBT远程提权漏漏洞，主要测试以下四个漏洞：

- ETERNALBLUE
- ETERNALCHAMPION
- ETERNALROMANCE
- ETERNALSYNERGY

### 1.命令行下测试

执行fb.py,进入命令行操作模式

设置好扫描参数，依次执行：

`use Smbtouch`

`execute`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/3-1.png)

接着执行插件，回显如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/3-2.png)

探测成功，获得如下信息：

系统：Windows Server 2003 3790 Service Pack 2 x86

可用漏洞：

- ETERNALROMANCE  - FB
- ETERNALCHAMPION - DANE/FB

接着使用具体的漏洞攻击即可

**注:**

被攻击主机需要开放445端口，测试环境可选择关闭防火墙或是手动打开445端口

命令行开启445端口的代码如下:

`netsh advfirewall firewall add rule name="445" protocol=TCP dir=in localport=445 action=allow`

### 2.直接执行exe

进入文件夹shadowbroker-master\windows\touches，直接执行Smbtouch-1.1.1.exe

提示缺少dll，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/3-3.png)

在文件夹shadowbroker-master\windows\lib\x86-Windows下找到缺失的dll，补全

直接执行Smbtouch-1.1.1.exe，回显提示：

`TargetIp must have a value assigned.`

所以接下来需要编辑Smbtouch-1.1.1.0.xml文件

需要添加如下参数：

- NetworkTimeout：60
- TargetIp：127.0.0.1
- TargetPort：445
- Protocol：SMB
- Credentials：Anonymous

对照xml文件格式，添加代码`<value>data</value>`，并且重命名为Smbtouch-1.1.1.xml

**注：**

文件名不是原来的Smbtouch-1.1.1.0.xml

修改好的xml文件可参照：

https://github.com/3gstudent/Smbtouch-Scanner/blob/master/Smbtouch-1.1.1.xml

再次执行Smbtouch-1.1.1.exe

回显如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/3-4.png)

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/3-5.png)

成功执行，并且回显xml文件内容


## 0x04 Smbtouch Scanner
---

基于以上内容，如果想尝试对指定网段进行扫描，那么需要反复修改xml配置文件，接着执行Smbtouch-1.1.1.exe进行探测

采用python自动实现以上操作，需要考虑如下问题：

- 执行Smbtouch-1.1.1.exe并获得回显
- 对回显内容进行解析，去掉多余部分
- 对范围ip地址解析
- 自动读写xml文件
- 生成log文件
- 多线程提高效率

完整代码可参考：

https://github.com/3gstudent/Smbtouch-Scanner

### 实际测试：

### 1.设置扫描ip段

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/4-1.png)

### 2.执行SmbtouchScanner.py

等待扫描完成，回显显示简要信息

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/4-2.png)

### 3.同级目录生成日志文件，显示详细信息

包含具体存在的漏洞，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-20/4-3.png)

### 4.补充

考虑到安全原因，此开源代码尚不支持多线程


## 0x05 防御建议
---

针对NSA的SMB和NBT远程提权漏漏洞，建议升级系统补丁，开启防火墙，限制445端口

限制445端口的命令行代码如下：

`netsh advfirewall firewall add rule name="445" protocol=TCP dir=in localport=445 action=block`

同时，为确保内网安全，可使用SmbtouchScanner.py对内网进行扫描检测

**注：**

目前Smbtouch-1.1.1.exe已被杀毒软件查杀


## 0x06 小结
---

本文介绍了如何使用python实现自动检测内网是否存在可被SMB和NBT协议攻击的漏洞，当然，泄露的漏洞不止以上4个，Touch插件也不只有Smbtouch

后续更新会同步至github：https://github.com/3gstudent/

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

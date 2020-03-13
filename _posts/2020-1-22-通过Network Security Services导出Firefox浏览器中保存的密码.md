---
layout: post
title: 通过Network Security Services导出Firefox浏览器中保存的密码
---


## 0x00 前言
---

在上一篇文章[《渗透技巧——导出Firefox浏览器中保存的密码》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%AF%BC%E5%87%BAFirefox%E6%B5%8F%E8%A7%88%E5%99%A8%E4%B8%AD%E4%BF%9D%E5%AD%98%E7%9A%84%E5%AF%86%E7%A0%81/)介绍了导出Firefox浏览器密码的常用方法，其中[firefox_decrypt.py](https://github.com/unode/firefox_decrypt)使用NSS(Network Security Services)进行解密，支持key3.db和key4.db的Master Password解密。本文将要对其涉及的原理进行介绍，编写测试代码，实现对Master Password的验证，分享脚本编写的细节

## 0x01 简介
---

本文将要介绍如下内容：

- Network Security Services简介
- 通过python调用Network Security Services导出Firefox浏览器密码
- 开源python脚本
- 爆破脚本的实现

## 0x02 Network Security Services简介
---

Network Security Services(NSS)是一组旨在支持安全的客户端和服务器应用程序跨平台开发的库

参考文档：

https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS

Firefox浏览器使用NSS作为加密算法和安全网络协议的基础库，在凭据加解密上使用了PKCS#11标准

参考文档：

https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/PKCS11

## 0x03 通过Python调用Network Security Services导出Firefox浏览器的密码
---

参考代码：

https://github.com/unode/firefox_decrypt

https://github.com/Kerisa/BrowserPasswordDump/blob/master/MozillaPwd.py

Windows系统下的解密流程如下：

1. 加载Network Security Services需要的nss3.dll
2. 调用NSS_Init()进行初始化
3. 调用PK11_GetInternalKeySlot()来获得internal slot(用作验证Master Password)
4. 调用PK11_CheckUserPassword()验证Master Password
5. 读取logins.json获得加密数据
6. 调用PK11SDR_Decrypt()进行解密


具体需要注意的问题如下：

### 1. Python和Firefox的版本需要保持一致

64位系统下，需要同为32位或64位

### 2. 将Firefox的安装路径加入到环境变量，便于调用

Firefox浏览器的安装目录下有我们需要调用的nss3.dll，所以可以选择将Firefox的安装路径加入到环境变量PATH，对应的python代码如下:

```
import os
firefoxPath = "C:\Program Files\Mozilla Firefox"
os.environ["PATH"] = ';'.join([firefoxPath, os.environ["PATH"]])
```

**注：**

64位操作系统下，64位Firefox浏览器的默认安装目录为`C:\Program Files\Mozilla Firefox`，32位Firefox浏览器的默认安装目录为`C:\Program Files (x86)\Mozilla Firefox`

调用nss3.dll的python代码如下：

```
import ctypes
NssDll = ctypes.CDLL("nss3.dll")
```

### 3. NSS初始化时需要三个文件

具体位置为：`%APPDATA%\Mozilla\Firefox\Profiles\xxxxxxxx.default\`

需要以下三个文件：

- cert9.db
- key4.db
- logins.json

可将以上三个文件保存在同一文件夹下，例如`c:\test\data`

NSS初始化的代码如下：

```
profilePath = "C:\\test\\data"
NssDll.NSS_Init(profilePath)
```

### 4. 读取logins.json获得加密的数据

`encryptedUsername`和`encryptedPassword`项为加密的数据，需要使用NSS进行解密

在解密前需要先进行base64解码，再调用`PK11SDR_Decrypt()`解密获得明文

`timeCreated`、`timeLastUsed`和`timePasswordChanged`项为Epoch Time格式(从协调世界时1970年1月1日0时0分0秒起到现在的总秒数,不包括闰秒)，可通过如下网址转换成实际的时间：

https://esqsoft.com/javascript_examples/date-to-epoch.htm

转换时间格式的python代码如下：

```
from datetime import datetime
def timestamp_to_strtime(timestamp):
	return datetime.fromtimestamp(timestamp / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
print timestamp_to_strtime(1580901797579) 
```

**注:**

不同版本的Firefox保存记录的文件名称不同，具体区别如下：

- Version大于等于32.0，保存记录的文件为logins.json
- Version大于等于3.5，小于32.0，保存记录的文件为signons.sqlite

更详细的文件说明可参考：

```
http://kb.mozillazine.org/Profile_folder_-_Firefox
```

## 0x04 开源python脚本
---

参考代码：

https://github.com/unode/firefox_decrypt

https://github.com/Kerisa/BrowserPasswordDump/blob/master/MozillaPwd.py

我的测试代码已上传至GitHub，地址如下:

https://github.com/3gstudent/Homework-of-Python/blob/master/ExportFirefoxPassword.py

测试环境:

- 64位Windows操作系统安装64位Firefox浏览器
- Firefox默认安装路径为`"C:\Program Files\Mozilla Firefox"`
- 配置文件路径为`"C:\\Users\\a\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\2yi8qmhz.default-beta"`，包括以下三个文件：
 - cert9.db
 - key4.db
 - logins.json

代码支持两个功能：

### 1. 验证Master Password

对应子函数`checkMasterPassword(MasterPassword)`

如果MasterPassword正确，显示正确的MasterPassword，并返回TRUE

如果MasterPassword错误，返回FALSE

这个可以用来实现对Master Password的爆破

### 2. 导出Firefox浏览器中保存的密码

对应子函数`ExportData(MasterPassword)`

如果未设置Master Password，MasterPassword参数设置为`""`即可

如果设置了Master Password，需要填入正确的Master Password才能解密获得真正的数据

具体能够导出以下信息：

- url
- username
- password
- timeCreated
- timePasswordChanged
- timeLastUsed

## 0x05 小结
---

本文介绍了通过Python调用Network Security Services导出Firefox浏览器密码的方法，分享脚本编写细节。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)











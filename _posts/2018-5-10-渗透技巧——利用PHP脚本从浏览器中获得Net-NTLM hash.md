---
layout: post
title: 渗透技巧——利用PHP脚本从浏览器中获得Net-NTLM hash
---


## 0x00 前言
---

在上篇文章[《渗透技巧——通过HTTP协议获得Net-NTLM hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%80%9A%E8%BF%87HTTP%E5%8D%8F%E8%AE%AE%E8%8E%B7%E5%BE%97Net-NTLM-hash/)介绍了通过HTTP协议获得客户端当前登录用户Net-NTLM hash的方法，侧重于介绍原理和思路，本文将要给出一个具体的实现方法，利用PHP脚本模拟Net-NTLM认证过程，提取出客户端的Net-NTLM hash


## 0x01 简介
---

本文将要介绍以下内容：

- Net-NTLM认证过程
- 利用PHP脚本模拟认证过程
- 脚本编写细节
- 实际测试

## 0x02 Net-NTLM认证过程
---

参考资料：

https://www.innovation.ch/personal/ronald/ntlm.html

依然使用这幅图，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-10/2-1.png)

**注：**

图片截取自https://www.innovation.ch/personal/ronald/ntlm.html


## 0x03 利用PHP脚本模拟认证过程
---

想要通过PHP脚本模拟Net-NTLM认证过程，主要考虑的是Server端的实现

### 1、发送`WWW-Authenticate: NTLM`

接收Client的GET请求，回复`401 Unauthorized WWW-Authenticate: NTLM`，提示Client需要NTLM认证

### 2、发送`WWW-Authenticate: NTLM <base64-encoded type-2-message>`

接收Client的`Type-1-Message`，回复`Type-2-message`


The Type 2 Message的结构如下：

|Offset|Description|Content|
| - | :-: | -: | 
|0|NTLMSSP Signature|Null-terminated ASCII "NTLMSSP" (0x4e544c4d53535000)|
|8|NTLM Message Type|long (0x02000000)|
|12|Target Name|security buffer|
|20|Flags|long|
|24|Challenge|8 bytes|
|(32)|Context (optional)|8 bytes (two consecutive longs)|
|(40)|Target Information (optional)|security buffer|
|(48)|OS Version Structure (Optional)|8 bytes|


详细参数说明可参考：

http://davenport.sourceforge.net/ntlm.html#theType2Message

值得注意的参数为`Flags`和`Challenge`

Challenge是使用hashcat破解Net-NTLM hash的必须参数

Flags包含多种类型，一个简单的Flags示例，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-10/2-2.png)


对应的数据格式如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-10/2-4.png)

### 3、解析Type-3-message

Type-3-message包含Client加密后的Net-NTLM hash消息，提取出对应格式的数据可用于破解

Type-3-message示例如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-10/2-3.png)

这里需要注意每个参数的存储格式

```
short   Length;
short   Maxlen;
short   Offset;
```

Offset对应参数具体内容的偏移地址

### 4、发送网页内容

Server向Client提供最终的请求内容


## 0x04 脚本编写细节
---

为了便于测试，不会对用户提交的凭据做验证，直接在HTTP的回复内容中返回用户的验证凭据

完整POC代码已开源，地址如下：

https://raw.githubusercontent.com/3gstudent/Writeup/master/catchyournetntlm.php


POC代码基于https://loune.net/2007/10/simple-lightweight-ntlm-in-php/

做了以下优化：

#### 1、不再局限于apache module

原脚本只能在apache下使用

#### 2、提取Net-NTLM hash

原脚本输出Client的三个属性： `$user` `$domain` `$workstation`

新脚本添加了文件格式解析的功能，提取出`HMAC-MD5`和`blob`

**脚本细节：**

原POC中的`function get_msg_str($msg, $start, $unicode = true)`

在调用`$user = get_msg_str($msg, 36);`时，由于之前的Flags指定了`unicode`，所以默认执行以下代码：

```
if ($unicode)
        return str_replace("\0", '', substr($msg, $off, $len));
```

会自动去除字符串中的`0x00`

而在提取`HMAC-MD5`和`blob`时，需要保留`0x00`，所以我们要传入参数false，不对字符`0x00`进行过滤

具体的代码为：

```
$Response = get_msg_str($msg, 20,false);
```

至于`challenge`，在脚本中指定为`0x0000000000000000`，所以最后拼接hashcat的格式时直接设置为`0x0000000000000000`即可


## 0x05 实际测试
---

### 1、本地测试

**Server：**

安装apache环境

简单的配置方法:  安装phpstudy

上传脚本catchyournetntlm.php

**Client：**

修改IE配置文件，将登录方式修改为`Automatic logon with current user name and password`

对应命令如下：

```
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v 1A00 /t REG_DWORD /d 00000000 /f
```

**注：**

域环境下不需要这个设置

Client访问服务器上的catchyournetntlm.php，服务器获得用户的Net-NTLM hash，提取出固定格式返回至Client

Client显示如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-10/3-1.png)

数据可直接用于hashcat的破解


### 2、在线测试

https://evi1cg.me/test.php

服务器使用nginx，未使用apache

**注：**

nginx下脚本的优化由evilcg完成

Client使用默认登录方法，访问该网址弹出对话框提示输入密码，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-10/4-1.png)

任意输入，获得输入内容的Net-NTLM hash，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-10/4-2.png)

将Client的登录方式修改为`Automatic logon with current user name and password`，访问该网址自动获得Client当前用户的Net-NTLM hash，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-10/4-3.png)

## 0x06 小结
---

本文介绍了利用PHP脚本从浏览器中获得Net-NTLM hash的方法，分享脚本编写细节，实际测试该方法的效果。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



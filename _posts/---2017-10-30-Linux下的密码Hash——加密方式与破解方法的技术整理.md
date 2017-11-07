---
layout: post
title: Linux下的密码Hash——加密方式与破解方法的技术整理
---

## 0x00 前言
---

Linux系统下，用户的密码会被加密保存在文件`/etc/shadow`中，关于密码的加密方式与破解方法有哪些呢？本文尝试对这一部分内容进行整理，介绍相关基础知识，测试常用方法，帮助大家对此有更直观的认识。

## 0x01 简介
---

本文将要介绍以下内容：

- Linux下用户密码的保存格式
- Linux下用户密码的加密方法
- 破解用户密码hash的常用工具和方法

## 0x02 Linux下用户密码的保存格式
---

Linux密码信息保存在两个文件中，分别为：`/etc/passwd`和`/etc/shadow`

### /etc/passwd:

普通用户权限能够查看

保存用户信息，每一行代表一个用户，每一行通过冒号`：`分为七个部分

1. 用户名
2. 密码，x表示密码保存在`/etc/shadow`
3. UID，0代表root
4. GID，表示所在组
5. 描述信息，依次为Full Name、Room Number、Work Phone、Home Phone和Other
6. 用户主目录
7. 默认shell类型

**eg.**

`test2:x:1001:1001:test2,11111,111111-11,222222-22,test:/home/test2:/bin/bash`

- 用户名：test2
- 密码保存在`/etc/shadow`
- UID为1001
- GID为1001
- 描述信息：
	Full Name []: test2
	Room Number []: 11111
	Work Phone []: 111111-11
	Home Phone []: 222222-22
	Other []: test
- 用户主目录为`/home/test2`
- 默认shell为`/bin/bash`


### /etc/shadow:

只有root用户权限能够查看

保存加密后的密码和用户的相关密码信息，每一行代表一个用户，每一行通过冒号`：`分为九个部分

1. 用户名
2. 加密后的密码
3. 上次修改密码的时间(从1970.1.1开始的总天数)
4. 两次修改密码间隔的最少天数，如果为0，则没有限制
5. 两次修改密码间隔最多的天数,表示该用户的密码会在多少天后过期，如果为99999则没有限制
6. 提前多少天警告用户密码将过期
7. 在密码过期之后多少天禁用此用户
8. 用户过期日期(从1970.1.1开始的总天数)，如果为0，则该用户永久可用
9. 保留

**注：**

参数说明可通过`man shadow`获取

**eg.**

`test2:$6$C/vGzhVe$aKK6QGdhzTmYyxp8.E68gCBkPhlWQ4W7/OpCFQYV.qsCtKaV00bToWh286yy73jedg6i0qSlZkZqQy.wmiUdj0:17470:0:99999:7:::`

- 用户名：test2
- 加密后的密码：`$6$C/vGzhVe$aKK6QGdhzTmYyxp8.E68gCBkPhlWQ4W7/OpCFQYV.qsCtKaV00bToWh286yy73jedg6i0qSlZkZqQy.wmiUdj0`
- 上次修改密码的时间(从1970.1.1开始的总天数为17470)
- 两次修改密码间隔：没有限制
- 两次修改密码间隔最多的天数：没有限制
- 提前7天警告用户密码将过期
- 该用户永久可用


由示例可知，加密的密码具有固定格式：

`$id$salt$encrypted`

id表示加密算法，1代表`MD5`，5代表`SHA-256`，6代表`SHA-512`
salt表示密码学中的Salt,系统随机生成
encrypted表示密码的hash



## 0x03 破解用户密码hash的常用工具和方法
---

由于Linux的密码加密使用了Salt,所以无法使用彩虹表的方式进行破解,常用的方法为字典破解和暴力破解

字典破解和暴力破解的常用工具：

### 1、John the Ripper

#### (1) 字典破解

Kali2.0集成了John the Ripper


字典文件位于`/usr/share/john/password.lst`

使用Kali Linux上的John自带的密码列表。路径为`/usr/share/john/password.lst`

使用字典破解：

```
john --wordlist=/usr/share/john/password.lst ./shadow 
```

**注：**

也可使用其他字典

#### (2) 暴力破解：

```
john ./shadow 
```

列出已破解的明文密码：

```
john --show ./shadow 
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-30/2-1.png)

### 2、hashcat

Kali2.0集成了hashcat

字典文件使用`/usr/share/john/password.lst`

修改hash格式：只保留`$salt$encrypted`

**eg.**

原hash：

`test2:$6$C/vGzhVe$aKK6QGdhzTmYyxp8.E68gCBkPhlWQ4W7/OpCFQYV.qsCtKaV00bToWh286yy73jedg6i0qSlZkZqQy.wmiUdj0:17470:0:99999:7:::`

修改后：

`$6$C/vGzhVe$aKK6QGdhzTmYyxp8.E68gCBkPhlWQ4W7/OpCFQYV.qsCtKaV00bToWh286yy73jedg6i0qSlZkZqQy.wmiUdj0`

#### (1) 字典破解：

```
hashcat -m 1800 -o found1.txt --remove shadow /usr/share/john/password.lst 
```

参数说明：

-m：hash-type，1800对应`SHA-512 `
详细参数可查表：https://hashcat.net/wiki/doku.php?id=example_hashes
-o：输出文件
--remove：表示hash被破解后将从hash文件移除
shadow：代表hash文件
/usr/share/john/password.lst：代表字典文件

成功破解出2个hash，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-30/2-2.png)

#### (2) 暴力破解：

```
hashcat -m 1800 -a 3 -o found2.txt shadow ?l?l?l?l --force
```

参数说明：
-a：attack-mode，默认为0，3代表Brute-force，即暴力破解
?l：表示小写字母，即abcdefghijklmnopqrstuvwxyz，4个?l代表暴力破解的长度为4
?u：表示大写字母，即ABCDEFGHIJKLMNOPQRSTUVWXYZ
?h：代表十六进制字符小写，即0123456789
?H：代表十六进制字符大写，即0123456789abcdef
?s：表示特殊符号，即!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
?a：表示所有字符，即?l?u?d?s
?b：表示十六进制，即0x00 - 0xff

成功暴力破解出hash，结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-30/2-3.png)


### 3、在线网站

1.https://hce.iteknical.com/

HCE分布式计算平台,需要积分才能使用

2.http://www.cmd5.com/

目前暂不支持SHA-512

### 4、mimipenguin

下载地址：

https://github.com/huntergregal/mimipenguin

原理类似于mimikatz，通过内存导出明文密码


## 0x04 小结
---

本文介绍了Linux下的密码保存格式，测试了两款常用工具：John the Ripper和hashcat，分别使用字典和暴力两种破解方法。

作为一篇总结基础知识的文章，希望能够尽可能的做到简洁实用，欢迎读者补充，后续也会对这部分内容不断进行完善。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



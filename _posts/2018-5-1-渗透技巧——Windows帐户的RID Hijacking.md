---
layout: post
title: 渗透技巧——Windows帐户的RID Hijacking
---


## 0x00 前言
---

在之前的文章[《渗透技巧——Windows系统的帐户隐藏》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E7%B3%BB%E7%BB%9F%E7%9A%84%E5%B8%90%E6%88%B7%E9%9A%90%E8%97%8F/)介绍过利用帐户克隆建立隐藏帐户的技巧，是通过复制目标帐户对应注册表项F键的值，使得隐藏帐户获得了相同的权限。

如果换一种思路，将目标帐户对应注册表项F键的部分内容覆盖已有帐户，那么已有帐户能否获得目标帐户的权限呢？

这就是本文将要介绍的方法——RID Hijacking

**注：**

该方法最早公开于2017年12月，地址如下：

http://csl.com.co/rid-hijacking/

## 0x01 简介
---

本文将要介绍以下内容：

- RID劫持的方法
- 编写脚本的实现思路
- 利用分析
- 防御检测


## 0x02 相关概念
---

### SID

全称Security Identifiers(安全标识符)，是Windows系统用于唯一标识用户或组的可变长度结构

官方说明地址：

https://msdn.microsoft.com/en-us//library/windows/desktop/aa379594(v=vs.85).aspx

SID包含以下信息：

- The revision level of the SID structure
- 48-bit identifier authority value
- relative identifier (RID) 

#### 实例

Windows命令行执行`whoami /all`可获得当前用户的SID，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/2-1.png)

SID为： `S-1-5-21-2752016420-1571072424-526487797-1001`

S表示该字符串是SID
1表示SID的版本号
5-21-2752016420-1571072424-526487797对应ID authority
1001表示RID


### RID

Windows系统帐户对应固定的RID：

- 500： ADMINISTRATOR
- 501： GUEST
- 502: krbtgt(域环境)
- 512: Domain Admins(域环境)
- 513: Domain Users(域环境)
- 514: Domain Guests(域环境)
- 515: Domain Computers(域环境)
- 516: Domain Controllers(域环境)

## 0x03 RID劫持方法
---

对于Windows系统来说，注册表`HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names`下包含当前系统的所有帐户列表，每个帐户的默认键值对应该帐户详细信息的注册表位置(即RID的十六进制表示)

**注：**

需要获得system权限才能读取


举例如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/3-1.png)

帐户a的注册表默认值为`0x3e9`

**注：**

帐户a为普通用户权限

详细信息的注册表位置为`HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\000003E9`

详细信息如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/3-2.png)

F键的内容如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/3-3.png)

偏移位置`0x30f`和`0x31f`对应RID

由于是litte-endian字节存储，所以上图中从F键获得的RID值为`0x03E9`，转换为十进制为`1001`

使用帐户a登录，执行`whoami /all`获得帐户a的SID，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/3-4.png)

内容相同


### 测试1： 伪造成内置管理员帐户ADMINISTRATOR

将帐户a的RID修改为500(固定值，表示windows系统内置管理员ADMINISTRATOR)，对应十六进制为`01F4`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/3-5.png)

**注：**

帐户a需要重新登录才能生效

登录帐户a，帐户a继承了ADMINISTRATOR的权限，成为了管理员


登录用户名为： 原用户名.机器名，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/3-6.png)


用户文件夹也随之改变，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/3-7.png)


**直观理解：**

帐户a变成了新帐户a.WIN-BH7SVRRDGVA，继承了ADMINISTRATOR的权限


### 测试2： 伪造成管理员帐户1

新建管理员帐户1，RID为1000(0x03e8)，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/4-1.png)

将帐户a的RID修改为1000(0x03e8)

修改后如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/4-2.png)

重新登录帐户a

帐户a继承了帐户1的权限，成为了管理员

登录用户名变为1，执行`whoami /all`输出的用户名为a，但RID为1000(帐户1的RID)，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/4-3.png)

环境变量对应为用户1，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-1/4-4.png)

**直观理解：**

帐户a变成了原有帐户1，继承了1的权限，但在部分功能的显示上还保留帐户a

## 0x04 编写脚本的实现思路
---

### 实现思路

1. 获得system权限
2. 读取指定帐户的注册表信息
3. 修改固定偏移地址，指定为新的RID
4. 导入注册表，完成修改

具体实现细节上可参考文章[《渗透技巧——Windows系统的帐户隐藏》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E7%B3%BB%E7%BB%9F%E7%9A%84%E5%B8%90%E6%88%B7%E9%9A%90%E8%97%8F/)中的说明

参考代码：

https://github.com/3gstudent/Windows-User-Clone


由于功能较为简单，因此实现代码留给读者完成

msf对应的实现模块： `windows/manage/rid_hijack`

## 0x05 利用分析
---

对于RID Hijacking，实现原理上很简单： **定位帐户的注册表文件，修改代表RID信息的位置即可**

但在利用上存在以下不足：

- 帐户重新登录才能生效
- 环境变量被修改，影响正常使用
- 用户名的显示存在问题，容易被发现
- 模拟ADMINISTRATOR的权限会新建用户文件夹

### 利用场景

1. 启用帐户guest，修改RID,登录帐户guest，获得高权限
2. 修改低权限用户RID，登录获得高权限


## 0x06 防御检测
---

站在防御的角度，攻击者首先需要获得当前系统的system权限

检测思路：

- 查看注册表`HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\`下的信息是否存在异常

- 帐户guest是否被开启

## 0x07 小结
---

本文介绍了RID Hijacking的实现方法，分析利用条件，给出防御建议



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







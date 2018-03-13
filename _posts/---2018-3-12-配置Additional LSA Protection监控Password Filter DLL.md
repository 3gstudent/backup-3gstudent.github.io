---
layout: post
title: 配置Additional LSA Protection监控Password Filter DLL
---


## 0x00 前言
---

针对文章[《Password Filter DLL在渗透测试中的应用》](https://3gstudent.github.io/3gstudent.github.io/Password-Filter-DLL%E5%9C%A8%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%AD%E7%9A%84%E5%BA%94%E7%94%A8/)中wyzzoo的回复,提醒注意高版本系统上考虑的问题,地址如下:

https://github.com/3gstudent/feedback/issues/13#issuecomment-371694931

于是我对这部分内容进行研究,整理成文

## 0x01 简介
---

本文将要介绍以下内容:

- 如何配置额外的LSA保护
- 如何获得监控结果
- 补充一个Password Filter DLL的利用思路
- 利用Additional LSA Protection的检测效果

## 0x02 配置额外的LSA保护
---

参考官方文档:

https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

Windows8.1系统开始,为LSA提供了额外的保护,以防止由未受保护的进程读取内存和代码注入

### 保护方法:

要求加载到LSA的任何插件都使用Microsoft签名进行数字签名


具体的说,数字签名指的是catalog签名，签名需要满足WHQL认证

参考资料：

https://docs.microsoft.com/zh-cn/windows-hardware/drivers/install/whql-release-signature

关于catalog签名有过文章介绍:[《CAT文件数字签名使用技巧》](https://3gstudent.github.io/3gstudent.github.io/CAT%E6%96%87%E4%BB%B6%E6%95%B0%E5%AD%97%E7%AD%BE%E5%90%8D%E4%BD%BF%E7%94%A8%E6%8A%80%E5%B7%A7/)


测试系统： Win8.1 x64

### 配置方法:

#### 1、操作系统需要满足条件:

Win8.1或者更新的系统

#### 2、修改注册表

注册表位置`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe`，新建DWORD项`AuditLevel`，值为`00000008`

对应cmd命令如下：

```
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v "AuditLevel" /t REG_DWORD /d "00000008" /f
```

#### 3、重启系统


## 0x03 获得监控结果
---

查看日志Event 3065和Event 3066

Event 3065：此事件记录代码完整性检查确定进程（通常是lsass.exe）试图加载不符合共享段的安全要求的特定驱动程序。但是，由于设置了系统策略，图像被允许加载。

Event 3066：此事件记录代码完整性检查确定进程（通常是lsass.exe）试图加载不符合Microsoft签名级别要求的特定驱动程序。但是，由于设置了系统策略，图像被允许加载。


位置：`Applications and Services Logs\Microsoft\Windows\CodeIntegrity`

能够记录不符合条件的dll，但并未阻止加载dll，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-12/2-1.png)

通过命令行查询日志Event 3065和Event 3066：

获取日志分类列表：

```
wevtutil el >1.txt
```

找到`CodeIntegrity`对应的为`Microsoft-Windows-CodeIntegrity/Operational`

查找Event 3065和Event 3066：

```
wevtutil qe Microsoft-Windows-CodeIntegrity/Operational /rd:true /f:text /q:"*[system/eventid=3065 and 3066]"
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-12/2-2.png)

**补充：**

删除日志CodeIntegrity：

```
wevtutil cl "Microsoft-Windows-CodeIntegrity/Operational"
```

## 0x04 补充一个Password Filter DLL的利用思路——利用Long UNC文件名欺骗实现DLL的“隐藏”
---

具体隐藏细节可参考文章[《Catalog签名伪造——Long UNC文件名欺骗》](https://3gstudent.github.io/3gstudent.github.io/Catalog%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0-Long-UNC%E6%96%87%E4%BB%B6%E5%90%8D%E6%AC%BA%E9%AA%97/)

### 1、将dll命名为Long UNC文件名格式，保存在`%windir%\system32\`下

lsass.exe进程默认加载scecli.dll，所以选择将dll伪装成scecli.dll

命令行：

```
type Win32Project3.dll > "\\?\C:\windows\system32\scecli.dll "
```

**注：**

scecli.dll名称后面有一个空格


### 2、获得该dll的短文件名

命令行：

```
dir /x scecli*.dll
```

获得短文件名`SCECLI~1.DLL`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-12/3-1.png)

### 3、修改注册表键值

读取键值：

```
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages"
```

添加dll：

```
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages" /t REG_MULTI_SZ /d "scecli\0SCECLI~1.DLL" /f
```

### 4、重启

使用Process Explorer查看lsass进程加载的dll

显示加载两个同样的scecli.dll，具体属性存在差别，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-12/3-2.png)

### 5、检测

Event 3066成功检测，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-12/3-3.png)

## 0x05 补充
---

1、为Password Filter DLL添加一个伪造的微软Authenticode签名，并且修改证书验证机制使其生效，仍无法绕过Additional LSA Protection的监控，因为Password Filter DLL需要合法的catalog签名，而不是Authenticode签名

2、自己为Password Filter DLL制作一个catalog签名并将其添加到系统的安全编录数据库中，仍无法绕过Additional LSA Protection的监控


## 0x06 小结
---

本文介绍了配置Additional LSA Protection监控Password Filter DLL的方法和检测效果，如果Password Filter DLL未获得合法的catalog签名，系统能绕成功检测，但默认不会阻止加载


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






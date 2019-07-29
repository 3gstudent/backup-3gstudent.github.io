---
layout: post
title: Use Logon Scripts to maintain persistence
---

## 0x00 前言
---

依旧是对后门利用方法做介绍，本次介绍的是使用Logon Scripts的方法。然而我在研究过程中发现了一个特别的用法，脚本优先于杀毒软件执行，能够绕过杀毒软件对敏感操作的拦截，本文将要具体介绍这个技巧。

**注:**

有些杀毒软件是可以做到优先于Logon Scripts启动的

## 0x01 简介
---

- Logon Scripts用法
- 绕过360对wmi调用的拦截
- 特别用法

## 0x02 Logon Scripts用法
---

思路来自于Adam@Hexacorn，地址如下：

http://www.hexacorn.com/blog/2014/11/14/beyond-good-ol-run-key-part-18/

### 简要介绍Logon Scripts的用法

注册表路径：`HKCU\Environment\`

创建字符串键值： `UserInitMprLogonScript`

键值设置为bat的绝对路径：`c:\test\11.bat`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-9/1-1.png)

bat内容如下：

`start calc.exe`

注销，登录

执行脚本11.bat，弹出计算器


## 0x03 绕过360对通过wmi修改环境变量的拦截
---

在之前的文章[《Use CLR to maintain persistence》](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-maintain-persistence/)提到过使用wmic修改环境变量的方法

命令如下：

```
wmic ENVIRONMENT create name="COR_ENABLE_PROFILING",username="%username%",VariableValue="1"

wmic ENVIRONMENT create name="COR_PROFILER",username="%username%",VariableValue="{11111111-1111-1111-1111-111111111111}"
```

然而，360会对WMI的操作进行拦截，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-9/2-1.png)

其实通过WMI添加环境变量等价于在注册表`HKCR\Environment\`新建键值

所以对WMI的操作可以通过写注册表的操作进行代替


以上WMI命令可替换为如下powershell代码：

```
New-ItemProperty "HKCU:\Environment\" COR_ENABLE_PROFILING -value "1" -propertyType string | Out-Null

New-ItemProperty "HKCU:\Environment\" COR_PROFILER -value "{11111111-1111-1111-1111-111111111111}" -propertyType string | Out-Null
```

## 0x04 特别用法
---

源于我的一个特别的想法

我在对该技巧研究的过程中，产生了一个有趣的想法，Logon Scripts启动的顺序是否优先于其他程序呢？

如果是的话，那么是否也优先于杀毒软件呢？

下面开始我的测试：


### 1、cmd输入如下代码

```
wmic ENVIRONMENT create name="test",username="%username%",VariableValue="I run faster!"
```

不出意外，被拦截


### 2、设置Logon Scripts

11.bat代码如下：

```
wmic ENVIRONMENT create name="test",username="%username%",VariableValue="I run faster!"
reg query HKEY_CURRENT_USER\Environment /V test
pause
```

### 3、启用Logon Scripts

注册表路径：`HKCR\Environment\`

创建字符串键值： `UserInitMprLogonScript`

键值设置为bat的绝对路径：`c:\test\11.bat`

由于调用WMI会被拦截，可以通过powershell实现，代码如下：

```
New-ItemProperty "HKCU:\Environment\" UserInitMprLogonScript -value "c:\test\11.bat" -propertyType string | Out-Null
```

### 4、注销，重新登录，测试

如果注册表`HKCR\Environment\`成功被写入键值`test` `REG_SZ` `I run faster!`，说明Logon Scripts优先于杀毒软件执行，绕过杀毒软件的限制


完整操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-8-9/3.gif)

测试成功，验证我们的结论

## 0x05 防御
---

监控注册表键值`HKCR\Environment\UserInitMprLogonScript`


## 0x06 小结
---

本文对Logon Scripts的用法进行了测试，并且介绍了一个特别用法，Logon Scripts能够优先于杀毒软件执行，绕过杀毒软件对敏感操作的拦截。
站在防御的角度，要对此保持警惕。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

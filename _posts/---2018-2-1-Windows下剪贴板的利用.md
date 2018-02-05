---
layout: post
title: 渗透技巧——Windows下剪贴板的利用
---


## 0x00 前言
---

在Windows系统下，剪贴板是一个常见的功能，这其中有哪些可被利用的地方呢？本文将尝试整理这部分内容

## 0x01 简介
---

本文将要介绍以下内容：

- 写入剪贴板的方法
- 读取剪贴板的方法
- 利用思路

## 0x02 剪贴板简介
---

剪贴板是指windows操作系统提供的一个暂存数据和共享数据的模块，可理解为数据中转站

剪贴板的内容保存在内存中，所以系统重启后，保存的数据丢失

XP系统支持剪贴板查看器clipbrd.exe(Win7后移除)，可查看剪贴板内容 

剪贴板查看器clipbrd.exe不需要安装，可直接在其他系统(例如Win7)下使用

复制数据后，在剪贴板查看器clipbrd.exe中实时显示复制的内容，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/2-1.png)


## 0x03 写入剪贴板的方法
---

### 1、Ctrl+C

复制数据，或者通过快捷键`Ctrl+C`，数据保存到剪贴板中


### 2、cmd下的方法

将`whoami`输出的内容复制到剪贴板上：

```
whoami|clip
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/2-2.png)

将`11.txt`的内容复制到剪贴板上：

```
clip<11.txt
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/2-3.png)

### 3、程序调用API实现

c++测试代码如下：

```
#include <windows.h>
BOOL CopyToClipboard(char* pszData)
{
    if(::OpenClipboard(NULL))
    {
        ::EmptyClipboard();
        HGLOBAL clipbuffer;
        char *buffer;
        clipbuffer = ::GlobalAlloc(GMEM_DDESHARE, strlen(pszData)+1);
        buffer = (char *)::GlobalLock(clipbuffer);
        strcpy_s(buffer,strlen(pszData)+1, pszData);
        ::GlobalUnlock(clipbuffer);
        ::SetClipboardData(CF_TEXT, clipbuffer);
        ::CloseClipboard();
        return TRUE;
    }
    return FALSE;
}
int main(int argc, char* argv[])
{
	CopyToClipboard("clipcopydatatest");
	return 0;
}
```

执行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/2-4.png)


## 0x04 读取剪贴板的内容
---

### 1、Ctrl+V

粘贴数据，或者通过快捷键`Ctrl+V`，读取剪贴板中保存的数据

### 2、读取工具

剪贴板查看器clipbrd.exe

### 3、程序调用API实现

c++测试代码如下：

```
#include <windows.h>
BOOL GetTextFromClipboard()
{
    if(::OpenClipboard(NULL))
    {
        
        HGLOBAL hMem = GetClipboardData(CF_TEXT);
        if(NULL != hMem)
        {
            char* lpStr = (char*)::GlobalLock(hMem); 
            if(NULL != lpStr)
            {
                printf("%s",lpStr);
                ::GlobalUnlock(hMem);
            }
        }
        ::CloseClipboard();
        return TRUE;
    }
    return FALSE;
}
int main(int argc, char* argv[])
{
	GetTextFromClipboard();
	return 0;
}
```

成功读取剪贴板内容，执行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/3-1.png)

**注：**

也可以模拟键盘输入`Ctrl+V`，获得剪贴板内容


## 0x05 利用思路
---

### 1、实时捕获剪贴板内容

渗透测试中，在取得系统控制权限后，会尝试读取用户的剪贴板内容，获得有价值的信息

而实际利用上，最好能够实时捕获剪贴板的内容，配合键盘记录，能够全面监控用户的登录输入内容

在程序实现上，可以加一个循环判断，如果剪贴板内容改变，就记录下来

#### (1) 使用c++读取当前系统的剪贴板信息

代码参考上节内容，加入循环判断，写入文件的功能，代码暂略

#### (2) 使用powershell读取当前系统的剪贴板信息

参考地址：

https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Get-ClipboardContents.ps1

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/4-1.png)

### 2、Pastejacking

用作钓鱼网站，欺骗用户复制网址中的一段内容，劫持copyTextToClipboard事件，在复制的内容中加入恶意代码

复制内容`echo "not evil"`，实际剪贴板获得的内容为`echo "evil"`

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/4-2.png)


### 3、修改配置允许IE浏览器读取剪贴板内容

页面内容：

```
<!DOCTYPE html>
<html>
<script type="text/javascript">
var content = clipboardData.getData("Text");
if (content!=null) 
{
	document.write(content);
}
else 
{
  	document.write('No text found in clipboard.');
}
</script>
</html>
```

用户通过IE浏览器访问，默认情况下会弹框提示是否允许此网页访问剪贴板

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/4-3.png)

选择`允许访问`，网页获得剪贴板内容，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/4-4.png)

**注：**

Chrome、Firefox浏览器不允许通过getData访问用户的剪贴板内容

如果获得了用户系统的权限，可以修改IE配置，允许网页访问剪贴板

修改方式如下：

`Internet选项` -> `安全` -> `自定义级别`

`设置` -> `脚本` -> `允许对剪贴板进行编程访问` -> `启用`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/4-5.png)


对应注册表键值`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3`下的`1407`

- 0表示允许
- 1表示提示
- 3表示禁止

修改注册表设置允许访问剪贴板的命令为：

```
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v 1407 /t REG_DWORD /d 00000000 /f
```

重启IE浏览器后，配置生效

访问网页自动获得剪贴板内容，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-2-1/4-6.png)


## 0x06 小结
---

本文介绍了Windows系统下剪贴板在渗透测试中的相关利用技巧，通过实例演示后渗透阶段的利用方法


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)








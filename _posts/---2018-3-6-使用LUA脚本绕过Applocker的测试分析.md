---
layout: post
title: 使用LUA脚本绕过Applocker的测试分析
---

## 0x00 前言
---

在之前的文章《Bypass Windows AppLocker》曾对绕过Applocker的方法进行过学习，而最近看到一篇文章介绍了使用LUA脚本绕过Applocker的方法，学习之后产生了以下疑问：绕过原理是什么呢？能绕过哪种AppLocker的规则呢？适用条件又是什么呢？

文章地址：

https://homjxi0e.wordpress.com/2018/03/02/whitelisting-bypassing-using-lua-lanuage-wlua-com/

## 0x01 简介
---

本文将要介绍以下内容：

- LUA脚本简介
- 绕过测试
- 绕过原理
- 适用条件
- 防御方法

## 0x02 LUA脚本简介
---

- 轻量小巧的脚本语言
- 用标准C语言编写
- 可以被C/C++ 代码调用
- 可以调用C/C++的函数
- 在目前所有脚本引擎中的速度最快

## 0x03 Windows系统下执行LUA脚本
---

1、安装Lua for Windows，下载地址：

http://files.luaforge.net/releases/luaforwindows/luaforwindows

2、输出hello world

脚本内容：

```
print"Hello,world!"
```

cmd：

```
lua.exe 1.txt
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-6/2-1.png)


3、调用Windows API

脚本内容：

```
require "alien"
MessageBox = alien.User32.MessageBoxA 
MessageBox:types{ret ='long',abi ='stdcall','long','string','string','long'}
MessageBox(0, "title for test","LUA call windows api",0)
```

执行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-6/2-2.png)

4、c++执行LUA脚本

参考代码如下：

```
extern "C" {  
#include "lua.h"    
#include <lauxlib.h>     
#include <lualib.h>     
} 
int main(int argc,char* argv[])
{
	lua_State *L =  lua_open();
    luaL_openlibs(L);
    luaL_dofile(L, argv[1]);
    lua_close(L);
    return 0;
}
```

工程需要做如下设置：

(1)修改`VC++ 目录`

`包含目录`，添加`C:\Program Files\Lua\5.1\include`

`库目录`，添加`C:\Program Files\Lua\5.1\lib`

(2)`链接器` - `输入` - `附加依赖项`，添加

```
lua5.1.lib
lua51.lib
```

执行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-6/3-1.png)


c++执行LUA脚本来调用Windows API，需要在同级目录添加支持文件，执行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-6/3-2.png)


## 0x04 测试使用LUA脚本绕过Applocker
---

### 测试一：

测试系统： Win7x86

安装Lua for Windows

开启Applocker，配置默认规则

使用lua.exe执行脚本：

成功绕过Applocker的拦截

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-6/2-3.png)

### 测试二：

测试系统： Win7x86

安装Lua for Windows

开启Applocker，配置默认规则，添加规则： 拦截lua.exe

未绕过Applocker的拦截

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-6/2-4.png)

**注：**

还可以使用wlua.exe执行lua脚本

### 测试三：

测试系统： Win7x64

未安装Lua for Windows

开启Applocker，配置默认规则，系统禁止执行脚本

lua.exe同级目录放置lua5.1.dll(来自Lua for Windows安装路径)

使用lua.exe执行脚本：

未绕过Applocker的拦截

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-3-6/2-5.png)

**补充：**

将lua.exe换成wlua.exe，脚本内容修改为POC内容，地址如下：

https://gist.githubusercontent.com/homjxi0e/fd023113bf8b1b6789afa05c3913157c/raw/6bf41cbd76e9df6d6d3edcc9e289191f898451dc/AppLockerBypassing.wlua

测试结果均相同

## 0x05 最终结论
---

经过以上测试，得出最终结论：

使用LUA脚本，在一定程序上能绕过Applocker，但需要满足以下条件：

- 当前系统已安装Lua for Windows
- Applocker的规则未禁止lua.exe和wlua.exe

## 0x06 小结
---

本文对LUA脚本的开发做了简要介绍，测试使用LUA脚本绕过Applocker的POC，得出最终结论



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


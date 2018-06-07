---
layout: post
title: 渗透技巧——通过HTTP协议获得Net-NTLM hash
---


## 0x00 前言
---


在之前的文章[《Windows下的密码hash——NTLM hash和Net-NTLM hash介绍》](https://3gstudent.github.io/3gstudent.github.io/Windows%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81hash-NTLM-hash%E5%92%8CNet-NTLM-hash%E4%BB%8B%E7%BB%8D/)、[《渗透技巧——利用netsh抓取连接文件服务器的NTLMv2 Hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8netsh%E6%8A%93%E5%8F%96%E8%BF%9E%E6%8E%A5%E6%96%87%E4%BB%B6%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%9A%84NTLMv2-Hash/)和[《渗透技巧——利用图标文件获取连接文件服务器的NTLMv2 Hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8%E5%9B%BE%E6%A0%87%E6%96%87%E4%BB%B6%E8%8E%B7%E5%8F%96%E8%BF%9E%E6%8E%A5%E6%96%87%E4%BB%B6%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%9A%84NTLMv2-Hash/)曾介绍了通过SMB协议获得登录用户Net-NTLM hash的方法，利用的前提是客户端通过界面使用SMB协议连接服务器时，默认先使用本机的用户名和密码hash尝试登录。

对于HTTP协议，也同样支持NTLM认证。那么，通过HTTP协议能否同样获得当前登录用户的Net-NTLM hash呢？限制条件有哪些？如何防御？本文将要逐一介绍。


## 0x01 简介 
---

本文将要介绍以下内容：

- NTLM Over HTTP Protocol简介
- 找出利用前提
- 如何具体利用
- 防御思路


## 0x02 NTLM Over HTTP Protocol简介
---

官方文档：

https://msdn.microsoft.com/en-us/library/cc237488.aspx

参考资料：

https://www.innovation.ch/personal/ronald/ntlm.html

使用HTTP协议的NTLM认证流程：

1. 客户端向服务器发送一个GET请求，请求获得网页内容
2. 服务器由于开启了NTLM认证，所以返回401，提示需要NTLM认证
3. 客户端发起NTLM认证，向服务器发送协商消息
4. 服务器收到消息后，生成一个16位的随机数(这个随机数被称为Challenge),明文发送回客户端
5. 客户端接收到Challenge后，使用输入的密码hash对Challenge加密，生成response，将response发送给服务器
6. 服务器接收客户端加密后的response，经过同样的运算，比较结果，若匹配，提供后续服务，否则，认证失败

直观的流程图，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/2-1.png)

**注：**

图片截取自https://www.innovation.ch/personal/ronald/ntlm.html，具体的消息格式可查看链接中的介绍


### 实际测试

服务器：

- OS: Server2012 R2
- IP: 192.168.62.136
- 安装IIS服务

客户端：

- OS: Win7 x86
- IP: 192.168.62.134

#### 1、服务器开启NTLM认证

进入IIS管理页面，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/2-2.png)

选择`Authentication`

关闭其他认证，只开启`Windows Authentication`

添加`Provider`: `NTLM`

配置如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/2-3.png)

#### 2、服务器运行Wireshark，进行抓包

只提取`HTTP`

#### 3、客户端访问服务器

弹框提示输入用户名密码，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/2-4.png)

此时服务器抓取的HTTP数据包如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/2-5.png)

对应流程1和2

#### 4、客户端输入正确的用户名密码

此时服务器抓取的HTTP数据包如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/2-6.png)

对应流程3-6

#### 5、使用Hashcat对该Net-NTLM hash进行破解

NTLMv2的格式为：

`username::domain:challenge:HMAC-MD5:blob`

通过数据包获得challenge，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/2-7.png)

通过数据包获得username、domain、HMAC-MD5和blob

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/2-8.png)

拼接格式，使用hash破解即可

详细细节可参考：

[《Windows下的密码hash——NTLM hash和Net-NTLM hash介绍》](https://3gstudent.github.io/3gstudent.github.io/Windows%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81hash-NTLM-hash%E5%92%8CNet-NTLM-hash%E4%BB%8B%E7%BB%8D/)中的0x03部分


## 0x03 利用分析
---

经过以上的测试，可以看到HTTP协议的破解同SMB协议类似，那么在利用上是否相同呢？

我们知道，使用SMB协议通过界面操作连接服务器时，默认先使用本机的用户名和密码hash尝试登录，而刚才的测试没有发现HTTP协议也具有这个特性

也就是说，只要用户不输入正确的用户口令，服务器就无法获得正确的Net-NTLM hash，无法进一步利用

并且，Responder和Inveigh的HTTP认证拦截功能也提到能够获得用户的hash，地址如下：

https://github.com/SpiderLabs/Responder#features

https://github.com/Kevin-Robertson/Inveigh

这个功能该如何使用？能够获得哪种hash？能不能获得客户端当前登录用户的hash？

我在IE浏览器的配置中找到了答案

打开IE浏览器，找到如下位置：

`工具` -> `Internet选项` -> `安全` -> `自定义级别` -> `用户验证`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/3-1.png)

默认情况下，用户认证的登录方式为`Automatic logon only in Intranet zone`

所以接下来需要做两个测试


#### 测试一

将登录方式修改为`Automatic logon with current user name and password`

重启IE浏览器，再次测试

客户端通过IE访问服务器，弹出登录验证框，此时查看服务器的抓包情况

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-5-8/3-2.png)

发现客户端自动先使用本机的用户名和密码hash尝试登录，这时我们就能够通过进一步破解还原出用户口令，同SMB的利用思路一致

#### 测试二

改为域环境，其他不变

客户端也会先使用本机的用户名和密码hash尝试登录

至此，我们找到了限定条件，通过HTTP协议获得当前登录用户的Net-NTLM hash适用于以下两种情况：

1. 客户端用户认证的登录方式为`Automatic logon with current user name and password`

2. 用户认证的登录方式默认不变，客户端同服务器需要在同一Intranet zone

同样，这也是Responder和Inveigh支持HTTP协议用户hash获取的利用前提


## 0x04 具体利用方法
---

1、Intranet zone下使用Responder和Inveigh

如果是在工作组环境下，无法获得当前登录用户的Net-NTLM hash，可在域环境下使用

2、已获得客户端权限，修改用户认证方式

对应注册表`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3`下的键`1A00`

- `0`表示自动使用当前用户名和密码登录
- `10000`表示用户名和密码提示
- `20000`表示只在Intranet区域自动登录，默认值
- `30000`表示匿名登录

如果将客户端用户认证的登录方式修改为`Automatic logon with current user name and password`，那么客户端在访问任何需要登录验证的网站都会先使用本机的用户名和密码hash尝试登录


## 0x05 防御
---

结合利用思路，在此提出防御建议：

用户认证方式应禁止设置为`Automatic logon with current user name and password`，对应注册表键值禁止被修改为0

查询命令如下：

```
REG QUERY "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v 1A00
```

否则，很有可能被破解出客户端当前登录用户的口令

## 0x06 小结
---

本文介绍了通过HTTP协议获得客户端当前登录用户Net-NTLM hash的方法，找到限制条件(Intranet zone下或者用户认证方式被修改为`Automatic logon with current user name and password`)，限制条件同样适用于Responder和Inveigh的HTTP认证拦截功能，最后给出防御建议： 用户认证方式应禁止设置为`Automatic logon with current user name and password`



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





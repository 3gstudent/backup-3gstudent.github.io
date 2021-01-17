---
layout: post
title: Zimbra-SOAP-API开发指南2
---

## 0x00 前言
---

在上一篇文章[《Zimbra-SOAP-API开发指南》](https://3gstudent.github.io/3gstudent.github.io/Zimbra-SOAP-API%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97/)介绍了Zimbra SOAP API的调用方法，开源代码[Zimbra_SOAP_API_Manage](https://github.com/3gstudent/Homework-of-Python/blob/master/Zimbra_SOAP_API_Manage.py)。
本文将要在此基础上扩充功能，添加使用管理员权限可以实现的功能。

## 0x01 简介
---

本文将要介绍以下内容：

- 获得指定邮箱用户的token
- 通过clientUploader插件向服务器上传文件
- 日志检测

## 0x02 获得指定邮箱用户的token
---

说明文档：https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/zimbraAdmin/DelegateAuth.html

对应命名空间为`zimbraAdmin`

请求的地址为：`uri+":7071/service/admin/soap"`

根据说明文档中的SOAP格式，可通过以下Python代码实现：

```
def gettoken_request(uri,token):
    print("[*] Input the mailbox:")
    mail = input("[>]: ")
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <DelegateAuthRequest xmlns="urn:zimbraAdmin">
            <account by="name">{mail}</account>        
         </DelegateAuthRequest>
       </soap:Body>
    </soap:Envelope>
    """    
    try:
        print("[*] Try to get the token")
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token,mail=mail),verify=False,timeout=15)
        if 'authToken' in r.text:
            pattern_token = re.compile(r"<authToken>(.*?)</authToken>")
            token = pattern_token.findall(r.text)
            print("[+] authTOken:%s"%(token[0]))
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

返回的结果如下：

```     
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Header><context xmlns="urn:zimbra"/></soap:Header><soap:Body><DelegateAuthResponse xmlns="urn:zimbraAdmin"><authToken>XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</authToken><lifetime>3600000</lifetime></DelegateAuthResponse></soap:Body></soap:Envelope>
```

提取出`authToken`值可以用于邮箱登录，登录方法如下：

进入Zimbra邮箱登录的Web页面，添加以下Cookie信息：

Name：`ZM_AUTH_TOKEN`
Value：`XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

在登录页面输入邮箱用户名称，不需要输入口令，点击登录

Chrome浏览器添加Cookie的方法：

在Chrome浏览器中按下`F12`，开启开发者工具，选择`Application`标签

依次打开`Storage`->`Cookies`

## 0x03 通过clientUploader插件向服务器上传文件
---

这里需要注意上传文件的操作需要在请求头(Request Headers)中设置`Content-Type`为`multipart/form-data; boundary=${boundary}`，格式示例：

```
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno
```

完整的数据包格式示例：

```
POST /service/extension/clientUploader/upload HTTP/1.1
Host: mail.xx.com
Proxy-Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno
Content-Length: 400
Cookie:ZM_ADMIN_AUTH_TOKEN=0_530bf417d0f3e55ed628e4671e44b1dea4652bab_69643d33363a65306661666438392d313336302d313164392d383636312d3030306139356439386566323b6578703d31333a313535343835323934303131393b61646d696e3d313a313b
Upgrade-Insecure-Requests:1

------WebKitFormBoundary1abcdefghijklmno
Content-Disposition:form-data;name="file";filename="test.jsp"
Content-Type: image/jpeg

test12345
------WebKitFormBoundary1abcdefghijklmno--
```

其中，`------WebKitFormBoundary1abcdefghijklmno`为分隔符，`------WebKitFormBoundary1abcdefghijklmno--`为结束符

如果未设置该属性，上传文件的操作会会失败，返回结果如下：

```
<html><head></head><body onload="window.parent._uploadManager.loaded(20000001,'null');">The request does not upload a file</body></html>
```

在Python脚本的编写过程中，如果直接在Headers中加入属性：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno`，示例代码如下：

```
headers["Content-Type"]="multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno"
```

这样会产生bug，无法成功

此时的数据包格式如下：

```
POST /service/extension/clientUploader/upload HTTP/1.1
Host: mail.xx.com
Proxy-Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno
Content-Length: 400
Cookie:ZM_ADMIN_AUTH_TOKEN=0_530bf417d0f3e55ed628e4671e44b1dea4652bab_69643d33363a65306661666438392d313336302d313164392d383636312d3030306139356439386566323b6578703d31333a313535343835323934303131393b61646d696e3d313a313b
Upgrade-Insecure-Requests:1

------3c4bc2fbc2368a87e5def7b234fd126b
Content-Disposition:form-data;name="file";filename="test.jsp"
Content-Type: image/jpeg

test12345
------3c4bc2fbc2368a87e5def7b234fd126b--
```

发现分隔符和结束符为重新随机生成的数值，而不是我们在请求头(Request Headers)中设置的`----WebKitFormBoundary1abcdefghijklmno`

所以Python代码需要做修改，这里给出一种解决方法：使用`requests_toolbelt`库

代码示例：

```
    fileContent = 0;
    path = input("[*] Input the path of the file:")
    with open(path,'r') as f:
        fileContent = f.read()
    filename = path
    print("[*] filepath:"+path)
    print("[*] filedata:"+fileContent)

    headers = {
    "Content-Type":"application/xml"
    }   
    headers["Content-Type"]="multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"

    m = MultipartEncoder(fields={
    'filename1':(None,"test",None),
    'clientFile':(filename,fileContent,"image/jpeg"),
    'requestId':(None,"12345",None),
    }, boundary = '----WebKitFormBoundary1abcdefghijklmno')

    r = requests.post(uri+"/service/extension/clientUploader/upload",data=m,headers=headers,verify=False)
    if 'window.parent._uploadManager.loaded(1,' in r.text:
        print("[+] Upload Success!")
        print("[+] URL:%s/downloads/%s"%(uri,filename))
    else:
        print("[!]")
        print(r.text)  
        exit(0)
```


上传成功后，路径为`downloads`目录，经过验证的用户才能访问


## 0x04 开源代码
---

新的代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-Python/blob/master/Zimbra_SOAP_API_Manage.py

增加了以下两个功能：

- Gettoken
- upload

同时增加了对CVE-2019-9621 SSRF漏洞的支持，在邮件服务器关闭了7071管理端口的情况下，通过SSRF漏洞实现对管理资源的访问。

## 0x05 日志检测
---

登录日志的位置为`/opt/zimbra/log/mailbox.log`

其他种类的邮件日志可参考https://wiki.zimbra.com/wiki/Log_Files

## 0x06 小结
---

本文扩充了Zimbra SOAP API的调用方法，添加两个实用功能：获得指定邮箱用户的token和通过clientUploader插件向服务器上传文件，记录实现细节。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



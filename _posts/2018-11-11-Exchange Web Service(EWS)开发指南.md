---
layout: post
title: Exchange Web Service(EWS)开发指南
---


## 0x00 前言
---

Exchange Web Service(EWS)提供了一个访问Exchange资源的接口，我在github没有找到很合适的参考项目，于是对这方面的内容做一个系统性的整理，开源一份EWS的实现代码ewsManage，便于后续的二次开发。
## 0x01 简介
---

本文将要介绍以下内容：

- 使用EWS Managed API访问Exchange资源
- 使用EWS SOAP XML message访问Exchange资源
- 开源代码ewsManage
- ewsManage功能介绍

## 0x02 简介
---

官方文档：

https://docs.microsoft.com/en-us/exchange/client-developer/exchange-server-development

两种访问Exchange资源的方法：

- 使用EWS Managed API 
- 使用EWS SOAP XML message

测试环境：

- Exchange Server 2013 SP1
- user: test1@test.com
- pwd: test123!
- url: https://test.com/ews/Exchange.asmx
- AutodiscoverUrl: test1@test.com

## 0x03 使用EWS Managed API
---

官方资料：

https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/get-started-with-ews-managed-api-client-applications

这里使用EWS Managed API 2.0 

下载地址：

https://www.microsoft.com/en-us/download/details.aspx?id=35371

安装后从文件夹中找到文件`Microsoft.Exchange.WebServices.dll`和`Microsoft.Exchange.WebServices.xml`

**注：**

如果已经获得这两个文件，不需要安装EwsManagedApi.msi，这两个文件可以在后面的开源工程ewsManage中找到

### (1)C Sharp实现

开发环境：VS2015

新建工程，并引用文件：

`Microsoft.Exchange.WebServices.dll`和`Microsoft.Exchange.WebServices.xml`

C Sharp代码示例（列出收件箱所有邮件的标题）：

```
using System;
using Microsoft.Exchange.WebServices.Data;
using System.Net;
namespace EMAIL_EWS
{
    class Program
    {
        static void Main(string[] args)
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };
            ExchangeService service = new ExchangeService(ExchangeVersion.Exchange2013_SP1);
            service.Credentials = new WebCredentials("test1", "test123!");
            service.AutodiscoverUrl("test1@test.com");
            ItemView view = new ItemView(int.MaxValue);
            FindItemsResults<Item> findResults = service.FindItems(WellKnownFolderName.Inbox, view);
            foreach (Item item in findResults.Items)
            {
                if (item.Subject != null)
                {
                    Console.WriteLine(item.Subject);
                }
                else
                {
                    Console.WriteLine("no Title\r\n");
                }
            }
        }
    }
}
```

### (2)Powershell实现

Powershell代码示例（列出收件箱所有邮件的标题）：

```
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
Import-Module -Name "C:\test\Microsoft.Exchange.WebServices.dll"
$Credentials = New-Object Microsoft.Exchange.WebServices.Data.WebCredentials("test1","test123!")
$exchService = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService
$exchService.Credentials = $Credentials
$exchService.AutodiscoverUrl("test1@test.com")
$exchService
$inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchService,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox)
$inbox|gm
$ms = $inbox.FindItems(10) 
foreach ($m in $ms)
{
$m.Load()
$m.subject
}
```

**注：**

Powershell同样需要`Microsoft.Exchange.WebServices.dll`

在程序开发中需要注意的细节如下：

#### 1.Exchange Server的证书不可信

这会导致通过IE访问时显示证书不可信，需要点击Continue才能正常访问，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-11-7/3-1.png)

程序实现时会产生错误，提示如下：

```
The underlying connection was closed. Could not establish a secure SSL/TLS connection
```

可以通过添加证书信任策略避免这个问题：

```
using System.Net;
ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };
```

#### 2.Autodiscover自动发现服务

用来简化用户配置过程，具体到程序实现上对应`ExchangeService.AutodiscoverUrl`

参考地址：

https://msdn.microsoft.com/en-us/library/office/dd634273(v=exchg.80).aspx

输入邮箱地址，自动解析出Exchange Server Url

用法举例：

```
ExchangeService service = new ExchangeService(ExchangeVersion.Exchange2013_SP1);
service.AutodiscoverUrl("test1@test.com", RedirectionUrlValidationCallback);
```

等价于

```
ExchangeService service = new ExchangeService(ExchangeVersion.Exchange2013_SP1);
service.Url = new Uri("https://test.com/ews/Exchange.asmx");
```

**注：**

实际使用时，如果Exchange Server关闭Autodiscover自动发现服务，可以选择指定Url

#### 3..NET Framework 4 and .NET Framework 3.5

.NET Framework 4为推荐开发环境

Win7系统默认为.NET Framework 3.5，不支持.NET Framework 4

为了支持Win7，将工程指定为.NET Framework 3.5，不影响EWS Managed API的使用

#### 4.明文读取邮件的body属性

读取邮件的body属性时(也就是获得邮件的内容)，默认输出格式为htlm

想要获得邮件的内容，需要将输出格式改为Text

解决方法：

https://stackoverflow.com/questions/11243911/ews-body-plain-text

#### 5.搜索自定义文件夹时，指定深度搜索（遍历所有文件夹，包括更深的目录）

```
FindFoldersResults findResults = null;
FolderView view = new FolderView(int.MaxValue) { Traversal = FolderTraversal.Deep };
```

#### 6.编译后仍需要依赖文件

编译后的程序在执行时，仍需要依赖文件`Microsoft.Exchange.WebServices.dll`(在同级目录)


## 0x04 使用EWS SOAP XML message
---

官方资料：

https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/get-started-with-ews-client-applications

EWS请求和响应使用SOAP(Simple Object Access Protocol)协议

SOAP消息格式：

```
<SOAP-ENV:Envelope各种属性>
　<SOAP:HEADER>
　</SOAP:HEADER>
　<SOAP:Body>
　</SOAP:Body>
</SOAP-ENV:Envelope>
```

对应EWS的结构：

- Envelope元素（必须），作为SOAP消息的标志
- Header元素（可选），可用来指定ExchangeServer的版本
- Body元素（必须），包含所有的调用和响应信息
- Fault 元素（可选），包含错误消息

C Sharp代码示例（发送邮件）：

```
using System;
using System.Net;
using System.IO;
using System.Text;
namespace EMAIL_EWS
{
    class Program
    {
        static void Main(string[] args)
        {
            String user = "test1";
            String password = "test123!";
            String readPath = ""
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };          
            StreamReader sendData = new StreamReader("ews.xml", Encoding.Default);
            byte[] sendDataByte = Encoding.UTF8.GetBytes(sendData.ReadToEnd());
            sendData.Close();
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://test.com/ews/Exchange.asmx");
                request.Method = "POST";
                request.ContentType = "text/xml";
                request.ContentLength = sendDataByte.Length;
                request.AllowAutoRedirect = false;
                request.Credentials = new NetworkCredential(user, password);
                Stream requestStream = request.GetRequestStream();
                requestStream.Write(sendDataByte, 0, sendDataByte.Length);
                requestStream.Close();

                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    throw new WebException(response.StatusDescription);
                }
                Stream receiveStream = response.GetResponseStream();
                
                StreamReader readStream = new StreamReader(receiveStream, Encoding.UTF8);

                String receiveString = readStream.ReadToEnd();
                response.Close();
                readStream.Close();

                StreamWriter receiveData = new StreamWriter("out.xml");
                receiveData.Write(receiveString);                         
                receiveData.Close();                                        
            }
            catch (WebException e)
            {
                Console.WriteLine("[!]{0}", e.Message);
                Environment.Exit(0);
            }
            Console.WriteLine("[+]Done");
        }
    }
}
```

代码读取文件ems.xml的内容并进行发送，将结果保存为out.xml

ems.xml的内容为发送邮件：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" 
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" 
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:CreateItem MessageDisposition="SendAndSaveCopy">
      <m:SavedItemFolderId>
        <t:DistinguishedFolderId Id="sentitems" />
      </m:SavedItemFolderId>
      <m:Items>
        <t:Message>
          <t:Subject>This is Subject</t:Subject>
          <t:Body BodyType="HTML">This is Body</t:Body>
          <t:ToRecipients>
            <t:Mailbox>
              <t:EmailAddress>test1@test.com</t:EmailAddress>
              </t:Mailbox>
          </t:ToRecipients>
        </t:Message>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>
```

返回的内容(out.xml)如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2018-11-7/3-2.png)

`ResponseCode`为`NoError`，表示操作成功

**注：**

以上代码并不需要依赖文件`Microsoft.Exchange.WebServices.dll`

当然，如果需要使用Autodiscover自动发现服务，还是需要依赖文件`Microsoft.Exchange.WebServices.dll`

## 0x05 开源实现代码ewsManage
---

我将以上两种方法整合到一个工程，并添加了更多实用的功能，代码下载地址：

https://github.com/3gstudent/ewsManage

目前支持以下功能：

- 支持EWS Managed API和EWS SOAP
- 支持使用用户名口令或者使用当前凭据登录邮箱
- 支持是否忽略不可信证书
- 列出指定位置的邮件，包括附件中的文件名称和邮件内容
（对邮件内容长度做判断，如果大于100个字符，只显示前100个字符的内容）
- 列出指定位置的未读邮件，包括附件中的文件名称和邮件内容
（对邮件内容长度做判断，如果大于100个字符，只显示前100个字符的内容）
- 列出指定位置中的自定义文件夹（遍历所有子文件夹）
- 查看自定义文件下的所有邮件
- 查看自定义文件下的未读邮件
- 保存指定位置中的所有邮件(格式为eml)
- 保存指定邮件中的附件（指定ID）
- 向指定邮件添加附件（指定ID）
- 删除指定邮件的附件（指定ID）
- 删除指定邮件的所有附件
- 搜索带有指定关键词的邮件（常见位置，搜索标题名，附件名称和邮件正文）
- 删除指定邮件（指定ID）
- 查看某个邮件的具体内容（指定ID）
- 发送邮件(使用EWS SOAP)
- 读取xml文件，通过EWS SOAP发送命令

支持查询和操作的位置：

- 收件箱(Inbox)
- 草稿(Drafts)
- 已发送邮件(SentItems)
- 已删除邮件(DeletedItems)
- 发件箱(Outbox)
- 垃圾邮件(JunkEmail)

用法示例：

(1)

```
ewsManage.exe -CerValidation Yes -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ListUnreadMail -Folder Inbox
```

使用证书验证，使用URL登录，查看收件箱的所有未读邮件，输出以下邮件信息：

- Subject
- HasAttachments
- ItemId
- DateTimeCreated
- DateTimeReceived
- DateTimeSent
- DisplayCc:
- DisplayTo
- InReplyTo:
- Size
- MessageBody（如果大于100个字符，只显示前100个字符的内容）

(2)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -use the default credentials -AutodiscoverUrl test1@test.com -Mode ListMail -Folder SentItems
```

忽略证书验证，使用当前凭据自动登录，调用Autodiscover自动发现服务，查看所有已发送邮件的信息，输出的信息类别同(1)

**注：**

可以配合mimikatz的Overpass-the-hash，实现通过hash登录Exchange

(3)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ListFolder -Folder Inbox
```

忽略证书验证，使用URL登录，查看收件箱中所有自定义文件夹的信息，输出以下信息：

- DisplayName
- Id
- TotalCount（该自定义文件夹下邮件的数量）

(4)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ListMailofFolder -Id AAMaADFlMjRjMdM2LTgxZTUtNGRmZC05ZDQyLTMzNDFlMzBmZWY1NwAzAAAAAAAR9UOK286vT6HjUgukBQGmAQBHzR2O8KNmTcffGwlY0A76AAAAADfqAAA=
```

查看指定自定义文件夹（通过Id筛选）中的所有邮件，输出的信息类别同(1)

(5)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ExportMail -Folder Inbox
```

将收件箱的所有邮件保存为eml文件

(6)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode SaveAttachment -Id AAMzADFlMjRjMzM3LTgxZTUzNGRmZC25ZDQyLTMaNDFlMzBwZWY1NwBGAAAAAAAR8UOK236vT6HjUnujBQGmBwBHzR1O8KNmTrjfGwlY0A56AAAAAAEKAABHzR1O8KNmTrjfGzlY2A75AAAAABxFAAA=
```

保存指定邮件（通过Id筛选）中的附件，输出路径为当前路径

(7)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode AddAttachment -Id AAMzADFlMjRjMzM3LTgxZTUzNGRmZC25ZDQyLTMaNDFlMzBwZWY1NwBGAAAAAAAR8UOK236vT6HjUnujBQGmBwBHzR1O8KNmTrjfGwlY0A56AAAAAAEKAABHzR1O8KNmTrjfGzlY2A75AAAAABxFAAA= -AttachmentFile 1.txt
```

向指定邮件（通过Id筛选）添加附件，附件名称为1.txt

(8)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode DeleteAttachment -Id AAMzADFlMjRjMzM3LTgxZTUzNGRmZC25ZDQyLTMaNDFlMzBwZWY1NwBGAAAAAAAR8UOK236vT6HjUnujBQGmBwBHzR1O8KNmTrjfGwlY0A56AAAAAAEKAABHzR1O8KNmTrjfGzlY2A75AAAAABxFAAA= -AttachmentFile 1.txt
```

删除指定邮件（通过Id筛选）中的某个附件，附件名称为1.txt

(9)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ClearAllAttachment -Id AAMzADFlMjRjMzM3LTgxZTUzNGRmZC25ZDQyLTMaNDFlMzBwZWY1NwBGAAAAAAAR8UOK236vT6HjUnujBQGmBwBHzR1O8KNmTrjfGwlY0A56AAAAAAEKAABHzR1O8KNmTrjfGzlY2A75AAAAABxFAAA=
```

删除指定邮件（通过Id筛选）中的所有附件

(10)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode SearchMail -String vpn
```

搜索带有指定关键词为vpn的邮件

文件夹位置：

- 收件箱(Inbox)
- 草稿(Drafts)
- 已发送邮件(SentItems)
- 已删除邮件(DeletedItems)
- 发件箱(Outbox)
- 垃圾邮件(JunkEmail)

邮件位置：

- 标题名(Subject)
- 附件名称(AttachmentName)
- 邮件正文(Body)

(11)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode DeleteMail -Id AAMzADFlMjRjMzM3LTgxZTUzNGRmZC25ZDQyLTMaNDFlMzBwZWY1NwBGAAAAAAAR8UOK236vT6HjUnujBQGmBwBHzR1O8KNmTrjfGwlY0A56AAAAAAEKAABHzR1O8KNmTrjfGzlY2A75AAAAABxFAAA=
```

完全删除指定邮件（通过Id筛选）

(12)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ViewMail -Id AAMzADFlMjRjMzM3LTgxZTUzNGRmZC25ZDQyLTMaNDFlMzBwZWY1NwBGAAAAAAAR8UOK236vT6HjUnujBQGmBwBHzR1O8KNmTrjfGwlY0A56AAAAAAEKAABHzR1O8KNmTrjfGzlY2A75AAAAABxFAAA=
```

查看某个邮件的具体内容（指定ID）,包括完整的正文内容

(13)

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ReadXML -Path ews.xml
```

读取ews.xml文件中的命令，通过EWS SOAP发送

## 0x06 小结
---

本文介绍了两种访问Exchange资源的方法，开源工程ewsManage，便于后续的二次开发。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



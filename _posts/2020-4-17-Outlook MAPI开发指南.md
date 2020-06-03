---
layout: post
title: Outlook MAPI开发指南
---



## 0x00 前言
---

Outlook MAPI提供了一组访问Outlook的接口，用来扩展Outlook应用程序的开发，本文将会介绍Outlook MAPI的基本用法，开源一份Outlook MAPI的实现代码mapi_tool，便于后续的二次开发。

## 0x01 简介
---

本文将要介绍以下内容：

- 基本知识
- 使用Outlook MAPI访问Outlook资源
- 开源代码mapi_tool
- mapi_tool功能介绍
- 多种环境下的利用思路

## 0x02 基本知识
---

参考资料：

https://docs.microsoft.com/en-us/office/client-developer/outlook/mapi/outlook-mapi-reference

Outlook MAPI的使用前提：需要安装Outlook客户端

Outlook MAPI同EWS的区别：

- Outlook MAPI用来访问Outlook客户端中的资源
- EWS用来访问Exchange服务器中的资源

关于EWS的使用可以参考之前的文章[《Exchange Web Service(EWS)开发指南》](https://3gstudent.github.io/3gstudent.github.io/Exchange-Web-Service(EWS)%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97/)

Outlook客户端中的用户邮件存储在后缀名为ost的文件中，和Exchange服务器中的数据库保持一致

ost文件的默认保存位置：`%LOCALAPPDATA%\Microsoft\Outlook\`

MAPI主要包括以下三个功能：

- Address Books，设置E-mail type、protocol等参数
- Transport，文件的发送和接收
- Message Store，发送接收等信息的处理

## 0x03 使用Outlook MAPI访问Outlook资源
---

### 1.安装Outlook客户端并配置参数

### 2.启动Outlook客户端进行用户登录

### 3.使用C Sharp开发程序，实现读取收件箱邮件的功能

参考资料：

https://docs.microsoft.com/en-us/dotnet/api/microsoft.office.interop.outlook?view=outlook-pia

https://docs.microsoft.com/en-us/office/vba/api/outlook.namespace

开发环境：VS2015

新建工程，选择控制台应用程序，引用文件：`Microsoft.Office.Interop.Outlook.dll`

**注：**

安装Outlook客户端后，可在`C:\Windows\assembly\GAC_MSIL\Microsoft.Office.Interop.Outlook\`下获得Microsoft.Office.Interop.Outlook.dll

Microsoft.Office.Interop.Outlook.dll要同Outlook的版本保持一致

Microsoft.Office.Interop.Outlook.dll的`文件属性`-`Details`-`Product name`对应支持Outlook的版本，Product version对应具体的Outlook版本，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-17/2-1.png)

Product version对应具体的Outlook版本可参考：

https://docs.microsoft.com/en-us/Exchange/new-features/build-numbers-and-release-dates?redirectedfrom=MSDN&view=exchserver-2019

C Sharp代码示例：

```
using System;
using Microsoft.Office.Interop.Outlook;
namespace ConsoleApplication3
{
    class Program
    {
        static void Main(string[] args)
        {
            Microsoft.Office.Interop.Outlook.Application app = new Microsoft.Office.Interop.Outlook.Application();
            Microsoft.Office.Interop.Outlook.NameSpace ns = app.GetNamespace("MAPI");
            Microsoft.Office.Interop.Outlook.MAPIFolder inbox = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderInbox);
            Microsoft.Office.Interop.Outlook.Items items = inbox.Items;
            Console.WriteLine("Size:" + inbox.Items.Count);
            foreach (var item in items)
            {
                var mail = item as Microsoft.Office.Interop.Outlook.MailItem;
                if (mail != null)
                {
                    if(mail.UnRead==true)
                        Console.WriteLine("[+] UnRead Mail");
                    else
                        Console.WriteLine("[+] Mail");
                    Console.WriteLine("[*] Subject:" + mail.Subject);
                    Console.WriteLine("[*] From:" + mail.SenderName);
                    Console.WriteLine("[*] To:" + mail.To);
                    Console.WriteLine("[*] CC:" + mail.CC);
                    Console.WriteLine("[*] ReceivedTime:" + mail.ReceivedTime);                   
                    if(mail.Attachments.Count>0)
                    {
                        Console.WriteLine("[>] Attachments:" + mail.Attachments.Count);
                        Microsoft.Office.Interop.Outlook.Attachments attachments = mail.Attachments;
                        foreach (Microsoft.Office.Interop.Outlook.Attachment att in attachments)
                        {
                            Console.WriteLine("    Name:" + att.FileName);
                        }
                    }
                    Console.WriteLine("[*] Body:\r\n" + mail.Body);                                
                    Console.WriteLine("[*] OutlookVersion:" + mail.OutlookVersion);
                    Console.WriteLine("[*] EntryID:" + mail.EntryID);
                }
            }
        }
    }
}
```

代码执行后将会列举收件箱中的邮件，输出以下内容：

- 收件箱邮件个数
- 是否已读
- 主题
- 发件人
- 收件人
- 抄送
- 接收时间
- 附件名称
- 正文内容
- Outlook版本
- EntryID

代码执行后，Outlook客户端会弹出警告，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-17/2-2.png)

选择允许后，成功获得收件箱信息，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-17/2-3.png)

弹出警告的原因：当前系统的防病毒软件处于非活动状态或过期

参考资料：

https://support.microsoft.com/en-us/help/3189806/a-program-is-trying-to-send-an-e-mail-message-on-your-behalf-warning-i

#### 两种关闭方法：

1.开启并更新防病毒软件

2.修改注册表关闭警告

注册表位置：`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\<x.0>\Outlook\Security`

64位操作系统安装32位Office的注册表位置：`HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Office\<x.0>\Outlook\Security`

`<x.0>`同Office的版本保持一致，例如Office2010的值为`14.0`，Office2013的值为`15.0`

注册表项：`ObjectModelGuard`，类型：`REG_DWORD`，值为`2`


#### 在使用时需要注意的细节如下：

1.引用的Microsoft.Exchange.WebServices.dll要与Outlook客户端的版本保持一致

2.默认配置下，部分操作不会弹出警告

例如：

- 列出收件箱邮件个数
- 列出邮件主题
- 列出邮件接收时间
- 列出邮件附件名称

#### 3.如果后台没有运行Outlook客户端

通过程序可读取当前Outlook客户端中的资源，但是获取资源后还会弹框提示要求输入凭据，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-17/2-4.png)

如果选择了记住凭据，那么后续操作不会要求输入凭据，关于凭据的使用可以参考之前的文章[《渗透技巧——Windows中Credential Manager的信息获取》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E4%B8%ADCredential-Manager%E7%9A%84%E4%BF%A1%E6%81%AF%E8%8E%B7%E5%8F%96/)

## 0x04 开源实现代码mapi_tool
---

代码地址：https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/mapi_tool.cs

在编译上面，为了增加通用性，代码支持使用csc.exe进行编译

支持.Net 3.5或更高版本，编译命令：

```
C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe mapi_tool.cs /r:Microsoft.Office.Interop.Outlook.dll
or
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe mapi_tool.cs /r:Microsoft.Office.Interop.Outlook.dll
```

为了便于测试，我上传了Office2010下的[Microsoft.Office.Interop.Outlook.dll](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/Office14-Microsoft.Office.Interop.OutlookMicrosoft.Office.Interop.Outlook.dll)和Office2013下的[Microsoft.Office.Interop.Outlook.dll](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/Office15-Microsoft.Office.Interop.Outlook.dll)

在功能实现上，对是否弹出安全提示做了区分

不会弹出安全提示的功能：

- 获得所有文件夹中的邮件长度
- 获得配置信息，包括CurrentProfileName、ExchangeMailboxServerName、ExchangeMailboxServerVersion
- 列出指定位置的邮件，包括邮件主题、接收时间、附件中的文件名称和EntryID
- 列出指定位置的未读邮件，包括邮件主题、接收时间、附件中的文件名称和EntryID

会弹出安全提示的功能：

- 获得配置信息，包括Account-DisplayName、Account-SmtpAddress、Account-AutoDiscoverXml、Account-AccountType
- 获得联系人信息
- 获得GlobalAddress
- 列出指定位置的邮件，包括邮件主题、发件人、收件人、抄送、接收时间、附件中的文件名称、正文内容、Outlook版本和EntryID
- 列出指定位置的未读邮件，包括邮件主题、发件人、收件人、抄送、接收时间、附件中的文件名称、正文内容、Outlook版本和EntryID
- 保存指定邮件中的附件

在代码开发上，需要注意以下细节：

1. 保存附件时需要使用绝对路径
2. 获得联系人列表时，数组开始的位置为1，而不是0
3. 获得配置信息时，数组开始的位置为1，而不是0

## 0x05 多种环境下的利用思路
---

### 1.正在运行Outlook客户端

通过[mapi_tool](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/mapi_tool.cs)可以对Outlook客户端的资源进行访问，某些操作有可能会弹出安全提示

关闭安全提示的两种方法：

- 开启并更新防病毒软件
- 修改注册表关闭警告

#### 导出Outlook客户端所有邮件信息的方法：

(1)获得ost文件

ost文件的默认保存位置：`%LOCALAPPDATA%\Microsoft\Outlook\`

无法直接复制，提示文件被占用

可以使用Joe Bialek的[NinjaCopy](https://github.com/3gstudent/NinjaCopy)复制被占用的文件

(2)将ost文件转换成pst文件

工具有很多，这个提供一种：Advanced Exchange Recovery

(3)将pst文件导入Outlook客户端

### 2.没有启动Outlook客户端

通过[mapi_tool](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/mapi_tool.cs)可以对Outlook客户端的资源进行访问，某些操作有可能会弹出安全提示

如果执行需要同服务器进行交互的操作，例如获取配置信息，会弹框提示要求输入凭据，如果凭据管理器已经存储了对应的凭据，就不会弹框提示

查看已保存凭据的命令：

```
cmdkey /list
```

#### 导出Outlook客户端所有邮件信息的方法：

(1)获得ost文件

可直接复制ost文件

(2)将ost文件转换成pst文件

方法同上

(3)将pst文件导入Outlook客户端

方法同上

## 0x06 小结
---

本文介绍了使用Outlook MAPI访问Outlook资源的方法，开源代码[mapi_tool](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/mapi_tool.cs)，便于后续的二次开发。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





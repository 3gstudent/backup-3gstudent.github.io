---
layout: post
title: Exchange Web Service(EWS)开发指南2——SOAP XML message
---


## 0x00 前言
---

在之前的文章[《Exchange Web Service(EWS)开发指南》](https://3gstudent.github.io/3gstudent.github.io/Exchange-Web-Service(EWS)%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97/)开源了工具[ewsManage](https://github.com/3gstudent/ewsManage)，实现了对Exchange资源的访问。

本文将要更近一步，通过SOAP XML message实现利用hash对Exchange资源的访问。

## 0x01 简介
---

本文将要介绍以下内容：

- 利用hash访问Exchange资源的方法
- SOAP XML message的使用
- 开源Python实现代码
- 代码开发细节

## 0x02 利用hash访问Exchange资源的方法
---

在之前的文章《渗透技巧——Pass the Hash with Exchange Web Service》介绍了使用hash登录ews的方法

本文将要基于之前的研究，介绍登录ews以后访问Exchange资源的方法，所以在程序实现上会继续选择Python，使用EWS SOAP XML message访问Exchange的资源

对于EWS SOAP XML message的格式，有以下两种方法进行参考：

1.查找资料

https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/get-started-with-ews-client-applications

https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/ews-xml-elements-in-exchange

2.抓包分析

配置Wireshark，实现在Exchange Server上面捕获明文通信数据

使用[ewsManage](https://github.com/3gstudent/ewsManage)访问Exchange资源

捕获通信数据，能够获得不同操作对应的EWS SOAP XML message格式，示例如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-20/2-1.png)

## 0x03 SOAP XML message的使用
---

相比于EWS Managed API，SOAP XML message更底层，需要考虑的细节也更多一些

### 1.查看收件箱的邮件数量

发送的XML格式：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" 
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" 
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetFolder>
      <m:FolderShape>
        <t:BaseShape>Default</t:BaseShape>
      </m:FolderShape>
      <m:FolderIds>
        <t:DistinguishedFolderId Id="inbox"/>
      </m:FolderIds>
    </m:GetFolder>
  </soap:Body>
</soap:Envelope>
```

返回的内容格式：

```
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Header>
<h:ServerVersionInfo xmlns:h="http://schemas.microsoft.com/exchange/services/2006/types" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" MajorVersion="15" MinorVersion="0" MajorBuildNumber="847" MinorBuildNumber="31"/>
</s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<m:GetFolderResponse xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
<m:ResponseMessages>
<m:GetFolderResponseMessage ResponseClass="Success">
<m:ResponseCode>NoError</m:ResponseCode>
<m:Folders>
<t:Folder>
<t:FolderId Id="AQAOAHRlc3QxQHRlc3QuY29tAC4AAAOeuRYNE6D6Q70cD0Q/s0RIAQAXa2D52NzfQYSx7xK5j92NAAACAQ0AAAA=" ChangeKey="AQAAABYAAAAXa2D52NzfQYSx7xK5j92NAAAAABK9"/>
<t:DisplayName>Inbox</t:DisplayName>
<t:TotalCount>6</t:TotalCount>
<t:ChildFolderCount>0</t:ChildFolderCount>
<t:UnreadCount>4</t:UnreadCount>
</t:Folder>
</m:Folders>
</m:GetFolderResponseMessage>
</m:ResponseMessages>
</m:GetFolderResponse>
</s:Body>
</s:Envelope>
```

通过返回内容可以获得收件箱的邮件总数量，未读邮件数量

### 2.获得收件箱邮件信息

发送的XML格式：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>AllProperties</t:BaseShape>
        <t:BodyType>Text</t:BodyType>
      </m:ItemShape>
      <m:IndexedPageItemView MaxEntriesReturned="2147483647" Offset="0" BasePoint="Beginning" />
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="inbox" />
      </m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>
```

通过返回内容可以获得收件箱所有邮件的标题、收发关系、是否带有附件等，但无法显示正文内容和附件名称

通过返回内容能够获得每个邮件对应的ItemId和ChangeKey，进而获得邮件内容、附件的名称和Id

### 3.获得指定邮件的具体内容

发送的XML格式：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>AllProperties</t:BaseShape>
        <t:BodyType>Text</t:BodyType>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="{id}" ChangeKey="{key}" />
      </m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>
```

其中的`{id}`为指定邮件对应的ItemId，`{key}`为指定邮件对应的ChangeKey

通过返回内容可以获得邮件的详细信息，包括正文内容

### 4.获得指定邮件的附件名称

发送的XML格式：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Attachments" />
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="{id}" />
      </m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>
```

其中的`{id}`为指定邮件对应的ItemId

返回的内容格式：

```
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Header>
<h:ServerVersionInfo xmlns:h="http://schemas.microsoft.com/exchange/services/2006/types" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" MajorVersion="15" MinorVersion="0" MajorBuildNumber="847" MinorBuildNumber="31" Version="V2_8"/>
</s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<m:GetItemResponse xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
<m:ResponseMessages>
<m:GetItemResponseMessage ResponseClass="Success">
<m:ResponseCode>NoError</m:ResponseCode>
<m:Items>
<t:Message>
<t:ItemId Id="AAMkADc2OGUyODVmLWY3NjktNDY2MC1iMzllLTM4MThjYzU4OGQ4YgBGAAAAAACeuRYNE6D6Q70cD0Q/s0RIBwAXa2D52NzfQYSx7xK5j92NAAAAAAENAAAXa2D52NzfQYSx7xK5j92NAAAAAAztAAA=" ChangeKey="CQAAABYAAAAXa2D52NzfQYSx7xK5j92NAAAAAAzk"/>
<t:Attachments>
<t:FileAttachment>
<t:AttachmentId Id="AAMkADc2OGUyODVmLWY3NjktNDY2MC1iMzllLTM4MThjYzU4OGQ4YgBGAAAAAACeuRYNE6D6Q70cD0Q/s0RIBwAXa2D52NzfQYSx7xK5j92NAAAAAAENAAAXa2D52NzfQYSx7xK5j92NAAAAAAztAAABEgAQAJwa7iI1b4ZGoFo6F/TfALM="/>
<t:Name>1.docx</t:Name>
<t:Size>3013</t:Size>
<t:LastModifiedTime>2020-05-21T01:17:07</t:LastModifiedTime>
<t:IsInline>false</t:IsInline>
<t:IsContactPhoto>false</t:IsContactPhoto>
</t:FileAttachment>
</t:Attachments>
<t:HasAttachments>true</t:HasAttachments>
</t:Message>
</m:Items>
</m:GetItemResponseMessage>
</m:ResponseMessages>
</m:GetItemResponse>
</s:Body>
</s:Envelope>
```

通过返回内容可以获得附件的名称，但无法获得附件的内容

通过返回内容能够获得每个附件对应的Id，进而获得附件的类型和内容

### 5.获得指定附件的内容

发送的XML格式：

```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:GetAttachment>
      <m:AttachmentIds>
        <t:AttachmentId Id="{id}" />
      </m:AttachmentIds>
    </m:GetAttachment>
  </soap:Body>
</soap:Envelope>
```

其中的`{id}`为指定附件对应的Id

返回的内容格式：

```
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Header>
<h:ServerVersionInfo xmlns:h="http://schemas.microsoft.com/exchange/services/2006/types" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" MajorVersion="15" MinorVersion="0" MajorBuildNumber="847" MinorBuildNumber="31" Version="V2_8"/>
</s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<m:GetAttachmentResponse xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
<m:ResponseMessages>
<m:GetAttachmentResponseMessage ResponseClass="Success">
<m:ResponseCode>NoError</m:ResponseCode>
<m:Attachments>
<t:FileAttachment>
<t:AttachmentId Id="AAMkADc2OGUyODVmLWY3NjktNDY2MC1iMzllLTM4MThjYzU4OGQ4YgBGAAAAAACeuRYNE6D6Q70cD0Q/s0RIBwAXa2D52NzfQYSx7xK5j92NAAAAAAENAAAXa2D52NzfQYSx7xK5j92NAAAAAAzvAAABEgAQAK2JBdCt/lxColLkCuqo5hw="/>
<t:Name>1.txt</t:Name>
<t:ContentType>text/plain</t:ContentType>
<t:Content>{xxxxxxx}</t:Content>
</t:FileAttachment>
</m:Attachments>
</m:GetAttachmentResponseMessage>
</m:ResponseMessages>
</m:GetAttachmentResponse>
</s:Body>
</s:Envelope>
```

其中的`{xxxxxxx}`为base64编码后的内容，解码后可获得附件的内容

这是需要注意附件的类型，如果为text，表示文本类型，否则在保存附件时需要以二进制格式写入

## 0x04 开源Python实现代码
---

代码已开源，地址如下：

https://github.com/3gstudent/Homework-of-Python/blob/master/ewsManage.py

使用Python实现，脚本运行前需要安装Impacket

安装方法： `pip install Impacket`

分别支持对明文和ntlm hash的登录

在功能上基本上和[ewsManage](https://github.com/3gstudent/ewsManage)保持一致

支持以下功能：

- 查看收件箱邮件数量
- 查看发件箱邮件数量
- 查看收件箱邮件信息
- 查看发件箱邮件信息
- 查看指定邮件的具体信息
- 查看指定附件的信息
- 保存指定附件

用法示例：

(1)查看收件箱邮件数量(使用明文登录)

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 getfolderofinbox
```

(2)查看收件箱中的邮件信息(使用hash登录)

```
ewsManage.py 192.168.1.1 443 ntlmhash test.com user1 c5a237b7e9d8e708d8436b6148a25fa1 listmailofinbox
```

(3)查看指定邮件的具体信息

查看收件箱中的邮件信息：

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 listmailofinbox
```

结果保存为listmailofinbox.xml，从文件中获得对应邮件的ItemId和ChangeKey

查看指定邮件的具体信息：

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 getmail
```

接着输入邮件的ItemId和ChangeKey

最终结果保存为getmail.xml

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-20/3-1.png)

(4)保存指定附件

查看收件箱中的邮件信息：

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 listmailofinbox
```

结果保存为listmailofinbox.xml，从中获得对应邮件的ItemId

查看指定附件的信息：

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 getattachment
```

接着输入邮件的ItemId

命令行输出附件名称

结果保存为getattachment.xml，从文件中获得对应附件的Id

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-20/3-2.png)

保存指定邮件：

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 saveattachment
```

接着输入附件的Id

自动保存附件，区分是否为text格式

结果保存为saveattachment.xml

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-5-20/3-3.png)

## 0x05 小结
---

本文介绍了SOAP XML message的使用，开源代码[ewsManage.py](https://github.com/3gstudent/Homework-of-Python/blob/master/ewsManage.py)，实现了利用hash对Exchange资源的访问


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)








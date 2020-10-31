---
layout: post
title: 渗透基础——Exchange用户邮箱中的隐藏文件夹
---


## 0x00 前言
---

对于Exchange用户邮箱，可通过设置文件夹属性创建隐藏文件夹，用户使用owa网页登录和使用Outlook均无法查看隐藏文件夹中的内容。

站在渗透测试的角度，我们可以利用隐藏文件夹存储重要的信息，作为C2通信的数据通道。

本文将要介绍隐藏文件夹的使用方法，通过程序实现创建、访问和删除隐藏文件夹，结合利用思路给出防御建议。

## 0x01 简介
---

本文将要介绍以下内容：

- 隐藏文件夹的创建原理
- 隐藏文件夹的常用操作
- 使用EWS Managed API的实现代码
- 使用EWS SOAP XML message的实现代码
- 开源代码
- 防御检测

## 0x02 隐藏文件夹的创建原理
---

参考资料：

https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-work-with-hidden-folders-by-using-ews-in-exchange

对于Exchange用户邮箱，将文件夹的扩展属性`PidTagAttributeHidden`(0x10F4000B)设置为true时，该文件夹对于用户不可见

默认配置下，Exchange用户邮箱包括多个常用文件夹，例如收件箱、发件箱和草稿等，详细列表可参考：https://docs.microsoft.com/en-us/dotnet/api/microsoft.exchange.webservices.data.wellknownfoldername?view=exchange-ews-api#Microsoft_Exchange_WebServices_Data_WellKnownFolderName_MsgFolderRoot

我们可以在根目录或者任一文件夹(例如收件箱)下创建一个文件夹，将其扩展属性`PidTagAttributeHidden`(0x10F4000B)设置为true，那么这个文件夹就是隐藏文件夹，对于用户不可见。同时，隐藏文件夹下的所有邮件对用户也是不可见的。更进一步，隐藏文件夹下的邮件内容和附件内容对用户同样不可见。但是我们只要知道了隐藏文件夹的Id，就能够通过程序进行数据交互。

通过程序进行数据交互时，需要考虑以下操作：
(这里以在Inbox下创建隐藏文件夹为例)

- 在Inbox下创建文件夹
- 查看Inbox下的文件夹列表
- 在Inbox下创建隐藏文件夹
- 查看Inbox下的隐藏文件夹列表
- 查看指定文件夹(无论是否具有隐藏属性)下的邮件列表
- 在指定文件夹(无论是否具有隐藏属性)下创建邮件
- 删除指定文件夹
- 为指定邮件添加附件

## 0x03 使用EWS Managed API的实现代码
---

### 1.在Inbox下创建文件夹

```
private static void CreateFolderofInbox(ExchangeService service)
{
                Folder folder = new Folder(service);
                folder.DisplayName = "Custom Folder";
                folder.Save(WellKnownFolderName.Inbox);
                Console.WriteLine("[*] FolderId:" + folder.Id);
}
```

### 2.查看Inbox下的文件夹列表

```
private static void ListFolderofInbox(ExchangeService service)
{
                FindFoldersResults findResults = null;
                FolderView view = new FolderView(int.MaxValue) { Traversal = FolderTraversal.Deep };
                findResults = service.FindFolders(WellKnownFolderName.Inbox, view);
                foreach (Folder folder in findResults.Folders)
                {
                    Console.WriteLine("\r\n");
                    Console.WriteLine("[*]DisplayName:{0}", folder.DisplayName);
                    Console.WriteLine("[*]Id:{0}", folder.Id);
                    Console.WriteLine("[*]TotalCount:{0}", folder.TotalCount);
                }
}
```

### 3.在Inbox下创建隐藏文件夹

```
private static void CreateHiddenFolderofInbox(ExchangeService service)
{
                Folder folder = new Folder(service);
                folder.DisplayName = "Custom Hidden Folder";
                folder.Save(WellKnownFolderName.Inbox);
                Console.WriteLine("[*] Hidden FolderId:" + folder.Id);
                
                // Create an extended property definition for the PidTagAttributeHidden property.
                ExtendedPropertyDefinition isHiddenProp = new ExtendedPropertyDefinition(0x10f4, MapiPropertyType.Boolean);
                PropertySet propSet = new PropertySet(isHiddenProp);
                // Bind to a folder and retrieve the PidTagAttributeHidden property.
                Folder folderhidden = Folder.Bind(service, folder.Id, propSet);
                // Set the PidTagAttributeHidden property to true.
                folderhidden.SetExtendedProperty(isHiddenProp, true);
                // Save the changes.
                folderhidden.Update();
}
```

### 4.查看Inbox下的隐藏文件夹列表

```
private static void ListHiddenFolderofInbox(ExchangeService service)
{
                // Create an extended property definition for the PidTagAttributeHidden property.
                ExtendedPropertyDefinition isHiddenProp = new ExtendedPropertyDefinition(0x10f4, MapiPropertyType.Boolean);
                // Create a folder view to retrieve up to 100 folders and 
                // retrieve only the PidTagAttributeHidden and the display name.
                FolderView folderView = new FolderView(100);
                folderView.PropertySet = new PropertySet(isHiddenProp, FolderSchema.DisplayName);
                // Indicate a Traversal value of Deep, so that all subfolders are retrieved.
                folderView.Traversal = FolderTraversal.Deep;
                // Find all hidden folders under the MsgFolderRoot.
                // This call results in a FindFolder call to EWS.
                FindFoldersResults findFolder = service.FindFolders(WellKnownFolderName.Inbox,
                        new SearchFilter.IsEqualTo(isHiddenProp, true), folderView);
                // Display the folder ID and display name of each hidden folder.
                foreach (Folder folder in findFolder)
                {
                    Console.WriteLine("[*] DisplayName: {0}", folder.DisplayName);
                    Console.WriteLine("[*] FolderId: {0}", folder.Id);                    
                    Console.WriteLine("\r\n");
                }
}
```

### 5.查看指定文件夹(无论是否具有隐藏属性)下的邮件列表

```
private static void ListMailofFolder(FolderId folderId, ExchangeService service)
{
                IdString = folderId;
                Folder Folders = Folder.Bind(service, IdString);
                FindItemsResults<Item> findResults = null;
                ItemView view = new ItemView(int.MaxValue);
                PropertySet itempropertyset = new PropertySet(BasePropertySet.FirstClassProperties);
                itempropertyset.RequestedBodyType = BodyType.Text;
                view.PropertySet = itempropertyset;
                findResults = Folders.FindItems(view);
                foreach (Item item in findResults.Items)
                {
                    Console.WriteLine("\r\n");
                    if (item.Subject != null)
                    {
                        Console.WriteLine("[*]Subject:{0}", item.Subject);
                    }
                    else
                    {
                        Console.WriteLine("[*]Subject:<null>");
                    }

                    Console.WriteLine("[*]HasAttachments:{0}", item.HasAttachments);
                    if (item.HasAttachments)
                    {
                        EmailMessage message = EmailMessage.Bind(service, item.Id, new PropertySet(ItemSchema.Attachments));
                        foreach (Attachment attachment in message.Attachments)
                        {
                            FileAttachment fileAttachment = attachment as FileAttachment;
                            fileAttachment.Load();
                            Console.WriteLine(" - Attachments:{0}", fileAttachment.Name);
                        }
                    }
                    Console.WriteLine("[*]ItemId:{0}", item.Id);
                    Console.WriteLine("[*]DateTimeCreated:{0}", item.DateTimeCreated);
                    Console.WriteLine("[*]DateTimeReceived:{0}", item.DateTimeReceived);
                    Console.WriteLine("[*]DateTimeSent:{0}", item.DateTimeSent);
                    Console.WriteLine("[*]DisplayCc:{0}", item.DisplayCc);
                    Console.WriteLine("[*]DisplayTo:{0}", item.DisplayTo);
                    Console.WriteLine("[*]InReplyTo:{0}", item.InReplyTo);
                    Console.WriteLine("[*]Size:{0}", item.Size);
                    item.Load(itempropertyset);
                    if (item.Body.ToString().Length > 100)
                    {
                        item.Body = item.Body.ToString().Substring(0, 100);
                        Console.WriteLine("[*]MessageBody(too big,only output 100):{0}", item.Body);
                    }
                    else
                    {
                        Console.WriteLine("[*]MessageBody:{0}", item.Body);
                    }
                }
}
```

### 6.在指定文件夹(无论是否具有隐藏属性)下创建邮件

```
private static void CreateMail(FolderId folderId, ExchangeService service)
{
                EmailMessage msg = new EmailMessage(service);
                msg.Subject = "test mail";               
                msg.Save(folderId);
}
```

### 7.为指定邮件添加附件

```
private static void AddFileAttachment(ItemId id, string fileName, ExchangeService service)
{
                    EmailMessage message = EmailMessage.Bind(service, id);
                    message.Attachments.AddFileAttachment(fileName);
                    message.Update(ConflictResolutionMode.AlwaysOverwrite);
                    Console.WriteLine("\r\n[+]AddAttachment success");
}
```

### 8.删除指定文件夹

EWS Managed API不支持直接删除，需要构造XML格式的SOAP包

## 0x04 使用EWS SOAP XML message的实现代码
---

为了节省篇幅，只介绍`<soap:Body>`中的内容

### 1.在Inbox下创建文件夹

```
<m:CreateFolder>
  <m:ParentFolderId>
    <t:DistinguishedFolderId Id="inbox" />
  </m:ParentFolderId>
  <m:Folders>
    <t:Folder>
      <t:DisplayName>{name}</t:DisplayName>
    </t:Folder>
  </m:Folders>
</m:CreateFolder>
```

### 2.查看Inbox下的文件夹列表

```
<m:FindFolder Traversal="Deep">
  <m:FolderShape>
    <t:BaseShape>AllProperties</t:BaseShape>
  </m:FolderShape>
  <m:IndexedPageFolderView MaxEntriesReturned="2147483647" Offset="0" BasePoint="Beginning" />
  <m:ParentFolderIds>
    <t:DistinguishedFolderId Id="inbox" />
  </m:ParentFolderIds>
</m:FindFolder>
```

### 3.在Inbox下创建隐藏文件夹

这里需要发送三个数据包，依次为创建文件夹，添加隐藏属性和更新隐藏属性

创建文件夹：

```
   <m:CreateFolder>
      <m:ParentFolderId>
        <t:DistinguishedFolderId Id="inbox" />
      </m:ParentFolderId>
      <m:Folders>
        <t:Folder>
          <t:DisplayName>{name}</t:DisplayName>
        </t:Folder>
      </m:Folders>
    </m:CreateFolder>
```

添加隐藏属性：

```
<m:GetFolder>
  <m:FolderShape>
    <t:BaseShape>IdOnly</t:BaseShape>
    <t:AdditionalProperties>
      <t:ExtendedFieldURI PropertyTag="4340" PropertyType="Boolean" />
    </t:AdditionalProperties>
  </m:FolderShape>
  <m:FolderIds>
    <t:FolderId Id="{id}" ChangeKey="{key}" />
  </m:FolderIds>
</m:GetFolder>
```

更新隐藏属性：

```
   <m:UpdateFolder>
      <m:FolderChanges>
        <t:FolderChange>
          <t:FolderId Id="{id}" ChangeKey="{key}" />
          <t:Updates>
            <t:SetFolderField>
              <t:ExtendedFieldURI PropertyTag="4340" PropertyType="Boolean" />
              <t:Folder>
                <t:ExtendedProperty>
                  <t:ExtendedFieldURI PropertyTag="4340" PropertyType="Boolean" />
                  <t:Value>true</t:Value>
                </t:ExtendedProperty>
              </t:Folder>
            </t:SetFolderField>
          </t:Updates>
        </t:FolderChange>
      </m:FolderChanges>
    </m:UpdateFolder>
```

### 4.查看Inbox下的隐藏文件夹列表

```
   <m:FindFolder Traversal="Deep">
      <m:FolderShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:ExtendedFieldURI PropertyTag="4340" PropertyType="Boolean" />
          <t:FieldURI FieldURI="folder:DisplayName" />
        </t:AdditionalProperties>
      </m:FolderShape>
      <m:IndexedPageFolderView MaxEntriesReturned="100" Offset="0" BasePoint="Beginning" />
      <m:Restriction>
        <t:IsEqualTo>
          <t:ExtendedFieldURI PropertyTag="4340" PropertyType="Boolean" />
          <t:FieldURIOrConstant>
            <t:Constant Value="true" />
          </t:FieldURIOrConstant>
        </t:IsEqualTo>
      </m:Restriction>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="inbox" />
      </m:ParentFolderIds>
    </m:FindFolder>
```

### 5.查看指定文件夹(无论是否具有隐藏属性)下的邮件列表

```
<m:FindItem Traversal="Shallow">
  <m:ItemShape>
    <t:BaseShape>AllProperties</t:BaseShape>
    <t:BodyType>Text</t:BodyType>
  </m:ItemShape>
  <m:IndexedPageItemView MaxEntriesReturned="2147483647" Offset="0" BasePoint="Beginning" />
  <m:ParentFolderIds>
    <t:FolderId Id="{id}" />
  </m:ParentFolderIds>
</m:FindItem>
```


### 6.在指定文件夹(无论是否具有隐藏属性)下创建邮件

```
<m:CreateItem MessageDisposition="SaveOnly">
  <m:SavedItemFolderId>
    <t:FolderId Id="{id}" />
  </m:SavedItemFolderId>
  <m:Items>
    <t:Message>
      <t:Subject>test mail</t:Subject>
    </t:Message>
  </m:Items>
</m:CreateItem>
```

### 7.为指定邮件添加附件

```
<m:CreateAttachment>
  <m:ParentItemId Id="{id}" ChangeKey="{key}"/>
  <m:Attachments>
    <t:FileAttachment>
      <t:Name>{name}</t:Name>
      <t:Content>{data}</t:Content>
    </t:FileAttachment>
  </m:Attachments>
</m:CreateAttachment>
```

### 8.删除指定文件夹

```
<m:DeleteItem DeleteType="HardDelete" xmlns="https://schemas.microsoft.com/exchange/services/2006/messages">
  <m:ItemIds>
    <t:ItemId Id="{id}"/>
  </m:ItemIds>
</m:DeleteItem>
```

## 0x05 开源代码
---

### 1.使用EWS Managed API

https://github.com/3gstudent/ewsManage

使用示例

(1)在Inbox下创建隐藏文件夹test1

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode CreateHiddenFolderofInbox -Name test1
```

获得文件夹对应的FolderId:`AAMkADc4YjRlNDc1LWI0YjctNDEzZi1hNTQ5LWZkYWY0ZGZhZDM0NgAuAAAAAABEBlGH6URWQp6Nlg9RxLmyAQA1ZCfAg9a0Sq75no2JOzsqAAAAA1FUAAA=`

(2)查看Inbox下的隐藏文件夹

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ListHiddenFolder -Folder Inbox
```

(3)在隐藏文件夹test1下创建测试邮件

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode CreateTestMail -Id AAMkADc4YjRlNDc1LWI0YjctNDEzZi1hNTQ5LWZkYWY0ZGZhZDM0NgAuAAAAAABEBlGH6URWQp6Nlg9RxLmyAQA1ZCfAg9a0Sq75no2JOzsqAAAAA1FUAAA=
```

(4)查看隐藏文件夹test1下的所有邮件

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ListMailofFolder -Id AAMkADc4YjRlNDc1LWI0YjctNDEzZi1hNTQ5LWZkYWY0ZGZhZDM0NgAuAAAAAABEBlGH6URWQp6Nlg9RxLmyAQA1ZCfAg9a0Sq75no2JOzsqAAAAA1FUAAA=
```

获得测试邮件对应的ItemId:`AAMkADc4YjRlNDc1LWI0YjctNDEzZi1hNTQ5LWZkYWY0ZGZhZDM0NgBGAAAAAABEBlGH6URWQp6Nlg9RxLmyBwA1ZCfAg9a0Sq75no2JOzsqAAAAA1FUAAA1ZCfAg9a0Sq75no2JOzsqAAAAA1FVAAA=`

(5)向测试邮件添加附件

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode AddAttachment -Id AAMkADc4YjRlNDc1LWI0YjctNDEzZi1hNTQ5LWZkYWY0ZGZhZDM0NgAuAAAAAABEBlGH6URWQp6Nlg9RxLmyAQA1ZCfAg9a0Sq75no2JOzsqAAAAA1FUAAA= -AttachmentFile c:\test\1.exe
```

(6)读取测试邮件的内容

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ViewMail -Id AAMkADc4YjRlNDc1LWI0YjctNDEzZi1hNTQ5LWZkYWY0ZGZhZDM0NgAuAAAAAABEBlGH6URWQp6Nlg9RxLmyAQA1ZCfAg9a0Sq75no2JOzsqAAAAA1FUAAA=
```

(7)保存测试邮件中的附件

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode SaveAttachment -Id AAMkADc4YjRlNDc1LWI0YjctNDEzZi1hNTQ5LWZkYWY0ZGZhZDM0NgAuAAAAAABEBlGH6URWQp6Nlg9RxLmyAQA1ZCfAg9a0Sq75no2JOzsqAAAAA1FUAAA=
```

(8)删除测试邮件

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode DeleteMail -Id AAMkADc4YjRlNDc1LWI0YjctNDEzZi1hNTQ5LWZkYWY0ZGZhZDM0NgAuAAAAAABEBlGH6URWQp6Nlg9RxLmyAQA1ZCfAg9a0Sq75no2JOzsqAAAAA1FUAAA=
```


### 2.使用EWS SOAP XML message

https://github.com/3gstudent/Homework-of-Python/blob/master/ewsManage.py

(1)在Inbox下创建隐藏文件夹test2

创建文件夹：

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 createfolderofinbox 
```

获得Id:`AAMkADc4YjRlNDc1LWI0YjctNDEzZi1hNTQ5LWZkYWY0ZGZhZDM0NgAuAAAAAABEBlGH6URWQp6Nlg9RxLmyAQA1ZCfAg9a0Sq75no2JOzsqAAAAA1U+AAA=，ChangeKey:AQAAABYAAAA1ZCfAg9a0Sq75no2JOzsqAAAAAGE/`

添加隐藏属性：

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 SetHiddenPropertyType
```

更新隐藏属性：

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 UpdateHiddenPropertyType
```

(2)查看Inbox下的隐藏文件夹

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 listhiddenfolderofinbox
```

(3)在隐藏文件夹test1下创建测试邮件

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 createtestmail
```

(4)查看隐藏文件夹test1下的所有邮件

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 listmailoffolder
```

(5)向测试邮件添加附件

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 createattachment
```

(6)读取测试邮件的内容

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 getmail
```

(7)保存测试邮件中的附件

获得附件对应的Id:

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 getattachment 
```

保存附件：

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 saveattachment 
```

(8)删除测试邮件

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 deletemail
```

(9)删除测试邮件隐藏文件夹test1

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 deletefolder
```

## 0x06 防御检测
---

1.通过程序查看是否存在隐藏文件夹

例如：

```
ewsManage.exe -CerValidation No -ExchangeVersion Exchange2013_SP1 -u test1 -p test123! -ewsPath https://test.com/ews/Exchange.asmx -Mode ListHiddenFolder -Folder Inbox

ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 listhiddenfolderofinbox
```

2.查看邮件用户上次登录时间

使用Exchange Server PowerShell：

```
Get-MailboxDatabase | Get-MailboxStatistics |fl DisplayName,LastLogonTime
```

3.查看ews访问日志

默认位置：`C:\inetpub\logs\LogFiles\W3SVC1`，搜索关键词`/EWS/Exchange.asmx`

## 0x07 小结
---

本文介绍了Exchange用户邮箱隐藏文件夹的使用方法，分别介绍使用EWS Managed API和EWS SOAP XML message实现创建、访问和删除隐藏文件夹的方法，开源代码[ewsManage](https://github.com/3gstudent/ewsManage)和[ewsManage.py](https://github.com/3gstudent/Homework-of-Python/blob/master/ewsManage.py)，结合利用思路给出防御建议



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)













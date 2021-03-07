---
layout: post
title: 利用zimbra clientuploader实现文件上传
---


## 0x00 前言
---

Zimbra邮件服务器的管理面板支持文件上传的功能，通常情况下，我们通过管理员用户登录管理面板，使用名为Client Upload的功能即可将文件上传至Zimbra邮件服务器的downloads目录。

这里面我们需要进一步的思考，实现文件上传的方法有哪些？如何禁用文件上传的功能？能否通过第三方扩展或者插件实现文件上传？能否绕过？

本文仅在技术研究的角度回答以上问题。

## 0x01 简介
---

本文将要介绍以下内容：

- 原理分析
- 通过zimbraAdmin管理面板实现文件上传
- 通过zimlet实现文件上传
- 通过Zimbra SOAP API实现文件上传
- 利用思路
- 防御建议

## 0x02 原理分析
---

Zimbra邮件服务器通过`com_zimbra_clientuploader`实现文件上传的功能

我们可以在Zimbra邮件服务器的安装文件中找到文件上传功能对应的文件

对应安装目录下的文件为`/opt/zimbra/lib/ext/com_zimbra_clientuploader/com_zimbra_clientuploader.jar`

为了查看具体的实现代码，这里需要对jar文件进行反编译

反编译的功能可以使用JD-GUI，地址：http://java-decompiler.github.io/

使用JD-GUI打开`com_zimbra_clientuploader.jar`，文件结构如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/2-1.png)

(1)文件上传功能的主函数

对应文件`ClientUploaderHandler.class`

(2)文件上传功能的写入位置

对应文件`ClientUploaderLC.class`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/2-2.png)

写入位置为`/opt/zimbra/jetty/webapps/zimbra/downloads`

(3)响应代码对应的内容

对应文件`ZClientUploaderResoCode.class`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/2-3.png)

内容如下：

```
  SUCCEEDED(1L, "Succeeded"),
  FAILED(20000000L, "Upload failed"),
  NOT_A_FILE(20000001L, "The request does not upload a file"),
  REPO_INVALID(20000002L, "Invalid directory for client repo or temporary files."),
  REPO_NO_WRITE(20000003L, "No write permission on directory for client repo or temporary files"),
  SAVE_ERROR(20000004L, "Failed to save the upload file"),
  PARSE_REQUEST_ERROR(20000005L, "Failed to parse the request"),
  FILE_EXCEED_LIMIT(20000006L, "File size exceeds allowed max size"),
  MISSING_LIB_PATH(30000001L, "Cannot find lib directory so cannot execute zmupdatedownload"),
  UPDATE_LINK_FAILED(30000002L, "Failed to update links in downloads/index.html"),
  NO_PERMISSION(40000001L, "Permission denied");
```

可以用来判断上传失败的原因

综合以上代码，我们可以得出以下推断：

1. `com_zimbra_clientuploader`作为Zimbra的一部分，保存在安装目录下，实现文件上传的功能，提供文件上传的接口
2. 通过Zimbra管理面板能够安装第三方插件，一种是扩展Zimbra管理面板的功能，对应名称为Admin Extensions，另一种是扩展客户端的功能，对应名称为Zimlets
3. 无论是Admin Extensions还是Zimlets，实现文件上传都要调用`com_zimbra_clientuploader`提供的文件上传接口。反过来说，只要禁用了`com_zimbra_clientuploader`提供的文件上传接口，那么使用Admin Extensions和Zimlets都无法实现文件上传。

下面分别介绍三种实现文件上传的方法并验证我们的推断。

## 0x03 通过zimbraAdmin管理面板实现文件上传
---

通过管理员用户登录管理面板，选择`Tools and Migration`->`Client Upload`，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/3-1.png)

上传成功后，Zimbra邮件服务器的保存路径：`/opt/zimbra/jetty/webapps/zimbra/downloads`


## 0x04 通过zimlet实现文件上传
---

Zimlets用来扩展客户端的功能，也就是说，当安装了Zimlets，使用普通用户登录邮箱时，就能够访问已安装的Zimlets

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/3-2.png)

Zimlets的开发可以参考https://wiki.zimbra.com/wiki/Zimlet_Developers_Guide:Example_Zimlets

**注：**

Zimlets支持运行jsp文件，但是默认关闭该功能

查看是否开启的命令：

```
zmprov gs <mail domain name> | grep zimbraZimletJspEnabled
```

启用Zimbra执行jsp的命令：

```
zmprov ms <mail domain name> zimbraZimletJspEnabled TRUE
zmcontrol restart
```

这里举例进行说明，使用示例`Zimlets Simple_JSP_via_Action`，下载地址：

https://wiki.zimbra.com/wiki/ZCS_6.0:Zimlet_Developers_Guide:Examples:Simple_JSP_via_Action

通过Zimbra管理面板进行安装，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/3-3.png)

选择安装文件`com_zimbra_example_simplejspaction.zip`

使用普通用户登录邮箱，在Zimlets下能够访问已安装的Zimlets，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/3-4.png)

点击后，发现jsp文件能够访问，但是无法运行，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/3-5.png)

这里我找到了一种有趣的文件上传方法：虽然无法运行jsp文件，但是可以运行html文件，那么我们何不通过html实现文件上传呢？

新建文件upload.html，内容如下：

```
<html>
<body>
<form method=POST ENCTYPE="multipart/form-data" ACTION="https://<url>/service/extension/clientUploader/upload" METHOD=POST>
<input type="file" name="xxx" />
<input type="submit" value="submit" />
</form>
</body>
</html>
```

其中，`<url>`需要替换为Zimbra邮件服务器对应的url

将upload.html压缩到`com_zimbra_example_simplejspaction.zip`中，重新通过Zimbra管理面板进行安装

使用普通用户登录邮箱，访问`https://<url>/zimlet/com_zimbra_example_simplejspaction/upload.html`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/3-6.png)

直接上传会失败，这是因为普通用户没有上传文件的权限

这里可以通过修改Cookie的方式，实现文件上传

添加Cookie的名称为`ZM_ADMIN_AUTH_TOKEN`，Cookie的数值可在登录Zimbra管理面板后的Cookie中获得

同时要删除普通用户的Cookie，对应名称为`ZM_AUTH_TOKEN`

完整的Cookie格式如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/3-7.png)

上传成功后，在Zimbra邮件服务器的`/opt/zimbra/jetty/webapps/zimbra/downloads`下可以看到对应的文件

为了进一步利用，我们可以尝试添加一个隐藏的zimlet，这里以名称`com_zimbra_test`为例

`com_zimbra_test.xml`的文件内容如下：

```
<zimlet name="com_zimbra_test"
        version="1.0"
        description="Zimlet test">
    <zimletPanelItem label=" " icon="zimbraIcon">
        <toolTipText> </toolTipText>
    </zimletPanelItem>
</zimlet>
```


安装后，在用户邮箱内的Zimlets中显示为空行，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-2-1/3-8.png)

## 0x05 通过Zimbra SOAP API实现文件上传
---

代码可参考：

https://github.com/3gstudent/Homework-of-Python/blob/master/Zimbra_SOAP_API_Manage.py

细节可参考之前的文章《Zimbra-SOAP-API开发指南2》


## 0x06 验证推断
---

修改Zimbra邮件服务器`/opt/zimbra/jetty/webapps/zimbra/downloads`目录的用户访问权限，将`Create and delete files`修改为`List files only`

再次使用以上三种方法上传文件，均失败，返回结果如下：

```
<html><head></head><body onload="window.parent._uploadManager.loaded(20000003,'Upload failed');"></body></html>
```

`20000003`对应的内容为`"No write permission on directory for client repo or temporary files"`，表示权限不够

由此验证了之前的推论：

只要禁用了com_zimbra_clientuploader提供的文件上传接口，那么使用Admin Extensions和Zimlets都无法实现文件上传。

## 0x07 防御建议
---

禁用Zimbra邮件服务器`/opt/zimbra/jetty/webapps/zimbra/downloads`目录的用户写入权限

## 0x08 小结
---

本文介绍了Zimbra邮件服务器三种实现文件上传的方法，得出结论：只要禁用了`com_zimbra_clientuploader`提供的文件上传接口，去除用户的写权限，使用Admin Extensions和Zimlets都无法实现文件上传。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)




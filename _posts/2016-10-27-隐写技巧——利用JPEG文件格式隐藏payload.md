---
layout: post
title: 隐写技巧——利用JPEG文件格式隐藏payload
---

## 0x00 前言
---

继续对图片隐写技巧的学习，这次是对JPEG文件格式的学习和理解。同PNG文件的格式对比，JPEG文件相对简单，读取其中隐藏payload的方式大同小异，两者区别在于文件格式不同，可供利用的细节存在差异。

### 本文相关工具：

- 16进制编辑器：`Hex Editor`

- 隐写检测：`Stegdetect`

下载地址：

https://github.com/abeluck/stegdetect

- 编辑Exit信息：`MagicEXIF`

下载地址：

http://www.magicexif.com/

- 分析JPEG图片格式：`JPEGsnoop`

下载地址：

http://www.impulseadventure.com/photo/jpeg-snoop.html


## 0x01 相关概念
---

### JPEG文件

JPEG是Joint Photographic Experts Group(联合图像专家组)的缩写

支持有陨压缩

不支持透明

不支持动画

非矢量

**JEPG同JPG的区别**

JPEG既可作为扩展名，又能代表文件格式

JPG是JPEG的简写，代表扩展名

JPEG和JPG基本上是没有区别的，它们的格式也是通用的



### 色彩模型

采用YCrCb色彩模型，更适合图形压缩，而不是RGB

- Y表示亮度
- Cr表示红色分量
- Cb表示蓝色分量

人眼对图片上的亮度Y的变化远比色度C的变化敏感. 如果每个点保存一个8bit的亮度值Y, 每2x2个点保存一个CrCb值, 图象在肉眼中的感觉不会起太大的变化，而且节省一半的空间

RGB模型4个点需要4x3=12字节

YCrCb模型4个点需要4+2=6字节


**[R G B] -> [Y Cb Cr] 转换：**

Y = 0.299*R + 0.587*G + 0.114*B  

Cb =  - 0.1687*R - 0.3313*G + 0.5   *B + 128

Cr =    0.5   *R - 0.4187*G - 0.0813*B + 128

**[Y,Cb,Cr] -> [R,G,B] 转换：**

R = Y                    + 1.402  *(Cr-128)

G = Y - 0.34414*(Cb-128) - 0.71414*(Cr-128)

B = Y + 1.772  *(Cb-128)


### 文件格式

JPEG文件大体上可以分成两个部分：标记码和压缩数据

**标记码：**

由两个字节构成，第一个字节是固定值`0xFF`，后一个字节则根据不同意义有不同数值

在每个标记码之前可以添加数目不限的无意义的0xFF填充，连续的多个0xFF可以被理解为一个0xFF，并表示一个标记码的开始

常见的标记码：

- SOI  0xD8 图像开始
- APP0 0xE0  应用程序保留标记0
- APPn 0xE1 - 0xEF  应用程序保留标记n(n=1～15)
- DQT  0xDB 量化表(Define Quantization Table)
- SOF0 0xC0 帧开始(Start Of Frame)
- DHT  0xC4 定义Huffman表(Define Huffman Table)
- DRI  0XDD 定义差分编码累计复位的间隔(Define Restart Interval)
- SOS  0xDA 扫描开始(Start Of Scan)
- EOI  0xD9 图像结束

**压缩数据：**

前两个字节保存整个段的长度，包括这两个字节

**注：**

这个长度的表示方法按照高位在前，低位在后，与PNG文件的长度表示方法不同

例如长度是0x12AB，存储顺序为0x12，0xAB


### Exif信息

Exif文件是JPEG文件的一种，遵从JPEG标准，只是在文件头信息中增加了拍摄信息和索引图

用相机拍出来的jpeg都会有这个信息

储存在APP1(0xFFE1)数据区中

接下来两字节保存APP1数据区(即Exif数据区)的大小

接着为Exif Header，固定结构：0x457869660000

后面为Exif的数据

查看Exif信息的工具：`exiftool`

**下载地址：**

https://github.com/alchemy-fr/exiftool

编辑Exit信息的工具：`MagicEXIF`

**下载地址：**

http://www.magicexif.com/

添加操作如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/3-1.png)




## 0x02 常见隐写方法
---

- DCT加密

- LSB加密

- DCT LSB

- Average DCT

- High  Capacity  DCT

- High  Capacity  DCT - Algorithm


以上隐写方法引用自：

https://www.blackhat.com/docs/asia-14/materials/Ortiz/Asia-14-Ortiz-Advanced-JPEG-Steganography-And-Detection.pdf

目前已经有很多开源的工具能够实现以上高级的隐写方法

**常见隐写工具：**

- JSteg
- JPHide
- OutGuess
- Invisible Secrets
- F5
- appendX
- Camouflage

当然，对应的隐写检测工具也出现了很久

比如：`Stegdetect`

**下载地址：**

https://github.com/abeluck/stegdetect


## 0x03 利用JPEG文件格式隐藏Payload
---

接下来介绍在学习文件格式后产生的一些隐藏思路：

### 1、直接在尾部添加数据

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/4-1.png)

如图，不会影响图片的正常浏览


### 2、插入自定义COM注释

COM注释为0xff和0xfe

插入数据0x11111111

长度为0x04

总长度为0x06

完整的十六进制格式为`0xffff000611111111`

插入位置为DHT前面，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/4-2.png)


插入后如图，不影响图片的正常查看

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/4-3.png)

将ff改为fe，如图，同样不影响图片的正常查看

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/4-4.png)

### 3、插入可被忽略的标记码

原理同上，标志码换成可被忽略的特殊值

例如：

- 00
- 01 *TEM
- d0 *RST0
- dc DNL
- ef APP15

经测试以上标识码均不影响图片的正常查看


### 4、修改DQT

DQT: Define Quantization Table

标识码为0xdb

接下来两字节表示长度

接下来一字节表示QT设置信息

前4bit为QT号

后4bit为QT精度,0=8bit,否则为16bit

最后是QT信息，长度为64的整数倍

查看测试图片的DQT信息，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/4-5.png)


长度为0x43，十进制为67

00表示QT号为0，精度为8bit

接着64字节为QT信息字节

**注：**

此处DQT格式参考自http://www.opennet.ru/docs/formats/jpeg.txt


尝试将这64字节替换，如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/4-6.png)


前后对比如图，能够发现图片的变化

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/4-7.png)

如果仅仅是调整其中部分字节，改为payload，那么能有多大区别呢，对比如图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/4-8.png)


依次类推，可供修改的位置还有很多

## 0x04 检测和识别
---

对于以上的隐藏方法，借助jpeg图片格式分析工具就能发现其中的痕迹

比如`JPEGsnoop`

**下载地址：**

http://www.impulseadventure.com/photo/jpeg-snoop.html

支持如下文件的格式分析：

- .JPG - JPEG Still Photo
- .THM - Thumbnail for RAW Photo / Movie Files
- .AVI* - AVI Movies
- .DNG - Digital Negative RAW Photo
- .PSD - Adobe Photoshop files
- .CRW, .CR2, .NEF, .ORF, .PEF - RAW Photo
- .MOV* - QuickTime Movies, QTVR (Virtual Reality / 360 Panoramic)
- .PDF - Adobe PDF Documents

**实际测试：**

如下图，发现了图片中添加的COM注释

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/5-1.png)


如下图，通过查看DQT的数据识别添加的payload，0x11对应的十进制为17

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/5-2.png)


同样，JPEGsnoop能够解析jpeg图片的EXIF信息，如下图

![Alt text](https://raw.githubusercontent.com/3gstudent/BlogPic/master/2016-10-27/5-3.png)

**注：**

为便于测试，截图中的以下数值通过MagicEXIF软件手动添加：

```
  EXIF Make/Model:     OK   [test] [???]
  EXIF Makernotes:     NONE
  EXIF Software:       OK   [MagicEXIF Metadata Codec 1.02]
```


## 0x05 补充
---

相比于png文件，由于jpeg文件没有对图像数据的校验位，所以在jpeg文件中添加payload简单了很多

下载JPEG图片解析并执行payload的方法不再介绍

(可参照https://3gstudent.github.io/3gstudent.github.io/%E9%9A%90%E5%86%99%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8PNG%E6%96%87%E4%BB%B6%E6%A0%BC%E5%BC%8F%E9%9A%90%E8%97%8FPayload/)

## 0x06 小结
---

本文对JPEG的格式进行介绍，着重分析如何根据JPEG的文件格式，利用特定标志码隐藏payload，这种方式虽然不会影响图片的正常浏览，但是借助于格式分析软件仍能够发现其中的细节。介绍JPEG格式的官方文档里面待学习的内容还有很多，认识越深，可供研究的技巧将会更多。


---


[LEAVE A REPLY](https://github.com/3gstudent/feedback/issues/new)



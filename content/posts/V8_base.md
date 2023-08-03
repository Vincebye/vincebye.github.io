---
title: "V8_base"
date: 2023-08-03T14:23:27+08:00
draft: false
---


# v8
## 前言

v8是chrome浏览器的JavaScript解析引擎，v8编译后二进制名称叫d8而不是v8

## 基础知识

[](https://segmentfault.com/a/1190000037435824)

介绍了V8中各个组件的功能以及工作流程

### 解析JS语句的基本流程
**![](https://lh4.googleusercontent.com/DdxdIvDsEfcpgly1PY_Rrd2kPsUO89AIC-2Bg8QrG-x3F0YQhostDv1DBUBdhFEWIiYrkE3D7FU9KBXoa6TLzm9e0j5QksYCAeS7soxmZwLXa3CM5uSvMCi5PBJl2xWvN0hpszGZ-IVXhA92ZsSRSYHBgHCZXmW3cR3lSw_SrN5of7Fyi0DIQ6jsNzqe)**
![[Pasted image 20221014222038.png]]

![[Pasted image 20221014222052.png]]
v8在读取js语句后，首先将这一条语句解析为语法树，然后通过解释器将语法树变为中间语言的Bytecode字节码，经过优化将字节码转换为机器码来执行。

```jsx
v8读取js语句→语法树→中间语言的Bytecode字节码+优化→机器码
```

### JSArray内存展示
| JSArray      | ElementsKind           |
| ------------ | ---------------------- |
| [1,2,3]      | PACKED_SMI_ELEMENTS    |
| [1,,,,,,2,3] | HOLEY_SMI_EMELENTS     |
| [1.1,1.2]    | PACKED_DOUBLE_ELEMENTS |
| [{},1.1,2]             | PACKED_ELEMENTS                       |

### JIT优化
为了加快解析过程，v8会记录下某条语法树的执行次数，当v8发现某条语法树执行次数超过一定阀值后，就会将这段语法树直接转换为机器码。后续再调用这条js语句时，v8会直接调用这条语法树对应的机器码，而不用再转换为ByteCode字节码，这样就大大加快了执行速度

### v8对象结构

以上面的数组对象b为例，通过job命令可以看到一个对象在内存中布局大致如下所示：

[Untitled](https://www.notion.so/a2cb3f557ff94b1482a3389148f79949)

### diff代码

diff文件的相关内容

[读懂diff](http://www.ruanyifeng.com/blog/2012/08/how_to_read_diff.html)

## V8调试
 v8 中内置了一些 runtime 函数，可以在启动 d8 时追加`--allow-natives-syntax`参数来启动内置函数的使用。
`%PrepareFunctionForOptimization` 是 v8 众多内置函数中的其中一个。该函数可以为 JIT 优化函数前做准备，确保 JSFunction 存在 FeedbackVector等相关的结构（在必要时甚至会先编译该函数）。
```
// 调用链如下  
Runtime_PrepareFunctionForOptimization  
bool EnsureFeedbackVector(Handle<JSFunction> function)  
void JSFunction::EnsureFeedbackVector(Handle<JSFunction> function)
```

由于该内置函数只是为对应的 JSFunction **准备 FeedbackVector**（请记住这个准备操作），因此**可以通过多次调用目标函数**来准备 FeedbackVector，替换该内置函数的调用。
## 内存结构

```
 elements  ----> +------------------------+
                  |          MAP           +<---------+
                  +------------------------+          |
                  |      element 1         |          |
                  +------------------------+          |
                  |      element 2         |          |
                  |      ......            |          |
                  |      element n         |          |
ArrayObject  ---->-------------------------+          |
                  |      map               |          |
                  +------------------------+          |
                  |      prototype         |          |
                  +------------------------+          |
                  |      elements          |          |
                  |                        +----------+
                  +------------------------+
                  |      length            |
                  +------------------------+
                  |      properties        |
                  +------------------------+
```

## 切换版本
```
git checkout 8.1.307  
gclient sync  
tools/dev/v8gen.py x64.debug  
ninja -C out.gn/x64.debug
```
## 环境搭建

```jsx
sudo apt-get update
sudo apt install build-essential
sudo apt-get update && sudo apt-get install pkg-config
sudo apt install python
//git代理配置
//git config --global http.proxy <http://ip>:port
//git config --global http.proxy http://192.168.174.1:7890
git config --global http.proxy http://172.26.240.1:7890
//环境变量
export http_proxy="http://192.168.174.1:7890"
//export http_proxy="http://172.26.240.1:7890"
export https_proxy=$http_proxy

//安装depot_tools
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
//echo 'export PATH=$PATH:"/path/to/depot_tools"' >> ~/.bashrc
echo 'export PATH=$PATH:"/home/v/depot_tools"' >> ~/.bashrc

//安装ninja
git clone https://github.com/ninja-build/ninja.git
cd ninja && ./configure.py --bootstrap && cd ..
//echo 'export PATH=$PATH:"/path/to/ninja"' >> ~/.bashrc
echo 'export PATH=$PATH:"/home/v/ninja"' >> ~/.bashrc

//编译v8
bash
fetch v8
cd v8
git reset --hard [commit hash with vulnerability]
//如果编译最新版的话，就不用这行命令
//如果是要调洞的话，就要在这里切到有漏洞的那个commit
gclient sync
//gclient sync 用来下载一些其他需要的东西，
//这个还需要curl的代理，之前也已经在环境变量配置了
tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug
//如果只是想编译d8的话（这样更快），最后一个命令后面加个d8的参数ninja -C out.gn/x64.debug d8
//编译release版本的话，最后两行改成这个。
//tools/dev/v8gen.py x64.release
//ninja -C out.gn/x64.release

//Turbolizer搭建
sudo apt-get install curl software-properties-common
curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
sudo apt-get install -y nodejs
cd tools/turbolizer/
npm i
npm run-script build
python -m SimpleHTTPServer

//参考链接
//https://bbs.pediy.com/thread-252812.htm

//gdb环境
source /home/v/v8/tools/gdbinit
source /home/v/v8/tools/gdb-v8-support.py

//npm
npm config set proxy=http://192.168.174.1:7890 
npm config set registry=http://registry.npmjs.org
```



## 学习资料

[Chrome浏览器漏洞入门 - Twings](https://aluvion.gitee.io/2021/03/16/Chrome%E6%B5%8F%E8%A7%88%E5%99%A8%E6%BC%8F%E6%B4%9E%E5%85%A5%E9%97%A8/)

[一个bin菜鸡 | Hpasserby](https://hpasserby.top/)

# Turbofan


[简单理解 V8 Turbofan](https://paper.seebug.org/1936/)

没基础看的不是很懂，里面写的也是一言难尽

[Introduction to TurboFan](https://doar-e.github.io/blog/2019/01/28/introduction-to-turbofan/#introduction)


# IPC
[【DC010技术沙龙】Chrome IPC机制研究及漏洞挖掘](https://www.ichunqiu.com/open/61709)
介绍了一下构造IPC Fuzzer的思路，利用的pykd框架
# pdfium
利用生成式fuzz挖掘Chrome PDFium漏洞

## 历史漏洞
https://cloud.tencent.com/developer/article/1005712
[# Google Chrome pdfium shading drawing 整数溢出导致远程代码执行](https://blogs.360.cn/post/google-chrome-pdfium-shading-drawing-%E6%95%B4%E6%95%B0%E6%BA%A2%E5%87%BA%E5%AF%BC%E8%87%B4%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C.html)

### Issue 770148(CVE-2017-15411)
![[Pasted image 20221007131222.png]]
### Issue 982397
![[Pasted image 20221007131525.png]]
## 漏洞模式
### UAF漏洞模式
![[Pasted image 20221007131803.png]]
---
title: "Turbofan"
date: 2023-08-03T14:23:01+08:00
draft: false
---

启动 turbolizer。如果原先版本的 turbolizer 无法使用，则可以使用在线版本的 turbolizer [v8.1](https://v8.github.io/tools/v8.1/turbolizer/index.html)
# 前言
## 准备Turbolizer
Turbolizer:调试TurboFan的`sea of nodes`图的工具
```bash
cd tools/turbolizer
npm i
npm run-script build
python -m SimpleHTTPServer
```
执行JS文件带--trace-turbo会生成.cfg和.json文件（用来提供给Turbolizer生成各种优化图)

>在JS执行过程中，首先由ignition生成字节码，如果JS中的函数被执行很多次，Turbofan会生成优化代码
# Sea of nodes节点海
Turbofan运行方式可以由节点海来表示，节点可以表示数学运算、加载、存储、调用、常数等，以下为三种常用来描述节点的边
## Control edges控制边
表示分支和循环
![[Pasted image 20221019215734.png]]
## Value edges值边
表示数据依赖
![[Pasted image 20221019215837.png]]
## Effect edges影响边
影响边排序操作，如读取或者写入状态
在下图中obj[x]=obj[x]+1
- 在写入之前你需要先读取x的值，所以在load和store之间有一个影响边
- 在store之前，有一个增加操作，所以需要在load和+之间设置一个影响边
- 最后影响链load->add->store如下所示
![[Pasted image 20221019220258.png]]
# Phases各个阶段
以下函数为例
```js
function opt_me() {
  let x = Math.random();
  let y = x + 2;
  return y + 3;
}
```
## Graph builder phase
生成图形，JSCall对应Math.random()函数
![[Pasted image 20221019231831.png]]

## Typer phase
这个阶段，会访问图中的每个节点并尝试减少它们，会推导出每个节点的类型
![[Pasted image 20221019232215.png]]
## Type lowering
接者简化类型，SpeculativeNumberAdd->NumberAdd
![[Pasted image 20221019232626.png]]
## Escape analysis
### CheckBounds
具有CheckBounds操作码的节点会在load和store之前进行检查
## Simplified lowering
CheckBounds elimination功能在这里实现
一句话就是在满足条件的情况下，他会消除一部分CheckBounds节点
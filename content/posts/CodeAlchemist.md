---
title: "CodeAlchemist"
date: 2023-08-03T14:20:50+08:00
draft: false
---

# CodeAlchemist: Semantics-Aware Code Generation to Find Vulnerabilities in JavaScript Engines

- CodeAlchemist: Semantics-Aware Code Generation to Find Vulnerabilities in JavaScript Engines论文阅读
    - 论文解决问题
        - JS Engine Fuzzer很难生成语法和语义正确的测试样本，本篇试图减少运行错误，生成语法语义正确的测试样本
- 文章主要内容
    - JS Engine Fuzzer很难生成语法和语义正确的测试样本，本篇试图减少运行错误，生成语法语义正确的测试样本，提出了一个新的模型assembly constraint
- 模型结构
    - Seed Parse:切割JS文件生成code bricks
        - 解析JS文件到一个AST，将AST分割成一系列code bricks,切割粒度为语句
- Constraint analyzer:给每个code bricks打标签，组成一个code brick pool
    - 通过标准化code bricks的所有特征，精简code bricks，将精简后的code bricks通过数据流分析得出use-def作为每一个code brick的约束标签
- engine fuzzer:基于code bricks的标签约束关系从code brick pool生成测试样本
- 定义的名词
    - code bricks:切割的JS种子文件片段
    - assembly constraint:每一个code bricks都有一系列约束标签，后续根据这些标签来对code bricks进行组合
- 改进方向
    - 优化种子选择策略（CodeAlchemist直接基于现有的种子）
    - 优化code brick选择策略
        - code利用的黑盒方式，可参考灰盒根据代码覆盖率或者相似差
        - 与Skyfire和TreeFuzz的概率语言模型结合
    - 支持更多目标
        - C、C++
- 相关知识
    - JS 7种原始类型
        - Undefined,Null,String,Boolean,Symbol,Number,Object
- ECMAScript标准 5种原始运行错误
    - syntax error,range error,reference error,type error,URI error,其他的称为custom error
- 实验对象
    - Chakra,v8,JavaScriptCore,SpiderMonkey
- 开源地址
    - [https://github](https://github/). com/SoftSec-KAIST/CodeAlchemist
- 相关研究
    - LangFuzz：解析样本JS文件作为种子文件，然后分割成代码片段重新组合生成测试样本，未开源
    - jsfunfuzz:基于编写的规则生成JS样本，开源，本文基于这个进行改进
    - Skyfire,TreeFuzz：构建了概率语言模型，基于模型生成测试样本
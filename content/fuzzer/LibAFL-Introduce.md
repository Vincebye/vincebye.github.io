---
title: "LibAFL Introduce"
date: 2023-04-12T00:38:17+08:00
draft: false
---

#Fuzzer #Rust
## 序
### 前置知识
- Rust
- Fuzzing
### LibAFL介绍
LibAFL：为了解决大量的fuzzer工具重复工作的问题，将fuzzer拆分成多个部分，编写fuzzer只需要将其组装，如输入可以改成字节输入或者AST输入，不需要重新安装熟悉多个fuzzer。缺点就是Rust门槛比较高。
### 资源
LibAFL Book：https://aflplus.plus/libafl-book/libafl.html
项目：https://github.com/AFLplusplus/LibAFL

## 正文
### baby_fuzzer
官方给出的一个简单案例用来说明如何使用LibAFL，我们摘取一部分,以下就是一个简单的fuzzer代码，~~看着很复杂，不如直接AFL++一把梭。~~
```Rust
    // Create an observation channel using the signals map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };
    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    #[cfg(not(feature = "tui"))]
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::new(String::from("Baby Fuzzer"), false);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
```
首先序中说过LibAFL是将fuzzer的多个步骤进行解耦，好让每个部分可以进行替换，实现一个fuzzer可以搞定所有fuzzer的效果。那我们如果编写fuzzer需要哪些部分呢？以下是我根据自己的认知需要的部分
- A-存储我们fuzzing过程中的状态
- B-提供fuzzing过程中的输入数据
- C-提供fuzzing输入的变异算法
- D-判定fuzzing结果是否有效（包含最少两种：有趣则加入原始语料库，产生如crash效果加入crash结果库）
- E-收集覆盖率
- F-任务调度，种子以怎样的方式或者算法加入队列
- G-执行器，如何去执行fuzzing
- H-界面输出，提供一个类似AFL界面来告知用户fuzzing的结果
我自己大概能想到这几个组件，接下来看一下LibAFL的组件
### 组件
- Observer
- Executor
	- InProcessExecutor
	- ForkserverExecutor
	- TimeoutExecutor
	- InProcessForkExecutor
- Feedback
- Input
- Corpus
- Mutator
- Generator
- Stage


以baby_fuzzer为例看看如何装配组件的
![picture](../../static/Pasted%20image%2020230408200259.png)
通过对着色部分的组装完成一个简单的fuzzer,乍看是有些繁杂，但是了解了每个部分功能以后，直接在原有代码进行更改就会比较简便。
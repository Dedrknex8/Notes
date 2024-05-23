# ip addr `10.10.141.8`

# Date 23-05-24 || Rohit Tiwari [22:54]

## PORTS TO TRY

```
============================================
PORT 22 : look for cred , bruteforce hydra

============================================
80 : apache -- check for fuzzing,source code and robo.txt

=============================================
8085: CMS--fuzzing--source code and robo.txt
=============================================
3389 RPC:
```

# Nmap scan

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Sustah_10.10.141.8]
└─$ sudo nmap -sVC -v -A $ip -T4 -oN Sustah_nmap_scan   
[sudo] password for dedrknex: 
Sorry, try again.
[sudo] password for dedrknex: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 23:10 IST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 23:10
Completed NSE at 23:10, 0.00s elapsed
Initiating NSE at 23:10
Completed NSE at 23:10, 0.00s elapsed
Initiating NSE at 23:10
Completed NSE at 23:10, 0.00s elapsed
Initiating Ping Scan at 23:10
Scanning 10.10.141.8 [4 ports]
Completed Ping Scan at 23:10, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:10
Completed Parallel DNS resolution of 1 host. at 23:10, 0.03s elapsed
Initiating SYN Stealth Scan at 23:10
Scanning 10.10.141.8 [1000 ports]
Discovered open port 80/tcp on 10.10.141.8
Discovered open port 22/tcp on 10.10.141.8
Discovered open port 8085/tcp on 10.10.141.8
Completed SYN Stealth Scan at 23:10, 1.71s elapsed (1000 total ports)
Initiating Service scan at 23:10
Scanning 3 services on 10.10.141.8
Completed Service scan at 23:10, 6.40s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.141.8
Initiating Traceroute at 23:10
Completed Traceroute at 23:10, 0.17s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 23:10
Completed Parallel DNS resolution of 2 hosts. at 23:10, 0.03s elapsed
NSE: Script scanning 10.10.141.8.
Initiating NSE at 23:10
Completed NSE at 23:10, 4.91s elapsed
Initiating NSE at 23:10
Completed NSE at 23:10, 0.69s elapsed
Initiating NSE at 23:10
Completed NSE at 23:10, 0.00s elapsed
Nmap scan report for 10.10.141.8
Host is up (0.17s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bd:a4:a3:ae:66:68:1d:74:e1:c0:6a:eb:2b:9b:f3:33 (RSA)
|   256 9a:db:73:79:0c:72:be:05:1a:86:73:dc:ac:6d:7a:ef (ECDSA)
|_  256 64:8d:5c:79:de:e1:f7:3f:08:7c:eb:b7:b3:24:64:1f (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Susta
8085/tcp open  http    Gunicorn 20.0.4
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD POST
|_http-server-header: gunicorn/20.0.4
|_http-title: Spinner
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.4
OS details: Linux 5.4
Uptime guess: 0.008 days (since Thu May 23 22:58:21 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```


# PORT 80

>On checking port found nothing new a simple apche sevrer wiht web hosted in it

![[Attachments/Pasted image 20240523231414.png]]

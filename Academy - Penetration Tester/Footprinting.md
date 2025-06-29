# Footprinting

## Certificates

[crt.sh](https://crt.sh) - Certificate Transparency Logs (RFC 6962)

### JSON Output via curl

```bash
curl -s "https://crt.sh/?q=inlanefreight.com&output=json" | jq .
```

### Sort by Subdomains

```bash
curl -s "https://crt.sh/?q=inlanefreight.com&output=json" | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

### Company hosted Servers along with IP

```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

## DNS Records

```bash
dig any domain.com
```

## Cloud

-   [domain.glass](http://domain.glass) - Company infrastructure resource
-   [buckets.grayhatwarfare.com](http://buckets.grayhatwarfare.com) - Another resource to search buckets (specifically files)

## FTP

Port: `21`

## SMB

Ports: `139`, `445`

### rpcclient useful commands

```bash
rpcclient smbIP -U ''
```

**Domain/Shares:**

```
enumdomains
querydominfo
netshareenumall
netsharegetinfo sharename
```

**Users:**

```
enumdomusers
queryuser 0xXXX
```

## NFS

Ports: `111`, `2049` (UDP/TCP)

### Show available shares:

```bash
showmount -e IP
```

### Mounting NFS Share:

```bash
sudo mount -t nfs victimIP:/ ./locationLocal -o nolock
```

## DNS

Port: `53`

ICANN hosts 13 root servers around the globe.

### DIG Queries

**NS Query**

```bash
dig ns inlanefreight.htb @10.129.14.128
```

**Version Query**

```bash
dig CH TXT version.bind 10.129.120.85
```

**Any Query**

```bash
dig any inlanefreight.htb @10.129.14.128
```

**AXFR Zone Transfer**

```bash
dig axfr inlanefreight.htb @10.129.14.128
```

**AXFR Zone Transfer Internal**

```bash
dig axfr internal.inlanefreight.htb @10.129.14.128
```

### Tool: DNSenum

```bash
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

... or just use GoBuster.

**Note:** Learn more about zone transfer exploitation.

## SMTP

Ports: `25`, `465`, `587`

Tool: `smtp-user-recon.py` in tools -- more accurate for enumerating users (htb specific)

```bash
msfconsole -> use smtp_enum
```

## IMAP/POP3

Ports:
*   **POP3**: `143`, `995`
*   **IMAP**: `143`, `993`

### Connect over TLS

```bash
openssl s_client -connect 10.129.14.128:pop3s
openssl s_client -connect 10.129.14.128:imaps
```

### HTB Solution Example

```
1 LOGIN robin robin
1 lIST “” *
1 SELECT DEV.DEPARTMENT.INT
1 fetch 1 all
1 FETCH 1 BODY[TEXT] to get the flag
```

## SNMP

Ports: `161`, `162` (UDP)
Tools: `snmpwalk`, `onesixtyone`, `braa`

```bash
snmpwalk -v2c -c public $IP
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```

### braa

```bash
# Syntax
braa <community string>@<IP>:.1.3.6.*
# Example
braa public@10.129.14.128:.1.3.6.*
```

## MySQL

Port: `3306` (Note: Original doc said 3360, but 3306 is the default)

### Nmap Script

```bash
nmap --script mysql*
```

### MySQL Commands

```sql
-- Connect to the MySQL server. There should not be a space between the '-p' flag, and the password.
mysql -u <user> -p<password> -h <IP address>

-- Show all databases.
show databases;

-- Select one of the existing databases.
use <database>;

-- Show all available tables in the selected database.
show tables;

-- Show all columns in the selected table.
show columns from <table>;

-- Show everything in the desired table.
select * from <table>;

-- Search for needed string in the desired table.
select * from <table> where <column> = "<string>";
```

## MSSQL

Port: `1433` (Note: Original doc said 3306, but 1433 is the default)

### Steroided Nmap

```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

### Metasploit

```
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248
```

### mssqlclient

```bash
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

## Oracle TNS

Port: `1521`

```bash
sudo nmap -p1521 -sV 10.129.204.235 --open
```

### SID Bruteforcing

```bash
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```

### Enumeration

```bash
./odat.py all -s 10.129.204.235
```

### SQLplus Login

```bash
sqlplus scott/tiger@10.129.204.235/XE
```

### sqlplus error handling

```bash
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"; sudo ldconfig
```

## IPMI

Port: `623`

```bash
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

### Metasploit

**Version Scan**
```
msf6 > use auxiliary/scanner/ipmi/ipmi_version
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_version) > show options
```

**Dump Hashes**
```
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphash) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options
```

## SSH

Port: `22`

### Auditing

```bash
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py 10.129.14.132
```

## Rsync

Port: `873`

### Probing shares

```bash
nc -nv IP 873
```

### Enumerating open share

```bash
rsync -av --list-only rsync://127.0.0.1/dev
```

## R-Services

Ports: `512`, `513`, `514`

### Scanning for R-Services

```bash
sudo nmap -sV -p 512,513,514 10.0.17.2
```

### RLogin

```bash
rlogin ip -l username
```

### Rwho / Rusers

```bash
rwho -a
rusers -al IP
```

## Windows Remote Management (WinRM)

Ports:
*   **RDP**: `3389`
*   **WinRM**: `5985`, `5986`
*   **WMI**: `135`

### RDP Footprinting

```bash
nmap -sV -sC 10.129.201.248 -p3389 --script "rdp-*"
```

### RDP Security Check

```bash
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl 10.129.201.248
```

### xfreerdp initiation

```bash
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```

### Footprinting WinRM

```bash
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```

### Evil-WinRM

```bash
evilwinrm -i ip -u user -p pass
```

### WMI Footprinting

```bash
wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```
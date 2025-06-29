# Network Enumeration with Nmap

### Network Range ICMP Scan

```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

Bring in `hosts.txt` exported from the command above with `-iL`.

**Strategies:** [Nmap Host Discovery Strategies](https://nmap.org/book/host-discovery-strategies.html)

### TTL per OS

-   **Linux**: 64
-   **Windows**: 128
-   **Cisco**: 255

### Full packet-trace on tx/rx

Use the `--packet-trace` switch.

---

## Nmap Cheat Sheet

### Scanning Options

| Flag                 | Description                                                                  |
| -------------------- | ---------------------------------------------------------------------------- |
| `10.10.10.0/24`      | Target network range.                                                        |
| `-sn`                | Disables port scanning (Ping Scan).                                          |
| `-Pn`                | Disables ICMP Echo Requests (No Ping).                                       |
| `-n`                 | Disables DNS Resolution.                                                     |
| `-PE`                | Performs the ping scan by using ICMP Echo Requests against the target.       |
| `--packet-trace`     | Shows all packets sent and received.                                         |
| `--reason`           | Displays the reason for a specific result.                                   |
| `--disable-arp-ping` | Disables ARP Ping Requests.                                                  |
| `--top-ports=<num>`  | Scans the specified top ports that have been defined as most frequent.       |
| `-p-`                | Scan all 65535 ports.                                                        |
| `-p22-110`           | Scan all ports between 22 and 110.                                           |
| `-p22,25`            | Scans only the specified ports 22 and 25.                                    |
| `-F`                 | Scans top 100 ports.                                                         |
| `-sS`                | Performs a TCP SYN-Scan.                                                     |
| `-sA`                | Performs a TCP ACK-Scan.                                                     |
| `-sU`                | Performs a UDP Scan.                                                         |
| `-sV`                | Scans the discovered services for their versions.                            |
| `-sC`                | Perform a Script Scan with scripts that are categorized as "default".        |
| `--script <script>`  | Performs a Script Scan by using the specified scripts.                       |
| `-O`                 | Performs an OS Detection Scan to determine the OS of the target.             |
| `-A`                 | Performs OS Detection, Service Detection, and traceroute scans.              |
| `-D RND:5`           | Sets the number of random Decoys that will be used to scan the target.       |
| `-e <iface>`         | Specifies the network interface that is used for the scan.                   |
| `-S <IP>`            | Specifies the source IP address for the scan.                                |
| `-g <port>`          | Specifies the source port for the scan.                                      |
| `--dns-server <ns>`  | DNS resolution is performed by using a specified name server.                |

### Output Options

| Flag         | Description                                                                    |
| ------------ | ------------------------------------------------------------------------------ |
| `-oA <file>` | Stores the results in all available formats starting with the name of "file".  |
| `-oN <file>` | Stores the results in normal format with the name "file".                      |
| `-oG <file>` | Stores the results in "grepable" format with the name of "file".               |
| `-oX <file>` | Stores the results in XML format with the name of "file".                      |

### Performance Options

| Flag                        | Description                                                        |
| --------------------------- | ------------------------------------------------------------------ |
| `--max-retries <num>`       | Sets the number of retries for scans of specific ports.            |
| `--stats-every=5s`          | Displays scan's status every 5 seconds.                            |
| `-v`/`-vv`                  | Displays verbose output during the scan.                           |
| `--initial-rtt-timeout 50ms`| Sets the specified time value as initial RTT timeout.              |
| `--max-rtt-timeout 100ms`   | Sets the specified time value as maximum RTT timeout.              |
| `--min-rate 300`            | Sets the number of packets that will be sent simultaneously.       |
| `-T <0-5>`                  | Specifies the specific timing template (0=slowest, 5=fastest).     |

### Stylesheet output

If we output with `-oX`, we can use `xsltproc` to create an HTML visual.

```bash
xsltproc target.xml -o target.html
```

### Nmap Scripting Engine (NSE)

```bash
# Run a script or a comma-separated list of scripts
nmap --script <script-name1>,<script-name2> <target>

# Run all scripts in the 'vuln' category
nmap --script vuln <target>
```

### Decoy & Circumventive Scans

`-D` throws our IP in a list of randomized IPs.
`-e` flag lets us indicate which interface to scan from (e.g., `-e tun0`).

---

## IPS/IDS/Firewall Evasion

### DNS Specific Evasion

```bash
nmap <targetIp> -sS -Pn -n --disable-arp-ping --source-port 53 -v
nmap <targetIp> -p50000 -sS -Pn -n --disable-arp-ping --source-port 53 -v
ncat -nv --source-port 53 <targetIp> 50000
```

### General Firewall Evasion Techniques

```bash
# Use 10 random decoys
nmap -sS -p22,80,443 -n -Pn --disable-arp-ping -D RND:10 <targetIp>

# Specify decoys, including your own IP (ME)
nmap -sS -p22,80,443 -n -Pn --disable-arp-ping -D 10.10.10.1,10.10.10.2,ME <targetIp>

# Spoof source IP (requires root, may not get replies)
nmap -sS -p22,80,443 -n -Pn --disable-arp-ping -e eth0 -S <spoofedIp> <targetIp>

# Use proxies
nmap -sS -p22,80,443 -n -Pn --disable-arp-ping --proxies http://127.0.0.1:8080,http://127.0.0.1:8081 <targetIp>

# Append random data to packets
nmap -sS -p22,80,443 -n -Pn --disable-arp-ping --data-length 25 <targetIp>

# Limit retries
nmap -sS -p22,80,443 -n -Pn --disable-arp-ping --max-retries 1 <targetIp>

# Add a scan delay
nmap -sS -p22,80,443 -n -Pn --disable-arp-ping --scan-delay 2s <targetIp>

# Send packets with a bad checksum
nmap -sS -p22,80,443 -n -Pn --disable-arp-ping --badsum <targetIp>
```

---

## Other Scanning Tools

### Masscan

```bash
masscan -p80,443,8080 10.0.0.0/8 --rate=100000 -oL masscan.log
```

### Hping3

```bash
hping3 -S 10.10.10.10 -p 80 -c 5
```

### TCPDump

```bash
tcpdump -i eth0 -n -v tcp port 22 and src host 10.10.10.10
```

### Wireshark Filter

```
ip.addr == 10.10.10.10 && tcp.port == 22
```

### Netcat

```bash
nc -nv -w 1 -z 10.10.10.10 20-30
```

### Metasploit

```
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.10
set PORTS 20-30
run
```

---

## Port Scanning with Scripting Languages

### Powershell

```powershell
1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.10",$_)) "Port $_ is open!"} 2>$null
```

### Bash

```bash
for port in {1..1024}; do (echo >/dev/tcp/10.10.10.10/$port) >/dev/null 2>&1 && echo "Port $port is open!"; done
```

### Python

```python
import socket

target = "10.10.10.10"

for port in range(1, 1025):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((target,port))
    if result == 0:
        print(f"Port {port} is open")
    s.close()
```

### Rust

```rust
use std::net::TcpStream;
use std::io::{self, Write};

fn main() {
    let target = "10.10.10.10";
    for port in 1..1025 {
        match TcpStream::connect(format!("{}:{}", target, port)) {
            Ok(_) => {
                println!("Port {} is open", port);
            }
            Err(_) => {}
        }
    }
}
```
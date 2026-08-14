# 🔭 Net Recon Scanner

> TCP connect port scanner with banner grabbing, service detection,
> and OS fingerprinting. CIDR support. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](net_recon.py)

> **Authorized use only.** Only scan systems you own or have explicit written permission to test.

---

## Overview

Net Recon performs TCP connect scanning with concurrent threads — no raw
sockets required. Detects 60+ services, grabs banners, and provides
risk assessment for open ports.

```bash
# Scan single host
python net_recon.py 192.168.1.1

# Scan with port range
python net_recon.py 192.168.1.1 --ports 1-1024

# Scan entire subnet
python net_recon.py 192.168.1.0/24

# Scan specific ports
python net_recon.py example.com --ports 22,80,443,8080

# Top 100 ports
python net_recon.py 192.168.1.1 --top100

# With banner grabbing
python net_recon.py 192.168.1.1 --banners

# JSON output
python net_recon.py 192.168.1.1 --json -o scan.json
```

---

## Features

### Port Scanning

- **TCP Connect** scan (no root/admin required)
- Concurrent scanning with configurable thread count
- CIDR notation support (`192.168.1.0/24`)
- Port range specification (`1-65535`, `22,80,443`, `1-1024`)
- Top 100/1000 common ports preset
- Configurable timeout

### Service Detection (60+ services)

| Port | Service | Port  | Service        |
| ---- | ------- | ----- | -------------- |
| 21   | FTP     | 3306  | MySQL          |
| 22   | SSH     | 3389  | RDP            |
| 23   | Telnet  | 4444  | Metasploit     |
| 25   | SMTP    | 5432  | PostgreSQL     |
| 53   | DNS     | 5900  | VNC            |
| 80   | HTTP    | 6379  | Redis          |
| 135  | MS-RPC  | 8080  | HTTP-Alt       |
| 139  | NetBIOS | 8443  | HTTPS-Alt      |
| 443  | HTTPS   | 9200  | Elasticsearch  |
| 445  | SMB     | 27017 | MongoDB        |
| 1433 | MSSQL   | 2375  | Docker API     |
| 2049 | NFS     | 6443  | Kubernetes API |

### Banner Grabbing

Grabs service banners from open ports:

- HTTP/HTTPS: Server header, title, redirect
- SSH: Version string (OpenSSH/version)
- FTP: Welcome message
- SMTP: Server greeting
- Raw TCP: First 512 bytes

### Risk Assessment

Flags high-risk services automatically:
| Risk | Ports |
|---|---|
| 🔴 CRITICAL | 4444 (Metasploit), 2375 (Docker API unauth), 5900 (VNC) |
| 🟠 HIGH | 22 (SSH), 3389 (RDP), 445 (SMB) |
| 🟡 MEDIUM | 21 (FTP), 23 (Telnet), 161 (SNMP), 6379 (Redis) |

### OS Fingerprinting (Heuristic)

- Windows indicators: 135, 139, 445, 3389 open
- Linux indicators: 22 open, 111 (portmap), 2049 (NFS)
- Network device: 23 (Telnet), 161 (SNMP)

---

## Usage

```bash
# Quick scan (top 100 ports)
python net_recon.py 192.168.1.1 --top100

# Full TCP scan
python net_recon.py 192.168.1.1 --ports 1-65535 --threads 200

# Subnet scan (common ports)
python net_recon.py 10.0.0.0/24 --ports 22,80,443,3389,445 --threads 50

# With banners (slower but more info)
python net_recon.py 192.168.1.1 --top100 --banners

# Verbose output
python net_recon.py 192.168.1.1 --top100 --verbose

# JSON for further analysis
python net_recon.py 192.168.1.1 --top100 --json -o scan_results.json

# Save Markdown report
python net_recon.py 192.168.1.1 --top100 -o recon_report.md
```

---

## Example Output

```
  NET RECON SCANNER — 192.168.1.1
  Ports    : top 100
  Threads  : 100
  Timeout  : 2.0s
  ════════════════════════════════════════════════════════════════════

  PORT     SERVICE    STATE   BANNER
  22/tcp   SSH        OPEN    OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  80/tcp   HTTP       OPEN    nginx/1.18.0
  443/tcp  HTTPS      OPEN    nginx/1.18.0
  3306/tcp MySQL      OPEN    ← HIGH RISK
  8080/tcp HTTP-Alt   OPEN    Apache Tomcat/9.0.65

  ════════════════════════════════════════════════════════════════════
  Open ports   : 5
  High risk    : 1 (MySQL exposed)
  OS guess     : Linux (SSH present, no Windows services)
  Scan time    : 8.3s
```

---

## Repository Structure

```
net-recon/
├── net_recon.py
├── README.md
└── .gitignore
```

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) —  Cybersecurity Specialist, Porto, Portugal*

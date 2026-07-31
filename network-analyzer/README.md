# 🌐 Network Traffic Analyzer

> PCAP parser with anomaly detection — port scans, brute-force,
> DNS tunneling, C2 beaconing, data exfiltration. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](network_analyzer.py)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)](https://attack.mitre.org)

---

## Overview

Network Traffic Analyzer parses PCAP files and applies behavioral detection
to identify malicious patterns — without requiring Wireshark or Scapy.
Built with pure Python stdlib — reads raw PCAP binary format directly.

```bash
# Analyze a PCAP file
python network_analyzer.py capture.pcap

# Demo mode (370 synthetic packets with 4 attack types)
python network_analyzer.py --demo

# JSON output for SIEM
python network_analyzer.py capture.pcap --json -o alerts.json

# Stats only (no detection)
python network_analyzer.py capture.pcap --no-detect

# Save Markdown report
python network_analyzer.py capture.pcap -o report.md
```

---

## Anomaly Detectors

| Detector                | MITRE     | Threshold                       | Severity |
| ----------------------- | --------- | ------------------------------- | -------- |
| Port Scan               | T1046     | 15 unique ports in 5s           | HIGH     |
| SSH/FTP/RDP Brute Force | T1110     | 20 SYNs/minute                  | HIGH     |
| DNS Tunneling           | T1071.004 | Shannon entropy > 3.8 bits      | HIGH     |
| C2 Beaconing            | T1071     | CV < 15% over 8+ connections    | CRITICAL |
| Data Exfiltration       | T1041     | > 50MB outbound                 | MEDIUM   |
| High Volume / DoS       | T1498     | 500+ packets/min from single IP | HIGH     |

---

## Detection Details

### Port Scan (T1046)

```
Algorithm : Sliding window 5 seconds
Trigger   : Source IP sends SYN to 15+ unique destination ports
Evidence  : [22, 80, 443, 8080, 3306, 5432...] in 4.2s
MITRE     : T1046 — Network Service Discovery
```

### DNS Tunneling (T1071.004)

```
Algorithm : Shannon entropy per DNS label
Trigger   : Entropy > 3.8 bits/char  OR  label length > 30 chars
Example   : aGVsbG8gd29ybGQ.evil-c2.xyz
             ^^^^^^^^^^^^^^^^ High entropy = encoded data
MITRE     : T1071.004 — Application Layer Protocol: DNS
```

### C2 Beaconing (T1071)

```
Algorithm : Coefficient of Variation (CV) of inter-connection intervals
Trigger   : CV < 0.15 over 8+ connections (very regular = automated)
Example   : connections at 30.1s, 30.0s, 29.9s, 30.2s intervals
MITRE     : T1071 — Application Layer Protocol
```

### SSH/RDP Brute Force (T1110)

```
Algorithm : SYN packet rate per (src, dst, port)
Trigger   : 20+ SYN packets per minute to port 22/21/3389/23/5900
Evidence  : 247 SYNs from 203.0.113.42 to :22 in 60s
MITRE     : T1110 — Brute Force
```

---

## Demo Mode

The demo generates 370 synthetic packets covering 4 attack types:

```bash
python network_analyzer.py --demo
```

| Synthetic traffic        | Packets | Attack type |
| ------------------------ | ------- | ----------- |
| Normal HTTPS to CDN      | 200     | — baseline  |
| Port scan (ports 1–49)   | 49      | T1046       |
| SSH brute force          | 80      | T1110       |
| DNS tunneling queries    | 20      | T1071.004   |
| C2 beaconing (port 4444) | 15      | T1071       |

---

## PCAP Format Support

| Format               | Magic Bytes   | Support |
| -------------------- | ------------- | ------- |
| PCAP (little-endian) | `d4 c3 b2 a1` | Full    |
| PCAP (big-endian)    | `a1 b2 c3 d4` | Full    |
| PCAP-NG              | `0a 0d 0d 0a` | Partial |
| Link type: Ethernet  | `0x0001`      | Full    |

**Note:** For non-Ethernet captures, use `tshark -F pcap` to convert first.

---

## Example Output

```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TRAFFIC STATISTICS
  Packets     : 364
  Total bytes : 182,450 (0MB)
  Duration    : 424.8s
  Rate        : 0.9 pkt/s
  Unique IPs  : 6 src / 4 dst

  Protocol Distribution:
  TCP      ████████████████████ 200 (54.9%)
  DNS      ████████ 80  (22.0%)
  HTTPS    ████ 49  (13.5%)
  UDP      ██ 35   (9.6%)

  Top Source IPs:
  192.168.1.10       200 packets
  185.220.101.47     49  packets
  203.0.113.42       80  packets

  ANOMALY DETECTION — 4 findings
  ════════════════════════════════════════════════════════════════════
  [CRITICAL] C2 Beaconing
  Src: 192.168.1.33  →  Dst: 198.51.100.10:4444
  15 connections at 30.1s avg interval (CV=0.043 — highly regular)
  Evidence: Beaconing interval: 30.1s | Regularity: 0.043

  [HIGH] Port Scan
  Src: 185.220.101.47  →  Dst: 192.168.1.10
  49 unique ports in 4.8s
  Evidence: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10...]

  [HIGH] SSH Brute Force
  Src: 203.0.113.42  →  Dst: 192.168.1.1:22
  80 SYN attempts (80/min)
  Evidence: 80 SYNs in 60s → port 22

  [HIGH] DNS Tunneling
  Src: 192.168.1.55  →  DNS Server:53
  20 high-entropy queries
  Evidence: Example: aGVsbG8gd29ybGQ.evil-c2.xyz
```

---

## Integration with Other Tools

```bash
# Generate PCAP with tcpdump (capture 60s)
sudo tcpdump -i eth0 -w capture.pcap -G 60 -W 1

# Capture specific traffic
sudo tcpdump -i eth0 port 22 or port 80 -w ssh_http.pcap

# Analyze and pipe to SIEM
python network_analyzer.py capture.pcap --json | \
  curl -X POST https://siem.company.com/api/alerts \
  -H "Content-Type: application/json" -d @-

# Monitor alerts in real time (bash loop)
while true; do
  python network_analyzer.py /tmp/live.pcap --json --no-banner 2>/dev/null
  sleep 30
done
```

---

## Repository Structure

```
ciber
    └──network-analyzer/
                    ├── network_analyzer.py     ← Main analyzer
                    ├── samples/
                    │     └── README.md ← How to obtain test PCAP samples
                    ├── README.md
                    └── .gitignore
```

---

## References

- [MITRE ATT&CK — T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK — T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE ATT&CK — T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Wireshark PCAP Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [Shannon Entropy in Malware Analysis](https://www.sans.org/reading-room/whitepapers/malware/malware-analysis-statistical-analysis-33315)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal*

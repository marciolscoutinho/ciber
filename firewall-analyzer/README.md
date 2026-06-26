# 🔥 Firewall Rule Analyzer

> Firewall rule review tool for iptables and UFW. Detects permissive default
> policies, exposed high-risk ports, allow-all rules, missing logging, and
> redundant rules. Zero external dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](firewall_analyzer.py)
[![CIS](https://img.shields.io/badge/CIS-Benchmark-orange?style=flat-square)](https://www.cisecurity.org)

---

## Overview

Firewall Rule Analyzer parses saved or live firewall rules and highlights
security weaknesses that commonly appear in Linux host firewalls:

- permissive default policies;
- high-risk management ports exposed to `0.0.0.0/0`;
- `ACCEPT all` rules;
- legacy protocols such as Telnet, FTP, rsh, and rexec;
- missing logging before `DROP` / `REJECT`;
- duplicate or redundant rules.

The tool is designed for defensive review, internal hardening, audits, labs, and
authorized security assessments.

---

## Installation

```bash
git clone https://github.com/marciolscoutinho/ciber.git
cd ciber
python firewall_analyzer.py --version
```

Requirements:

- Python 3.8+
- No external Python dependencies
- Optional: `iptables`, `ufw`, or `sudo` access for live scans

---

## Usage

```bash
# Demo mode: intentionally insecure sample ruleset
python firewall_analyzer.py --demo

# JSON demo output
python firewall_analyzer.py --demo --json

# Save JSON report
python firewall_analyzer.py --demo --json -o firewall_report.json

# Save Markdown report
python firewall_analyzer.py --demo -o firewall_report.md

# Analyze saved iptables output
iptables -L -n --line-numbers > rules.txt
python firewall_analyzer.py rules.txt --type iptables

# Analyze saved UFW output
ufw status numbered > ufw_status.txt
python firewall_analyzer.py ufw_status.txt --type ufw

# Auto-detect input format
python firewall_analyzer.py rules.txt

# Analyze live local firewall rules
python firewall_analyzer.py --live
```

---

## Detection Rules

### Default Policies

| Check                        | Severity | Description                                       |
| ---------------------------- |:--------:| ------------------------------------------------- |
| `INPUT` policy is `ACCEPT`   | CRITICAL | Inbound traffic may be accepted by default        |
| `FORWARD` policy is `ACCEPT` | HIGH     | Forwarding between interfaces may be unrestricted |
| `OUTPUT` policy is `ACCEPT`  | INFO     | Usually acceptable for general-purpose servers    |

### High-Risk Ports Exposed to Any Source

| Port  | Service                       | Severity |
| -----:| ----------------------------- |:--------:|
| 3389  | RDP                           | CRITICAL |
| 445   | SMB                           | CRITICAL |
| 2375  | Docker API                    | CRITICAL |
| 4444  | Common reverse-shell listener | CRITICAL |
| 22    | SSH                           | HIGH     |
| 3306  | MySQL                         | HIGH     |
| 5432  | PostgreSQL                    | HIGH     |
| 27017 | MongoDB                       | HIGH     |
| 6379  | Redis                         | HIGH     |
| 9200  | Elasticsearch                 | HIGH     |
| 161   | SNMP                          | HIGH     |
| 21    | FTP                           | HIGH     |
| 23    | Telnet                        | HIGH     |

### Rule Quality

| Check                                     | Severity | Description                                           |
| ----------------------------------------- |:--------:| ----------------------------------------------------- |
| `ACCEPT all` rule                         | CRITICAL | No source, destination, protocol, or port restriction |
| TCP/UDP `ACCEPT` without destination port | HIGH     | Accepts all ports for that protocol                   |
| Legacy protocol exposed                   | HIGH     | Unencrypted or obsolete service exposed               |
| Docker API exposed                        | CRITICAL | Possible host-level control if reachable              |
| No logging before `DROP` / `REJECT`       | MEDIUM   | Reduced auditability and incident visibility          |
| ICMP fully blocked                        | MEDIUM   | Can break diagnostics and path MTU discovery          |
| Duplicate rule                            | LOW      | Increases ruleset complexity without value            |

---

## Example Output

```text
FIREWALL ANALYSIS SUMMARY
Source   : demo-insecure-ruleset
Type     : iptables
Rules    : 8
Findings : 12

Default policies:
  INPUT      ACCEPT
  FORWARD    ACCEPT
  OUTPUT     ACCEPT

Score: 0/100
CRITICAL  ███████ 7
HIGH      ████ 4
MEDIUM    █ 1
```

---

## Recommended Minimal iptables Ruleset

```bash
# Flush existing rules
iptables -F

# Default policies: deny inbound and forwarding by default
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established/related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from a trusted administration IP only
iptables -A INPUT -s 203.0.113.10 -p tcp --dport 22 -j ACCEPT

# Allow web traffic
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Log and drop everything else
iptables -A INPUT -j LOG --log-prefix "[FW-DROP] " --log-level 4
iptables -A INPUT -j DROP
```

---

## Exit Codes

| Code | Meaning                          |
| ----:| -------------------------------- |
| `0`  | No MEDIUM/HIGH/CRITICAL findings |
| `1`  | MEDIUM or HIGH findings detected |
| `2`  | CRITICAL findings detected       |

---

## Repository Structure

```text
ciber/
    └──firewall-analyzer/
                       ├── firewall_analyzer.py
                       ├── README.md
                       ├── LICENSE
                       ├── .gitignore
                       ├── .markdownlint.json
                       └── .github/
                                 └── workflows/
                                             └── ci.yml
```

---

## References

- [CIS Linux Benchmark — Network Configuration](https://www.cisecurity.org/benchmark/distribution_independent_linux)
- [iptables manual page](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [UFW Community Documentation](https://help.ubuntu.com/community/UFW)
- [NIST SP 800-41 Rev. 1 — Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal*

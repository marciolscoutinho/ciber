<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=14&height=200&section=header&text=Threat%20Intelligence%20Aggregator&fontSize=38&fontAlignY=35&animation=twinkling&fontColor=ffffff" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python%203.x-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Sources-NVD%20%7C%20CISA%20KEV-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge" />
</p>

<p align="center"><strong>Aggregate CVEs, IOCs, and threat feeds from public sources. Look up IPs, domains, and hashes. Detect DGA-generated domains.</strong></p>

---

## Features

| Feature          | Description                                              |
| ---------------- | -------------------------------------------------------- |
| 🔍 NVD CVE API   | Search NIST National Vulnerability Database              |
| 🚨 CISA KEV      | Monitor CISA Known Exploited Vulnerabilities feed        |
| 🌐 IOC Lookup    | IP, domain, and hash reputation checks                   |
| 🤖 DGA Detection | Heuristic detection of algorithmically-generated domains |
| 📋 Report        | Terminal + JSON export                                   |

## Usage

```bash
# Search for a CVE
python threat_intel.py --cve CVE-2021-44228

# Check CISA Known Exploited Vulnerabilities
python threat_intel.py --kev

# IOC lookup (IP, domain, or hash)
python threat_intel.py --ioc 198.51.100.7
python threat_intel.py --ioc malicious-domain.ru
python threat_intel.py --ioc d41d8cd98f00b204e9800998ecf8427e

# DGA heuristic check
python threat_intel.py --dga suspicious-xkqzmpvw.net

# Full JSON report
python threat_intel.py --full --json report.json
```

## Output Example

```
╔══════════════════════════════════════════════════════════╗
║         THREAT INTELLIGENCE AGGREGATOR                   ║
╠══════════════════════════════════════════════════════════╣
║  CVE-2021-44228 (Log4Shell)                              ║
║  CVSS: 10.0 CRITICAL                                     ║
║  CISA KEV: YES — actively exploited                      ║
╚══════════════════════════════════════════════════════════╝

[NVD]
  Published  : 2021-12-10
  Description: Apache Log4j2 JNDI features used in config...
  References : 23 references

[CISA KEV]
  ✅ In Known Exploited Vulnerabilities catalogue
  Due Date   : 2021-12-24
  Vendor     : Apache
  Product    : Log4j2
```

## Data Sources

- **NIST NVD** — National Vulnerability Database (CVE details, CVSS scores)
- **CISA KEV** — Known Exploited Vulnerabilities catalogue (JSON feed)
- **Zero external dependencies** — uses only Python `urllib` and `json`

## Standards Alignment

- MITRE ATT&CK — TA0043 Reconnaissance
- STIX/TAXII-compatible structured output
- CISA Shields Up recommendations

---

> Built by [Márcio Coutinho](https://github.com/marciolscoutinho) | Cybersecurity Specialist

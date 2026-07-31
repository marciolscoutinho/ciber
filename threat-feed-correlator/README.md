# 🎯 Threat Feed Correlator

> Aggregates and correlates IOCs from multiple public threat intelligence feeds.
> Detects IOCs seen across multiple sources — higher confidence, fewer false positives.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](threat_feed_correlator.py)
[![Feeds](https://img.shields.io/badge/Feeds-5%20Sources-red?style=flat-square)](threat_feed_correlator.py)

---

## Overview

Threat Feed Correlator pulls from 5 public threat intelligence feeds,
deduplicates entries, and highlights IOCs confirmed by multiple sources.
Multi-source confirmation raises the confidence score and reduces false positives.

```bash
# Load default feeds (Feodo Tracker + CISA KEV)
python threat_feed_correlator.py --feeds feodo cisa

# Load all feeds
python threat_feed_correlator.py --feeds all

# Lookup a specific IOC
python threat_feed_correlator.py --feeds all --lookup 185.220.101.47

# Filter by type
python threat_feed_correlator.py --feeds all --type ip --severity critical

# Only show correlated (multi-feed) IOCs
python threat_feed_correlator.py --feeds all --correlated-only

# Save report
python threat_feed_correlator.py --feeds all -o threat_report.md
```

---

## Integrated Feeds

| Feed              | Provider     | IOC Types                   | Update Frequency | Auth |
| ----------------- | ------------ | --------------------------- | ---------------- | ---- |
| **Feodo Tracker** | abuse.ch     | IP (C2 botnets)             | Real-time        | None |
| **URLhaus**       | abuse.ch     | URLs (malware distribution) | Real-time        | None |
| **MalwareBazaar** | abuse.ch     | SHA-256 hashes              | Real-time        | None |
| **CISA KEV**      | CISA         | CVE IDs                     | Daily            | None |
| **blocklist.de**  | blocklist.de | IP (honeypot reports)       | Hourly           | None |

---

## Correlation Logic

```
IOC in Feed A only     → Confidence: 70%
IOC in Feed A + B      → Confidence: 85%  (+15% per additional source)
IOC in Feed A + B + C  → Confidence: 95%  (capped at 95%)
```

Multi-feed IOCs appear in the **Correlated IOCs** section — these are
the highest-confidence indicators for immediate action.

---

## IOC Types Supported

| Type          | Examples                      | Sources             |
| ------------- | ----------------------------- | ------------------- |
| `ip`          | `185.220.101.47`              | Feodo, blocklist.de |
| `url`         | `http://evil.xyz/payload.exe` | URLhaus             |
| `hash-sha256` | `a3b4c5d6...` (64 hex chars)  | MalwareBazaar       |
| `cve`         | `CVE-2021-44228`              | CISA KEV            |
| `domain`      | `evil-c2.xyz`                 | URLhaus (extracted) |

---

## Usage Examples

```bash
# Load all feeds and show stats
python threat_feed_correlator.py --feeds all

# Check if an IP is malicious
python threat_feed_correlator.py --feeds feodo blocklist --lookup 185.220.101.47

# Check a SHA-256 hash
python threat_feed_correlator.py --feeds bazaar \
  --lookup a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4

# Check a CVE
python threat_feed_correlator.py --feeds cisa --lookup CVE-2021-44228

# Export JSON for SIEM
python threat_feed_correlator.py --feeds all \
  --correlated-only --json -o correlated_iocs.json

# Save Markdown report
python threat_feed_correlator.py --feeds all -o threat_report.md
```

---

## Example Output

```
  Threat Feed Correlator — Loading feeds
  → Feodo Tracker (abuse.ch)...     892 IOCs  (312ms)
  → URLhaus (abuse.ch)...            500 IOCs  (891ms)
  → MalwareBazaar (abuse.ch)...      300 IOCs  (445ms)
  → CISA KEV...                      900 IOCs  (203ms)
  → blocklist.de...                  200 IOCs  (678ms)

  CORRELATION STATISTICS
  Total IOCs    : 2,642
  Correlated    : 47 (seen in multiple feeds)

  By Type:
  ip             ████████████████████ 1,092
  url            ████████████ 500
  hash-sha256    ████████ 300
  cve            ████████ 900

  By Severity:
  critical       ████████████████████ 1,800
  high           ████ 392
  medium         ██ 250

  Top Correlated IOCs (multiple feeds):
  185.220.101.47         ip          [Feodo, blocklist.de]  Conf: 85%
  203.0.113.99           ip          [Feodo, blocklist.de]  Conf: 85%
  CVE-2021-44228         cve         [CISA KEV, URLhaus]    Conf: 85%
```

---

## IOC Lookup Output

```bash
python threat_feed_correlator.py --feeds all --lookup CVE-2021-44228
```

```
  Lookup: CVE-2021-44228

  [CRITICAL] CVE-2021-44228
  Type      : cve
  Confidence: 100%
  Sources   : CISA KEV
  Tags      : exploited-in-wild, cisa-kev, apache
  Desc.     : Log4Shell — Apache Log4j2 JNDI Injection RCE
```

---

## Repository Structure

```
ciber
    └──threat-feed-correlator/
                            ├── threat_feed_correlator.py
                            ├── README.md
                            └── .gitignore
```

---

## References

- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch)
- [abuse.ch URLhaus](https://urlhaus.abuse.ch)
- [abuse.ch MalwareBazaar](https://bazaar.abuse.ch)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [blocklist.de](https://www.blocklist.de)
- [MISP Threat Sharing](https://www.misp-project.org)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal*

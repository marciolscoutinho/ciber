# 🎯 STRIDE Threat Modeling Tool

> Generates structured threat models using STRIDE methodology.
> Pre-defined threats per component type. Markdown + JSON reports.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](threat_model.py)
[![STRIDE](https://img.shields.io/badge/Methodology-STRIDE-blue?style=flat-square)](https://learn.microsoft.com/azure/security/develop/threat-modeling-tool-threats)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)](https://attack.mitre.org)

---

## Overview

STRIDE Threat Modeling Tool generates structured threat models for common
system architectures. Select your component types, and the tool automatically
generates threats, likelihood/impact scores, and mitigations.

```bash
# Demo threat model (web app + database + auth + file upload)
python threat_model.py --demo

# Custom components
python threat_model.py --components web_api database authentication

# Interactive builder (guided)
python threat_model.py --interactive

# Save Markdown report
python threat_model.py --demo -o threat_model_report.md

# JSON output
python threat_model.py --demo --json

# List component types
python threat_model.py --list-components
```

---

## STRIDE Framework

| Letter | Category               | Security Property | Description                           |
| ------ | ---------------------- | ----------------- | ------------------------------------- |
| **S**  | Spoofing               | Authentication    | Pretending to be another entity       |
| **T**  | Tampering              | Integrity         | Modifying data without authorisation  |
| **R**  | Repudiation            | Non-repudiation   | Denying having performed an action    |
| **I**  | Information Disclosure | Confidentiality   | Exposing data to unauthorised parties |
| **D**  | Denial of Service      | Availability      | Making system unavailable             |
| **E**  | Elevation of Privilege | Authorization     | Gaining more access than allowed      |

---

## Component Types

### `web_api` — REST API / Web Application (7 threats)

| Category       | Threat                | Likelihood | Impact | Risk     |
| -------------- | --------------------- | ---------- | ------ | -------- |
| T — Tampering  | SQL/NoSQL Injection   | 4/5        | 5/5    | CRITICAL |
| E — Elevation  | Mass Assignment       | 3/5        | 5/5    | HIGH     |
| S — Spoofing   | JWT/Token Spoofing    | 3/5        | 5/5    | HIGH     |
| I — Disclosure | IDOR                  | 4/5        | 4/5    | HIGH     |
| D — DoS        | Missing Rate Limiting | 4/5        | 3/5    | MEDIUM   |
| T — Tampering  | SSRF                  | 3/5        | 4/5    | MEDIUM   |
| I — Disclosure | Over-fetching         | 3/5        | 3/5    | MEDIUM   |

### `database` — SQL/NoSQL Database (6 threats)

| Category        | Threat                     | Risk   |
| --------------- | -------------------------- | ------ |
| S — Spoofing    | Weak Authentication        | HIGH   |
| T — Tampering   | Unencrypted Backup         | HIGH   |
| I — Disclosure  | Data at Rest Unencrypted   | HIGH   |
| D — DoS         | Connection Pool Exhaustion | MEDIUM |
| E — Elevation   | Excessive Privileges       | HIGH   |
| R — Repudiation | Query Logging Disabled     | MEDIUM |

### `authentication` — Auth Service (6 threats)

| Category       | Threat                  | Risk     |
| -------------- | ----------------------- | -------- |
| S — Spoofing   | Credential Stuffing     | HIGH     |
| S — Spoofing   | Session Hijacking       | HIGH     |
| T — Tampering  | Insecure Password Reset | HIGH     |
| I — Disclosure | User Enumeration        | LOW      |
| D — DoS        | Missing Account Lockout | HIGH     |
| E — Elevation  | JWT Claims Manipulation | CRITICAL |

### `microservices` — Microservices Architecture (5 threats)

| Category       | Threat                   | Risk     |
| -------------- | ------------------------ | -------- |
| S — Spoofing   | No mTLS Between Services | HIGH     |
| T — Tampering  | Message Tampering        | HIGH     |
| I — Disclosure | Sensitive Data in Logs   | HIGH     |
| D — DoS        | Cascading Failures       | CRITICAL |
| E — Elevation  | Container Escape         | CRITICAL |

### `file_upload` — File Upload Endpoint (4 threats)

| Category       | Threat                           | Risk     |
| -------------- | -------------------------------- | -------- |
| T — Tampering  | Malicious File Upload (Webshell) | CRITICAL |
| I — Disclosure | Path Traversal via Filename      | HIGH     |
| D — DoS        | DoS via Large Files              | MEDIUM   |
| S — Spoofing   | MIME Type Spoofing               | MEDIUM   |

---

## Risk Scoring

```
Risk Score = Likelihood × Impact  (both on scale 1-5)

Score 20-25 → CRITICAL
Score 15-19 → HIGH
Score  8-14 → MEDIUM
Score  1-7  → LOW
```

---

## Usage

```bash
# Threat model for web application
python threat_model.py --components web_api database authentication

# Name your system
python threat_model.py --system-name "E-Commerce Platform" --components web_api database

# Interactive mode (guided component selection)
python threat_model.py --interactive

# Generate demo (4 components)
python threat_model.py --demo --system-name "Banking API"

# Save report
python threat_model.py --demo -o threat_model.md

# JSON export
python threat_model.py --demo --json -o threats.json
```

---

## Example Output

```
  THREAT MODEL — Banking API
  Components: 4 | Threats identified: 24
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CRITICAL   ████████████ 3
  HIGH       ████████████████████ 8
  MEDIUM     ████████████ 9
  LOW        ████ 4

  [T001] SQL Injection (Tampering — API REST)
  Score: 20/25 (CRITICAL)
  Mitigations:
  - Prepared statements / parameterized queries
  - Input validation and whitelist of characters
  - WAF with SQLi protection rules
  - ORM with built-in injection protection
```

---

## Repository Structure

```
ciber
    └──threat-model/
                  ├── threat_model.py
                  ├── README.md
                  └── .gitignore
```

---

## References

- [Microsoft STRIDE Threat Modeling](https://learn.microsoft.com/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [NIST SP 800-154 — Data-Centric System Threat Modeling](https://csrc.nist.gov/publications/detail/sp/800-154/draft)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal*

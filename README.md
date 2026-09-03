# Cibersecurity

**Python CLI security tools — built from real investigations, zero external dependencies.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero deps](https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square)](.)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)](https://attack.mitre.org)
[![OWASP](https://img.shields.io/badge/OWASP-aligned-blue?style=flat-square)](https://owasp.org)

---

## What this is

39 Python CLI tools spanning log analysis, forensics, threat intelligence, web application testing, hardening, SAST, and network reconnaissance. Every tool runs on Python 3.10+ with zero external dependencies — just the standard library. No `pip install`, no virtual environments, no version conflicts. Drop the script, run it.

Most of these tools started as solutions to a specific problem I was working through — a CTF challenge, a log analysis task, a forensic investigation. The ones that proved useful enough got cleaned up, documented, tested, and published here. The ones that didn't stayed in a folder somewhere.

The design philosophy is consistent across all of them:

- **Zero external dependencies.** If it needs `requests` or `pandas` to work, it gets rewritten until it doesn't. The only exception is the test harnesses, which sometimes use `pytest` as a dev dependency.
- **Reproduction over assertion.** Every number in a report or analysis produced by these tools can be recalculated by re-running the script. Nothing comes from memory.
- **Transparent failure.** If a parser can't classify a line, it skips and documents — it doesn't guess or silently ignore.
- **OWASP / NIST / MITRE alignment** where applicable. Not for the badges — because it's the vocabulary that practitioners actually use.

---

## Tools

### Log Analysis & Incident Response

| Tool                                      | What it does                                                                                                                                         |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`log-sentinel`](log-sentinel/)           | Multi-format log normalisation and correlation engine — syslog, Apache CLF, UFW firewall logs, JSON Lines. Produces unified chronological timelines. |
| [`firewall-analyzer`](firewall-analyzer/) | UFW/iptables log parser — blocked vs allowed traffic, port distribution, top talkers, outbound anomaly detection.                                    |
| [`network-analyzer`](network-analyzer/)   | Packet-level network log analysis — protocol breakdown, connection duration, data volume by endpoint.                                                |

> **Notable artifact:** [`log-sentinel/log_correlator.py`](log-sentinel/) — used in case CP-2025-001 to reconstruct a 3-month multi-phase intrusion from 5,597 events across four log types. Includes 13 programmatic verification checks. The full incident report is in [`forensics-lab/`](forensics-lab/).

---

### Forensics & Malware Analysis

| Tool                                                  | What it does                                                                                                                          |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| [`forensics-lab`](forensics-lab/)                     | Incident reconstruction toolkit — timeline correlation, IOC extraction, evidence provenance validation.                               |
| [`malware-static-analyzer`](malware-static-analyzer/) | Static analysis of suspicious files — entropy analysis, string extraction, PE header inspection, YARA rule matching.                  |
| [`yara-builder`](yara-builder/)                       | YARA rule generator from IOC sets — builds rules from file hashes, strings, byte patterns.                                            |
| [`steganalysis`](steganalysis/)                       | Steganography detection in image files — LSB analysis, metadata inspection, chi-square tests.                                         |
| [`ir-checklist`](ir-checklist/)                       | Incident response checklist generator — produces phase-by-phase containment, eradication, and recovery checklists from incident type. |
| [`hash-identifier`](hash-identifier/)                 | Hash format identification and offline cracking against wordlists — MD5, SHA-1, SHA-256, bcrypt, NTLM, and others.                    |

> **Notable artifact:** [`forensics-lab/evidence_provenance_validator.py`](forensics-lab/) — 16 unit tests, CI workflow, zero-dependency CLI for chain-of-custody validation. Built for Operação Atalaia (UC01482 exam).

---

### Threat Intelligence

| Tool                                                                | What it does                                                                                                                    |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [`threat-intelligence-aggregator`](threat-intelligence-aggregator/) | Correlates IOCs against multiple open-source feeds — aggregates, deduplicates, scores by recency and source confidence.         |
| [`threat-feed-correlator`](threat-feed-correlator/)                 | Cross-references IPs, domains, and hashes against AbuseIPDB, AlienVault OTX, and VirusTotal APIs.                               |
| [`osint-toolkit`](osint-toolkit/)                                   | Passive OSINT enumeration — WHOIS, DNS history, certificate transparency, Shodan dorks, email pattern inference.                |
| [`cve-research`](cve-research/)                                     | CVE lookup and impact assessment — pulls from NVD, cross-references with known exploit availability.                            |
| [`cve-patch-tracker`](cve-patch-tracker/)                           | Tracks patch status for a given asset inventory against published CVEs — generates prioritised remediation lists by CVSS score. |

---

### Web Application Security

| Tool                                          | What it does                                                                                                                          |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| [`web-app-fuzzer`](web-app-fuzzer/)           | Directory and parameter fuzzer — supports custom wordlists, extension bruteforcing, response fingerprinting.                          |
| [`api-security-tester`](api-security-tester/) | REST API security tests — authentication bypass, rate limiting, IDOR, parameter pollution, schema validation gaps.                    |
| [`header-tester`](header-tester/)             | HTTP security header analyser — checks for CSP, HSTS, X-Frame-Options, CORP/COEP, cookie flags. Scores against OWASP recommendations. |
| [`jwt-analyzer`](jwt-analyzer/)               | JWT inspection and vulnerability testing — algorithm confusion (RS256→HS256), none-algorithm bypass, weak secret bruteforce.          |
| [`ssl-analyzer`](ssl-analyzer/)               | TLS/SSL configuration audit — cipher suite analysis, certificate chain validation, HSTS preload status, protocol downgrade checks.    |
| [`dir-brute-forcer`](dir-brute-forcer/)       | Web directory and file bruteforcer — concurrent requests, custom User-Agent, response code filtering, recursive mode.                 |
| [`subdomain-takeover`](subdomain-takeover/)   | Detects subdomain takeover candidates — resolves CNAMEs to dangling cloud provider endpoints across AWS, GitHub Pages, Heroku, etc.   |

---

### Hardening & Compliance

| Tool                                                  | What it does                                                                                                                           |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| [`hardening-scripts`](hardening-scripts/)             | System hardening automation — applies CIS Benchmark recommendations for Linux servers. Dry-run mode before any changes.                |
| [`ssh-hardening`](ssh-hardening/)                     | SSH configuration auditor and hardener — identifies weak ciphers, MACs, and key exchange algorithms; generates hardened `sshd_config`. |
| [`compliance-checker`](compliance-checker/)           | Policy compliance checker — maps system configuration against CIS, NIST SP 800-53, and ISO 27001 controls.                             |
| [`password-policy-auditor`](password-policy-auditor/) | Audits password policy enforcement — checks PAM configuration, password age, lockout thresholds, complexity requirements.              |
| [`docker-audit`](docker-audit/)                       | Docker security audit — privileged containers, exposed sockets, image vulnerability surface, network mode misconfigurations.           |

---

### SAST & Supply Chain

| Tool                                              | What it does                                                                                                                      |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| [`secrets-scanner`](secrets-scanner/)             | Scans codebases for hardcoded secrets — API keys, credentials, private keys, connection strings. Regex + entropy-based detection. |
| [`sbom-generator`](sbom-generator/)               | Software Bill of Materials generator — produces SPDX and CycloneDX output from Python and Node.js projects.                       |
| [`supply-chain-analyzer`](supply-chain-analyzer/) | Dependency risk analysis — checks for typosquatting candidates, maintainer abandonment indicators, and known-malicious packages.  |
| [`vulnhunter`](vulnhunter/)                       | SAST scanner for common vulnerability patterns — SQL injection, command injection, path traversal, insecure deserialization.      |

---

### Password & Authentication

| Tool                                      | What it does                                                                                                          |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| [`password-analyzer`](password-analyzer/) | Password strength analysis and entropy calculation — estimates crack time against dictionary and brute-force attacks. |

---

### Network Reconnaissance

| Tool                              | What it does                                                                                                                |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| [`net-recon`](net-recon/)         | Network reconnaissance toolkit — port scanning, service fingerprinting, TTL-based OS guessing, banner grabbing.             |
| [`cloud-scanner`](cloud-scanner/) | Cloud asset discovery — enumerates exposed S3 buckets, Azure Blob containers, and GCP Storage buckets from a target domain. |

---

### Reporting & Planning

| Tool                                          | What it does                                                                                                                          |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| [`pentest-report`](pentest-report/)           | Penetration test report generator — takes structured JSON findings and produces formatted Markdown/HTML reports.                      |
| [`threat-model`](threat-model/)               | STRIDE-based threat modelling assistant — walks through data flow diagrams and generates threat catalogues with MITRE ATT&CK mapping. |
| [`blue-team-playbooks`](blue-team-playbooks/) | Incident response playbooks — detection, containment, eradication, and recovery procedures by attack type.                            |

---

### CTF & Labs

| Tool                              | What it does                                                                                                                  |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| [`ctf-crypto`](ctf-crypto/)       | Cryptography toolkit for CTF — Caesar, Vigenère, XOR, RSA small-exponent attacks, frequency analysis, base encoding variants. |
| [`hack-me`](hack-me/)             | Intentionally vulnerable lab environment — for practising the tools in this repo in a controlled setting.                     |
| [`security-quiz`](security-quiz/) | Interactive security knowledge quiz — covers OWASP Top 10, network protocols, cryptography fundamentals, incident response.   |

---

## Academic context

These tools were built alongside a Level 5 CET/TeSP Cybersecurity Specialist programme (Custóias, Matosinhos). Several are direct deliverables from assessed practical activities:

| UC                                          | Tool / Artifact                                                          |
| ------------------------------------------- | ------------------------------------------------------------------------ |
| UC01481 — Log Analysis                      | `log-sentinel/log_analyzer.py` (Apache security analysis, 33 unit tests) |
| UC01482 — Log Normalisation & Filtering     | `log-sentinel/log_correlator.py` (CP-2025-001, 13 verification checks)   |
| UC01482 — Forensics exam (Operação Atalaia) | `forensics-lab/evidence_provenance_validator.py` (16 unit tests, CI)     |
| UC01480 — Threat Intelligence (Modules 5–6) | `threat-intelligence-aggregator/`, `threat-feed-correlator/`             |

Academic origin doesn't mean academic quality. These tools have proper error handling, docstrings, unit tests where applicable, and are designed to be useful outside of a classroom.

---

## How to use any tool

Every tool follows the same pattern:

```bash
python3 <tool-name>/<script>.py --help
```

No installation, no virtual environment. The `--help` flag always works and always explains the options. If it doesn't, open an issue.

---

## What this is not

- A framework. These are standalone scripts, not a library you import.
- An offensive toolkit for unauthorized use. Every tool that touches a network or system is scoped to authorized testing only. See the disclaimer below.
- A finished product. Active development — some tools are more polished than others. The ones with unit tests are the ones I trust most.

---

## Authorized use only

These tools are provided for **educational purposes, authorized security testing, and research only**.

Running these tools against systems, networks, or infrastructure you do not own or have explicit written permission to test is illegal and unethical. The author accepts no liability for misuse.

If in doubt: don't.

---

## Contact

Márcio Coutinho
[github.com/marciolscoutinho](https://github.com/marciolscoutinho)

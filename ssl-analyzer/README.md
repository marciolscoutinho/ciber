<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=12&height=200&section=header&text=SSL/TLS%20Analyzer&fontSize=50&fontAlignY=35&animation=twinkling&fontColor=ffffff" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python%203.x-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Standard-CIS%20%7C%20NIST-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge" />
</p>

<p align="center"><strong>Pure-Python SSL/TLS auditor — cipher suites, certificate validation, protocol versions, and known vulnerabilities.</strong></p>

---

## Features

| Check              | Description                                                |
| ------------------ | ---------------------------------------------------------- |
| 🔐 Certificate     | Expiry, CN/SAN, self-signed, chain validation              |
| 🔒 Protocols       | TLS 1.0/1.1 (deprecated), TLS 1.2/1.3 detection            |
| 🧪 Cipher Suites   | Weak ciphers (RC4, DES, 3DES, NULL, EXPORT)                |
| 🛡 Vulnerabilities | BEAST, POODLE, DROWN, Heartbleed, FREAK, Logjam heuristics |
| 📊 HTTPS Redirect  | HTTP → HTTPS redirect check                                |
| 📋 Report          | Terminal + JSON export                                     |

## Usage

```bash
# Basic scan
python ssl_analyzer.py example.com

# Custom port
python ssl_analyzer.py example.com --port 8443

# JSON output
python ssl_analyzer.py example.com --json report.json

# Verbose
python ssl_analyzer.py example.com --verbose
```

## Output Example

```
╔══════════════════════════════════════════════════╗
║         SSL/TLS ANALYZER — ssl_analyzer          ║
╠══════════════════════════════════════════════════╣
║  Target   : example.com:443                      ║
║  Risk Score: 12/100  [LOW]                       ║
╚══════════════════════════════════════════════════╝

[CERTIFICATE]
  ✅ Valid until: 2025-12-31 (expires in 180 days)
  ✅ Common Name: example.com
  ✅ SANs: example.com, www.example.com

[PROTOCOLS]
  ✅ TLS 1.3: supported
  ✅ TLS 1.2: supported
  ❌ TLS 1.1: not exposed
  ❌ TLS 1.0: not exposed

[FINDINGS]
  No critical issues found.
```

## Standards Alignment

- CIS Controls v8 — 13.2 (Network Infrastructure Hardening)
- NIST SP 800-52r2 — Guidelines for TLS Implementations
- OWASP Testing Guide — OTG-CRYPST-001

## Zero Dependencies

Uses only `ssl` and `socket` from Python stdlib.

---

> Built by [Márcio Coutinho](https://github.com/marciolscoutinho) | Cybersecurity Specialist

# 🔌 API Security Tester

> Lightweight REST API security checks mapped to the OWASP API Security Top 10 2023.  
> Authorized testing only. Zero external dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](api_security_tester.py)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010%202023-black?style=flat-square)](https://owasp.org/API-Security/)

> **Authorized use only.** Only test APIs you own or have explicit written permission to assess.

Repository: <https://github.com/marciolscoutinho/ciber/api-security-tester>

---

## Overview

API Security Tester automates lightweight checks against critical API security risks identified by OWASP. It focuses on authentication, authorization, resource consumption, security misconfiguration, and API inventory exposure.

This tool is intended for:

- Defensive security testing
- Development and staging API reviews
- Cybersecurity training labs
- Bug bounty research within explicitly defined scope
- Internal security validation before release

It is **not** a replacement for a full penetration test, secure code review, threat model, or manual verification.

---

## Installation

No third-party packages are required.

```bash
git clone https://github.com/marciolscoutinho/ciber.git
cd ciber
python --version
python api_security_tester.py --version
```

Requires Python 3.8 or newer.

---

## Quick Start

```bash
# Basic scan without authentication
python api_security_tester.py https://api.example.com

# Authenticated scan with a raw bearer token
python api_security_tester.py https://api.example.com --token "eyJhbGciOi..."

# Authenticated scan with the full Authorization value
python api_security_tester.py https://api.example.com --token "Bearer eyJhbGciOi..."

# Scan specific object endpoints for BOLA-style checks
python api_security_tester.py https://api.example.com   --endpoints /api/v1/users/1 /api/v1/orders/1

# JSON output to stdout and file
python api_security_tester.py https://api.example.com --json -o api_security_report.json

# Verbose mode
python api_security_tester.py https://api.example.com --verbose

# Lab or self-signed TLS target only
python api_security_tester.py https://localhost:8443 --insecure
```

---

## OWASP API Security Top 10 2023 Coverage

| API      | Name                                       | Checks Performed                                                              |
| -------- | ------------------------------------------ | ----------------------------------------------------------------------------- |
| **API1** | Broken Object Level Authorization (BOLA)   | ID manipulation (`0`, `-1`, `99999`, `admin`, `../admin`)                     |
| **API2** | Broken Authentication                      | Missing token, malformed token, empty token                                   |
| **API3** | Broken Object Property Level Authorization | Mass assignment payloads (`role:admin`, `isAdmin:true`, wildcard permissions) |
| **API4** | Unrestricted Resource Consumption          | Excessive pagination values (`limit=99999`, `page_size=99999`)                |
| **API5** | Broken Function Level Authorization        | Common administrative and internal endpoints                                  |
| **API8** | Security Misconfiguration                  | Missing headers, permissive CORS, verbose errors                              |
| **API9** | Improper Inventory Management              | Multiple active API versions and legacy paths                                 |

Current automated coverage: **7/10 OWASP API Top 10 categories**.

---

## Test Details

### API1 — BOLA (Broken Object Level Authorization)

```text
Tests   : Replace numeric IDs with 0, -1, 99999, admin, ../admin
Examples: /api/v1/users/{id}, /api/v1/orders/{id}
Finding : HTTP 200 with data that may not belong to the authenticated user
Severity: HIGH
```

### API2 — Broken Authentication

```text
Tests:
  - Request without Authorization header
  - Authorization: Bearer invalid
  - Authorization: Bearer null
  - Authorization: Bearer eyJ.bad.token
Finding : HTTP 200 response to unauthenticated or malformed-auth requests
Severity: CRITICAL / HIGH
```

### API3 — Mass Assignment

```json
{"role":"admin","isAdmin":true,"userId":1}
{"role":"superuser","permissions":["*"]}
{"balance":99999,"premium":true}
```

Finding: HTTP 200/201 where privileged fields appear accepted or reflected.  
Severity: HIGH.

### API5 — Function Level Authorization

```text
Tests: GET /admin, /api/admin, /actuator, /api/debug,
       /management, /.env, /api/config, /api/v1/stats
Finding : HTTP 200 on administrative endpoints with a normal user token
Severity: HIGH
```

### API8 — Security Misconfiguration

```text
Tests:
  - Missing security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options
  - CORS probe: Origin: https://evil.com
  - Verbose error probe: /api/v1/trigger_error_xyzabc
Finding : Permissive CORS, missing headers, or exposed stack traces
Severity: HIGH / MEDIUM / LOW
```

---

## Output and Exit Codes

| Code | Meaning                                           |
| ----:| ------------------------------------------------- |
| `0`  | No findings, only `LOW`, or informational results |
| `1`  | At least one `MEDIUM` or `HIGH` finding           |
| `2`  | At least one `CRITICAL` finding                   |

Reports are written as JSON when `--json` or `-o` is used.

---

## Safe Testing Environments

```bash
# OWASP WebGoat / WebWolf
# Documentation: https://owasp.org/www-project-webgoat/
docker run -p 8080:8080 webgoat/goat-and-wolf
python api_security_tester.py http://localhost:8080/WebGoat/

# VAmPI - Vulnerable API
docker run -p 5000:5000 erev0s/vampi:latest
python api_security_tester.py http://localhost:5000   --endpoints /users/v1/admin /books/v1

# Your own local hack-me API
python api_security_tester.py http://localhost:5000   --token "$(python -c 'print("test-token")')"
```

---

## Repository Structure

```text
ciber/
├── .github/
│   └── workflows/
│       └── ci.yml
├── .gitignore
├── DISCLAIMER.md
├── LICENSE
├── README.md
└── api_security_tester.py
```

---

## Legal and Ethical Notice

This project is for authorized security testing, research, and education only. Do not scan, probe, or test systems without explicit permission from the owner.

Read the full disclaimer before using the tool: [DISCLAIMER.md](DISCLAIMER.md)

---

## References

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/)
- [OWASP Web Security Testing Guide — API Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [VAmPI — Vulnerable API](https://github.com/erev0s/VAmPI)

---

Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal.

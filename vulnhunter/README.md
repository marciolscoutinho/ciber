# 🔍 VulnHunter

> Zero-dependency Python SAST tool detecting 21+ vulnerability categories mapped to OWASP Top 10 and CWE.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-black?style=flat-square)](https://owasp.org/Top10/)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](vulnhunter.py)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square)](https://github.com/marciolscoutinho/vulnhunter/actions)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Detection Rules](#detection-rules)
- [Installation](#installation)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [CI/CD Integration](#cicd-integration)
- [Architecture](#architecture)

---

## Overview

VulnHunter performs **static analysis** of Python source code, identifying security vulnerabilities before they reach production. It maps each finding to **OWASP Top 10 2021** and **CWE** identifiers.

**No external dependencies** — runs with Python 3.8+ stdlib only.

```bash
python vulnhunter.py scan ./my-project/
```

```
[CRITICAL] CWE-89  SQL Injection — app.py:42
           query = f"SELECT * FROM users WHERE id={user_id}"
           Fix: Use parameterized queries

[HIGH]     CWE-798 Hardcoded Secret — config.py:15
           api_key = "sk-prod-abc123xyz..."
           Fix: Use environment variables
```

---

## Detection Rules

| ID     | Vulnerability                  | CWE     | OWASP    | Severity    |
| ------ | ------------------------------ | ------- | -------- | ----------- |
| VH-001 | SQL Injection                  | CWE-89  | A03:2021 | 🔴 Critical |
| VH-002 | Command Injection              | CWE-78  | A03:2021 | 🔴 Critical |
| VH-003 | Path Traversal                 | CWE-22  | A01:2021 | 🔴 Critical |
| VH-004 | Server-Side Template Injection | CWE-94  | A03:2021 | 🔴 Critical |
| VH-005 | Hardcoded Secrets              | CWE-798 | A07:2021 | 🔴 Critical |
| VH-006 | Cross-Site Scripting (XSS)     | CWE-79  | A03:2021 | 🟠 High     |
| VH-007 | SSRF                           | CWE-918 | A10:2021 | 🟠 High     |
| VH-008 | Insecure Deserialization       | CWE-502 | A08:2021 | 🟠 High     |
| VH-009 | XML External Entity (XXE)      | CWE-611 | A05:2021 | 🟠 High     |
| VH-010 | LDAP Injection                 | CWE-90  | A03:2021 | 🟠 High     |
| VH-011 | Open Redirect                  | CWE-601 | A01:2021 | 🟠 High     |
| VH-012 | Weak Cryptography              | CWE-327 | A02:2021 | 🟠 High     |
| VH-013 | Unsafe File Upload             | CWE-434 | A04:2021 | 🟠 High     |
| VH-014 | NoSQL Injection                | CWE-943 | A03:2021 | 🟡 Medium   |
| VH-015 | Mass Assignment                | CWE-915 | A03:2021 | 🟡 Medium   |
| VH-016 | Debug Mode Enabled             | CWE-489 | A05:2021 | 🟡 Medium   |
| VH-017 | Logging Injection              | CWE-117 | A09:2021 | 🟡 Medium   |
| VH-018 | Broken Access Control          | CWE-284 | A01:2021 | 🟡 Medium   |
| VH-019 | Information Disclosure         | CWE-200 | A05:2021 | 🟡 Medium   |
| VH-020 | Race Condition                 | CWE-362 | A04:2021 | 🟡 Medium   |
| VH-021 | Unsafe Eval                    | CWE-95  | A03:2021 | 🟡 Medium   |

---

## Installation

```bash
# No installation needed — pure Python stdlib
git clone https://github.com/marciolscoutinho/vulnhunter.git
cd vulnhunter

# Verify Python version
python --version  # Python 3.8+
```

---

## Usage

### Scan a single file

```bash
python vulnhunter.py scan app.py
```

### Scan a directory recursively

```bash
python vulnhunter.py scan ./src/
```

### Filter by severity

```bash
python vulnhunter.py scan ./src/ --min-severity HIGH
```

### Output formats

```bash
# Terminal (default — color-coded)
python vulnhunter.py scan ./src/

# JSON (machine-readable)
python vulnhunter.py scan ./src/ --json -o report.json

# HTML (shareable report)
python vulnhunter.py scan ./src/ --html -o report.html
```

### List all detection rules

```bash
python vulnhunter.py rules
```

---

## Output Formats

### Terminal Output

```
══════════════════════════════════════════════════
  VULNHUNTER SCAN RESULTS
  Target: ./myapp/  |  Files: 12  |  Issues: 3
══════════════════════════════════════════════════

  [CRITICAL] VH-001 — SQL Injection
  File   : myapp/db.py:42
  Code   : query = f"SELECT * FROM users WHERE id={user_id}"
  CWE    : CWE-89
  OWASP  : A03:2021 — Injection
  Fix    : Use parameterized queries: cursor.execute('SELECT...', (id,))
```

### JSON Output

```json
{
  "scan_time": "2024-01-15T10:30:00",
  "target": "./myapp/",
  "files_scanned": 12,
  "total_findings": 3,
  "findings": [
    {
      "id": "VH-001",
      "severity": "CRITICAL",
      "title": "SQL Injection",
      "file": "myapp/db.py",
      "line": 42,
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "code": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
      "remediation": "Use parameterized queries"
    }
  ]
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/sast.yml
name: SAST Scan

on: [push, pull_request]

jobs:
  vulnhunter:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run VulnHunter
        run: python vulnhunter.py scan ./src/ --min-severity HIGH
        # Exit code 2 = CRITICAL findings found
        # Exit code 1 = HIGH findings found
        # Exit code 0 = clean
```

### Exit Codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| `0`  | No findings (or below threshold) |
| `1`  | HIGH severity findings           |
| `2`  | CRITICAL severity findings       |

---

## Architecture

```
vulnhunter.py
├── FileScanner          — file discovery + filtering
├── RuleEngine           — pattern matching (regex-based)
│   ├── SQLiRule         — SQL injection patterns
│   ├── CMDiRule         — command injection patterns
│   ├── SecretsRule      — hardcoded credential patterns
│   └── ... (21 rules)
├── Reporter
│   ├── TerminalReporter — ANSI color output
│   ├── JSONReporter     — structured output
│   └── HTMLReporter     — shareable report
└── CLI                  — argparse interface
```

---

## ⚠️ Disclaimer

VulnHunter performs **static analysis only**. Results may include false positives and false negatives. Manual code review is always recommended alongside automated tools.

---

*Built by [Márcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

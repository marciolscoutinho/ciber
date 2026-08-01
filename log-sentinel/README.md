# 📊 Log Sentinel

> Multi-format log analyzer with behavioral detection — brute-force, scanners,
> path traversal, anomalous logins. SIEM-ready JSON/CSV export.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](log_sentinel.py)
[![Tests](https://img.shields.io/badge/Tests-35%20pytest-brightgreen?style=flat-square)](tests/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square)](.github/workflows/ci.yml)

---

## 📋 Overview

Log Sentinel parses multiple log formats and applies **behavioral detection rules**
to identify attacks, anomalies, and security incidents in real time.

```bash
# Analyze Apache access log
python log_sentinel.py --file /var/log/apache2/access.log --format apache

# Analyze SSH auth log
python log_sentinel.py --file /var/log/auth.log --format ssh

# Export SIEM-ready JSON
python log_sentinel.py --file access.log --format apache --json -o alerts.json
```

---

## 🎯 Supported Log Formats

| Format   | Log Source                  | Parser                    |
| -------- | --------------------------- | ------------------------- |
| `apache` | Apache/Nginx access logs    | Common Log Format (CLF)   |
| `ssh`    | Linux auth.log              | SSH authentication events |
| `syslog` | System logs                 | RFC 5424                  |
| `json`   | Structured application logs | Auto key mapping          |

---

## 🚨 Detection Rules

### Apache / Nginx

| Rule                  | Description                                  | Threshold      |
| --------------------- | -------------------------------------------- | -------------- |
| SQL Injection         | `'`, `UNION SELECT`, `OR 1=1` in URI         | Any occurrence |
| XSS                   | `<script>`, `javascript:`, `onerror=` in URI | Any occurrence |
| Path Traversal        | `../`, `%2e%2e%2f`, `....//`                 | Any occurrence |
| SSTI                  | `{{`, `${`, `#{` in URI                      | Any occurrence |
| Command Injection     | `cmd=`, `exec=`, `                           | ls`, `;id`     |
| Scanner Detection     | Nmap, sqlmap, nikto, Burp, dirb UA           | Any occurrence |
| High Volume IP        | Single IP with excessive requests            | >500 req/min   |
| 4xx Flood             | Many 404/403 from same IP                    | >50 errors/min |
| Sensitive Path Access | `/admin`, `/.env`, `/.git`, `/wp-admin`      | Any occurrence |

### SSH Authentication

| Rule                    | Description                          | Threshold      |
| ----------------------- | ------------------------------------ | -------------- |
| Brute Force             | Failed login attempts                | >10 in 60s     |
| Login After Failures    | Success after multiple failures      | Configurable   |
| Invalid User            | Attempts with non-existent usernames | Any occurrence |
| Root Login Attempt      | Direct root SSH login attempt        | Any occurrence |
| Distributed Brute Force | Multiple IPs targeting same user     | >5 IPs         |

---

## 🚀 Usage

```bash
# Apache log analysis
python log_sentinel.py --file /var/log/apache2/access.log --format apache

# SSH with custom brute-force threshold
python log_sentinel.py --file /var/log/auth.log --format ssh --threshold 5

# JSON output for SIEM
python log_sentinel.py --file access.log --format apache --json -o alerts.json

# CSV output for spreadsheet
python log_sentinel.py --file access.log --format apache --csv -o alerts.csv

# Verbose (show all parsed events)
python log_sentinel.py --file access.log --format apache --verbose

# Analyze last N lines
python log_sentinel.py --file access.log --format apache --tail 1000
```

---

## 📊 Example Output

```
  ════════════════════════════════════════════════════════════════════════
  LOG SENTINEL ANALYSIS REPORT
  File   : /var/log/apache2/access.log
  Format : apache
  Lines  : 48,291
  ════════════════════════════════════════════════════════════════════════

  [CRITICAL] SQL Injection Attempt
  IP     : 185.220.101.47
  Time   : 2024-01-15 03:22:11
  URI    : /search?q=1'+UNION+SELECT+username,password,3+FROM+users--
  UA     : sqlmap/1.7.8

  [HIGH] SSH Brute Force Detected
  IP     : 203.0.113.42
  Attempts: 247 in 60 seconds
  Users  : root, admin, ubuntu, pi

  [HIGH] Web Scanner Detected
  IP     : 198.51.100.23
  UA     : Nmap Scripting Engine
  Paths  : 1,842 unique paths probed

  SUMMARY
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total events    : 48,291
  Alerts generated: 14
  Critical        : 3
  High            : 6
  Medium          : 5
  Top attacker    : 185.220.101.47 (247 events)
```

---

## 🧪 Test Coverage

```bash
# Run all tests
pytest tests/ -v

# Coverage report
pytest tests/ --cov=log_sentinel --cov-report=html
```

**35 tests across 2 test files:**

| File                    | Tests | Coverage                                                 |
| ----------------------- | ----- | -------------------------------------------------------- |
| `test_parser_apache.py` | 18    | Apache parsing, SQLi, XSS, SSTI, scanner UA, risk score  |
| `test_parser_ssh.py`    | 17    | Brute-force threshold, post-failure login, invalid users |

---

## 🔁 CI/CD

```yaml
# .github/workflows/ci.yml
jobs:
  test:         # pytest on Python 3.8, 3.10, 3.12
  scan-samples: # run on sample log files
  validate-json: # JSON schema validation
```

---

## 📁 Repository Structure

```
log-sentinel/
├── log_sentinel.py
├── tests/
│   ├── test_parser_apache.py   ← 18 pytest tests
│   └── test_parser_ssh.py      ← 17 pytest tests
├── samples/
│   ├── sample_apache.log
│   └── sample_ssh.log
├── .github/workflows/ci.yml
├── README.md
└── .gitignore
```

---

*Built by [Márcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

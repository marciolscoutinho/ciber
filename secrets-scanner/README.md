# 🔑 Secrets Scanner

> Scans files and git history for leaked secrets — API keys, tokens, private keys,
> passwords, and connection strings. 28 detection rules. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](secrets_scanner.py)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square)](https://github.com/marciolscoutinho/secrets-scanner/actions)

---

## 📋 Overview

Secrets Scanner detects credentials accidentally committed to source code or git history.
Inspired by **TruffleHog** and **gitleaks** — built with zero external dependencies.

```bash
# Scan a directory
python secrets_scanner.py ./myproject

# Scan including git history
python secrets_scanner.py ./myproject --git

# Scan only CRITICAL and HIGH
python secrets_scanner.py ./myproject --severity HIGH
```

---

## 🎯 Detection Rules (28)

| Category         | Rule ID  | Examples                                   | Severity    |
| ---------------- | -------- | ------------------------------------------ | ----------- |
| **AWS**          | AWS-001  | `AKIA[0-9A-Z]{16}` (Access Key ID)         | 🔴 CRITICAL |
| **AWS**          | AWS-002  | Secret Access Key pattern                  | 🔴 CRITICAL |
| **GCP**          | GCP-001  | `AIza[0-9A-Za-z\-_]{35}`                   | 🟠 HIGH     |
| **GCP**          | GCP-002  | Service Account JSON                       | 🔴 CRITICAL |
| **Azure**        | AZ-001   | Storage connection string                  | 🔴 CRITICAL |
| **Azure**        | AZ-002   | SAS token                                  | 🟠 HIGH     |
| **GitHub**       | GH-001   | `ghp_[a-zA-Z0-9]{36}`                      | 🔴 CRITICAL |
| **GitHub**       | GH-002   | `gho_[a-zA-Z0-9]{36}`                      | 🔴 CRITICAL |
| **GitHub**       | GH-003   | `ghs_/ghu_` tokens                         | 🔴 CRITICAL |
| **Slack**        | SL-001   | `xox[baprs]-...`                           | 🟠 HIGH     |
| **Stripe**       | TW-001   | `sk_live_/pk_live_`                        | 🔴 CRITICAL |
| **SendGrid**     | SQ-001   | `SG.[a-zA-Z0-9]{22}.[a-zA-Z0-9]{43}`       | 🟠 HIGH     |
| **Twilio**       | TW-002   | `AC[a-f0-9]{32}`                           | 🟠 HIGH     |
| **Passwords**    | PW-001   | `password = "..."` assignments             | 🟠 HIGH     |
| **Passwords**    | PW-002   | `"password": "..."` dict keys              | 🟠 HIGH     |
| **Database**     | DB-001   | `mysql://user:pass@host`                   | 🔴 CRITICAL |
| **Database**     | DB-002   | MongoDB connection strings                 | 🔴 CRITICAL |
| **Private Keys** | KEY-001  | `-----BEGIN RSA PRIVATE KEY-----`          | 🔴 CRITICAL |
| **Private Keys** | KEY-002  | PGP private key blocks                     | 🔴 CRITICAL |
| **Private Keys** | KEY-003  | OpenSSH private keys                       | 🔴 CRITICAL |
| **JWT**          | JWT-001  | JWT token pattern                          | 🟡 MEDIUM   |
| **JWT**          | JWT-002  | `jwt_secret = "..."`                       | 🔴 CRITICAL |
| **SMTP**         | SMTP-001 | SMTP credentials                           | 🟠 HIGH     |
| **Environment**  | ENV-001  | `.env` file secret patterns                | 🟠 HIGH     |
| **HubSpot**      | HB-001   | HubSpot API keys                           | 🟡 MEDIUM   |
| **Generic**      | PRIV-001 | username+password combos                   | 🟡 MEDIUM   |
| **Entropy**      | ENT-001  | High-entropy strings in credential context | 🟢 LOW      |

---

## 🚀 Usage

```bash
# Basic directory scan
python secrets_scanner.py ./src/

# Include git history (last 50 commits)
python secrets_scanner.py ./myrepo --git

# Scan last 200 commits
python secrets_scanner.py ./myrepo --git --max-commits 200

# Only show HIGH and CRITICAL
python secrets_scanner.py ./src/ --severity HIGH

# JSON output
python secrets_scanner.py ./src/ --json -o secrets_report.json

# Save report
python secrets_scanner.py ./src/ -o secrets_report.json

# List all detection rules
python secrets_scanner.py ./src/ --list-rules

# Verbose (show progress)
python secrets_scanner.py ./src/ --verbose
```

---

## 📊 Example Output

```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [CRITICAL] (AWS-001) AWS Access Key ID
  File     : config/settings.py:23
  Line     : aws_access_key = "AKIAIOSFODNN7EXAMPLE..."
  Desc.    : AWS Access Key ID exposed — full AWS account access possible
  Fix      : Revoke in IAM > Access keys. Use environment variables.

  [CRITICAL] (KEY-001) RSA Private Key
  Commit   : a3f2b1c9 | Author: dev@company.com | Date: 2024-01-10
  Line     : -----BEGIN RSA PRIVATE KEY-----
  Desc.    : RSA private key committed to git history
  Fix      : Revoke and regenerate keypair immediately.

  ════════════════════════════════════════════════════════════════════════
  SECRETS SCAN SUMMARY
  Target        : ./myproject
  Files scanned : 47
  Total findings: 3
  CRITICAL      : ████████ 2
  HIGH          : ████ 1
  Risk Score    : 85/100
  ════════════════════════════════════════════════════════════════════════

  ⚠  ACTION REQUIRED:
  1. IMMEDIATELY revoke all CRITICAL and HIGH secrets
  2. Assume secrets are compromised even without evidence
  3. Add .env, *.key, *.pem to .gitignore
  4. Use git-filter-repo or BFG to remove from git history
  5. Implement pre-commit hooks to prevent future leaks
```

---

## 🔁 CI/CD Integration

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
python secrets_scanner.py . --severity HIGH --no-banner
if [ $? -ne 0 ]; then
    echo "🚨 Secrets detected! Commit blocked."
    exit 1
fi
```

### GitHub Actions

```yaml
name: Secrets Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git scan
      - name: Scan for secrets
        run: |
          python secrets_scanner.py . --git --severity HIGH --no-banner
```

### Exit Codes

| Code | Meaning                               |
| ---- | ------------------------------------- |
| `0`  | No secrets found (or below threshold) |
| `1`  | HIGH secrets found                    |
| `2`  | CRITICAL secrets found                |

---

## 🛡️ Remediation Guide

### If a secret is found in the current codebase:

```bash
# 1. Remove from code and add to .gitignore
echo ".env" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore

# 2. Revoke the secret immediately (before cleaning git history)

# 3. Remove from git history using BFG
java -jar bfg.jar --delete-files .env
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force
```

### If a secret is found in git history:

```bash
# Using git-filter-repo (recommended)
pip install git-filter-repo
git filter-repo --invert-paths --path path/to/secret_file

# Or using BFG Repo-Cleaner
java -jar bfg.jar --replace-text secrets.txt myrepo.git
```

---

*Built by [Márcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

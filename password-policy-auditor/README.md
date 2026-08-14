# 🔑 Password Policy Auditor

> Audits Linux system password policies against NIST SP 800-63B and CIS Benchmark.
> Checks PAM, pwquality.conf, login.defs, faillock, and user accounts.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](password_policy_auditor.py)
[![NIST](https://img.shields.io/badge/NIST-SP%20800--63B-blue?style=flat-square)](https://pages.nist.gov/800-63-3/sp800-63b.html)
[![CIS](https://img.shields.io/badge/CIS-Benchmark-orange?style=flat-square)](https://www.cisecurity.org)

---

## Overview

Audits password configuration files and user accounts on Linux systems,
reporting deviations from NIST SP 800-63B and CIS Benchmark standards.

```bash
# Audit local system (auto-detect)
python password_policy_auditor.py

# Include user account audit
python password_policy_auditor.py --accounts

# Demo mode (insecure configuration)
python password_policy_auditor.py --demo

# Show passing checks too
python password_policy_auditor.py --show-ok

# Save report
python password_policy_auditor.py -o password_report.md
```

---

## Audit Coverage

### `/etc/security/pwquality.conf` — PAM Password Quality

| Setting     | Expected | Severity | Description                       |
| ----------- | -------- | -------- | --------------------------------- |
| `minlen`    | >= 14    | HIGH     | Minimum password length           |
| `dcredit`   | <= -1    | MEDIUM   | At least 1 digit required         |
| `ucredit`   | <= -1    | MEDIUM   | At least 1 uppercase required     |
| `lcredit`   | <= -1    | MEDIUM   | At least 1 lowercase required     |
| `ocredit`   | <= -1    | MEDIUM   | At least 1 special char required  |
| `maxrepeat` | <= 3     | LOW      | Max consecutive repeated chars    |
| `difok`     | >= 7     | LOW      | Min chars different from previous |

### `/etc/login.defs` — System-wide Defaults

| Setting          | Expected           | Severity | CIS Ref     |
| ---------------- | ------------------ | -------- | ----------- |
| `PASS_MAX_DAYS`  | <= 365             | HIGH     | CIS 5.4.1.1 |
| `PASS_MIN_DAYS`  | >= 1               | LOW      | CIS 5.4.1.2 |
| `PASS_WARN_AGE`  | >= 7               | LOW      | CIS 5.4.1.3 |
| `PASS_MIN_LEN`   | >= 14              | HIGH     | CIS 5.3.1   |
| `LOGIN_RETRIES`  | <= 5               | MEDIUM   | CIS 5.2.7   |
| `ENCRYPT_METHOD` | SHA512 or YESCRYPT | CRITICAL | CIS 5.3.4   |

### PAM Faillock — Account Lockout

| Setting             | Expected | Severity | Description                     |
| ------------------- | -------- | -------- | ------------------------------- |
| faillock configured | yes      | HIGH     | Account lockout must be enabled |
| `deny`              | <= 5     | HIGH     | Lock after 5 failed attempts    |
| `unlock_time`       | >= 900   | MEDIUM   | 15 min lockout duration         |

### User Account Audit (`--accounts`)

| Check                                  | Severity | Description                     |
| -------------------------------------- | -------- | ------------------------------- |
| UID 0 accounts (non-root)              | CRITICAL | Only root should have UID 0     |
| Accounts without password              | CRITICAL | Empty password = no auth needed |
| Passwords > 365 days old               | MEDIUM   | Stale credentials               |
| System accounts with interactive shell | HIGH     | Daemon accounts can login       |

---

## NIST SP 800-63B Key Requirements

> **Note:** NIST 800-63B Rev.4 (2024 draft) significantly changes recommendations:

| NIST Requirement                         | Description                                  |
| ---------------------------------------- | -------------------------------------------- |
| Minimum 8 characters (recommended 15+)   | Length > complexity                          |
| No forced periodic rotation              | Only change when compromised                 |
| Check against breached password lists    | HaveIBeenPwned API                           |
| No composition rules (uppercase+special) | Reduces usability without improving security |
| MFA strongly recommended                 | Most important control                       |

---

## Usage

```bash
# Basic audit (no root needed for most checks)
python password_policy_auditor.py

# Full audit including user accounts (requires /etc/shadow read)
sudo python password_policy_auditor.py --accounts

# Demo with insecure config
python password_policy_auditor.py --demo

# Show all checks (including passing)
python password_policy_auditor.py --show-ok

# JSON output
python password_policy_auditor.py --json

# Save Markdown report
python password_policy_auditor.py -o password_audit.md
```

---

## Example Output

```
  PASSWORD POLICY AUDIT SUMMARY
  System   : Linux
  Checks   : 12
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Score: 42/100  [████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]
  ❌ Non-Compliant: 7  ✅ Compliant: 5

  [CRITICAL] Hash algorithm: MD5  (login.defs)
  Expected  : SHA512 or YESCRYPT
  Fix       : Set ENCRYPT_METHOD SHA512 in /etc/login.defs
              Existing passwords remain MD5 until changed.

  [HIGH] Minimum password length: 6  (pwquality.conf)
  Expected  : >= 14 (CIS) / >= 8 (NIST minimum)
  Fix       : Set 'minlen = 14' in /etc/security/pwquality.conf

  [HIGH] No account lockout (faillock not configured)
  Fix       : Install faillock and configure:
              deny = 5
              unlock_time = 900
```

---

## Remediation

```bash
# Fix hash algorithm
echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs

# Fix minimum length
echo "minlen = 14" >> /etc/security/pwquality.conf
echo "dcredit = -1" >> /etc/security/pwquality.conf
echo "ucredit = -1" >> /etc/security/pwquality.conf
echo "lcredit = -1" >> /etc/security/pwquality.conf
echo "ocredit = -1" >> /etc/security/pwquality.conf

# Configure faillock (/etc/security/faillock.conf)
cat >> /etc/security/faillock.conf << EOF
deny = 5
unlock_time = 900
fail_interval = 900
EOF

# Fix password expiry
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
```

---

## Repository Structure

```
password-policy-auditor/
├── password_policy_auditor.py
├── README.md
└── .gitignore
```

---

## References

- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [CIS Benchmark — Linux Password Policy](https://www.cisecurity.org/benchmark/distribution_independent_linux)
- [PAM pwquality Documentation](https://github.com/libpwquality/libpwquality)
- [ENISA — Password Policy Guidelines](https://www.enisa.europa.eu/publications/guidelines-for-smes-on-the-security-of-personal-data-processing)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist , Porto, Portugal*

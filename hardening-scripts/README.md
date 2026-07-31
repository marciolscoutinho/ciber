# 🛡️ Hardening Scripts

> Linux system hardening checker against CIS Benchmark Level 1 & 2.
> 20 automated controls. Weighted security score 0-100. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](hardening_check.py)
[![CIS](https://img.shields.io/badge/CIS-Benchmark%20L1%2FL2-orange?style=flat-square)](https://www.cisecurity.org)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square)](.github/workflows/ci.yml)

---

## Overview

Hardening Scripts audits a Linux system configuration against the
**CIS Benchmark for Linux** — the gold standard for system hardening.
Reports a weighted compliance score and prioritized remediation steps.

```bash
# Audit local system (requires some root checks)
python hardening_check.py

# Check mode only (no changes)
python hardening_check.py --check

# JSON output
python hardening_check.py --json -o hardening_results.json

# Save Markdown report
python hardening_check.py -o hardening_report.md

# Show only failing checks
python hardening_check.py --failures-only

# Verbose (show all checks including passing)
python hardening_check.py --verbose
```

---

## Controls (20)

### Filesystem & Mount (4)

| Check                             | CIS Ref | Severity | Description                     |
| --------------------------------- | ------- | -------- | ------------------------------- |
| `/tmp` separate partition         | 1.1.2   | MEDIUM   | Dedicated partition with noexec |
| `/tmp` noexec,nodev,nosuid        | 1.1.3-5 | HIGH     | Mount options for `/tmp`        |
| `/var` separate partition         | 1.1.6   | MEDIUM   | Log rotation protection         |
| Sticky bit on world-writable dirs | 1.1.21  | HIGH     | Prevent file deletion by others |

### Software & Updates (3)

| Check                    | CIS Ref | Severity | Description                |
| ------------------------ | ------- | -------- | -------------------------- |
| Package manager GPG keys | 1.2.1   | HIGH     | Verify package signatures  |
| Auto-update enabled      | 1.3.1   | MEDIUM   | Automatic security patches |
| AIDE/Tripwire installed  | 1.3.2   | MEDIUM   | File integrity monitoring  |

### Process Hardening (4)

| Check                   | CIS Ref | Severity | Description                     |
| ----------------------- | ------- | -------- | ------------------------------- |
| Core dumps restricted   | 1.5.1   | MEDIUM   | Prevent sensitive data in dumps |
| ASLR enabled            | 1.5.3   | HIGH     | Address space randomisation     |
| Prelink disabled        | 1.5.4   | LOW      | Avoid ASLR bypass via prelink   |
| AppArmor/SELinux active | 1.6.1   | HIGH     | Mandatory access control        |

### Network (4)

| Check                            | CIS Ref | Severity | Description             |
| -------------------------------- | ------- | -------- | ----------------------- |
| IP forwarding disabled           | 3.1.1   | HIGH     | Not a router            |
| Packet redirect sending disabled | 3.1.2   | MEDIUM   | Prevent routing attacks |
| Reverse path filtering           | 3.2.7   | HIGH     | Block spoofed packets   |
| TCP SYN cookies enabled          | 3.2.8   | HIGH     | SYN flood protection    |

### Accounts & Logging (5)

| Check                        | CIS Ref | Severity | Description         |
| ---------------------------- | ------- | -------- | ------------------- |
| Password expiry configured   | 5.4.1   | HIGH     | PASS_MAX_DAYS ≤ 365 |
| Password minimum length      | 5.3.1   | HIGH     | PASS_MIN_LEN ≥ 14   |
| Root PATH not containing `.` | 6.2.6   | CRITICAL | Prevent PATH hijack |
| Auditd installed and running | 4.1.1   | HIGH     | System audit daemon |
| rsyslog/syslog-ng active     | 4.2.1   | HIGH     | Centralized logging |

---

## Usage

```bash
# Full audit
python hardening_check.py

# Dry-run (no system modifications — check-only)
python hardening_check.py --check

# Only show failing checks
python hardening_check.py --failures-only

# JSON for automation
python hardening_check.py --json > hardening.json

# Save report
python hardening_check.py -o hardening_report.md

# Check specific category
python hardening_check.py --category network
python hardening_check.py --category accounts
```

---

## Example Output

```
  LINUX HARDENING AUDIT
  CIS Benchmark Level 1 & 2
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [CRITICAL] Root PATH contains current directory (.)
  CIS Ref  : 6.2.6
  Fix      : Remove '.' from root's PATH in /root/.bashrc and /root/.profile

  [HIGH] ASLR not fully enabled
  Current  : kernel.randomize_va_space = 1
  Expected : kernel.randomize_va_space = 2
  Fix      : echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf
             sysctl -p

  [HIGH] AppArmor not active
  Fix      : apt install apparmor apparmor-utils
             systemctl enable apparmor && systemctl start apparmor

  ════════════════════════════════════════════════════════════════════
  Score   : 67/100  [██████████████████████████████░░░░░░░░░░]
  PASS    : 12  FAIL: 7  WARN: 1
```

---

## Remediation Examples

```bash
# Enable ASLR
echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-hardening.conf
sysctl --system

# Enable TCP SYN cookies
echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/99-hardening.conf
sysctl --system

# Disable IP forwarding
echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-hardening.conf
sysctl --system

# Enable reverse path filtering
echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.d/99-hardening.conf
sysctl --system

# Install and configure auditd
apt install auditd audispd-plugins
systemctl enable auditd && systemctl start auditd
```

---

## Repository Structure

```
ciber
    └── hardening-scripts/
                        ├── hardening_check.py
                        ├── .github/
                        │         └── workflows/
                        │                     └── ci.yml
                        ├── README.md
                        └── .gitignore
```

---

## References

- [CIS Benchmark for Debian Linux](https://www.cisecurity.org/benchmark/debian_linux)
- [CIS Benchmark for Ubuntu Linux](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [NIST SP 800-123 — Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [Linux Security Hardening](https://madaidans-insecurities.github.io/guides/linux-hardening.html)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal*

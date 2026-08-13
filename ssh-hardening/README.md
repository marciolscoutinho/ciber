# 🔒 SSH Hardening Checker

> Audits SSH server configuration (sshd_config) against CIS Benchmark
> and NIST SP 800-53. 30 checks. Weighted score 0–100.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](ssh_hardening.py)
[![CIS](https://img.shields.io/badge/CIS-Benchmark-orange?style=flat-square)](https://www.cisecurity.org)
[![NIST](https://img.shields.io/badge/NIST-SP%20800--53-blue?style=flat-square)](https://csrc.nist.gov)

---

## 📋 Overview

Audits `sshd_config` against industry standards and generates a weighted
compliance score with prioritized remediation steps.

```bash
# Audit local SSH config
python ssh_hardening.py

# Audit specific config file
python ssh_hardening.py /etc/ssh/sshd_config

# Read live active config (sshd -T)
python ssh_hardening.py --live

# Show all checks including passing ones
python ssh_hardening.py --show-pass

# Save Markdown report
python ssh_hardening.py -o ssh_report.md
```

---

## 🎯 Checks (30 Total)

### Authentication (7 checks)

| Directive                         | Expected | Severity    | CIS Ref    |
| --------------------------------- | -------- | ----------- | ---------- |
| `PermitRootLogin`                 | `no`     | 🔴 CRITICAL | CIS 5.2.10 |
| `PasswordAuthentication`          | `no`     | 🔴 CRITICAL | CIS 5.2.12 |
| `PermitEmptyPasswords`            | `no`     | 🟠 HIGH     | CIS 5.2.11 |
| `PubkeyAuthentication`            | `yes`    | 🟠 HIGH     | CIS 5.2.1  |
| `ChallengeResponseAuthentication` | `no`     | 🟡 MEDIUM   | CIS 5.2.14 |
| `KerberosAuthentication`          | `no`     | 🟡 MEDIUM   | —          |
| `GSSAPIAuthentication`            | `no`     | 🟡 MEDIUM   | CIS 5.2.15 |

### Protocol & Cryptography (4 checks)

| Directive           | Expected                             | Severity    |
| ------------------- | ------------------------------------ | ----------- |
| `HostKeyAlgorithms` | no ECDSA NIST / DSS                  | 🔴 CRITICAL |
| `Ciphers`           | chacha20-poly1305, aes256-gcm        | 🟠 HIGH     |
| `MACs`              | hmac-sha2-512-etm, hmac-sha2-256-etm | 🟠 HIGH     |
| `KexAlgorithms`     | curve25519-sha256, dh-group16-sha512 | 🟠 HIGH     |

### Timeouts & Limits (5 checks)

| Directive             | Expected | Severity  | CIS Ref    |
| --------------------- | -------- | --------- | ---------- |
| `LoginGraceTime`      | ≤ 60s    | 🟠 HIGH   | CIS 5.2.16 |
| `MaxAuthTries`        | ≤ 4      | 🟠 HIGH   | CIS 5.2.7  |
| `MaxSessions`         | ≤ 4      | 🟡 MEDIUM | CIS 5.2.8  |
| `ClientAliveInterval` | > 0      | 🟡 MEDIUM | CIS 5.2.6  |
| `ClientAliveCountMax` | ≤ 0      | 🟡 MEDIUM | CIS 5.2.6  |

### Port & Access Control (4 checks)

| Directive       | Expected           | Severity  |
| --------------- | ------------------ | --------- |
| `Port`          | ≠ 22 (recommended) | 🟡 MEDIUM |
| `ListenAddress` | specific interface | 🟠 HIGH   |
| `AllowUsers`    | configured         | 🟠 HIGH   |
| `DenyUsers`     | configured         | 🟡 MEDIUM |

### Security Features (10 checks)

| Directive                | Expected          | Severity  | CIS Ref    |
| ------------------------ | ----------------- | --------- | ---------- |
| `X11Forwarding`          | `no`              | 🟠 HIGH   | CIS 5.2.5  |
| `AllowTcpForwarding`     | `no`              | 🟡 MEDIUM | CIS 5.2.20 |
| `AllowAgentForwarding`   | `no`              | 🟡 MEDIUM | CIS 5.2.21 |
| `Banner`                 | `/etc/issue.net`  | 🟡 MEDIUM | CIS 5.2.22 |
| `PrintLastLog`           | `yes`             | 🟢 LOW    | —          |
| `StrictModes`            | `yes`             | 🟠 HIGH   | —          |
| `UsePrivilegeSeparation` | `sandbox`         | 🟡 MEDIUM | —          |
| `Compression`            | `delayed` or `no` | 🟡 MEDIUM | —          |
| `LogLevel`               | `VERBOSE`         | 🟢 LOW    | CIS 5.2.24 |
| `IgnoreRhosts`           | `yes`             | 🟠 HIGH   | CIS 5.2.9  |

---

## 🚀 Usage

```bash
# Audit current system (auto-detect config)
python ssh_hardening.py

# Audit specific file
python ssh_hardening.py /etc/ssh/sshd_config

# Read live active config (requires root or sudo)
sudo python ssh_hardening.py --live

# Show all checks (including passing)
python ssh_hardening.py --show-pass

# JSON output
python ssh_hardening.py --json

# Save Markdown report
python ssh_hardening.py -o ssh_report.md
```

---

## 📊 Example Output

```
  SSH HARDENING AUDIT SUMMARY
  Source   : /etc/ssh/sshd_config
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Score: 42/100  [████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]
  ✅ PASS: 8  ❌ FAIL: 18  ⚠ WARN: 4  ⏭ SKIP: 0
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Priority actions:
  ● PermitRootLogin         → PermitRootLogin no
  ● PasswordAuthentication  → PasswordAuthentication no
  ● Ciphers                 → chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
  ● MaxAuthTries            → MaxAuthTries 4
```

---

## 🛡️ Hardened sshd_config Template

```
# SSH Hardening Template — CIS Benchmark compliant
Protocol 2
Port 2222                           # Non-standard port
ListenAddress 192.168.1.10         # Specific interface only

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no

# Cryptography
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512

# Timeouts & Limits
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 0

# Access control
AllowUsers adminuser deployuser
DenyUsers nobody daemon bin

# Forwarding (disable all)
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no

# Security
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
UsePrivilegeSeparation sandbox
Compression no
LogLevel VERBOSE
Banner /etc/issue.net
PrintLastLog yes
```

---

## 🔗 References

- [CIS Benchmark — Linux SSH](https://www.cisecurity.org/benchmark/distribution_independent_linux)
- [NIST SP 800-53 — AC-17 Remote Access](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Mozilla SSH Guidelines](https://infosec.mozilla.org/guidelines/openssh)
- [OpenSSH Security](https://www.openssh.com/security.html)

---

*Built by [Márcio Coutinho](https://github.com/marciolscoutinho) — Cibersecurity Specialist  · Porto, Portugal*

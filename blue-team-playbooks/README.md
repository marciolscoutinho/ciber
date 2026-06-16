# 🛡️ Ciber — Blue Team Playbooks

> Incident response runbooks aligned with NIST SP 800-61 Rev. 3 and SANS PICERL.
> Ready-to-use checklists for common security incidents in SOC, Blue Team, and defensive cybersecurity contexts.

[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![NIST](https://img.shields.io/badge/NIST-SP%20800--61%20Rev.3-blue?style=flat-square)](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
[![PICERL](https://img.shields.io/badge/SANS-PICERL-orange?style=flat-square)](https://www.sans.org/white-papers/33901/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square)](.github/workflows/ci.yml)

---

## 📋 Overview

This repository contains professional incident response playbooks for Blue Team analysts, SOC teams, system administrators, and security engineers.

The playbooks are structured around operational response phases inspired by **SANS PICERL** and mapped to modern incident response guidance from **NIST SP 800-61 Rev. 3**.

```text
PICERL Phases:
  P — Preparation
  I — Identification
  C — Containment
  E — Eradication
  R — Recovery
  L — Lessons Learned
```

---

## 📚 Available Playbooks

| ID     | Incident Type                         | Severity    | Key Actions                                                               |
| ------ | ------------------------------------- | ----------- | ------------------------------------------------------------------------- |
| PB-001 | SSH Brute Force / Credential Stuffing | 🟠 HIGH     | Block source, review authentication logs, harden SSH                      |
| PB-002 | Ransomware                            | 🔴 CRITICAL | Isolate immediately, preserve evidence, validate backups                  |
| PB-003 | Data Exfiltration                     | 🔴 CRITICAL | Stop the exfiltration path, preserve traffic evidence, assess GDPR impact |
| PB-004 | Privilege Escalation                  | 🔴 CRITICAL | Revoke privileges, terminate sessions, audit SUID/sudo/admin changes      |

---

## 🚨 PB-001 — SSH Brute Force / Credential Stuffing

**Trigger:** Repeated failed SSH logins from one or more IP addresses, or any successful login after a brute-force pattern.

**Immediate Actions (< 15 minutes):**

```bash
# 1. Identify attacking IPs
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head

# 2. Block the main source with iptables
sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP

# 3. Block with fail2ban, if installed
sudo fail2ban-client set sshd banip <ATTACKER_IP>

# 4. Check for successful logins from the same IP
grep "Accepted password\|Accepted publickey" /var/log/auth.log | grep <ATTACKER_IP>
```

**Full Playbook:** [playbooks/PB-001-ssh-brute-force.md](playbooks/PB-001-ssh-brute-force.md)

---

## 🚨 PB-002 — Ransomware

**Trigger:** Encrypted files, ransom note, mass file renaming, shadow copy deletion, or EDR alert for encryption behavior.

**Priority:** Every minute can mean more encrypted files. Isolation comes before cleanup.

**Immediate Actions (< 15 minutes):**

```bash
# 1. ISOLATE — unplug network cable and disable Wi-Fi
sudo nmcli networking off          # Linux
netsh interface set interface "Wi-Fi" DISABLED  # Windows

# 2. Check shadow copies before destructive changes
vssadmin list shadows              # Windows
lvs                                # Linux LVM snapshots

# 3. Suspend or pause, do not power off if RAM evidence may be useful
# Use hypervisor pause, OS suspend, or memory acquisition where possible.

# 4. Block known C2 or ransom-note IPs at the perimeter firewall
```

**Full Playbook:** [playbooks/PB-002-ransomware.md](playbooks/PB-002-ransomware.md)

---

## 🚨 PB-003 — Data Exfiltration

**Trigger:** Large outbound data transfer, unexpected cloud upload, DLP alert, DNS tunneling pattern, or unusual access to sensitive data.

**Immediate Actions (< 15 minutes):**

```bash
# 1. Identify the exfiltration channel
ss -tnp | grep ESTABLISHED
sudo lsof -i -n -P | grep ESTABLISHED

# 2. Capture traffic evidence before blocking
sudo tcpdump -i eth0 -w /evidence/capture_$(date +%s).pcap host <DEST_IP>

# 3. Block destination IP at the firewall
sudo iptables -A OUTPUT -d <DEST_IP> -j DROP

# 4. Identify the process and accessed files
sudo lsof -p <PID>
ls -la /proc/<PID>/fd
```

**GDPR check:** If personal data is involved, assess whether notification to CNPD is required within 72 hours under Article 33 GDPR.

**Full Playbook:** [playbooks/PB-003-data-exfiltration.md](playbooks/PB-003-data-exfiltration.md)

---

## 🚨 PB-004 — Privilege Escalation

**Trigger:** Unexpected root/admin activity, sudo abuse, SUID exploitation, unauthorized membership in privileged groups, or UAC/admin token abuse.

**Immediate Actions (< 15 minutes):**

```bash
# 1. Identify the escalation method
grep "sudo" /var/log/auth.log | tail -50
grep "su:" /var/log/auth.log | tail -50

# 2. Check who has root-equivalent access
awk -F: '($3 == 0) {print}' /etc/passwd
grep -v "^#" /etc/sudoers

# 3. Check suspicious SUID binaries
find / -perm -4000 -type f 2>/dev/null | sort

# 4. Check running processes as root
ps aux | awk '$1 == "root" {print}'
```

**Full Playbook:** [playbooks/PB-004-privilege-escalation.md](playbooks/PB-004-privilege-escalation.md)

---

## 📁 Repository Structure

```text
ciber/
  ├──blue-team-playbooks
                ├── README.md
                ├── LICENSE
                ├── .gitignore
                ├── .markdownlint.json
                ├── playbooks/
                │       ├── PB-001-ssh-brute-force.md
                │       ├── PB-002-ransomware.md
                │       ├── PB-003-data-exfiltration.md
                │       └── PB-004-privilege-escalation.md
                └── .github/
                        └── workflows/
                                └── ci.yml
```

---

## 📞 Emergency and Reporting Contacts — Portugal

| Entity                          | Role                                 | Contact                             |
| ------------------------------- | ------------------------------------ | ----------------------------------- |
| CNCS                            | National Cybersecurity Centre        | cncs@cncs.gov.pt / +351 210 497 400 |
| CERT.PT                         | Cybersecurity incident reporting     | cert@cert.pt / +351 210 497 399     |
| CNPD                            | Portuguese Data Protection Authority | geral@cnpd.pt / +351 213 928 400    |
| Polícia Judiciária — UNC3T      | Cybercrime reporting contact         | unc3t@pj.pt                         |
| Procuradoria-Geral da República | Cybercrime contact                   | cibercrime@pgr.pt                   |

> Always follow your organization's internal escalation procedures before external reporting, unless legal obligations require immediate notification.

---

## 🏗️ Playbook Structure

Each playbook follows this structure:

```markdown
# PB-XXX — [Incident Type]

## 1. Identification — When to Activate This Playbook
## 2. Initial Triage
## 3. Containment
## 4. Eradication
## 5. Recovery
## 6. Lessons Learned
## References
```

---

## 🔗 References

- [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [No More Ransom — Decryption Tools](https://www.nomoreransom.org/)
- [CNCS — National Cybersecurity Centre Portugal](https://www.cncs.gov.pt/)

---

## ⚖️ Legal and Ethical Use

These playbooks are intended for defensive security, authorized incident response, education, and internal security operations.

Do not use any command or procedure against systems you do not own or do not have explicit authorization to assess.

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

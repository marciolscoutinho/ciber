# PB-003 — Data Exfiltration

| Field              | Detail                                                                        |
| ------------------ | ----------------------------------------------------------------------------- |
| **ID**             | PB-003                                                                        |
| **Severity**       | 🔴 CRITICAL                                                                   |
| **MITRE ATT&CK**   | T1041 — Exfiltration Over C2 / T1048 — Exfiltration Over Alternative Protocol |
| **NIST Phase**     | Detection → Containment → Eradication → Recovery                              |
| **Estimated Time** | 2–6 hours                                                                     |
| **Last Review**    | 2026                                                                          |

---

## 1. Identification — When to Activate This Playbook

### Indicators of Compromise (IoCs)

- Anomalous outbound upload volume to unknown external IP addresses
- Large data transfers outside business hours
- Mass access to sensitive files by a single account
- Compression or encryption of large datasets before transfer
- Connections to unauthorized cloud storage services such as personal Dropbox, Mega, or similar
- High-volume DNS queries or unusual domain names that may indicate DNS tunneling
- Data Loss Prevention (DLP) alerts involving classified or personal data
- Unexpected use of tools such as `curl`, `wget`, `scp`, `rsync`, `ftp`, `nc`, or `ncat`

### Quick Detection

```bash
# Top external destinations by uploaded volume
# Requires firewall, proxy, or NetFlow logs; adapt to your SIEM.

# Linux — monitor outbound traffic in real time
sudo iftop -i eth0 -n -P
sudo nethogs eth0

# Show established connections
ss -tnp | grep ESTABLISHED
netstat -an | grep ESTABLISHED | grep -v "127.0.0.1\|::1"

# Check recent transfer commands in shell history
grep -r "curl\|wget\|scp\|rsync\|ftp" /var/log/bash_history 2>/dev/null
cat /root/.bash_history | grep -E "curl|wget|scp|nc |ncat"

# Windows — established connections
netstat -bno | findstr ESTABLISHED
Get-NetTCPConnection -State Established | Sort-Object RemoteAddress

# Recent large uploads in proxy logs, if available
# grep "POST\|PUT" /var/log/squid/access.log | awk '$5 > 1000000' | sort -k5 -rn | head -20
```

### DNS Tunneling Analysis

```bash
# DNS queries with very long subdomains
cat /var/log/named/queries.log 2>/dev/null | \
  awk '{print length($0), $0}' | sort -rn | head -20

# Domains with many queries from one host
cat /var/log/named/queries.log 2>/dev/null | \
  awk '{print $6}' | sort | uniq -c | sort -rn | head -20

# Capture DNS traffic for analysis
sudo tcpdump -i eth0 -n port 53 -w /tmp/dns_capture.pcap &
sleep 60 && sudo kill %1

# Analyze with tshark
tshark -r /tmp/dns_capture.pcap -T fields -e dns.qry.name | sort | uniq -c | sort -rn
```

---

## 2. Initial Triage — First 15 Minutes

```bash
# 1. Identify the account or process responsible for anomalous traffic
sudo lsof -i -n -P | grep ESTABLISHED

# 2. Estimate how much data has already left the network
# Review firewall, proxy, DLP, and NetFlow logs with timestamps.

# 3. Is the transfer still active?
sudo watch -n 2 "ss -tnp | grep ESTABLISHED"

# 4. What is the destination?
curl -s "https://ipinfo.io/<DESTINATION_IP>" 2>/dev/null

# 5. Which files were recently accessed by the suspicious account?
sudo find /home /srv /var -user <username> -newer /tmp/ref_time -type f 2>/dev/null

# 6. Is compression or encryption currently running?
ps aux | grep -E "zip|tar|gzip|7z|openssl|gpg"
```

**Mandatory record:** Account involved, destination IP/domain, estimated volume, data category, start time, detection time, evidence location.

---

## 3. Containment

### 3.1 Block Outbound Traffic to the Suspicious Destination

```bash
DEST_IP="<suspicious_destination_ip>"

# iptables — immediate outbound block
sudo iptables -I OUTPUT -d $DEST_IP -j DROP
sudo iptables -I FORWARD -d $DEST_IP -j DROP

# Domain-level temporary block through hosts file
echo "0.0.0.0 suspicious-domain.example" | sudo tee -a /etc/hosts

# Windows Firewall
netsh advfirewall firewall add rule name="BLOCK_EXFIL" dir=out action=block remoteip=$DEST_IP
```

### 3.2 Suspend the Compromised Account

```bash
# Linux
sudo passwd -l <username>
sudo pkill -u <username>
sudo usermod --expiredate 1 <username>

# Windows Active Directory
Disable-ADAccount -Identity <username>
```

### 3.3 Revoke Tokens and Active Sessions

```bash
# Revoke OAuth/JWT sessions and API tokens in the affected applications.

# AWS example
aws iam delete-access-key --access-key-id <KEY_ID> --user-name <username>

# GitHub example
# Revoke the compromised token in the GitHub UI or via API.
```

### 3.4 Preserve Network Evidence

```bash
# Capture remaining suspicious traffic before permanent blocking, when safe.
sudo tcpdump -i eth0 -w /evidence/exfil_$(date +%Y%m%d_%H%M).pcap host $DEST_IP

# Save process/network state
ss -tunap > /evidence/network_$(date +%Y%m%d_%H%M).txt
ps auxf > /evidence/processes_$(date +%Y%m%d_%H%M).txt
```

---

## 4. Eradication

```bash
# 4.1 Determine how the attacker gained access
grep "Failed password\|Accepted" /var/log/auth.log | grep <ATTACKER_IP>

# 4.2 Check persistence mechanisms
crontab -l -u <username>
sudo cat /etc/cron.d/* 2>/dev/null
ls -la /home/<username>/.ssh/authorized_keys
systemctl list-units --type=service | grep -v systemd

# Windows persistence
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s
schtasks /query /fo LIST /v | findstr "Task Name\|Run As User\|Task To Run"

# 4.3 Check whether data was staged locally before transfer
find /tmp /var/tmp /dev/shm -type f -newer /tmp/ref_time 2>/dev/null
find /home/<username> \( -name "*.zip" -o -name "*.tar.gz" -o -name "*.7z" \) 2>/dev/null

# 4.4 Remove staging files only after evidence collection
```

---

## 5. Recovery

### 5.1 Impact Assessment

- [ ] Which data was exfiltrated?
- [ ] What classification applies: public, internal, confidential, secret, personal data?
- [ ] Are GDPR, contractual, sectoral, or regulatory notification duties triggered?
- [ ] Must customers, partners, regulators, or data subjects be notified?
- [ ] Is there risk of blackmail, public disclosure, resale, or competitive harm?

### 5.2 GDPR Notification Check

```text
If personal data was exfiltrated, assess notification obligations:
  → Supervisory authority in Portugal: CNPD
  → GDPR Article 33: notify without undue delay and, where feasible, within 72 hours
  → GDPR Article 34: notify affected individuals when there is high risk
```

### 5.3 Restore and Harden

```bash
# Rotate all credentials for the affected account and related systems.
# Revoke and regenerate API keys, SSH keys, and OAuth tokens.
# Patch the exploited weakness.
# Enable MFA if it was not already enforced.
# Review DLP policies and outbound traffic alerts.
# Re-baseline normal upload volumes.
```

---

## 6. Lessons Learned

### Post-Incident Questions

- [ ] Was DLP monitoring active? Did it detect the incident?
- [ ] Were sensitive data access logs enabled and centralized?
- [ ] Did network segmentation limit access to critical data?
- [ ] Was least privilege implemented?
- [ ] What was the time between exfiltration start and detection?
- [ ] Were the affected credentials reused elsewhere?

### Preventive Measures

| Measure                                                      | Priority    |
| ------------------------------------------------------------ | ----------- |
| DLP with volume and classification alerts                    | 🔴 Critical |
| Centralized logging of sensitive data access                 | 🔴 Critical |
| MFA on all accounts with access to critical data             | 🔴 Critical |
| Network segmentation for critical data stores                | 🟠 High     |
| Outbound traffic monitoring with baselines                   | 🟠 High     |
| Data classification and sensitive asset inventory            | 🟠 High     |
| Block unauthorized cloud storage services through proxy/CASB | 🟡 Medium   |

---

## References

- [MITRE ATT&CK T1041](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK T1048](https://attack.mitre.org/techniques/T1048/)
- [GDPR — Regulation (EU) 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [CNPD — Data Breach Information](https://www.cnpd.pt/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

---

*[← Back to index](../README.md)*

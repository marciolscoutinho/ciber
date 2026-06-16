# PB-001 — SSH Brute Force / Credential Stuffing

| Field              | Detail                                              |
| ------------------ | --------------------------------------------------- |
| **ID**             | PB-001                                              |
| **Severity**       | 🟠 HIGH                                             |
| **MITRE ATT&CK**   | T1110 — Brute Force / T1110.001 — Password Guessing |
| **NIST Phase**     | Detection → Containment → Eradication → Recovery    |
| **Estimated Time** | 30–90 minutes                                       |
| **Last Review**    | 2026                                                |

---

## 1. Identification — When to Activate This Playbook

### Indicators of Compromise (IoCs)

- Multiple SSH authentication failures in a short time window (`Failed password for`)
- Login attempts using non-existent users (`Invalid user`)
- SSH traffic from suspicious geographies, cloud providers, or known hostile IP ranges
- Anomalous spike on port 22 in firewall, IDS, or SIEM logs
- One or more successful SSH logins after repeated failures

### Quick Detection Commands

```bash
# Count SSH login failures during the last 24 hours (Linux/auth.log)
grep "Failed password" /var/log/auth.log | wc -l

# Show the top 10 IP addresses with failed attempts
grep "Failed password" /var/log/auth.log \
  | awk '{print $(NF-3)}' \
  | sort | uniq -c | sort -rn | head -10

# Check successful logins after failures
grep "Accepted password\|Accepted publickey" /var/log/auth.log \
  | tail -50

# Systems using journald
journalctl -u ssh --since "24 hours ago" | grep "Failed\|Accepted"

# Show attempts by username
grep "Invalid user" /var/log/auth.log \
  | awk '{print $8}' | sort | uniq -c | sort -rn | head -10
```

### Activation Threshold

| Condition                                     | Action                            |
| --------------------------------------------- | --------------------------------- |
| More than 50 failures/hour from one IP        | Block the IP immediately          |
| More than 200 failures/hour from multiple IPs | Activate the full playbook        |
| Any successful login after repeated failures  | **Confirmed incident — escalate** |

---

## 2. Initial Triage — First 15 Minutes

```bash
# 1. Identify the attacking IP
ATTACKER_IP="<identified_ip>"

# 2. Is the attack still active?
grep "$ATTACKER_IP" /var/log/auth.log | tail -5

# 3. Was there any successful login from this IP?
grep "$ATTACKER_IP" /var/log/auth.log | grep "Accepted"

# 4. How many total attempts were made?
grep "$ATTACKER_IP" /var/log/auth.log | grep "Failed" | wc -l

# 5. Which users were targeted?
grep "$ATTACKER_IP" /var/log/auth.log \
  | grep -oP 'for \K\S+' | sort | uniq -c | sort -rn

# 6. Are there active SSH sessions from suspicious IPs?
who
ss -tnp | grep ":22"
w
```

**Mandatory record:** Date/time, attacking IP address(es), targeted users, whether any login succeeded, analyst name, actions taken.

---

## 3. Containment

### 3.1 Block the Source IP with iptables or ufw

```bash
# iptables — immediate block
sudo iptables -A INPUT -s $ATTACKER_IP -j DROP
sudo iptables -A INPUT -s $ATTACKER_IP -p tcp --dport 22 -j DROP

# ufw — Ubuntu/Debian
sudo ufw deny from $ATTACKER_IP to any port 22

# Persist iptables rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### 3.2 fail2ban — Automatic Protection

```bash
# Check if fail2ban is active
sudo systemctl status fail2ban

# Manually ban the IP
sudo fail2ban-client set sshd banip $ATTACKER_IP

# Show currently banned IPs
sudo fail2ban-client status sshd

# Recommended /etc/fail2ban/jail.local baseline:
# [sshd]
# enabled  = true
# maxretry = 5
# findtime = 600
# bantime  = 3600
```

### 3.3 Restrict SSH Access by Source IP

```bash
# Add attacker to hosts.deny
echo "sshd: $ATTACKER_IP" | sudo tee -a /etc/hosts.deny

# Restrict SSH to known networks in sshd_config
# AllowUsers user@192.168.1.0/24
sudo nano /etc/ssh/sshd_config
sudo systemctl reload sshd
```

### 3.4 If a Successful Login Was Detected

```bash
# Terminate active sessions for the compromised user
sudo pkill -u <username>
# or, if required:
sudo kill -9 $(pgrep -u <username>)

# Lock the account immediately
sudo passwd -l <username>
sudo usermod --expiredate 1 <username>
```

---

## 4. Eradication

```bash
# 4.1 Check whether new SSH keys were added
sudo cat /home/*/.ssh/authorized_keys 2>/dev/null
sudo cat /root/.ssh/authorized_keys 2>/dev/null

# 4.2 Check suspicious cron jobs
crontab -l
sudo crontab -l
ls -la /etc/cron*

# 4.3 Check processes started by the suspicious user
ps aux | grep <username>
sudo lsof -u <username>

# 4.4 Check recent changes to system files
sudo find /etc /usr/bin /usr/sbin -newer /etc/passwd -type f 2>/dev/null

# 4.5 Review /etc/passwd for new UID 0 accounts
sudo awk -F: '$3 == 0 {print}' /etc/passwd
```

---

## 5. Recovery

```bash
# 5.1 Force password reset for affected local accounts
sudo passwd <username>

# 5.2 Revoke and regenerate SSH keys for affected users
sudo rm /home/<username>/.ssh/authorized_keys
# User must generate a new key pair and submit a new public key.

# 5.3 Disable SSH password authentication
sudo nano /etc/ssh/sshd_config
# PasswordAuthentication no
# PermitRootLogin no
# PubkeyAuthentication yes
sudo systemctl reload sshd

# 5.4 Change SSH port as an additional measure
# Port 2222  ← in /etc/ssh/sshd_config
sudo systemctl reload sshd

# 5.5 Install and configure fail2ban if it was not present
sudo apt install fail2ban -y
sudo systemctl enable fail2ban --now
```

---

## 6. Lessons Learned

### Post-Incident Questions

- [ ] What was the entry vector: weak password, default account, exposed port, reused credentials?
- [ ] Was fail2ban configured? With which thresholds?
- [ ] Was authentication monitoring active in the SIEM?
- [ ] Was password-based SSH authentication disabled?
- [ ] How long passed between the first attempt and detection?
- [ ] Was the source part of a distributed campaign?

### Preventive Measures

| Measure                                                   | Priority    |
| --------------------------------------------------------- | ----------- |
| Disable SSH password authentication                       | 🔴 Critical |
| Install and configure fail2ban                            | 🔴 Critical |
| Enforce strong SSH key management                         | 🔴 Critical |
| Change the default SSH port                               | 🟠 High     |
| Implement MFA for privileged remote access                | 🟠 High     |
| Real-time monitoring of auth.log / journald               | 🟡 Medium   |
| Automatic blocking based on IP reputation and geolocation | 🟡 Medium   |

---

## References

- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [fail2ban Documentation](https://www.fail2ban.org/wiki/index.php/MANUAL_0_8)
- [CIS Controls](https://www.cisecurity.org/controls)

---

*[← Back to index](../README.md)*

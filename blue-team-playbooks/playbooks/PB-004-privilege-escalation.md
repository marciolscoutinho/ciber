# PB-004 — Privilege Escalation

| Field              | Detail                                                                                    |
| ------------------ | ----------------------------------------------------------------------------------------- |
| **ID**             | PB-004                                                                                    |
| **Severity**       | 🔴 CRITICAL                                                                               |
| **MITRE ATT&CK**   | T1068 — Exploitation for Privilege Escalation / T1548 — Abuse Elevation Control Mechanism |
| **NIST Phase**     | Detection → Containment → Eradication → Recovery                                          |
| **Estimated Time** | 1–4 hours                                                                                 |
| **Last Review**    | 2026                                                                                      |

---

## 1. Identification — When to Activate This Playbook

### Indicators of Compromise (IoCs)

- Non-privileged account executing commands with `sudo` or as `root`
- Normal user process running with UID 0
- Account added to `sudo`, `wheel`, `admin`, or `Administrators`
- Unexpected SUID/SGID permission changes on system binaries
- Execution of known kernel or privilege escalation exploits
- Elevated Windows token in an unexpected process
- UAC policy changes or suspicious administrator token abuse
- Audit logs showing successful sudo from an unauthorized user

### Quick Detection

```bash
# Linux — recent sudo activity
grep "sudo" /var/log/auth.log | grep -v "pam_unix\|session opened\|session closed" | tail -50

# Accounts with UID 0
awk -F: '$3 == 0 {print "⚠ UID 0:", $1}' /etc/passwd

# Groups with sudo access
grep -E "^sudo|^wheel|^admin" /etc/group

# Root processes that may require review
ps aux | awk '$1 == "root" {print}' | grep -v -E "systemd|kernel|kworker|migration|rcu|irq"

# Windows — processes with administrator-like ownership
Get-Process | Where-Object {$_.Name -ne "System"} | ForEach-Object {
  $owner = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner()
  if ($owner.User -eq "Administrator" -or $owner.Domain -eq "BUILTIN\Administrators") {
    Write-Output "PID: $($_.Id) - $($_.Name) - $($owner.Domain)\$($owner.User)"
  }
}
```

### Common Linux Escalation Techniques

```bash
# SUID binaries execute with the owner privileges.
find / -perm -u=s -type f 2>/dev/null
# Check candidates against GTFOBins.

# Dangerous passwordless sudo configuration
sudo -l

# Capabilities assigned to binaries
getcap -r / 2>/dev/null | grep -v "cap_net_admin\|cap_net_raw"

# Root cron jobs using scripts writable by normal users
cat /etc/crontab && ls -la /etc/cron.*

# Services running as root with writable files
systemctl list-units --type=service --state=running | \
  xargs -I{} systemctl show {} -p ExecStart,User | paste - - | grep -v "User=root"
```

---

## 2. Initial Triage — First 15 Minutes

```bash
# 1. Has privilege escalation already occurred?
id <username>
groups <username>

# 2. When was the user added to privileged groups?
grep "<username>" /var/log/auth.log | grep "group\|sudo\|wheel"

# 3. Are root processes tied to the suspicious user?
ps aux | grep <username>

# 4. Does the user currently have a privileged session?
who -a
w
sudo -l -U <username>

# 5. Were new privileged accounts created?
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3}' /etc/passwd
grep -E "^sudo|^wheel|^admin" /etc/group

# 6. Were critical files recently modified?
find /etc /usr/bin /usr/sbin /bin /sbin \
  -newer /tmp/ref_time -type f 2>/dev/null | head -30
```

**Mandatory record:** Account involved, suspected escalation method, privileges obtained, affected systems, timestamp, evidence collected.

---

## 3. Containment

### 3.1 Revoke Privileges Immediately

```bash
# Linux — remove user from sudo/wheel
sudo gpasswd -d <username> sudo
sudo gpasswd -d <username> wheel

# Revoke explicit sudoers entry using visudo
sudo visudo
# Remove or comment: <username> ALL=(ALL:ALL) ALL

# Terminate active user sessions
sudo pkill -u <username>
sudo loginctl terminate-user <username>

# Temporarily lock the account
sudo passwd -l <username>

# Windows — remove from local Administrators
Remove-LocalGroupMember -Group "Administrators" -Member "<username>"

# Active Directory
Remove-ADGroupMember -Identity "Domain Admins" -Members "<username>" -Confirm:$false
```

### 3.2 Revoke Active Tokens and Sessions

```powershell
# Windows — force logoff
query session /server:<server>
logoff <session_id> /server:<server>

# Kerberos
klist purge
```

### 3.3 Correct the Escalation Vector

```bash
# Remove improper SUID bit
sudo chmod u-s /path/to/binary

# Remove improper capability
sudo setcap -r /path/to/binary

# Remove improper sudoers entry
sudo visudo

# Fix writable cron script permissions
sudo chmod 750 /path/to/cron_script.sh
sudo chown root:root /path/to/cron_script.sh
```

---

## 4. Eradication

```bash
# 4.1 Full SUID/SGID audit
find / -perm -u=s -o -perm -g=s -type f 2>/dev/null | \
  xargs ls -la | tee /tmp/suid_audit_$(date +%Y%m%d).txt

# 4.2 Full sudoers audit
sudo cat /etc/sudoers
sudo ls -la /etc/sudoers.d/

# 4.3 Check common backdoors
find /home /root -name authorized_keys -exec cat {} \;

# UID 0 accounts
awk -F: '$3 == 0' /etc/passwd

# Accounts with usable password hashes
sudo awk -F: '$2 != "!" && $2 != "*" && $2 != "" {print $1}' /etc/shadow

# 4.4 Check whether a kernel exploit may have been used
uname -r
# Review CVEs for the running kernel and distribution.

# 4.5 Apply critical patches
sudo apt update && sudo apt upgrade -y      # Debian/Ubuntu
sudo yum update --security -y               # RHEL/CentOS
```

---

## 5. Recovery

```bash
# 5.1 Restore critical file permissions from a known-good baseline.
# Recommended tools: aide, tripwire, rkhunter.

# Run rkhunter
sudo apt install rkhunter -y
sudo rkhunter --update
sudo rkhunter --check --sk

# Run aide
sudo apt install aide -y
sudo aide --check

# 5.2 Reapply least privilege.
# Remove unnecessary sudo rights and privileged group membership.

# 5.3 Enable auditd for future monitoring.
sudo apt install auditd -y
sudo systemctl enable auditd --now

# Rule to detect privileged command execution
sudo auditctl -a always,exit -F arch=b64 -S execve -F uid=0 -k privilege_exec
```

---

## 6. Lessons Learned

### Post-Incident Questions

- [ ] How did the user obtain access to the escalation vector?
- [ ] Was the weakness caused by misconfiguration, exploit, credential theft, or social engineering?
- [ ] Was the system fully patched?
- [ ] Was sudo/UAC monitoring active?
- [ ] Was least privilege enforced?
- [ ] Was there detection for unusual SUID, capabilities, or admin group changes?

### Preventive Measures

| Measure                                                                   | Priority    |
| ------------------------------------------------------------------------- | ----------- |
| Periodic audit of SUID, sudoers, and privileged groups                    | 🔴 Critical |
| Rigorous patch management for kernel and base system                      | 🔴 Critical |
| Least privilege: no unnecessary sudo/admin rights                         | 🔴 Critical |
| auditd rules for privileged execution                                     | 🟠 High     |
| MFA for sudo/PAM or privileged access workflows                           | 🟠 High     |
| AIDE/Tripwire for binary integrity monitoring                             | 🟠 High     |
| Integrity monitoring for `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` | 🟡 Medium   |

---

## References

- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1548](https://attack.mitre.org/techniques/T1548/)
- [GTFOBins — SUID/Sudo Exploitation](https://gtfobins.github.io/)
- [Linux Privilege Escalation — HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [CIS Controls — Account Management](https://www.cisecurity.org/controls/v8)

---

*[← Back to index](../README.md)*

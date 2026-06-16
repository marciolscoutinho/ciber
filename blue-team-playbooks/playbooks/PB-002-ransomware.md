# PB-002 — Ransomware — Detection and Containment

| Field              | Detail                                                              |
| ------------------ | ------------------------------------------------------------------- |
| **ID**             | PB-002                                                              |
| **Severity**       | 🔴 CRITICAL                                                         |
| **MITRE ATT&CK**   | T1486 — Data Encrypted for Impact / T1490 — Inhibit System Recovery |
| **NIST Phase**     | Detection → Containment → Eradication → Recovery                    |
| **Estimated Time** | 2–8 hours; initial containment should start in less than 30 minutes |
| **Last Review**    | 2026                                                                |

---

> ⚠ **WARNING:** Ransomware can spread rapidly across internal networks. The first 30 minutes are critical. The absolute priority is to **isolate the affected system before any cleanup attempt**.

---

## 1. Identification — When to Activate This Playbook

### Indicators of Compromise (IoCs)

- Files with unknown or mass-renamed extensions such as `.locked`, `.encrypted`, `.crypt`, `.enc`
- Ransom note files such as `README_DECRYPT.txt`, `HOW_TO_RESTORE.html`, or similar across multiple directories
- Massive disk I/O caused by an unknown process encrypting files
- Deleted shadow copies or restore points (`vssadmin delete shadows`)
- Unknown process with high CPU usage and intensive file access
- Antivirus, EDR, or SIEM alert for mass encryption behavior
- Sudden inability to open business-critical documents

### Quick Detection

```bash
# Linux — files modified in the last 30 minutes
touch /tmp/check_time
find / -newer /tmp/check_time -type f 2>/dev/null | head -50

# Count suspicious encrypted extensions
find /home /var /srv -type f \( -name "*.locked" -o -name "*.enc" \) 2>/dev/null | wc -l

# Processes with high write I/O
sudo iotop -o -b -n 3 2>/dev/null || pidstat -d 1 5

# Windows PowerShell — unusual extensions in user folders
Get-ChildItem -Recurse C:\Users -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -notin @('.exe','.dll','.sys','.lnk','.txt','.pdf','.docx') } |
  Group-Object Extension | Sort-Object Count -Descending | Select-Object -First 20

# Check whether VSS was deleted
vssadmin list shadows
```

---

## 2. Initial Triage — First 15 Minutes

```text
⏱ TIME IS RUNNING — every minute may mean more encrypted files.
```

**Immediate checklist:**

- [ ] Identify affected system(s): hostname, IP address, logged-in user
- [ ] Determine whether encryption is still active
- [ ] Estimate the impact radius: local files, network shares, databases, backups
- [ ] Identify the likely entry vector: phishing, exposed RDP, USB, web exploit, stolen credentials
- [ ] Check whether other systems show similar symptoms
- [ ] Preserve evidence before destructive cleanup whenever feasible

```bash
# Identify suspicious high-CPU processes
ps aux --sort=-%cpu | head -20          # Linux
Get-Process | Sort-Object CPU -Desc | Select-Object -First 20   # Windows

# Show files opened by a suspicious process
sudo lsof -p <PID> | grep -v "mem\|txt\|cwd\|rtd" | head -30

# Show network connections of the process
ss -tp | grep <PID>                    # Linux
netstat -ano | findstr <PID>           # Windows
```

**Mandatory record:** System name, IP address, user, suspected process, ransom note filename, encrypted extension, first observed timestamp.

---

## 3. Containment

### 3.1 Immediate System Isolation — Highest Priority

```bash
# Linux — disable network interfaces immediately
sudo ip link set eth0 down
sudo ip link set wlan0 down

# More aggressive option:
sudo systemctl stop NetworkManager
sudo ifconfig eth0 down

# Windows PowerShell — run as Administrator
Disable-NetAdapter -Name "*" -Confirm:$false
```

> In critical environments, physical isolation by unplugging the network cable may be faster and more reliable than waiting for commands to complete.

### 3.2 Stop Network Propagation

```bash
# Firewall — block all outbound traffic from the affected IP
sudo iptables -I OUTPUT -s <AFFECTED_IP> -j DROP
sudo iptables -I FORWARD -s <AFFECTED_IP> -j DROP

# Windows Firewall
netsh advfirewall firewall add rule name="RANSOMWARE_BLOCK" dir=out action=block remoteip=any
```

### 3.3 Suspend, Do Not Immediately Power Off

```bash
# Suspending preserves RAM, which may contain useful forensic artifacts or keys.

# Linux
sudo systemctl suspend

# Windows
shutdown /h
```

> Do not abruptly power off the system unless encryption or propagation is still active and cannot be stopped otherwise.

### 3.4 Preserve Evidence

```bash
# Capture the current state before major cleanup actions.

# Memory acquisition on Linux, if tooling is available
sudo avml /media/usb/memory.raw

# Active processes
ps auxf > /media/usb/processes_$(date +%Y%m%d_%H%M).txt

# Active network connections
ss -tunap > /media/usb/network_$(date +%Y%m%d_%H%M).txt

# Hash of suspicious executable
sudo sha256sum /proc/<PID>/exe 2>/dev/null

# Windows event logs
wevtutil epl System C:\forensics\system_events.evtx
wevtutil epl Security C:\forensics\security_events.evtx
wevtutil epl Application C:\forensics\application_events.evtx
```

---

## 4. Eradication

```bash
# 4.1 Identify and terminate the ransomware process, only after evidence capture
sudo kill -9 <PID>
# Windows:
Stop-Process -Id <PID> -Force

# 4.2 Identify the ransomware binary
ls -la /proc/<PID>/exe
cat /proc/<PID>/maps | grep -v "\.so"

# 4.3 Calculate hash for malware identification
sudo sha256sum /proc/<PID>/exe

# 4.4 Search the hash in malware intelligence sources
# https://www.virustotal.com/
# https://bazaar.abuse.ch/

# 4.5 Remove binary and persistence mechanisms
crontab -l
sudo crontab -l
systemctl list-units --type=service --state=running | grep -v systemd
grep -r "ransomware_binary_name" /etc/cron* /etc/systemd/system/ 2>/dev/null

# Windows persistence checks
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
schtasks /query /fo LIST /v | findstr "Task Name\|Status\|Run"
Get-Service | Where-Object {$_.Status -eq 'Running'} | Sort-Object DisplayName
```

---

## 5. Recovery

### 5.1 Assess Decryption Possibility

1. Identify the ransomware family from:
   - File extension
   - Ransom note text
   - Binary hash
   - Known indicators in EDR/SIEM
2. Check trusted free decryptor sources:
   - https://www.nomoreransom.org/
   - Vendor-specific decryptor repositories
3. If decryption is not possible, restore from verified clean backups.

### 5.2 Restore from Backups

```bash
# Linux — restore from tar/rsync backup
tar -xzf /backup/system_backup.tar.gz -C /restore/

# Verify backup integrity before restore
sha256sum /backup/system_backup.tar.gz

# Confirm the backup is not encrypted
file /backup/system_backup.tar.gz
```

### 5.3 Reimage if Trust Cannot Be Restored

If the system is severely compromised, reimaging is safer than partial cleanup:

1. Format and reinstall the operating system.
2. Restore data from a clean pre-incident backup.
3. Apply all security updates before reconnecting to the network.
4. Rotate all credentials used on the affected system.
5. Validate business applications before returning to production.

---

## 6. Lessons Learned

### Post-Incident Questions

- [ ] What was the entry vector: phishing, RDP, unpatched vulnerability, USB, stolen credentials?
- [ ] Were backups available, tested, offline, or immutable?
- [ ] How long did detection take after encryption started?
- [ ] Which data was encrypted, exfiltrated, or destroyed?
- [ ] Did EDR or antivirus detect and block the attack?
- [ ] Did network segmentation limit propagation?

### Preventive Measures

| Measure                                                    | Priority    |
| ---------------------------------------------------------- | ----------- |
| Regular offline or immutable backups with integrity checks | 🔴 Critical |
| Patch critical vulnerabilities in less than 30 days        | 🔴 Critical |
| Network segmentation and Zero Trust controls               | 🔴 Critical |
| Disable or restrict RDP behind VPN/MFA                     | 🔴 Critical |
| EDR with mass-encryption behavior detection                | 🟠 High     |
| Anti-phishing training and simulation                      | 🟠 High     |
| Least privilege — users without local admin rights         | 🟠 High     |
| Monitoring for VSS/shadow copy deletion                    | 🟡 Medium   |

---

## References

- [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1490](https://attack.mitre.org/techniques/T1490/)
- [No More Ransom — Decryption Tools](https://www.nomoreransom.org/)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

---

*[← Back to index](../README.md)*

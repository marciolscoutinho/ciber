# 🔍 YARA Rule Builder

> Build, validate, and scan with YARA rules. 7 pre-built templates
> for the most common malware families. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](yara_builder.py)
[![YARA](https://img.shields.io/badge/YARA-Compatible-green?style=flat-square)](https://virustotal.github.io/yara/)

---

## Overview

YARA Rule Builder simplifies writing, validating and applying YARA rules
for malware detection and threat hunting. Includes 7 production-ready
templates covering the most prevalent malware categories.

```bash
# List available templates
python yara_builder.py list

# Generate a template
python yara_builder.py generate ransomware -o ransomware.yar

# Validate existing rule
python yara_builder.py validate my_rule.yar

# Scan directory with a rule
python yara_builder.py scan my_rule.yar ./suspicious_files/

# Build custom rule interactively
python yara_builder.py build --name "DetectMimikatz" -o mimikatz.yar
```

---

## Built-in Templates (7)

### 1. `reverse_shell` — Reverse Shell Detection

```yara
rule detect_reverse_shell {
    meta:
        description = "Detects reverse shell patterns"
        tags        = "malware, backdoor, C2"
        mitre       = "T1059.004"
    strings:
        $bash1  = "/bin/bash -i" nocase
        $bash2  = "bash -c" nocase
        $nc1    = "nc -e" nocase
        $nc2    = "ncat --exec" nocase
        $socat  = "socat exec" nocase
        $mkfifo = "mkfifo /tmp/" nocase
        $python = "import socket,subprocess,os" nocase
        $perl   = "use Socket;$i=" nocase
    condition:
        any of them
}
```

### 2. `webshell_php` — PHP Webshell Detection

```yara
rule detect_webshell_php {
    strings:
        $eval_base64   = /eval\s*\(\s*base64_decode/ nocase
        $assert_post   = /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $system_get    = /system\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $passthru_post = /passthru\s*\(\s*\$_(GET|POST)/ nocase
        $shell_exec    = /shell_exec\s*\(\s*\$_(GET|POST)/ nocase
        $preg_replace  = /preg_replace\s*\(.*\/e.*\$_(POST|GET)/ nocase
    condition:
        any of them
}
```

### 3. `ransomware_behavior` — Ransomware Indicators

```yara
rule detect_ransomware {
    strings:
        $vss1   = "vssadmin delete shadows" nocase
        $vss2   = "wbadmin delete catalog" nocase
        $ransom = "Your files have been encrypted" nocase
        $tor    = ".onion" nocase
        $btc    = "bitcoin" nocase
        $key1   = "CryptEncrypt" nocase
        $key2   = "CryptGenKey" nocase
    condition:
        2 of them
}
```

### 4. `credential_dumping` — Mimikatz / Credential Theft

| Template             | Tags            | MITRE             |
| -------------------- | --------------- | ----------------- |
| `credential_dumping` | T1003, mimikatz | sekurlsa, lsadump |

### 5. `log4shell` — CVE-2021-44228

| Template    | Tags                 | MITRE                    |
| ----------- | -------------------- | ------------------------ |
| `log4shell` | CVE-2021-44228, JNDI | ${jndi:ldap://} variants |

### 6. `powershell_obfuscation` — PS Evasion

| Template                 | Tags      | MITRE                |
| ------------------------ | --------- | -------------------- |
| `powershell_obfuscation` | T1059.001 | -EncodedCommand, IEX |

### 7. `network_scan_tool` — Scanner Detection

| Template            | Tags  | MITRE               |
| ------------------- | ----- | ------------------- |
| `network_scan_tool` | T1046 | Nmap, masscan, zmap |

---

## Usage

```bash
# List all templates
python yara_builder.py list

# Generate template to file
python yara_builder.py generate webshell_php -o webshell.yar
python yara_builder.py generate log4shell -o log4shell.yar

# Validate rule syntax
python yara_builder.py validate webshell.yar

# Scan single file
python yara_builder.py scan webshell.yar ./uploads/suspicious.php

# Scan directory recursively
python yara_builder.py scan ransomware.yar /var/www/html/

# Scan with multiple rules
python yara_builder.py scan-dir ./rules/ /suspicious/

# Build interactive rule
python yara_builder.py build \
  --name "DetectEvilTool" \
  --description "Detects EvilTool malware" \
  --strings "evil_string_1" "evil_func()" \
  --tags "malware" "backdoor" \
  -o evil_tool.yar

# Generate all templates at once
python yara_builder.py generate-all -o ./rules/
```

---

## Rule Structure

```yara
rule RuleName {
    meta:
        description = "What this rule detects"
        author      = "Marcio Coutinho"
        date        = "2024-06-21"
        version     = "1.0"
        tags        = "malware, category"
        mitre       = "T1234"
        reference   = "https://..."

    strings:
        $string1    = "malicious string" nocase
        $hex1       = { 4D 5A 90 00 }     // Hex pattern
        $regex1     = /evil[0-9]+\.exe/   // Regex pattern
        $wide1      = "evil" wide         // Wide chars (UTF-16)

    condition:
        // Match logic
        any of ($string*) or
        2 of ($hex*) or
        (filesize < 1MB and $regex1)
}
```

---

## Integration Examples

```bash
# CI/CD: scan build artifacts before deployment
python yara_builder.py scan ./rules/webshell_php.yar ./dist/

# Incident Response: quick scan of suspicious directory
python yara_builder.py generate-all -o /tmp/ir_rules/
for rule in /tmp/ir_rules/*.yar; do
  python yara_builder.py scan "$rule" /var/www/ && \
    echo "CLEAN: $rule" || echo "HIT: $rule"
done

# Generate YARA for known IOC strings
python yara_builder.py build \
  --name "Incident_20240115" \
  --strings "evil-c2.xyz" "aGVsbG8gd29ybGQ=" "185.220.101.47" \
  -o incident_rule.yar
```

---

## Repository Structure

```
ciber
    └── yara-builder/
                   ├── yara_builder.py
                   ├── templates/
                   │           ├── reverse_shell.yar
                   │           ├── webshell_php.yar
                   │           ├── ransomware.yar
                   │           ├── credential_dumping.yar
                   │           ├── log4shell.yar
                   │           ├── powershell_obfuscation.yar
                   │           └── network_scanner.yar
                   ├── README.md
                   └── .gitignore
```

---

## References

- [YARA Documentation](https://yara.readthedocs.io)
- [VirusTotal YARA](https://virustotal.github.io/yara/)
- [Awesome YARA Rules](https://github.com/InQuest/awesome-yara)
- [MITRE ATT&CK](https://attack.mitre.org)
- [YARA Forge](https://yarahq.github.io)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal*

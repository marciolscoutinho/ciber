# Directory & File Brute-Forcer

> Authorized directory and file discovery for web application security testing.
> Detects exposed admin panels, backup files, configuration files, debug endpoints,
> dependency manifests, and other paths that should be reviewed by defenders.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](dir_brute_forcer.py)
[![Category](https://img.shields.io/badge/Category-Web%20Security-orange?style=flat-square)](.)

> **Authorized use only.** Use this tool only on systems you own, administer, or have explicit written permission to assess.

---

## Overview

`dir_brute_forcer.py` is a zero-dependency Python tool for enumerating common web paths during authorized security assessments. It performs baseline filtering to reduce soft-404 false positives and assigns a defensive severity label to findings such as exposed secrets, backups, source-control metadata, or admin interfaces.

It is intentionally lightweight and suitable for labs, internal audits, portfolio demonstrations, and controlled bug bounty scopes.

---

## Features

| Feature             | Description                                                              |
| ------------------- | ------------------------------------------------------------------------ |
| Path discovery      | Finds common hidden endpoints, admin panels, backups, and metadata files |
| Built-in wordlist   | Curated list of common paths for light assessments                       |
| Custom wordlist     | Supports your own path list with `--wordlist`                            |
| Extension expansion | Appends common extensions such as `.php`, `.bak`, `.old`, `.log`, `.sql` |
| Concurrent probing  | Configurable worker threads with a safety cap                            |
| Baseline filtering  | Filters obvious 404 and soft-404 responses                               |
| Defensive triage    | Labels findings as CRITICAL, HIGH, MEDIUM, LOW, or INFO                  |
| Controlled pacing   | Configurable delay to reduce load on authorized targets                  |
| Reports             | Terminal summary, JSON, CSV, or Markdown output                          |

---

## Usage

```bash
# Basic discovery
python dir_brute_forcer.py https://target.example.com

# Same target using the optional --url form
python dir_brute_forcer.py --url https://target.example.com

# Quick light scan
python dir_brute_forcer.py https://target.example.com --quick

# Custom wordlist
python dir_brute_forcer.py https://target.example.com --wordlist paths.txt

# Append common file extensions
python dir_brute_forcer.py https://target.example.com --extensions

# Increase workers and reduce delay only when this is allowed by scope
python dir_brute_forcer.py https://target.example.com --threads 20 --delay 0.1

# Report only selected status codes
python dir_brute_forcer.py https://target.example.com --status 200 301 302 403

# JSON to stdout
python dir_brute_forcer.py https://target.example.com --json --no-banner

# JSON to file
python dir_brute_forcer.py https://target.example.com --json -o report.json

# Markdown report
python dir_brute_forcer.py https://target.example.com -o report.md

# CSV report
python dir_brute_forcer.py https://target.example.com --csv -o report.csv
```

For lab environments with self-signed TLS certificates, use:

```bash
python dir_brute_forcer.py https://lab.local --insecure
```

---

## Example Output

```text
[200] /admin                  1,024B ← Exposed administration interface
[200] /backup.zip         14,100,000B ← Possible exposed database backup
[301] /api                         0B → /api/
[403] /.git                       0B ← Resource exists but access is forbidden
[200] /config.php.bak          2,048B ← Exposed configuration or secrets file
```

---

## Severity Model

| Severity | Typical Finding                                                                 |
| -------- | ------------------------------------------------------------------------------- |
| CRITICAL | Exposed `.env`, web shell, secrets file, or direct sensitive config exposure    |
| HIGH     | Exposed backups, source-control metadata, dependency manifests, or admin panels |
| MEDIUM   | Debug endpoints, API documentation, uploads, or diagnostic interfaces           |
| LOW      | Accessible non-sensitive endpoints or protected existing resources              |
| INFO     | Miscellaneous responses worth manual review                                     |

---

## Exit Codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| `0`  | No MEDIUM/HIGH/CRITICAL findings |
| `1`  | MEDIUM or HIGH findings detected |
| `2`  | CRITICAL findings detected       |

---

## Repository Structure

```text
dir-brute-forcer/
├── dir_brute_forcer.py
├── README.md
├── DISCLAIMER.md
├── LICENSE
├── .gitignore
└── .github/
    └── workflows/
        └── ci.yml
```

---

## Legal and Ethical Notice

This project is for defensive security, research, and educational purposes only. Directory and file enumeration can be intrusive if performed without authorization. Always obtain written permission and follow the defined scope, rate limits, and testing window.

See [DISCLAIMER.md](DISCLAIMER.md) before using this tool.

---

Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal.

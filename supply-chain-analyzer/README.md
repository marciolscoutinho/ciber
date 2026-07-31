# 🔗 Supply Chain Security Analyzer

> Detects malicious dependencies, typosquatting, dependency confusion attacks,
> and known vulnerabilities in Python and Node.js projects.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](supply_chain.py)
[![OWASP](https://img.shields.io/badge/OWASP-A06%3A2021-black?style=flat-square)](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
[![MITRE](https://img.shields.io/badge/MITRE-T1195.001-red?style=flat-square)](https://attack.mitre.org/techniques/T1195/001/)

---

## 📋 Overview

Supply chain attacks are one of the fastest-growing threat vectors in software security.
This tool analyzes project dependencies to detect threats **before they reach production**.

```bash
# Analyze current project
python supply_chain.py .

# With OSV.dev CVE lookup
python supply_chain.py . --nvd

# Check for dependency confusion
python supply_chain.py . --internal-prefix mycompany- internal-

# Save report
python supply_chain.py . -o supply_chain_report.md
```

---

## 🎯 Detection Capabilities

### 1. Known Malicious Packages (Offline Database)

Checks against a curated database of confirmed malicious packages removed from PyPI/npm:

| Package               | Ecosystem | Description                                          |
| --------------------- | --------- | ---------------------------------------------------- |
| `colourama`           | PyPI      | Typosquat of `colorama` with crypto-stealing payload |
| `python-sqlite`       | PyPI      | Backdoored package                                   |
| `jeIlyfish`           | PyPI      | Typosquat of `jellyfish` (lowercase L → uppercase i) |
| `setup-tools`         | PyPI      | Typosquat of `setuptools`                            |
| `event-stream@3.3.6`  | npm       | Backdoor inserted into popular package               |
| `ua-parser-js@0.7.29` | npm       | Compromised with cryptominer                         |
| `node-ipc@10.1.1`     | npm       | Deliberate sabotage with malware                     |
| `crossenv`            | npm       | Typosquat of `cross-env`                             |

### 2. Typosquatting Detection

- **Database check**: Direct lookup against 30+ documented typosquats
- **Levenshtein distance**: Flags packages with edit distance ≤ 1 from popular packages (numpy, pandas, requests, etc.)

### 3. Dependency Confusion Attacks

- Detects internal package names (by prefix) installed from the public registry
- Classic attack: attacker publishes higher-versioned package to PyPI/npm with your internal package name

### 4. OSV.dev Vulnerability Lookup (Online)

- Queries [osv.dev](https://osv.dev) for known CVEs per package version
- Works for both PyPI and npm ecosystems
- No API key required

### 5. PyPI Metadata Analysis (Online)

- Packages created less than 30 days ago with few releases
- Abandoned packages (last release > 3 years ago)
- Outdated versions compared to latest

---

## 📦 Supported Manifest Formats

| File                 | Ecosystem | Parser                                   |
| -------------------- | --------- | ---------------------------------------- |
| `requirements.txt`   | Python    | Full parsing with version constraints    |
| `requirements/*.txt` | Python    | Recursive discovery                      |
| `Pipfile`            | Python    | `[packages]` + `[dev-packages]` sections |
| `setup.py`           | Python    | `install_requires` extraction            |
| `pyproject.toml`     | Python    | Basic parsing                            |
| `package.json`       | Node.js   | `dependencies` + `devDependencies`       |

---

## 🚀 Usage

```bash
# Basic offline scan (typosquatting + malicious packages)
python supply_chain.py ./myproject

# Include OSV.dev CVE lookup (slower, online)
python supply_chain.py ./myproject --nvd

# Dependency confusion detection
python supply_chain.py ./myproject --internal-prefix mycompany acme

# Skip PyPI metadata checks
python supply_chain.py ./myproject --no-pypi

# JSON output
python supply_chain.py ./myproject --json -o report.json

# Markdown report
python supply_chain.py ./myproject -o supply_chain_report.md
```

---

## 📊 Example Output

```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [CRITICAL] Typosquatting Known
  Package : colourama @ 1.0.0
  Problem : 'colourama' is a documented typosquat of 'colorama'
  Evidence : Package 'colourama' found in known typosquat list
  Fix     : Replace with 'colorama'. Audit systems where it was installed.
  MITRE   : T1195.001 — Supply Chain Compromise

  [HIGH]     Possible Typosquatting
  Package : pyyamml @ 5.4.1
  Problem : 'pyyamml' is very similar to 'pyyaml' (edit distance=1)
  Evidence : Levenshtein('pyyamml', 'pyyaml') = 1
  Fix     : Verify you intended 'pyyaml'. Check package hashes.

  SUPPLY CHAIN ANALYSIS SUMMARY
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Dependencies : 8
  Findings     : 3
  CRITICAL     : 1
  HIGH         : 2
  Risk Score   : 60/100
```

---

## 🔒 Real-World Attack Examples

### Typosquatting Attack (2017)

- **Package**: `colourama` (typosquat of `colorama`)
- **Downloads**: 2,100+ before removal
- **Payload**: Cryptocurrency address replacement in clipboard
- **Lesson**: Always verify package names carefully

### Dependency Confusion Attack (2021)

- **Researcher**: Alex Birsan
- **Method**: Published public packages with same names as internal packages at higher versions
- **Impact**: Affected Apple, Microsoft, PayPal, Uber, and 30+ other companies
- **Lesson**: Use private registries with priority over public ones

### node-ipc Sabotage (2022)

- **Package**: `node-ipc` (50M+ weekly downloads)
- **Version**: 10.1.1
- **Action**: Maintainer intentionally added malware targeting Russian/Belarusian IP addresses
- **Lesson**: Even trusted maintainers can compromise packages

---

## 🛡️ Remediation Recommendations

### For Typosquatting

```bash
# Always verify before installing
pip show <package-name>     # Check author, homepage, description
pip install <package>==<specific-version>  # Pin versions

# Use hash verification
pip install --require-hashes -r requirements.txt
```

### For Dependency Confusion

```bash
# Use private registry with priority
pip install --index-url https://private.registry.com/simple/ \
            --extra-index-url https://pypi.org/simple/ package

# Register your internal package names on PyPI as "dummy" packages
# to prevent attackers from claiming them
```

### For CVE Vulnerabilities

```bash
# Regular audit
python supply_chain.py . --nvd

# Automated in CI/CD
python supply_chain.py . --nvd --json -o sbom_audit.json
# Exit code 2 = CRITICAL vulnerabilities found
```

---

## 📁 Repository Structure

```
ciber
    └── supply-chain/
                  ├── supply_chain.py       ← Main analyzer
                  ├── README.md
                  └── .gitignore
```

---

## 🔗 References

- [OWASP A06:2021 — Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [MITRE ATT&CK T1195.001 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [OSV.dev — Open Source Vulnerabilities](https://osv.dev)
- [CISA: Software Supply Chain Security Guidance](https://www.cisa.gov/software-supply-chain-security)
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

---

*Built by [Márcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist  · Porto, Portugal*

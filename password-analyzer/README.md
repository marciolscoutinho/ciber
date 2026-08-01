# 🔐 Password Analyzer

> Analyzes password strength — entropy, crack time estimation, wordlist
> generation, and security recommendations. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](password_analyzer.py)
[![NIST](https://img.shields.io/badge/NIST-SP%20800--63B-blue?style=flat-square)](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## Overview

Password Analyzer calculates the real strength of a password using
entropy analysis and crack time estimation against multiple attack scenarios.
Also generates targeted wordlists using OSINT data.

```bash
# Analyze a password
python password_analyzer.py "Password123!"

# Analyze multiple passwords
python password_analyzer.py "pass1" "pass2" "Th3-M4r!n3iro-C4nt4"

# Generate wordlist from profile
python password_analyzer.py --wordlist \
  --name "Joao Silva" \
  --birthdate "1990-05-15" \
  --keywords "porto benfica" \
  --company "acme"

# Batch analysis from file
python password_analyzer.py --file passwords.txt

# Verbose analysis
python password_analyzer.py "MyPassword" --verbose

# JSON output
python password_analyzer.py "password123" --json
```

---

## Strength Analysis

### Entropy Calculation

```
Entropy = log2(charset_size ^ length)

Charsets:
  Lowercase only    : 26 chars
  + Uppercase       : 52 chars
  + Digits          : 62 chars
  + Special (!@#$)  : 95 chars (printable ASCII)

Examples:
  "password"    : log2(26^8)  = 37.6 bits  (WEAK)
  "Password1"   : log2(62^9)  = 53.6 bits  (FAIR)
  "P@ssw0rd!23" : log2(95^11) = 72.3 bits  (GOOD)
  "horse-staple-battery-correct" : 100+ bits (EXCELLENT)
```

### Crack Time Estimation

Estimates cracking time against different attack scenarios:

| Scenario             | Speed         | Description                  |
| -------------------- | ------------- | ---------------------------- |
| Online (throttled)   | 1,000/s       | Web login with rate limiting |
| Online (no throttle) | 100,000/s     | API without rate limiting    |
| Offline (MD5)        | 1 billion/s   | MD5 on GPU                   |
| Offline (bcrypt)     | 1,000/s       | bcrypt on GPU                |
| Offline (NTLM)       | 100 billion/s | NTLM on multi-GPU            |

### Score (0-100)

| Score  | Grade | Description                 |
| ------ | ----- | --------------------------- |
| 80-100 | A     | Excellent — very strong     |
| 60-79  | B     | Good — meets best practices |
| 40-59  | C     | Fair — some weaknesses      |
| 20-39  | D     | Weak — easily cracked       |
| 0-19   | F     | Very weak — do not use      |

---

## Pattern Detection

The analyzer detects common weaknesses:

| Pattern           | Example                   | Penalty |
| ----------------- | ------------------------- | ------- |
| Common words      | `password`, `qwerty`      | -30 pts |
| Keyboard walks    | `qwerty`, `12345`, `asdf` | -20 pts |
| L33t substitution | `p@ssw0rd`                | -10 pts |
| Personal patterns | Name + year               | -15 pts |
| Repeated chars    | `aaaaaa`                  | -15 pts |
| Sequential chars  | `abcdef`, `123456`        | -10 pts |
| Common suffixes   | `!`, `123`, `@1`          | -5 pts  |

---

## Wordlist Generator

Generates a targeted wordlist from personal information:

```bash
python password_analyzer.py --wordlist \
  --name "Joao Silva" \
  --birthdate "1990-05-15" \
  --keywords "porto benfica futebol" \
  --company "acme" \
  --output wordlist.txt
```

**Generates combinations like:**

```
joaosilva
joao1990
silva1990
joao@1990
JoaoSilva
joaosilva!
joao.silva
acme1990
porto1990
benfica!
...
```

---

## Usage

```bash
# Single password analysis
python password_analyzer.py "MyPassword123!"

# Compare multiple passwords
python password_analyzer.py "password" "P@ssword" "Th3-M4r!n3iro-C4nt4"

# Analyze passwords from file (one per line)
python password_analyzer.py --file passwords.txt

# Generate wordlist
python password_analyzer.py --wordlist \
  --name "Target Name" \
  --birthdate "YYYY-MM-DD" \
  --keywords "keyword1 keyword2" \
  --output wordlist.txt

# Verbose (show all pattern detections)
python password_analyzer.py "Password123" --verbose

# JSON output
python password_analyzer.py "test123" --json
```

---

## Example Output

```
  PASSWORD ANALYSIS: "Password123!"
  ════════════════════════════════════════════════════════════════════

  Length      : 12
  Charset     : lowercase + uppercase + digits + special (95 chars)
  Entropy     : 78.8 bits
  Score       : 62/100  Grade: B

  ● Contains uppercase letters
  ● Contains lowercase letters
  ● Contains digits
  ● Contains special characters
  ⚠ Common substitution pattern: 'a'→'@', 'o'→'0'
  ⚠ Common word 'password' detected (l33t)

  Crack Time Estimates:
  Online (rate limited)  : centuries
  Online (no limit)      : years
  Offline MD5 (GPU)      : ~2 hours
  Offline NTLM (GPU)     : ~1 minute  ← CONCERN
  Offline bcrypt (GPU)   : centuries

  Recommendations:
  ● Avoid common word patterns even with substitutions
  ● Use a passphrase: "horse-staple-battery-correct"
  ● Add a password manager to use unique passwords everywhere
```

---

## Repository Structure

```
ciber
    └──password-analyzer/
                       ├── password_analyzer.py
                       ├── README.md
                       └── .gitignore
```

---

## References

- [NIST SP 800-63B — Memorised Secret Requirements](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5)
- [zxcvbn — Password Strength Estimator](https://github.com/dropbox/zxcvbn)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [HaveIBeenPwned](https://haveibeenpwned.com)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

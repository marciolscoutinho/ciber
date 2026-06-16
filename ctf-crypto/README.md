# 🔐 CTF Crypto Toolkit

> Classical cipher toolkit for CTF challenges: Caesar, Vigenere, XOR, base
> encodings, Morse, frequency analysis, and auto-decode. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](ctf_crypto.py)
[![CTF](https://img.shields.io/badge/Use-CTF%20%7C%20Cryptanalysis-purple?style=flat-square)](.)

---

## Overview

CTF Crypto Toolkit is a single-file Python utility for solving beginner and
intermediate cryptography tasks in CTF competitions and forensic training labs.
It supports classical ciphers, common encodings, XOR operations, and lightweight
frequency analysis without external packages.

> Intended use: CTFs, authorized labs, digital forensics exercises, and education.

```bash
# Auto-decode unknown ciphertext
python ctf_crypto.py auto "SGVsbG8gV29ybGQ="

# Caesar brute force
python ctf_crypto.py caesar --brute "Khoor Zruog"

# Vigenere decrypt with a known key
python ctf_crypto.py vigenere --decrypt --key "SECRET" "ZMCLO..."

# XOR brute force, single-byte key
python ctf_crypto.py xor --brute "48656c6c6f"

# Frequency analysis
python ctf_crypto.py freq "KHOOR ZRUOG"
```

---

## Capabilities

### Classical Ciphers

| Cipher           | Modes                                   | Features                                       |
| ---------------- | --------------------------------------- | ---------------------------------------------- |
| **Caesar**       | Encrypt, decrypt, brute force           | Scores candidates using English frequency      |
| **Vigenere**     | Encrypt, decrypt, key-length estimation | Uses Index of Coincidence for key-length hints |
| **Atbash**       | Encrypt/decrypt                         | A↔Z, B↔Y substitution                          |
| **ROT13**        | Encode/decode                           | Available through `encode` / `decode`          |
| **Rail Fence**   | Encrypt, decrypt                        | Configurable rail count                        |
| **Substitution** | Encrypt, decrypt                        | Custom 26-letter substitution alphabet         |

### Encodings

| Encoding               | Decode | Encode |
| ---------------------- | ------ | ------ |
| **Base64**             | Yes    | Yes    |
| **Base32**             | Yes    | Yes    |
| **Base16 / Hex**       | Yes    | Yes    |
| **URL encoding**       | Yes    | Yes    |
| **HTML entities**      | Yes    | Yes    |
| **Binary**             | Yes    | Yes    |
| **Octal**              | Yes    | Yes    |
| **Decimal codepoints** | Yes    | Yes    |
| **Morse code**         | Yes    | Yes    |

### Analysis and Attack Helpers

| Tool                               | Description                                                   |
| ---------------------------------- | ------------------------------------------------------------- |
| **Frequency Analysis**             | Letter frequency compared with English reference distribution |
| **Index of Coincidence**           | Helps distinguish monoalphabetic vs polyalphabetic ciphertext |
| **Vigenere key-length estimation** | Uses average Index of Coincidence per candidate key length    |
| **XOR brute force**                | Single-byte XOR key cracking                                  |
| **XOR known-plaintext helper**     | Recovers XOR key material from known plaintext and ciphertext |
| **Auto-decode**                    | Tries common encodings and Caesar candidates automatically    |

---

## Installation

```bash
git clone https://github.com/marciolscoutinho/ciber.git
cd ciber
python ctf_crypto.py --help
```

No dependencies are required beyond Python 3.8+.

---

## Usage Examples

### Auto-Decode

```bash
python ctf_crypto.py auto "SGVsbG8gV29ybGQ="
# [Base64] Hello World

python ctf_crypto.py auto "Khoor Zruog"
# Top Caesar candidate should include: Hello World

python ctf_crypto.py auto "48 65 6c 6c 6f"
# [Hex] Hello
```

### Caesar Cipher

```bash
# Brute force all shifts and rank by English frequency
python ctf_crypto.py caesar --brute "KHOOR ZRUOG"

# Decrypt with a known shift
python ctf_crypto.py caesar --decrypt --shift 13 "URYYB JBEYQ"

# Encrypt with a chosen shift
python ctf_crypto.py caesar --shift 3 "HELLO WORLD"
```

### Vigenere Cipher

```bash
# Decrypt with a known key
python ctf_crypto.py vigenere --decrypt --key "KEY" "RIJVS UYVJN"

# Encrypt with a known key
python ctf_crypto.py vigenere --key "KEY" "HELLO WORLD"

# Estimate likely key lengths from ciphertext
python ctf_crypto.py vigenere --guess-keylen "ZMCLOIYAIGZMLVNQNQYVHE..."
```

### Rail Fence and Substitution

```bash
# Rail Fence encrypt/decrypt
python ctf_crypto.py railfence --rails 3 "WEAREDISCOVEREDFLEEATONCE"
python ctf_crypto.py railfence --decrypt --rails 3 "WECRLTEERDSOEEFEAOCAIVDEN"

# Simple substitution with a 26-letter alphabet
python ctf_crypto.py substitution --key "QWERTYUIOPASDFGHJKLZXCVBNM" "HELLO"
python ctf_crypto.py substitution --decrypt --key "QWERTYUIOPASDFGHJKLZXCVBNM" "ITSSG"
```

### XOR Operations

```bash
# Brute-force single-byte XOR
python ctf_crypto.py xor --brute "1b37373331363f78151b7f2b783431333d78"

# XOR with a known single-byte key
python ctf_crypto.py xor --key 0x42 "48 65 6c 6c 6f"

# Fixed XOR between two hex values
python ctf_crypto.py xor "1c0111001f010100061a024b53535009181c" \
  --hex2 "686974207468652062756c6c277320657965"

# Recover XOR key material from known plaintext and ciphertext
python ctf_crypto.py xor "0a000a" --known-plain "key"
```

### Frequency Analysis

```bash
python ctf_crypto.py freq "KHOOR ZRUOG WKLV LV D WHVW"
```

The output includes letter distribution and the Index of Coincidence.

### Encodings

The generic format is:

```bash
python ctf_crypto.py encode "Hello World" --method b64
python ctf_crypto.py decode "SGVsbG8gV29ybGQ=" --method b64
```

Supported methods:

```text
b64, b32, b16, hex, url, html, binary, octal, decimal, rot13, morse
```

Examples:

```bash
python ctf_crypto.py encode "Hello" --method hex
python ctf_crypto.py decode "48 65 6c 6c 6f" --method hex
python ctf_crypto.py morse --decode ".... . .-.. .-.. ---"
python ctf_crypto.py encode "HELLO" --method binary
```

### JSON Output

Use `--json` before the command to emit machine-readable output:

```bash
python ctf_crypto.py --json auto "SGVsbG8gV29ybGQ="
python ctf_crypto.py --json freq "KHOOR ZRUOG"
python ctf_crypto.py --json caesar --brute "Khoor Zruog"
```

---

## CTF Workflow

```bash
# 1. Try auto-decode first
python ctf_crypto.py auto "<ciphertext>"

# 2. If it looks like Base64
python ctf_crypto.py decode "<ciphertext>" --method b64

# 3. If it looks like hex
python ctf_crypto.py decode "<hex-string>" --method hex

# 4. If it contains only letters, try Caesar brute force
python ctf_crypto.py caesar --brute "<ciphertext>"

# 5. If it may be Vigenere, estimate key length
python ctf_crypto.py vigenere --guess-keylen "<ciphertext>"

# 6. If it is hex and looks XORed, try single-byte XOR brute force
python ctf_crypto.py xor --brute "<hex-string>"
```

---

## Repository Structure

```text
ciber/
    └── ctf-crypto/
                ├── ctf_crypto.py
                ├── README.md
                ├── LICENSE
                ├── .gitignore
                └── .github/
                          └── workflows/
                                    └── ci.yml
```

---

## Safety and Scope

This tool is for CTF challenges, authorized labs, and education. It does not
perform network activity, exploitation, credential theft, or unauthorized access.

---

## References

- [CryptoHack — Cryptography Challenges](https://cryptohack.org)
- [dCode.fr — Cipher Tools](https://www.dcode.fr/en)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [Crypto101 — Free Cryptography Book](https://www.crypto101.io)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal*

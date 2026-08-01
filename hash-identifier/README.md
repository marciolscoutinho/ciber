# #️⃣ Hash Identifier

> Identifies 28+ hash types, maps to hashcat/john-the-ripper modes,
> generates hashes, and estimates cracking difficulty. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](hash_id.py)
[![CTF](https://img.shields.io/badge/Use-CTF%20%7C%20Forensics%20%7C%20Pentesting-purple?style=flat-square)](.)

---

## Overview

Hash Identifier automatically detects hash types from their format,
maps them to hashcat and john-the-ripper cracking modes, and provides
cracking strategy recommendations.

```bash
# Identify a hash
python hash_id.py 5d41402abc4b2a76b9719d911017c592

# Identify multiple hashes
python hash_id.py hash1 hash2 hash3

# Read from file
python hash_id.py --file hashes.txt

# Generate hash of string
python hash_id.py --generate "password123" --algo all

# Interactive mode
python hash_id.py --interactive
```

---

## Supported Hash Types (28+)

| Hash              | Length | Hashcat Mode | John Format |
| ----------------- | ------ | ------------ | ----------- |
| MD5               | 32     | 0            | md5         |
| MD4               | 32     | 900          | md4         |
| SHA-1             | 40     | 100          | sha1        |
| SHA-224           | 56     | 1300         | sha224      |
| SHA-256           | 64     | 1400         | sha256      |
| SHA-384           | 96     | 10800        | sha384      |
| SHA-512           | 128    | 1700         | sha512      |
| SHA3-256          | 64     | 17300        | —           |
| SHA3-512          | 128    | 17600        | —           |
| NTLM              | 32     | 1000         | NT          |
| LM                | 32     | 3000         | LM          |
| NetNTLMv1         | varies | 5500         | netntlm     |
| NetNTLMv2         | varies | 5600         | netntlmv2   |
| bcrypt            | 60     | 3200         | bcrypt      |
| SHA-512crypt      | varies | 1800         | sha512crypt |
| SHA-256crypt      | varies | 7400         | sha256crypt |
| MD5crypt          | varies | 500          | md5crypt    |
| MySQL 3.x         | 16     | 200          | —           |
| MySQL 4.1+        | 41     | 300          | mysql-sha1  |
| Django SHA-1      | varies | 800          | —           |
| Django bcrypt     | varies | 3200         | —           |
| CRC32             | 8      | 11500        | crc32       |
| RIPEMD-160        | 40     | 6000         | ripemd-160  |
| Whirlpool         | 128    | 6100         | whirlpool   |
| BLAKE2b-256       | 64     | 600          | —           |
| Keccak-256        | 64     | 17300        | —           |
| WPA-PMKID         | 64     | 22000        | —           |
| JWT (HMAC-SHA256) | varies | —            | —           |

---

## Usage

```bash
# Identify single hash
python hash_id.py 5d41402abc4b2a76b9719d911017c592
# Output:
#   Possible types (confidence):
#   1. MD5             (HIGH)   — hashcat: -m 0  | john: --format=md5
#   2. MD4             (MEDIUM) — hashcat: -m 900 | john: --format=md4
#   3. NTLM            (MEDIUM) — hashcat: -m 1000| john: --format=NT

# Identify multiple hashes
python hash_id.py \
  "5d41402abc4b2a76b9719d911017c592" \
  "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" \
  "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36zLHkyyGSt5sDyaXnLpEF6"

# Read hashes from file (one per line)
python hash_id.py --file hashes.txt

# Generate hash examples
python hash_id.py --generate "password" --algo md5
python hash_id.py --generate "password" --algo all

# JSON output
python hash_id.py 5d41402abc4b2a76b9719d911017c592 --json
```

---

## Example Output

```
  HASH IDENTIFICATION
  ════════════════════════════════════════════════════════════════════
  Hash     : 5d41402abc4b2a76b9719d911017c592
  Length   : 32 characters
  Charset  : hex [0-9a-f]

  Possible types:
  1. [HIGH]   MD5
     Hashcat : hashcat -m 0 hash.txt wordlist.txt
     John    : john --format=md5 hash.txt
     Crack   : john --format=md5 --wordlist=rockyou.txt hash.txt

  2. [MEDIUM] NTLM (Windows password hash)
     Hashcat : hashcat -m 1000 hash.txt wordlist.txt
     Extract : mimikatz "lsadump::sam"

  3. [MEDIUM] MD4
     Hashcat : hashcat -m 900 hash.txt wordlist.txt

  Cracking Strategy:
  ● Dictionary attack: hashcat -m 0 -a 0 hash.txt rockyou.txt
  ● Rule-based:        hashcat -m 0 -a 0 -r best64.rule hash.txt rockyou.txt
  ● Brute-force:       hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a
```

---

## Repository Structure

```
hash-id/
├── hash_id.py
├── README.md
└── .gitignore
```

---

## References

- [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [John the Ripper Wiki](https://www.openwall.com/john/doc/)
- [CrackStation](https://crackstation.net)
- [NTLM Hash Formats](https://en.wikipedia.org/wiki/NT_LAN_Manager)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

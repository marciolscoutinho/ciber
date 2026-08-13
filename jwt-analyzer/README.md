# 🔐 JWT Analyzer

> JSON Web Token security analyzer — decode, detect vulnerabilities,
> brute-force weak secrets, and demonstrate CVE-2015-9235 (alg:none).

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](jwt_analyzer.py)
[![CVE](https://img.shields.io/badge/CVE--2015--9235-alg%3Anone-red?style=flat-square)](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)

---

## 📋 Overview

JWT Analyzer helps security professionals audit JSON Web Tokens for common
vulnerabilities, misconfigurations, and weak secrets.

```bash
# Decode and analyze a JWT
python jwt_analyzer.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Brute-force weak secret
python jwt_analyzer.py <token> --brute

# Demonstrate alg:none attack (CVE-2015-9235)
python jwt_analyzer.py <token> --forge-none

# Verify with known secret
python jwt_analyzer.py <token> --secret mysecret
```

---

## 🎯 Security Checks

| Check                     | CVE           | Severity    | Description                 |
| ------------------------- | ------------- | ----------- | --------------------------- |
| Algorithm `none`          | CVE-2015-9235 | 🔴 CRITICAL | Accepts unsigned tokens     |
| Algorithm Confusion       | CVE-2016-5431 | 🟠 HIGH     | RS256→HS256 confusion       |
| Missing `exp` claim       | —             | 🟠 HIGH     | Token never expires         |
| Expired token             | —             | 🟡 MEDIUM   | Token past expiry date      |
| Lifetime > 30 days        | —             | 🟡 MEDIUM   | Excessive token lifetime    |
| Sensitive data in payload | —             | 🟡 MEDIUM   | Passwords/keys in claims    |
| `kid` header injection    | —             | 🔴 CRITICAL | SQL/path injection in kid   |
| `jku`/`x5u` external URL  | —             | 🟠 HIGH     | Attacker-controlled key URL |

---

## 🚀 Usage

### Decode and Analyze

```bash
# From argument
python jwt_analyzer.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.xxx

# From stdin
echo "eyJ..." | python jwt_analyzer.py

# Interactive prompt
python jwt_analyzer.py
```

### Verify Signature

```bash
# Verify HMAC signature with known secret
python jwt_analyzer.py <token> --secret "mysupersecret"
```

### Brute-Force Weak Secrets

```bash
# Use built-in wordlist (30 common JWT secrets)
python jwt_analyzer.py <token> --brute

# Custom wordlist
python jwt_analyzer.py <token> --brute --wordlist jwt_secrets.txt
```

### Demonstrate Vulnerabilities

```bash
# CVE-2015-9235: Generate alg:none token (no signature)
python jwt_analyzer.py <token> --forge-none

# Modify a claim and re-sign
python jwt_analyzer.py <token> --modify-claim role admin --secret mysecret
python jwt_analyzer.py <token> --modify-claim isAdmin true --secret mysecret

# JSON output
python jwt_analyzer.py <token> --json
```

---

## 📊 Example Output

```
  HEADER
    alg          none  ← CRITICAL
    typ          JWT

  PAYLOAD
    sub          user123
    role         user
    iat          1705276800  (2024-01-15T00:00:00+00:00)
    exp          1705363200  (2024-01-16T00:00:00+00:00)

  SECURITY FINDINGS (3):
  [CRITICAL] Algorithm 'none' — Token without signature
  CVE     : CVE-2015-9235
  Detail  : The token uses alg:none — tokens can be forged without knowing the secret.
  Fix     : Reject tokens with alg:none. Validate algorithm against a whitelist.

  [HIGH] Possible Algorithm Confusion Attack
  CVE     : CVE-2016-5431
  Detail  : If server accepts HS256 signed with RSA public key as secret, tokens can be forged.
  Fix     : Use algorithm whitelist. Never accept both RS* and HS* on the same endpoint.

  [MEDIUM] Token expires in 1 day — consider shorter lifetime
  Fix     : Access tokens: ≤ 15 min. Refresh tokens: ≤ 7 days.
```

---

## 🔬 CVE-2015-9235 — Algorithm None

```
Normal JWT:  header.payload.SIGNATURE
Forged JWT:  header.payload.
             (alg:none — no signature needed!)
```

**How it works:**

1. Attacker decodes any valid JWT
2. Modifies payload (e.g., `role: admin`)
3. Changes `alg` to `none`
4. Removes the signature
5. If the server accepts `alg:none` → authentication bypass!

**Demo:**

```bash
python jwt_analyzer.py <token> --forge-none
# Output: eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIiwicm9sZSI6ImFkbWluIn0.
```

---

## 🔬 CVE-2016-5431 — Algorithm Confusion

```
RS256 setup: server verifies with PUBLIC KEY
Attack:      sign HS256 token using PUBLIC KEY as HMAC secret
             → server verifies HS256 with public key → PASSES!
```

**Prevention:**

```python
# ✅ Always specify expected algorithm explicitly
import jwt
decoded = jwt.decode(token, public_key, algorithms=["RS256"])
# Never: algorithms=["RS256", "HS256"] together!
```

---

## 🛡️ Secure JWT Configuration

```python
# ✅ Secure JWT generation (Python example)
import jwt, datetime

payload = {
    "sub": user_id,
    "role": "user",
    "iat": datetime.datetime.utcnow(),
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
    "jti": str(uuid.uuid4()),  # Unique token ID for revocation
}

token = jwt.encode(
    payload,
    secret,
    algorithm="HS256"  # Or RS256 with key pair
)

# ✅ Secure verification
decoded = jwt.decode(
    token,
    secret,
    algorithms=["HS256"],  # Whitelist only!
    options={"require": ["exp", "iat", "sub"]}
)
```

---

## 📁 Repository Structure

```
jwt-analyzer/
├── jwt_analyzer.py          ← Main analyzer
├── wordlists/
│   └── jwt_secrets.txt      ← Common JWT secrets
├── README.md
└── .gitignore
```

---

## 🔗 References

- [CVE-2015-9235 — JWT alg:none vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)
- [CVE-2016-5431 — JWT algorithm confusion](https://nvd.nist.gov/vuln/detail/CVE-2016-5431)
- [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [PortSwigger: JWT Attacks](https://portswigger.net/web-security/jwt)
- [OWASP: JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

*Built by [Márcio Coutinho](https://github.com/marciolscoutinho) — Cibersecurity Specialist · Porto, Portugal*

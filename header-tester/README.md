<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=9&height=200&section=header&text=HTTP%20Header%20Security%20Tester&fontSize=40&fontAlignY=35&animation=twinkling&fontColor=ffffff" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python%203.x-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Standard-OWASP%20%7C%20Mozilla-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge" />
</p>

<p align="center"><strong>Audit HTTP security headers against OWASP and Mozilla Observatory standards — detect misconfigurations instantly.</strong></p>

---

## Features

| Check             | Header                        | Risk   |
| ----------------- | ----------------------------- | ------ |
| ✅ HSTS            | `Strict-Transport-Security`   | High   |
| ✅ CSP             | `Content-Security-Policy`     | High   |
| ✅ X-Frame         | `X-Frame-Options`             | Medium |
| ✅ XSS Protection  | `X-XSS-Protection`            | Medium |
| ✅ Content Type    | `X-Content-Type-Options`      | Medium |
| ✅ Referrer Policy | `Referrer-Policy`             | Low    |
| ✅ Permissions     | `Permissions-Policy`          | Low    |
| ✅ CORS            | `Access-Control-Allow-Origin` | High   |
| ✅ Server Info     | `Server`, `X-Powered-By`      | Info   |
| ✅ Cache Control   | `Cache-Control`               | Low    |

## Usage

```bash
# Scan a URL
python header_tester.py --url https://example.com

# Multiple URLs
python header_tester.py --urls urls.txt

# JSON export
python header_tester.py --url https://example.com --json report.json

# Strict mode (fail on any missing header)
python header_tester.py --url https://example.com --strict
```

## Output Example

```
╔══════════════════════════════════════════════════╗
║    HTTP HEADER SECURITY TESTER — header_tester   ║
╠══════════════════════════════════════════════════╣
║  Target  : https://example.com                   ║
║  Score   : 72/100  [GOOD]                        ║
╚══════════════════════════════════════════════════╝

  ✅ Strict-Transport-Security : max-age=31536000; includeSubDomains
  ✅ X-Frame-Options           : DENY
  ❌ Content-Security-Policy   : MISSING  [HIGH RISK]
  ⚠️  X-XSS-Protection         : 1 (deprecated, use CSP)
  ✅ X-Content-Type-Options    : nosniff
  ❌ Referrer-Policy           : MISSING  [LOW RISK]
  ⚠️  Server                   : nginx/1.24 (version disclosed)
```

## Standards Alignment

- OWASP Secure Headers Project
- Mozilla Observatory Grading
- CIS Controls v8 — 16.5
- NIST SP 800-44r2

---

> Built by [Márcio Coutinho](https://github.com/marciolscoutinho) | Cybersecurity Specialist

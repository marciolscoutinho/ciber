<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=18&height=200&section=header&text=Web%20Application%20Fuzzer&fontSize=48&fontAlignY=35&animation=twinkling&fontColor=ffffff" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python%203.x-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Standard-OWASP%20Top%2010-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge" />
</p>

<p align="center"><strong>Parameter fuzzing, hidden endpoint discovery, and error disclosure detection for authorized web application testing.</strong></p>

---

## Features

| Feature              | Description                                                 |
| -------------------- | ----------------------------------------------------------- |
| 🧪 Parameter Fuzzing | GET/POST parameter injection testing                        |
| 🔍 Error Disclosure  | Stack traces, debug info, version leaks                     |
| 💉 Payload Sets      | SQLi, XSS, SSTI, Path Traversal, Command Injection payloads |
| 🌐 Header Injection  | Host, X-Forwarded-For, Referer manipulation                 |
| ⚡ Concurrent         | Async-style threaded requests                               |
| 📊 Report            | Terminal + JSON + HTML export                               |
| 🚦 Rate Limiting     | Configurable delay + retry logic                            |

## Usage

```bash
# Fuzz GET parameters
python web_app_fuzzer.py --url "https://target.com/search?q=FUZZ" --wordlist params.txt

# POST body fuzzing
python web_app_fuzzer.py --url "https://target.com/login" --method POST --data "user=admin&pass=FUZZ"

# Error disclosure scan
python web_app_fuzzer.py --url "https://target.com" --mode errors

# Full scan with report
python web_app_fuzzer.py --url "https://target.com" --full --json report.json
```

## Payload Categories

- **SQLi**: `' OR '1'='1`, `1; DROP TABLE users--`, UNION-based
- **XSS**: `<script>alert(1)</script>`, event handlers, SVG
- **SSTI**: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- **Path Traversal**: `../../../etc/passwd`, URL-encoded variants
- **Command Injection**: `; id`, `| whoami`, backtick variants

## ⚠️ Authorized Use Only

Always obtain **written permission** before testing any web application.

---

> Built by [Márcio Coutinho](https://github.com/marciolscoutinho) | Cybersecurity Specialist

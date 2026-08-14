# 🎮 hack-me — Vulnerable CTF Application

> Intentionally vulnerable Flask web application with 5 real flags.
> Built for learning web application security in a safe, controlled environment.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.x-black?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-black?style=flat-square)](https://owasp.org/Top10/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square)](.github/workflows/ci.yml)

> ⚠️ **WARNING:** This application is **intentionally insecure**.
> Run it **only** inside Docker on a private network. Never expose to the internet.

---

## 📋 Overview

hack-me is a deliberately vulnerable Flask application designed to practice
exploiting common web vulnerabilities in a safe, isolated environment.
Each vulnerability maps to a real CVE class and OWASP Top 10 category.

```bash
# Quick start
docker-compose up -d
# Visit: http://localhost:5000
```

---

## 🚩 Flags

There are **5 flags** to find. No spoilers here — check `SOLUTIONS.md` only after you try!

| Flag        | Vulnerability                  | OWASP    | Difficulty |
| ----------- | ------------------------------ | -------- | ---------- |
| FLAG{1_...} | SQL Injection                  | A03:2021 | 🟢 Easy    |
| FLAG{2_...} | Server-Side Template Injection | A03:2021 | 🟡 Medium  |
| FLAG{3_...} | Path Traversal                 | A01:2021 | 🟡 Medium  |
| FLAG{4_...} | Command Injection              | A03:2021 | 🔴 Hard    |
| FLAG{5_...} | Hardcoded Secret               | A07:2021 | 🟢 Easy    |

---

## 🚀 Quick Start

### Using Docker (recommended)

```bash
# Clone the repository
git clone https://github.com/marciolscoutinho/hack-me.git
cd hack-me

# Build and start
docker-compose up -d

# Visit the app
open http://localhost:5000

# Stop when done
docker-compose down
```

### Manual (Python)

```bash
pip install flask
python init_db.py   # Initialize the database
python app.py       # Start the app on port 5000
```

---

## 🎯 Challenges

### Challenge 1 — The Login Bypass

The login form has a classic vulnerability.
Can you log in without knowing the password?

**Hint:** What happens when SQL queries trust user input?

**Endpoint:** `http://localhost:5000/login`

---

### Challenge 2 — The Template Trick

The profile page renders user-controlled data in a template.
Can you make the template engine execute your code?

**Hint:** Try putting some math in your username...

**Endpoint:** `http://localhost:5000/profile`

---

### Challenge 3 — The File Reader

The app lets you read files from the server.
Can you read files outside the intended directory?

**Hint:** Files have paths. Paths have separators. Separators can be tricky.

**Endpoint:** `http://localhost:5000/files`

---

### Challenge 4 — The Ping Tool

There's an admin tool that pings hosts.
Can you make it run other commands?

**Hint:** Shell commands can be chained...

**Endpoint:** `http://localhost:5000/admin/ping`

---

### Challenge 5 — The Source Code

The hardest flag is the easiest to find — if you know where to look.

**Hint:** Developers sometimes leave things in the source code they shouldn't.

---

## 🔧 Architecture

```
hack-me/
├── app.py                  ← Main Flask application (vulnerabilities here)
├── init_db.py              ← Database initialization
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── profile.html
│   ├── files.html
│   └── admin.html
├── static/
│   └── style.css
├── Dockerfile
├── docker-compose.yml
├── CHALLENGE.md            ← Challenge descriptions (no spoilers)
├── SOLUTIONS.md            ← Full solutions with explanations
├── .github/
│   └── workflows/
│       └── ci.yml          ← Build + smoke tests
├── README.md
└── .gitignore
```

---

## 📚 Learning Resources

After finding each flag, research the vulnerability class:

| Vulnerability     | Learn More                                                                                                                                                                             |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SQL Injection     | [OWASP SQLi](https://owasp.org/www-community/attacks/SQL_Injection) · [PortSwigger Labs](https://portswigger.net/web-security/sql-injection)                                           |
| SSTI              | [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection) · [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) |
| Path Traversal    | [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)                                                                                                         |
| Command Injection | [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)                                                                                                   |
| Hardcoded Secrets | [CWE-798](https://cwe.mitre.org/data/definitions/798.html)                                                                                                                             |

---

## 🔗 Similar Practice Platforms

- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application
- [WebGoat](https://github.com/WebGoat/WebGoat) — OWASP WebGoat
- [HackTheBox](https://hackthebox.com) — Online labs
- [TryHackMe](https://tryhackme.com) — Guided learning paths
- [PentesterLab](https://pentesterlab.com) — Web security exercises

---

*Built by [Márcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

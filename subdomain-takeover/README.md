<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6&height=200&section=header&text=Subdomain%20Takeover%20Checker&fontSize=42&fontAlignY=35&animation=twinkling&fontColor=ffffff" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python%203.x-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Type-Recon%20%7C%20Defensive-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge" />
</p>

<p align="center"><strong>Detect dangling DNS records pointing to unclaimed cloud services — before attackers do.</strong></p>

---

## What is Subdomain Takeover?

When a subdomain (e.g., `blog.example.com`) points via CNAME to a service (e.g., GitHub Pages, Heroku, AWS S3) that has been decommissioned but the DNS record not removed, an attacker can claim that service and serve malicious content under the victim's domain.

## Features

| Feature             | Description                                             |
| ------------------- | ------------------------------------------------------- |
| 🔍 CNAME Resolution | Detects dangling CNAME chains                           |
| 🌐 40+ Fingerprints | GitHub Pages, Heroku, AWS S3, Netlify, Fastly, Azure... |
| 📡 DNS Enumeration  | Wordlist-based subdomain discovery                      |
| 📋 Report           | Terminal + JSON export                                  |
| ⚡ Fast              | Concurrent DNS resolution                               |

## Usage

```bash
# Check a single subdomain
python subdomain_takeover.py --target blog.example.com

# Enumerate subdomains from wordlist
python subdomain_takeover.py --domain example.com --wordlist subdomains.txt

# JSON report
python subdomain_takeover.py --domain example.com --json report.json
```

## Vulnerable Fingerprints Detected

AWS S3, GitHub Pages, Heroku, Netlify, Azure App Service, Fastly, Shopify,
Tumblr, Ghost, Pantheon, Desk.com, Helpjuice, Instapage, Surveygizmo, and 30+ more.

## Standards Alignment

- OWASP Testing Guide — OTG-CONFIG-002
- HackerOne Hacktivity (common bug class)
- Bug Bounty Programs — P2/P3 severity

## ⚠️ Authorized Use Only

This tool is for security assessments of systems you **own or have written permission to test**.

---

> Built by [Márcio Coutinho](https://github.com/marciolscoutinho) | Level 5 Cybersecurity Specialist

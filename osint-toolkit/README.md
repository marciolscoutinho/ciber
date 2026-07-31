# 🌐 OSINT Toolkit

> Passive reconnaissance tool — DNS, subdomain enumeration, IP geolocation,
> SSL certificates, HTTP security headers. Zero dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](osint_toolkit.py)
[![Passive](https://img.shields.io/badge/Technique-Passive%20Recon-blue?style=flat-square)](.)

> **Passive reconnaissance only** — no active scanning, no exploitation.
> All data collected from public sources.

---

## Overview

OSINT Toolkit aggregates publicly available information about a target domain
or IP address. Useful for penetration testing reconnaissance, threat intelligence,
and security assessments.

```bash
# Full reconnaissance on domain
python osint_toolkit.py example.com

# IP address lookup
python osint_toolkit.py 185.220.101.47

# Specific modules only
python osint_toolkit.py example.com --modules dns ssl headers

# JSON output
python osint_toolkit.py example.com --json -o recon.json

# Save report
python osint_toolkit.py example.com -o recon_report.md
```

---

## Modules

### DNS Lookup

- A records (IPv4 addresses)
- AAAA records (IPv6 addresses)
- MX records (mail servers)
- NS records (name servers)
- TXT records (SPF, DMARC, DKIM, domain verification)
- CNAME records
- Reverse DNS (PTR) lookup
- SOA records

### Subdomain Enumeration

Passive enumeration using DNS resolution against 35+ common subdomains:

```
www, mail, ftp, smtp, pop, imap, webmail, remote, vpn,
api, dev, staging, test, admin, portal, blog, shop, cdn,
static, assets, m, mobile, app, secure, login, dashboard,
git, docs, support, help, status, beta, demo, sandbox...
```

### IP Geolocation

Using `ip-api.com` free tier (no API key required):

- Country, region, city
- ISP and organisation
- Timezone
- Latitude/longitude
- AS number

### SSL Certificate Information

- Subject and SAN (Subject Alternative Names)
- Issuer and certificate chain
- Validity period and days remaining
- Signature algorithm
- Certificate type (DV, OV, EV, wildcard)

### HTTP Security Headers

- Present/missing security headers
- HSTS, CSP, X-Frame-Options, Referrer-Policy
- Technology disclosure (Server, X-Powered-By)
- Redirect chain analysis

### WHOIS Information

- Registrar and registration dates
- Expiry date
- Name servers
- Registrant country (when available)

---

## Usage

```bash
# Complete recon
python osint_toolkit.py example.com

# Domain only (DNS + subdomains)
python osint_toolkit.py example.com --modules dns subdomains

# IP recon
python osint_toolkit.py 8.8.8.8 --modules geo reverse-dns

# SSL analysis only
python osint_toolkit.py example.com --modules ssl

# Headers only
python osint_toolkit.py https://example.com --modules headers

# JSON export
python osint_toolkit.py example.com --json -o recon.json

# Verbose (show all found/not-found)
python osint_toolkit.py example.com --verbose

# Custom DNS server
python osint_toolkit.py example.com --dns 1.1.1.1
```

---

## Example Output

```
  OSINT RECON REPORT — example.com
  ════════════════════════════════════════════════════════════════════

  DNS RECORDS
  A       : 93.184.216.34
  AAAA    : 2606:2800:220:1:248:1893:25c8:1946
  MX      : 0 example.com
  NS      : a.iana-servers.net, b.iana-servers.net
  TXT     : "v=spf1 -all"

  SUBDOMAINS FOUND (3/35)
  ✓ www.example.com      → 93.184.216.34
  ✓ mail.example.com     → 93.184.216.34
  ✓ api.example.com      → 93.184.216.35

  IP GEOLOCATION — 93.184.216.34
  Location   : Los Angeles, California, US
  ISP        : Edgecast Inc.
  ASN        : AS15133
  Timezone   : America/Los_Angeles

  SSL CERTIFICATE
  CN         : www.example.com
  Issuer     : DigiCert Inc
  Valid until: Jan 15 2025 (127 days)
  SANs       : example.com, www.example.com
  EV Cert    : No
  Wildcard   : No

  HTTP HEADERS
  ✗ Content-Security-Policy  MISSING
  ✓ Strict-Transport-Security  max-age=31536000
  ✓ X-Content-Type-Options   nosniff
  ⚠ Server: ECS (nyb/1D18)  ← info disclosure
```

---

## Repository Structure

```
ciber
    └──osint-toolkit/
                   ├── osint_toolkit.py
                   ├── README.md
                   └── .gitignore
```

---

## References

- [OSINT Framework](https://osintframework.com)
- [DNS Dumpster](https://dnsdumpster.com)
- [Shodan](https://www.shodan.io)
- [BuiltWith](https://builtwith.com)
- [ip-api.com](https://ip-api.com)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist, Porto, Portugal*

# 📋 Compliance Checker

> GDPR + ISO/IEC 27001:2022 + NIS2 gap analysis tool.  
> Generates a compliance score, identifies gaps, and produces a prioritized remediation plan.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](compliance_checker.py)
[![GDPR](https://img.shields.io/badge/GDPR-EU%202016%2F679-003399?style=flat-square)](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng)
[![ISO27001](https://img.shields.io/badge/ISO-27001%3A2022-orange?style=flat-square)](https://www.iso.org/standard/27001)
[![NIS2](https://img.shields.io/badge/NIS2-EU%202022%2F2555-blue?style=flat-square)](https://eur-lex.europa.eu/eli/dir/2022/2555)

---

## Overview

Compliance Checker performs a structured **gap analysis** across three major security and privacy frameworks:

- **GDPR** — Regulation (EU) 2016/679
- **ISO/IEC 27001:2022** — Information Security Management System requirements
- **NIS2 Directive** — Directive (EU) 2022/2555 cybersecurity risk-management and reporting obligations

The tool generates a compliance score, identifies non-compliant and partially compliant controls, and creates a remediation roadmap suitable for internal reviews, audits, or security improvement planning.

```bash
# Assess all frameworks using deterministic demo answers
python compliance_checker.py --framework all --demo --org "ACME Corp"

# Interactive assessment
python compliance_checker.py --framework gdpr --interactive --org "Company Ltd"

# Save a Markdown report
python compliance_checker.py --framework all --demo -o compliance_report.md

# Generate JSON output
python compliance_checker.py --framework all --demo --json -o compliance_report.json

# List all controls
python compliance_checker.py --list --framework iso27001
```

> The legacy Portuguese alias `--framework rgpd` is still accepted, but `--framework gdpr` is recommended for English documentation and usage.

---

## Controls Library

### GDPR — 9 Controls

| ID         | Article          | Title                                    | Mandatory |
| ---------- | ---------------- | ---------------------------------------- |:---------:|
| GDPR-Art5  | Art. 5           | Data Processing Principles               | ✅         |
| GDPR-Art6  | Art. 6 / Art. 30 | Lawful Basis for Processing              | ✅         |
| GDPR-Art12 | Art. 12-14       | Transparency and Communication           | ✅         |
| GDPR-Art17 | Art. 17          | Right to Erasure                         | ✅         |
| GDPR-Art25 | Art. 25          | Data Protection by Design and by Default | ✅         |
| GDPR-Art28 | Art. 28          | Processor Contracts                      | ✅         |
| GDPR-Art32 | Art. 32          | Security of Processing                   | ✅         |
| GDPR-Art33 | Art. 33-34       | Personal Data Breach Notification        | ✅         |
| GDPR-Art35 | Art. 35          | Data Protection Impact Assessment        | Optional  |

### ISO/IEC 27001:2022 — 10 Controls

| ID        | Annex  | Title                                                   | Mandatory |
| --------- | ------ | ------------------------------------------------------- |:---------:|
| ISO-A5.1  | A.5.1  | Information Security Policies                           | ✅         |
| ISO-A5.9  | A.5.9  | Inventory of Information and Other Associated Assets    | ✅         |
| ISO-A5.15 | A.5.15 | Access Control                                          | ✅         |
| ISO-A6.3  | A.6.3  | Information Security Awareness, Education, and Training | ✅         |
| ISO-A7.2  | A.7.2  | Physical Entry Controls                                 | ✅         |
| ISO-A8.2  | A.8.2  | Privileged Access Rights                                | ✅         |
| ISO-A8.7  | A.8.7  | Protection Against Malware                              | ✅         |
| ISO-A8.13 | A.8.13 | Information Backup                                      | ✅         |
| ISO-A8.16 | A.8.16 | Monitoring Activities                                   | ✅         |
| ISO-A8.23 | A.8.23 | Web Filtering                                           | Optional  |

### NIS2 Directive — 10 Controls

| ID           | Article       | Title                                                  | Mandatory |
| ------------ | ------------- | ------------------------------------------------------ |:---------:|
| NIS2-Art21-a | Art. 21(2)(a) | Risk Analysis and Information System Security Policies | ✅         |
| NIS2-Art21-b | Art. 21(2)(b) | Incident Handling                                      | ✅         |
| NIS2-Art21-c | Art. 21(2)(c) | Business Continuity and Crisis Management              | ✅         |
| NIS2-Art21-d | Art. 21(2)(d) | Supply Chain Security                                  | ✅         |
| NIS2-Art21-e | Art. 21(2)(e) | Security in Acquisition and Development                | ✅         |
| NIS2-Art21-f | Art. 21(2)(f) | Vulnerability Handling and Disclosure                  | ✅         |
| NIS2-Art21-g | Art. 21(2)(g) | Cyber Hygiene and Cybersecurity Training               | ✅         |
| NIS2-Art21-h | Art. 21(2)(h) | Cryptography and Encryption                            | ✅         |
| NIS2-Art21-i | Art. 21(2)(i) | Multi-Factor Authentication                            | ✅         |
| NIS2-Art23   | Art. 23       | Significant Incident Notification                      | ✅         |

---

## Usage

### Demo Assessment

```bash
python compliance_checker.py --framework all --demo --org "ACME Corp"
```

### Interactive Assessment

```bash
python compliance_checker.py --framework gdpr --interactive --org "My Company"
```

### Single Framework

```bash
python compliance_checker.py --framework iso27001 --demo
python compliance_checker.py --framework nis2 --demo
```

### Markdown Report

```bash
python compliance_checker.py --framework all --demo -o compliance_report.md
```

### JSON Output

```bash
python compliance_checker.py --framework all --demo --json -o compliance_report.json
```

### List Controls

```bash
python compliance_checker.py --list --framework gdpr
```

---

## Example Output

```text
  ════════════════════════════════════════════════════════════════════════
  COMPLIANCE REPORT — ALL FRAMEWORKS
  Organization : ACME Corp
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Score: 60.3%  [████████████████████████░░░░░░░░░░░░░░░░]
  ✅ Compliant: 12  ⚠ Partial: 12  ❌ Non-Compliant: 5  ➖ N/A: 0
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Critical gaps:
  ❌ [MANDATORY] GDPR-Art17 — Right to Erasure
  ❌ [MANDATORY] ISO-A8.2 — Privileged Access Rights
  ❌ [MANDATORY] NIS2-Art21-b — Incident Handling
```

---

## Auto-Generated Remediation Plan

The Markdown report includes a prioritized remediation plan:

| Priority | Framework | Control                                    | Effort | Target Deadline |
|:--------:| --------- | ------------------------------------------ |:------:| --------------- |
| 1        | GDPR      | GDPR-Art17 — Right to Erasure              | High   | 90 days         |
| 2        | ISO27001  | ISO-A8.2 — Privileged Access Rights        | High   | 90 days         |
| 3        | NIS2      | NIS2-Art21-b — Incident Handling           | High   | 90 days         |
| 4        | NIS2      | NIS2-Art21-i — Multi-Factor Authentication | Medium | 60 days         |

---

## Repository Structure

```text
ciber/
  └── compliance-checker
                  ├── compliance_checker.py
                  ├── README.md
                  ├── LICENSE
                  ├── .gitignore
                  ├── .markdownlint.json
                  └── .github/
                            └── workflows/
                            └── ci.yml
```

---

## Important Notes

This tool is designed for **self-assessment, education, and internal gap analysis**. It does not replace a formal legal review, certification audit, Data Protection Officer assessment, or qualified cybersecurity audit.

---

## References

- [GDPR — Regulation (EU) 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [NIS2 Directive — Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng)
- [CNPD — Portuguese Data Protection Authority](https://www.cnpd.pt/)
- [CNCS — Portuguese National Cybersecurity Centre](https://www.cncs.gov.pt/)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

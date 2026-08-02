# 🚨 IR Checklist Generator

> Dynamic Incident Response checklists — NIST SP 800-61 + SANS PICERL.
> Generates exportable Markdown checklists for 8 incident types.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](ir_checklist.py)
[![NIST](https://img.shields.io/badge/NIST-SP%20800--61-blue?style=flat-square)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
[![PICERL](https://img.shields.io/badge/SANS-PICERL-orange?style=flat-square)](https://www.sans.org)

---

## Overview

Generates structured, role-aware incident response checklists aligned with
NIST SP 800-61 Rev.2 and SANS PICERL methodology. Each checklist includes
priority levels, responsible parties, and time targets.

```bash
# List available incident types
python ir_checklist.py list

# Generate ransomware checklist (P1)
python ir_checklist.py ransomware --severity P1 -o ir_ransomware.md

# Generate phishing checklist for specific org
python ir_checklist.py phishing --org "ACME Corp" --analyst "J. Silva"

# JSON output (for ticketing systems)
python ir_checklist.py data-breach --json

# Filter by phase only
python ir_checklist.py ransomware --phase containment
```

---

## Supported Incident Types

| Type             | Specific Actions | Description                                           |
| ---------------- | ---------------- | ----------------------------------------------------- |
| `ransomware`     | 15               | Encryption detected, C2 blocking, backup verification |
| `data-breach`    | 12               | Data quantification, RGPD Art.33, legal notification  |
| `phishing`       | 12               | Email removal, URL blocking, credential reset         |
| `ddos`           | 9                | CDN activation, ISP blackholing, rate limiting        |
| `insider-threat` | 8                | Confidential handling, evidence preservation          |
| `web-compromise` | 8                | Webshell removal, file integrity, patch               |
| `zero-day`       | 8                | Vendor monitoring, temporary mitigations              |

**Common actions** (added to all types): 11 additional actions

---

## PICERL Phases

```
P — Preparation      : Pre-incident controls and readiness
I — Identification   : Detection, triage, severity classification
C — Containment      : Isolate and limit blast radius      ← Most critical
E — Eradication      : Remove root cause
R — Recovery         : Restore normal operations
L — Lessons Learned  : Post-mortem, improvement
```

---

## Priority Levels

| Priority | Label     | Time Target  | Examples                        |
| -------- | --------- | ------------ | ------------------------------- |
| P1       | IMMEDIATE | < 15 minutes | Isolate infected host, block C2 |
| P2       | HIGH      | < 1 hour     | Revoke compromised credentials  |
| P3       | MEDIUM    | < 4 hours    | Notify management, legal review |
| P4       | LOW       | < 24 hours   | Update documentation            |

---

## Example Output

```bash
python ir_checklist.py ransomware --severity P1
```

```
  IR CHECKLIST — RANSOMWARE
  Analyst: IR Lead | Org: Organisation | Severity: P1
  Total: 26 actions | Immediate: 5
  ════════════════════════════════════════════════════════════════════

  IDENTIFICATION
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [IMMEDIATE ] ☐  Confirm presence of encrypted files and ransom note
               → SOC / IR Lead | < 15min
               💡 Check: altered extensions, README_DECRYPT.txt, changed wallpaper

  [IMMEDIATE ] ☐  Identify affected systems and scope of encryption
               → IT / SOC | < 15min

  [HIGH      ] ☐  Check if shadow copies were deleted
               → IT | < 1h
               💡 vssadmin list shadows — empty = shadow copies deleted

  CONTAINMENT
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [IMMEDIATE ] ☐  ISOLATE affected systems from network (cable AND Wi-Fi)
               → IT / IR Lead | < 15min
               💡 PRIORITY — every minute = more encrypted files

  [IMMEDIATE ] ☐  Disable network shares and mapped drives
               → IT | < 15min
```

---

## Generated Markdown Report

The `-o` flag generates a complete Markdown checklist with:

- Header (incident type, severity, analyst, organisation, timestamp)
- Phase-by-phase tables with checkboxes
- Priority colour coding (IMMEDIATE/HIGH/MEDIUM/LOW)
- Responsible party per action
- Time targets
- Emergency contacts section (CNCS, CNPD)
- Action log table for timestamped documentation

---

## Roles

| Role           | Description                                   |
| -------------- | --------------------------------------------- |
| IR Lead        | Incident Response Lead — overall coordination |
| SOC            | Security Operations Centre analysts           |
| IT             | IT/Systems administrators                     |
| Management     | CISO, CTO, executive team                     |
| Legal          | Legal counsel and compliance                  |
| DPO            | Data Protection Officer                       |
| Communications | PR and internal/external communications       |
| Dev            | Development team                              |

---

## Integration Examples

```bash
# Generate for all common incident types
for type in ransomware data-breach phishing ddos; do
  python ir_checklist.py $type --severity P1 \
    --org "Company Ltd" \
    -o "checklists/ir_${type}_$(date +%Y%m%d).md"
done

# Export to JSON for Jira/ServiceNow integration
python ir_checklist.py ransomware --json | \
  jq '.items[] | select(.priority == "IMMEDIATE")' > immediate_actions.json

# Filter containment phase only
python ir_checklist.py ransomware --phase containment -o containment_only.md
```

---

## Repository Structure

```
ir-checklist/
├── ir_checklist.py
├── checklists/
│   ├── ir_ransomware_example.md
│   ├── ir_data-breach_example.md
│   ├── ir_phishing_example.md
│   └── ir_ddos_example.md
├── README.md
└── .gitignore
```

---

## References

- [NIST SP 800-61 Rev.2 — Computer Security Incident Handling](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [ENISA — Good Practice Guide for Incident Management](https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management)
- [CNCS — Centro Nacional de Ciberseguranca](https://www.cncs.gov.pt)
- [CNPD — Comissao Nacional de Protecao de Dados](https://www.cnpd.pt)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

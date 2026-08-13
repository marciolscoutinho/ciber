# 📦 SBOM Generator

> Software Bill of Materials generator — CycloneDX 1.4 (JSON + XML).
> Compliant with CISA mandate, US Executive Order 14028, and NIS2.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](sbom_generator.py)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.4-00aaff?style=flat-square)](https://cyclonedx.org)
[![CISA](https://img.shields.io/badge/CISA-SBOM%20Mandate-red?style=flat-square)](https://www.cisa.gov/sbom)

---

## Overview

Generates a complete Software Bill of Materials from your project's dependencies.
Supports pip, npm, and manual inventory. Outputs CycloneDX 1.4 JSON and XML —
the formats required by CISA and the US Executive Order 14028.

```bash
# Generate SBOM from project (auto-detect manifests)
python sbom_generator.py ./myproject

# Use live pip/npm environment
python sbom_generator.py ./myproject --live

# JSON only
python sbom_generator.py . --format json -o sbom.json

# XML only
python sbom_generator.py . --format xml -o sbom.xml

# Custom project metadata
python sbom_generator.py . --name "MyApp" --version "2.1.0" --author "J. Silva"
```

---

## Why SBOM?

A Software Bill of Materials is a **machine-readable inventory** of all software
components in your application. It enables:

| Use Case                     | Description                                                       |
| ---------------------------- | ----------------------------------------------------------------- |
| **Vulnerability Management** | Instantly know if you're affected when a new CVE drops            |
| **Supply Chain Security**    | Understand what third-party code you're shipping                  |
| **License Compliance**       | Identify GPL/copyleft dependencies before they cause legal issues |
| **Regulatory Compliance**    | Required by CISA (US), NIS2 (EU), and many defence contracts      |
| **Incident Response**        | Rapid impact assessment during a supply chain attack              |

---

## Supported Manifest Files

| File                 | Ecosystem | Discovery                          |
| -------------------- | --------- | ---------------------------------- |
| `requirements.txt`   | Python    | Recursive (all subdirectories)     |
| `requirements/*.txt` | Python    | Recursive                          |
| `Pipfile`            | Python    | `[packages]` + `[dev-packages]`    |
| `setup.py`           | Python    | `install_requires` extraction      |
| `pyproject.toml`     | Python    | Basic parsing                      |
| `package.json`       | Node.js   | `dependencies` + `devDependencies` |

---

## CycloneDX 1.4 Output

### JSON Format (`sbom.json`)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "serialNumber": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
  "metadata": {
    "timestamp": "2024-01-15T10:30:00+00:00",
    "tools": [{"vendor": "Marcio Coutinho", "name": "sbom-generator", "version": "1.0.0"}],
    "component": {
      "type": "application",
      "name": "MyApp",
      "version": "2.1.0",
      "purl": "pkg:generic/myapp@2.1.0"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-flask-pip",
      "name": "flask",
      "version": "2.3.0",
      "purl": "pkg:pypi/flask@2.3.0",
      "licenses": [{"license": {"id": "BSD-3-Clause"}}],
      "externalReferences": [
        {"type": "website", "url": "https://flask.palletsprojects.com"}
      ]
    }
  ],
  "dependencies": [
    {"ref": "root-component", "dependsOn": ["comp-flask-pip", "..."]}
  ]
}
```

### Package URL (purl) Standard

Every component gets a standardized purl:

| Ecosystem | purl Format                | Example                   |
| --------- | -------------------------- | ------------------------- |
| PyPI      | `pkg:pypi/name@version`    | `pkg:pypi/flask@2.3.0`    |
| npm       | `pkg:npm/name@version`     | `pkg:npm/express@4.18.2`  |
| apt       | `pkg:deb/name@version`     | `pkg:deb/openssl@3.0.2`   |
| Generic   | `pkg:generic/name@version` | `pkg:generic/myapp@1.0.0` |

---

## License Analysis

The tool identifies and flags license risks:

```
  Licenses:
  MIT                    24 packages
  Apache-2.0             12 packages
  BSD-3-Clause           8 packages
  GPL-3.0-only           2 packages  ← COPYLEFT WARNING
  NOASSERTION            5 packages  ← Unknown license

  WARNING: Copyleft licenses (GPL) detected — verify compatibility
```

**License categories:**

| Category        | Examples             | Risk                             |
| --------------- | -------------------- | -------------------------------- |
| Permissive      | MIT, Apache-2.0, BSD | Low                              |
| Weak copyleft   | LGPL, MPL            | Medium                           |
| Strong copyleft | GPL-2.0, GPL-3.0     | High — may require open-sourcing |
| Unknown         | NOASSERTION          | Requires manual review           |

---

## Regulatory Compliance

| Regulation              | Requirement                                 | This Tool                  |
| ----------------------- | ------------------------------------------- | -------------------------- |
| US EO 14028             | SBOM for all software sold to US government | CycloneDX 1.4 JSON         |
| CISA SBOM Mandate       | Minimum elements per NTIA guidance          | All 7 minimum elements     |
| NIS2 Art.21(d)          | Supply chain security documentation         | Machine-readable inventory |
| EU Cyber Resilience Act | Software transparency requirements          | Component + license data   |

**NTIA minimum elements** (all included):

1. Supplier name
2. Component name
3. Version
4. Other unique identifiers (purl)
5. Dependency relationship
6. Author of SBOM data
7. Timestamp

---

## Integration Examples

```bash
# CI/CD: Generate SBOM on every release
python sbom_generator.py . \
  --name "$APP_NAME" \
  --version "$VERSION" \
  --format both \
  -o "sbom-$VERSION"

# Combine with supply chain scanner
python sbom_generator.py . --format json -o sbom.json
python supply_chain.py . --inventory sbom.json --nvd

# Upload to Dependency Track
curl -X POST https://deptrack.company.com/api/v1/bom \
  -H "X-Api-Key: $API_KEY" \
  -F "project=$PROJECT_UUID" \
  -F "bom=@sbom.json"
```

---

## Repository Structure

```
sbom-generator/
├── sbom_generator.py
├── README.md
└── .gitignore
```

---

## References

- [CycloneDX Specification 1.4](https://cyclonedx.org/specification/overview/)
- [CISA SBOM Guidance](https://www.cisa.gov/sbom)
- [NTIA Minimum Elements for SBOM](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)
- [Package URL (purl) Specification](https://github.com/package-url/purl-spec)
- [US Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cibersecurity Specialist, Porto, Portugal*

# 🐳 Docker Security Auditor

> CIS-inspired Docker security auditor for Dockerfile static analysis and runtime
> container inspection. Zero external Python dependencies.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero-00ff88?style=flat-square)](docker_audit.py)
[![CIS](https://img.shields.io/badge/CIS-Docker%20Benchmark-orange?style=flat-square)](https://www.cisecurity.org/benchmark/docker)

---

## Overview

Docker Security Auditor checks Dockerfiles and running container configurations for
common security misconfigurations. It is designed for defensive reviews,
portfolio labs, CI validation, and internal hardening work.

The runtime mode requires the Docker CLI. Dockerfile analysis works with Python
standard library only.

---

## Usage

```bash
# Audit a Dockerfile
python docker_audit.py dockerfile ./Dockerfile

# Compatibility syntax
python docker_audit.py --dockerfile ./Dockerfile

# Scan every Dockerfile in a directory
python docker_audit.py scan ./project

# Audit a running or existing container
python docker_audit.py runtime my-container

# JSON output
python docker_audit.py dockerfile ./Dockerfile --json

# Save Markdown report
python docker_audit.py dockerfile ./Dockerfile -o docker_report.md

# Save JSON report
python docker_audit.py dockerfile ./Dockerfile --json -o docker_report.json

# Demo mode
python docker_audit.py --demo

# List implemented checks
python docker_audit.py --list-checks
```

---

## Dockerfile Checks

| Check ID | Severity      | Description                                                    |
| -------- |:-------------:| -------------------------------------------------------------- |
| DI-001   | HIGH/MEDIUM   | Base image missing a pinned tag or using `:latest`             |
| DI-002   | HIGH/CRITICAL | Container runs as root or explicitly uses `USER root`          |
| DI-003   | LOW           | `ADD` used where `COPY` is safer                               |
| DI-004   | LOW           | `COPY` without explicit `--chown`                              |
| DI-005   | CRITICAL      | Possible secrets in `ENV` or `ARG`                             |
| DI-006   | LOW           | Package installs without version pinning or APT cleanup        |
| DI-007   | HIGH          | Remote script piped directly into a shell                      |
| DI-008   | MEDIUM        | World-writable permissions such as `chmod 777`                 |
| DI-009   | LOW           | Missing `HEALTHCHECK`                                          |
| DI-010   | LOW           | Process manager used as PID 1                                  |
| DI-011   | MEDIUM        | Privileged port exposed (`< 1024`)                             |
| DI-012   | LOW           | Missing or relative `WORKDIR`                                  |
| DI-013   | CRITICAL      | Possible credentials embedded in `RUN`                         |
| DI-014   | MEDIUM        | Build tools installed in final image without multi-stage build |
| DI-015   | LOW           | Missing `.dockerignore` file                                   |

---

## Runtime Checks

| Check ID | Severity      | Description                               |
| -------- |:-------------:| ----------------------------------------- |
| RT-001   | CRITICAL      | Container running in privileged mode      |
| RT-002   | HIGH          | Dangerous Linux capabilities added        |
| RT-003   | MEDIUM        | Root filesystem is writable               |
| RT-004   | HIGH          | Host network mode enabled                 |
| RT-005   | HIGH          | Host PID namespace enabled                |
| RT-006   | MEDIUM        | No memory limit configured                |
| RT-007   | LOW           | No CPU limit configured                   |
| RT-008   | HIGH/CRITICAL | Sensitive host paths mounted              |
| RT-009   | CRITICAL      | Docker socket mounted in the container    |
| RT-010   | HIGH          | Secret-like environment variables exposed |
| RT-011   | MEDIUM        | `no-new-privileges` not enabled           |

---

## Example Output

```text
DOCKER SECURITY AUDIT REPORT
Target      : ./Dockerfile
Audit type  : dockerfile
Security Score: 52.0/100  [████████████████████░░░░░░░░░░░░░░░░░░░░]
Passed: 7  Failed: 3  Warnings: 5

CRITICAL  ██ 2
HIGH      █ 1
MEDIUM    ██ 2
LOW       ███ 3
```

---

## Secure Dockerfile Template

```dockerfile
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim
WORKDIR /app

RUN groupadd -r appuser && useradd -r -g appuser appuser
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --chown=appuser:appuser . .

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

EXPOSE 8080
CMD ["python", "app.py"]
```

---

## CI/CD Example

```yaml
name: Docker Audit

on: [push, pull_request]

jobs:
  docker-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Audit Dockerfile
        run: python docker_audit.py dockerfile ./Dockerfile --no-banner
```

Exit codes:

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | No MEDIUM/HIGH/CRITICAL findings |
| 1    | MEDIUM or HIGH findings found    |
| 2    | CRITICAL findings found          |

---

## Repository Structure

```text
ciber/
    └──docker-audit/
                  ├── docker_audit.py
                  ├── README.md
                  ├── LICENSE
                  ├── .gitignore
                  ├── .markdownlint.json
                  └── .github/
                            └── workflows/
                                        └── ci.yml
```

---

## References

- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

---

*Built by [Marcio Coutinho](https://github.com/marciolscoutinho) — Cybersecurity Specialist · Porto, Portugal*

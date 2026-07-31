#!/usr/bin/env python3
"""
supply_chain.py — Supply Chain Security Analyzer v1.0.0
========================================================
Analyzes Python and Node.js project dependencies to detect:
- Typosquatting (names similar to legitimate packages)
- Packages with suspicious versions or recently published packages
- Dependencies with known vulnerabilities (via OSV/PyPI Advisory)
- Dependency confusion attacks
- Abandoned packages with high exposure

OWASP A06:2021 — Vulnerable and Outdated Components
MITRE ATT&CK: T1195.001 — Supply Chain Compromise

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 03/05/2025
Reqs.  : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations

import argparse, json, re, sys, urllib.request, urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.RED}{C.BOLD}
 ███████╗██╗   ██╗██████╗ ██████╗ ██╗  ██╗   ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
 ██╔════╝██║   ██║██╔══██╗██╔══██╗██║  ╚██╗ ██╔════╝██║  ██║██╔══██╗██║████╗  ██║
 ███████╗██║   ██║██████╔╝██████╔╝██║   ██║ ██║     ███████║███████║██║██╔██╗ ██║
 ╚════██║██║   ██║██╔═══╝ ██╔═══╝ ██║   ██║ ██║     ██╔══██║██╔══██║██║██║╚██╗██║
 ███████║╚██████╔╝██║     ██║     ███████╔╝ ╚██████╗██║  ██║██║  ██║██║██║ ╚████║
 ╚══════╝ ╚═════╝ ╚═╝     ╚═╝     ╚══════╝   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝{C.RESET}
{C.DIM} v{__version__} — Supply Chain Security | Typosquatting · Dependency Confusion · CVE · OSV{C.RESET}
"""

SEP  = "━"*72
SEP2 = "═"*72

# ══════════════════════════════════════════════════════════════════════════════
# TYPOSQUATTING DATABASE
# ══════════════════════════════════════════════════════════════════════════════

# Popular legitimate packages and known typosquatting variants
LEGIT_PACKAGES_PYTHON = {
    "requests","flask","django","numpy","pandas","scipy","matplotlib",
    "tensorflow","torch","scikit-learn","pillow","sqlalchemy","celery",
    "fastapi","pydantic","pytest","black","mypy","cryptography","paramiko",
    "boto3","botocore","google-cloud","azure","pyOpenSSL","urllib3","certifi",
    "setuptools","pip","wheel","twine","poetry","click","rich","httpx",
    "aiohttp","pyyaml","toml","dotenv","python-dotenv","jinja2","werkzeug",
    "gunicorn","uvicorn","starlette","alembic","redis","pymongo","psycopg2",
}

LEGIT_PACKAGES_NPM = {
    "react","vue","angular","express","lodash","axios","moment","webpack",
    "babel","eslint","prettier","jest","mocha","chalk","commander","yargs",
    "dotenv","nodemon","cors","helmet","jsonwebtoken","bcrypt","mongoose",
    "sequelize","typeorm","knex","pg","mysql2","redis","socket.io",
    "next","nuxt","gatsby","typescript","ts-node","rollup","vite","esbuild",
}

# Known typosquatting patterns
TYPOSQUAT_PATTERNS_PYTHON = {
    "reqeusts":"requests", "requets":"requests", "requsets":"requests",
    "pil":"pillow", "PIL":"pillow",
    "nump":"numpy", "numppy":"numpy",
    "panads":"pandas", "pands":"pandas",
    "flsak":"flask", "falsk":"flask",
    "djnago":"django", "dajngo":"django",
    "setup-tools":"setuptools", "setuptool":"setuptools",
    "criptography":"cryptography", "cryptograpy":"cryptography",
    "parmiko":"paramiko", "paramiko2":"paramiko",
    "urlib3":"urllib3", "urllib2":"urllib3",
    "boto":"boto3", "boto2":"boto3",
    "pyyamml":"pyyaml", "pyaml":"pyyaml",
    "jinja":"jinja2", "jinja3":"jinja2",
    "werkzeug2":"werkzeug",
    "fastapi2":"fastapi", "fast-api":"fastapi",
    "python-dotenv2":"python-dotenv",
    "sqlalchemy2":"sqlalchemy",
    "click2":"click",
    "httpx2":"httpx",
}

TYPOSQUAT_PATTERNS_NPM = {
    "loadash":"lodash", "lodahs":"lodash",
    "expresss":"express", "exress":"express",
    "requets":"requests",
    "cross-env2":"cross-env",
    "mocha2":"mocha",
    "jest2":"jest", "jset":"jest",
    "wepack":"webpack", "webpak":"webpack",
    "momment":"moment", "moent":"moment",
    "dotenv2":"dotenv", "dot-env":"dotenv",
    "chalk2":"chalk", "chak":"chalk",
    "commander2":"commander",
    "nodemon2":"nodemon", "nodmon":"nodemon",
}

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Dependency:
    name:      str
    version:   str
    ecosystem: str   # pip / npm
    source:    str   # requirements.txt / package.json / etc.

@dataclass
class SupplyChainFinding:
    severity:    str
    category:    str
    package:     str
    version:     str
    description: str
    evidence:    str
    remediation: str
    cve:         str = ""
    mitre:       str = ""

@dataclass
class SupplyChainReport:
    project_path: str
    timestamp:    str
    dependencies: List[Dependency]
    findings:     List[SupplyChainFinding]
    risk_score:   int
    ecosystem:    List[str]

    def to_dict(self) -> dict:
        return {
            "project": self.project_path,
            "timestamp": self.timestamp,
            "total_dependencies": len(self.dependencies),
            "total_findings": len(self.findings),
            "risk_score": self.risk_score,
            "findings": [f.__dict__ for f in self.findings],
        }

# ══════════════════════════════════════════════════════════════════════════════
# PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def parse_requirements_txt(path: Path) -> List[Dependency]:
    deps = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#","-","--")):
            continue
        # name==version, name>=version, name~=version, name
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!~^]+\s*[\w\.\*]+)?", line)
        if m:
            name    = m.group(1).lower().replace("_","-")
            version = m.group(2).strip() if m.group(2) else "unknown"
            # Extract a clean numeric version
            ver_clean = re.sub(r"[><=!~^]","", version).strip()
            deps.append(Dependency(name, ver_clean or version, "pip", str(path)))
    return deps


def parse_pipfile(path: Path) -> List[Dependency]:
    deps = []
    content = path.read_text(errors="replace")
    in_packages = False
    for line in content.splitlines():
        if re.match(r"\[(packages|dev-packages)\]", line, re.I):
            in_packages = True; continue
        if line.startswith("[") and in_packages:
            in_packages = False
        if in_packages:
            m = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*=\s*["\']?([^"\']+)["\']?', line)
            if m:
                name = m.group(1).lower().replace("_","-")
                ver  = m.group(2).strip().strip('"\'')
                deps.append(Dependency(name, ver, "pip", str(path)))
    return deps


def parse_setup_py(path: Path) -> List[Dependency]:
    deps = []
    content = path.read_text(errors="replace")
    # install_requires=[...] or extras_require
    for match in re.finditer(r"install_requires\s*=\s*\[([^\]]+)\]", content, re.S):
        block = match.group(1)
        for pkg in re.findall(r'["\']([^"\']+)["\']', block):
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!~^][^,;\"\']*)?", pkg)
            if m:
                name = m.group(1).lower().replace("_","-")
                ver  = re.sub(r"[><=!~^]","", m.group(2) or "").strip()
                deps.append(Dependency(name, ver or "unknown", "pip", str(path)))
    return deps


def parse_package_json(path: Path) -> List[Dependency]:
    deps = []
    try:
        data = json.loads(path.read_text(errors="replace"))
        for section in ("dependencies","devDependencies","peerDependencies"):
            for name, version in data.get(section, {}).items():
                ver_clean = version.lstrip("^~>=<")
                deps.append(Dependency(name.lower(), ver_clean, "npm", str(path)))
    except json.JSONDecodeError:
        pass
    return deps


def discover_manifests(project_path: str) -> List[Path]:
    root = Path(project_path)
    manifests = []
    patterns = [
        "requirements*.txt", "requirements/*.txt",
        "Pipfile", "setup.py", "pyproject.toml",
        "package.json",
    ]
    skip_dirs = {"node_modules",".venv","venv","env",".git","dist","build"}

    for pattern in patterns:
        for p in root.rglob(pattern):
            if not any(skip in p.parts for skip in skip_dirs):
                manifests.append(p)
    return manifests


def load_all_dependencies(project_path: str) -> Tuple[List[Dependency], List[str]]:
    manifests = discover_manifests(project_path)
    all_deps: List[Dependency] = []
    ecosystems: List[str] = []

    for manifest in manifests:
        name = manifest.name.lower()
        if "requirements" in name and name.endswith(".txt"):
            deps = parse_requirements_txt(manifest)
            if deps: ecosystems.append("pip")
            all_deps.extend(deps)
        elif name == "pipfile":
            deps = parse_pipfile(manifest)
            if deps and "pip" not in ecosystems: ecosystems.append("pip")
            all_deps.extend(deps)
        elif name == "setup.py":
            deps = parse_setup_py(manifest)
            if deps and "pip" not in ecosystems: ecosystems.append("pip")
            all_deps.extend(deps)
        elif name == "package.json":
            deps = parse_package_json(manifest)
            if deps: ecosystems.append("npm")
            all_deps.extend(deps)

    # Deduplicate by name and ecosystem
    seen = set()
    unique = []
    for d in all_deps:
        key = (d.name, d.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(d)

    return unique, list(set(ecosystems))

# ══════════════════════════════════════════════════════════════════════════════
# ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _levenshtein(a: str, b: str) -> int:
    """Return the edit distance between two strings."""
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        curr = [i+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1,
                            prev[j]+(0 if ca==cb else 1)))
        prev = curr
    return prev[-1]


def check_typosquatting(dep: Dependency) -> Optional[SupplyChainFinding]:
    """Check whether the package is a possible typosquat."""
    name = dep.name.lower().replace("_","-")
    typo_db = (TYPOSQUAT_PATTERNS_PYTHON if dep.ecosystem == "pip"
               else TYPOSQUAT_PATTERNS_NPM)
    legit_db = (LEGIT_PACKAGES_PYTHON if dep.ecosystem == "pip"
                else LEGIT_PACKAGES_NPM)

    # Direct check against the typosquat database
    if name in typo_db:
        legit = typo_db[name]
        return SupplyChainFinding(
            "CRITICAL","Known Typosquatting",
            dep.name, dep.version,
            f"'{dep.name}' is a documented typosquat of '{legit}'.",
            f"Package '{dep.name}' found in the known typosquat list.",
            f"Replace it with '{legit}'. Check whether any code or systems were compromised.",
            mitre="T1195.001 — Supply Chain Compromise")

    # Similarity check (Levenshtein distance ≤ 2)
    for legit in legit_db:
        if name == legit: break
        dist = _levenshtein(name, legit)
        if dist == 1 and len(name) >= 4:
            return SupplyChainFinding(
                "HIGH","Possible Typosquatting",
                dep.name, dep.version,
                f"'{dep.name}' is very similar to '{legit}' (edit distance={dist}).",
                f"Levenshtein({name!r}, {legit!r}) = {dist}",
                f"Verify that you intended to use '{legit}'. Compare package hashes.",
                mitre="T1195.001")

    return None


def check_dependency_confusion(dep: Dependency,
                                 internal_prefixes: List[str]) -> Optional[SupplyChainFinding]:
    """Detect a potential dependency confusion attack."""
    name = dep.name.lower()
    for prefix in internal_prefixes:
        if name.startswith(prefix.lower()):
            return SupplyChainFinding(
                "HIGH","Dependency Confusion Risk",
                dep.name, dep.version,
                f"Package with internal prefix '{prefix}' installed from a public registry.",
                f"'{dep.name}' starts with the internal prefix '{prefix}' but comes from the public PyPI/npm registry.",
                "Use a private registry (Nexus/Artifactory) with priority over the public registry. "
                "Reserve the name on the public PyPI/npm registry.",
                mitre="T1195.001 — Dependency Confusion")
    return None


def _fetch_json(url: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(url,
            headers={"User-Agent": f"supply-chain-analyzer/{__version__}"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def check_pypi_metadata(dep: Dependency) -> List[SupplyChainFinding]:
    """Check package metadata on PyPI."""
    findings: List[SupplyChainFinding] = []
    if dep.ecosystem != "pip": return findings

    data = _fetch_json(f"https://pypi.org/pypi/{dep.name}/json")
    if not data: return findings

    info = data.get("info", {})
    releases = data.get("releases", {})

    # Recently created package (< 30 days) with little history
    first_upload = None
    for ver, files in releases.items():
        for f in files:
            upload_time = f.get("upload_time","")
            if upload_time:
                try:
                    t = datetime.fromisoformat(upload_time.replace("Z",""))
                    if first_upload is None or t < first_upload:
                        first_upload = t
                except Exception: pass

    if first_upload:
        age_days = (datetime.utcnow() - first_upload).days
        if age_days < 30 and len(releases) <= 2:
            findings.append(SupplyChainFinding(
                "MEDIUM","Very Recent Package",
                dep.name, dep.version,
                f"Package was created only {age_days} days ago and has few releases.",
                f"First publication: {first_upload.date()} | Releases: {len(releases)}",
                "Assess whether this package is necessary. Prefer mature alternatives."))

    # Package without an active maintainer (no release for more than 3 years)
    last_release = None
    for ver, files in releases.items():
        for f in files:
            t_str = f.get("upload_time","")
            if t_str:
                try:
                    t = datetime.fromisoformat(t_str.replace("Z",""))
                    if last_release is None or t > last_release:
                        last_release = t
                except Exception: pass

    if last_release:
        stale_days = (datetime.utcnow() - last_release).days
        if stale_days > 1095:  # 3 years
            findings.append(SupplyChainFinding(
                "LOW","Abandoned Package",
                dep.name, dep.version,
                f"The last release was {stale_days//365} years ago ({last_release.date()}).",
                f"Last release: {last_release.date()}",
                "Evaluate actively maintained alternatives. Abandoned packages accumulate vulnerabilities."))

    # Check whether the installed version is the latest
    latest = info.get("version","")
    if latest and dep.version and dep.version != "unknown":
        if dep.version != latest:
            findings.append(SupplyChainFinding(
                "LOW","Outdated Version",
                dep.name, dep.version,
                f"Installed version ({dep.version}) ≠ latest version ({latest}).",
                f"Installed: {dep.version} | Available: {latest}",
                f"Update: pip install {dep.name}=={latest}"))

    return findings


def check_osv_vulnerabilities(dep: Dependency) -> List[SupplyChainFinding]:
    """Query OSV.dev for known vulnerabilities."""
    findings: List[SupplyChainFinding] = []
    ecosystem_map = {"pip":"PyPI","npm":"npm"}
    ecosystem = ecosystem_map.get(dep.ecosystem)
    if not ecosystem or dep.version in ("unknown",""):
        return findings

    payload = json.dumps({
        "package": {"name": dep.name, "ecosystem": ecosystem},
        "version": dep.version,
    }).encode()

    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type":"application/json",
                     "User-Agent":f"supply-chain-analyzer/{__version__}"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
    except Exception:
        return findings

    for vuln in data.get("vulns", [])[:5]:
        vuln_id   = vuln.get("id","")
        summary   = vuln.get("summary","")[:120]
        severity  = "HIGH"
        cvss      = 0.0

        # Extract the CVSS score
        for sev in vuln.get("severity",[]):
            if sev.get("type","") == "CVSS_V3":
                score_match = re.search(r"CVSS:3\.\d/[^/]+/[^/]+/[^/]+/[^/]+/[^/]+/[^/]+/[^/]+/(\d+\.\d+)", sev.get("score",""))
        for db_specific in vuln.get("database_specific",{}).get("severity",[]):
            pass
        # Simplified
        aliases = vuln.get("aliases",[])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]
        cve     = cve_ids[0] if cve_ids else vuln_id

        # Estimated score
        if "critical" in summary.lower(): severity = "CRITICAL"
        elif "high" in summary.lower():   severity = "HIGH"
        elif "medium" in summary.lower(): severity = "MEDIUM"
        else:                              severity = "HIGH"

        findings.append(SupplyChainFinding(
            severity, "Known Vulnerability (OSV)",
            dep.name, dep.version,
            summary or f"Vulnerability {vuln_id} in {dep.name} {dep.version}",
            f"OSV ID: {vuln_id} | CVE: {cve}",
            f"Update {dep.name} to a non-vulnerable version.",
            cve=cve))

    return findings

# ══════════════════════════════════════════════════════════════════════════════
# KNOWN MALICIOUS PACKAGES (database offline)
# ══════════════════════════════════════════════════════════════════════════════

# Confirmed malicious packages (public history — removed from PyPI/npm)
KNOWN_MALICIOUS: Dict[str, str] = {
    # Python
    "colourama": "typosquat of 'colorama' — contained a cryptocurrency-stealing payload",
    "python-sqlite": "typosquat containing a backdoor",
    "jeIlyfish": "typosquat of 'jellyfish' (lowercase l → uppercase I)",
    "python-dateutils": "typosquat of 'python-dateutil'",
    "setup-tools": "typosquat of 'setuptools'",
    "loguru2": "malicious package disguised as loguru",
    "aiohttp-socks5": "contained data-exfiltration malware",
    "keep": "package containing cryptocurrency-mining code",
    # npm
    "event-stream@3.3.6": "backdoor inserted into a popular package",
    "ua-parser-js@0.7.29": "compromised version containing a cryptominer",
    "rc@1.2.8": "compromised version",
    "coa@2.0.3": "compromised version",
    "crossenv": "typosquat of 'cross-env'",
    "d3.js": "typosquat of 'd3'",
    "lodahs": "typosquat of 'lodash'",
    "discorrd": "typosquat of 'discord.js'",
    "node-ipc@10.1.1": "deliberate sabotage involving malware targeting Russian and Belarusian IP addresses",
}


def check_known_malicious(dep: Dependency) -> Optional[SupplyChainFinding]:
    key = dep.name.lower()
    if key in KNOWN_MALICIOUS:
        return SupplyChainFinding(
            "CRITICAL","Confirmed Malicious Package",
            dep.name, dep.version,
            f"'{dep.name}' is listed as a known malicious package.",
            KNOWN_MALICIOUS[key],
            "REMOVE IMMEDIATELY. Audit all systems where it was installed. "
            "Check whether any data was compromised.",
            mitre="T1195.001 — Supply Chain Compromise")
    return None

# ══════════════════════════════════════════════════════════════════════════════
# MAIN ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

def analyze(deps: List[Dependency],
             use_osv: bool = True,
             use_pypi: bool = True,
             internal_prefixes: List[str] = None,
             verbose: bool = False) -> List[SupplyChainFinding]:
    all_findings: List[SupplyChainFinding] = []
    prefixes = internal_prefixes or []
    total    = len(deps)

    for i, dep in enumerate(deps, 1):
        if verbose:
            print(f"  {C.DIM}[{i}/{total}] Analyzing {dep.name} {dep.version} ({dep.ecosystem})...{C.RESET}", end="\r")

        # 1. Confirmed malicious package
        f = check_known_malicious(dep)
        if f: all_findings.append(f)

        # 2. Typosquatting
        f = check_typosquatting(dep)
        if f: all_findings.append(f)

        # 3. Dependency confusion
        if prefixes:
            f = check_dependency_confusion(dep, prefixes)
            if f: all_findings.append(f)

        # 4. PyPI metadata (online)
        if use_pypi and dep.ecosystem == "pip":
            all_findings.extend(check_pypi_metadata(dep))

        # 5. OSV vulnerabilities (online)
        if use_osv:
            all_findings.extend(check_osv_vulnerabilities(dep))

    if verbose:
        print(" " * 72, end="\r")  # clear the progress line

    return all_findings

# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL  = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN}
SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW"]


def print_findings(findings: List[SupplyChainFinding]) -> None:
    for f in sorted(findings, key=lambda x: SEV_ORDER.index(x.severity)
                    if x.severity in SEV_ORDER else 99):
        col = SEV_COL.get(f.severity,"")
        print(f"\n{SEP}")
        print(f"  {col}{C.BOLD}[{f.severity}]{C.RESET} {f.category}")
        print(f"  {C.DIM}Package :{C.RESET} {C.YELLOW}{f.package}{C.RESET} @ {f.version}")
        print(f"  {C.DIM}Issue   :{C.RESET} {f.description}")
        print(f"  {C.DIM}Evidence:{C.RESET} {f.evidence[:100]}")
        print(f"  {C.DIM}Fix     :{C.RESET} {f.remediation[:120]}")
        if f.cve:
            print(f"  {C.DIM}CVE     :{C.RESET} {f.cve}")
        if f.mitre:
            print(f"  {C.DIM}MITRE   :{C.RESET} {f.mitre}")


def print_summary(report: SupplyChainReport) -> None:
    by_sev: Dict[str,int] = {}
    for f in report.findings:
        by_sev[f.severity] = by_sev.get(f.severity,0)+1

    score_col = C.RED if report.risk_score>=60 else C.YELLOW if report.risk_score>=30 else C.GREEN
    bar_len   = min(report.risk_score, 100)//5
    bar       = "█"*bar_len + "░"*(20-bar_len)

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}SUPPLY CHAIN ANALYSIS SUMMARY{C.RESET}")
    print(f"  Project      : {report.project_path}")
    print(f"  Ecosystems   : {', '.join(report.ecosystem) or 'none'}")
    print(f"  Dependencies : {len(report.dependencies)}")
    print(f"  Findings     : {len(report.findings)}")
    print(SEP)
    for sev in SEV_ORDER:
        count = by_sev.get(sev,0)
        if count:
            col = SEV_COL.get(sev,"")
            print(f"  {col}{sev:<10}{C.RESET} {'█'*min(count,30)} {count}")
    print(SEP)
    print(f"  {score_col}{C.BOLD}Risk Score: {report.risk_score}/100{C.RESET}  [{bar}]")
    print(SEP2)

    if by_sev.get("CRITICAL",0):
        print(f"\n  {C.RED}⚠ IMMEDIATE ACTION:{C.RESET}")
        for f in report.findings:
            if f.severity == "CRITICAL":
                print(f"  {C.RED}●{C.RESET} {f.package}: {f.description[:80]}")


def generate_markdown(report: SupplyChainReport) -> str:
    lines = [
        f"# 🔗 Supply Chain Security Report",
        f"**Project:** {report.project_path} | **Date:** {report.timestamp[:10]}",
        f"**Dependencies analyzed:** {len(report.dependencies)} | **Findings:** {len(report.findings)}",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|---|:---:|",
    ]
    by_sev: Dict[str,int] = {}
    for f in report.findings:
        by_sev[f.severity] = by_sev.get(f.severity,0)+1
    em = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    for sev in SEV_ORDER:
        lines.append(f"| {em.get(sev,'')} {sev} | **{by_sev.get(sev,0)}** |")

    lines += ["","## Findings","",
              "| Severity | Package | Category | Description |",
              "|:---:|---|---|---|"]
    for f in report.findings:
        lines.append(f"| {em.get(f.severity,'')} {f.severity} "
                     f"| `{f.package}@{f.version}` | {f.category} "
                     f"| {f.description[:80]} |")

    lines += ["",f"*Generated by supply-chain-analyzer v{__version__}*"]
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="supply-chain",
        description="Supply Chain Security Analyzer — Typosquatting · CVE · OSV · Dependency Confusion")
    parser.add_argument("path", nargs="?", default=".",
        help="Project path (default: current directory)")
    parser.add_argument("--no-osv",   action="store_true",
        help="Disable OSV.dev lookup (offline mode)")
    parser.add_argument("--no-pypi",  action="store_true",
        help="Disable PyPI metadata lookup")
    parser.add_argument("--internal-prefix", nargs="*", default=[],
        metavar="PREFIX",
        help="Internal package prefixes (for dependency confusion detection)")
    parser.add_argument("-v","--verbose", action="store_true")
    parser.add_argument("-o","--output",  help="Save a Markdown report")
    parser.add_argument("--json",         action="store_true", dest="json_out")
    parser.add_argument("--no-banner",    action="store_true")
    parser.add_argument("--version",      action="version", version=f"supply-chain {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    print(f"  {C.DIM}Discovering manifests in: {args.path}{C.RESET}")
    deps, ecosystems = load_all_dependencies(args.path)

    if not deps:
        # Demo
        print(f"  {C.YELLOW}No manifest found. Using demonstration dependencies.{C.RESET}")
        deps = [
            Dependency("colourama","1.0.0","pip","requirements.txt"),
            Dependency("requests","2.28.0","pip","requirements.txt"),
            Dependency("django","3.2.0","pip","requirements.txt"),
            Dependency("pyyamml","5.4.1","pip","requirements.txt"),
            Dependency("cryptography","38.0.1","pip","requirements.txt"),
            Dependency("flask","2.2.0","pip","requirements.txt"),
            Dependency("lodahs","4.17.21","npm","package.json"),
            Dependency("express","4.18.0","npm","package.json"),
        ]
        ecosystems = ["pip","npm"]

    print(f"  {C.DIM}{len(deps)} dependencies found in {ecosystems}.{C.RESET}")
    print(f"  {C.DIM}Analyzing {'(offline)' if args.no_osv else '(with OSV.dev)'}...{C.RESET}")

    findings = analyze(
        deps,
        use_osv   = not args.no_osv,
        use_pypi  = not args.no_pypi,
        internal_prefixes = args.internal_prefix,
        verbose   = args.verbose,
    )

    weights  = {"CRITICAL":40,"HIGH":20,"MEDIUM":8,"LOW":2}
    risk     = min(sum(weights.get(f.severity,0) for f in findings), 100)
    report   = SupplyChainReport(args.path, datetime.now().isoformat(),
                                  deps, findings, risk, ecosystems)

    if args.json_out:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_findings(findings)
        print_summary(report)

    if args.output:
        md = generate_markdown(report)
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    sys.exit(2 if any(f.severity=="CRITICAL" for f in findings) else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
threat_model.py — STRIDE Threat Modeling Tool v1.0.0
======================================================
Generates structured threat models using the STRIDE methodology.
Produces Markdown and JSON reports with threats, mitigations, and risk scores.

STRIDE: Spoofing · Tampering · Repudiation · Info Disclosure · DoS · Elevation

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 03/04/2025
Req.   : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations
import argparse, json, sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

__version__ = "1.0.0"

class C:
    RED="\033[91m";YELLOW="\033[93m";GREEN="\033[92m"
    CYAN="\033[96m";BOLD="\033[1m";DIM="\033[2m";RESET="\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
 ███████╗████████╗██████╗ ██╗██████╗ ███████╗
 ██╔════╝╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝
 ███████╗   ██║   ██████╔╝██║██║  ██║█████╗
 ╚════██║   ██║   ██╔══██╗██║██║  ██║██╔══╝
 ███████║   ██║   ██║  ██║██║██████╔╝███████╗
 ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝{C.RESET}
{C.DIM} v{__version__} — STRIDE Threat Modeling | Risk Score | Markdown Report{C.RESET}
"""

SEP  = "━"*72
SEP2 = "═"*72

# ══════════════════════════════════════════════════════════════════════════════
# STRIDE CATEGORIES
# ══════════════════════════════════════════════════════════════════════════════

STRIDE_CATEGORIES = {
    "S": {
        "name":        "Spoofing",
        "description": "Pretending to be another entity (user, system, or service)",
        "property":    "Authentication",
        "icon":        "🎭",
        "mitigations": [
            "Implement strong authentication (MFA, certificates)",
            "Use HTTPS/TLS for all communications",
            "Validate identity on every request (stateless authentication)",
            "Implement mutual TLS (mTLS) between services",
            "Use short-lived tokens (JWT exp < 15 min)",
        ],
    },
    "T": {
        "name":        "Tampering",
        "description": "Modifying data in transit or at rest without authorization",
        "property":    "Integrity",
        "icon":        "🔧",
        "mitigations": [
            "Sign critical data (HMAC, digital signatures)",
            "Use checksums to verify file integrity",
            "Implement granular access control (RBAC/ABAC)",
            "Use HTTPS to protect data in transit",
            "Implement change auditing (audit log)",
            "Use databases with transaction controls (ACID)",
        ],
    },
    "R": {
        "name":        "Repudiation",
        "description": "Denying having performed an action when it cannot be proven",
        "property":    "Non-repudiation",
        "icon":        "🚫",
        "mitigations": [
            "Implement immutable, centralized logging (SIEM)",
            "Use digital signatures for critical actions",
            "Record timestamp, IP address, user, and action for every operation",
            "Synchronize clocks (NTP) for event correlation",
            "Store logs with tamper protection (WORM)",
        ],
    },
    "I": {
        "name":        "Information Disclosure",
        "description": "Exposure of sensitive data to unauthorized entities",
        "property":    "Confidentiality",
        "icon":        "👁️",
        "mitigations": [
            "Encrypt data at rest (AES-256)",
            "Encrypt data in transit (TLS 1.3)",
            "Apply the principle of least privilege",
            "Mask sensitive data in logs and error responses",
            "Implement DLP (Data Loss Prevention)",
            "Classify and inventory sensitive data",
        ],
    },
    "D": {
        "name":        "Denial of Service",
        "description": "Making the system unavailable to legitimate users",
        "property":    "Availability",
        "icon":        "💥",
        "mitigations": [
            "Implement rate limiting and throttling",
            "Use a CDN and DDoS protection",
            "Implement circuit breakers and timeouts",
            "Scale resources with automatic scaling",
            "Validate and limit input sizes",
            "Use queues to process heavy workloads",
        ],
    },
    "E": {
        "name":        "Elevation of Privilege",
        "description": "Gaining more permissions than authorized",
        "property":    "Authorization",
        "icon":        "⬆️",
        "mitigations": [
            "Implement authorization at every layer (defense in depth)",
            "Use RBAC/ABAC with least privilege",
            "Validate permissions server-side (never trust the client)",
            "Apply security patches regularly",
            "Run containers/processes with minimal privileges",
            "Implement separation of duties for critical actions",
        ],
    },
}

# ══════════════════════════════════════════════════════════════════════════════
# COMPONENT THREAT LIBRARY
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Threat:
    id:             str
    stride_cat:     str       # S/T/R/I/D/E
    title:          str
    description:    str
    affected:       str       # component name
    likelihood:     int       # 1-5
    impact:         int       # 1-5
    attack_vector:  str
    mitigations:    List[str]
    cvss_like:      float     # calculated score

    @property
    def risk_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def risk_level(self) -> str:
        s = self.risk_score
        if s >= 20: return "CRITICAL"
        if s >= 15: return "HIGH"
        if s >= 8:  return "MEDIUM"
        return "LOW"


COMPONENT_THREATS: Dict[str, List[dict]] = {
    "web_api": [
        {"cat":"S","title":"JWT/Token Spoofing",
         "desc":"An attacker forges or steals authentication tokens to access the system as another user.",
         "likelihood":3,"impact":5,"vector":"Network",
         "mitigations":["Validate the JWT signature","Implement token rotation","Enforce HTTPS"]},
        {"cat":"T","title":"SQL/NoSQL Injection",
         "desc":"Malicious input alters database queries, enabling unauthorized access or modification.",
         "likelihood":4,"impact":5,"vector":"Network",
         "mitigations":["Prepared statements","Input validation","WAF","Secure ORM"]},
        {"cat":"T","title":"SSRF (Server-Side Request Forgery)",
         "desc":"An attacker causes the server to make requests to internal resources.",
         "likelihood":3,"impact":4,"vector":"Network",
         "mitigations":["Allowlist permitted URLs","Disable cloud metadata endpoints","Validate URLs"]},
        {"cat":"I","title":"IDOR (Insecure Direct Object Reference)",
         "desc":"Access to other users' resources by manipulating identifiers.",
         "likelihood":4,"impact":4,"vector":"Network",
         "mitigations":["Verify object-level authorization","Use UUIDs instead of sequential IDs"]},
        {"cat":"I","title":"Sensitive Data Exposure in Responses",
         "desc":"The API returns more data than necessary (over-fetching).",
         "likelihood":3,"impact":3,"vector":"Network",
         "mitigations":["Implement field filtering","Use DTOs/projections","Review API contracts"]},
        {"cat":"D","title":"Missing API Rate Limiting",
         "desc":"Without throttling, the API is vulnerable to brute-force attacks and denial of service.",
         "likelihood":4,"impact":3,"vector":"Network",
         "mitigations":["Rate limiting by IP address/user","Circuit breaker","CAPTCHA on critical endpoints"]},
        {"cat":"E","title":"Mass Assignment / Parameter Pollution",
         "desc":"An attacker injects unexpected parameters (for example, role or isAdmin) into the request.",
         "likelihood":3,"impact":5,"vector":"Network",
         "mitigations":["Allowlist permitted fields","Never bind requests directly to models","Strict validation"]},
    ],
    "database": [
        {"cat":"S","title":"Weak Database Authentication",
         "desc":"Default or weak database credentials.",
         "likelihood":2,"impact":5,"vector":"Adjacent",
         "mitigations":["Strong passwords and regular rotation","Certificate-based authentication","MFA for privileged access"]},
        {"cat":"T","title":"Unencrypted Backup",
         "desc":"Database backups are stored without encryption.",
         "likelihood":3,"impact":5,"vector":"Physical",
         "mitigations":["Encrypt backups (AES-256)","Control access to backup storage","Test restoration regularly"]},
        {"cat":"I","title":"Sensitive Data Unencrypted at Rest",
         "desc":"PII, passwords, and financial data are stored in plaintext.",
         "likelihood":2,"impact":5,"vector":"Physical",
         "mitigations":["Transparent Data Encryption (TDE)","Encrypt sensitive fields at the application layer","Tokenization"]},
        {"cat":"D","title":"Connection pool exhaustion",
         "desc":"An attacker exhausts available connections, making the database unavailable.",
         "likelihood":3,"impact":4,"vector":"Network",
         "mitigations":["Limit connections per user","Connection pooling with timeouts","Connection monitoring"]},
        {"cat":"E","title":"Principle of Least Privilege Not Enforced",
         "desc":"The application uses a DBA-privileged account instead of an account with minimal permissions.",
         "likelihood":3,"impact":5,"vector":"Network",
         "mitigations":["Application account with minimal GRANT permissions","Separate accounts by role (read/write/admin)","Privilege auditing"]},
        {"cat":"R","title":"Query Logging Disabled",
         "desc":"Without query logs, unauthorized access cannot be detected or investigated.",
         "likelihood":2,"impact":3,"vector":"Network",
         "mitigations":["Enable database audit logging","Centralize logs in the SIEM","Alerts for anomalous queries"]},
    ],
    "authentication": [
        {"cat":"S","title":"Credential Stuffing",
         "desc":"Use of credential lists compromised in other breaches to gain access.",
         "likelihood":5,"impact":4,"vector":"Network",
         "mitigations":["Mandatory MFA","Rate limiting on login attempts","Detection of IP addresses associated with known breaches (HaveIBeenPwned API)"]},
        {"cat":"S","title":"Phishing / Session Hijacking",
         "desc":"Session theft through XSS or phishing to gain access as a legitimate user.",
         "likelihood":4,"impact":4,"vector":"Network",
         "mitigations":["HttpOnly cookies","SameSite=Strict","CSP headers","Token binding"]},
        {"cat":"T","title":"Insecure Password Reset Flow",
         "desc":"The reset token is predictable, has no expiration, or is sent to an unverified email address.",
         "likelihood":3,"impact":4,"vector":"Network",
         "mitigations":["Random reset tokens (256 bits)","Short expiration period (15 minutes)","Invalidate after use"]},
        {"cat":"I","title":"User Enumeration",
         "desc":"Different responses for existing and nonexistent users disclose information.",
         "likelihood":4,"impact":2,"vector":"Network",
         "mitigations":["Identical responses for valid and invalid users","Rate limiting","Constant response time"]},
        {"cat":"D","title":"Missing Account Lockout",
         "desc":"Without account lockout, unlimited password brute-force attempts are possible.",
         "likelihood":4,"impact":4,"vector":"Network",
         "mitigations":["Progressive lockout after N attempts","CAPTCHA after failed attempts","Anomalous login alerts"]},
        {"cat":"E","title":"Privilege escalation via JWT claims",
         "desc":"Manipulation of JWT claims (for example, role:admin) when the signature is not validated.",
         "likelihood":3,"impact":5,"vector":"Network",
         "mitigations":["Validate the JWT signature server-side","Allowlist permitted algorithms","Never trust claims without verification"]},
    ],
    "microservices": [
        {"cat":"S","title":"Service Does Not Authenticate Other Services",
         "desc":"Internal services accept requests without verifying the caller's identity.",
         "likelihood":3,"impact":4,"vector":"Adjacent",
         "mitigations":["mutual TLS (mTLS)","Service mesh (Istio/Linkerd)","Per-service API keys"]},
        {"cat":"T","title":"Event/message tampering",
         "desc":"Messages in the message broker (Kafka/RabbitMQ) are not signed.",
         "likelihood":2,"impact":4,"vector":"Adjacent",
         "mitigations":["Sign message payloads","Encrypt sensitive messages","ACLs on the broker"]},
        {"cat":"I","title":"Sensitive Data in Logs",
         "desc":"Services log tokens, passwords, or PII in centralized logs.",
         "likelihood":4,"impact":4,"vector":"Network",
         "mitigations":["Mask sensitive data before logging","Log sanitization middleware","Log auditing"]},
        {"cat":"D","title":"Cascading Failures Without a Circuit Breaker",
         "desc":"A failure in one service causes cascading failures throughout the architecture.",
         "likelihood":3,"impact":5,"vector":"Network",
         "mitigations":["Circuit breaker pattern","Bulkhead isolation","Retry with exponential backoff","Fallback responses"]},
        {"cat":"E","title":"Container escape",
         "desc":"A runtime vulnerability allows a process to escape the container namespace.",
         "likelihood":2,"impact":5,"vector":"Local",
         "mitigations":["Unprivileged containers","Seccomp profiles","AppArmor/SELinux","Minimal images (distroless)"]},
    ],
    "file_upload": [
        {"cat":"T","title":"Malicious file upload",
         "desc":"Upload of malicious files (web shells or executables) that are subsequently executed.",
         "likelihood":4,"impact":5,"vector":"Network",
         "mitigations":["Validate file type using magic bytes, not the extension","Store files outside the web root","Rename files","AV scan"]},
        {"cat":"I","title":"Path traversal via filename",
         "desc":"A filename contains '../' to access files outside the permitted directory.",
         "likelihood":3,"impact":4,"vector":"Network",
         "mitigations":["Sanitize the filename","Use path.basename()","Validate the final path with realpath()"]},
        {"cat":"D","title":"DoS Through Large File Uploads",
         "desc":"Uploading extremely large files exhausts disk space or memory.",
         "likelihood":4,"impact":3,"vector":"Network",
         "mitigations":["Limit the maximum upload size","Process uploads asynchronously","Per-user quota"]},
        {"cat":"S","title":"MIME type spoofing",
         "desc":"An attacker sends a file with a forged Content-Type header to bypass validation.",
         "likelihood":3,"impact":3,"vector":"Network",
         "mitigations":["Validate using magic bytes (libmagic)","Do not trust the client-provided Content-Type","Re-encode images"]},
    ],
}

# ══════════════════════════════════════════════════════════════════════════════
# THREAT MODEL BUILDER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SystemComponent:
    name:       str
    comp_type:  str
    description:str
    trust_level:str   # high/medium/low/untrusted
    threats:    List[Threat] = field(default_factory=list)

@dataclass
class ThreatModel:
    system_name:  str
    description:  str
    author:       str
    version:      str
    date:         str
    components:   List[SystemComponent]
    data_flows:   List[dict]
    assumptions:  List[str]
    out_of_scope: List[str]

    @property
    def all_threats(self) -> List[Threat]:
        return [t for c in self.components for t in c.threats]

    @property
    def risk_summary(self) -> dict:
        summary = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for t in self.all_threats:
            summary[t.risk_level] = summary.get(t.risk_level,0)+1
        return summary


def build_threats_for_component(comp: SystemComponent, threat_id_start: int = 1) -> List[Threat]:
    threats = []
    threat_defs = COMPONENT_THREATS.get(comp.comp_type, [])
    for i, td in enumerate(threat_defs):
        cat_info = STRIDE_CATEGORIES[td["cat"]]
        # CVSS-like score
        likelihood = td["likelihood"]
        impact     = td["impact"]
        cvss_like  = round((likelihood/5 * 0.4 + impact/5 * 0.6) * 10, 1)
        threats.append(Threat(
            id            = f"T{threat_id_start+i:03d}",
            stride_cat    = td["cat"],
            title         = td["title"],
            description   = td["desc"],
            affected      = comp.name,
            likelihood    = likelihood,
            impact        = impact,
            attack_vector = td["vector"],
            mitigations   = td["mitigations"] + cat_info["mitigations"][:2],
            cvss_like     = cvss_like,
        ))
    return threats


# ══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATORS
# ══════════════════════════════════════════════════════════════════════════════

def generate_markdown_report(model: ThreatModel) -> str:
    lines = []
    summary = model.risk_summary
    total   = len(model.all_threats)

    lines.append(f"# 🛡️ Threat Model — {model.system_name}")
    lines.append(f"\n> **Version:** {model.version} | **Author:** {model.author} | **Date:** {model.date}")
    lines.append(f"\n**Metodologia:** STRIDE | **Framework:** Microsoft Threat Modeling")
    lines.append(f"\n---\n")

    lines.append("## 📋 Executive Summary\n")
    lines.append(f"{model.description}\n")
    lines.append(f"| Severity | Count |")
    lines.append(f"|---|:---:|")
    for sev, count in summary.items():
        emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(sev,"")
        lines.append(f"| {emoji} {sev} | **{count}** |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    lines.append("## 🏗️ Architecture\n")
    lines.append("### Components\n")
    lines.append("| Component | Type | Trust Level |")
    lines.append("|---|---|:---:|")
    for comp in model.components:
        trust_emoji = {"high":"🟢","medium":"🟡","low":"🟠","untrusted":"🔴"}.get(comp.trust_level,"")
        lines.append(f"| **{comp.name}** | {comp.comp_type} | {trust_emoji} {comp.trust_level} |")
    lines.append("")

    if model.data_flows:
        lines.append("### Data Flows\n")
        lines.append("| # | From | To | Protocol | Sensitivity |")
        lines.append("|:---:|---|---|---|:---:|")
        for i, df in enumerate(model.data_flows, 1):
            lines.append(f"| {i} | {df['from']} | {df['to']} | {df.get('protocol','HTTPS')} | {df.get('sensitivity','Medium')} |")
        lines.append("")

    lines.append("## 🎯 STRIDE Threat Analysis\n")

    for cat_key, cat_info in STRIDE_CATEGORIES.items():
        cat_threats = [t for t in model.all_threats if t.stride_cat == cat_key]
        if not cat_threats:
            continue
        lines.append(f"### {cat_info['icon']} {cat_key} — {cat_info['name']}\n")
        lines.append(f"*{cat_info['description']}* | **Security Property:** {cat_info['property']}\n")

        for threat in sorted(cat_threats, key=lambda t: t.risk_score, reverse=True):
            sev_emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(threat.risk_level,"")
            lines.append(f"#### {sev_emoji} [{threat.id}] {threat.title}\n")
            lines.append(f"| Field | Detail |")
            lines.append(f"|---|---|")
            lines.append(f"| **Component** | {threat.affected} |")
            lines.append(f"| **Vector** | {threat.attack_vector} |")
            lines.append(f"| **Likelihood** | {threat.likelihood}/5 |")
            lines.append(f"| **Impact** | {threat.impact}/5 |")
            lines.append(f"| **Risk Score** | {threat.risk_score}/25 ({threat.risk_level}) |")
            lines.append(f"| **CVSS-like** | {threat.cvss_like}/10.0 |")
            lines.append("")
            lines.append(f"**Description:** {threat.description}\n")
            lines.append(f"**Mitigations:**")
            for mit in threat.mitigations[:5]:
                lines.append(f"- {mit}")
            lines.append("")

    if model.assumptions:
        lines.append("## 📌 Assumptions\n")
        for a in model.assumptions:
            lines.append(f"- {a}")
        lines.append("")

    if model.out_of_scope:
        lines.append("## 🚫 Out of Scope\n")
        for o in model.out_of_scope:
            lines.append(f"- {o}")
        lines.append("")

    lines.append("## 🔗 References\n")
    lines.append("- [STRIDE Methodology — Microsoft](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)")
    lines.append("- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)")
    lines.append("- [MITRE ATT&CK Framework](https://attack.mitre.org/)")
    lines.append(f"\n---\n*Report generated by threat-model v{__version__} — {datetime.now().isoformat()}*")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def interactive_build() -> ThreatModel:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}INTERACTIVE THREAT MODEL BUILDER{C.RESET}")
    print(SEP)

    name   = input(f"  {C.DIM}System name:{C.RESET} ").strip() or "System"
    desc   = input(f"  {C.DIM}Short description:{C.RESET} ").strip()
    author = input(f"  {C.DIM}Author:{C.RESET} ").strip() or "Márcio Coutinho"

    print(f"\n  {C.BOLD}Available component types:{C.RESET}")
    comp_types = list(COMPONENT_THREATS.keys())
    for i, ct in enumerate(comp_types, 1):
        threat_count = len(COMPONENT_THREATS[ct])
        print(f"  {C.CYAN}[{i}]{C.RESET} {ct:<20} ({threat_count} threats)")

    components = []
    print(f"\n  {C.DIM}Add components (leave blank to finish):{C.RESET}")
    threat_id  = 1
    while True:
        comp_name = input(f"  Component name: ").strip()
        if not comp_name:
            break
        print(f"  Type [{', '.join(f'{i+1}={ct}' for i,ct in enumerate(comp_types))}]: ", end="")
        try:
            idx = int(input().strip()) - 1
            ct  = comp_types[idx] if 0 <= idx < len(comp_types) else "web_api"
        except (ValueError, IndexError):
            ct  = "web_api"
        trust = input(f"  Trust level [high/medium/low/untrusted]: ").strip() or "medium"
        comp  = SystemComponent(comp_name, ct, f"Component {comp_name}", trust)
        comp.threats = build_threats_for_component(comp, threat_id)
        threat_id += len(comp.threats)
        components.append(comp)
        print(f"  {C.GREEN}✓ {comp_name} added ({len(comp.threats)} threats generated){C.RESET}")

    if not components:
        # Default demo
        components = _demo_components()

    return ThreatModel(
        system_name  = name,
        description  = desc or f"Threat model for {name}",
        author       = author,
        version      = "1.0",
        date         = datetime.now().strftime("%Y-%m-%d"),
        components   = components,
        data_flows   = _demo_data_flows(components),
        assumptions  = ["System accessible via the Internet","Users authenticated with username/password","Data classified as confidential"],
        out_of_scope = ["Physical attacks against hardware","Root CA compromise","Advanced social engineering (APT)"],
    )


def _demo_components() -> List[SystemComponent]:
    """Demo components — typical web system."""
    configs = [
        ("REST API",     "web_api",       "high",    1),
        ("Database","database",      "high",    20),
        ("Auth Service", "authentication","high",    30),
        ("File Storage", "file_upload",   "medium",  45),
    ]
    result = []
    for name, ctype, trust, start in configs:
        c = SystemComponent(name, ctype, f"Component {name}", trust)
        c.threats = build_threats_for_component(c, start)
        result.append(c)
    return result


def _demo_data_flows(components: List[SystemComponent]) -> List[dict]:
    flows = []
    names = [c.name for c in components]
    if len(names) >= 2:
        flows.append({"from":"Internet","to":names[0],"protocol":"HTTPS","sensitivity":"High"})
    if len(names) >= 3:
        flows.append({"from":names[0],"to":names[1],"protocol":"TLS/TCP","sensitivity":"High"})
        flows.append({"from":names[0],"to":names[2],"protocol":"HTTPS","sensitivity":"High"})
    return flows


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN}

def print_summary(model: ThreatModel) -> None:
    summary = model.risk_summary
    total   = len(model.all_threats)
    print(f"\n{SEP2}")
    print(f"  {C.BOLD}THREAT MODEL — {model.system_name}{C.RESET}")
    print(f"  Components: {len(model.components)} | Threats identified: {total}")
    print(SEP)
    for sev, count in summary.items():
        col = SEV_COL.get(sev,C.DIM)
        bar = "█"*min(count,30)
        print(f"  {col}{sev:<10}{C.RESET} {bar} {count}")
    print(SEP2)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="threat-model",
        description="STRIDE Threat Modeling Tool — Build · Analyze · Report")
    parser.add_argument("--interactive","-i",action="store_true",
        help="Interactive builder (guided)")
    parser.add_argument("--demo", action="store_true",
        help="Generate a demo model (typical web application)")
    parser.add_argument("--components", nargs="+",
        choices=list(COMPONENT_THREATS.keys()),
        help="Components to include")
    parser.add_argument("--system-name", default="System", help="System name")
    parser.add_argument("--author", default="Márcio Coutinho")
    parser.add_argument("-o","--output", help="Output .md file")
    parser.add_argument("--json", action="store_true", dest="json_out")
    parser.add_argument("--list-components", action="store_true")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version=f"threat-model {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    if args.list_components:
        print(f"\n  {C.BOLD}Available component types:{C.RESET}\n")
        for ct, threats in COMPONENT_THREATS.items():
            print(f"  {C.CYAN}{ct:<20}{C.RESET} {len(threats)} predefined threats")
        return

    if args.interactive:
        model = interactive_build()
    elif args.demo or not args.components:
        comps = _demo_components()
        model = ThreatModel(
            system_name  = args.system_name,
            description  = "Demo threat model — web application with a REST API, database, authentication, and file uploads.",
            author       = args.author,
            version      = "1.0",
            date         = datetime.now().strftime("%Y-%m-%d"),
            components   = comps,
            data_flows   = _demo_data_flows(comps),
            assumptions  = ["System exposed to the Internet","Password-based authentication","Personal data processed in accordance with the GDPR"],
            out_of_scope = ["Physical attacks","Insider threats with root access to the infrastructure","Root CA compromise"],
        )
    else:
        comps = []
        tid   = 1
        for ct in args.components:
            c = SystemComponent(ct.replace("_"," ").title(), ct, f"Component {ct}", "medium")
            c.threats = build_threats_for_component(c, tid)
            tid += len(c.threats)
            comps.append(c)
        model = ThreatModel(
            system_name  = args.system_name,
            description  = f"Threat model for {args.system_name}",
            author       = args.author,
            version      = "1.0",
            date         = datetime.now().strftime("%Y-%m-%d"),
            components   = comps,
            data_flows   = _demo_data_flows(comps),
            assumptions  = ["Components accessible over the network"],
            out_of_scope = ["Physical attacks"],
        )

    print_summary(model)

    if args.json_out:
        out = {
            "system": model.system_name, "author": model.author,
            "date": model.date, "risk_summary": model.risk_summary,
            "components": [{"name":c.name,"type":c.comp_type,"trust":c.trust_level,
                "threats":[{"id":t.id,"cat":t.stride_cat,"title":t.title,
                    "risk":t.risk_level,"score":t.risk_score} for t in c.threats]}
                for c in model.components],
        }
        print(json.dumps(out, indent=2))
    else:
        md = generate_markdown_report(model)
        out_path = args.output or f"threat_model_{model.system_name.lower().replace(' ','_')}.md"
        Path(out_path).write_text(md, encoding="utf-8")
        print(f"\n  {C.GREEN}[✓] Report generated: {out_path}{C.RESET}")
        print(f"  {C.DIM}{len(model.all_threats)} threats | {len(md.splitlines())} lines of Markdown{C.RESET}")

if __name__ == "__main__":
    main()

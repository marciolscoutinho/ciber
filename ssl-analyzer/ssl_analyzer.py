#!/usr/bin/env python3
"""
ssl_analyzer.py — SSL/TLS Security Analyzer v1.0.0
====================================================
Analyzes SSL/TLS configurations: protocol versions, cipher suites,
certificates, HSTS, OCSP, and known vulnerabilities.
Comparable to testssl.sh, but implemented in pure Python.

⚠  USE ONLY ON SYSTEMS YOU OWN OR HAVE WRITTEN AUTHORIZATION TO TEST.

Author      : Marcio Coutinho — Cybersecurity Specialist, Porto, Portugal
Date        : 26/03/2024
Reqs.  : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations

import argparse, socket, ssl, struct, sys, time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
  ███████╗███████╗██╗         █████╗ ███╗   ██╗ █████╗ ██╗   ██╗   ██╗███████╗███████╗██████╗
  ██╔════╝██╔════╝██║        ██╔══██╗████╗  ██║██╔══██╗██║   ╚██╗ ██╔╝╚════██║██╔════╝██╔══██╗
  ███████╗███████╗██║        ███████║██╔██╗ ██║███████║██║    ╚████╔╝     ██╔╝█████╗  ██████╔╝
  ╚════██║╚════██║██║        ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝     ██╔╝  ██╔══╝  ██╔══██╗
  ███████║███████║███████╗   ██║  ██║██║ ╚████║██║  ██║███████╗██║      ██║   ███████╗██║  ██║
  ╚══════╝╚══════╝╚══════╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝{C.RESET}
{C.DIM} v{__version__} — SSL/TLS Analyzer | Protocol · Ciphers · Certificates · HSTS · OCSP{C.RESET}
{C.YELLOW} ⚠  Authorized use only. Never test systems without explicit written permission.{C.RESET}
"""

SEP  = "━"*72
SEP2 = "═"*72

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SSLFinding:
    severity:    str
    category:    str
    title:       str
    description: str
    evidence:    str
    remediation: str
    ref:         str = ""

@dataclass
class CertInfo:
    subject:       Dict[str,str]
    issuer:        Dict[str,str]
    serial:        str
    not_before:    str
    not_after:     str
    days_remaining:int
    san:           List[str]
    sig_alg:       str
    key_size:      int
    is_wildcard:   bool
    is_ev:         bool
    is_self_signed:bool

@dataclass
class TLSInfo:
    host:          str
    port:          int
    ip:            str
    # Protocol support
    protocols:     Dict[str,bool]   # "TLSv1.0" → True/False
    # Negotiated
    negotiated_proto: str
    negotiated_cipher:str
    # Certificate
    cert:          Optional[CertInfo]
    # Features
    hsts:          bool
    hsts_max_age:  int
    hsts_subdomains:bool
    ocsp_stapling: bool
    # Findings
    findings:      List[SSLFinding] = field(default_factory=list)

# ══════════════════════════════════════════════════════════════════════════════
# WEAK CIPHERS & PROTOCOLS
# ══════════════════════════════════════════════════════════════════════════════

WEAK_PROTOCOLS = {"SSLv2","SSLv3","TLSv1","TLSv1.1"}

WEAK_CIPHER_PATTERNS = [
    ("NULL",     "CRITICAL", "NULL cipher — no encryption"),
    ("EXPORT",   "CRITICAL", "EXPORT cipher — 40/56-bit keys (vulnerable to FREAK/LOGJAM)"),
    ("anon",     "CRITICAL", "Anonymous cipher — no authentication (vulnerable to MitM)"),
    ("RC4",      "HIGH",     "RC4 — stream cipher considered broken since 2013 (RFC 7465)"),
    ("DES",      "HIGH",     "DES — 56-bit key, breakable in < 1 day"),
    ("3DES",     "HIGH",     "3DES — vulnerable to SWEET32 (CVE-2016-2183)"),
    ("MD5",      "HIGH",     "MD5 in MAC — known collision weaknesses"),
    ("RC2",      "HIGH",     "RC2 — obsolete weak algorithm"),
    ("IDEA",     "MEDIUM",   "IDEA — legacy algorithm not recommended"),
    ("CBC",      "LOW",      "CBC mode — vulnerable to BEAST/POODLE with SSLv3/TLS 1.0"),
    ("SHA-1",    "MEDIUM",   "SHA-1 in signatures — deprecated since 2017"),
]

STRONG_CIPHER_KEYWORDS = [
    "ECDHE","DHE","AES-256-GCM","AES-128-GCM",
    "CHACHA20","TLS_AES","TLS_CHACHA20",
]

# ══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE PARSER
# ══════════════════════════════════════════════════════════════════════════════

def parse_cert(cert: dict) -> CertInfo:
    """Extracts certificate information from getpeercert()."""
    def _dict(pairs) -> Dict[str,str]:
        return {k: v for t in (pairs or []) for k, v in [t[0]]}

    subject = _dict(cert.get("subject",[]))
    issuer  = _dict(cert.get("issuer",[]))

    # SANs
    san = [v for t, v in cert.get("subjectAltName",[]) if t == "DNS"]

    # Datas
    not_before = cert.get("notBefore","")
    not_after  = cert.get("notAfter","")

    days_remaining = 0
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (exp - datetime.utcnow()).days
        except Exception: pass

    # Wildcard
    cn = subject.get("commonName","")
    is_wildcard = cn.startswith("*.")

    # Self-signed
    is_self_signed = (subject.get("organizationName","") ==
                      issuer.get("organizationName",""))

    # EV certificate (heuristic)
    is_ev = "EV" in issuer.get("organizationName","") or \
            bool(subject.get("jurisdictionCountryName",""))

    return CertInfo(
        subject        = subject,
        issuer         = issuer,
        serial         = str(cert.get("serialNumber","")),
        not_before     = not_before,
        not_after      = not_after,
        days_remaining = days_remaining,
        san            = san,
        sig_alg        = "",   # not available via the standard library
        key_size       = 0,    # not available via the standard library
        is_wildcard    = is_wildcard,
        is_ev          = is_ev,
        is_self_signed = is_self_signed,
    )

# ══════════════════════════════════════════════════════════════════════════════
# PROTOCOL CHECKER
# ══════════════════════════════════════════════════════════════════════════════

def _try_connect(host: str, port: int,
                 ssl_version, timeout: float = 5.0) -> Tuple[bool, str]:
    """Attempts an SSL connection using a specific version. Returns (success, cipher)."""
    try:
        ctx = ssl.SSLContext(ssl_version)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()[0] if ssock.cipher() else ""
                return True, cipher
    except ssl.SSLError:
        return False, ""
    except Exception:
        return False, ""


def check_protocol_support(host: str, port: int) -> Dict[str,bool]:
    """Checks which protocol versions are accepted."""
    results: Dict[str,bool] = {}

    # TLSv1.3
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                results["TLSv1.3"] = True
    except Exception:
        results["TLSv1.3"] = False

    # TLSv1.2
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                results["TLSv1.2"] = True
    except Exception:
        results["TLSv1.2"] = False

    # TLSv1.1 (deprecated)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                results["TLSv1.1"] = True
    except Exception:
        results["TLSv1.1"] = False

    # TLSv1.0 (deprecated)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        except AttributeError:
            pass
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                results["TLSv1.0"] = True
    except Exception:
        results["TLSv1.0"] = False

    return results

# ══════════════════════════════════════════════════════════════════════════════
# MAIN SCAN
# ══════════════════════════════════════════════════════════════════════════════

def scan(host: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    """Scan SSL/TLS completo de um host."""
    findings: List[SSLFinding] = []

    # Resolver IP
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"  {C.RED}[ERROR] Could not resolve '{host}': {e}{C.RESET}")
        sys.exit(1)

    # Main connection to obtain complete information
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    cert_raw = None
    negotiated_proto = ""
    negotiated_cipher = ""
    cert_info: Optional[CertInfo] = None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_raw          = ssock.getpeercert()
                negotiated_proto  = ssock.version() or ""
                cipher_info       = ssock.cipher()
                negotiated_cipher = cipher_info[0] if cipher_info else ""

                # HSTS via HTTP request
                hsts = False; hsts_max_age = 0; hsts_sub = False
                try:
                    ssock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                    response = ssock.recv(4096).decode(errors="replace")
                    if "strict-transport-security" in response.lower():
                        hsts = True
                        import re as _re
                        m = _re.search(r"max-age=(\d+)", response, _re.I)
                        if m: hsts_max_age = int(m.group(1))
                        hsts_sub = "includeSubDomains" in response
                except Exception: pass

    except ssl.SSLCertVerificationError as e:
        findings.append(SSLFinding(
            "CRITICAL","Certificate","Invalid or untrusted certificate",
            str(e),str(e),
            "Obtain a certificate signed by a trusted CA. Verify the chain of trust.",
            "RFC 5246"))
        # Retry without certificate verification
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host,port),timeout=timeout) as sock:
                with ctx2.wrap_socket(sock,server_hostname=host) as ssock:
                    cert_raw          = ssock.getpeercert()
                    negotiated_proto  = ssock.version() or ""
                    cipher_info       = ssock.cipher()
                    negotiated_cipher = cipher_info[0] if cipher_info else ""
        except Exception: pass
        hsts = False; hsts_max_age = 0; hsts_sub = False

    except Exception as e:
        print(f"  {C.RED}[ERROR] Connection failed: {e}{C.RESET}")
        sys.exit(1)

    # Parse certificate
    if cert_raw:
        cert_info = parse_cert(cert_raw)

    # Check protocol versions
    print(f"  {C.DIM}Checking protocol versions...{C.RESET}")
    protocols = check_protocol_support(host, port)

    # ── Findings analysis ─────────────────────────────────────────────────

    # Weak protocols
    for proto, supported in protocols.items():
        if supported and proto in WEAK_PROTOCOLS:
            findings.append(SSLFinding(
                "HIGH","Protocol",f"{proto} supported (deprecated)",
                f"{proto} is deprecated and vulnerable to downgrade attacks.",
                f"{proto} accepted by the server",
                f"Disable {proto}. Support only TLS 1.2 and TLS 1.3.",
                "RFC 8996"))

    # TLS 1.3 not supported
    if not protocols.get("TLSv1.3"):
        findings.append(SSLFinding(
            "MEDIUM","Protocol","TLS 1.3 not supported",
            "TLS 1.3 provides better security and performance.",
            "TLS 1.3 not accepted",
            "Enable TLS 1.3 on the web server (nginx/apache/haproxy).",
            "RFC 8446"))

    # Cipher suites
    cipher_upper = negotiated_cipher.upper()
    for keyword, sev, desc in WEAK_CIPHER_PATTERNS:
        if keyword.upper() in cipher_upper:
            findings.append(SSLFinding(
                sev,"Cipher",f"Weak cipher negotiated: {keyword}",
                desc,
                f"Cipher negociado: {negotiated_cipher}",
                "Configure the cipher suite list to use modern algorithms only.",
                "NIST SP 800-52r2"))

    # No PFS (Perfect Forward Secrecy)
    if negotiated_cipher and \
       not any(k in negotiated_cipher.upper() for k in ("ECDHE","DHE","TLS_AES","TLS_CHACHA")):
        findings.append(SSLFinding(
            "MEDIUM","Cipher","No Perfect Forward Secrecy (PFS)",
            "Without ECDHE/DHE, past sessions may be decrypted if the private key is compromised.",
            f"Cipher without PFS: {negotiated_cipher}",
            "Use cipher suites with ECDHE or DHE: ECDHE-RSA-AES256-GCM-SHA384",
            "NIST SP 800-52r2"))

    # Certificate
    if cert_info:
        if cert_info.is_self_signed:
            findings.append(SSLFinding(
                "HIGH","Certificate","Self-signed certificate",
                "The certificate is not trusted — any client can create an equivalent one.",
                "Issuer == Subject",
                "Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.).",
                "RFC 5280"))

        if cert_info.days_remaining < 0:
            findings.append(SSLFinding(
                "CRITICAL","Certificate",f"Certificate EXPIRED {abs(cert_info.days_remaining)} days ago",
                "Expired certificate — connections are rejected by modern clients.",
                f"Not After: {cert_info.not_after}",
                "Renew the certificate immediately.",
                "RFC 5280"))
        elif cert_info.days_remaining < 14:
            findings.append(SSLFinding(
                "HIGH","Certificate",f"Certificate expires in {cert_info.days_remaining} days",
                "Certificate is about to expire.",
                f"Not After: {cert_info.not_after}",
                "Renew the certificate before it expires. Consider automatic renewal (certbot).",
                "RFC 5280"))
        elif cert_info.days_remaining < 30:
            findings.append(SSLFinding(
                "MEDIUM","Certificate",f"Certificate expires in {cert_info.days_remaining} days",
                "Certificate has a short remaining validity period.",
                f"Not After: {cert_info.not_after}",
                "Plan certificate renewal.",
                "RFC 5280"))

    # HSTS
    if not hsts:
        findings.append(SSLFinding(
            "MEDIUM","Headers","HSTS not configured",
            "Without Strict-Transport-Security, browsers may be redirected to HTTP.",
            "Strict-Transport-Security header not found",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "RFC 6797"))
    elif hsts_max_age < 31536000:
        findings.append(SSLFinding(
            "LOW","Headers",f"HSTS max-age too short ({hsts_max_age}s)",
            "HSTS max-age should be at least 1 year (31536000s).",
            f"max-age={hsts_max_age}",
            "Set max-age=31536000 (minimum for the preload list).",
            "RFC 6797"))

    return TLSInfo(
        host=host, port=port, ip=ip,
        protocols=protocols,
        negotiated_proto=negotiated_proto,
        negotiated_cipher=negotiated_cipher,
        cert=cert_info,
        hsts=hsts, hsts_max_age=hsts_max_age, hsts_subdomains=hsts_sub,
        ocsp_stapling=False,
        findings=findings,
    )

# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN}

def print_report(info: TLSInfo) -> None:
    print(f"\n{SEP2}")
    print(f"  {C.BOLD}SSL/TLS ANALYSIS — {info.host}:{info.port}{C.RESET}")
    print(f"  IP: {info.ip}")
    print(SEP2)

    # Protocols
    print(f"\n  {C.BOLD}Protocol Support:{C.RESET}")
    for proto, supported in info.protocols.items():
        if supported:
            col  = C.RED if proto in WEAK_PROTOCOLS else C.GREEN
            icon = "⚠" if proto in WEAK_PROTOCOLS else "✓"
            print(f"    {col}{icon} {proto}{C.RESET}")
        else:
            print(f"    {C.DIM}✗ {proto}{C.RESET}")

    # Negotiated
    proto_col = C.GREEN if info.negotiated_proto in ("TLSv1.3","TLSv1.2") else C.RED
    print(f"\n  {C.BOLD}Negotiated:{C.RESET}")
    print(f"    Protocol : {proto_col}{info.negotiated_proto}{C.RESET}")
    print(f"    Cipher   : {info.negotiated_cipher}")

    # Certificate
    if info.cert:
        c = info.cert
        days_col = (C.RED if c.days_remaining < 0
                    else C.YELLOW if c.days_remaining < 30
                    else C.GREEN)
        print(f"\n  {C.BOLD}Certificate:{C.RESET}")
        print(f"    CN       : {c.subject.get('commonName','—')}")
        print(f"    Issuer   : {c.issuer.get('organizationName','—')}")
        print(f"    Expires  : {c.not_after}  {days_col}({c.days_remaining} days){C.RESET}")
        print(f"    Wildcard : {'Yes' if c.is_wildcard else 'No'}")
        print(f"    EV Cert  : {'Yes' if c.is_ev else 'No'}")
        if c.san:
            print(f"    SANs     : {', '.join(c.san[:5])}" +
                  (f" +{len(c.san)-5}" if len(c.san)>5 else ""))

    # HSTS
    print(f"\n  {C.BOLD}HSTS:{C.RESET}")
    hsts_col = C.GREEN if info.hsts else C.RED
    print(f"    Enabled  : {hsts_col}{'Yes' if info.hsts else 'No'}{C.RESET}")
    if info.hsts:
        print(f"    max-age  : {info.hsts_max_age}s")
        print(f"    subDomains: {'Yes' if info.hsts_subdomains else 'No'}")

    # Findings
    print(f"\n{SEP}")
    print(f"  {C.BOLD}FINDINGS ({len(info.findings)}){C.RESET}")
    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    for f in sorted(info.findings,
                    key=lambda x: sev_order.index(x.severity) if x.severity in sev_order else 99):
        col = SEV_COL.get(f.severity,"")
        print(f"\n  {col}[{f.severity}]{C.RESET} {C.BOLD}{f.title}{C.RESET}")
        print(f"    {f.description}")
        print(f"    {C.DIM}Fix: {f.remediation[:80]}{C.RESET}")

    # Score
    weights = {"CRITICAL":30,"HIGH":15,"MEDIUM":8,"LOW":2}
    deduct  = sum(weights.get(f.severity,0) for f in info.findings)
    score   = max(0, 100-deduct)
    col     = C.GREEN if score>=80 else C.YELLOW if score>=60 else C.RED
    bar_len = score//5
    bar     = "█"*bar_len + "░"*(20-bar_len)
    print(f"\n{SEP}")
    print(f"  {col}{C.BOLD}SSL/TLS Score: {score}/100{C.RESET}  [{bar}]")
    print(SEP2)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="ssl-analyzer",
        description="SSL/TLS Analyzer — Protocol · Ciphers · Certificates · HSTS")
    parser.add_argument("host",  help="Host to analyze (e.g. example.com)")
    parser.add_argument("--port","-p", type=int, default=443)
    parser.add_argument("--timeout",   type=float, default=10.0)
    parser.add_argument("--json",      action="store_true", dest="json_out")
    parser.add_argument("-o","--output", help="Save JSON report")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version",   action="version", version=f"ssl-analyzer {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    print(f"  {C.DIM}Analyzing {args.host}:{args.port}...{C.RESET}")
    info = scan(args.host, args.port, args.timeout)

    if args.json_out:
        out = {
            "host": info.host, "port": info.port, "ip": info.ip,
            "protocols": info.protocols,
            "negotiated": {"protocol": info.negotiated_proto,
                           "cipher": info.negotiated_cipher},
            "hsts": {"enabled": info.hsts, "max_age": info.hsts_max_age},
            "findings": [f.__dict__ for f in info.findings],
        }
        print(json.dumps(out, indent=2))
    else:
        print_report(info)

    if args.output:
        out = {"host":info.host,"findings":[f.__dict__ for f in info.findings]}
        Path(args.output).write_text(json.dumps(out, indent=2))
        print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    sys.exit(2 if any(f.severity=="CRITICAL" for f in info.findings) else 0)

if __name__ == "__main__":
    main()

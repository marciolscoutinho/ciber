#!/usr/bin/env python3
"""
header_tester.py — HTTP Header Security Tester v1.0.0
=======================================================
Analyzes HTTP security headers: CSP, CORS, HSTS, X-Frame-Options,
information disclosure, cookie flags, and much more.

⚠  USE ONLY ON SYSTEMS YOU OWN OR HAVE WRITTEN AUTHORIZATION TO TEST.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 21/09/2024
Reqs.  : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations
import argparse, json, re, socket, ssl, sys, urllib.request, urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
 ██╗  ██╗████████╗████████╗██████╗      ████████╗███████╗███████╗████████╗███████╗██████╗
 ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗        ██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ███████║   ██║      ██║   ██████╔╝        ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
 ██╔══██║   ██║      ██║   ██╔═══╝         ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
 ██║  ██║   ██║      ██║   ██║             ██║   ███████╗███████║   ██║   ███████╗██║  ██║
 ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝             ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{C.RESET}
{C.DIM} v{__version__} — HTTP Header Security Tester | CSP · CORS · HSTS · Cookies · Info Disclosure{C.RESET}
{C.YELLOW} ⚠  Authorized use only. Never test systems without explicit written permission.{C.RESET}
"""

SEP  = "━"*72
SEP2 = "═"*72

# ══════════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS DATABASE
# ══════════════════════════════════════════════════════════════════════════════

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS enforces HTTPS and prevents downgrade attacks.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "ref": "RFC 6797",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "CSP helps prevent XSS and data injection.",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none'",
        "ref": "CSP Level 3",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Prevents clickjacking through iframe embedding.",
        "recommended": "DENY or SAMEORIGIN",
        "ref": "RFC 7034",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME type sniffing.",
        "recommended": "nosniff",
        "ref": "OWASP",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls information sent in the Referer header.",
        "recommended": "strict-origin-when-cross-origin",
        "ref": "W3C",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controls access to browser features (camera, microphone, etc.).",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "ref": "W3C Feature Policy",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "XSS protection for legacy browsers (IE/older Chrome).",
        "recommended": "1; mode=block",
        "ref": "OWASP",
    },
}

INFO_DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-WordPress-Cache", "X-Runtime",
    "Via", "X-Backend-Server", "X-Forwarded-Server", "X-Application-Version",
    "X-Debug-Token", "X-Debug-Token-Link", "PHP-Version",
]

# CSP directives that weaken CSP effectiveness
UNSAFE_CSP_VALUES = [
    ("'unsafe-inline'",  "HIGH",   "CSP with 'unsafe-inline' — allows inline XSS"),
    ("'unsafe-eval'",    "HIGH",   "CSP with 'unsafe-eval' — allows eval() and similar constructs"),
    ("*",               "HIGH",   "CSP with wildcard (*) — allows any origin"),
    ("data:",           "MEDIUM", "CSP with data: — allows data URIs (XSS risk)"),
    ("http://",         "MEDIUM", "CSP with http:// — allows insecure content"),
    ("unsafe-hashes",   "MEDIUM", "CSP with unsafe-hashes — reduces protection"),
]

@dataclass
class HeaderFinding:
    severity:    str
    category:    str
    title:       str
    description: str
    evidence:    str
    remediation: str
    ref:         str = ""

@dataclass
class HeaderReport:
    url:           str
    status_code:   int
    server:        str
    headers:       Dict[str,str]
    findings:      List[HeaderFinding]
    score:         float
    missing:       List[str]
    disclosure:    Dict[str,str]
    cors_analysis: dict
    csp_analysis:  dict
    cookie_analysis:List[dict]

# ══════════════════════════════════════════════════════════════════════════════
# HTTP FETCHER
# ══════════════════════════════════════════════════════════════════════════════

def fetch_headers(url: str, follow_redirects: bool = True,
                  timeout: int = 15) -> Tuple[int, Dict[str,str], str]:
    """Returns (status_code, headers_dict, final_url)."""
    if not url.startswith(("http://","https://")):
        url = "https://" + url

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
        )
        if not follow_redirects:
            class NoRedirect(urllib.request.HTTPErrorProcessor):
                def http_response(self, req, resp): return resp
                https_response = http_response
            opener = urllib.request.build_opener(NoRedirect)

        req = urllib.request.Request(url, headers={
            "User-Agent": f"header-tester/{__version__} (security audit)",
            "Accept": "*/*",
        })
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, resp.url
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        return e.code, headers, url
    except Exception as e:
        print(f"  {C.RED}[ERROR] {e}{C.RESET}")
        sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
# ANALYZERS
# ══════════════════════════════════════════════════════════════════════════════

def analyze_missing_headers(headers: Dict[str,str]) -> List[HeaderFinding]:
    findings = []
    for hdr, info in REQUIRED_HEADERS.items():
        if hdr.lower() not in headers:
            findings.append(HeaderFinding(
                info["severity"], "Missing Header",
                f"Header '{hdr}' missing",
                info["description"],
                f"Header '{hdr}' not present in the response",
                f"Add: {hdr}: {info['recommended']}",
                info["ref"],
            ))
    return findings


def analyze_info_disclosure(headers: Dict[str,str]) -> Tuple[List[HeaderFinding], Dict[str,str]]:
    findings = []
    disclosed: Dict[str,str] = {}
    for hdr in INFO_DISCLOSURE_HEADERS:
        val = headers.get(hdr.lower(),"")
        if val:
            disclosed[hdr] = val
            # Assess severity based on content
            sev = "MEDIUM"
            if any(kw in val.lower() for kw in ["apache","nginx","iis","php","python","ruby","express"]):
                sev = "HIGH" if re.search(r"\d+\.\d+", val) else "MEDIUM"
            findings.append(HeaderFinding(
                sev, "Information Disclosure",
                f"Header '{hdr}' exposes stack information",
                f"The header reveals technology information: {val[:80]}",
                f"{hdr}: {val}",
                f"Remove or mask the '{hdr}' header.",
                "OWASP A05:2021",
            ))
    return findings, disclosed


def analyze_csp(headers: Dict[str,str]) -> Tuple[List[HeaderFinding], dict]:
    findings = []
    csp_val  = headers.get("content-security-policy","")
    analysis = {"present": bool(csp_val), "value": csp_val[:200], "issues": []}

    if not csp_val:
        return findings, analysis

    # Check unsafe values
    for val, sev, desc in UNSAFE_CSP_VALUES:
        if val.lower() in csp_val.lower():
            analysis["issues"].append(desc)
            findings.append(HeaderFinding(
                sev, "CSP Weakness", desc,
                "Unsafe values in Content-Security-Policy weaken protection.",
                f"CSP contains: {val}",
                f"Remove '{val}' from the CSP. Use hashes or nonces instead of 'unsafe-inline'.",
                "CSP Level 3",
            ))

    # Check whether default-src is missing
    if "default-src" not in csp_val.lower():
        analysis["issues"].append("Missing default-src")
        findings.append(HeaderFinding(
            "MEDIUM","CSP Weakness","CSP missing 'default-src'",
            "Missing default-src, directives not especificadas not têm fallback.",
            "Missing default-src no CSP",
            "Add 'default-src' as a fallback for other directives.",
            "CSP Level 3",
        ))

    # Check whether object-src is missing (allows plugins)
    if "object-src" not in csp_val.lower() and "default-src 'none'" not in csp_val.lower():
        findings.append(HeaderFinding(
            "MEDIUM","CSP Weakness","CSP missing 'object-src'",
            "Without object-src, Flash and other plugins may be loaded.",
            "object-src not defined",
            "Add 'object-src: none' to the CSP.",
            "CSP Level 3",
        ))

    return findings, analysis


def analyze_cors(headers: Dict[str,str], url: str) -> Tuple[List[HeaderFinding], dict]:
    findings = []
    acao     = headers.get("access-control-allow-origin","")
    acac     = headers.get("access-control-allow-credentials","").lower()
    acam     = headers.get("access-control-allow-methods","")
    acah     = headers.get("access-control-allow-headers","")

    analysis = {
        "allow_origin":      acao,
        "allow_credentials": acac,
        "allow_methods":     acam,
        "allow_headers":     acah,
        "issues":            [],
    }

    if not acao:
        return findings, analysis

    # Wildcard with credentials
    if acao == "*" and acac == "true":
        analysis["issues"].append("Wildcard with credentials")
        findings.append(HeaderFinding(
            "CRITICAL","CORS",
            "CORS: Access-Control-Allow-Origin: * with Allow-Credentials: true",
            "Dangerous combination — modern browsers block it, but misconfigurations can still create risk.",
            f"ACAO: * + ACAC: true",
            "Specify an explicit origin with ACAO. Never use * with credentials.",
            "OWASP CORS",
        ))

    # Origin wildcard
    elif acao == "*":
        analysis["issues"].append("Wildcard origin")
        findings.append(HeaderFinding(
            "MEDIUM","CORS",
            "CORS: Access-Control-Allow-Origin: * (all domains)",
            "Any domain can make cross-origin requests and read the response.",
            "ACAO: *",
            "Use an explicit origin allowlist.",
            "OWASP CORS",
        ))

    # Origin reflects the request (possible misconfiguration)
    elif acao not in ("null","") and "." in acao:
        # Check whether it is dynamic (reflects the request origin)
        # Heuristic: check whether the header origin matches the URL origin
        from urllib.parse import urlparse
        parsed = urlparse(url)
        own_origin = f"{parsed.scheme}://{parsed.netloc}"
        if acao != own_origin:
            analysis["issues"].append("Explicit origin configured")

    # Dangerous methods
    if acam:
        dangerous_methods = ["DELETE","PUT","PATCH"]
        for method in dangerous_methods:
            if method in acam.upper():
                findings.append(HeaderFinding(
                    "LOW","CORS",
                    f"CORS allows method {method}",
                    f"Method {method} is allowed cross-origin — assess whether it is required.",
                    f"Access-Control-Allow-Methods: {acam}",
                    "Limit CORS methods to the minimum required.",
                    "OWASP CORS",
                ))
                break

    return findings, analysis


def analyze_cookies(headers: Dict[str,str]) -> Tuple[List[HeaderFinding], List[dict]]:
    findings = []
    cookies  = []

    # There may be multiple Set-Cookie headers
    # urllib may combine them — attempt to parse them
    raw_cookies = []
    for k, v in headers.items():
        if k == "set-cookie":
            raw_cookies.extend(v.split("\n"))  # some parsers separate them with \n

    if not raw_cookies and "set-cookie" in headers:
        raw_cookies = [headers["set-cookie"]]

    for raw in raw_cookies:
        raw = raw.strip()
        if not raw: continue

        parts      = [p.strip() for p in raw.split(";")]
        name_val   = parts[0].split("=", 1) if "=" in parts[0] else [parts[0],""]
        name       = name_val[0].strip()
        flags      = {p.strip().lower() for p in parts[1:]}

        has_httponly = any("httponly" in f for f in flags)
        has_secure   = any("secure" in f for f in flags)
        has_samesite = any("samesite" in f for f in flags)
        samesite_val = next((f.split("=")[1] if "=" in f else "" for f in flags
                             if "samesite" in f), "")

        cookies.append({
            "name":     name,
            "httponly": has_httponly,
            "secure":   has_secure,
            "samesite": samesite_val or ("set" if has_samesite else "missing"),
        })

        # Check flags
        if not has_httponly:
            findings.append(HeaderFinding(
                "HIGH","Cookie",
                f"Cookie '{name}' missing HttpOnly",
                "Without HttpOnly, the cookie can be accessed via JavaScript (session hijacking risk through XSS).",
                f"Set-Cookie: {raw[:80]}",
                f"Add the HttpOnly flag to cookie '{name}'.",
                "OWASP A05:2021",
            ))

        if not has_secure:
            findings.append(HeaderFinding(
                "HIGH","Cookie",
                f"Cookie '{name}' missing Secure",
                "Without Secure, the cookie may be transmitted over unencrypted HTTP.",
                f"Set-Cookie: {raw[:80]}",
                f"Add the Secure flag to cookie '{name}'.",
                "RFC 6265",
            ))

        if not has_samesite:
            findings.append(HeaderFinding(
                "MEDIUM","Cookie",
                f"Cookie '{name}' missing SameSite",
                "Without SameSite, the cookie is sent in cross-site requests (CSRF risk).",
                f"Set-Cookie: {raw[:80]}",
                f"Add SameSite=Strict or SameSite=Lax to cookie '{name}'.",
                "RFC 6265bis",
            ))
        elif samesite_val.lower() == "none" and not has_secure:
            findings.append(HeaderFinding(
                "HIGH","Cookie",
                f"Cookie '{name}': SameSite=None without Secure",
                "SameSite=None requires Secure — browsers reject this combination.",
                f"SameSite=None without Secure",
                "Add the Secure flag to the cookie.",
                "RFC 6265bis",
            ))

    return findings, cookies


def analyze_hsts(headers: Dict[str,str]) -> List[HeaderFinding]:
    findings = []
    hsts_val = headers.get("strict-transport-security","")
    if not hsts_val:
        return findings  # already handled in missing headers

    # max-age
    m = re.search(r"max-age\s*=\s*(\d+)", hsts_val, re.I)
    if m:
        max_age = int(m.group(1))
        if max_age < 31536000:
            findings.append(HeaderFinding(
                "LOW","HSTS",
                f"HSTS max-age too short ({max_age}s < 31536000s)",
                "max-age should be at least 1 year for the preload list.",
                f"Strict-Transport-Security: {hsts_val}",
                "Set max-age=31536000.",
                "RFC 6797",
            ))
    else:
        findings.append(HeaderFinding(
            "HIGH","HSTS","HSTS without max-age",
            "HSTS without max-age é invalid — browsers ignoram o header.",
            f"Strict-Transport-Security: {hsts_val}",
            "Add max-age: Strict-Transport-Security: max-age=31536000",
            "RFC 6797",
        ))

    if "includeSubDomains" not in hsts_val:
        findings.append(HeaderFinding(
            "LOW","HSTS","HSTS without includeSubDomains",
            "Subdomains are not protected by HSTS.",
            f"Strict-Transport-Security: {hsts_val}",
            "Add includeSubDomains to the HSTS header.",
            "RFC 6797",
        ))

    return findings


def analyze_xframe(headers: Dict[str,str]) -> List[HeaderFinding]:
    findings = []
    xfo = headers.get("x-frame-options","")
    if xfo and xfo.upper() not in ("DENY","SAMEORIGIN"):
        findings.append(HeaderFinding(
            "MEDIUM","Clickjacking",
            f"X-Frame-Options with invalid value: '{xfo}'",
            "Unrecognized value — browsers may ignore it.",
            f"X-Frame-Options: {xfo}",
            "Use X-Frame-Options: DENY or SAMEORIGIN.",
            "RFC 7034",
        ))

    # ALLOW-FROM is deprecated
    if xfo and "ALLOW-FROM" in xfo.upper():
        findings.append(HeaderFinding(
            "LOW","Clickjacking",
            "X-Frame-Options uses ALLOW-FROM (deprecated)",
            "ALLOW-FROM is not supported in Chrome/Edge. Use CSP frame-ancestors.",
            f"X-Frame-Options: {xfo}",
            "Replace with Content-Security-Policy: frame-ancestors 'self' https://trusted.com",
            "CSP Level 3",
        ))
    return findings


def check_http_redirect(base_url: str) -> List[HeaderFinding]:
    """Checks whether HTTP redirects to HTTPS."""
    findings = []
    if base_url.startswith("https://"):
        http_url = "http://" + base_url[8:]
    else:
        return findings

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        class NoRedirect(urllib.request.HTTPErrorProcessor):
            def http_response(self, req, resp): return resp
            https_response = http_response

        opener = urllib.request.build_opener(NoRedirect)
        req    = urllib.request.Request(http_url, headers={
            "User-Agent": f"header-tester/{__version__}",
        })
        with opener.open(req, timeout=8) as resp:
            location = resp.headers.get("Location","")
            if resp.status in (200,) and not location:
                findings.append(HeaderFinding(
                    "HIGH","HTTPS Redirect",
                    "HTTP does not redirect to HTTPS",
                    "The site is accessible over HTTP without redirection — data may travel in clear text.",
                    f"HTTP {resp.status} without a Location header",
                    "Add a 301 redirect from HTTP to HTTPS.",
                    "RFC 7231",
                ))
            elif location and not location.startswith("https://"):
                findings.append(HeaderFinding(
                    "HIGH","HTTPS Redirect",
                    "HTTP redirects to HTTP (not HTTPS)",
                    f"Redirect to: {location}",
                    f"Location: {location}",
                    "Ensure the redirect points to https://",
                    "RFC 7231",
                ))
    except Exception:
        pass
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# FULL SCAN
# ══════════════════════════════════════════════════════════════════════════════

def scan(url: str) -> HeaderReport:
    if not url.startswith(("http://","https://")):
        url = "https://" + url

    print(f"  {C.DIM}Fetching {url}...{C.RESET}")
    status, headers, final_url = fetch_headers(url)

    all_findings: List[HeaderFinding] = []

    # Missing headers
    missing = [h for h in REQUIRED_HEADERS if h.lower() not in headers]
    all_findings.extend(analyze_missing_headers(headers))

    # Info disclosure
    disc_findings, disclosed = analyze_info_disclosure(headers)
    all_findings.extend(disc_findings)

    # CSP
    csp_findings, csp_analysis = analyze_csp(headers)
    all_findings.extend(csp_findings)

    # CORS
    cors_findings, cors_analysis = analyze_cors(headers, final_url)
    all_findings.extend(cors_findings)

    # Cookies
    cookie_findings, cookies = analyze_cookies(headers)
    all_findings.extend(cookie_findings)

    # HSTS details
    all_findings.extend(analyze_hsts(headers))

    # X-Frame-Options
    all_findings.extend(analyze_xframe(headers))

    # HTTP → HTTPS redirect
    all_findings.extend(check_http_redirect(final_url))

    # Score
    weights = {"CRITICAL":30,"HIGH":15,"MEDIUM":8,"LOW":2}
    score   = max(0.0, round(100 - sum(weights.get(f.severity,0)
                                       for f in all_findings), 1))

    return HeaderReport(
        url           = final_url,
        status_code   = status,
        server        = disclosed.get("Server",""),
        headers       = headers,
        findings      = all_findings,
        score         = score,
        missing       = missing,
        disclosure    = disclosed,
        cors_analysis = cors_analysis,
        csp_analysis  = csp_analysis,
        cookie_analysis=cookies,
    )


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL  = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN}
SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW"]

def print_report(r: HeaderReport) -> None:
    print(f"\n{SEP2}")
    print(f"  {C.BOLD}HTTP HEADER SECURITY ANALYSIS{C.RESET}")
    print(f"  URL    : {r.url}")
    print(f"  Status : {r.status_code}")
    if r.server:
        print(f"  Server : {C.YELLOW}{r.server}{C.RESET}")
    print(SEP2)

    # Security headers present
    print(f"\n  {C.BOLD}Security Headers:{C.RESET}")
    for hdr in REQUIRED_HEADERS:
        present = hdr.lower() in r.headers
        icon    = f"{C.GREEN}✓{C.RESET}" if present else f"{C.RED}✗{C.RESET}"
        val     = r.headers.get(hdr.lower(),"")
        val_str = f"  {C.DIM}{val[:50]}{C.RESET}" if present else ""
        print(f"  {icon} {hdr:<32}{val_str}")

    # Information Disclosure
    if r.disclosure:
        print(f"\n  {C.BOLD}Information Disclosure:{C.RESET}")
        for hdr, val in r.disclosure.items():
            print(f"  {C.YELLOW}⚠{C.RESET} {hdr}: {C.YELLOW}{val}{C.RESET}")

    # CORS
    if r.cors_analysis.get("allow_origin"):
        acao = r.cors_analysis["allow_origin"]
        col  = C.RED if acao == "*" else C.YELLOW if r.cors_analysis["issues"] else C.GREEN
        print(f"\n  {C.BOLD}CORS:{C.RESET}")
        print(f"  Allow-Origin : {col}{acao}{C.RESET}")
        print(f"  Credentials  : {r.cors_analysis.get('allow_credentials','not set')}")
        print(f"  Methods      : {r.cors_analysis.get('allow_methods','not set')}")

    # CSP Summary
    if r.csp_analysis.get("present"):
        csp_ok = not r.csp_analysis.get("issues")
        col    = C.GREEN if csp_ok else C.YELLOW
        print(f"\n  {C.BOLD}CSP:{C.RESET} {col}{'OK' if csp_ok else str(len(r.csp_analysis['issues'])) + ' issues'}{C.RESET}")

    # Cookies
    if r.cookie_analysis:
        print(f"\n  {C.BOLD}Cookies ({len(r.cookie_analysis)}):{C.RESET}")
        for ck in r.cookie_analysis:
            ho = f"{C.GREEN}H{C.RESET}" if ck["httponly"] else f"{C.RED}h{C.RESET}"
            sc = f"{C.GREEN}S{C.RESET}" if ck["secure"]   else f"{C.RED}s{C.RESET}"
            ss = f"{C.GREEN}SS{C.RESET}" if ck["samesite"] not in ("missing","") \
                 else f"{C.RED}ss{C.RESET}"
            print(f"  [{ho}{sc}{ss}] {ck['name'][:40]}  "
                  f"{C.DIM}samesite={ck['samesite']}{C.RESET}")

    # Findings
    print(f"\n{SEP}")
    print(f"  {C.BOLD}FINDINGS ({len(r.findings)}){C.RESET}")
    for f in sorted(r.findings, key=lambda x: SEV_ORDER.index(x.severity)
                    if x.severity in SEV_ORDER else 99):
        col = SEV_COL.get(f.severity,"")
        print(f"\n  {col}[{f.severity}]{C.RESET} {C.BOLD}{f.title}{C.RESET}")
        print(f"    {f.description}")
        if f.evidence and f.evidence != f.title:
            print(f"    {C.DIM}Evidence: {f.evidence[:80]}{C.RESET}")
        print(f"    {C.DIM}Fix: {f.remediation[:100]}{C.RESET}")

    # Score
    score_col = C.GREEN if r.score>=80 else C.YELLOW if r.score>=60 else C.RED
    bar_len   = int(r.score/100*40)
    bar       = "█"*bar_len + "░"*(40-bar_len)
    print(f"\n{SEP}")
    print(f"  {score_col}{C.BOLD}Security Score: {r.score}/100{C.RESET}  [{bar}]")
    grade = ("A" if r.score>=90 else "B" if r.score>=80 else
             "C" if r.score>=70 else "D" if r.score>=60 else "F")
    print(f"  Grade: {score_col}{C.BOLD}{grade}{C.RESET}")
    print(SEP2)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="header-tester",
        description="HTTP Header Security Tester — CSP · CORS · HSTS · Cookies · Info Disclosure")
    parser.add_argument("url",  help="URL to analyze (e.g. https://example.com)")
    parser.add_argument("--json",  action="store_true", dest="json_out")
    parser.add_argument("-o","--output", help="Save JSON report")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version",   action="version", version=f"header-tester {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    report = scan(args.url)

    if args.json_out:
        out = {
            "url":      report.url,
            "score":    report.score,
            "missing":  report.missing,
            "disclosure":report.disclosure,
            "cors":     report.cors_analysis,
            "cookies":  report.cookie_analysis,
            "findings": [f.__dict__ for f in report.findings],
        }
        print(json.dumps(out, indent=2))
    else:
        print_report(report)

    if args.output:
        out = {"url":report.url,"score":report.score,
               "findings":[f.__dict__ for f in report.findings]}
        Path(args.output).write_text(json.dumps(out, indent=2))
        print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    sys.exit(2 if report.score < 50 else 0)

if __name__ == "__main__":
    main()

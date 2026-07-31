#!/usr/bin/env python3
"""
subdomain_takeover.py — Subdomain Takeover Checker v1.0.0
==========================================================
Detects subdomains vulnerable to takeover: CNAME records pointing to unclaimed services,
orphaned DNS records, and expired cloud services.

⚠  USE ONLY ON DOMAINS YOU OWN OR HAVE WRITTEN AUTHORIZATION TO TEST.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 23/09/2024
Reqs.  : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations
import argparse, json, re, socket, ssl, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.RED}{C.BOLD}
 ███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
 ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
 ███████╗██║   ██║██████╔╝██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
 ╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
 ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
 ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝{C.RESET}
{C.DIM} v{__version__} — Subdomain Takeover Checker | CNAME · DNS · Cloud Services{C.RESET}
{C.YELLOW} ⚠  Authorized use only. Never test domains without explicit written permission.{C.RESET}
"""

SEP  = "━"*72
SEP2 = "═"*72

# ══════════════════════════════════════════════════════════════════════════════
# VULNERABLE SERVICE FINGERPRINTS
# ══════════════════════════════════════════════════════════════════════════════

# Based on: https://github.com/EdOverflow/can-i-take-over-xyz
VULNERABLE_SERVICES: Dict[str, dict] = {
    # GitHub Pages
    "github.io": {
        "name": "GitHub Pages",
        "fingerprints": ["There isn't a GitHub Pages site here",
                          "For root URLs", "404 - File not found"],
        "severity": "HIGH",
        "takeover": "Create a GitHub repository with the correct name and enable Pages.",
        "documentation": "https://docs.github.com/pages",
    },
    # Heroku
    "herokuapp.com": {
        "name": "Heroku",
        "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app"],
        "severity": "HIGH",
        "takeover": "Create a Heroku app with the name matching the subdomain.",
        "documentation": "https://devcenter.heroku.com/articles/custom-domains",
    },
    # AWS S3
    "s3.amazonaws.com": {
        "name": "AWS S3",
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist",
                         "Code: NoSuchBucket"],
        "severity": "CRITICAL",
        "takeover": "Create an S3 bucket with the same name, then configure it as a website.",
        "documentation": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/website-hosting-custom-domain-walkthrough.html",
    },
    "s3-website": {
        "name": "AWS S3 Website",
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "CRITICAL",
        "takeover": "Create an S3 bucket with the matching name.",
        "documentation": "",
    },
    # Azure
    "azurewebsites.net": {
        "name": "Azure App Service",
        "fingerprints": ["404 Web Site not found", "Microsoft Azure",
                          "App Service - Web App not found"],
        "severity": "HIGH",
        "takeover": "Create an Azure App Service with the matching hostname.",
        "documentation": "https://docs.microsoft.com/azure/app-service/app-service-web-tutorial-custom-domain",
    },
    "azureedge.net": {
        "name": "Azure CDN",
        "fingerprints": ["The resource you are looking for has been removed"],
        "severity": "HIGH",
        "takeover": "Create an Azure CDN endpoint with the matching name.",
        "documentation": "",
    },
    "cloudapp.net": {
        "name": "Azure Cloud Service",
        "fingerprints": ["404", "was not found"],
        "severity": "MEDIUM",
        "takeover": "Claim the cloud service in Azure.",
        "documentation": "",
    },
    # Shopify
    "myshopify.com": {
        "name": "Shopify",
        "fingerprints": ["Sorry, this shop is currently unavailable",
                          "Only one step left!", "Sorry, this page is not available."],
        "severity": "HIGH",
        "takeover": "Create a Shopify store and associate the domain.",
        "documentation": "",
    },
    # Tumblr
    "tumblr.com": {
        "name": "Tumblr",
        "fingerprints": ["Whatever you were looking for doesn't currently exist at this address",
                          "There's nothing here."],
        "severity": "HIGH",
        "takeover": "Create a Tumblr blog and point the custom domain to it.",
        "documentation": "",
    },
    # Fastly
    "fastly.net": {
        "name": "Fastly CDN",
        "fingerprints": ["Fastly error: unknown domain", "Please check that this domain has been added"],
        "severity": "MEDIUM",
        "takeover": "Create a Fastly service and add the domain.",
        "documentation": "",
    },
    # Zendesk
    "zendesk.com": {
        "name": "Zendesk",
        "fingerprints": ["Help Center Closed", "Oops, this help center no longer exists"],
        "severity": "HIGH",
        "takeover": "Create a Zendesk account and configure the custom domain.",
        "documentation": "",
    },
    # Ghost
    "ghost.io": {
        "name": "Ghost",
        "fingerprints": ["The thing you were looking for is no longer here"],
        "severity": "MEDIUM",
        "takeover": "Create a Ghost blog and configure the domain.",
        "documentation": "",
    },
    # Cargo Collective
    "cargocollective.com": {
        "name": "Cargo Collective",
        "fingerprints": ["If you're moving domains, you must also update your DNS settings"],
        "severity": "MEDIUM",
        "takeover": "Create a Cargo Collective account.",
        "documentation": "",
    },
    # Netlify
    "netlify.app": {
        "name": "Netlify",
        "fingerprints": ["Not Found - Request ID:", "netlify"],
        "severity": "MEDIUM",
        "takeover": "Create a Netlify site and associate the domain.",
        "documentation": "",
    },
    # Surge.sh
    "surge.sh": {
        "name": "Surge.sh",
        "fingerprints": ["project not found"],
        "severity": "MEDIUM",
        "takeover": "Install the Surge CLI and publish to the domain.",
        "documentation": "",
    },
    # Intercom
    "intercom.io": {
        "name": "Intercom",
        "fingerprints": ["This page is reserved for artistic dogs", "Uh oh. That page doesn"],
        "severity": "MEDIUM",
        "takeover": "Create an Intercom account and associate the domain.",
        "documentation": "",
    },
    # HubSpot
    "hubspot.net": {
        "name": "HubSpot",
        "fingerprints": ["Domain not found", "does not exist in our system"],
        "severity": "MEDIUM",
        "takeover": "Associate the domain with a HubSpot account.",
        "documentation": "",
    },
    # Wordpress.com
    "wordpress.com": {
        "name": "WordPress.com",
        "fingerprints": ["Do you want to register", "doesn't exist"],
        "severity": "MEDIUM",
        "takeover": "Create a WordPress.com blog and associate the domain.",
        "documentation": "",
    },
    # Fly.io
    "fly.dev": {
        "name": "Fly.io",
        "fingerprints": ["404 Not Found", "app not found"],
        "severity": "MEDIUM",
        "takeover": "Create a Fly.io app and associate the domain.",
        "documentation": "",
    },
    # Webflow
    "webflow.io": {
        "name": "Webflow",
        "fingerprints": ["The page you are looking for doesn't exist or has been moved"],
        "severity": "MEDIUM",
        "takeover": "Create a Webflow project and publish it to the domain.",
        "documentation": "",
    },
}

# Common subdomain wordlist for enumeration
COMMON_SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","imap","webmail","remote","vpn",
    "api","dev","staging","test","admin","portal","blog","shop","cdn",
    "static","assets","m","mobile","app","secure","login","dashboard",
    "git","gitlab","jenkins","jira","confluence","monitor","grafana",
    "kibana","docs","support","help","status","beta","alpha","demo",
    "old","backup","legacy","internal","intranet","vpn2","gateway",
    "proxy","auth","sso","oauth","id","accounts","profile","user",
    "images","img","files","upload","downloads","media","video","audio",
    "forum","community","wiki","kb","knowledge","feedback","survey",
    "payment","pay","checkout","store","shop2","ecommerce","cart",
    "api2","api-v2","v2","v3","sandbox","preview","staging2","qa",
    "uat","prod","production","live","web","web2","www2","new","ns1","ns2",
]

@dataclass
class SubdomainResult:
    subdomain:  str
    cname:      Optional[str]
    ip:         Optional[str]
    status:     str        # VULNERABLE / NXDOMAIN / DANGLING / SAFE / TIMEOUT
    service:    Optional[str]
    severity:   str
    description:str
    takeover:   str = ""
    http_status:int = 0
    evidence:   str = ""

@dataclass
class TakeoverReport:
    domain:     str
    timestamp:  str
    subdomains_checked: int
    findings:   List[SubdomainResult]

# ══════════════════════════════════════════════════════════════════════════════
# DNS RESOLVER (stdlib)
# ══════════════════════════════════════════════════════════════════════════════

def resolve_cname(hostname: str) -> Optional[str]:
    """Resolve a CNAME using getaddrinfo and a heuristic fallback."""
    try:
        # The Python standard library does not provide direct CNAME lookup
        # Use socket.getfqdn as a heuristic
        fqdn = socket.getfqdn(hostname)
        if fqdn and fqdn != hostname:
            return fqdn
    except Exception:
        pass
    # Fallback: try the system host command through subprocess
    try:
        import subprocess
        r = subprocess.run(["host", "-t", "CNAME", hostname],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "is an alias for" in line:
                parts = line.split("is an alias for")
                if len(parts) > 1:
                    return parts[1].strip().rstrip(".")
    except Exception:
        pass
    return None


def resolve_ip(hostname: str, timeout: float = 5.0) -> Optional[str]:
    """Resolve a hostname to an IP address."""
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
    except Exception:
        return None


def is_nxdomain(hostname: str) -> bool:
    """Check whether the hostname does not exist (NXDOMAIN)."""
    try:
        socket.gethostbyname(hostname)
        return False
    except socket.gaierror as e:
        # errno -2 = NXDOMAIN, -3 = SERVFAIL
        return True
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════════════════
# HTTP CHECKER
# ══════════════════════════════════════════════════════════════════════════════

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE


def http_get(url: str, timeout: float = 8.0) -> Tuple[int, str]:
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": f"subdomain-takeover-checker/{__version__}",
            "Accept": "text/html,*/*",
        })
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_SSL_CTX))
        with opener.open(req, timeout=timeout) as r:
            body = r.read(4096).decode(errors="replace")
            return r.status, body
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read(2048).decode(errors="replace")
        except Exception: pass
        return e.code, body
    except Exception:
        return 0, ""


def check_http_fingerprints(subdomain: str,
                              service_info: dict) -> Tuple[bool, int, str]:
    """Check whether the service returns vulnerable takeover fingerprints."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        status, body = http_get(url)
        if status == 0:
            continue
        for fingerprint in service_info.get("fingerprints",[]):
            if fingerprint.lower() in body.lower():
                return True, status, fingerprint
    return False, 0, ""

# ══════════════════════════════════════════════════════════════════════════════
# MAIN CHECKER
# ══════════════════════════════════════════════════════════════════════════════

def check_subdomain(subdomain: str, verbose: bool = False) -> SubdomainResult:
    """Check a single subdomain for a takeover vulnerability."""

    # 1. Resolve the IP address
    ip = resolve_ip(subdomain)

    # 2. NXDOMAIN — the subdomain does not exist
    if ip is None:
        if verbose:
            print(f"  {C.DIM}✗ {subdomain} (NXDOMAIN){C.RESET}")
        return SubdomainResult(
            subdomain=subdomain, cname=None, ip=None,
            status="NXDOMAIN", service=None, severity="INFO",
            description="Subdomain does not exist (NXDOMAIN)",
        )

    # 3. Try to obtain the CNAME
    cname = resolve_cname(subdomain)

    # 4. Check whether the CNAME points to a vulnerable service
    if cname:
        for service_domain, service_info in VULNERABLE_SERVICES.items():
            if service_domain in cname.lower():
                # Check HTTP fingerprints
                is_vuln, http_status, fingerprint = check_http_fingerprints(
                    subdomain, service_info)

                if is_vuln:
                    if verbose:
                        print(f"  {C.RED}[VULNERABLE]{C.RESET} {subdomain} "
                              f"→ {cname} ({service_info['name']})")
                    return SubdomainResult(
                        subdomain   = subdomain,
                        cname       = cname,
                        ip          = ip,
                        status      = "VULNERABLE",
                        service     = service_info["name"],
                        severity    = service_info["severity"],
                        description = (f"CNAME points to {service_info['name']} "
                                       f"that is unclaimed — takeover may be possible!"),
                        takeover    = service_info["takeover"],
                        http_status = http_status,
                        evidence    = f"Fingerprint: '{fingerprint}'",
                    )
                else:
                    # The CNAME points to a service but no fingerprint was found — it may be dangling
                    if verbose:
                        print(f"  {C.YELLOW}[CHECK]{C.RESET} {subdomain} "
                              f"→ {cname} ({service_info['name']}) — check manually")
                    return SubdomainResult(
                        subdomain   = subdomain,
                        cname       = cname,
                        ip          = ip,
                        status      = "DANGLING",
                        service     = service_info["name"],
                        severity    = "MEDIUM",
                        description = (f"CNAME points to {service_info['name']} "
                                       f"— check whether the account is active"),
                        takeover    = service_info["takeover"],
                        http_status = http_status,
                    )

    # 5. No vulnerable CNAME — check whether the IP resolves but HTTP does not respond
    # (possible dangling A record)
    http_status, _ = http_get(f"https://{subdomain}")
    if http_status == 0:
        http_status, _ = http_get(f"http://{subdomain}")

    if ip and http_status == 0:
        if verbose:
            print(f"  {C.YELLOW}[DANGLING]{C.RESET} {subdomain} resolves to {ip} "
                  f"but there is no HTTP response")
        return SubdomainResult(
            subdomain   = subdomain,
            cname       = cname,
            ip          = ip,
            status      = "DANGLING",
            service     = None,
            severity    = "LOW",
            description = f"Resolves to {ip} but there is no HTTP response — possible orphaned A record",
            http_status = 0,
        )

    if verbose:
        print(f"  {C.GREEN}✓{C.RESET} {subdomain} → {ip} (safe)")

    return SubdomainResult(
        subdomain=subdomain, cname=cname, ip=ip,
        status="SAFE", service=None, severity="INFO",
        description="Subdomain is active and appears safe",
        http_status=http_status,
    )


def enumerate_subdomains(domain: str, wordlist_path: Optional[str] = None,
                          threads: int = 20, verbose: bool = False) -> List[SubdomainResult]:
    """Enumerate subdomains and check each one."""
    if wordlist_path:
        words = [l.strip() for l in Path(wordlist_path).read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
    else:
        words = COMMON_SUBDOMAINS

    subdomains = [f"{w}.{domain}" for w in words]
    print(f"  {C.DIM}Checking {len(subdomains)} subdomains "
          f"with {threads} threads...{C.RESET}")

    results: List[SubdomainResult] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sd, verbose): sd
                   for sd in subdomains}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1
            if not verbose:
                print(f"  {C.DIM}Progress: {completed}/{len(subdomains)}{C.RESET}",
                      end="\r")

    print(" " * 50, end="\r")
    return results


def check_single_list(subdomains: List[str], threads: int = 10,
                       verbose: bool = False) -> List[SubdomainResult]:
    """Check a list of specific subdomains."""
    results: List[SubdomainResult] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sd, verbose): sd
                   for sd in subdomains}
        for future in as_completed(futures):
            results.append(future.result())
    return results

# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN,"INFO":C.DIM}

def print_results(results: List[SubdomainResult]) -> None:
    vulnerable = [r for r in results if r.status == "VULNERABLE"]
    dangling   = [r for r in results if r.status == "DANGLING"]
    active     = [r for r in results if r.status == "SAFE"]
    nxdomain   = [r for r in results if r.status == "NXDOMAIN"]

    if vulnerable:
        print(f"\n{SEP}")
        print(f"  {C.RED}{C.BOLD}🔴 VULNERABLE — TAKEOVER POSSIBLE ({len(vulnerable)}){C.RESET}")
        print(SEP)
        for r in vulnerable:
            print(f"\n  {C.RED}[CRITICAL/HIGH]{C.RESET} {C.BOLD}{r.subdomain}{C.RESET}")
            print(f"  Service  : {r.service}")
            if r.cname:
                print(f"  CNAME    : {r.cname}")
            print(f"  IP       : {r.ip}")
            print(f"  Evidence : {C.YELLOW}{r.evidence}{C.RESET}")
            print(f"  Takeover : {r.takeover}")

    if dangling:
        print(f"\n{SEP}")
        print(f"  {C.YELLOW}⚠  DANGLING — Check Manually ({len(dangling)}){C.RESET}")
        print(SEP)
        for r in dangling:
            svc = f" [{r.service}]" if r.service else ""
            print(f"  {C.YELLOW}●{C.RESET} {r.subdomain}{svc}")
            if r.cname: print(f"    CNAME → {r.cname}")
            print(f"    {C.DIM}{r.description}{C.RESET}")


def print_summary(results: List[SubdomainResult], domain: str) -> None:
    vuln     = sum(1 for r in results if r.status=="VULNERABLE")
    dangling = sum(1 for r in results if r.status=="DANGLING")
    active   = sum(1 for r in results if r.status=="SAFE")
    nxdomain = sum(1 for r in results if r.status=="NXDOMAIN")

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}SUBDOMAIN TAKEOVER SUMMARY — {domain}{C.RESET}")
    print(SEP)
    print(f"  Total checked     : {len(results)}")
    print(f"  {C.RED}Vulnerable        : {vuln}{C.RESET}")
    print(f"  {C.YELLOW}Dangling          : {dangling}{C.RESET}")
    print(f"  {C.GREEN}Active (safe)     : {active}{C.RESET}")
    print(f"  {C.DIM}NXDOMAIN          : {nxdomain}{C.RESET}")
    print(SEP2)

    if vuln == 0 and dangling == 0:
        print(f"\n  {C.GREEN}✅ No vulnerable subdomains detected.{C.RESET}")


def generate_markdown(report: TakeoverReport) -> str:
    vulnerable = [r for r in report.findings if r.status=="VULNERABLE"]
    dangling   = [r for r in report.findings if r.status=="DANGLING"]
    lines = [
        f"# 🔍 Subdomain Takeover Report — {report.domain}",
        f"**Date:** {report.timestamp[:16]} | **Checked:** {report.subdomains_checked}",
        f"",
        f"## Summary",
        f"| Status | Count |",f"|---|:---:|",
        f"| 🔴 Vulnerable | **{len(vulnerable)}** |",
        f"| 🟡 Dangling | **{len(dangling)}** |",
        f"| ✅ Safe | **{sum(1 for r in report.findings if r.status=='SAFE')}** |",
        f"",
    ]
    if vulnerable:
        lines += [f"## 🔴 Vulnerable — Takeover Possible","",
                  f"| Subdomain | Service | CNAME | Evidence | Takeover |",
                  f"|---|---|---|---|---|"]
        for r in vulnerable:
            lines.append(f"| `{r.subdomain}` | {r.service} | `{r.cname or '-'}` "
                         f"| {r.evidence[:50]} | {r.takeover[:60]} |")
    if dangling:
        lines += [f"","## 🟡 Dangling — Check Manually","",
                  f"| Subdomain | Service | CNAME |",f"|---|---|---|"]
        for r in dangling:
            lines.append(f"| `{r.subdomain}` | {r.service or '-'} | `{r.cname or '-'}` |")
    lines += [f"",f"*Generated by subdomain-takeover v{__version__}*"]
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="subdomain-takeover",
        description="Subdomain Takeover Checker — CNAME · DNS · Cloud Services")
    parser.add_argument("domain",
        help="Root domain to analyze (e.g., example.com)")
    parser.add_argument("--subdomains", nargs="*",
        metavar="SUB",
        help="Specific list of subdomains to check")
    parser.add_argument("--wordlist", "-w",
        help="Subdomain wordlist file")
    parser.add_argument("--threads", "-t", type=int, default=20,
        help="Parallel threads (default: 20)")
    parser.add_argument("-v","--verbose", action="store_true")
    parser.add_argument("--json",         action="store_true", dest="json_out")
    parser.add_argument("-o","--output",  help="Save Markdown report")
    parser.add_argument("--no-banner",    action="store_true")
    parser.add_argument("--list-services",action="store_true",
        help="List services with takeover fingerprints")
    parser.add_argument("--version",      action="version",
        version=f"subdomain-takeover {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    if args.list_services:
        print(f"\n  {C.BOLD}Services with takeover fingerprints ({len(VULNERABLE_SERVICES)}):{C.RESET}\n")
        for domain, info in VULNERABLE_SERVICES.items():
            sev_col = C.RED if info["severity"]=="CRITICAL" else \
                      C.YELLOW if info["severity"]=="HIGH" else C.CYAN
            print(f"  {sev_col}[{info['severity']}]{C.RESET} "
                  f"{info['name']:<25} *.{domain}")
        return

    print(f"  {C.DIM}Domain: {args.domain}{C.RESET}")

    if args.subdomains:
        full_subs = [f"{s}.{args.domain}" if not s.endswith(args.domain)
                     else s for s in args.subdomains]
        results = check_single_list(full_subs, args.threads, args.verbose)
    else:
        results = enumerate_subdomains(
            args.domain,
            wordlist_path = args.wordlist,
            threads       = args.threads,
            verbose       = args.verbose,
        )

    print_results(results)
    print_summary(results, args.domain)

    report = TakeoverReport(
        domain             = args.domain,
        timestamp          = datetime.now().isoformat(),
        subdomains_checked = len(results),
        findings           = results,
    )

    if args.json_out:
        out = {
            "domain":    report.domain,
            "timestamp": report.timestamp,
            "checked":   report.subdomains_checked,
            "vulnerable":[r.__dict__ for r in results if r.status=="VULNERABLE"],
            "dangling":  [r.__dict__ for r in results if r.status=="DANGLING"],
        }
        print(json.dumps(out, indent=2))

    if args.output:
        md = generate_markdown(report)
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    vuln_count = sum(1 for r in results if r.status=="VULNERABLE")
    sys.exit(2 if vuln_count > 0 else 0)


if __name__ == "__main__":
    main()

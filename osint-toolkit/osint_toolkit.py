#!/usr/bin/env python3
"""
osint_toolkit.py — OSINT Toolkit v1.0.0
=========================================
Passive reconnaissance: DNS, WHOIS, subdomains, and IP geolocation.
For use in authorized penetration tests, bug bounty programs, and research.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 11/11/2025
Requirements: Python 3.8+ | Zero external dependencies (uses stdlib socket/urllib)
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

__version__ = "1.0.0"


class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


# ══════════════════════════════════════════════════════════════════════════════
# DNS LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def dns_lookup(domain: str) -> Dict[str, List[str]]:
    """Resolve basic DNS records using socket."""
    results: Dict[str, List[str]] = {}

    # A record
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        results["A"] = list({i[4][0] for i in infos})
    except socket.gaierror:
        results["A"] = []

    # AAAA record
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
        results["AAAA"] = list({i[4][0] for i in infos})
    except socket.gaierror:
        results["AAAA"] = []

    # Reverse DNS para cada A record
    reverses = []
    for ip in results.get("A", []):
        try:
            rev = socket.gethostbyaddr(ip)[0]
            reverses.append(f"{ip} → {rev}")
        except socket.herror:
            reverses.append(f"{ip} → (no PTR)")
    results["PTR"] = reverses

    return results


def check_common_subdomains(domain: str, wordlist: Optional[List[str]] = None) -> List[Dict]:
    """Check common subdomains through DNS resolution."""
    DEFAULT_SUBS = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
        "remote", "vpn", "api", "dev", "staging", "test", "admin",
        "portal", "blog", "shop", "cdn", "static", "assets",
        "m", "mobile", "app", "secure", "login", "dashboard",
        "mx", "ns1", "ns2", "git", "gitlab", "jenkins", "jira",
        "confluence", "monitor", "grafana", "kibana", "docs",
    ]
    subs = wordlist or DEFAULT_SUBS
    found = []

    for sub in subs:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append({"subdomain": fqdn, "ip": ip, "status": "RESOLVED"})
        except socket.gaierror:
            pass

    return found


# ══════════════════════════════════════════════════════════════════════════════
# IP GEOLOCATION (ip-api.com — free, no key required)
# ══════════════════════════════════════════════════════════════════════════════

def ip_info(ip: str) -> dict:
    """Retrieve IP geolocation and ASN information via ip-api.com (free tier)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "osint-toolkit/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"status": "fail", "message": str(e), "query": ip}


# ══════════════════════════════════════════════════════════════════════════════
# SSL CERTIFICATE INFO
# ══════════════════════════════════════════════════════════════════════════════

def ssl_cert_info(domain: str, port: int = 443) -> dict:
    """Extract SSL/TLS certificate information."""
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((domain, port), timeout=10),
            server_hostname=domain,
        )
        cert = conn.getpeercert()
        conn.close()

        subject   = dict(x[0] for x in cert.get("subject", []))
        issuer    = dict(x[0] for x in cert.get("issuer", []))
        sans      = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        not_after = cert.get("notAfter", "")

        # Calculate days until expiration
        days_left = None
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.utcnow()).days
            except ValueError:
                pass

        return {
            "common_name":    subject.get("commonName"),
            "organization":   subject.get("organizationName"),
            "issuer":         issuer.get("organizationName"),
            "issuer_cn":      issuer.get("commonName"),
            "valid_until":    not_after,
            "days_remaining": days_left,
            "sans":           sans,
            "version":        conn.version() if hasattr(conn, "version") else "TLS",
        }
    except ssl.SSLCertVerificationError as e:
        return {"error": f"SSL verification failed: {e}"}
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# PORT SCANNER (basic — TCP connect)
# ══════════════════════════════════════════════════════════════════════════════

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def port_scan(host: str, ports: Optional[List[int]] = None,
              timeout: float = 1.0) -> List[Dict]:
    """Run a TCP connect scan on the specified ports."""
    targets = ports or list(COMMON_PORTS.keys())
    open_ports = []

    for port in targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                # Banner grab
                banner = ""
                try:
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(2)
                    s2.connect((host, port))
                    s2.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s2.recv(256).decode(errors="ignore").split("\n")[0].strip()
                    s2.close()
                except Exception:
                    pass
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "banner":  banner,
                    "state":   "open",
                })
        except Exception:
            pass

    return open_ports


# ══════════════════════════════════════════════════════════════════════════════
# HTTP HEADERS ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

INFO_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-Generator", "X-Drupal-Cache", "X-WordPress",
]


def analyze_http_headers(url: str) -> dict:
    """Analisa headers HTTP — security headers e information disclosure."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "osint-toolkit/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)

        present_security = {h: headers.get(h, "") for h in SECURITY_HEADERS if h in headers}
        missing_security = [h for h in SECURITY_HEADERS if h not in headers]
        info_disclosure  = {h: headers[h] for h in INFO_HEADERS if h in headers}

        return {
            "url":              url,
            "status_code":      resp.status,
            "server":           headers.get("Server", ""),
            "security_headers": present_security,
            "missing_security": missing_security,
            "info_disclosure":  info_disclosure,
            "all_headers":      dict(headers),
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTERS
# ══════════════════════════════════════════════════════════════════════════════

SEP  = "━" * 68
SEP2 = "═" * 68

BANNER = f"""
{C.CYAN}{C.BOLD}
   ██████╗ ███████╗██╗███╗   ██╗████████╗    ████████╗██╗  ██╗
  ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝       ██╔══╝██║ ██╔╝
  ██║   ██║███████╗██║██╔██╗ ██║   ██║           ██║   █████╔╝
  ██║   ██║╚════██║██║██║╚██╗██║   ██║           ██║   ██╔═██╗
  ╚██████╔╝███████║██║██║ ╚████║   ██║           ██║   ██║  ██╗
   ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝           ╚═╝   ╚═╝  ╚═╝{C.RESET}
{C.DIM}  v{__version__} — OSINT Toolkit | DNS · IP · SSL · Headers · Subdomain Enum{C.RESET}
{C.YELLOW}  ⚠ For use exclusively on authorized systems and for ethical research.{C.RESET}
"""


def print_dns(domain: str, records: dict) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}DNS — {domain}{C.RESET}")
    print(SEP)
    for rtype, values in records.items():
        if values:
            print(f"  {C.CYAN}{rtype:<6}{C.RESET} {', '.join(values)}")
        else:
            print(f"  {C.DIM}{rtype:<6} (no records){C.RESET}")


def print_subdomains(found: list) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}Subdomains Found ({len(found)}){C.RESET}")
    print(SEP)
    if not found:
        print(f"  {C.DIM}No common subdomains resolved.{C.RESET}")
        return
    for s in found:
        print(f"  {C.GREEN}✓{C.RESET} {s['subdomain']:<40} {C.DIM}{s['ip']}{C.RESET}")


def print_ip_info(data: dict) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}IP Info — {data.get('query', '?')}{C.RESET}")
    print(SEP)
    if data.get("status") == "fail":
        print(f"  {C.RED}Erro: {data.get('message')}{C.RESET}")
        return
    fields = [
        ("Country",     data.get("country", "") + f" ({data.get('countryCode', '')})"),
        ("Region",      data.get("regionName", "")),
        ("City",        data.get("city", "")),
        ("ISP",         data.get("isp", "")),
        ("Organization", data.get("org", "")),
        ("ASN",         data.get("as", "")),
    ]
    for label, value in fields:
        if value.strip():
            print(f"  {C.DIM}{label:<14}{C.RESET} {value}")


def print_ssl(domain: str, data: dict) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}SSL/TLS Certificate — {domain}{C.RESET}")
    print(SEP)
    if "error" in data:
        print(f"  {C.RED}Erro: {data['error']}{C.RESET}")
        return

    days = data.get("days_remaining")
    day_color = C.GREEN if days and days > 30 else C.RED
    print(f"  {C.DIM}Common Name  {C.RESET} {data.get('common_name', '—')}")
    print(f"  {C.DIM}Organization{C.RESET} {data.get('organization', '—')}")
    print(f"  {C.DIM}Issued by   {C.RESET} {data.get('issuer', '—')}")
    print(f"  {C.DIM}Valid until {C.RESET} {data.get('valid_until', '—')} "
          f"({day_color}{days} days{C.RESET})")
    sans = data.get("sans", [])
    if sans:
        print(f"  {C.DIM}SANs ({len(sans)})  {C.RESET} {', '.join(sans[:8])}"
              + (f" ... +{len(sans)-8}" if len(sans) > 8 else ""))


def print_headers(data: dict) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}HTTP Headers — {data.get('url', '?')}{C.RESET}")
    print(SEP)
    if "error" in data:
        print(f"  {C.RED}Erro: {data['error']}{C.RESET}")
        return

    # Info disclosure
    disc = data.get("info_disclosure", {})
    if disc:
        print(f"  {C.YELLOW}⚠ Information Disclosure:{C.RESET}")
        for h, v in disc.items():
            print(f"    {C.YELLOW}{h}: {v}{C.RESET}")

    # Security headers present
    sec = data.get("security_headers", {})
    if sec:
        print(f"\n  {C.GREEN}✅ Security Headers present:{C.RESET}")
        for h, v in sec.items():
            print(f"    {C.DIM}{h}{C.RESET}")

    # Missing security headers
    missing = data.get("missing_security", [])
    if missing:
        print(f"\n  {C.RED}❌ Missing Security Headers:{C.RESET}")
        for h in missing:
            print(f"    {C.RED}{h}{C.RESET}")


def print_ports(host: str, ports: list) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}Port Scan — {host} ({len(ports)} open){C.RESET}")
    print(SEP)
    if not ports:
        print(f"  {C.DIM}No open ports detected.{C.RESET}")
        return
    for p in ports:
        banner = f"  {C.DIM}{p['banner'][:50]}{C.RESET}" if p["banner"] else ""
        print(f"  {C.GREEN}●{C.RESET} {p['port']:<6} {C.CYAN}{p['service']:<12}{C.RESET}{banner}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="osint-toolkit",
        description="OSINT Toolkit — DNS · IP · SSL · Headers · Subdomains"
    )
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("--dns",        action="store_true", help="DNS lookup")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate common subdomains")
    parser.add_argument("--ip",         action="store_true", help="IP geolocation")
    parser.add_argument("--ssl",        action="store_true", help="SSL certificate information")
    parser.add_argument("--headers",    action="store_true", help="Analyze HTTP headers")
    parser.add_argument("--ports",      action="store_true", help="Port scan (common ports)")
    parser.add_argument("--all",        action="store_true", help="Run all modules")
    parser.add_argument("--json",       action="store_true", dest="json_out")
    parser.add_argument("--no-banner",  action="store_true")
    parser.add_argument("--version",    action="version", version=f"osint-toolkit {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    target  = args.target.strip().lstrip("https://").lstrip("http://").rstrip("/")
    run_all = args.all or not any([args.dns, args.subdomains, args.ip,
                                   args.ssl, args.headers, args.ports])

    report = {"target": target, "timestamp": datetime.now().isoformat()}

    if run_all or args.dns:
        records = dns_lookup(target)
        report["dns"] = records
        if not args.json_out:
            print_dns(target, records)

    if run_all or args.subdomains:
        subs = check_common_subdomains(target)
        report["subdomains"] = subs
        if not args.json_out:
            print_subdomains(subs)

    if run_all or args.ip:
        # Resolve the IP address if the target is a domain
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target
        info = ip_info(ip)
        report["ip_info"] = info
        if not args.json_out:
            print_ip_info(info)

    if run_all or args.ssl:
        ssl_data = ssl_cert_info(target)
        report["ssl"] = ssl_data
        if not args.json_out:
            print_ssl(target, ssl_data)

    if run_all or args.headers:
        hdr_data = analyze_http_headers(target)
        report["headers"] = hdr_data
        if not args.json_out:
            print_headers(hdr_data)

    if run_all or args.ports:
        open_ports = port_scan(target)
        report["ports"] = open_ports
        if not args.json_out:
            print_ports(target, open_ports)

    if args.json_out:
        print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

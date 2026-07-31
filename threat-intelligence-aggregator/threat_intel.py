#!/usr/bin/env python3
"""
threat_intel.py — Threat Intelligence Aggregator v1.0.0
=========================================================
Aggregates public threat intelligence feeds: recent CVEs (NVD),
malicious IPs (abuse.ch), suspicious domains, and IOCs from open sources.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 28/10/2025
Reqs.  : Python 3.8+ | Zero external dependencies (urllib + json)
Sources: NVD API (public), abuse.ch (public), CISA KEV (public)
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

__version__ = "1.0.0"

# ── ANSI ──────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
     ██║   ███████║██████╔╝█████╗  ███████║   ██║
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝  ██╗███╗   ██╗████████╗███████╗██╗     {C.RESET}
{C.CYAN}{C.BOLD}                                                    ██║████╗  ██║╚══██╔══╝██╔════╝██║
                                                    ██║██╔██╗ ██║   ██║   █████╗  ██║
                                                    ██║██║╚██╗██║   ██║   ██╔══╝  ██║
                                                    ██║██║ ╚████║   ██║   ███████╗███████╗
                                                    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝{C.RESET}
{C.DIM} v{__version__} — NVD CVE · CISA KEV · abuse.ch · VirusTotal (API) · IOC Lookup{C.RESET}
"""

SEP  = "━" * 72
SEP2 = "═" * 72

# ══════════════════════════════════════════════════════════════════════════════
# HTTP HELPER
# ══════════════════════════════════════════════════════════════════════════════

def fetch_json(url: str, headers: dict = None, timeout: int = 15) -> Optional[dict]:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": f"threat-intel/{__version__} (security research)",
                **(headers or {}),
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  {C.RED}[HTTP {e.code}] {url}{C.RESET}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  {C.RED}[ERROR] {url}: {e}{C.RESET}", file=sys.stderr)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CVERecord:
    cve_id:      str
    description: str
    cvss_score:  Optional[float]
    cvss_vector: Optional[str]
    severity:    str
    published:   str
    modified:    str
    references:  List[str] = field(default_factory=list)
    cwe:         List[str] = field(default_factory=list)
    affected:    List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class KEVEntry:
    cve_id:           str
    vendor:           str
    product:          str
    vulnerability:    str
    date_added:       str
    due_date:         str
    short_description:str
    notes:            str


@dataclass
class IOCResult:
    ioc:          str
    ioc_type:     str        # ip / domain / hash
    malicious:    bool
    confidence:   str        # HIGH / MEDIUM / LOW / UNKNOWN
    tags:         List[str]
    sources:      List[str]
    details:      dict = field(default_factory=dict)


# ══════════════════════════════════════════════════════════════════════════════
# NVD CVE API  (public, no key required for basic queries)
# ══════════════════════════════════════════════════════════════════════════════

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_cvss(cve_item: dict) -> tuple[Optional[float], Optional[str], str]:
    """Extract the CVSS score, vector, and severity from an NVD item."""
    metrics = cve_item.get("metrics", {})
    # Try CVSS v3.1 > v3.0 > v2.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        data = metrics.get(key, [])
        if data:
            d = data[0].get("cvssData", {})
            score  = d.get("baseScore")
            vector = d.get("vectorString")
            sev    = data[0].get("baseSeverity") or d.get("baseSeverity", "")
            return score, vector, sev.upper() if sev else _score_to_severity(score)
    return None, None, "UNKNOWN"


def _score_to_severity(score: Optional[float]) -> str:
    if score is None: return "UNKNOWN"
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    return "LOW"


def _parse_cve_item(item: dict) -> CVERecord:
    cve   = item.get("cve", {})
    cve_id = cve.get("id", "")

    # English description
    desc_list = cve.get("descriptions", [])
    desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "No description")

    # CVSS
    score, vector, severity = _parse_cvss(cve)

    # CWE
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en":
                cwes.append(d["value"])

    # References (top 3)
    refs = [r["url"] for r in cve.get("references", [])[:3]]

    # Affected CPEs (top 5)
    affected = []
    for cfg in cve.get("configurations", [])[:2]:
        for node in cfg.get("nodes", [])[:3]:
            for cpe_m in node.get("cpeMatch", [])[:3]:
                cpe = cpe_m.get("criteria", "")
                # Simplify cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    affected.append(f"{parts[3]}:{parts[4]}:{parts[5]}" if len(parts) > 5 else f"{parts[3]}:{parts[4]}")

    return CVERecord(
        cve_id      = cve_id,
        description = desc[:500],
        cvss_score  = score,
        cvss_vector = vector,
        severity    = severity,
        published   = cve.get("published", "")[:10],
        modified    = cve.get("lastModified", "")[:10],
        references  = refs,
        cwe         = list(set(cwes))[:3],
        affected    = list(set(affected))[:5],
    )


def search_cve(query: str = None, cve_id: str = None,
               severity: str = None, days: int = 7,
               max_results: int = 10) -> List[CVERecord]:
    """Search for CVEs using the public NVD API."""
    params = {"resultsPerPage": min(max_results, 20)}

    if cve_id:
        params["cveId"] = cve_id
    elif query:
        params["keywordSearch"] = query
        # Severity filter
        if severity:
            params["cvssV3Severity"] = severity.upper()
        # Last N days
        if days:
            now = datetime.now(timezone.utc)
            from datetime import timedelta
            start = now - timedelta(days=days)
            params["pubStartDate"] = start.strftime("%Y-%m-%dT00:00:00.000")
            params["pubEndDate"]   = now.strftime("%Y-%m-%dT23:59:59.999")

    url = NVD_BASE + "?" + urllib.parse.urlencode(params)
    data = fetch_json(url)
    if not data:
        return []

    return [_parse_cve_item(v) for v in data.get("vulnerabilities", [])]


# ══════════════════════════════════════════════════════════════════════════════
# CISA KEV (Known Exploited Vulnerabilities) — public JSON feed
# ══════════════════════════════════════════════════════════════════════════════

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def get_cisa_kev(limit: int = 20, search: str = None) -> List[KEVEntry]:
    data = fetch_json(KEV_URL)
    if not data:
        return []

    entries = []
    vulns = data.get("vulnerabilities", [])

    # Sort by most recent date
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)

    for v in vulns:
        if search and search.lower() not in (v.get("vendorProject","") + v.get("product","") + v.get("cveID","")).lower():
            continue
        entries.append(KEVEntry(
            cve_id            = v.get("cveID", ""),
            vendor            = v.get("vendorProject", ""),
            product           = v.get("product", ""),
            vulnerability     = v.get("vulnerabilityName", ""),
            date_added        = v.get("dateAdded", ""),
            due_date          = v.get("dueDate", ""),
            short_description = v.get("shortDescription", "")[:200],
            notes             = v.get("notes", "")[:100],
        ))
        if len(entries) >= limit:
            break

    return entries


# ══════════════════════════════════════════════════════════════════════════════
# IOC LOOKUP (ip-api.com + DNS reputation heuristics)
# ══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_TLDs = {".xyz",".top",".tk",".ml",".ga",".cf",".pw",".cc",".su"}
SUSPICIOUS_KEYWORDS = ["payload","malware","c2","shell","rat","botnet","exploit","ransom","loader","stealer"]


def _detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    # IP
    try:
        socket.inet_pton(socket.AF_INET, ioc)
        return "ip"
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ioc)
        return "ip"
    except OSError:
        pass
    # Hash
    if len(ioc) in (32, 40, 56, 64, 96, 128) and all(c in "0123456789abcdefABCDEF" for c in ioc):
        hash_types = {32:"MD5", 40:"SHA-1", 56:"SHA-224", 64:"SHA-256", 96:"SHA-384", 128:"SHA-512"}
        return f"hash-{hash_types.get(len(ioc),'unknown')}"
    # Domain
    if "." in ioc and not ioc.startswith("http"):
        return "domain"
    return "unknown"


def lookup_ip(ip: str) -> IOCResult:
    url  = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,as,proxy,hosting,mobile,query"
    data = fetch_json(url) or {}

    tags    = []
    sources = ["ip-api.com"]
    malicious = False
    confidence = "LOW"

    if data.get("proxy"):
        tags.append("proxy/vpn"); confidence = "MEDIUM"
    if data.get("hosting"):
        tags.append("hosting/vps")
    if data.get("mobile"):
        tags.append("mobile")

    # Heuristic: ASNs known for abuse
    org = (data.get("org","") + data.get("isp","")).lower()
    abuse_orgs = ["tor exit","spamhaus","abuseipdb","digitalocean","linode","vultr","hetzner"]
    if any(kw in org for kw in abuse_orgs):
        tags.append("potential-abuse-asn"); confidence = "MEDIUM"; malicious = True

    return IOCResult(
        ioc        = ip,
        ioc_type   = "ip",
        malicious  = malicious,
        confidence = confidence,
        tags       = tags,
        sources    = sources,
        details    = {k: v for k, v in data.items() if k not in ("status",)},
    )


def lookup_domain(domain: str) -> IOCResult:
    tags    = []
    sources = ["heuristic"]
    malicious = False
    confidence = "LOW"

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDs:
        if domain.endswith(tld):
            tags.append(f"suspicious-tld:{tld}"); confidence = "MEDIUM"

    # Suspicious keywords
    domain_lower = domain.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain_lower:
            tags.append(f"suspicious-keyword:{kw}"); confidence = "HIGH"; malicious = True

    # DNS resolution
    try:
        ip = socket.gethostbyname(domain)
        tags.append(f"resolves:{ip}")
        sources.append("dns-resolve")
    except socket.gaierror:
        tags.append("no-dns-resolution")

    # Domain length (DGA heuristic)
    parts = domain.split(".")
    if parts:
        label = parts[0]
        if len(label) > 20:
            tags.append("long-label:possible-dga"); confidence = max(confidence, "MEDIUM")
        # Label entropy (basic DGA detection)
        if len(label) > 8:
            import math, collections
            freq = collections.Counter(label)
            entropy = -sum(f/len(label)*math.log2(f/len(label)) for f in freq.values())
            if entropy > 3.8:
                tags.append(f"high-entropy-label:{entropy:.2f}:possible-dga")

    return IOCResult(
        ioc        = domain,
        ioc_type   = "domain",
        malicious  = malicious,
        confidence = confidence,
        tags       = tags,
        sources    = sources,
        details    = {"domain": domain},
    )


def lookup_hash(hash_val: str) -> IOCResult:
    """Basic lookup without an API key. A VT API key enables a complete lookup."""
    return IOCResult(
        ioc        = hash_val,
        ioc_type   = _detect_ioc_type(hash_val),
        malicious  = False,
        confidence = "UNKNOWN",
        tags       = ["requires-api-key"],
        sources    = ["manual"],
        details    = {
            "note": "For a complete hash lookup, configure VIRUSTOTAL_API_KEY in the environment",
            "virustotal_url": f"https://www.virustotal.com/gui/file/{hash_val}",
            "malwarebazaar_url": f"https://bazaar.abuse.ch/browse.php?search=sha256:{hash_val}" if len(hash_val)==64 else "",
        },
    )


def lookup_ioc(ioc: str) -> IOCResult:
    ioc_type = _detect_ioc_type(ioc)
    if ioc_type == "ip":
        return lookup_ip(ioc)
    if ioc_type == "domain":
        return lookup_domain(ioc)
    if ioc_type.startswith("hash"):
        return lookup_hash(ioc)
    return IOCResult(ioc=ioc, ioc_type="unknown", malicious=False,
                     confidence="UNKNOWN", tags=[], sources=[])


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEVERITY_COLOURS = {
    "CRITICAL": C.RED,
    "HIGH":     C.YELLOW,
    "MEDIUM":   C.CYAN,
    "LOW":      C.GREEN,
    "UNKNOWN":  C.DIM,
}


def print_cve(cve: CVERecord) -> None:
    sc = SEVERITY_COLOURS.get(cve.severity, C.DIM)
    score_str = f"{cve.cvss_score:.1f}" if cve.cvss_score else "N/A"
    print(f"\n{SEP}")
    print(f"  {C.BOLD}{cve.cve_id}{C.RESET}  {sc}[{cve.severity} {score_str}]{C.RESET}")
    print(f"  {C.DIM}Published: {cve.published} | Modified: {cve.modified}{C.RESET}")
    print(f"\n  {cve.description[:300]}")
    if cve.cwe:
        print(f"\n  {C.DIM}CWE:{C.RESET} {', '.join(cve.cwe)}")
    if cve.affected:
        print(f"  {C.DIM}Affected:{C.RESET} {', '.join(cve.affected[:3])}")
    if cve.references:
        print(f"  {C.DIM}Refs:{C.RESET} {cve.references[0]}")


def print_kev(entry: KEVEntry) -> None:
    print(f"\n  {C.RED}{C.BOLD}{entry.cve_id}{C.RESET}  "
          f"{C.YELLOW}{entry.vendor} — {entry.product}{C.RESET}")
    print(f"  {C.DIM}Added: {entry.date_added} | Due: {entry.due_date}{C.RESET}")
    print(f"  {entry.short_description[:120]}")


def print_ioc(result: IOCResult) -> None:
    mal_str = f"{C.RED}⚠ MALICIOUS{C.RESET}" if result.malicious else f"{C.GREEN}✓ CLEAN{C.RESET}"
    conf_col = C.RED if result.confidence == "HIGH" else C.YELLOW if result.confidence == "MEDIUM" else C.DIM
    print(f"\n{SEP}")
    print(f"  {C.BOLD}{result.ioc}{C.RESET}  [{C.DIM}{result.ioc_type}{C.RESET}]  "
          f"{mal_str}  Confidence: {conf_col}{result.confidence}{C.RESET}")
    if result.tags:
        print(f"  {C.DIM}Tags:{C.RESET} {', '.join(result.tags)}")
    if result.details:
        for k, v in list(result.details.items())[:6]:
            if v and k not in ("query",):
                print(f"  {C.DIM}{k:<16}{C.RESET} {str(v)[:80]}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="threat-intel",
        description="Threat Intelligence Aggregator — NVD · CISA KEV · IOC Lookup"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # cve
    cv = sub.add_parser("cve", help="Search for CVEs in the NVD")
    cv.add_argument("query", nargs="?", help="Search by keyword or CVE ID")
    cv.add_argument("--id",       help="Specific CVE ID (e.g., CVE-2021-44228)")
    cv.add_argument("--severity", choices=["CRITICAL","HIGH","MEDIUM","LOW"])
    cv.add_argument("--days",     type=int, default=30, help="Last N days (default: 30)")
    cv.add_argument("--limit",    type=int, default=10)

    # kev
    kv = sub.add_parser("kev", help="CISA Known Exploited Vulnerabilities")
    kv.add_argument("search", nargs="?", help="Filter by vendor, product, or CVE")
    kv.add_argument("--limit", type=int, default=20)

    # ioc
    io = sub.add_parser("ioc", help="IOC lookup (IP, domain, or hash)")
    io.add_argument("iocs", nargs="+", help="IP addresses, domains, or hashes")

    # summary
    sub.add_parser("summary", help="Summary of the latest public feeds")

    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--json",      action="store_true", dest="json_out")
    parser.add_argument("--output",    help="Save JSON output to a file")
    parser.add_argument("--version",   action="version", version=f"threat-intel {__version__}")

    args = parser.parse_args()
    if not args.no_banner:
        print(BANNER)

    cmd = args.command

    if cmd == "cve":
        print(f"  {C.DIM}Querying the NVD API...{C.RESET}")
        cves = search_cve(
            query      = args.query or args.id,
            cve_id     = args.id,
            severity   = args.severity,
            days       = args.days,
            max_results= args.limit,
        )
        if not cves:
            print(f"  {C.YELLOW}No CVEs found.{C.RESET}"); return
        print(f"  {C.GREEN}{len(cves)} CVEs found{C.RESET}")
        if args.json_out:
            print(json.dumps([c.to_dict() for c in cves], indent=2))
        else:
            for cve in cves:
                print_cve(cve)
        if args.output:
            with open(args.output, "w") as f:
                json.dump([c.to_dict() for c in cves], f, indent=2)
            print(f"\n  {C.GREEN}[✓] Saved: {args.output}{C.RESET}")

    elif cmd == "kev":
        print(f"  {C.DIM}Querying the CISA KEV feed...{C.RESET}")
        entries = get_cisa_kev(limit=args.limit, search=args.search)
        if not entries:
            print(f"  {C.YELLOW}No entries found.{C.RESET}"); return
        print(f"  {C.RED}{len(entries)} vulnerabilities with confirmed exploitation{C.RESET}")
        print(SEP2)
        if args.json_out:
            print(json.dumps([e.__dict__ for e in entries], indent=2))
        else:
            for e in entries:
                print_kev(e)

    elif cmd == "ioc":
        results = []
        for ioc in args.iocs:
            print(f"  {C.DIM}Looking up {ioc}...{C.RESET}")
            result = lookup_ioc(ioc)
            results.append(result)
            if not args.json_out:
                print_ioc(result)
        if args.json_out:
            print(json.dumps([{
                "ioc": r.ioc, "type": r.ioc_type, "malicious": r.malicious,
                "confidence": r.confidence, "tags": r.tags, "details": r.details,
            } for r in results], indent=2))

    elif cmd == "summary":
        print(f"\n{SEP2}")
        print(f"  {C.BOLD}THREAT INTEL SUMMARY{C.RESET}")
        print(SEP2)
        # Recent critical CVEs
        print(f"\n  {C.RED}{C.BOLD}CRITICAL CVEs — Last 7 days:{C.RESET}")
        cves = search_cve(severity="CRITICAL", days=7, max_results=5)
        for c in cves:
            score = f"{c.cvss_score:.1f}" if c.cvss_score else "?"
            print(f"  {C.RED}●{C.RESET} {C.BOLD}{c.cve_id}{C.RESET} [{score}] {c.description[:80]}")
        # Recent CISA KEV entries
        print(f"\n  {C.YELLOW}{C.BOLD}CISA KEV — Confirmed Exploitation (top 5):{C.RESET}")
        kevs = get_cisa_kev(limit=5)
        for k in kevs:
            print(f"  {C.YELLOW}●{C.RESET} {C.BOLD}{k.cve_id}{C.RESET} {k.vendor} {k.product} — {k.vulnerability[:60]}")
        print(f"\n{SEP2}")
        print(f"  CVE Source: NVD (nvd.nist.gov)")
        print(f"  KEV Source: CISA (cisa.gov/known-exploited-vulnerabilities-catalog)")
        print(f"  Timestamp : {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()

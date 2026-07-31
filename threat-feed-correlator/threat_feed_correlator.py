#!/usr/bin/env python3
"""
threat_feed_correlator.py — Threat Feed Correlator v1.0.0
==========================================================
Aggregates and correlates IOCs from multiple public threat intelligence feeds.
Sources: abuse.ch, CISA KEV, Feodo Tracker, URLhaus, AlienVault OTX (public).

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 01/02/2026
Reqs.  : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations
import argparse, csv, io, json, re, socket, sys, time, urllib.request, urllib.error
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗    ███████╗███████╗███████╗██████╗
 ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔════╝██╔══██╗
    ██║   ███████║██████╔╝█████╗  ███████║   ██║       █████╗  █████╗  █████╗  ██║  ██║
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ██╔══╝  ██╔══╝  ██╔══╝  ██║  ██║
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║       ██║     ███████╗███████╗██████╔╝
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝     ╚══════╝╚══════╝╚═════╝{C.RESET}
{C.DIM} v{__version__} — Threat Feed Correlator | abuse.ch · CISA KEV · URLhaus · Feodo · OTX{C.RESET}
"""

SEP  = "━"*72
SEP2 = "═"*72

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class IOC:
    value:      str
    ioc_type:   str    # ip / domain / url / hash / email
    confidence: int    # 0-100
    severity:   str    # critical / high / medium / low
    tags:       List[str] = field(default_factory=list)
    sources:    List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen:  str = ""
    malware:    str = ""
    description:str = ""

    def add_source(self, source: str, tags: List[str] = None) -> None:
        if source not in self.sources:
            self.sources.append(source)
        if tags:
            for t in tags:
                if t not in self.tags:
                    self.tags.append(t)
        # More sources = higher confidence
        self.confidence = min(95, self.confidence + 15)

@dataclass
class FeedResult:
    feed_name:  str
    ioc_count:  int
    status:     str   # ok / error / timeout
    elapsed_ms: float
    error:      str = ""

@dataclass
class CorrelationReport:
    timestamp:    str
    feeds_loaded: List[FeedResult]
    iocs:         List[IOC]
    correlations: List[dict]  # IOCs seen in multiple feeds
    stats:        dict

    def to_dict(self) -> dict:
        return {
            "timestamp":    self.timestamp,
            "feeds":        [f.__dict__ for f in self.feeds_loaded],
            "total_iocs":   len(self.iocs),
            "correlations": len(self.correlations),
            "stats":        self.stats,
            "top_iocs":     [i.__dict__ for i in self.iocs
                             if len(i.sources) > 1][:20],
        }

# ══════════════════════════════════════════════════════════════════════════════
# HTTP HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _fetch(url: str, timeout: int = 15) -> Tuple[Optional[str], float, str]:
    """Return (content, elapsed_ms, error)."""
    t0 = time.time()
    try:
        req = urllib.request.Request(url,
            headers={"User-Agent": f"threat-feed-correlator/{__version__}",
                     "Accept":     "application/json, text/csv, text/plain"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content  = r.read(10*1024*1024).decode(errors="replace")  # max 10 MB
            elapsed  = (time.time()-t0)*1000
            return content, elapsed, ""
    except urllib.error.HTTPError as e:
        return None, (time.time()-t0)*1000, f"HTTP {e.code}"
    except Exception as e:
        return None, (time.time()-t0)*1000, str(e)[:80]

# ══════════════════════════════════════════════════════════════════════════════
# FEED PARSERS
# ══════════════════════════════════════════════════════════════════════════════

class FeedParser:
    """Base class for feed parsers."""

    def __init__(self, name: str, url: str):
        self.name = name
        self.url  = url

    def fetch_and_parse(self) -> Tuple[List[IOC], FeedResult]:
        content, elapsed, error = _fetch(self.url)
        if not content:
            return [], FeedResult(self.name, 0, "error", elapsed, error)
        try:
            iocs   = self.parse(content)
            result = FeedResult(self.name, len(iocs), "ok", elapsed)
            return iocs, result
        except Exception as e:
            return [], FeedResult(self.name, 0, "error", elapsed, str(e)[:80])

    def parse(self, content: str) -> List[IOC]:
        raise NotImplementedError


class FeodoTrackerParser(FeedParser):
    """abuse.ch Feodo Tracker — botnet C2 IPs (Emotet, Trickbot, etc.)."""

    def __init__(self):
        super().__init__("Feodo Tracker (abuse.ch)",
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")

    def parse(self, content: str) -> List[IOC]:
        iocs = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                iocs.append(IOC(
                    value      = line,
                    ioc_type   = "ip",
                    confidence = 90,
                    severity   = "critical",
                    tags       = ["botnet","c2","feodo"],
                    sources    = [self.name],
                    description= "C2 server listed by Feodo Tracker (Emotet/Trickbot/Dridex)",
                ))
        return iocs


class URLhausParser(FeedParser):
    """abuse.ch URLhaus — malware distribution URLs."""

    def __init__(self):
        super().__init__("URLhaus (abuse.ch)",
            "https://urlhaus.abuse.ch/downloads/csv_recent/")

    def parse(self, content: str) -> List[IOC]:
        iocs = []
        try:
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                if not row or row[0].startswith("#"): continue
                if len(row) < 5: continue
                url_val  = row[2].strip('"') if len(row) > 2 else ""
                status   = row[3].strip('"') if len(row) > 3 else ""
                tags_raw = row[5].strip('"') if len(row) > 5 else ""
                tags     = [t.strip() for t in tags_raw.split(",") if t.strip()]

                if not url_val or not url_val.startswith("http"): continue
                sev = "critical" if status == "online" else "medium"
                iocs.append(IOC(
                    value      = url_val,
                    ioc_type   = "url",
                    confidence = 85 if status == "online" else 60,
                    severity   = sev,
                    tags       = tags + ["malware-distribution"],
                    sources    = [self.name],
                    description= f"Malware distribution URL (status: {status})",
                ))
                if len(iocs) >= 500: break  # limit
        except Exception: pass
        return iocs


class MalwareBazaarParser(FeedParser):
    """abuse.ch MalwareBazaar — malware sample hashes."""

    def __init__(self):
        super().__init__("MalwareBazaar (abuse.ch)",
            "https://bazaar.abuse.ch/export/csv/recent/")

    def parse(self, content: str) -> List[IOC]:
        iocs = []
        try:
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                if not row or row[0].startswith("#"): continue
                if len(row) < 5: continue
                sha256   = row[1].strip('"') if len(row) > 1 else ""
                file_type= row[3].strip('"') if len(row) > 3 else ""
                signature= row[4].strip('"') if len(row) > 4 else ""
                tags_raw = row[6].strip('"') if len(row) > 6 else ""
                tags     = [t.strip() for t in tags_raw.split(",") if t.strip()]

                if not sha256 or len(sha256) != 64: continue
                iocs.append(IOC(
                    value      = sha256,
                    ioc_type   = "hash-sha256",
                    confidence = 95,
                    severity   = "high",
                    tags       = tags + [file_type.lower(), "malware-sample"],
                    sources    = [self.name],
                    malware    = signature,
                    description= f"Malware sample hash: {signature or 'unknown'}",
                ))
                if len(iocs) >= 300: break
        except Exception: pass
        return iocs


class CISAKEVParser(FeedParser):
    """CISA Known Exploited Vulnerabilities — CVEs with confirmed exploitation."""

    def __init__(self):
        super().__init__("CISA KEV",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")

    def parse(self, content: str) -> List[IOC]:
        iocs = []
        try:
            data = json.loads(content)
            for vuln in data.get("vulnerabilities",[]):
                cve_id = vuln.get("cveID","")
                if not cve_id: continue
                vendor  = vuln.get("vendorProject","")
                product = vuln.get("product","")
                vuln_name = vuln.get("vulnerabilityName","")
                date_added = vuln.get("dateAdded","")
                iocs.append(IOC(
                    value      = cve_id,
                    ioc_type   = "cve",
                    confidence = 100,
                    severity   = "critical",
                    tags       = ["exploited-in-wild","cisa-kev",
                                  vendor.lower().replace(" ","-")],
                    sources    = [self.name],
                    first_seen = date_added,
                    description= f"{vuln_name} — {vendor} {product}",
                ))
        except Exception: pass
        return iocs


class BlocklistDEParser(FeedParser):
    """blocklist.de — IPs with reported malicious activity."""

    def __init__(self):
        super().__init__("blocklist.de",
            "https://lists.blocklist.de/lists/all.txt")

    def parse(self, content: str) -> List[IOC]:
        iocs = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                iocs.append(IOC(
                    value      = line,
                    ioc_type   = "ip",
                    confidence = 70,
                    severity   = "medium",
                    tags       = ["reported-malicious","blocklist"],
                    sources    = [self.name],
                    description= "IP with malicious activity reported by honeypots",
                ))
                if len(iocs) >= 200: break
        return iocs

# ══════════════════════════════════════════════════════════════════════════════
# CORRELATOR ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class IOCStore:
    """In-memory IOC database with automatic correlation."""

    def __init__(self):
        self._store: Dict[str, IOC] = {}  # value → IOC

    def add(self, ioc: IOC) -> None:
        key = ioc.value.lower()
        if key in self._store:
            self._store[key].add_source(ioc.sources[0], ioc.tags)
            # Update malware name if it was not already set
            if ioc.malware and not self._store[key].malware:
                self._store[key].malware = ioc.malware
        else:
            self._store[key] = ioc

    def add_all(self, iocs: List[IOC]) -> None:
        for ioc in iocs:
            self.add(ioc)

    @property
    def all_iocs(self) -> List[IOC]:
        return list(self._store.values())

    @property
    def correlated(self) -> List[IOC]:
        """IOCs seen in more than one feed."""
        return [ioc for ioc in self._store.values() if len(ioc.sources) > 1]

    def by_type(self, ioc_type: str) -> List[IOC]:
        return [i for i in self._store.values() if i.ioc_type == ioc_type]

    def by_severity(self, severity: str) -> List[IOC]:
        return [i for i in self._store.values() if i.severity == severity]

    def search(self, query: str) -> List[IOC]:
        q = query.lower()
        return [i for i in self._store.values()
                if q in i.value.lower() or
                   any(q in t.lower() for t in i.tags) or
                   q in i.description.lower()]


def compute_stats(store: IOCStore) -> dict:
    all_iocs = store.all_iocs
    by_type: Dict[str,int]  = defaultdict(int)
    by_sev:  Dict[str,int]  = defaultdict(int)
    by_src:  Dict[str,int]  = defaultdict(int)

    for ioc in all_iocs:
        by_type[ioc.ioc_type] += 1
        by_sev[ioc.severity]  += 1
        for src in ioc.sources:
            by_src[src] += 1

    top_tags: Dict[str,int] = defaultdict(int)
    for ioc in all_iocs:
        for tag in ioc.tags:
            top_tags[tag] += 1

    return {
        "total":        len(all_iocs),
        "correlated":   len(store.correlated),
        "by_type":      dict(sorted(by_type.items(), key=lambda x: -x[1])),
        "by_severity":  dict(sorted(by_sev.items(),
                            key=lambda x: ["critical","high","medium","low"].index(x[0])
                            if x[0] in ["critical","high","medium","low"] else 99)),
        "by_source":    dict(sorted(by_src.items(), key=lambda x: -x[1])),
        "top_tags":     dict(sorted(top_tags.items(), key=lambda x: -x[1])[:15]),
    }

# ══════════════════════════════════════════════════════════════════════════════
# IOC LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

def _detect_type(value: str) -> str:
    value = value.strip()
    if re.match(r"^CVE-\d{4}-\d+$", value, re.I):    return "cve"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value): return "ip"
    if re.match(r"^[a-f0-9]{64}$", value, re.I):      return "hash-sha256"
    if re.match(r"^[a-f0-9]{40}$", value, re.I):      return "hash-sha1"
    if re.match(r"^[a-f0-9]{32}$", value, re.I):      return "hash-md5"
    if value.startswith(("http://","https://")):       return "url"
    if "." in value and not value.startswith("."): return "domain"
    return "unknown"

def lookup_ioc(store: IOCStore, value: str) -> List[IOC]:
    results = store.search(value)
    # Also attempt an exact case-insensitive match
    exact = [i for i in store.all_iocs if i.value.lower() == value.lower()]
    return list({id(i): i for i in exact+results}.values())

# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL = {"critical":C.RED,"high":C.YELLOW,"medium":C.CYAN,"low":C.GREEN}

def print_feed_results(results: List[FeedResult]) -> None:
    print(f"\n  {C.BOLD}Feed Status:{C.RESET}")
    for r in results:
        if r.status == "ok":
            print(f"  {C.GREEN}✓{C.RESET} {r.feed_name:<40} {r.ioc_count:>6} IOCs  ({r.elapsed_ms:.0f}ms)")
        else:
            print(f"  {C.RED}✗{C.RESET} {r.feed_name:<40} {C.RED}{r.error}{C.RESET}")


def print_stats(stats: dict) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}CORRELATION STATISTICS{C.RESET}")
    print(f"  Total IOCs    : {stats['total']:,}")
    print(f"  Correlated    : {C.YELLOW}{stats['correlated']}{C.RESET} (seen in multiple feeds)")

    print(f"\n  {C.BOLD}By Type:{C.RESET}")
    for itype, count in stats["by_type"].items():
        bar = "█" * min(count//10, 30)
        print(f"  {C.CYAN}{itype:<18}{C.RESET} {bar} {count}")

    print(f"\n  {C.BOLD}By Severity:{C.RESET}")
    for sev, count in stats["by_severity"].items():
        col = SEV_COL.get(sev, "")
        print(f"  {col}{sev:<10}{C.RESET} {'█'*min(count//5,30)} {count}")

    if stats["top_tags"]:
        print(f"\n  {C.BOLD}Top Tags:{C.RESET}")
        for tag, count in list(stats["top_tags"].items())[:8]:
            print(f"  {C.DIM}{tag:<25}{C.RESET} {count}")


def print_correlated(store: IOCStore, limit: int = 15) -> None:
    correlated = sorted(store.correlated,
                        key=lambda i: (len(i.sources), i.confidence), reverse=True)
    if not correlated: return
    print(f"\n{SEP}")
    print(f"  {C.BOLD}Top Correlated IOCs (multiple feeds){C.RESET}")
    print(f"  {'IOC':<45} {'Type':<14} {'Sources':<4} {'Conf':>4}")
    print(f"  {'─'*68}")
    for ioc in correlated[:limit]:
        col = SEV_COL.get(ioc.severity,"")
        val_display = ioc.value[:44]
        srcs = f"[{','.join(s[:8] for s in ioc.sources[:2])}...]" if len(ioc.sources)>2 \
               else f"[{','.join(s[:12] for s in ioc.sources)}]"
        print(f"  {col}{val_display:<45}{C.RESET} {ioc.ioc_type:<14} "
              f"{len(ioc.sources):<4} {ioc.confidence:>3}%")


def generate_markdown(report: CorrelationReport) -> str:
    stats = report.stats
    lines = [
        f"# 🔍 Threat Feed Correlation Report",
        f"**Date:** {report.timestamp[:16]} | **Total IOCs:** {stats['total']:,} | "
        f"**Correlated:** {stats['correlated']}",
        f"",
        f"## Loaded Feeds",
        f"",
        f"| Feed | IOCs | Status | Time |",
        f"|---|:---:|:---:|---:|",
    ]
    for f in report.feeds_loaded:
        status_em = "✅" if f.status=="ok" else "❌"
        lines.append(f"| {f.feed_name} | {f.ioc_count:,} | {status_em} | {f.elapsed_ms:.0f}ms |")

    lines += [f"","## Statistics","",
              f"| Type | Count |",f"|---|:---:|"]
    for t, c in stats["by_type"].items():
        lines.append(f"| {t} | {c:,} |")

    if report.correlations:
        lines += [f"","## Top Correlations (multiple feeds)","",
                  f"| IOC | Type | Feeds | Confidence | Tags |",
                  f"|---|---|:---:|:---:|---|"]
        for ioc in report.correlations[:20]:
            tags = ", ".join(ioc.get("tags",[])[:3])
            lines.append(
                f"| `{ioc['value'][:50]}` | {ioc['ioc_type']} "
                f"| {ioc['source_count']} | {ioc['confidence']}% | {tags} |")

    lines += [f"",f"*Generated by threat-feed-correlator v{__version__}*"]
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

AVAILABLE_FEEDS = {
    "feodo":   FeodoTrackerParser,
    "urlhaus": URLhausParser,
    "bazaar":  MalwareBazaarParser,
    "cisa":    CISAKEVParser,
    "blocklist": BlocklistDEParser,
}

def main() -> None:
    parser = argparse.ArgumentParser(prog="threat-feed-correlator",
        description="Threat Feed Correlator — abuse.ch · CISA KEV · blocklist.de")
    parser.add_argument("--feeds", nargs="*",
        choices=list(AVAILABLE_FEEDS.keys()) + ["all"],
        default=["feodo","cisa"],
        help="Feeds to load (default: feodo cisa)")
    parser.add_argument("--lookup", metavar="IOC",
        help="Search for a specific IOC (IP, hash, CVE, URL)")
    parser.add_argument("--type",   choices=["ip","url","hash-sha256","cve","domain"],
        help="Filter output by IOC type")
    parser.add_argument("--severity", choices=["critical","high","medium","low"],
        help="Filter by severity")
    parser.add_argument("--correlated-only", action="store_true",
        help="Show only IOCs seen in multiple feeds")
    parser.add_argument("-o","--output", help="Save Markdown report")
    parser.add_argument("--json",    action="store_true", dest="json_out")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version=f"threat-feed-correlator {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    # Select feeds
    if "all" in (args.feeds or []):
        feed_names = list(AVAILABLE_FEEDS.keys())
    else:
        feed_names = args.feeds or ["feodo","cisa"]

    print(f"  {C.DIM}Loading {len(feed_names)} feed(s): {', '.join(feed_names)}{C.RESET}")

    store        = IOCStore()
    feed_results = []

    for fname in feed_names:
        cls    = AVAILABLE_FEEDS[fname]
        parser_obj = cls()
        print(f"  {C.DIM}→ {parser_obj.name}...{C.RESET}", end="", flush=True)
        iocs, result = parser_obj.fetch_and_parse()
        store.add_all(iocs)
        feed_results.append(result)
        if result.status == "ok":
            print(f" {C.GREEN}{result.ioc_count} IOCs{C.RESET}")
        else:
            print(f" {C.RED}ERROR: {result.error}{C.RESET}")

    # Add demo IOCs if no feeds could be loaded
    if not store.all_iocs:
        print(f"  {C.YELLOW}No feeds loaded — using demonstration data.{C.RESET}")
        demo = [
            IOC("185.220.101.47","ip",90,"critical",["botnet","c2","tor-exit"],["Feodo Tracker"],"2024-01-15","",malware="Emotet"),
            IOC("203.0.113.42","ip",70,"high",["scanner","honeypot"],["blocklist.de"],"2024-01-14"),
            IOC("CVE-2021-44228","cve",100,"critical",["log4shell","rce","exploited-in-wild"],["CISA KEV"],"2021-12-10"),
            IOC("CVE-2017-0144","cve",100,"critical",["eternalblue","smb","exploited-in-wild"],["CISA KEV"],"2017-03-14"),
            IOC("http://malicious-payload.xyz/dropper.exe","url",85,"critical",["malware-distribution","exe"],["URLhaus"],"2024-01-16"),
            IOC("a3b8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9","hash-sha256",95,"high",["ransomware","lockerbit"],["MalwareBazaar"],"2024-01-15",malware="LockBit"),
        ]
        # Demo correlation: 185.220.101.47 appears in two feeds
        demo[0].add_source("blocklist.de",["reported"])
        for d in demo: store.add(d)

    stats = compute_stats(store)

    # Lookup mode
    if args.lookup:
        print(f"\n{SEP}")
        print(f"  {C.BOLD}Lookup: {args.lookup}{C.RESET}")
        results = lookup_ioc(store, args.lookup)
        if results:
            for ioc in results:
                col = SEV_COL.get(ioc.severity,"")
                print(f"\n  {col}[{ioc.severity.upper()}]{C.RESET} {ioc.value}")
                print(f"  Type      : {ioc.ioc_type}")
                print(f"  Confidence: {ioc.confidence}%")
                print(f"  Sources   : {', '.join(ioc.sources)}")
                print(f"  Tags      : {', '.join(ioc.tags)}")
                if ioc.malware: print(f"  Malware   : {ioc.malware}")
                if ioc.description: print(f"  Desc.     : {ioc.description}")
        else:
            print(f"  {C.GREEN}✅ IOC not found in the loaded feeds.{C.RESET}")
        return

    # Normal output
    print_feed_results(feed_results)
    print_stats(stats)
    print_correlated(store)

    # Filters
    display_iocs = store.all_iocs
    if args.type:
        display_iocs = [i for i in display_iocs if i.ioc_type == args.type]
    if args.severity:
        display_iocs = [i for i in display_iocs if i.severity == args.severity]
    if args.correlated_only:
        display_iocs = [i for i in display_iocs if len(i.sources) > 1]

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}SUMMARY{C.RESET}")
    print(f"  Total IOCs     : {stats['total']:,}")
    print(f"  Correlated     : {stats['correlated']}")
    print(f"  Active feeds   : {sum(1 for f in feed_results if f.status=='ok')}/{len(feed_results)}")
    print(SEP2)

    if args.json_out:
        correlations = [{"value":i.value,"ioc_type":i.ioc_type,
                         "severity":i.severity,"confidence":i.confidence,
                         "tags":i.tags,"sources":i.sources,
                         "source_count":len(i.sources),
                         "malware":i.malware} for i in store.correlated]
        report = CorrelationReport(
            datetime.now().isoformat(), feed_results,
            store.all_iocs, correlations, stats)
        print(json.dumps(report.to_dict(), indent=2))

    if args.output:
        correlations = [{"value":i.value,"ioc_type":i.ioc_type,
                         "severity":i.severity,"confidence":i.confidence,
                         "tags":i.tags,"source_count":len(i.sources)} for i in store.correlated]
        report = CorrelationReport(datetime.now().isoformat(),
            feed_results, store.all_iocs, correlations, stats)
        md = generate_markdown(report)
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")


if __name__ == "__main__":
    main()

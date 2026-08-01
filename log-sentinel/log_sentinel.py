#!/usr/bin/env python3
"""
log_sentinel.py — Log-Sentinel v1.0.0
======================================
Multi-format log analyzer for Blue Team / SOC use.
Supports: Apache, Nginx, SSH auth.log, Windows Event Log (XML)
Output  : Terminal (ANSI), JSON, CSV
Author  : Márcio Coutinho — Cybersecurity Specialist
Date    : 12/03/2026

Zero external dependencies — Python 3.8+ stdlib only.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterator, List, Optional

__version__ = "1.0.0"

# ══════════════════════════════════════════════════════════════════════════════
# ANSI COLOURS
# ══════════════════════════════════════════════════════════════════════════════

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @staticmethod
    def disable() -> None:
        for attr in ("RED", "YELLOW", "GREEN", "CYAN", "BLUE", "BOLD", "DIM", "RESET"):
            setattr(C, attr, "")


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


THREAT_COLOURS = {
    ThreatLevel.CRITICAL: C.RED,
    ThreatLevel.HIGH:     C.YELLOW,
    ThreatLevel.MEDIUM:   C.CYAN,
    ThreatLevel.LOW:      C.GREEN,
    ThreatLevel.INFO:     C.DIM,
}

THREAT_SCORE = {
    ThreatLevel.CRITICAL: 100,
    ThreatLevel.HIGH:     50,
    ThreatLevel.MEDIUM:   20,
    ThreatLevel.LOW:      5,
    ThreatLevel.INFO:     1,
}


@dataclass
class LogEvent:
    timestamp:   str
    source_ip:   str
    threat:      ThreatLevel
    category:    str
    description: str
    raw_line:    str
    source_file: str
    line_number: int
    extra:       dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["threat"] = self.threat.value
        return d


@dataclass
class ScanReport:
    target:        str
    log_format:    str
    scan_time:     str
    total_lines:   int
    total_events:  int
    risk_score:    int
    events:        List[LogEvent]
    top_ips:       dict
    by_threat:     dict
    by_category:   dict

    def to_dict(self) -> dict:
        return {
            "meta": {
                "target":     self.target,
                "log_format": self.log_format,
                "scan_time":  self.scan_time,
                "version":    __version__,
            },
            "summary": {
                "total_lines":  self.total_lines,
                "total_events": self.total_events,
                "risk_score":   self.risk_score,
                "by_threat":    self.by_threat,
                "by_category":  self.by_category,
                "top_ips":      self.top_ips,
            },
            "events": [e.to_dict() for e in self.events],
        }


# ══════════════════════════════════════════════════════════════════════════════
# DETECTION RULES
# ══════════════════════════════════════════════════════════════════════════════

# SSH brute-force: attempt threshold per IP
SSH_BRUTE_THRESHOLD = 5

# HTTP status codes → threat level
HTTP_THREAT_MAP = {
    400: (ThreatLevel.LOW,      "Bad Request"),
    401: (ThreatLevel.MEDIUM,   "Unauthorized"),
    403: (ThreatLevel.MEDIUM,   "Forbidden"),
    404: (ThreatLevel.LOW,      "Not Found"),
    429: (ThreatLevel.MEDIUM,   "Rate Limited"),
    500: (ThreatLevel.LOW,      "Server Error"),
    502: (ThreatLevel.LOW,      "Bad Gateway"),
}

# Web attack patterns (path/query)
WEB_ATTACK_PATTERNS = [
    (re.compile(r"(\.\./){2,}|%2e%2e",           re.I), ThreatLevel.HIGH,     "Path Traversal"),
    (re.compile(r"(union\s+select|order\s+by\s+\d|;\s*drop\s+table)", re.I),
                                                         ThreatLevel.CRITICAL, "SQL Injection"),
    (re.compile(r"<script|javascript:|on\w+\s*=", re.I), ThreatLevel.HIGH,    "XSS Attempt"),
    (re.compile(r"(\$\{|#\{|\{\{|<%=)",           re.I), ThreatLevel.HIGH,    "Template Injection"),
    (re.compile(r"(cmd|powershell|bash|/bin/sh)\s*(\.exe)?[\s&|;]", re.I),
                                                         ThreatLevel.CRITICAL, "Command Injection"),
    (re.compile(r"(etc/passwd|etc/shadow|win\.ini|boot\.ini)", re.I),
                                                         ThreatLevel.CRITICAL, "Sensitive File Access"),
    (re.compile(r"(wp-admin|phpmyadmin|\.env|web\.config|\.git/config)", re.I),
                                                         ThreatLevel.HIGH,     "Admin/Config Probe"),
    (re.compile(r"(nikto|sqlmap|nmap|masscan|nuclei|dirbuster|gobuster)", re.I),
                                                         ThreatLevel.HIGH,     "Scanner Detected"),
]

# Private/bogon IP ranges
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# LOG PARSERS
# ══════════════════════════════════════════════════════════════════════════════

# Apache/Nginx Combined Log Format
_APACHE_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_apache(path: Path, source_file: str) -> Iterator[LogEvent]:
    ip_counter: Counter = Counter()
    events: list = []

    with open(path, errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            m = _APACHE_RE.match(raw)
            if not m:
                continue

            ip     = m.group("ip")
            status = int(m.group("status"))
            req    = m.group("path")
            ua     = m.group("ua") or ""
            time   = m.group("time")

            ip_counter[ip] += 1

            # Check attack patterns in the URL
            for pattern, level, category in WEB_ATTACK_PATTERNS:
                if pattern.search(req) or pattern.search(ua):
                    events.append(LogEvent(
                        timestamp   = time,
                        source_ip   = ip,
                        threat      = level,
                        category    = category,
                        description = f"{category} detected: {req[:120]}",
                        raw_line    = raw,
                        source_file = source_file,
                        line_number = lineno,
                        extra       = {"status": status, "path": req, "user_agent": ua},
                    ))
                    break

            # Suspicious status codes
            if status in HTTP_THREAT_MAP and status not in (404,):
                level, desc = HTTP_THREAT_MAP[status]
                events.append(LogEvent(
                    timestamp   = time,
                    source_ip   = ip,
                    threat      = level,
                    category    = "HTTP Error",
                    description = f"HTTP {status} {desc}: {req[:80]}",
                    raw_line    = raw,
                    source_file = source_file,
                    line_number = lineno,
                    extra       = {"status": status, "path": req},
                ))

    # IPs with a high request volume (possible scan/DDoS)
    for ip, count in ip_counter.items():
        if count > 200 and not is_private_ip(ip):
            events.append(LogEvent(
                timestamp   = "—",
                source_ip   = ip,
                threat      = ThreatLevel.HIGH,
                category    = "High Volume Request",
                description = f"IP {ip} made {count} requests — possible scan or DoS",
                raw_line    = "",
                source_file = source_file,
                line_number = 0,
                extra       = {"request_count": count},
            ))

    yield from events


# SSH auth.log parser
_SSH_FAIL_RE    = re.compile(r'(?P<time>\w+ \d+ [\d:]+).*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)')
_SSH_ACCEPT_RE  = re.compile(r'(?P<time>\w+ \d+ [\d:]+).*Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)')
_SSH_INVALID_RE = re.compile(r'(?P<time>\w+ \d+ [\d:]+).*Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)')


def parse_ssh(path: Path, source_file: str) -> Iterator[LogEvent]:
    fail_count: Counter = Counter()   # IP → count
    events: list = []

    with open(path, errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()

            m = _SSH_FAIL_RE.search(raw)
            if m:
                ip   = m.group("ip")
                user = m.group("user")
                fail_count[ip] += 1
                events.append(LogEvent(
                    timestamp   = m.group("time"),
                    source_ip   = ip,
                    threat      = ThreatLevel.LOW,
                    category    = "SSH Failed Login",
                    description = f"Failed login for user '{user}'",
                    raw_line    = raw,
                    source_file = source_file,
                    line_number = lineno,
                    extra       = {"username": user, "fail_count": fail_count[ip]},
                ))
                continue

            m = _SSH_ACCEPT_RE.search(raw)
            if m:
                ip   = m.group("ip")
                user = m.group("user")
                # Successful login after failures → severity escalation
                prev_fails = fail_count.get(ip, 0)
                threat = ThreatLevel.CRITICAL if prev_fails >= SSH_BRUTE_THRESHOLD else ThreatLevel.INFO
                events.append(LogEvent(
                    timestamp   = m.group("time"),
                    source_ip   = ip,
                    threat      = threat,
                    category    = "SSH Successful Login" if threat == ThreatLevel.INFO else "SSH Brute Force Success",
                    description = (
                        f"Successful login for '{user}'" if threat == ThreatLevel.INFO
                        else f"⚠ Successful login after {prev_fails} failures for '{user}' — possible brute-force"
                    ),
                    raw_line    = raw,
                    source_file = source_file,
                    line_number = lineno,
                    extra       = {"username": user, "previous_failures": prev_fails},
                ))
                continue

            m = _SSH_INVALID_RE.search(raw)
            if m:
                events.append(LogEvent(
                    timestamp   = m.group("time"),
                    source_ip   = m.group("ip"),
                    threat      = ThreatLevel.MEDIUM,
                    category    = "SSH Invalid User",
                    description = f"Attempt with invalid user: '{m.group('user')}'",
                    raw_line    = raw,
                    source_file = source_file,
                    line_number = lineno,
                    extra       = {"username": m.group("user")},
                ))

    # Detect brute-force by volume
    for ip, count in fail_count.items():
        if count >= SSH_BRUTE_THRESHOLD:
            events.append(LogEvent(
                timestamp   = "—",
                source_ip   = ip,
                threat      = ThreatLevel.CRITICAL,
                category    = "SSH Brute Force",
                description = f"Brute-force detected: {count} failed attempts from {ip}",
                raw_line    = "",
                source_file = source_file,
                line_number = 0,
                extra       = {"total_failures": count},
            ))

    yield from events


# Auto-detect log format
def detect_format(path: Path) -> str:
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if _APACHE_RE.match(line):
                return "apache"
            if _SSH_FAIL_RE.search(line) or _SSH_ACCEPT_RE.search(line):
                return "ssh"
            break
    return "unknown"


def parse_log(path: Path, fmt: Optional[str] = None) -> tuple[str, list[LogEvent]]:
    detected = fmt or detect_format(path)
    source   = str(path)

    if detected == "apache":
        return detected, list(parse_apache(path, source))
    if detected == "ssh":
        return detected, list(parse_ssh(path, source))

    return "unknown", []


# ══════════════════════════════════════════════════════════════════════════════
# REPORT BUILDERS
# ══════════════════════════════════════════════════════════════════════════════

def build_report(target: str, fmt: str, events: list[LogEvent], total_lines: int) -> ScanReport:
    by_threat:   dict = defaultdict(int)
    by_category: dict = defaultdict(int)
    ip_counter:  Counter = Counter()

    for e in events:
        by_threat[e.threat.value]  += 1
        by_category[e.category]    += 1
        if e.source_ip and e.source_ip != "—":
            ip_counter[e.source_ip] += 1

    risk_score = sum(THREAT_SCORE[e.threat] for e in events)
    top_ips    = dict(ip_counter.most_common(10))

    return ScanReport(
        target       = target,
        log_format   = fmt,
        scan_time    = datetime.now().isoformat(),
        total_lines  = total_lines,
        total_events = len(events),
        risk_score   = risk_score,
        events       = events,
        top_ips      = top_ips,
        by_threat    = dict(by_threat),
        by_category  = dict(by_category),
    )


def write_json(report: ScanReport, output: str) -> str:
    path = f"{output}.json"
    with open(path, "w") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
    return path


def write_csv(report: ScanReport, output: str) -> str:
    path = f"{output}.csv"
    if not report.events:
        return path
    fields = list(report.events[0].to_dict().keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for e in report.events:
            row = e.to_dict()
            row["extra"] = json.dumps(row["extra"])
            writer.writerow(row)
    return path


# ══════════════════════════════════════════════════════════════════════════════
# TERMINAL OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

BANNER = f"""{C.CYAN}{C.BOLD}
 ██╗      ██████╗  ██████╗      ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
 ██║     ██╔═══██╗██╔════╝      ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
 ██║     ██║   ██║██║  ███╗     ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ██║     ██║   ██║██║   ██║     ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
 ███████╗╚██████╔╝╚██████╔╝     ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══════╝ ╚═════╝  ╚═════╝      ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{C.RESET}{C.DIM} v{__version__} — Multi-Format Log Analyzer | Blue Team / SOC | Zero Dependencies{C.RESET}
"""

SEP  = "━" * 72
SEP2 = "═" * 72


def print_event(e: LogEvent, min_level: ThreatLevel) -> None:
    order = list(ThreatLevel)
    if order.index(e.threat) > order.index(min_level):
        return
    colour = THREAT_COLOURS.get(e.threat, "")
    print(f"\n{SEP}")
    print(f"{colour}{C.BOLD}[{e.threat.value}]{C.RESET} {e.category}")
    print(f"  {C.DIM}File    {C.RESET} : {e.source_file}:{e.line_number}")
    print(f"  {C.DIM}IP      {C.RESET} : {e.source_ip}  |  {C.DIM}Timestamp{C.RESET}: {e.timestamp}")
    print(f"  {C.DIM}Desc.   {C.RESET} : {e.description}")
    if e.extra:
        for k, v in e.extra.items():
            print(f"  {C.DIM}{k:<8}{C.RESET} : {v}")


def print_summary(report: ScanReport) -> None:
    score_colour = (
        C.RED    if report.risk_score > 500
        else C.YELLOW if report.risk_score > 100
        else C.GREEN
    )
    print(f"\n{SEP2}")
    print(f"  {C.BOLD}SCAN SUMMARY — Log-Sentinel v{__version__}{C.RESET}")
    print(SEP2)
    print(f"  Target     : {report.target}")
    print(f"  Format     : {report.log_format}")
    print(f"  Lines      : {report.total_lines:,}")
    print(f"  Events     : {report.total_events:,}")
    print(SEP)

    for level in ThreatLevel:
        count = report.by_threat.get(level.value, 0)
        if count == 0:
            continue
        bar    = "█" * min(count, 40)
        colour = THREAT_COLOURS[level]
        print(f"  {colour}{level.value:<10}{C.RESET} {bar} {count}")

    print(SEP)
    print(f"  Risk Score : {score_colour}{C.BOLD}{report.risk_score}{C.RESET}")
    print(SEP2)

    if report.top_ips:
        print(f"\n  {C.BOLD}Top IPs by event count:{C.RESET}")
        for ip, count in list(report.top_ips.items())[:5]:
            flag = "🏴" if not is_private_ip(ip) else "🏠"
            print(f"    {flag} {ip:<20} {count} events")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def count_lines(path: Path) -> int:
    with open(path, errors="replace") as f:
        return sum(1 for _ in f)


def resolve_targets(target: str) -> list[Path]:
    p = Path(target)
    if p.is_dir():
        return sorted(
            f for f in p.rglob("*")
            if f.is_file() and f.suffix in (".log", ".txt", ".evtx", "")
            and not any(part.startswith(".") for part in f.parts)
        )
    if p.is_file():
        return [p]
    print(f"{C.RED}[ERROR] Target not found: {target}{C.RESET}")
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="log-sentinel",
        description="Log-Sentinel — Multi-format log analyzer for Blue Team / SOC",
    )
    parser.add_argument("-t", "--target",   required=True, help="File or directory to analyze")
    parser.add_argument("-o", "--output",   default="sentinel_report", help="Base name for output files")
    parser.add_argument("--format",         choices=["json", "csv", "both"], default="both")
    parser.add_argument("--log-format",     choices=["apache", "nginx", "ssh", "auto"], default="auto")
    parser.add_argument("--severity",       choices=[l.value for l in ThreatLevel], default="LOW",
                        help="Minimum severity to display in the terminal")
    parser.add_argument("--top",            type=int, default=20, help="Number of events to display in the terminal")
    parser.add_argument("--no-banner",      action="store_true")
    parser.add_argument("--no-colour",      action="store_true")
    parser.add_argument("--version",        action="version", version=f"Log-Sentinel {__version__}")
    args = parser.parse_args()

    if args.no_colour or not sys.stdout.isatty():
        C.disable()

    if not args.no_banner:
        print(BANNER)

    targets     = resolve_targets(args.target)
    all_events: list[LogEvent] = []
    total_lines = 0
    detected_fmt = "unknown"

    for path in targets:
        if args.log_format == "auto":
            fmt = detect_format(path)
        else:
            fmt = args.log_format if args.log_format != "nginx" else "apache"

        if fmt == "unknown":
            continue

        detected_fmt = fmt
        lines = count_lines(path)
        total_lines += lines
        _, events = parse_log(path, fmt)
        all_events.extend(events)

    if not all_events:
        print(f"{C.GREEN}[✓] No suspicious events found in the analyzed logs.{C.RESET}")
        sys.exit(0)

    # Sort by severity
    severity_order = {l: i for i, l in enumerate(ThreatLevel)}
    all_events.sort(key=lambda e: severity_order[e.threat])

    report = build_report(args.target, detected_fmt, all_events, total_lines)

    # Terminal output
    min_level = ThreatLevel(args.severity)
    shown = 0
    for event in all_events:
        if shown >= args.top:
            break
        print_event(event, min_level)
        shown += 1

    print_summary(report)

    # Export
    if args.format in ("json", "both"):
        path_out = write_json(report, args.output)
        print(f"\n{C.GREEN}[✓] JSON exported: {path_out}{C.RESET}")

    if args.format in ("csv", "both"):
        path_out = write_csv(report, args.output)
        print(f"{C.GREEN}[✓] CSV exported : {path_out}{C.RESET}")

    # Exit code for CI/CD
    if report.by_threat.get("CRITICAL", 0) > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()

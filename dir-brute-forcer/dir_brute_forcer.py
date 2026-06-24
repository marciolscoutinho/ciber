#!/usr/bin/env python3
"""
dir_brute_forcer.py — Directory & File Brute-Forcer v1.0.0
============================================================
Discovers exposed directories, files, and hidden web application endpoints.
Designed for authorized security testing, internal assessments, and labs.

Authorized use only. Never test systems without explicit written permission.

Author      : Marcio Coutinho — Cybersecurity Specialist
Date        : 28/10/2024
Requirements: Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations

import argparse
import csv
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

__version__ = "1.0.0"


class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


BANNER = f"""
{C.CYAN}{C.BOLD}
 ██████╗ ██╗██████╗     ██████╗ ██████╗ ██╗   ██╗████████╗███████╗
 ██╔══██╗██║██╔══██╗    ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝
 ██║  ██║██║██████╔╝    ██████╔╝██████╔╝██║   ██║   ██║   █████╗
 ██║  ██║██║██╔══██╗    ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝
 ██████╔╝██║██║  ██║    ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗
 ╚═════╝ ╚═╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝{C.RESET}
{C.DIM} v{__version__} — Directory & File Brute-Forcer | Hidden Endpoints · Backup Files · Admin Panels{C.RESET}
{C.YELLOW} ⚠  Authorized use only. Never test systems without explicit written permission.{C.RESET}
"""

SEP = "━" * 72
SEP2 = "═" * 72

# Curated built-in wordlist for authorized discovery. Keep this compact so the
# default run remains gentle; use a custom wordlist for larger assessments.
BUILTIN_WORDLIST = [
    # Admin panels
    "admin", "administrator", "admin.php", "admin/login", "admin/dashboard",
    "wp-admin", "wp-login.php", "cpanel", "phpmyadmin", "adminer.php",
    "webadmin", "manager", "management", "controlpanel", "backend", "console",
    # Common paths
    "login", "signin", "signup", "register", "logout", "auth", "oauth",
    "dashboard", "home", "index", "index.php", "index.html", "default.php",
    "main", "start", "portal",
    # API and documentation
    "api", "api/v1", "api/v2", "api/v3", "swagger", "swagger-ui",
    "swagger.json", "openapi.json", "openapi.yaml", "graphql", "api-docs",
    "docs", "documentation", "redoc",
    # Configuration and sensitive files
    ".env", ".env.local", ".env.production", ".env.backup", "config.php",
    "config.yml", "config.json", "config.xml", "settings.php", "settings.py",
    "database.yml", "database.php", "db.php", "connection.php", "wp-config.php",
    "web.config", "appsettings.json", "application.properties",
    # Backup files
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "database.sql", "dump.sql", "site.zip", "www.zip", "html.zip",
    "backup.bak", "index.php.bak", "config.bak",
    # Git and VCS
    ".git", ".git/config", ".git/HEAD", ".svn/entries", ".hg", ".DS_Store",
    # Logs and info
    "logs", "error.log", "access.log", "debug.log", "app.log",
    "server-status", "server-info", "phpinfo.php", "info.php", "test.php",
    "debug", "status", "health", "healthcheck", "ping", "version",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    ".well-known/security.txt",
    # Upload and file paths
    "upload", "uploads", "files", "media", "images", "img", "static",
    "assets", "public", "private", "data", "downloads", "temp", "tmp", "cache",
    # Source code and dependencies
    "src", "source", "app", "application", "include", "includes", "lib",
    "vendor", "node_modules", "composer.json", "composer.lock", "package.json",
    "yarn.lock", "requirements.txt", "Pipfile", "Gemfile", "pom.xml",
    # Potential attacker leftovers to detect during defensive reviews
    "shell.php", "cmd.php", "webshell.php", "c99.php", "r57.php", "wso.php",
    "eval.php", "exec.php", "system.php",
    # CMS and framework paths
    "wp-content", "wp-includes", "plugins", "themes", "components", "modules",
    "templates", "user", "users", "account", "accounts", "profile", "profiles",
    "artisan", "storage", "bootstrap", "vendor/autoload.php",
    # Development and testing
    "test", "tests", "testing", "dev", "development", "staging", "beta",
    "alpha", "demo", "sample", "example", "todo", "readme", "README.md",
    "CHANGELOG", "LICENSE", "Makefile",
    # Cloud and infrastructure
    "aws", "gcp", "azure", "terraform", "k8s", "kubernetes", "Dockerfile",
    "docker-compose.yml", ".dockerignore",
    # Monitoring
    "actuator", "actuator/health", "actuator/env", "actuator/mappings",
    "metrics", "prometheus", "grafana", "kibana", "elastic", "_cat/indices",
    "_cluster/health",
]

FILE_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".pl", ".bak",
    ".old", ".orig", ".backup", ".tmp", ".temp", ".log", ".sql",
    ".db", ".sqlite", ".xml", ".json", ".yml", ".yaml", ".conf",
    ".config", ".ini", ".env", ".zip", ".tar.gz", ".gz", ".7z",
    ".rar", ".txt", ".md", ".html", ".htm",
]

DEFAULT_STATUS_CODES = [200, 201, 204, 301, 302, 303, 307, 308, 403, 405, 500]
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COL = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN, "LOW": C.GREEN, "INFO": C.DIM}
STATUS_COL = {
    200: C.GREEN, 201: C.GREEN, 204: C.GREEN,
    301: C.CYAN, 302: C.CYAN, 303: C.CYAN, 307: C.CYAN, 308: C.CYAN,
    403: C.YELLOW, 405: C.YELLOW, 500: C.RED,
}


@dataclass
class DirResult:
    url: str
    path: str
    status_code: int
    content_length: int
    content_type: str
    response_time: float
    severity: str
    note: str = ""
    redirect_to: str = ""


@dataclass
class BruteReport:
    target: str
    timestamp: str
    total_requests: int
    found: List[DirResult]
    scan_time: float

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "requests": self.total_requests,
            "scan_time": round(self.scan_time, 3),
            "found": [asdict(item) for item in self.found],
        }


def eprint(message: str = "", *, end: str = "\n") -> None:
    print(message, end=end, file=sys.stderr)


def build_ssl_context(insecure: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_probe(url: str, timeout: float = 8.0, insecure: bool = False) -> Tuple[int, int, str, float, str]:
    """Probe a URL and return status, length, content type, elapsed time, and redirect target."""
    start = time.time()
    redirect_to = ""

    class NoRedirect(urllib.request.HTTPErrorProcessor):
        def http_response(self, req, resp):  # type: ignore[override]
            return resp
        https_response = http_response

    try:
        opener = urllib.request.build_opener(
            NoRedirect,
            urllib.request.HTTPSHandler(context=build_ssl_context(insecure)),
        )
        req = urllib.request.Request(url, headers={
            "User-Agent": f"dir-brute/{__version__} (authorized security test)",
            "Accept": "text/html,application/json,*/*",
        })
        with opener.open(req, timeout=timeout) as response:
            status = response.status
            content_type = response.headers.get("Content-Type", "").split(";")[0].strip()
            raw = response.read(512)
            content_length = int(response.headers.get("Content-Length", len(raw)))
            if status in (301, 302, 303, 307, 308):
                redirect_to = response.headers.get("Location", "")
            return status, content_length, content_type, time.time() - start, redirect_to
    except urllib.error.HTTPError as exc:
        return exc.code, 0, "", time.time() - start, ""
    except Exception:
        return 0, 0, "", time.time() - start, ""


def classify_severity(path: str, status: int, content_type: str = "") -> Tuple[str, str]:
    """Classify a discovered path for defensive triage."""
    path_lower = path.lower().strip("/")

    if any(token in path_lower for token in ["shell", "cmd.php", "c99", "r57", "wso", "b374k"]):
        return "CRITICAL", "Possible web shell or attacker leftover detected"
    if any(token in path_lower for token in [".env", "wp-config", "database.yml", "appsettings", ".git/config"]):
        return "CRITICAL", "Exposed configuration or secrets file"
    if any(token in path_lower for token in [".sql", ".dump", "backup.zip", "dump.sql", "db.sql", "database.sql"]):
        return "HIGH", "Possible exposed database backup"
    if any(token in path_lower for token in [".git", ".svn", ".hg", "composer.json", "package.json", "requirements.txt"]):
        return "HIGH", "Source code, dependency manifest, or VCS exposure"
    if any(token in path_lower for token in ["admin", "phpmyadmin", "adminer", "cpanel", "wp-admin"]):
        return "HIGH", "Exposed administration interface"
    if any(token in path_lower for token in ["phpinfo", "server-status", "debug", "actuator", "graphql", "swagger"]):
        return "MEDIUM", "Exposed diagnostic or documentation endpoint"
    if any(token in path_lower for token in ["upload", "uploads", "files", "backup"]):
        return "MEDIUM", "Exposed file or upload directory"
    if status in (200, 201, 204):
        return "LOW", "Accessible endpoint"
    if status == 403:
        return "LOW", "Resource exists but access is forbidden"
    return "INFO", ""


def normalize_base_url(base_url: str) -> str:
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    parsed = urlparse(base_url)
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if not normalized.endswith("/"):
        normalized += "/"
    return normalized


def probe_path(
    base_url: str,
    path: str,
    not_found_len: int,
    not_found_status: int,
    timeout: float,
    insecure: bool = False,
) -> Optional[DirResult]:
    """Probe one path and decide whether it is worth reporting."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    status, content_len, ctype, elapsed, redirect = http_probe(url, timeout, insecure)

    if status == 0 or status == 404:
        return None
    if status == not_found_status and abs(content_len - not_found_len) < 20:
        return None

    severity, note = classify_severity(path, status, ctype)
    return DirResult(
        url=url,
        path=path,
        status_code=status,
        content_length=content_len,
        content_type=ctype,
        response_time=elapsed,
        severity=severity,
        note=note,
        redirect_to=redirect,
    )


def get_baseline(base_url: str, timeout: float = 8.0, insecure: bool = False) -> Tuple[int, int]:
    """Get status and content length for a random non-existing path."""
    fake_path = f"this_path_does_not_exist_xyz_{int(time.time())}"
    url = urljoin(base_url.rstrip("/") + "/", fake_path)
    status, content_length, _, _, _ = http_probe(url, timeout=timeout, insecure=insecure)
    return status, content_length


def build_wordlist(wordlist_path: Optional[str], extensions: bool = False, quick: bool = False) -> List[str]:
    """Build the path list to test."""
    if wordlist_path:
        words = [
            line.strip()
            for line in Path(wordlist_path).read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    else:
        words = BUILTIN_WORDLIST[:50] if quick else BUILTIN_WORDLIST

    paths = list(words)
    if extensions:
        base_words = [word for word in words if "." not in word.split("/")[-1]]
        for word in base_words[:50]:
            for ext in FILE_EXTENSIONS[:8]:
                paths.append(word + ext)

    seen: Set[str] = set()
    unique: List[str] = []
    for path in paths:
        clean = path.lstrip("/")
        if clean not in seen:
            seen.add(clean)
            unique.append(clean)
    return unique


def run_brute(
    base_url: str,
    wordlist_path: Optional[str] = None,
    extensions: bool = False,
    threads: int = 10,
    timeout: float = 8.0,
    delay: float = 0.05,
    quick: bool = False,
    verbose: bool = False,
    status_filter: Optional[List[int]] = None,
    insecure: bool = False,
    quiet: bool = False,
) -> BruteReport:
    base_url = normalize_base_url(base_url)
    threads = max(1, min(threads, 50))
    delay = max(0.0, delay)
    timeout = max(0.5, timeout)

    if not quiet:
        eprint(f"  {C.DIM}Target  : {base_url}{C.RESET}")
        eprint(f"  {C.DIM}Threads : {threads} | Delay: {delay}s | Timeout: {timeout}s{C.RESET}")
        if insecure:
            eprint(f"  {C.YELLOW}TLS verification is disabled for this run.{C.RESET}")

    if not quiet:
        eprint(f"  {C.DIM}Collecting baseline response...{C.RESET}")
    not_found_status, not_found_len = get_baseline(base_url, timeout, insecure)
    if not quiet:
        eprint(f"  {C.DIM}Baseline: HTTP {not_found_status} | ~{not_found_len} bytes{C.RESET}")

    paths = build_wordlist(wordlist_path, extensions=extensions, quick=quick)
    if not quiet:
        eprint(f"  {C.DIM}Wordlist: {len(paths)} paths to test{C.RESET}\n")

    found: List[DirResult] = []
    completed = 0
    start = time.time()
    accepted_codes = status_filter or DEFAULT_STATUS_CODES

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                probe_path,
                base_url,
                path,
                not_found_len,
                not_found_status,
                timeout,
                insecure,
            ): path
            for path in paths
        }

        for future in as_completed(futures):
            completed += 1
            result = future.result()
            if delay > 0:
                time.sleep(delay / threads)

            if not quiet and verbose:
                pct = completed / len(paths) * 100
                eprint(f"  {C.DIM}[{pct:>5.1f}%] {completed}/{len(paths)} | Found: {len(found)}{C.RESET}", end="\r")

            if result is None or result.status_code not in accepted_codes:
                continue

            found.append(result)
            if not quiet:
                col = (
                    C.RED if result.severity == "CRITICAL"
                    else C.YELLOW if result.severity == "HIGH"
                    else C.CYAN if result.severity == "MEDIUM"
                    else C.GREEN if result.status_code in (200, 201, 204)
                    else C.DIM
                )
                redirect = f" → {result.redirect_to[:50]}" if result.redirect_to else ""
                note = f" {C.YELLOW}← {result.note}{C.RESET}" if result.note else ""
                eprint(
                    f"\n  {col}[{result.status_code}]{C.RESET} /{result.path:<40} "
                    f"{C.DIM}{result.content_length:>8}B{C.RESET}{redirect}{note}"
                )

    scan_time = time.time() - start
    sorted_found = sorted(
        found,
        key=lambda r: (
            SEV_ORDER.index(r.severity) if r.severity in SEV_ORDER else 99,
            r.status_code,
            r.path,
        ),
    )
    return BruteReport(
        target=base_url,
        timestamp=datetime.now().isoformat(),
        total_requests=len(paths),
        found=sorted_found,
        scan_time=scan_time,
    )


def print_summary(report: BruteReport) -> None:
    by_sev: Dict[str, int] = {}
    by_status: Dict[int, int] = {}
    for result in report.found:
        by_sev[result.severity] = by_sev.get(result.severity, 0) + 1
        by_status[result.status_code] = by_status.get(result.status_code, 0) + 1

    rps = report.total_requests / max(report.scan_time, 1)
    print(f"\n{SEP2}")
    print(f"  {C.BOLD}DIR BRUTE-FORCE SUMMARY{C.RESET}")
    print(f"  Target    : {report.target}")
    print(f"  Requests  : {report.total_requests:,}  ({rps:.0f} req/s)")
    print(f"  Scan time : {report.scan_time:.1f}s")
    print(f"  Found     : {len(report.found)}")
    print(SEP)

    if by_sev:
        print(f"\n  {C.BOLD}By Severity:{C.RESET}")
        for sev in SEV_ORDER:
            count = by_sev.get(sev, 0)
            if count:
                col = SEV_COL.get(sev, "")
                print(f"  {col}{sev:<10}{C.RESET} {'█' * min(count, 30)} {count}")

    if by_status:
        print(f"\n  {C.BOLD}By Status Code:{C.RESET}")
        for status, count in sorted(by_status.items()):
            col = STATUS_COL.get(status, C.DIM)
            print(f"  {col}HTTP {status}{C.RESET}  {'█' * min(count, 30)} {count}")

    critical_high = [r for r in report.found if r.severity in ("CRITICAL", "HIGH")]
    if critical_high:
        print(f"\n  {C.RED}{C.BOLD}Critical / High Findings:{C.RESET}")
        for result in critical_high[:10]:
            col = SEV_COL.get(result.severity, "")
            print(f"  {col}●{C.RESET} [{result.status_code}] {result.url}")
            if result.note:
                print(f"    {C.YELLOW}{result.note}{C.RESET}")
    elif not report.found:
        print(f"\n  {C.GREEN}No interesting paths found.{C.RESET}")

    print(SEP2)


def generate_markdown(report: BruteReport) -> str:
    lines = [
        "# Directory Brute-Force Report",
        f"**Target:** {report.target} | **Date:** {report.timestamp[:16]}",
        f"**Requests:** {report.total_requests:,} | **Found:** {len(report.found)} | **Time:** {report.scan_time:.1f}s",
        "",
        "## Results",
        "",
        "| Status | Path | Size | Severity | Note |",
        "|:---:|---|---:|:---:|---|",
    ]
    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
    for result in report.found:
        redirect = f" → {result.redirect_to[:40]}" if result.redirect_to else ""
        lines.append(
            f"| **{result.status_code}** | `{result.path}`{redirect} "
            f"| {result.content_length:,}B | {emoji.get(result.severity, '')} {result.severity} | {result.note} |"
        )
    lines.append("")
    lines.append(f"*Generated by dir-brute-forcer v{__version__}.*")
    return "\n".join(lines)


def write_csv(report: BruteReport, path: str) -> None:
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["status", "path", "url", "size", "content_type", "severity", "note", "redirect_to"],
        )
        writer.writeheader()
        for result in report.found:
            writer.writerow({
                "status": result.status_code,
                "path": result.path,
                "url": result.url,
                "size": result.content_length,
                "content_type": result.content_type,
                "severity": result.severity,
                "note": result.note,
                "redirect_to": result.redirect_to,
            })


def exit_code_for_report(report: BruteReport) -> int:
    if any(result.severity == "CRITICAL" for result in report.found):
        return 2
    if any(result.severity in ("HIGH", "MEDIUM") for result in report.found):
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dir-brute",
        description="Directory & File Brute-Forcer — authorized hidden endpoint discovery",
    )
    parser.add_argument("url", nargs="?", help="Target base URL, for example https://example.com")
    parser.add_argument("--url", dest="url_option", help="Target base URL (alternative to positional URL)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist; default is the built-in list")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Parallel worker threads, max 50; default: 10")
    parser.add_argument("-d", "--delay", type=float, default=0.05, help="Delay between requests in seconds; default: 0.05")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds; default: 8")
    parser.add_argument("-x", "--extensions", action="store_true", help="Append common file extensions to base words")
    parser.add_argument("--quick", action="store_true", help="Use a smaller built-in wordlist for a light scan")
    parser.add_argument("--status", nargs="*", type=int, default=DEFAULT_STATUS_CODES, help="HTTP status codes to report")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification for lab/self-signed targets")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show progress while scanning")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Emit JSON to stdout, or to --output if provided")
    parser.add_argument("--csv", action="store_true", dest="csv_out", help="Write CSV to --output; requires --output")
    parser.add_argument("-o", "--output", help="Output file path: Markdown by default, JSON with --json, CSV with --csv")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version=f"dir-brute {__version__}")
    args = parser.parse_args()

    target = args.url_option or args.url
    if not target:
        parser.error("a target URL is required, either as a positional argument or with --url")
    if args.csv_out and not args.output:
        parser.error("--csv requires --output")

    json_mode = bool(args.json_out)
    quiet = json_mode
    if not args.no_banner and not json_mode:
        print(BANNER)

    report = run_brute(
        base_url=target,
        wordlist_path=args.wordlist,
        extensions=args.extensions,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        quick=args.quick,
        verbose=args.verbose,
        status_filter=args.status,
        insecure=args.insecure,
        quiet=quiet,
    )

    if json_mode:
        payload = json.dumps(report.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
    elif args.csv_out:
        write_csv(report, args.output)
        print_summary(report)
        print(f"\n  {C.GREEN}[✓] CSV report: {args.output}{C.RESET}")
    else:
        print_summary(report)
        if args.output:
            Path(args.output).write_text(generate_markdown(report), encoding="utf-8")
            print(f"\n  {C.GREEN}[✓] Markdown report: {args.output}{C.RESET}")

    sys.exit(exit_code_for_report(report))


if __name__ == "__main__":
    main()

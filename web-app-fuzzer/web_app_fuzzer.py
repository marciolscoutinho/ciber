#!/usr/bin/env python3
"""
web_app_fuzzer.py — Web Application Fuzzer v1.0.0
===================================================
Parameter fuzzing, hidden endpoint discovery, and error disclosure
detection in web applications.

⚠  USE EXCLUSIVELY ON SYSTEMS YOU OWN OR HAVE WRITTEN AUTHORIZATION TO TEST.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 18/07/2025
Req.   : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations
import argparse, json, re, ssl, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.RED}{C.BOLD}
 ██╗    ██╗███████╗██████╗      ███████╗██╗   ██╗███████╗███████╗███████╗██████╗
 ██║    ██║██╔════╝██╔══██╗     ██╔════╝██║   ██║╚══███╔╝╚════██║██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝     █████╗  ██║   ██║  ███╔╝    ██╔╝█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗     ██╔══╝  ██║   ██║ ███╔╝    ██╔╝ ██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝     ██║     ╚██████╔╝███████╗ ██║   ███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝      ╚═╝      ╚═════╝ ╚══════╝ ╚═╝   ╚══════╝╚═╝  ╚═╝{C.RESET}
{C.DIM} v{__version__} — Web App Fuzzer | Parameter Fuzzing · Error Disclosure · Hidden Endpoints{C.RESET}
{C.YELLOW} ⚠  Authorized use only. Never test systems without explicit written permission.{C.RESET}
"""

SEP  = "━"*72
SEP2 = "═"*72

# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD LIBRARIES
# ══════════════════════════════════════════════════════════════════════════════

# Payloads that trigger revealing errors without causing actual damage
ERROR_TRIGGER_PAYLOADS = [
    # SQL Injection (error-based detection)
    "'", '"', "' OR '1'='1", "' OR 1=1--", "1' AND '1'='2",
    "1 AND 1=1", "1; SELECT 1", "' UNION SELECT NULL--",
    "1'", "1\"", "\\", "%%", "%27", "%22",
    # Template injection probes
    "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
    # Path traversal
    "../", "..%2f", "....//", "%2e%2e%2f",
    # XML/XXE
    "<?xml", "<!DOCTYPE", "<![CDATA[",
    # Command injection indicators
    ";ls", "|ls", "`id`", "$(id)",
    # Format strings
    "%s%s%s", "%x%x%x", "%n",
    # Null bytes
    "\x00", "%00",
    # Large input
    "A"*1000,
    # Special chars
    "<script>", "javascript:", "data:text/html",
]

# Payloads specifically for SQLi detection
SQLI_PAYLOADS = [
    ("'", "SQL Error"),
    ("''", "SQL Error"),
    ("1 AND 1=1", "Boolean True"),
    ("1 AND 1=2", "Boolean False"),
    ("1' AND '1'='1", "String True"),
    ("1' AND '1'='2", "String False"),
    ("1 ORDER BY 1--", "Order By"),
    ("1 ORDER BY 100--", "Order By OOB"),
    ("' OR SLEEP(0)--", "Time Based"),
]

# Payloads for SSTI detection
SSTI_PAYLOADS = [
    ("{{7*7}}",    "49",   "Jinja2/Twig"),
    ("${7*7}",     "49",   "Freemarker/Mako"),
    ("#{7*7}",     "49",   "Ruby ERB/Thymeleaf"),
    ("<%= 7*7 %>", "49",   "Ruby ERB"),
    ("{{7*'7'}}",  "7777777","Jinja2"),
    ("${{7*7}}",   "49",   "Jinja2 (escaped)"),
]

# Technology-revealing error signatures
ERROR_SIGNATURES = {
    # Database errors
    "You have an error in your SQL syntax": ("SQLi - MySQL Error", "CRITICAL"),
    "ORA-01756":                             ("SQLi - Oracle Error", "CRITICAL"),
    "Microsoft OLE DB Provider for SQL":     ("SQLi - MSSQL Error", "CRITICAL"),
    "PostgreSQL query failed":               ("SQLi - PostgreSQL Error", "CRITICAL"),
    "SQLite3::SQLException":                 ("SQLi - SQLite Error", "CRITICAL"),
    "Syntax error or access violation":      ("SQLi - Database Error", "CRITICAL"),
    "Unclosed quotation mark":               ("SQLi - MSSQL Error", "CRITICAL"),
    # Template errors
    "TemplateSyntaxError":                   ("SSTI - Jinja2 Error", "HIGH"),
    "UndefinedError":                        ("SSTI - Jinja2 Error", "HIGH"),
    "Traceback (most recent call last)":     ("Python Traceback Exposed", "HIGH"),
    # Framework errors
    "Django Version":                        ("Django Debug Mode", "HIGH"),
    "DJANGO_SETTINGS_MODULE":                ("Django Debug Info", "HIGH"),
    "RuntimeError at ":                      ("Flask Debug Error", "HIGH"),
    "Werkzeug Debugger":                     ("Werkzeug Debug Console!", "CRITICAL"),
    # Stack traces
    "at java.lang":                          ("Java Stack Trace", "MEDIUM"),
    "at org.springframework":               ("Spring Framework Error", "MEDIUM"),
    "System.Exception":                     (".NET Exception", "MEDIUM"),
    "Microsoft.CSharp":                     (".NET/C# Error", "MEDIUM"),
    "NullPointerException":                 ("Java NPE Disclosed", "MEDIUM"),
    "Fatal error:":                         ("PHP Fatal Error", "HIGH"),
    "Warning: ":                            ("PHP Warning Disclosed", "MEDIUM"),
    "Parse error:":                         ("PHP Parse Error", "HIGH"),
    # Path disclosure
    "/var/www/":                            ("Linux Path Disclosure", "MEDIUM"),
    "C:\\inetpub":                          ("Windows Path Disclosure", "MEDIUM"),
    "C:\\xampp":                            ("XAMPP Path Disclosure", "MEDIUM"),
    # Sensitive data patterns
    "root:x:0:0":                           ("passwd File Exposed!", "CRITICAL"),
    "AWS_SECRET_ACCESS_KEY":                ("AWS Credentials Exposed!", "CRITICAL"),
    "BEGIN RSA PRIVATE KEY":                ("Private Key Exposed!", "CRITICAL"),
}

# Common query-string parameters
COMMON_PARAMS = [
    "id", "user", "username", "page", "file", "path", "url", "redirect",
    "search", "query", "q", "name", "email", "token", "key", "action",
    "type", "cat", "category", "item", "product", "order", "sort",
    "filter", "lang", "language", "locale", "format", "output",
    "callback", "jsonp", "debug", "test", "admin", "config",
    "cmd", "exec", "command", "dir", "folder", "include",
    "template", "view", "layout", "theme", "style",
    "return", "returnUrl", "returnTo", "next", "goto",
    "ref", "referrer", "source", "from", "to",
]

@dataclass
class FuzzResult:
    url:         str
    method:      str
    param:       str
    payload:     str
    status_code: int
    response_len:int
    response_time:float
    finding:     Optional[str] = None
    severity:    str           = "INFO"
    evidence:    str           = ""

@dataclass
class FuzzReport:
    target:      str
    timestamp:   str
    total_requests: int
    findings:    List[FuzzResult]
    baseline_status: int
    baseline_len:    int

# ══════════════════════════════════════════════════════════════════════════════
# HTTP ENGINE
# ══════════════════════════════════════════════════════════════════════════════

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE


def http_get(url: str, timeout: float = 8.0) -> Tuple[int, str, float]:
    """Send a GET request. Return (status, body[:4096], elapsed_s)."""
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": f"web-fuzzer/{__version__} (authorized security test)",
            "Accept":     "text/html,application/json,*/*",
        })
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_SSL_CTX))
        with opener.open(req, timeout=timeout) as r:
            body = r.read(8192).decode(errors="replace")
            return r.status, body, time.time()-t0
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read(4096).decode(errors="replace")
        except Exception: pass
        return e.code, body, time.time()-t0
    except Exception:
        return 0, "", time.time()-t0


def inject_param(url: str, param: str, value: str) -> str:
    """Inject value into the URL parameter named param."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_qs = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_qs))


def build_url_with_param(base: str, param: str, value: str) -> str:
    """Add param=value to a URL."""
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{param}={urllib.parse.quote(value, safe='')}"

# ══════════════════════════════════════════════════════════════════════════════
# FUZZ ENGINES
# ══════════════════════════════════════════════════════════════════════════════

def check_error_disclosure(body: str, url: str, param: str,
                             payload: str) -> Optional[FuzzResult]:
    """Check whether the response contains revealing errors."""
    for signature, (finding, severity) in ERROR_SIGNATURES.items():
        if signature.lower() in body.lower():
            # Extract context
            idx     = body.lower().find(signature.lower())
            context = body[max(0,idx-50):idx+100].replace("\n"," ").strip()
            return FuzzResult(
                url=url, method="GET", param=param, payload=payload[:50],
                status_code=0, response_len=len(body), response_time=0,
                finding=finding, severity=severity,
                evidence=context[:150],
            )
    return None


def fuzz_parameter(base_url: str, param: str,
                    baseline_len: int, baseline_status: int,
                    payloads: List[str] = None,
                    verbose: bool = False,
                    delay: float = 0.0) -> List[FuzzResult]:
    """Fuzz a single parameter and return findings."""
    findings: List[FuzzResult] = []
    tests    = payloads or ERROR_TRIGGER_PAYLOADS[:20]

    for payload in tests:
        if delay > 0:
            time.sleep(delay)

        url = inject_param(base_url, param, payload)
        if param not in urlparse(base_url).query:
            url = build_url_with_param(base_url, param, payload)

        status, body, elapsed = http_get(url)
        if status == 0:
            continue

        if verbose:
            print(f"    {C.DIM}{param}={payload[:20]:<20} → {status} "
                  f"{len(body)}B {elapsed:.2f}s{C.RESET}", end="\r")

        # Check for error disclosure
        result = check_error_disclosure(body, url, param, payload)
        if result:
            result.status_code  = status
            result.response_len = len(body)
            result.response_time= elapsed
            result.url          = url
            findings.append(result)
            continue

        # Detect anomalous responses against the baseline
        len_diff = abs(len(body) - baseline_len)
        if status != baseline_status and status in (500, 503):
            findings.append(FuzzResult(
                url=url, method="GET", param=param, payload=payload[:50],
                status_code=status, response_len=len(body), response_time=elapsed,
                finding=f"5xx error after injecting a payload into '{param}'",
                severity="HIGH",
                evidence=f"Status {status} (baseline: {baseline_status})",
            ))

        # A significantly different response may indicate anomalous behavior
        if len_diff > 500 and status == baseline_status:
            # Check for SSTI
            for ssti_payload, expected, engine in SSTI_PAYLOADS:
                if payload == ssti_payload and expected in body:
                    findings.append(FuzzResult(
                        url=url, method="GET", param=param, payload=payload,
                        status_code=status, response_len=len(body), response_time=elapsed,
                        finding=f"SSTI Confirmed ({engine}): {payload} → {expected}",
                        severity="CRITICAL",
                        evidence=f"Payload executed: result {expected} found in the response",
                    ))

    return findings


def discover_params(url: str, verbose: bool = False) -> List[FuzzResult]:
    """Test common parameters against endpoints."""
    findings: List[FuzzResult] = []
    # Baseline
    baseline_status, baseline_body, _ = http_get(url)
    baseline_len = len(baseline_body)

    # Test each parameter with simple payloads
    simple_payloads = ["'", "{{7*7}}", "../", "\x00", "<script>"]

    for param in COMMON_PARAMS:
        for payload in simple_payloads:
            test_url = build_url_with_param(url, param, payload)
            status, body, elapsed = http_get(test_url)
            if status == 0: continue

            result = check_error_disclosure(body, test_url, param, payload)
            if result:
                result.status_code  = status
                result.response_len = len(body)
                result.response_time= elapsed
                findings.append(result)
                if verbose:
                    sev_col = {"CRITICAL":C.RED,"HIGH":C.YELLOW}.get(result.severity,C.CYAN)
                    print(f"\n  {sev_col}[{result.severity}]{C.RESET} "
                          f"param={param} payload={payload[:20]} → {result.finding}")
                break  # One finding per parameter is sufficient for detection

    return findings


def scan_for_errors(url: str, params: List[str] = None,
                     verbose: bool = False, delay: float = 0.1,
                     threads: int = 5) -> FuzzReport:
    """Run a full scan for error disclosure and vulnerabilities."""
    # Baseline
    print(f"  {C.DIM}Obtaining baseline...{C.RESET}")
    baseline_status, baseline_body, _ = http_get(url)
    baseline_len = len(baseline_body)
    print(f"  {C.DIM}Baseline: HTTP {baseline_status} | {baseline_len} bytes{C.RESET}")

    all_findings: List[FuzzResult] = []
    total_requests = 0

    # Extract existing URL parameters
    existing_params = list(parse_qs(urlparse(url).query).keys())
    test_params     = params or existing_params

    if not test_params:
        print(f"  {C.DIM}No parameters in the URL — testing common parameters...{C.RESET}")
        test_params = COMMON_PARAMS[:20]

    print(f"  {C.DIM}Testing {len(test_params)} parameter(s) with "
          f"{len(ERROR_TRIGGER_PAYLOADS)} payloads...{C.RESET}")

    for param in test_params:
        if verbose:
            print(f"\n  {C.DIM}Fuzzing: {param}{C.RESET}")
        results = fuzz_parameter(
            url, param, baseline_len, baseline_status,
            verbose=verbose, delay=delay,
        )
        total_requests += len(ERROR_TRIGGER_PAYLOADS)
        all_findings.extend(results)

        # Display findings immediately
        for r in results:
            sev_col = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN}.get(r.severity,C.DIM)
            print(f"\n  {sev_col}[{r.severity}]{C.RESET} {r.finding}")
            print(f"    Param={r.param} | Payload={r.payload[:40]}")
            if r.evidence:
                print(f"    {C.DIM}Evidence: {r.evidence[:100]}{C.RESET}")

    # Hidden parameter discovery
    if not existing_params:
        print(f"\n  {C.DIM}Discovering hidden parameters...{C.RESET}")
        param_findings = discover_params(url, verbose=verbose)
        total_requests += len(COMMON_PARAMS) * 5
        all_findings.extend(param_findings)
        for r in param_findings:
            sev_col = {"CRITICAL":C.RED,"HIGH":C.YELLOW}.get(r.severity,C.CYAN)
            print(f"\n  {sev_col}[{r.severity}]{C.RESET} Hidden parameter: {r.param}")
            print(f"    {r.finding}")

    # Deduplicate by (param, finding)
    seen   = set()
    unique = []
    for r in all_findings:
        key = (r.param, r.finding or "")
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return FuzzReport(
        target          = url,
        timestamp       = datetime.now().isoformat(),
        total_requests  = total_requests,
        findings        = unique,
        baseline_status = baseline_status,
        baseline_len    = baseline_len,
    )

# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL   = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN}
SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]


def print_summary(report: FuzzReport) -> None:
    by_sev: Dict[str,int] = {}
    for f in report.findings:
        by_sev[f.severity] = by_sev.get(f.severity,0)+1

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}WEB APP FUZZER SUMMARY{C.RESET}")
    print(f"  Target   : {report.target}")
    print(f"  Requests : {report.total_requests:,}")
    print(f"  Findings : {len(report.findings)}")
    print(SEP)
    for sev in SEV_ORDER:
        count = by_sev.get(sev,0)
        if count:
            col = SEV_COL.get(sev,"")
            print(f"  {col}{sev:<10}{C.RESET} {'█'*min(count,20)} {count}")
    print(SEP2)

    if not report.findings:
        print(f"  {C.GREEN}✅ No revealing errors or vulnerabilities detected.{C.RESET}")


def generate_markdown(report: FuzzReport) -> str:
    lines = [
        f"# 🔍 Web App Fuzzer Report",
        f"**Target:** {report.target} | **Date:** {report.timestamp[:16]}",
        f"**Requests:** {report.total_requests:,} | **Findings:** {len(report.findings)}",
        f"",
        f"## Findings",
        f"",
        f"| Severity | Parameter | Finding | Payload |",
        f"|:---:|---|---|---|",
    ]
    em = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}
    for f in sorted(report.findings,
                    key=lambda x: SEV_ORDER.index(x.severity)
                    if x.severity in SEV_ORDER else 99):
        lines.append(f"| {em.get(f.severity,'')} {f.severity} "
                     f"| `{f.param}` | {f.finding} | `{f.payload[:30]}` |")
    lines += [f"",f"*Generated by web-fuzzer v{__version__}*"]
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="web-fuzzer",
        description="Web App Fuzzer — Parameter Fuzzing · Error Disclosure · SSTI Detection")
    parser.add_argument("url",
        help="Target URL (e.g., https://example.com/search?q=test)")
    parser.add_argument("--params", nargs="*",
        help="Parameters to test (default: auto-detect + common)")
    parser.add_argument("--delay",  type=float, default=0.1,
        help="Delay between requests in seconds (default: 0.1)")
    parser.add_argument("--threads",type=int, default=1,
        help="Parallel threads (default: 1 — use caution with rate limiting)")
    parser.add_argument("-v","--verbose", action="store_true")
    parser.add_argument("--json",         action="store_true", dest="json_out")
    parser.add_argument("-o","--output",  help="Save a Markdown report")
    parser.add_argument("--no-banner",    action="store_true")
    parser.add_argument("--version",      action="version", version=f"web-fuzzer {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    print(f"  {C.DIM}Target: {args.url}{C.RESET}")
    print(f"  {C.DIM}Delay:  {args.delay}s | Threads: {args.threads}{C.RESET}\n")

    report = scan_for_errors(
        args.url,
        params  = args.params,
        verbose = args.verbose,
        delay   = args.delay,
        threads = args.threads,
    )

    if args.json_out:
        out = {
            "target":   report.target,
            "timestamp":report.timestamp,
            "requests": report.total_requests,
            "findings": [{
                "severity": f.severity,
                "param":    f.param,
                "payload":  f.payload,
                "finding":  f.finding,
                "status":   f.status_code,
                "evidence": f.evidence,
            } for f in report.findings],
        }
        print(json.dumps(out, indent=2))
    else:
        print_summary(report)

    if args.output:
        md = generate_markdown(report)
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    sys.exit(2 if any(f.severity=="CRITICAL" for f in report.findings) else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
api_security_tester.py — API Security Tester v1.0.1
=====================================================
Tests REST APIs against OWASP API Security Top 10 2023.
Designed for AUTHORIZED security audits of development and staging APIs.

OWASP API Top 10 2023:
API1  — Broken Object Level Authorization
API2  — Broken Authentication
API3  — Broken Object Property Level Authorization
API4  — Unrestricted Resource Consumption
API5  — Broken Function Level Authorization
API6  — Unrestricted Access to Sensitive Business Flows
API7  — Server Side Request Forgery
API8  — Security Misconfiguration
API9  — Improper Inventory Management
API10 — Unsafe Consumption of APIs

Author      : Marcio Coutinho — Cybersecurity Specialist
Date        : 20/11/2023
Requirements: Python 3.8+ | Zero external dependencies
Legal notice: Use only on APIs you own or have explicit written permission to test.
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

__version__ = "1.0.1"


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
   █████╗ ██████╗ ██╗    ████████╗███████╗███████╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██║    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ███████║██████╔╝██║       ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
  ██╔══██║██╔═══╝ ██║       ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║██║     ██║       ██║   ███████╗███████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝     ╚═╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{C.RESET}
{C.DIM} v{__version__} — OWASP API Security Top 10 2023 | Authorized Testing Only{C.RESET}
{C.YELLOW} ⚠  Use ONLY on APIs you own or have explicit written authorization to test.{C.RESET}
"""

SEP = "━" * 72
SEP2 = "═" * 72
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COL = {
    "CRITICAL": C.RED,
    "HIGH": C.YELLOW,
    "MEDIUM": C.CYAN,
    "LOW": C.GREEN,
    "INFO": C.DIM,
}


# ══════════════════════════════════════════════════════════════════════════════
# URL HELPERS
# ══════════════════════════════════════════════════════════════════════════════


def build_url_with_param(url: str, name: str, value: str) -> str:
    """Return *url* with query parameter *name* set to *value*."""
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[name] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def inject_param(url: str, name: str, payload: str) -> str:
    """Inject *payload* into an existing query parameter, adding it if absent."""
    return build_url_with_param(url, name, payload)


# ══════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class HttpResponse:
    status: int
    headers: dict
    body: str
    elapsed: float


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def http_request(
    method: str,
    url: str,
    headers: Optional[dict] = None,
    body: Optional[str] = None,
    timeout: int = 10,
    follow_redirects: bool = True,
    verify_tls: bool = True,
) -> Optional[HttpResponse]:
    """Perform a single HTTP request and return a normalized response object."""
    try:
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        data = body.encode() if body else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "User-Agent": f"api-security-tester/{__version__}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                **(headers or {}),
            },
        )

        handlers = [urllib.request.HTTPSHandler(context=ctx)]
        if not follow_redirects:
            handlers.append(NoRedirectHandler)
        opener = urllib.request.build_opener(*handlers)
        t0 = time.time()
        with opener.open(req, timeout=timeout) as resp:
            elapsed = time.time() - t0
            return HttpResponse(
                status=resp.status,
                headers=dict(resp.headers),
                body=resp.read(65536).decode(errors="replace"),
                elapsed=elapsed,
            )
    except urllib.error.HTTPError as err:
        try:
            body_text = err.read(65536).decode(errors="replace")
        except Exception:
            body_text = ""
        return HttpResponse(status=err.code, headers=dict(err.headers), body=body_text, elapsed=0.0)
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# FINDING MODEL
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class APIFinding:
    api_top10: str
    severity: str
    title: str
    endpoint: str
    method: str
    description: str
    evidence: str
    remediation: str
    request_sent: str = ""
    response_got: str = ""


# ══════════════════════════════════════════════════════════════════════════════
# TEST MODULES — OWASP API TOP 10 2023
# ══════════════════════════════════════════════════════════════════════════════


class APITester:
    def __init__(
        self,
        base_url: str,
        token: str = "",
        verbose: bool = False,
        timeout: int = 10,
        verify_tls: bool = True,
    ):
        self.base = base_url.rstrip("/")
        self.token = token.strip()
        self.verbose = verbose
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.findings: List[APIFinding] = []
        self.requests_made = 0

    def _auth_headers(self) -> dict:
        if not self.token:
            return {}
        if self.token.lower().startswith("bearer "):
            return {"Authorization": self.token}
        return {"Authorization": f"Bearer {self.token}"}

    def _req(
        self,
        method: str,
        path: str,
        headers: Optional[dict] = None,
        body: Optional[str] = None,
    ) -> Optional[HttpResponse]:
        url = urljoin(self.base + "/", path.lstrip("/"))
        merged = {**self._auth_headers(), **(headers or {})}
        self.requests_made += 1
        if self.verbose:
            print(f"  {C.DIM}→ {method} {url}{C.RESET}")
        return http_request(
            method,
            url,
            merged,
            body,
            timeout=self.timeout,
            verify_tls=self.verify_tls,
        )

    def _add(
        self,
        api_id: str,
        severity: str,
        title: str,
        endpoint: str,
        method: str,
        desc: str,
        evidence: str,
        fix: str,
        req_sent: str = "",
        resp: str = "",
    ) -> None:
        self.findings.append(
            APIFinding(
                api_top10=api_id,
                severity=severity,
                title=title,
                endpoint=endpoint,
                method=method,
                description=desc,
                evidence=evidence,
                remediation=fix,
                request_sent=req_sent,
                response_got=resp[:300] if resp else "",
            )
        )
        color = SEV_COL.get(severity, C.DIM)
        print(f"  {color}[{severity}]{C.RESET} {api_id} — {title}")

    # ── API1 — Broken Object Level Authorization ───────────────────────────
    def test_api1_bola(self, endpoints: List[str]) -> None:
        print(f"\n  {C.DIM}[API1] Testing Broken Object Level Authorization...{C.RESET}")
        for path in endpoints:
            for test_id in ["0", "99999", "-1", "admin", "../admin"]:
                test_path = re.sub(r"/\d+", f"/{test_id}", path) if re.search(r"/\d+", path) else path
                if test_path == path and test_id not in path:
                    continue
                resp = self._req("GET", test_path)
                if resp and resp.status == 200:
                    self._add(
                        "API1",
                        "HIGH",
                        "Potential BOLA — object access without ownership validation",
                        test_path,
                        "GET",
                        "The endpoint returned HTTP 200 for an object ID that may not belong to the authenticated user.",
                        f"GET {test_path} → HTTP {resp.status}",
                        "Validate object ownership on every request. Prefer non-sequential identifiers where appropriate.",
                        f"GET {test_path}",
                        resp.body[:200],
                    )
                    break

    # ── API2 — Broken Authentication ───────────────────────────────────────
    def test_api2_auth(self) -> None:
        print(f"\n  {C.DIM}[API2] Testing Authentication...{C.RESET}")

        auth_endpoints = ["/api/v1/users", "/api/users", "/users", "/admin", "/api/admin"]
        for ep in auth_endpoints:
            resp = http_request(
                "GET",
                urljoin(self.base + "/", ep.lstrip("/")),
                {"User-Agent": f"api-security-tester/{__version__}"},
                timeout=self.timeout,
                verify_tls=self.verify_tls,
            )
            if resp and resp.status == 200:
                self._add(
                    "API2",
                    "CRITICAL",
                    "Protected endpoint accessible without a token",
                    ep,
                    "GET",
                    "The endpoint returned data without requiring authentication.",
                    f"GET {ep} without Authorization header → HTTP {resp.status}",
                    "Require authentication on all protected endpoints. Use centralized authentication middleware.",
                    f"GET {ep} (no auth)",
                    resp.body[:200],
                )

        for bad_token in ["invalid", "null", "undefined", "eyJ.bad.token", ""]:
            for ep in ["/api/v1/me", "/api/me", "/me"]:
                resp = http_request(
                    "GET",
                    urljoin(self.base + "/", ep.lstrip("/")),
                    {
                        "Authorization": f"Bearer {bad_token}",
                        "User-Agent": f"api-security-tester/{__version__}",
                    },
                    timeout=self.timeout,
                    verify_tls=self.verify_tls,
                )
                if resp and resp.status == 200:
                    self._add(
                        "API2",
                        "HIGH",
                        "Invalid token accepted by the server",
                        ep,
                        "GET",
                        f"The server accepted the malformed token '{bad_token[:20]}'.",
                        f"Bearer {bad_token} → HTTP {resp.status}",
                        "Validate JWT signatures and token structure on every request. Reject malformed tokens with HTTP 401.",
                        f"GET {ep} Authorization: Bearer {bad_token}",
                        resp.body[:200],
                    )
                    break

    # ── API3 — Broken Object Property Level Authorization ──────────────────
    def test_api3_mass_assignment(self) -> None:
        print(f"\n  {C.DIM}[API3] Testing Mass Assignment...{C.RESET}")

        payloads = [
            '{"role":"admin","isAdmin":true,"userId":1}',
            '{"role":"superuser","permissions":["*"]}',
            '{"balance":99999,"premium":true}',
        ]
        for ep in ["/api/v1/users/me", "/api/users/profile", "/profile"]:
            for payload in payloads:
                resp = self._req("PUT", ep, body=payload)
                if resp and resp.status in (200, 201):
                    response_body = resp.body.lower()
                    if any(keyword in response_body for keyword in ["admin", "role", "permission", "isadmin"]):
                        self._add(
                            "API3",
                            "HIGH",
                            "Potential mass assignment — privileged fields accepted",
                            ep,
                            "PUT",
                            "The server accepted a payload containing privilege-related fields.",
                            f"PUT {ep} body={payload[:80]} → HTTP {resp.status}",
                            "Use DTOs or explicit allowlists for writable fields. Never bind request bodies directly to internal models.",
                            f"PUT {ep} {payload}",
                            resp.body[:200],
                        )
                        break

    # ── API4 — Unrestricted Resource Consumption ───────────────────────────
    def test_api4_resource(self) -> None:
        print(f"\n  {C.DIM}[API4] Testing Resource Consumption...{C.RESET}")

        for ep in ["/api/v1/products", "/api/items", "/products", "/items"]:
            for limit in ["10000", "99999", "-1"]:
                test_path = f"{ep}?limit={limit}&page_size={limit}&per_page={limit}"
                resp = self._req("GET", test_path)
                if resp and resp.status == 200:
                    try:
                        data = json.loads(resp.body)
                        if isinstance(data, list) and len(data) > 100:
                            self._add(
                                "API4",
                                "MEDIUM",
                                "Unbounded pagination parameter accepted",
                                test_path,
                                "GET",
                                f"The endpoint returned {len(data)} records without enforcing a server-side limit.",
                                f"GET {test_path} → {len(data)} items",
                                "Implement a server-side maximum limit and ignore excessive client-provided limits.",
                                f"GET {test_path}",
                                resp.body[:200],
                            )
                            break
                    except Exception:
                        pass

        for ep in ["/api/upload", "/upload", "/api/files"]:
            resp = self._req("OPTIONS", ep)
            if resp and "max-file-size" not in str(resp.headers).lower():
                resp2 = self._req("GET", ep)
                if resp2 and resp2.status != 404:
                    self._add(
                        "API4",
                        "LOW",
                        "Upload endpoint does not disclose a file-size limit",
                        ep,
                        "POST",
                        "The scan could not confirm a server-side upload size limit.",
                        f"OPTIONS {ep} → no Max-File-Size header",
                        "Implement and document server-side upload size limits.",
                        f"OPTIONS {ep}",
                        "",
                    )

    # ── API5 — Broken Function Level Authorization ─────────────────────────
    def test_api5_function_auth(self) -> None:
        print(f"\n  {C.DIM}[API5] Testing Function Level Authorization...{C.RESET}")

        admin_endpoints = [
            ("GET", "/admin"),
            ("GET", "/api/admin"),
            ("GET", "/api/v1/admin"),
            ("DELETE", "/api/v1/users/1"),
            ("POST", "/api/v1/users"),
            ("GET", "/api/internal"),
            ("GET", "/api/debug"),
            ("GET", "/.env"),
            ("GET", "/api/config"),
            ("GET", "/api/v1/stats"),
            ("GET", "/management"),
            ("GET", "/actuator"),
            ("GET", "/actuator/health"),
            ("GET", "/actuator/env"),
        ]
        for method, ep in admin_endpoints:
            resp = self._req(method, ep)
            if resp and resp.status == 200:
                self._add(
                    "API5",
                    "HIGH",
                    f"Administrative endpoint accessible: {ep}",
                    ep,
                    method,
                    "An administrative or internal endpoint returned HTTP 200 with the supplied user context.",
                    f"{method} {ep} → HTTP {resp.status}",
                    "Enforce role-based or attribute-based authorization on every privileged endpoint.",
                    f"{method} {ep}",
                    resp.body[:200],
                )

    # ── API8 — Security Misconfiguration ───────────────────────────────────
    def test_api8_misconfig(self) -> None:
        print(f"\n  {C.DIM}[API8] Testing Security Misconfiguration...{C.RESET}")

        resp = self._req("GET", "/")
        if not resp:
            return

        security_headers: Dict[str, Tuple[str, str]] = {
            "Strict-Transport-Security": ("MEDIUM", "HSTS is not configured"),
            "X-Content-Type-Options": ("LOW", "X-Content-Type-Options is missing"),
            "X-Frame-Options": ("LOW", "X-Frame-Options is missing"),
            "Content-Security-Policy": ("MEDIUM", "Content-Security-Policy is not configured"),
        }
        response_headers = {header.lower() for header in resp.headers}
        for header, (severity, message) in security_headers.items():
            if header.lower() not in response_headers:
                self._add(
                    "API8",
                    severity,
                    message,
                    "/",
                    "GET",
                    f"The security header '{header}' is not present in the response.",
                    f"Response headers: {list(resp.headers.keys())[:8]}",
                    f"Add the '{header}' header to relevant responses.",
                    "GET /",
                    "",
                )

        cors_resp = http_request(
            "GET",
            self.base,
            {
                "Origin": "https://evil.com",
                "User-Agent": f"api-security-tester/{__version__}",
            },
            timeout=self.timeout,
            verify_tls=self.verify_tls,
        )
        if cors_resp:
            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*" or acao == "https://evil.com":
                self._add(
                    "API8",
                    "HIGH",
                    f"Permissive CORS policy: Access-Control-Allow-Origin: {acao}",
                    "/",
                    "GET",
                    "The server allows cross-origin requests from arbitrary or attacker-controlled origins.",
                    f"ACAO: {acao}",
                    "Use a strict allowlist of trusted origins. Avoid '*' on authenticated APIs.",
                    "GET / Origin: https://evil.com",
                    f"ACAO: {acao}",
                )

        error_resp = self._req("GET", "/api/v1/trigger_error_xyzabc")
        if error_resp and error_resp.status >= 500:
            response_body = error_resp.body.lower()
            if any(
                keyword in response_body
                for keyword in ["traceback", "exception", "stack trace", "at line", "error in", "syntax error"]
            ):
                self._add(
                    "API8",
                    "MEDIUM",
                    "Stack trace exposed in 5xx response",
                    "/api/v1/trigger_error_xyzabc",
                    "GET",
                    "The server exposes internal error details to the client.",
                    f"HTTP {error_resp.status}: {error_resp.body[:150]}",
                    "Return generic error messages to clients and log detailed errors server-side.",
                    "GET /api/v1/trigger_error_xyzabc",
                    error_resp.body[:200],
                )

    # ── API9 — Improper Inventory Management ───────────────────────────────
    def test_api9_inventory(self) -> None:
        print(f"\n  {C.DIM}[API9] Testing API Inventory...{C.RESET}")

        old_versions = ["/api/v0/", "/api/v1/", "/api/v2/", "/api/beta/", "/api/test/", "/api/dev/", "/api/old/"]
        active = []
        for version_path in old_versions:
            resp = self._req("GET", version_path)
            if resp and resp.status not in (404, 410):
                active.append((version_path, resp.status))

        if len(active) > 2:
            versions_str = ", ".join(f"{path}→{status}" for path, status in active)
            self._add(
                "API9",
                "MEDIUM",
                f"Multiple active API versions: {versions_str}",
                "/api/v*/",
                "GET",
                "Old API versions appear to remain active and may contain unpatched vulnerabilities.",
                f"Discovered versions: {versions_str}",
                "Deprecate and disable old API versions. Maintain an up-to-date endpoint inventory.",
                "GET /api/v*/",
                "",
            )

    def run_all(self, endpoints: Optional[List[str]] = None) -> None:
        default_eps = ["/api/v1/users/1", "/api/v1/orders/1", "/api/products/1", "/api/items/1"]
        eps = endpoints or default_eps

        self.test_api2_auth()
        self.test_api1_bola(eps)
        self.test_api3_mass_assignment()
        self.test_api4_resource()
        self.test_api5_function_auth()
        self.test_api8_misconfig()
        self.test_api9_inventory()


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════


def print_summary(tester: APITester) -> None:
    findings = tester.findings
    by_sev: Dict[str, int] = {}
    for finding in findings:
        by_sev[finding.severity] = by_sev.get(finding.severity, 0) + 1

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}API SECURITY TEST SUMMARY{C.RESET}")
    print(f"  Base URL        : {tester.base}")
    print(f"  Requests made   : {tester.requests_made}")
    print(f"  Findings        : {len(findings)}")
    print(SEP)
    for severity in SEV_ORDER:
        count = by_sev.get(severity, 0)
        if count:
            color = SEV_COL.get(severity, "")
            print(f"  {color}{severity:<10}{C.RESET} {'█' * min(count, 20)} {count}")
    print(SEP2)

    if findings:
        print(f"\n  {C.BOLD}OWASP API Top 10 Coverage:{C.RESET}")
        by_api: Dict[str, List[str]] = {}
        for finding in findings:
            by_api.setdefault(finding.api_top10, []).append(finding.severity)
        for api_id in sorted(by_api):
            severities = by_api[api_id]
            worst = min(severities, key=lambda sev: SEV_ORDER.index(sev))
            color = SEV_COL.get(worst, "")
            print(f"    {color}[{api_id}]{C.RESET} {len(severities)} finding(s) — worst: {worst}")


def determine_exit_code(findings: List[APIFinding]) -> int:
    severities = {finding.severity for finding in findings}
    if "CRITICAL" in severities:
        return 2
    if severities.intersection({"HIGH", "MEDIUM"}):
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="api-security-tester",
        description="OWASP API Security Top 10 Tester — Authorized Use Only",
    )
    parser.add_argument("url", help="Base API URL, for example: https://api.example.com")
    parser.add_argument("-t", "--token", default="", help="Bearer token. Accepts either the raw token or 'Bearer <token>'.")
    parser.add_argument(
        "-e",
        "--endpoints",
        nargs="*",
        help="Specific endpoints to test, for example: /api/v1/users/1",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Print each request as it is sent.")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Print the JSON report to stdout.")
    parser.add_argument("-o", "--output", help="Save the JSON report to a file.")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds. Default: 10.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification for lab/self-signed targets.")
    parser.add_argument("--no-banner", action="store_true", help="Do not print the ASCII banner.")
    parser.add_argument("--version", action="version", version=f"api-security-tester {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    tester = APITester(
        args.url,
        token=args.token,
        verbose=args.verbose,
        timeout=args.timeout,
        verify_tls=not args.insecure,
    )
    print(f"  {C.DIM}Target: {args.url}{C.RESET}")
    print(f"  {C.DIM}Auth: {'Bearer token provided' if args.token else 'no token'}{C.RESET}")

    tester.run_all(args.endpoints)
    print_summary(tester)

    if args.json_out or args.output:
        report = {
            "base_url": args.url,
            "timestamp": datetime.now().isoformat(),
            "requests_made": tester.requests_made,
            "findings": [finding.__dict__ for finding in tester.findings],
        }
        json_str = json.dumps(report, indent=2)
        if args.json_out:
            print(json_str)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fp:
                fp.write(json_str)
            print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    sys.exit(determine_exit_code(tester.findings))


if __name__ == "__main__":
    main()

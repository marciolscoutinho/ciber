#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║               VulnHunter — Static Security Analyzer          ║
║         CWE/OWASP-Based Vulnerability Detection Tool         ║
║                                                              ║
║  Author    : Márcio Coutinho (Cibersecurity Specialist       ║
║  Date      : 31/07/2025                                      ║
║  Version   : 1.0.0                                           ║
║  License   : MIT                                             ║
║  Use       : For educational purposes and authorized         ║
║              audits only. Do not use on third-party systems  ║
║              without explicit written permission.            ║
╚══════════════════════════════════════════════════════════════╝

Description:
    Static source code analysis tool that detects security
    vulnerability patterns based on OWASP Top 10 categories
    and CWE identifiers.

    Supports: Python, JavaScript/TypeScript, PHP, Java, C/C++,
              Bash, and configuration files.

Usage:
    python vulnhunter.py -t <file_or_directory> [options]

Examples:
    python vulnhunter.py -t app.py
    python vulnhunter.py -t ./projeto/ --format html
    python vulnhunter.py -t ./src/ --severity HIGH --verbose
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from enum import Enum

# ══════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════

VERSION    = "1.0.0"
TOOL_NAME  = "VulnHunter"

BANNER = f"""
{chr(27)}[96m╔══════════════════════════════════════════════════════════════╗
║              VulnHunter v{VERSION} — Static Analyzer            ║
║         CWE/OWASP Vulnerability Scanner for Source Code      ║
╚══════════════════════════════════════════════════════════════╝{chr(27)}[0m
"""

# Extensions supported by language
SUPPORTED_EXTENSIONS: Dict[str, List[str]] = {
    "python":     [".py"],
    "javascript": [".js", ".ts", ".jsx", ".tsx"],
    "php":        [".php"],
    "c_cpp":      [".c", ".cpp", ".h", ".hpp"],
    "java":       [".java"],
    "bash":       [".sh", ".bash"],
    "config":     [".env", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".xml"],
}

ALL_EXTENSIONS = [ext for exts in SUPPORTED_EXTENSIONS.values() for ext in exts]

# Directories to skip during the scan
SKIP_DIRS = frozenset([
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".tox", ".eggs", "coverage",
])


# ══════════════════════════════════════════════════════════════
# SEVERITY
# ══════════════════════════════════════════════════════════════

class Severity(Enum):
    """Severity levels with a numeric score for risk calculation."""
    CRITICAL = ("CRITICAL", "\033[91m", 10)
    HIGH     = ("HIGH",     "\033[91m",  7)
    MEDIUM   = ("MEDIUM",   "\033[93m",  4)
    LOW      = ("LOW",      "\033[94m",  2)
    INFO     = ("INFO",     "\033[96m",  0)

    def __init__(self, label: str, color: str, score: int):
        self.label = label
        self.color = color
        self.score = score


# ══════════════════════════════════════════════════════════════
# VULNERABILITY RULES
# ══════════════════════════════════════════════════════════════

@dataclass
class VulnRule:
    """Defines a vulnerability detection rule."""
    id:                  str
    name:                str
    description:         str
    severity:            Severity
    cwe:                 str
    owasp:               str
    pattern:             str
    languages:           List[str]
    remediation:         str
    false_positive_note: str = ""


# ─── Rule Database ───────────────────────────────────────────
#     Organized by OWASP / CWE category

VULN_RULES: List[VulnRule] = [

    # ── A03 INJECTION — SQL ───────────────────────────────────

    VulnRule(
        id="VH-001",
        name="SQL Injection — String Formatting",
        description=(
            "Construction of SQL queries using string formatting (%s, f-strings). "
            "Allows an attacker to manipulate query logic by injecting arbitrary SQL."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        owasp="A03:2021 — Injection",
        pattern=(
            r'(execute|query|cursor\.execute)\s*\(\s*["\'].*%[sd].*["\']'
            r'|f["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b'
        ),
        languages=["python", "php", "java"],
        remediation=(
            "Use prepared statements / parameterized queries. "
            "Ex: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
        ),
    ),

    VulnRule(
        id="VH-002",
        name="SQL Injection — String Concatenation",
        description=(
            "Direct concatenation of variables or user input into SQL queries. "
            "Critical vulnerability that may lead to authentication bypass or data exfiltration."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        owasp="A03:2021 — Injection",
        pattern=(
            r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\+\s*\w+'
            r'|\$_(GET|POST|REQUEST|COOKIE)\['
        ),
        languages=["python", "php", "javascript", "java"],
        remediation=(
            "Use an ORM or prepared statements. "
            "Never concatenate user input directly into SQL queries."
        ),
    ),

    # ── A03 INJECTION — COMMAND ───────────────────────────────

    VulnRule(
        id="VH-010",
        name="OS Command Injection — os.system()",
        description=(
            "Use of os.system(), which passes commands directly to the shell. "
            "If the input is not sanitized, it allows arbitrary command execution."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        owasp="A03:2021 — Injection",
        pattern=r'\bos\.system\s*\(',
        languages=["python"],
        remediation=(
            "Replace it with subprocess.run() using an argument list and shell=False. "
            "Ex: subprocess.run(['ls', '-la'], shell=False)"
        ),
    ),

    VulnRule(
        id="VH-011",
        name="OS Command Injection — subprocess shell=True",
        description=(
            "subprocess with shell=True interprets the command as a shell string, "
            "allowing injection through metacharacters (;, |, &&, etc.)."
        ),
        severity=Severity.HIGH,
        cwe="CWE-78",
        owasp="A03:2021 — Injection",
        pattern=r'subprocess\.(run|Popen|call|check_output)\s*\(.*shell\s*=\s*True',
        languages=["python"],
        remediation=(
            "Use shell=False (default) and pass arguments as a list: "
            "subprocess.run(['program', 'arg1', 'arg2'])"
        ),
    ),

    VulnRule(
        id="VH-012",
        name="Code Injection — eval() / exec()",
        description=(
            "eval() and exec() execute arbitrary Python code. "
            "If they receive user input, they allow malicious code execution."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-94",
        owasp="A03:2021 — Injection",
        pattern=r'\b(eval|exec)\s*\(',
        languages=["python", "javascript", "php"],
        remediation=(
            "Avoid eval/exec entirely. "
            "For simple data, use ast.literal_eval(). "
            "For mathematical expressions, use the sympy library."
        ),
        false_positive_note="May be a false positive in REPL contexts or development tools.",
    ),

    # ── A03 INJECTION — XSS ───────────────────────────────────

    VulnRule(
        id="VH-020",
        name="Cross-Site Scripting (XSS) — innerHTML",
        description=(
            "Direct assignment to innerHTML without HTML sanitization. "
            "Allows malicious scripts to be injected into the page."
        ),
        severity=Severity.HIGH,
        cwe="CWE-79",
        owasp="A03:2021 — Injection",
        pattern=r'\.innerHTML\s*[+]?=\s*(?!.*DOMPurify)',
        languages=["javascript"],
        remediation=(
            "Use textContent for plain text. "
            "For HTML, sanitize with DOMPurify: element.innerHTML = DOMPurify.sanitize(html)"
        ),
    ),

    VulnRule(
        id="VH-021",
        name="Cross-Site Scripting (XSS) — document.write()",
        description=(
            "document.write() with unsanitized data may inject arbitrary HTML/JS. "
            "It also affects page performance."
        ),
        severity=Severity.HIGH,
        cwe="CWE-79",
        owasp="A03:2021 — Injection",
        pattern=r'document\.write\s*\(',
        languages=["javascript"],
        remediation=(
            "Replace it with safe DOM manipulation: "
            "document.createElement(), textContent, or appendChild()."
        ),
    ),

    # ── A03 INJECTION — SSTI ──────────────────────────────────

    VulnRule(
        id="VH-022",
        name="Server-Side Template Injection (SSTI)",
        description=(
            "Rendering templates with direct user input. "
            "In Jinja2/Flask, this allows arbitrary Python code execution on the server."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-94",
        owasp="A03:2021 — Injection",
        pattern=r'(render_template_string|Environment\(\)\.from_string)\s*\(.*request\.',
        languages=["python"],
        remediation=(
            "Never render templates with user input. "
            "Pass data as safe context variables: render_template('page.html', data=data)"
        ),
    ),

    # ── A02 CRYPTOGRAPHIC FAILURES ────────────────────────────

    VulnRule(
        id="VH-030",
        name="Weak Algorithm — MD5",
        description=(
            "MD5 is cryptographically broken and vulnerable to collision attacks. "
            "It must not be used for password hashing or integrity verification."
        ),
        severity=Severity.HIGH,
        cwe="CWE-327",
        owasp="A02:2021 — Cryptographic Failures",
        pattern=r'\b(hashlib\.md5|md5\s*\(|MD5\s*\(|md5sum)\b',
        languages=["python", "php", "javascript", "java", "c_cpp"],
        remediation=(
            "Use SHA-256 or stronger: hashlib.sha256(). "
            "For passwords, use bcrypt, scrypt, or Argon2."
        ),
    ),

    VulnRule(
        id="VH-031",
        name="Weak Algorithm — SHA-1",
        description=(
            "SHA-1 is obsolete and vulnerable to practical collision attacks "
            "(demonstrated by Google in 2017 with the SHAttered attack)."
        ),
        severity=Severity.MEDIUM,
        cwe="CWE-327",
        owasp="A02:2021 — Cryptographic Failures",
        pattern=r'\b(hashlib\.sha1|sha1\s*\(|SHA1\s*\()\b',
        languages=["python", "php", "javascript", "java"],
        remediation="Replace it with SHA-256 (hashlib.sha256) or SHA-3 (hashlib.sha3_256).",
    ),

    VulnRule(
        id="VH-032",
        name="Insecure PRNG — random Module",
        description=(
            "Python's random module is not cryptographically secure (it uses Mersenne Twister). "
            "Its internal state can be predicted after observing 624 consecutive outputs."
        ),
        severity=Severity.MEDIUM,
        cwe="CWE-338",
        owasp="A02:2021 — Cryptographic Failures",
        pattern=r'\brandom\.(random|randint|choice|randrange|shuffle|token)\s*\(',
        languages=["python"],
        remediation=(
            "Use the secrets module for cryptographic operations: "
            "secrets.token_hex(32), secrets.choice(sequence), secrets.randbelow(n)"
        ),
        false_positive_note="False positive if used only for simulations or games with no security implications.",
    ),

    # ── A08 INSECURE DESERIALIZATION ──────────────────────────

    VulnRule(
        id="VH-040",
        name="Insecure Deserialization — pickle",
        description=(
            "pickle.loads() with untrusted data allows arbitrary code execution "
            "during deserialization. This is a classic RCE (Remote Code Execution) vector."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        owasp="A08:2021 — Software and Data Integrity Failures",
        pattern=r'\bpickle\.(loads|load|Unpickler)\s*\(',
        languages=["python"],
        remediation=(
            "Never deserialize pickle data from untrusted sources (network, user). "
            "Use JSON or MessagePack for data exchange between services."
        ),
    ),

    VulnRule(
        id="VH-041",
        name="Insecure Deserialization — yaml.load()",
        description=(
            "yaml.load() without a safe Loader may instantiate arbitrary Python objects "
            "and execute code through YAML tags such as !!python/object."
        ),
        severity=Severity.HIGH,
        cwe="CWE-502",
        owasp="A08:2021 — Software and Data Integrity Failures",
        pattern=r'\byaml\.load\s*\(',
        languages=["python"],
        remediation=(
            "Replace it with yaml.safe_load() or "
            "explicitly use yaml.load(data, Loader=yaml.SafeLoader)."
        ),
    ),

    # ── A01 BROKEN ACCESS CONTROL — PATH TRAVERSAL ───────────

    VulnRule(
        id="VH-050",
        name="Path Traversal",
        description=(
            "Opening files using paths derived from user input. "
            "Allows access to arbitrary system files (for example, ../../../../etc/passwd)."
        ),
        severity=Severity.HIGH,
        cwe="CWE-22",
        owasp="A01:2021 — Broken Access Control",
        pattern=r'\bopen\s*\(\s*(request\.|input\s*\(|sys\.argv|os\.environ)',
        languages=["python"],
        remediation=(
            "Sanitize and validate paths: use os.path.realpath() and verify "
            "that the resulting path starts with the permitted base directory."
        ),
    ),

    # ── A02 CRYPTOGRAPHIC FAILURES — HARDCODED SECRETS ───────

    VulnRule(
        id="VH-060",
        name="Hardcoded Credential — Password",
        description=(
            "Password defined directly in the source code. "
            "Anyone with access to the repository may compromise the credentials."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-259",
        owasp="A02:2021 — Cryptographic Failures",
        pattern=(
            r'(?i)(password|passwd|pwd|secret|pass)\s*=\s*'
            r'["\'][^"\']{4,}["\']'
        ),
        languages=["python", "javascript", "php", "java", "bash", "config"],
        remediation=(
            "Use environment variables: os.environ.get('DB_PASSWORD'). "
            "Store secrets in .env (with python-dotenv) and add .env to .gitignore."
        ),
        false_positive_note="May detect variable names containing 'password' without an actual sensitive value.",
    ),

    VulnRule(
        id="VH-061",
        name="Hardcoded Credential — API Key / Token",
        description=(
            "API key or access token defined directly in the code. "
            "If the repository is public, or private but accessible to former collaborators, the key is compromised."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-321",
        owasp="A02:2021 — Cryptographic Failures",
        pattern=(
            r'(?i)(api_key|apikey|api_token|access_token|secret_key|auth_token|'
            r'private_key|client_secret)\s*=\s*["\'][A-Za-z0-9+/=_\-]{8,}["\']'
        ),
        languages=["python", "javascript", "php", "java", "bash", "config"],
        remediation=(
            "Move it to environment variables. "
            "Use tools such as python-dotenv, direnv, or a secrets manager."
        ),
    ),

    VulnRule(
        id="VH-062",
        name="Exposed AWS Access Key",
        description=(
            "AWS access key pattern (AKIA...) detected in the code. "
            "Exposed AWS keys are among the most common causes of cloud security incidents."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        owasp="A02:2021 — Cryptographic Failures",
        pattern=r'AKIA[0-9A-Z]{16}',
        languages=["python", "javascript", "php", "java", "bash", "config"],
        remediation=(
            "1) Immediately revoke the key in the AWS IAM Console. "
            "2) Use IAM Roles instead of static keys. "
            "3) Enable AWS CloudTrail to audit suspicious use."
        ),
    ),

    VulnRule(
        id="VH-063",
        name="Private Key in Source Code (PEM)",
        description=(
            "RSA/EC/DSA private key block detected in the source code. "
            "It compromises all infrastructure that depends on this key."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-321",
        owasp="A02:2021 — Cryptographic Failures",
        pattern=r'-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----',
        languages=["python", "javascript", "php", "java", "bash", "config"],
        remediation=(
            "Immediately remove it from the code and Git history (use git-filter-repo). "
            "Revoke and regenerate the key. Store it in a separate file with permissions set to 600."
        ),
    ),

    # ── A02 SSL / TLS ─────────────────────────────────────────

    VulnRule(
        id="VH-070",
        name="SSL Verification Disabled",
        description=(
            "verify=False disables SSL/TLS certificate validation, "
            "making the connection vulnerable to Man-in-the-Middle (MitM) attacks."
        ),
        severity=Severity.HIGH,
        cwe="CWE-295",
        owasp="A02:2021 — Cryptographic Failures",
        pattern=r'\bverify\s*=\s*False\b',
        languages=["python"],
        remediation=(
            "Remove verify=False. If the certificate is self-signed in development, "
            "use verify='/path/to/ca-bundle.crt' instead of disabling verification entirely."
        ),
    ),

    # ── A05 SECURITY MISCONFIGURATION ────────────────────────

    VulnRule(
        id="VH-080",
        name="Debug Mode Enabled",
        description=(
            "Debug mode enabled in a web application. In production, it exposes "
            "stack traces and environment variables, and may enable interactive consoles."
        ),
        severity=Severity.MEDIUM,
        cwe="CWE-94",
        owasp="A05:2021 — Security Misconfiguration",
        pattern=r'(?i)(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True)',
        languages=["python"],
        remediation=(
            "Ensure DEBUG=False in production. "
            "Use environment variables: DEBUG=os.environ.get('DEBUG', 'False') == 'True'"
        ),
    ),

    VulnRule(
        id="VH-081",
        name="Stack Trace Exposure",
        description=(
            "Printing the full traceback to the user. "
            "May reveal internal paths, library versions, and application logic."
        ),
        severity=Severity.LOW,
        cwe="CWE-209",
        owasp="A05:2021 — Security Misconfiguration",
        pattern=r'\btraceback\.(print_exc|format_exc)\s*\(',
        languages=["python"],
        remediation=(
            "Log the traceback internally with logging.exception() "
            "and return only a generic error message to the user."
        ),
        false_positive_note="Acceptable in development scripts and internal CLI tools.",
    ),

    # ── C/C++ MEMORY SAFETY ───────────────────────────────────

    VulnRule(
        id="VH-100",
        name="Buffer Overflow — Unsafe C Function",
        description=(
            "C functions without buffer bounds checking. "
            "gets(), strcpy(), sprintf(), and scanf() are among the most common causes of buffer overflows."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-120",
        owasp="A03:2021 — Injection",
        pattern=r'\b(gets|strcpy|strcat|sprintf|scanf)\s*\(',
        languages=["c_cpp"],
        remediation=(
            "Replace them with safer alternatives: "
            "fgets(), strncpy(), strncat(), snprintf(), and fgets(). "
            "Alternatively, use modern C++ libraries with bounds checking."
        ),
    ),

    VulnRule(
        id="VH-101",
        name="Format String Attack",
        description=(
            "printf() or fprintf() called with user input as the format string. "
            "Allows arbitrary memory reads and writes."
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-134",
        owasp="A03:2021 — Injection",
        pattern=r'\b(printf|fprintf|sprintf)\s*\(\s*\w+\s*[,)]',
        languages=["c_cpp"],
        remediation=(
            "Always use a literal format string: printf(\"%s\", user_input). "
            "Never use: printf(user_input)."
        ),
    ),
]


# ══════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """Represents a detected vulnerability."""
    rule_id:             str
    rule_name:           str
    severity:            str
    severity_score:      int
    cwe:                 str
    owasp:               str
    file_path:           str
    line_number:         int
    line_content:        str
    description:         str
    remediation:         str
    false_positive_note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Complete scan result."""
    target:               str
    scan_date:            str
    tool_version:         str
    files_scanned:        int
    total_findings:       int
    findings_by_severity: Dict[str, int]
    risk_score:           int
    findings:             List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "target":               self.target,
            "scan_date":            self.scan_date,
            "tool_version":         self.tool_version,
            "files_scanned":        self.files_scanned,
            "total_findings":       self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "risk_score":           self.risk_score,
            "findings":             [f.to_dict() for f in self.findings],
        }
        return d


# ══════════════════════════════════════════════════════════════
# TERMINAL COLORS
# ══════════════════════════════════════════════════════════════

class C:
    """ANSI color constants for terminal output."""
    RST  = "\033[0m"
    BOLD = "\033[1m"
    RED  = "\033[91m"
    YLW  = "\033[93m"
    BLU  = "\033[94m"
    CYN  = "\033[96m"
    GRN  = "\033[92m"
    MAG  = "\033[95m"
    WHT  = "\033[97m"
    GRY  = "\033[90m"


def severity_color(sev: str) -> str:
    return {
        "CRITICAL": C.RED,
        "HIGH":     C.RED,
        "MEDIUM":   C.YLW,
        "LOW":      C.BLU,
        "INFO":     C.CYN,
    }.get(sev, C.WHT)


# ══════════════════════════════════════════════════════════════
# SCANNER
# ══════════════════════════════════════════════════════════════

def detect_language(file_path: Path) -> Optional[str]:
    """Detects the programming language from the file extension."""
    ext = file_path.suffix.lower()
    for lang, extensions in SUPPORTED_EXTENSIONS.items():
        if ext in extensions:
            return lang
    return None


def get_files_to_scan(target: str) -> List[Path]:
    """Returns the files to scan from a single file or a recursive directory."""
    target_path = Path(target)
    files: List[Path] = []

    if target_path.is_file():
        if target_path.suffix.lower() in ALL_EXTENSIONS:
            files.append(target_path)

    elif target_path.is_dir():
        for ext in ALL_EXTENSIONS:
            for f in target_path.rglob(f"*{ext}"):
                # Exclude dependency and build directories
                if not any(part in SKIP_DIRS for part in f.parts):
                    files.append(f)

    return sorted(set(files))


def is_comment_line(line: str) -> bool:
    """Checks whether a line is a comment to reduce false positives."""
    stripped = line.strip()
    return stripped.startswith(("#", "//", "/*", "*", "--", "<!--"))


def scan_file(file_path: Path, rules: List[VulnRule], verbose: bool = False) -> List[Finding]:
    """
    Analyzes a source code file and returns the detected vulnerabilities.
    
    Process:
    1. Detects the language from the suffix
    2. Reads the file contents
    3. Applies each rule whose regular expression matches
    4. Filters commented lines to reduce false positives
    5. Returns a list of Finding objects
    """
    findings: List[Finding] = []

    # Check whether the file language is supported
    lang = detect_language(file_path)
    if lang is None:
        return findings

    # Read the contents
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (IOError, OSError) as e:
        print(f"{C.YLW}[WARNING] Unable to read {file_path}: {e}{C.RST}")
        return findings

    lines = content.splitlines()

    for rule in rules:
        # Does this rule apply to this language?
        if rule.languages and lang not in rule.languages:
            continue

        # Compile the regular expression
        try:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            print(f"{C.YLW}[WARNING] Invalid regular expression in rule {rule.id}: {e}{C.RST}")
            continue

        # Find all matches
        for match in pattern.finditer(content):
            line_num     = content[:match.start()].count('\n') + 1
            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

            # Ignore comment lines
            if is_comment_line(line_content):
                continue

            finding = Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity.label,
                severity_score=rule.severity.score,
                cwe=rule.cwe,
                owasp=rule.owasp,
                file_path=str(file_path),
                line_number=line_num,
                line_content=line_content[:150],    # truncate very long lines
                description=rule.description,
                remediation=rule.remediation,
                false_positive_note=rule.false_positive_note,
            )
            findings.append(finding)

            if verbose:
                col = severity_color(rule.severity.label)
                print(f"    {col}[{rule.severity.label}]{C.RST} {rule.name} @ line {line_num}")

    return findings


# ══════════════════════════════════════════════════════════════
# HTML REPORT
# ══════════════════════════════════════════════════════════════

def generate_html_report(result: ScanResult, output_path: str) -> None:
    """Generates an interactive, polished HTML report."""

    SEV_COLORS = {
        "CRITICAL": "#ff4757",
        "HIGH":     "#ff6b35",
        "MEDIUM":   "#ffd32a",
        "LOW":      "#3d9be9",
        "INFO":     "#2ed573",
    }

    # Build finding cards
    cards_html = ""
    sev_order   = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    sorted_findings = sorted(result.findings, key=lambda x: sev_order.get(x.severity, 0), reverse=True)

    for i, f in enumerate(sorted_findings, 1):
        col     = SEV_COLORS.get(f.severity, "#666")
        fp_html = (f'<div class="fp-note">⚠ Note (false positive): {f.false_positive_note}</div>'
                   if f.false_positive_note else "")
        cards_html += f"""
        <div class="card" data-severity="{f.severity}">
          <div class="card-header" style="--accent:{col}">
            <div class="card-meta">
              <span class="badge" style="background:{col}">{f.severity}</span>
              <span class="rule-id">{f.rule_id}</span>
              <span class="cwe-tag">{f.cwe}</span>
            </div>
            <h3 class="card-title">{f.rule_name}</h3>
          </div>
          <div class="card-body">
            <div class="info-row">
              <span class="info-label">File</span>
              <code class="info-value filepath">{f.file_path} : {f.line_number}</code>
            </div>
            <pre class="code-block"><code>{f.line_content}</code></pre>
            <div class="info-row">
              <span class="info-label">OWASP</span>
              <span class="info-value">{f.owasp}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Description</span>
              <span class="info-value">{f.description}</span>
            </div>
            <div class="fix-box">
              <span class="fix-label">✓ Remediation</span>
              <span class="fix-text">{f.remediation}</span>
            </div>
            {fp_html}
          </div>
        </div>"""

    # Risk score with dynamic color
    risk = result.risk_score
    risk_col = "#ff4757" if risk >= 50 else "#ffd32a" if risk >= 20 else "#2ed573"

    no_findings_msg = ""
    if result.total_findings == 0:
        no_findings_msg = '<div class="empty-state">✓ No vulnerabilities were detected in the analyzed files.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnHunter — Security Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap');

  :root {{
    --bg:      #080c14;
    --surface: #0d1520;
    --border:  #1a2535;
    --text:    #c8d6e8;
    --muted:   #4a6080;
    --accent:  #00d4ff;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Syne', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    font-size: 15px;
    line-height: 1.6;
  }}

  /* ── HEADER ─── */
  header {{
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 3rem;
    display: flex;
    align-items: flex-start;
    gap: 2rem;
  }}
  .logo-mark {{
    width: 52px; height: 52px;
    background: linear-gradient(135deg, #00d4ff, #7c4dff);
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.5rem; flex-shrink: 0;
  }}
  .header-text h1 {{
    font-size: 1.6rem; font-weight: 800;
    color: #fff; letter-spacing: -0.03em;
  }}
  .header-text h1 span {{ color: var(--accent); }}
  .header-meta {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.75rem; color: var(--muted);
    margin-top: 0.4rem;
    display: flex; gap: 1.5rem; flex-wrap: wrap;
  }}
  .header-meta span::before {{ content: '› '; color: var(--accent); }}

  /* ── STATS BAR ─── */
  .stats-bar {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 1px;
    background: var(--border);
    border-bottom: 1px solid var(--border);
  }}
  .stat {{
    background: var(--surface);
    padding: 1.4rem 1.6rem;
    text-align: center;
  }}
  .stat-number {{
    font-size: 2rem; font-weight: 800;
    line-height: 1; color: var(--text);
  }}
  .stat-label {{
    font-size: 0.72rem; text-transform: uppercase;
    letter-spacing: 0.1em; color: var(--muted);
    margin-top: 0.4rem;
  }}
  .risk-number {{ color: {risk_col}; font-size: 2.5rem; }}

  /* ── FILTERS ─── */
  .filters {{
    padding: 1.5rem 3rem;
    display: flex; gap: 0.6rem; flex-wrap: wrap;
    align-items: center;
    border-bottom: 1px solid var(--border);
  }}
  .filter-label {{
    font-size: 0.75rem; text-transform: uppercase;
    letter-spacing: 0.1em; color: var(--muted);
    margin-right: 0.5rem;
  }}
  .filter-btn {{
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 0.35rem 0.9rem;
    border-radius: 6px;
    cursor: pointer;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.8rem;
    transition: all 0.15s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    border-color: var(--accent);
    color: var(--accent);
    background: rgba(0, 212, 255, 0.07);
  }}

  /* ── MAIN CONTENT ─── */
  main {{ padding: 2rem 3rem; max-width: 1200px; }}

  .section-title {{
    font-size: 0.75rem; text-transform: uppercase;
    letter-spacing: 0.12em; color: var(--muted);
    margin-bottom: 1.2rem;
    padding-bottom: 0.6rem;
    border-bottom: 1px solid var(--border);
  }}

  /* ── CARDS ─── */
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 1rem;
    overflow: hidden;
    transition: border-color 0.2s;
  }}
  .card:hover {{ border-color: rgba(255,255,255,0.1); }}

  .card-header {{
    padding: 1rem 1.4rem 0.8rem;
    border-left: 3px solid var(--accent);
    cursor: pointer;
    user-select: none;
  }}
  .card-meta {{
    display: flex; align-items: center; gap: 0.5rem;
    margin-bottom: 0.4rem;
  }}
  .badge {{
    color: #000; font-weight: 700;
    padding: 0.15rem 0.55rem;
    border-radius: 4px;
    font-size: 0.72rem;
    letter-spacing: 0.05em;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .rule-id {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.75rem; color: var(--muted);
  }}
  .cwe-tag {{
    background: rgba(255,255,255,0.05);
    border: 1px solid var(--border);
    padding: 0.1rem 0.45rem;
    border-radius: 4px;
    font-size: 0.72rem;
    font-family: 'IBM Plex Mono', monospace;
    color: var(--muted);
  }}
  .card-title {{
    font-size: 0.95rem; font-weight: 700; color: #fff;
    letter-spacing: -0.01em;
  }}

  .card-body {{
    padding: 1rem 1.4rem 1.2rem;
    border-top: 1px solid var(--border);
    display: flex; flex-direction: column; gap: 0.6rem;
  }}
  .info-row {{
    display: flex; gap: 1rem; align-items: baseline;
  }}
  .info-label {{
    font-size: 0.72rem; text-transform: uppercase;
    letter-spacing: 0.08em; color: var(--muted);
    min-width: 80px; flex-shrink: 0;
  }}
  .info-value {{
    font-size: 0.88rem; color: var(--text);
  }}
  .filepath {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.82rem; color: var(--accent);
    word-break: break-all;
  }}

  .code-block {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.7rem 1rem;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.82rem;
    color: #ffd700;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }}

  .fix-box {{
    background: rgba(46, 213, 115, 0.06);
    border: 1px solid rgba(46, 213, 115, 0.2);
    border-radius: 6px;
    padding: 0.7rem 1rem;
    display: flex; gap: 0.8rem; align-items: baseline;
  }}
  .fix-label {{
    color: #2ed573; font-weight: 700;
    font-size: 0.78rem; white-space: nowrap;
  }}
  .fix-text {{ font-size: 0.87rem; color: var(--text); }}

  .fp-note {{
    background: rgba(255, 211, 42, 0.06);
    border: 1px solid rgba(255, 211, 42, 0.2);
    border-radius: 6px;
    padding: 0.5rem 1rem;
    font-size: 0.82rem;
    color: #ffd32a;
  }}

  .empty-state {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 3rem;
    text-align: center;
    color: #2ed573;
    font-size: 1.1rem;
  }}

  /* ── FOOTER ─── */
  footer {{
    padding: 2rem 3rem;
    border-top: 1px solid var(--border);
    display: flex; justify-content: space-between; align-items: center;
    font-size: 0.78rem; color: var(--muted);
    font-family: 'IBM Plex Mono', monospace;
    flex-wrap: wrap; gap: 1rem;
  }}
  footer strong {{ color: var(--accent); }}

  /* ── RESPONSIVE ─── */
  @media (max-width: 700px) {{
    header, main, .filters, footer {{ padding-left: 1.2rem; padding-right: 1.2rem; }}
    .stats-bar {{ grid-template-columns: repeat(3, 1fr); }}
  }}
</style>
</head>
<body>

<header>
  <div class="logo-mark">🔍</div>
  <div class="header-text">
    <h1><span>Vuln</span>Hunter — Security Report</h1>
    <div class="header-meta">
      <span>Target: {result.target}</span>
      <span>Date: {result.scan_date}</span>
      <span>Version: {result.tool_version}</span>
    </div>
  </div>
</header>

<div class="stats-bar">
  <div class="stat">
    <div class="stat-number" style="color:#00d4ff">{result.files_scanned}</div>
    <div class="stat-label">Files</div>
  </div>
  <div class="stat">
    <div class="stat-number" style="color:#ff4757">{result.findings_by_severity.get('CRITICAL', 0)}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat">
    <div class="stat-number" style="color:#ff6b35">{result.findings_by_severity.get('HIGH', 0)}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat">
    <div class="stat-number" style="color:#ffd32a">{result.findings_by_severity.get('MEDIUM', 0)}</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat">
    <div class="stat-number" style="color:#3d9be9">{result.findings_by_severity.get('LOW', 0)}</div>
    <div class="stat-label">Low</div>
  </div>
  <div class="stat">
    <div class="risk-number stat-number">{result.risk_score}</div>
    <div class="stat-label">Risk Score</div>
  </div>
</div>

<div class="filters">
  <span class="filter-label">Filter:</span>
  <button class="filter-btn active" onclick="filterCards('ALL')">All ({result.total_findings})</button>
  <button class="filter-btn" onclick="filterCards('CRITICAL')" style="border-color:#ff4757;color:#ff4757">
    CRITICAL ({result.findings_by_severity.get('CRITICAL', 0)})</button>
  <button class="filter-btn" onclick="filterCards('HIGH')" style="border-color:#ff6b35;color:#ff6b35">
    HIGH ({result.findings_by_severity.get('HIGH', 0)})</button>
  <button class="filter-btn" onclick="filterCards('MEDIUM')" style="border-color:#ffd32a;color:#ffd32a">
    MEDIUM ({result.findings_by_severity.get('MEDIUM', 0)})</button>
  <button class="filter-btn" onclick="filterCards('LOW')" style="border-color:#3d9be9;color:#3d9be9">
    LOW ({result.findings_by_severity.get('LOW', 0)})</button>
</div>

<main>
  <p class="section-title">Detected Vulnerabilities — {result.total_findings} result(s)</p>
  {cards_html if cards_html else no_findings_msg}
</main>

<footer>
  <span>Generated by <strong>VulnHunter v{VERSION}</strong> — Educational static analysis tool</span>
  <span>⚠ For authorized audits only</span>
</footer>

<script>
  function filterCards(severity) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.card').forEach(card => {{
      card.style.display = (severity === 'ALL' || card.dataset.severity === severity)
        ? '' : 'none';
    }});
  }}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"{C.GRN}[✓] HTML report saved: {output_path}{C.RST}")


# ══════════════════════════════════════════════════════════════
# JSON REPORT
# ══════════════════════════════════════════════════════════════

def generate_json_report(result: ScanResult, output_path: str) -> None:
    """Exports the complete result as structured JSON."""
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
    print(f"{C.GRN}[✓] JSON report saved: {output_path}{C.RST}")


# ══════════════════════════════════════════════════════════════
# TERMINAL OUTPUT
# ══════════════════════════════════════════════════════════════

SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def print_findings_terminal(findings: List[Finding], min_sev: str = "INFO") -> None:
    """Prints findings to the terminal with colored formatting."""
    min_rank = SEVERITY_RANK.get(min_sev, 1)
    visible  = sorted(
        [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= min_rank],
        key=lambda x: SEVERITY_RANK.get(x.severity, 0),
        reverse=True,
    )

    for f in visible:
        col = severity_color(f.severity)
        print(f"\n{col}{'━' * 65}{C.RST}")
        print(f"{col}[{f.severity}]{C.RST} {C.BOLD}{f.rule_name}{C.RST}  {C.GRY}{f.rule_id}{C.RST}")
        print(f"  {C.GRY}File{C.RST} : {C.CYN}{f.file_path}:{f.line_number}{C.RST}")
        print(f"  {C.GRY}CWE    {C.RST} : {f.cwe}   {C.GRY}│{C.RST}   {f.owasp}")
        print(f"  {C.GRY}Code   {C.RST} : {C.YLW}{f.line_content}{C.RST}")
        print(f"  {C.GRY}Desc.  {C.RST} : {f.description}")
        print(f"  {C.GRN}Fix    {C.RST} : {f.remediation}")
        if f.false_positive_note:
            print(f"  {C.YLW}⚠ FP   {C.RST} : {f.false_positive_note}")


def print_summary(result: ScanResult) -> None:
    """Prints the executive scan summary."""
    risk_col = C.RED if result.risk_score >= 50 else C.YLW if result.risk_score >= 20 else C.GRN

    print(f"\n{C.BOLD}{'═' * 65}{C.RST}")
    print(f"{C.BOLD}  SCAN SUMMARY — {TOOL_NAME} v{VERSION}{C.RST}")
    print(f"{'═' * 65}")
    print(f"  Target    : {result.target}")
    print(f"  Date      : {result.scan_date}")
    print(f"  Files     : {result.files_scanned}")
    print(f"{'─' * 65}")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = result.findings_by_severity.get(sev, 0)
        if count > 0:
            col = severity_color(sev)
            bar = "█" * min(count, 35)
            print(f"  {col}{sev:<10}{C.RST} {bar} {count}")

    print(f"{'─' * 65}")
    print(f"  Total     : {result.total_findings} finding(s)")
    print(f"  Risk Score: {risk_col}{C.BOLD}{result.risk_score}{C.RST}")
    print(f"{'═' * 65}\n")


# ══════════════════════════════════════════════════════════════
# CLI — ENTRY POINT
# ══════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnhunter",
        description=f"{TOOL_NAME} — Static Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vulnhunter.py -t app.py
  python vulnhunter.py -t ./project/ --format html -o report
  python vulnhunter.py -t ./src/ --severity HIGH --verbose
  python vulnhunter.py -t ./code/ --format both --no-banner
        """,
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="File or directory to analyze",
    )
    parser.add_argument(
        "-o", "--output", default="vulnhunter_report",
        help="Base name for output files (default: vulnhunter_report)",
    )
    parser.add_argument(
        "--format", choices=["json", "html", "both"], default="both",
        help="Output report format (default: both)",
    )
    parser.add_argument(
        "--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="INFO",
        help="Minimum severity to display in the terminal (default: INFO)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed progress for each file",
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="Suppress the opening banner",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} v{VERSION}",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # ── Banner ────────────────────────────────────────────────
    if not args.no_banner:
        print(BANNER)

    # ── Validate target ────────────────────────────────────────
    if not Path(args.target).exists():
        print(f"{C.RED}[ERROR] Target not found: {args.target}{C.RST}")
        sys.exit(1)

    # ── Discover files ───────────────────────────────────
    files = get_files_to_scan(args.target)
    if not files:
        print(f"{C.YLW}[WARNING] No supported files found in: {args.target}{C.RST}")
        sys.exit(0)

    print(f"{C.CYN}[*] Analyzing {len(files)} file(s)...{C.RST}\n")

    # ── Scan ──────────────────────────────────────────────────
    all_findings: List[Finding] = []
    for fp in files:
        if args.verbose:
            print(f"{C.GRY}[→] {fp}{C.RST}")
        all_findings.extend(scan_file(fp, VULN_RULES, verbose=args.verbose))

    # ── Deduplication (rule + file + line) ───────────────
    seen: set = set()
    unique: List[Finding] = []
    for f in all_findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # ── Statistics ──────────────────────────────────────────
    by_sev: Dict[str, int] = {}
    risk_score = 0
    for f in unique:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        risk_score += f.severity_score

    result = ScanResult(
        target=str(Path(args.target).resolve()),
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        tool_version=VERSION,
        files_scanned=len(files),
        total_findings=len(unique),
        findings_by_severity=by_sev,
        risk_score=risk_score,
        findings=unique,
    )

    # ── Output terminal ───────────────────────────────────────
    print_findings_terminal(unique, min_sev=args.severity)
    print_summary(result)

    # ── Generate reports ──────────────────────────────────────
    if args.format in ("json", "both"):
        generate_json_report(result, f"{args.output}.json")
    if args.format in ("html", "both"):
        generate_html_report(result, f"{args.output}.html")

    # ── Exit code ─────────────────────────────────────────────
    # Exit 2 → critical findings (useful in CI/CD pipelines)
    criticals = by_sev.get("CRITICAL", 0)
    if criticals:
        print(f"\n{C.RED}[!] {criticals} CRITICAL vulnerability(s) found.{C.RST}")
        print(f"{C.RED}[!] Immediate action is required before deployment.{C.RST}\n")
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()

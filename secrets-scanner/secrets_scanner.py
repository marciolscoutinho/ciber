#!/usr/bin/env python3
"""
secrets_scanner.py — Secrets Scanner v1.0.0
============================================
Detects exposed secrets in source code, configuration files,
and git history. Inspired by TruffleHog and gitleaks.

Categories: API keys, tokens, passwords, private keys, connection strings,
            cloud credentials (AWS/GCP/Azure), JWT, PEM certificates.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 24/10/2025
Req.   : Python 3.8+ | Zero external dependencies
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

__version__ = "1.0.0"


class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


BANNER = f"""
{C.RED}{C.BOLD}
 ███████╗███████╗ ██████╗██████╗ ███████╗████████╗███████╗
 ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝
 ███████╗█████╗  ██║     ██████╔╝█████╗     ██║   ███████╗
 ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║   ╚════██║
 ███████║███████╗╚██████╗██║  ██║███████╗   ██║   ███████║
 ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝{C.RESET}
{C.DIM} v{__version__} — Secrets Scanner | Files · Git History · Entropy · Zero Deps{C.RESET}
"""

# ══════════════════════════════════════════════════════════════════════════════
# SECRET RULES DATABASE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecretRule:
    id:          str
    name:        str
    severity:    str          # CRITICAL / HIGH / MEDIUM / LOW
    pattern:     re.Pattern
    description: str
    remediation: str
    false_positive_hints: List[str] = field(default_factory=list)


def _r(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


SECRET_RULES: List[SecretRule] = [
    # ── Cloud Credentials ──────────────────────────────────────────────────
    SecretRule("AWS-001", "AWS Access Key ID", "CRITICAL",
        _r(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS Access Key ID exposed — full AWS account access possible",
        "Revoke in IAM > Access keys. Use AWS Secrets Manager or environment variables.",
        ["EXAMPLE", "AKIAIOSFODNN7EXAMPLE"]),

    SecretRule("AWS-002", "AWS Secret Access Key", "CRITICAL",
        _r(r"(?i)aws.{0,20}secret.{0,20}['\"]([a-z0-9/+]{40})['\"]"),
        "AWS Secret Access Key — allows full AWS authentication",
        "Revoke immediately in IAM. Audit CloudTrail for unauthorized use."),

    SecretRule("GCP-001", "Google API Key", "HIGH",
        _r(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "Google API Key exposed",
        "Restrict the key in Google Cloud Console. Rotate it and use Secret Manager."),

    SecretRule("GCP-002", "Google Service Account", "CRITICAL",
        _r(r'"type"\s*:\s*"service_account"'),
        "Google service account file — access to GCP resources",
        "Revoke the key in IAM. Never commit service account JSON files."),

    SecretRule("AZ-001", "Azure Storage Account Key", "CRITICAL",
        _r(r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/]{86}=="),
        "Azure Storage connection string with account key",
        "Rotate the key in the Azure portal. Use Managed Identities instead of keys."),

    SecretRule("AZ-002", "Azure SAS Token", "HIGH",
        _r(r"(?i)sv=\d{4}-\d{2}-\d{2}&s[sco]=\w+&sp=\w+&se=[\d\-T%:Z]+&s[rt]=\w&sig=[a-zA-Z0-9%+/=]{40,}"),
        "Azure Shared Access Signature token",
        "Revoke the SAS token immediately. Configure a short expiration period."),

    # ── API Keys & Tokens ──────────────────────────────────────────────────
    SecretRule("GH-001", "GitHub Personal Access Token", "CRITICAL",
        _r(r"\bghp_[a-zA-Z0-9]{36}\b"),
        "GitHub Personal Access Token — access to repositories and source code",
        "Revoke in GitHub > Settings > Developer settings > Tokens."),

    SecretRule("GH-002", "GitHub OAuth Token", "CRITICAL",
        _r(r"\bgho_[a-zA-Z0-9]{36}\b"),
        "GitHub OAuth Access Token",
        "Revoke in GitHub > Settings > Applications."),

    SecretRule("GH-003", "GitHub App Token", "CRITICAL",
        _r(r"\b(ghs|ghu)_[a-zA-Z0-9]{36}\b"),
        "GitHub App Installation/User Token",
        "Revoke and regenerate the GitHub App token."),

    SecretRule("SL-001", "Slack Token", "HIGH",
        _r(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b"),
        "Slack API token — access to messages and channels",
        "Revoke at api.slack.com/apps. Rotate all tokens."),

    SecretRule("TW-001", "Stripe API Key", "CRITICAL",
        _r(r"\b(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}\b"),
        "Stripe API Key — access to payment data",
        "Revoke at dashboard.stripe.com/apikeys. CRITICAL if this is a production key."),

    SecretRule("SQ-001", "SendGrid API Key", "HIGH",
        _r(r"\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b"),
        "SendGrid API Key — email sending capability",
        "Revoke at app.sendgrid.com/settings/api_keys."),

    SecretRule("TW-002", "Twilio Account SID / Auth Token", "HIGH",
        _r(r"\bAC[a-f0-9]{32}\b"),
        "Twilio Account SID",
        "Revoke in console.twilio.com. Audit unauthorized calls/SMS."),

    SecretRule("HB-001", "HubSpot API Key", "MEDIUM",
        _r(r"(?i)hubspot.{0,10}['\"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]"),
        "HubSpot API Key",
        "Revoke in HubSpot > Account Settings > Integrations > API Key."),

    # ── Passwords & Credentials ────────────────────────────────────────────
    SecretRule("PW-001", "Hardcoded Password (assignment)", "HIGH",
        _r(r"(?i)(?:password|passwd|pwd|secret|pass)\s*[=:]\s*['\"]([^'\"]{6,})['\"]"),
        "Hardcoded password in source code or configuration",
        "Move it to an environment variable or secrets manager. Use os.environ.get()."),

    SecretRule("PW-002", "Hardcoded Password (dict key)", "HIGH",
        _r(r'''(?i)['"](password|passwd|secret|pwd)['"]\s*:\s*['"]([^'"]{6,})['"]'''),
        "Hardcoded password in dictionary/JSON/YAML",
        "Replace with a reference to an environment variable or secrets manager."),

    SecretRule("DB-001", "Database Connection String (with creds)", "CRITICAL",
        _r(r"(?i)(?:mysql|postgres|postgresql|mongodb|mssql|oracle|redis|mariadb)://[^:@\s]+:[^@\s]+@[^\s'\"]+"),
        "Database connection string with embedded credentials",
        "Separate credentials from the connection string. Use environment variables."),

    SecretRule("DB-002", "MongoDB Connection String", "CRITICAL",
        _r(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s'\"]{8,}"),
        "MongoDB connection string with password",
        "Use environment variables. Revoke exposed credentials."),

    # ── Private Keys & Certificates ────────────────────────────────────────
    SecretRule("KEY-001", "RSA Private Key", "CRITICAL",
        _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "RSA/EC/DSA/OpenSSH private key in source code",
        "Revoke and regenerate the key pair immediately. Never commit private keys."),

    SecretRule("KEY-002", "PGP Private Key", "CRITICAL",
        _r(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "PGP private key",
        "Revoke the compromised subkey. Notify recipients."),

    SecretRule("KEY-003", "SSH Private Key (OpenSSH)", "CRITICAL",
        _r(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "OpenSSH private key",
        "Remove it from authorized_keys on target servers. Regenerate the key pair."),

    # ── JWT & Auth Tokens ──────────────────────────────────────────────────
    SecretRule("JWT-001", "JSON Web Token", "MEDIUM",
        _r(r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b"),
        "JWT token in source code — may contain sensitive data or have a long lifetime",
        "Check expiration and claims. Never commit long-lived tokens."),

    SecretRule("JWT-002", "JWT Secret (hardcoded)", "CRITICAL",
        _r(r"(?i)jwt[_\-]?secret\s*[=:]\s*['\"]([^'\"]{8,})['\"]"),
        "Hardcoded JWT secret — allows arbitrary token forgery",
        "Move it to an environment variable. Invalidate all existing tokens."),

    # ── Infrastructure ─────────────────────────────────────────────────────
    SecretRule("SMTP-001", "SMTP Credentials", "HIGH",
        _r(r"(?i)smtp.{0,30}(?:pass|pwd|password|secret)\s*[=:]\s*['\"]([^'\"]{4,})['\"]"),
        "Hardcoded SMTP credentials — allows unauthorized email sending",
        "Use environment variables. Consider OAuth2 for Gmail/Outlook."),

    SecretRule("ENV-001", "Generic Secret in .env file", "HIGH",
        _r(r"^[A-Z_]{4,}(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|AUTH)\s*=\s*.{4,}$", re.M),
        "Secret in .env file — verify that it is not committed",
        "Add .env to .gitignore. Use .env.example without real values."),

    SecretRule("PRIV-001", "Private IP with credentials", "MEDIUM",
        _r(r"(?i)(?:user|username|login)\s*[=:]\s*['\"]?(\w+)['\"]?\s*[,\n]+\s*(?:pass|password|pwd)\s*[=:]\s*['\"]?([^'\"{\s]{4,})['\"]?"),
        "Username+password combination in source code",
        "Separate credentials from source code. Use a secrets manager."),

    # ── Entropy-based (high entropy strings) ──────────────────────────────
    SecretRule("ENT-001", "High Entropy String (possible secret)", "LOW",
        _r(r'''(?i)(?:key|secret|token|password|auth)\s*[=:]\s*['"]([a-zA-Z0-9+/=_\-]{32,})['"]\s'''),
        "High-entropy string in credential context",
        "Manually verify whether it is a real secret. Move it to an environment variable."),
]


# ══════════════════════════════════════════════════════════════════════════════
# FILE EXTENSIONS TO SCAN / SKIP
# ══════════════════════════════════════════════════════════════════════════════

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".php", ".go",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh", ".ps1", ".psm1",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".env", ".env.local", ".env.production", ".properties", ".xml",
    ".tf", ".tfvars", ".hcl",  # Terraform
    ".dockerfile", "Dockerfile",
    ".gradle", ".maven",
    ".txt", ".md", ".rst",
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
    "coverage", ".coverage", "htmlcov", "eggs", ".eggs",
}

SKIP_FILES_PATTERNS = [
    re.compile(r".*\.min\.(js|css)$"),
    re.compile(r".*\.map$"),
    re.compile(r".*\.lock$"),
    re.compile(r".*test.*fixture.*", re.I),
]

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecretFinding:
    rule_id:     str
    rule_name:   str
    severity:    str
    filepath:    str
    line_number: int
    line_content:str
    matched:     str
    description: str
    remediation: str
    commit:      Optional[str] = None
    author:      Optional[str] = None
    date:        Optional[str] = None

    def redacted_match(self) -> str:
        """Show only the first 6 characters of the secret."""
        m = self.matched.strip("'\"`")
        if len(m) > 8:
            return m[:6] + "..." + m[-2:] + f" ({len(m)} chars)"
        return "***"


@dataclass
class ScanReport:
    target:       str
    scan_type:    str
    timestamp:    str
    files_scanned:int
    findings:     List[SecretFinding]
    by_severity:  dict
    by_rule:      dict
    risk_score:   int

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ══════════════════════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _is_likely_false_positive(rule: SecretRule, match_str: str, line: str) -> bool:
    """Filter obvious false positives."""
    line_lower = line.lower()
    # Comments / examples
    if any(kw in line_lower for kw in ["example", "placeholder", "your_", "<your", "xxx", "changeme", "todo"]):
        return True
    # Rule-specific false-positive hints
    for hint in rule.false_positive_hints:
        if hint.upper() in match_str.upper():
            return True
    # Tests
    if re.search(r"(?i)(test|mock|fake|dummy|fixture)", line):
        return True
    return False


def scan_content(content: str, filepath: str,
                 rules: List[SecretRule] = None) -> List[SecretFinding]:
    """Scan file content against all rules."""
    rules    = rules or SECRET_RULES
    findings = []
    lines    = content.splitlines()

    # Deduplication by (rule_id, line)
    seen = set()

    for rule in rules:
        for m in rule.pattern.finditer(content):
            # Calculate line number
            line_num = content[:m.start()].count("\n") + 1
            if line_num > len(lines):
                continue
            line     = lines[line_num - 1]
            match_str = m.group(0)

            dedup_key = (rule.id, line_num, filepath)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            if _is_likely_false_positive(rule, match_str, line):
                continue

            # Redact line for output
            redacted_line = line.strip()[:120]

            findings.append(SecretFinding(
                rule_id     = rule.id,
                rule_name   = rule.name,
                severity    = rule.severity,
                filepath    = filepath,
                line_number = line_num,
                line_content= redacted_line,
                matched     = match_str[:80],
                description = rule.description,
                remediation = rule.remediation,
            ))

    return findings


def scan_file(filepath: Path, rules: List[SecretRule] = None) -> List[SecretFinding]:
    """Scan a single file."""
    # Check extension
    if filepath.suffix.lower() not in SCAN_EXTENSIONS and filepath.name not in SCAN_EXTENSIONS:
        return []
    # Check skip patterns
    if any(p.match(str(filepath)) for p in SKIP_FILES_PATTERNS):
        return []
    # Check size
    try:
        if filepath.stat().st_size > MAX_FILE_SIZE:
            return []
        content = filepath.read_text(errors="replace")
    except (PermissionError, OSError):
        return []

    return scan_content(content, str(filepath), rules)


def scan_directory(path: Path, rules: List[SecretRule] = None,
                   verbose: bool = False) -> tuple[List[SecretFinding], int]:
    """Recursively scan a directory."""
    all_findings: List[SecretFinding] = []
    files_scanned = 0

    for filepath in path.rglob("*"):
        # Ignore excluded directories
        if any(skip in filepath.parts for skip in SKIP_DIRS):
            continue
        if not filepath.is_file():
            continue

        findings = scan_file(filepath, rules)
        files_scanned += 1

        if findings:
            all_findings.extend(findings)
            if verbose:
                for f in findings:
                    sev_col = {"CRITICAL": C.RED, "HIGH": C.YELLOW,
                               "MEDIUM": C.CYAN, "LOW": C.DIM}.get(f.severity, "")
                    print(f"  {sev_col}[{f.severity}]{C.RESET} {f.filepath}:{f.line_number} — {f.rule_name}")

    return all_findings, files_scanned


# ══════════════════════════════════════════════════════════════════════════════
# GIT HISTORY SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def is_git_repo(path: Path) -> bool:
    return (path / ".git").exists() or (path / "HEAD").exists()


def get_git_log(repo_path: Path, max_commits: int = 100) -> List[dict]:
    """Get a list of commits with hash, author, and date."""
    try:
        result = subprocess.run(
            ["git", "log", f"--max-count={max_commits}",
             "--pretty=format:%H|%an|%ae|%ai|%s"],
            cwd=repo_path, capture_output=True, text=True, timeout=30
        )
        commits = []
        for line in result.stdout.splitlines():
            parts = line.split("|", 4)
            if len(parts) >= 4:
                commits.append({
                    "hash":    parts[0],
                    "author":  parts[1],
                    "email":   parts[2],
                    "date":    parts[3][:10],
                    "subject": parts[4] if len(parts) > 4 else "",
                })
        return commits
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def get_commit_diff(repo_path: Path, commit_hash: str) -> str:
    """Get the diff for a specific commit."""
    try:
        result = subprocess.run(
            ["git", "show", "--no-color", "--diff-filter=A", commit_hash],
            cwd=repo_path, capture_output=True, text=True, timeout=15
        )
        return result.stdout
    except Exception:
        return ""


def scan_git_history(repo_path: Path, max_commits: int = 50,
                     rules: List[SecretRule] = None,
                     verbose: bool = False) -> List[SecretFinding]:
    """Scan git history for secrets in previous commits."""
    if not is_git_repo(repo_path):
        print(f"  {C.YELLOW}Not a git repository.{C.RESET}")
        return []

    commits = get_git_log(repo_path, max_commits)
    if not commits:
        return []

    print(f"  {C.DIM}Analyzing {len(commits)} commits...{C.RESET}")
    all_findings: List[SecretFinding] = []

    for commit in commits:
        diff = get_commit_diff(repo_path, commit["hash"])
        if not diff:
            continue

        # Added lines only (+)
        added_lines = "\n".join(
            line[1:] for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )

        findings = scan_content(added_lines, f"[git:{commit['hash'][:8]}]", rules)
        for f in findings:
            f.commit = commit["hash"]
            f.author = f"{commit['author']} <{commit['email']}>"
            f.date   = commit["date"]
            if verbose:
                sev_col = {"CRITICAL": C.RED, "HIGH": C.YELLOW}.get(f.severity, C.DIM)
                print(f"  {sev_col}[{f.severity}]{C.RESET} commit {commit['hash'][:8]} "
                      f"({commit['date']}) — {f.rule_name}")
        all_findings.extend(findings)

    return all_findings


# ══════════════════════════════════════════════════════════════════════════════
# REPORT BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_report(target: str, scan_type: str,
                 findings: List[SecretFinding], files_scanned: int) -> ScanReport:
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_rule: dict = {}

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_rule[f.rule_id]      = by_rule.get(f.rule_id, 0) + 1

    score_weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2}
    risk = min(sum(score_weights.get(f.severity, 0) for f in findings), 100)

    return ScanReport(
        target        = target,
        scan_type     = scan_type,
        timestamp     = datetime.now().isoformat(),
        files_scanned = files_scanned,
        findings      = findings,
        by_severity   = by_severity,
        by_rule       = by_rule,
        risk_score    = risk,
    )


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEP  = "━" * 72
SEP2 = "═" * 72
SEV_COL = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN, "LOW": C.DIM}


def print_finding(f: SecretFinding, show_line: bool = True) -> None:
    col = SEV_COL.get(f.severity, "")
    print(f"\n{SEP}")
    print(f"  {col}{C.BOLD}[{f.severity}]{C.RESET} {f.rule_name}  "
          f"{C.DIM}({f.rule_id}){C.RESET}")
    print(f"  {C.DIM}File    :{C.RESET} {f.filepath}:{f.line_number}")
    if f.commit:
        print(f"  {C.DIM}Commit  :{C.RESET} {f.commit[:12]} | {f.author} | {f.date}")
    if show_line:
        print(f"  {C.DIM}Line    :{C.RESET} {C.YELLOW}{f.line_content[:100]}{C.RESET}")
    print(f"  {C.DIM}Desc.   :{C.RESET} {f.description}")
    print(f"  {C.DIM}Fix     :{C.RESET} {f.remediation[:100]}")


def print_summary(report: ScanReport) -> None:
    score_col = C.RED if report.risk_score >= 60 else C.YELLOW if report.risk_score >= 30 else C.GREEN
    bar = "█" * (report.risk_score // 5) + "░" * (20 - report.risk_score // 5)

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}SECRETS SCAN SUMMARY{C.RESET}")
    print(SEP2)
    print(f"  Target        : {report.target}")
    print(f"  Scan type     : {report.scan_type}")
    print(f"  Files scanned : {report.files_scanned:,}")
    print(f"  Total findings: {len(report.findings)}")
    print(SEP)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = report.by_severity.get(sev, 0)
        if count:
            col = SEV_COL.get(sev, "")
            print(f"  {col}{sev:<10}{C.RESET} {'█' * min(count, 30)} {count}")
    print(SEP)
    print(f"  Risk Score : {score_col}{C.BOLD}{report.risk_score}/100{C.RESET}  [{bar}]")
    print(SEP2)

    if report.findings:
        print(f"\n  {C.RED}⚠  ACTION REQUIRED:{C.RESET}")
        print(f"  1. IMMEDIATELY revoke all exposed CRITICAL and HIGH secrets")
        print(f"  2. Assume the secrets are compromised (even without evidence)")
        print(f"  3. Add .env, *.key, *.pem to .gitignore")
        print(f"  4. Use git-filter-repo or BFG to remove them from git history")
        print(f"  5. Implement pre-commit hooks to prevent future leaks")
    else:
        print(f"\n  {C.GREEN}✅ No secrets detected.{C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="secrets-scanner",
        description="Secrets Scanner — files, directories, and git history"
    )
    parser.add_argument("target",
        help="File, directory, or git repository to analyze")
    parser.add_argument("--git",
        action="store_true",
        help="Include git history scan (commits)")
    parser.add_argument("--max-commits", type=int, default=50,
        help="Maximum number of commits to analyze (default: 50)")
    parser.add_argument("--severity",
        choices=["CRITICAL","HIGH","MEDIUM","LOW"],
        help="Filter by minimum severity")
    parser.add_argument("-v","--verbose",
        action="store_true", help="Detailed output during the scan")
    parser.add_argument("--no-banner",
        action="store_true")
    parser.add_argument("--json",
        action="store_true", dest="json_out")
    parser.add_argument("-o","--output",
        help="Save JSON report to file")
    parser.add_argument("--list-rules",
        action="store_true", help="List all available rules")
    parser.add_argument("--version",
        action="version", version=f"secrets-scanner {__version__}")

    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    if args.list_rules:
        print(f"\n  {C.BOLD}Available rules ({len(SECRET_RULES)}):{C.RESET}\n")
        for rule in SECRET_RULES:
            col = SEV_COL.get(rule.severity, "")
            print(f"  {col}{rule.id:<10}{C.RESET} {rule.severity:<10} {rule.name}")
        return

    target = Path(args.target)
    if not target.exists():
        print(f"{C.RED}[ERROR] Path not found: {target}{C.RESET}")
        sys.exit(1)

    # Severity filter
    rules = SECRET_RULES
    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    if args.severity:
        min_idx = sev_order.index(args.severity)
        rules   = [r for r in SECRET_RULES if sev_order.index(r.severity) <= min_idx]

    all_findings:  List[SecretFinding] = []
    files_scanned  = 0
    scan_type      = "filesystem"

    # Filesystem scan
    print(f"\n  {C.DIM}Scanning {target}...{C.RESET}")
    if target.is_file():
        findings = scan_file(target, rules)
        all_findings.extend(findings)
        files_scanned = 1
    elif target.is_dir():
        findings, files_scanned = scan_directory(target, rules, verbose=args.verbose)
        all_findings.extend(findings)

    # Git history scan
    if args.git and target.is_dir():
        scan_type = "filesystem+git"
        print(f"\n  {C.DIM}Scanning git history ({args.max_commits} commits)...{C.RESET}")
        git_findings = scan_git_history(
            target, args.max_commits, rules, verbose=args.verbose
        )
        all_findings.extend(git_findings)

    # Build report
    report = build_report(str(target), scan_type, all_findings, files_scanned)

    # Output
    if args.json_out:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        sev_order_map = {s: i for i, s in enumerate(sev_order)}
        sorted_findings = sorted(
            all_findings,
            key=lambda f: sev_order_map.get(f.severity, 99)
        )
        for f in sorted_findings:
            print_finding(f)
        print_summary(report)

    if args.output:
        with open(args.output, "w") as fp:
            json.dump(report.to_dict(), fp, indent=2, default=str)
        print(f"\n  {C.GREEN}[✓] Report saved: {args.output}{C.RESET}")

    # CI/CD exit code
    sys.exit(2 if report.by_severity.get("CRITICAL", 0) > 0 else
             1 if report.by_severity.get("HIGH", 0) > 0 else 0)


if __name__ == "__main__":
    main()

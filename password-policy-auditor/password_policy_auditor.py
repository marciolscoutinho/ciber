#!/usr/bin/env python3
"""
password_policy_auditor.py — Password Policy Auditor v1.0.0
============================================================
Audits password policies on Linux/Windows systems and configuration
files against NIST SP 800-63B and CIS Benchmark.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 12/05/2024
Reqs.  : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations
import argparse, json, os, platform, re, subprocess, sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
 ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗
 ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
 ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
 ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
 ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
 ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝{C.RESET}
{C.DIM} v{__version__} — Password Policy Auditor | NIST SP 800-63B | CIS Benchmark | PAM{C.RESET}
"""

SEP  = "━"*68
SEP2 = "═"*68

# ══════════════════════════════════════════════════════════════════════════════
# NIST SP 800-63B REQUIREMENTS (2024)
# ══════════════════════════════════════════════════════════════════════════════

NIST_REQUIREMENTS = {
    "min_length":           8,    # absolute minimum — 15+ recommended
    "max_length":           64,   # minimum supported maximum — do not enforce max < 64
    "check_breached":       True, # check against breached-password lists
    "no_composition_rules": True, # NIST discourages rigid composition rules
    "no_hints":             True, # do not use password hints
    "no_security_questions":True, # do not use security questions
    "no_expiry":            False,# NIST 800-63B (Rev. 4 draft) removes periodic expiration
    "mfa_required":         True, # MFA strongly recommended
    "lockout_threshold":    10,   # lock after N failed attempts
    "lockout_duration":     30,   # lockout minutes (or progressive delay)
}

CIS_REQUIREMENTS = {
    "min_length":        14,   # CIS recommends 14+
    "max_age_days":      365,  # maximum annual rotation period
    "min_age_days":      1,    # prevent immediate reset
    "remember_history":  5,    # do not reuse the last N passwords
    "lockout_threshold": 5,    # lock after 5 attempts
    "lockout_duration":  30,   # minutes
    "complexity":        True, # uppercase, lowercase, digits, special characters
}

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PolicySetting:
    name:       str
    value:      str
    source:     str    # file or system
    is_secure:  bool
    severity:   str    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    expected:   str
    remediation:str
    reference:  str = ""

@dataclass
class UserAccount:
    username:    str
    uid:         int
    locked:      bool
    no_password: bool
    password_age:int    # days since last change
    max_age:     int    # days until expiration
    min_age:     int
    warn_days:   int
    last_changed:str
    shell:       str
    home:        str

@dataclass
class AuditReport:
    source:    str
    os_type:   str
    timestamp: str
    settings:  List[PolicySetting]
    accounts:  List[UserAccount]
    score:     float

    def to_dict(self) -> dict:
        return {
            "source": self.source, "os_type": self.os_type,
            "timestamp": self.timestamp, "score": self.score,
            "settings": [{
                "name": s.name, "value": s.value,
                "is_secure": s.is_secure, "severity": s.severity,
                "expected": s.expected,
            } for s in self.settings],
            "accounts_at_risk": [{
                "username": a.username, "locked": a.locked,
                "no_password": a.no_password, "password_age": a.password_age,
            } for a in self.accounts if a.no_password or (a.uid>=1000 and a.password_age > 365)],
        }

# ══════════════════════════════════════════════════════════════════════════════
# LINUX AUDITORS
# ══════════════════════════════════════════════════════════════════════════════

def _run(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""

def audit_pam_pwquality() -> List[PolicySetting]:
    """Audits /etc/security/pwquality.conf and /etc/pam.d/."""
    settings: List[PolicySetting] = []

    # Read pwquality.conf
    pwq_paths = ["/etc/security/pwquality.conf",
                 "/etc/pam.d/common-password"]
    pwq_content = ""
    for p in pwq_paths:
        if Path(p).exists():
            pwq_content += Path(p).read_text(errors="replace") + "\n"

    def get_pwq(key: str) -> Optional[str]:
        m = re.search(rf"^\s*{key}\s*=\s*(\S+)", pwq_content, re.M | re.I)
        return m.group(1) if m else None

    # minlen
    minlen = get_pwq("minlen")
    val    = int(minlen) if minlen and minlen.isdigit() else 0
    settings.append(PolicySetting(
        "Minimum length (minlen)", str(val) if val else "not defined",
        "pwquality.conf", val >= 14,
        "HIGH" if val < 8 else "MEDIUM" if val < 14 else "INFO",
        ">= 14 (CIS) / >= 8 (NIST minimum)",
        "Set 'minlen = 14' in /etc/security/pwquality.conf",
        "CIS 5.3.1 | NIST SP 800-63B"))

    # dcredit, ucredit, lcredit, ocredit
    for credit, label in [("dcredit","Digits"), ("ucredit","Uppercase"),
                            ("lcredit","Lowercase"), ("ocredit","Special characters")]:
        val_str = get_pwq(credit)
        if val_str:
            val = int(val_str) if val_str.lstrip("-").isdigit() else 0
            ok  = val <= -1  # -1 = require at least 1
        else:
            val_str = "not defined"; ok = False; val = 0
        settings.append(PolicySetting(
            f"Complexity: {label} ({credit})", val_str,
            "pwquality.conf", ok,
            "MEDIUM" if not ok else "INFO",
            "<= -1 (required)", f"Definir '{credit} = -1'",
            "CIS 5.3.1"))

    # maxrepeat
    maxrep = get_pwq("maxrepeat")
    val    = int(maxrep) if maxrep and maxrep.isdigit() else 0
    settings.append(PolicySetting(
        "Maximum repeated characters (maxrepeat)",
        maxrep or "not defined",
        "pwquality.conf", 0 < val <= 3,
        "LOW" if not (0 < val <= 3) else "INFO",
        "<= 3",
        "Set 'maxrepeat = 3'", "CIS 5.3.1"))

    # difok
    difok = get_pwq("difok")
    val   = int(difok) if difok and difok.isdigit() else 0
    settings.append(PolicySetting(
        "Minimum characters different from previous password (difok)",
        difok or "not defined",
        "pwquality.conf", val >= 7,
        "LOW" if val < 7 else "INFO",
        ">= 7",
        "Set 'difok = 7'", "CIS 5.3.1"))

    return settings


def audit_login_defs() -> List[PolicySetting]:
    """Audits /etc/login.defs."""
    settings: List[PolicySetting] = []
    login_defs = Path("/etc/login.defs")
    if not login_defs.exists():
        return settings

    content = login_defs.read_text(errors="replace")

    def get_val(key: str) -> Optional[str]:
        m = re.search(rf"^\s*{key}\s+(\S+)", content, re.M | re.I)
        return m.group(1) if m else None

    # PASS_MAX_DAYS
    pmd = get_val("PASS_MAX_DAYS")
    val = int(pmd) if pmd and pmd.isdigit() else 99999
    settings.append(PolicySetting(
        "Maximum password age in days (PASS_MAX_DAYS)",
        pmd or "not defined",
        "/etc/login.defs", val <= 365,
        "HIGH" if val > 365 else "INFO",
        "<= 365",
        "Set 'PASS_MAX_DAYS 365' in /etc/login.defs",
        "CIS 5.4.1.1"))

    # PASS_MIN_DAYS
    pmin = get_val("PASS_MIN_DAYS")
    val  = int(pmin) if pmin and pmin.isdigit() else 0
    settings.append(PolicySetting(
        "Minimum days before password change (PASS_MIN_DAYS)",
        pmin or "not defined",
        "/etc/login.defs", val >= 1,
        "LOW" if val < 1 else "INFO",
        ">= 1",
        "Set 'PASS_MIN_DAYS 1' in /etc/login.defs",
        "CIS 5.4.1.2"))

    # PASS_WARN_AGE
    pwa = get_val("PASS_WARN_AGE")
    val = int(pwa) if pwa and pwa.isdigit() else 0
    settings.append(PolicySetting(
        "Warning days before expiration (PASS_WARN_AGE)",
        pwa or "not defined",
        "/etc/login.defs", val >= 7,
        "LOW" if val < 7 else "INFO",
        ">= 7",
        "Set 'PASS_WARN_AGE 7' in /etc/login.defs",
        "CIS 5.4.1.3"))

    # PASS_MIN_LEN (login.defs)
    pml = get_val("PASS_MIN_LEN")
    val = int(pml) if pml and pml.isdigit() else 0
    settings.append(PolicySetting(
        "Minimum length (PASS_MIN_LEN)",
        pml or "not defined",
        "/etc/login.defs", val >= 14,
        "HIGH" if val < 8 else "MEDIUM" if val < 14 else "INFO",
        ">= 14",
        "Set 'PASS_MIN_LEN 14' in /etc/login.defs",
        "CIS 5.3.1"))

    # LOGIN_RETRIES
    lr  = get_val("LOGIN_RETRIES")
    val = int(lr) if lr and lr.isdigit() else 999
    settings.append(PolicySetting(
        "Login attempts (LOGIN_RETRIES)",
        lr or "not defined",
        "/etc/login.defs", val <= 5,
        "HIGH" if val > 10 else "MEDIUM" if val > 5 else "INFO",
        "<= 5",
        "Set 'LOGIN_RETRIES 5' in /etc/login.defs",
        "CIS 5.2.7"))

    # ENCRYPT_METHOD
    enc = get_val("ENCRYPT_METHOD")
    ok  = enc in ("SHA512", "YESCRYPT", "SHA256") if enc else False
    settings.append(PolicySetting(
        "Hash algorithm (ENCRYPT_METHOD)",
        enc or "not defined",
        "/etc/login.defs", ok,
        "CRITICAL" if enc in ("MD5","DES",None) else "INFO",
        "SHA512 or YESCRYPT",
        "Set 'ENCRYPT_METHOD SHA512' in /etc/login.defs",
        "CIS 5.3.4"))

    return settings


def audit_faillock() -> List[PolicySetting]:
    """Audits lockout configuration (faillock/pam_tally2)."""
    settings: List[PolicySetting] = []

    # /etc/security/faillock.conf (modern systems)
    fl_path = Path("/etc/security/faillock.conf")
    content = fl_path.read_text(errors="replace") if fl_path.exists() else ""

    # Check PAM as well
    pam_content = ""
    for p in ["/etc/pam.d/common-auth","/etc/pam.d/system-auth"]:
        if Path(p).exists():
            pam_content += Path(p).read_text(errors="replace")

    has_faillock = bool(content) or "faillock" in pam_content or "pam_tally" in pam_content

    settings.append(PolicySetting(
        "Account lockout configured (faillock/pam_tally)",
        "yes" if has_faillock else "no",
        "PAM / faillock.conf",
        has_faillock,
        "HIGH" if not has_faillock else "INFO",
        "yes",
        "Install and configure faillock: 'deny = 5' and 'unlock_time = 900'",
        "CIS 5.3.2"))

    # deny threshold
    if content:
        m = re.search(r"^\s*deny\s*=\s*(\d+)", content, re.M)
        if m:
            val = int(m.group(1))
            settings.append(PolicySetting(
                "Lockout threshold (deny)",
                str(val), "faillock.conf", val <= 5,
                "HIGH" if val > 10 else "MEDIUM" if val > 5 else "INFO",
                "<= 5",
                "Set 'deny = 5' in /etc/security/faillock.conf",
                "CIS 5.3.2"))

    return settings


def get_user_accounts() -> List[UserAccount]:
    """Reads /etc/passwd and /etc/shadow for account auditing."""
    accounts: List[UserAccount] = []
    try:
        passwd_lines = Path("/etc/passwd").read_text().splitlines()
    except Exception:
        return []

    shadow_data: Dict[str,Tuple] = {}
    try:
        for line in Path("/etc/shadow").read_text().splitlines():
            parts = line.split(":")
            if len(parts) >= 9:
                shadow_data[parts[0]] = (
                    parts[1],   # password hash
                    int(parts[2]) if parts[2].isdigit() else 0,   # last changed
                    int(parts[3]) if parts[3].isdigit() else 0,   # min days
                    int(parts[4]) if parts[4].isdigit() else 99999,# max days
                    int(parts[5]) if parts[5].isdigit() else 7,   # warn days
                )
    except Exception:
        pass

    for line in passwd_lines:
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username = parts[0]
        uid      = int(parts[2]) if parts[2].isdigit() else 0
        shell    = parts[6].strip()

        sh = shadow_data.get(username, ("",0,0,99999,7))
        pw_hash    = sh[0]
        last_chg   = sh[1]
        min_age    = sh[2]
        max_age    = sh[3]
        warn_days  = sh[4]

        # Calculate password age in days
        pw_age = 0
        last_changed = "unknown"
        if last_chg > 0:
            import time
            pw_age = int((time.time() / 86400) - last_chg)
            from datetime import datetime, timedelta
            last_changed = (datetime(1970,1,1) + timedelta(days=last_chg)).strftime("%Y-%m-%d")

        accounts.append(UserAccount(
            username    = username,
            uid         = uid,
            locked      = pw_hash.startswith(("!","*","!!","!!")),
            no_password = pw_hash in ("","*","!"),
            password_age= pw_age,
            max_age     = max_age,
            min_age     = min_age,
            warn_days   = warn_days,
            last_changed= last_changed,
            shell       = shell,
            home        = parts[5],
        ))

    return accounts


def audit_accounts(accounts: List[UserAccount]) -> List[PolicySetting]:
    """Generates findings based on user accounts."""
    settings: List[PolicySetting] = []

    # UID 0 accounts (root privileges) that are not root
    uid0_non_root = [a for a in accounts if a.uid == 0 and a.username != "root"]
    if uid0_non_root:
        settings.append(PolicySetting(
            "Non-root accounts with UID 0",
            ", ".join(a.username for a in uid0_non_root),
            "/etc/passwd",
            False, "CRITICAL",
            "none (only root should have UID 0)",
            "Change the UID of these accounts. Investigate their origin.",
            "CIS 6.2.5"))

    # Accounts without a password
    no_pw = [a for a in accounts if a.no_password and not a.locked and a.uid >= 1000]
    if no_pw:
        settings.append(PolicySetting(
            "User accounts without a password",
            ", ".join(a.username for a in no_pw),
            "/etc/shadow",
            False, "CRITICAL",
            "none",
            "Set a password or lock the account with 'passwd -l <user>'",
            "CIS 6.2.1"))

    # Very old passwords (> 365 days)
    old_pw = [a for a in accounts if a.uid >= 1000 and not a.locked
              and a.password_age > 365 and a.password_age < 99000]
    if old_pw:
        settings.append(PolicySetting(
            f"Old passwords (> 365 days) in {len(old_pw)} account(s)",
            ", ".join(a.username for a in old_pw[:5]),
            "/etc/shadow",
            False, "MEDIUM",
            "< 365 days",
            "Force password change: 'chage -d 0 <user>'",
            "CIS 5.4.1.1"))

    # System accounts with an interactive shell
    sys_with_shell = [a for a in accounts
                      if a.uid < 1000 and a.uid > 0
                      and a.shell not in ("/usr/sbin/nologin","/bin/false",
                                          "/sbin/nologin","false","nologin")]
    dangerous_sys = [a for a in sys_with_shell if a.username not in
                     ("sync","shutdown","halt","operator")]
    if dangerous_sys:
        settings.append(PolicySetting(
            "System accounts with an interactive shell",
            ", ".join(a.username for a in dangerous_sys[:5]),
            "/etc/passwd",
            False, "HIGH",
            "/usr/sbin/nologin or /bin/false",
            "usermod -s /usr/sbin/nologin <user>",
            "CIS 6.2.7"))

    return settings

# ══════════════════════════════════════════════════════════════════════════════
# DEMO DATA
# ══════════════════════════════════════════════════════════════════════════════

def generate_demo_settings() -> List[PolicySetting]:
    return [
        PolicySetting("Minimum length (minlen)","6","/etc/security/pwquality.conf",
            False,"HIGH",">=14","Definir 'minlen = 14'","CIS 5.3.1"),
        PolicySetting("Complexity: Digits (dcredit)","not defined","pwquality.conf",
            False,"MEDIUM","<= -1","Definir 'dcredit = -1'","CIS 5.3.1"),
        PolicySetting("Maximum password age (PASS_MAX_DAYS)","99999","/etc/login.defs",
            False,"HIGH","<= 365","Definir 'PASS_MAX_DAYS 365'","CIS 5.4.1.1"),
        PolicySetting("Account lockout configured","não","PAM",
            False,"HIGH","yes","Install faillock","CIS 5.3.2"),
        PolicySetting("Hash algorithm (ENCRYPT_METHOD)","MD5","/etc/login.defs",
            False,"CRITICAL","SHA512","Definir 'ENCRYPT_METHOD SHA512'","CIS 5.3.4"),
        PolicySetting("Minimum length (PASS_MIN_LEN)","6","/etc/login.defs",
            False,"MEDIUM",">=14","Definir 'PASS_MIN_LEN 14'","CIS 5.3.1"),
        PolicySetting("Login attempts (LOGIN_RETRIES)","10","/etc/login.defs",
            False,"MEDIUM","<= 5","Definir 'LOGIN_RETRIES 5'","CIS 5.2.7"),
    ]

# ══════════════════════════════════════════════════════════════════════════════
# SCORE & OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

def compute_score(settings: List[PolicySetting]) -> float:
    weights = {"CRITICAL":30,"HIGH":15,"MEDIUM":8,"LOW":3,"INFO":0}
    total   = sum(weights.get(s.severity,0) for s in settings)
    ok      = sum(weights.get(s.severity,0) for s in settings if s.is_secure)
    return round(ok/total*100, 1) if total else 100.0

SEV_COL = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN,"INFO":C.DIM}

def print_settings(settings: List[PolicySetting], show_ok: bool = False) -> None:
    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    for s in sorted(settings, key=lambda x: sev_order.index(x.severity)
                    if x.severity in sev_order else 99):
        if s.is_secure and not show_ok:
            continue
        icon = "✅" if s.is_secure else "❌"
        col  = SEV_COL.get(s.severity,"")
        print(f"\n  {icon} {col}[{s.severity}]{C.RESET} {C.BOLD}{s.name}{C.RESET}")
        print(f"     {C.DIM}Value  :{C.RESET} {C.YELLOW}{s.value}{C.RESET}")
        print(f"     {C.DIM}Expected:{C.RESET} {s.expected}")
        print(f"     {C.DIM}Source :{C.RESET} {s.source}")
        if not s.is_secure:
            print(f"     {C.DIM}Fix    :{C.RESET} {s.remediation}")
        if s.reference:
            print(f"     {C.DIM}Ref    :{C.RESET} {s.reference}")

def print_accounts(accounts: List[UserAccount]) -> None:
    risk = [a for a in accounts if a.no_password or
            (a.uid >= 1000 and not a.locked and a.password_age > 365)]
    if not risk:
        return
    print(f"\n{SEP}")
    print(f"  {C.BOLD}Accounts at Risk ({len(risk)}){C.RESET}")
    for a in risk[:10]:
        issues = []
        if a.no_password:    issues.append(f"{C.RED}NO PASSWORD{C.RESET}")
        if a.password_age > 365 and a.password_age < 99000:
            issues.append(f"{C.YELLOW}password {a.password_age}d old{C.RESET}")
        print(f"  {C.DIM}{a.username:<20}{C.RESET} UID:{a.uid}  "
              + "  ".join(issues))

def print_summary(report: AuditReport) -> None:
    score_col = C.GREEN if report.score>=80 else C.YELLOW if report.score>=60 else C.RED
    bar_len   = int(report.score/100*40)
    bar       = "█"*bar_len + "░"*(40-bar_len)
    by_sev: Dict[str,int] = {}
    for s in report.settings:
        if not s.is_secure:
            by_sev[s.severity] = by_sev.get(s.severity,0)+1

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}PASSWORD POLICY AUDIT SUMMARY{C.RESET}")
    print(f"  System   : {report.os_type}")
    print(f"  Checks   : {len(report.settings)}")
    print(SEP)
    print(f"  {score_col}{C.BOLD}Score: {report.score}/100{C.RESET}  [{bar}]")
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
        count = by_sev.get(sev,0)
        if count:
            col = SEV_COL.get(sev,"")
            print(f"  {col}{sev:<10}{C.RESET} {'█'*min(count,20)} {count}")
    print(SEP2)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="password-policy-auditor",
        description="Password Policy Auditor — NIST SP 800-63B | CIS Benchmark")
    parser.add_argument("--demo",      action="store_true", help="Demo mode")
    parser.add_argument("--accounts",  action="store_true", help="Audit user accounts")
    parser.add_argument("--show-ok",   action="store_true", help="Also show passing checks")
    parser.add_argument("-o","--output", help="Save Markdown report")
    parser.add_argument("--json",      action="store_true", dest="json_out")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version",   action="version", version=f"password-policy-auditor {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    os_type = platform.system()
    source  = "local system"

    if args.demo or os_type == "Windows":
        print(f"  {C.YELLOW}Using demo configuration (insecure Linux).{C.RESET}")
        settings = generate_demo_settings()
        accounts = []
        source   = "demo"
    else:
        print(f"  {C.DIM}Auditing Linux system...{C.RESET}")
        settings  = []
        settings += audit_pam_pwquality()
        settings += audit_login_defs()
        settings += audit_faillock()
        accounts  = get_user_accounts() if args.accounts else []
        if accounts:
            settings += audit_accounts(accounts)

    score  = compute_score(settings)
    report = AuditReport(source, os_type, datetime.now().isoformat(),
                          settings, accounts, score)

    if args.json_out:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_settings(settings, show_ok=args.show_ok)
        if accounts:
            print_accounts(accounts)
        print_summary(report)

    if args.output:
        lines = [f"# 🔑 Password Policy Audit Report",
                 f"**Score:** {score}/100 | **Date:** {datetime.now().strftime('%Y-%m-%d')}",
                 f"","## Findings",""]
        for s in settings:
            if not s.is_secure:
                lines.append(f"- **[{s.severity}]** {s.name}: `{s.value}` → {s.remediation}")
        Path(args.output).write_text("\n".join(lines), encoding="utf-8")
        print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    critical = sum(1 for s in settings if not s.is_secure and s.severity=="CRITICAL")
    sys.exit(2 if critical > 0 else 0)

if __name__ == "__main__":
    main()

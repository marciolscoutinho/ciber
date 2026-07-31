#!/usr/bin/env python3
"""
hardening_check.py — Linux CIS Benchmark Checker v1.0.0
=========================================================
Checks compliance with the CIS Benchmark for Linux (Ubuntu/Debian/RHEL).
Generates a before/after security score with a detailed report.

Author      : Marcio Coutinho — Cybersecurity Specialist
Date        : 20/10/2023
Reqs.  : Python 3.8+ | Run as root for complete checks
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

__version__ = "1.0.0"

# ══════════════════════════════════════════════════════════════════════════════
# ANSI COLOURS
# ══════════════════════════════════════════════════════════════════════════════

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

class Status(str, Enum):
    PASS    = "PASS"
    FAIL    = "FAIL"
    WARN    = "WARN"
    SKIP    = "SKIP"   # requires root or is not applicable


STATUS_COLOURS = {
    Status.PASS: C.GREEN,
    Status.FAIL: C.RED,
    Status.WARN: C.YELLOW,
    Status.SKIP: C.DIM,
}

STATUS_ICONS = {
    Status.PASS: "✅",
    Status.FAIL: "❌",
    Status.WARN: "⚠️ ",
    Status.SKIP: "⏭️ ",
}

SCORE_WEIGHTS = {
    Status.PASS: 1,
    Status.FAIL: 0,
    Status.WARN: 0.5,
    Status.SKIP: 0,
}


@dataclass
class CheckResult:
    cis_id:      str
    title:       str
    status:      Status
    detail:      str
    remediation: str
    section:     str
    scored:      bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class HardeningReport:
    hostname:    str
    os_info:     str
    scan_time:   str
    results:     List[CheckResult]
    score:       float          # 0–100
    pass_count:  int
    fail_count:  int
    warn_count:  int
    skip_count:  int

    def to_dict(self) -> dict:
        return {
            "meta": {
                "hostname":  self.hostname,
                "os":        self.os_info,
                "scan_time": self.scan_time,
                "version":   __version__,
            },
            "score": {
                "overall":  round(self.score, 1),
                "pass":     self.pass_count,
                "fail":     self.fail_count,
                "warn":     self.warn_count,
                "skip":     self.skip_count,
            },
            "results": [r.to_dict() for r in self.results],
        }


# ══════════════════════════════════════════════════════════════════════════════
# HELPER UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def run(cmd: str) -> tuple[int, str]:
    """Run a shell command, return (returncode, stdout+stderr)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:
        return -1, str(e)


def file_contains(path: str, pattern: str) -> bool:
    try:
        with open(path, errors="replace") as f:
            return bool(re.search(pattern, f.read(), re.M))
    except FileNotFoundError:
        return False


def file_exists(path: str) -> bool:
    return Path(path).exists()


def is_root() -> bool:
    return os.geteuid() == 0


def get_os_info() -> str:
    _, out = run("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    return out or "Unknown Linux"


def get_hostname() -> str:
    _, out = run("hostname")
    return out or "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# CIS BENCHMARK CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def check(cis_id: str, title: str, section: str,
          remediation: str, scored: bool = True) -> Callable:
    """Decorator to register a CIS check function."""
    def decorator(fn: Callable) -> Callable:
        fn._cis_meta = {
            "cis_id": cis_id, "title": title,
            "section": section, "remediation": remediation, "scored": scored,
        }
        return fn
    return decorator


# ── SECTION 1 — Initial Setup ─────────────────────────────────────────────────

@check("1.1.1", "Ensure mounting of cramfs filesystems is disabled",
       "1 — Filesystem Configuration",
       "Add 'install cramfs /bin/true' to /etc/modprobe.d/disable-filesystems.conf")
def cis_1_1_1() -> CheckResult:
    rc, out = run("modprobe -n -v cramfs 2>&1")
    status = Status.PASS if "install /bin/true" in out or rc != 0 else Status.FAIL
    return CheckResult("1.1.1", "cramfs filesystem disabled", status,
                       out[:200], cis_1_1_1._cis_meta["remediation"],
                       cis_1_1_1._cis_meta["section"])


@check("1.3.1", "Ensure AIDE is installed",
       "1 — Filesystem Configuration",
       "apt install aide && aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db")
def cis_1_3_1() -> CheckResult:
    rc, _ = run("which aide || dpkg -l aide 2>/dev/null | grep -q '^ii'")
    rc2, _ = run("dpkg -l aide 2>/dev/null | grep '^ii'")
    status = Status.PASS if rc == 0 or rc2 == 0 else Status.FAIL
    detail = "AIDE is installed." if status == Status.PASS else "AIDE was not found."
    return CheckResult("1.3.1", "AIDE installed", status, detail,
                       cis_1_3_1._cis_meta["remediation"],
                       cis_1_3_1._cis_meta["section"])


@check("1.4.1", "Ensure permissions on bootloader config are configured",
       "1 — Secure Boot Settings",
       "chown root:root /boot/grub/grub.cfg && chmod og-rwx /boot/grub/grub.cfg")
def cis_1_4_1() -> CheckResult:
    grub_paths = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
    for path in grub_paths:
        if Path(path).exists():
            st = os.stat(path)
            mode = stat.S_IMODE(st.st_mode)
            owner_ok = st.st_uid == 0
            perms_ok  = not (mode & (stat.S_IRWXG | stat.S_IRWXO))
            status = Status.PASS if owner_ok and perms_ok else Status.FAIL
            detail = f"{path}: mode={oct(mode)}, uid={st.st_uid}"
            return CheckResult("1.4.1", "Bootloader config permissions", status, detail,
                               cis_1_4_1._cis_meta["remediation"],
                               cis_1_4_1._cis_meta["section"])
    return CheckResult("1.4.1", "Bootloader config permissions", Status.SKIP,
                       "grub.cfg file was not found", "",
                       cis_1_4_1._cis_meta["section"])


# ── SECTION 2 — Services ──────────────────────────────────────────────────────

@check("2.1.1", "Ensure xinetd is not installed",
       "2 — Services",
       "apt purge xinetd")
def cis_2_1_1() -> CheckResult:
    rc, _ = run("dpkg -l xinetd 2>/dev/null | grep '^ii'")
    status = Status.PASS if rc != 0 else Status.FAIL
    detail = "xinetd is not installed." if status == Status.PASS else "xinetd is installed and should be removed."
    return CheckResult("2.1.1", "xinetd not installed", status, detail,
                       cis_2_1_1._cis_meta["remediation"],
                       cis_2_1_1._cis_meta["section"])


@check("2.2.1", "Ensure time synchronization is in use",
       "2 — Services",
       "apt install chrony && systemctl enable chrony --now")
def cis_2_2_1() -> CheckResult:
    rc1, _ = run("systemctl is-active chronyd 2>/dev/null")
    rc2, _ = run("systemctl is-active systemd-timesyncd 2>/dev/null")
    rc3, _ = run("systemctl is-active ntpd 2>/dev/null")
    status = Status.PASS if any(r == 0 for r in (rc1, rc2, rc3)) else Status.FAIL
    detail = "Time synchronization is active." if status == Status.PASS else "No active NTP/chrony service was found."
    return CheckResult("2.2.1", "Time synchronization active", status, detail,
                       cis_2_2_1._cis_meta["remediation"],
                       cis_2_2_1._cis_meta["section"])


# ── SECTION 3 — Network ────────────────────────────────────────────────────────

@check("3.1.1", "Ensure IP forwarding is disabled",
       "3 — Network Configuration",
       "echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-hardening.conf && sysctl -p")
def cis_3_1_1() -> CheckResult:
    _, out = run("sysctl net.ipv4.ip_forward")
    status = Status.PASS if "= 0" in out else Status.FAIL
    return CheckResult("3.1.1", "IP forwarding disabled", status, out,
                       cis_3_1_1._cis_meta["remediation"],
                       cis_3_1_1._cis_meta["section"])


@check("3.2.1", "Ensure source routed packets are not accepted",
       "3 — Network Configuration",
       "echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.d/99-hardening.conf")
def cis_3_2_1() -> CheckResult:
    _, out = run("sysctl net.ipv4.conf.all.accept_source_route")
    status = Status.PASS if "= 0" in out else Status.FAIL
    return CheckResult("3.2.1", "Source routed packets disabled", status, out,
                       cis_3_2_1._cis_meta["remediation"],
                       cis_3_2_1._cis_meta["section"])


@check("3.3.1", "Ensure ICMP redirects are not accepted",
       "3 — Network Configuration",
       "echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/99-hardening.conf")
def cis_3_3_1() -> CheckResult:
    _, out = run("sysctl net.ipv4.conf.all.accept_redirects")
    status = Status.PASS if "= 0" in out else Status.FAIL
    return CheckResult("3.3.1", "ICMP redirects disabled", status, out,
                       cis_3_3_1._cis_meta["remediation"],
                       cis_3_3_1._cis_meta["section"])


# ── SECTION 4 — Logging & Auditing ────────────────────────────────────────────

@check("4.1.1", "Ensure auditd is installed",
       "4 — Logging and Auditing",
       "apt install auditd && systemctl enable auditd --now")
def cis_4_1_1() -> CheckResult:
    rc, _ = run("dpkg -l auditd 2>/dev/null | grep '^ii'")
    status = Status.PASS if rc == 0 else Status.FAIL
    detail = "auditd is installed." if status == Status.PASS else "auditd is not installed."
    return CheckResult("4.1.1", "auditd installed", status, detail,
                       cis_4_1_1._cis_meta["remediation"],
                       cis_4_1_1._cis_meta["section"])


@check("4.1.2", "Ensure auditd service is running",
       "4 — Logging and Auditing",
       "systemctl enable auditd --now")
def cis_4_1_2() -> CheckResult:
    rc, out = run("systemctl is-active auditd")
    status = Status.PASS if rc == 0 and "active" in out else Status.FAIL
    return CheckResult("4.1.2", "auditd service running", status, out,
                       cis_4_1_2._cis_meta["remediation"],
                       cis_4_1_2._cis_meta["section"])


@check("4.2.1", "Ensure rsyslog is installed and running",
       "4 — Logging and Auditing",
       "apt install rsyslog && systemctl enable rsyslog --now")
def cis_4_2_1() -> CheckResult:
    rc1, _ = run("dpkg -l rsyslog 2>/dev/null | grep '^ii'")
    rc2, out = run("systemctl is-active rsyslog")
    status = Status.PASS if rc1 == 0 and "active" in out else Status.FAIL
    return CheckResult("4.2.1", "rsyslog installed and running", status, out,
                       cis_4_2_1._cis_meta["remediation"],
                       cis_4_2_1._cis_meta["section"])


# ── SECTION 5 — Access & Authentication ───────────────────────────────────────

@check("5.1.1", "Ensure cron daemon is running",
       "5 — Access, Authentication and Authorization",
       "systemctl enable cron --now")
def cis_5_1_1() -> CheckResult:
    rc, out = run("systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null")
    status = Status.PASS if rc == 0 else Status.FAIL
    return CheckResult("5.1.1", "cron daemon running", status, out,
                       cis_5_1_1._cis_meta["remediation"],
                       cis_5_1_1._cis_meta["section"])


@check("5.2.1", "Ensure SSH root login is disabled",
       "5 — Access, Authentication and Authorization",
       "Set 'PermitRootLogin no' in /etc/ssh/sshd_config && run systemctl reload sshd")
def cis_5_2_1() -> CheckResult:
    enabled = file_contains("/etc/ssh/sshd_config", r"^\s*PermitRootLogin\s+yes")
    status  = Status.FAIL if enabled else Status.PASS
    detail  = "PermitRootLogin yes was found." if enabled else "SSH root login is disabled."
    return CheckResult("5.2.1", "SSH root login disabled", status, detail,
                       cis_5_2_1._cis_meta["remediation"],
                       cis_5_2_1._cis_meta["section"])


@check("5.2.2", "Ensure SSH PermitEmptyPasswords is disabled",
       "5 — Access, Authentication and Authorization",
       "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config")
def cis_5_2_2() -> CheckResult:
    bad = file_contains("/etc/ssh/sshd_config", r"^\s*PermitEmptyPasswords\s+yes")
    status = Status.FAIL if bad else Status.PASS
    detail = "Empty passwords are allowed!" if bad else "PermitEmptyPasswords is set to no, or the secure default is in effect."
    return CheckResult("5.2.2", "SSH empty passwords disabled", status, detail,
                       cis_5_2_2._cis_meta["remediation"],
                       cis_5_2_2._cis_meta["section"])


@check("5.2.3", "Ensure SSH MaxAuthTries is set to 4 or less",
       "5 — Access, Authentication and Authorization",
       "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config")
def cis_5_2_3() -> CheckResult:
    _, content = run("grep -i MaxAuthTries /etc/ssh/sshd_config")
    m = re.search(r"MaxAuthTries\s+(\d+)", content, re.I)
    if m:
        val    = int(m.group(1))
        status = Status.PASS if val <= 4 else Status.FAIL
        detail = f"MaxAuthTries = {val}"
    else:
        status = Status.WARN
        detail = "MaxAuthTries is not configured (the default is 6)."
    return CheckResult("5.2.3", "SSH MaxAuthTries <= 4", status, detail,
                       cis_5_2_3._cis_meta["remediation"],
                       cis_5_2_3._cis_meta["section"])


@check("5.3.1", "Ensure password creation requirements are configured",
       "5 — Access, Authentication and Authorization",
       "apt install libpam-pwquality && set minlen=14 in /etc/security/pwquality.conf")
def cis_5_3_1() -> CheckResult:
    rc, _ = run("dpkg -l libpam-pwquality 2>/dev/null | grep '^ii'")
    if rc != 0:
        return CheckResult("5.3.1", "Password complexity configured", Status.FAIL,
                           "libpam-pwquality is not installed.",
                           cis_5_3_1._cis_meta["remediation"],
                           cis_5_3_1._cis_meta["section"])
    has_minlen = file_contains("/etc/security/pwquality.conf", r"minlen\s*=\s*1[4-9]|minlen\s*=\s*[2-9]\d")
    status = Status.PASS if has_minlen else Status.WARN
    detail = "minlen >= 14 is configured." if has_minlen else "minlen is below 14 or is not configured."
    return CheckResult("5.3.1", "Password complexity configured", status, detail,
                       cis_5_3_1._cis_meta["remediation"],
                       cis_5_3_1._cis_meta["section"])


@check("5.4.1", "Ensure default file creation mask is configured",
       "5 — Access, Authentication and Authorization",
       "Set 'umask 027' in /etc/bash.bashrc and /etc/profile")
def cis_5_4_1() -> CheckResult:
    found = (
        file_contains("/etc/bash.bashrc", r"umask\s+0?27") or
        file_contains("/etc/profile",     r"umask\s+0?27")
    )
    status = Status.PASS if found else Status.WARN
    detail = "umask 027 is configured." if found else "umask 027 was not found in the profile files."
    return CheckResult("5.4.1", "Default umask 027 configured", status, detail,
                       cis_5_4_1._cis_meta["remediation"],
                       cis_5_4_1._cis_meta["section"])


# ── SECTION 6 — System Maintenance ────────────────────────────────────────────

@check("6.1.1", "Ensure permissions on /etc/passwd are configured",
       "6 — System Maintenance",
       "chown root:root /etc/passwd && chmod 644 /etc/passwd")
def cis_6_1_1() -> CheckResult:
    st     = os.stat("/etc/passwd")
    mode   = stat.S_IMODE(st.st_mode)
    ok     = st.st_uid == 0 and mode == 0o644
    status = Status.PASS if ok else Status.FAIL
    detail = f"/etc/passwd: mode={oct(mode)}, uid={st.st_uid}"
    return CheckResult("6.1.1", "/etc/passwd permissions 644", status, detail,
                       cis_6_1_1._cis_meta["remediation"],
                       cis_6_1_1._cis_meta["section"])


@check("6.1.2", "Ensure permissions on /etc/shadow are configured",
       "6 — System Maintenance",
       "chown root:shadow /etc/shadow && chmod o-rwx,g-wx /etc/shadow")
def cis_6_1_2() -> CheckResult:
    try:
        st   = os.stat("/etc/shadow")
        mode = stat.S_IMODE(st.st_mode)
        # Must be 640 or more restrictive
        others_ok = not (mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH))
        root_own  = st.st_uid == 0
        status    = Status.PASS if others_ok and root_own else Status.FAIL
        detail    = f"/etc/shadow: mode={oct(mode)}, uid={st.st_uid}"
    except PermissionError:
        status = Status.SKIP
        detail = "Insufficient permissions to perform this check (run as root)."
    return CheckResult("6.1.2", "/etc/shadow permissions", status, detail,
                       cis_6_1_2._cis_meta["remediation"],
                       cis_6_1_2._cis_meta["section"])


@check("6.2.1", "Ensure no accounts have empty passwords",
       "6 — System Maintenance",
       "Set a password for every account: passwd <username>")
def cis_6_2_1() -> CheckResult:
    if not is_root():
        return CheckResult("6.2.1", "No empty passwords", Status.SKIP,
                           "Requires root.", cis_6_2_1._cis_meta["remediation"],
                           cis_6_2_1._cis_meta["section"])
    rc, out = run("awk -F: '($2 == \"\" ) {print $1}' /etc/shadow")
    status  = Status.PASS if not out.strip() else Status.FAIL
    detail  = "No accounts have an empty password." if not out.strip() else f"Accounts without a password: {out}"
    return CheckResult("6.2.1", "No empty passwords", status, detail,
                       cis_6_2_1._cis_meta["remediation"],
                       cis_6_2_1._cis_meta["section"])


# ══════════════════════════════════════════════════════════════════════════════
# RUNNER & REPORT
# ══════════════════════════════════════════════════════════════════════════════

ALL_CHECKS = [
    cis_1_1_1, cis_1_3_1, cis_1_4_1,
    cis_2_1_1, cis_2_2_1,
    cis_3_1_1, cis_3_2_1, cis_3_3_1,
    cis_4_1_1, cis_4_1_2, cis_4_2_1,
    cis_5_1_1, cis_5_2_1, cis_5_2_2, cis_5_2_3, cis_5_3_1, cis_5_4_1,
    cis_6_1_1, cis_6_1_2, cis_6_2_1,
]


def run_checks() -> HardeningReport:
    results = []
    for fn in ALL_CHECKS:
        try:
            result = fn()
        except Exception as e:
            meta = fn._cis_meta
            result = CheckResult(
                meta["cis_id"], meta["title"], Status.SKIP,
                f"Execution error: {e}", meta["remediation"], meta["section"],
            )
        results.append(result)
        icon   = STATUS_ICONS[result.status]
        colour = STATUS_COLOURS[result.status]
        print(f"  {icon} {colour}[{result.cis_id}]{C.RESET} {result.title}")

    scored = [r for r in results if r.scored and r.status != Status.SKIP]
    score  = (
        sum(SCORE_WEIGHTS[r.status] for r in scored) / len(scored) * 100
        if scored else 0.0
    )

    return HardeningReport(
        hostname   = get_hostname(),
        os_info    = get_os_info(),
        scan_time  = datetime.now().isoformat(),
        results    = results,
        score      = score,
        pass_count = sum(1 for r in results if r.status == Status.PASS),
        fail_count = sum(1 for r in results if r.status == Status.FAIL),
        warn_count = sum(1 for r in results if r.status == Status.WARN),
        skip_count = sum(1 for r in results if r.status == Status.SKIP),
    )


def print_summary(report: HardeningReport) -> None:
    SEP = "═" * 60
    score_col = C.GREEN if report.score >= 80 else C.YELLOW if report.score >= 60 else C.RED
    bar_len   = int(report.score / 100 * 40)
    bar       = "█" * bar_len + "░" * (40 - bar_len)

    print(f"\n{SEP}")
    print(f"  {C.BOLD}CIS BENCHMARK REPORT — {report.hostname}{C.RESET}")
    print(f"  OS       : {report.os_info}")
    print(f"  Scanned  : {report.scan_time}")
    print(SEP)
    print(f"  {score_col}{C.BOLD}Score: {report.score:.1f}/100{C.RESET}  [{bar}]")
    print(f"  ✅ PASS: {report.pass_count}  ❌ FAIL: {report.fail_count}  "
          f"⚠️  WARN: {report.warn_count}  ⏭️  SKIP: {report.skip_count}")
    print(SEP)

    if report.fail_count > 0:
        print(f"\n  {C.RED}{C.BOLD}Items to remediate:{C.RESET}")
        for r in report.results:
            if r.status == Status.FAIL:
                print(f"  {C.RED}❌ [{r.cis_id}]{C.RESET} {r.title}")
                print(f"     Fix: {r.remediation}")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        prog="hardening-check",
        description="Linux CIS Benchmark Checker — Zero Dependencies"
    )
    parser.add_argument("-o", "--output", default="hardening_report",
                        help="Base name for the JSON output file")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version=f"hardening-check {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(f"\n{C.CYAN}{C.BOLD}  🛡️  Linux CIS Benchmark Checker v{__version__}{C.RESET}")
        print(f"  {C.DIM}CIS Controls v8 | NIST-aligned | Márcio Coutinho{C.RESET}\n")
        if not is_root():
            print(f"  {C.YELLOW}⚠ Some checks require root privileges — some results will be marked SKIP{C.RESET}\n")

    print(f"  {C.DIM}Running {len(ALL_CHECKS)} checks...{C.RESET}\n")
    report = run_checks()
    print_summary(report)

    out_path = f"{args.output}.json"
    with open(out_path, "w") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
    print(f"\n  {C.GREEN}[✓] JSON report: {out_path}{C.RESET}")

    # CI exit code: fail if the score is below 60
    if report.score < 60:
        sys.exit(2)


if __name__ == "__main__":
    main()

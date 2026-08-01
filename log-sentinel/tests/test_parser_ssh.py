"""
tests/test_parser_ssh.py
===========================================================================
Author  : Márcio Coutinho — Cybersecurity Specialist
Date    : 12/03/2026
===========================================================================
Unit tests for the Log-Sentinel SSH auth.log parser.
Covers: brute-force detection, failed logins, invalid users,
       and severity escalation after the failure threshold.
"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_sentinel import (
    parse_ssh,
    detect_format,
    build_report,
    ThreatLevel,
    SSH_BRUTE_THRESHOLD,
)
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def make_ssh_log(lines: list[str]) -> Path:
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, prefix="sentinel_ssh_"
    )
    tmp.write("\n".join(lines) + "\n")
    tmp.close()
    return Path(tmp.name)


def cleanup(path: Path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def failed_login(ip: str, user: str = "root",
                 ts: str = "Apr 14 03:22:11") -> str:
    return (
        f"{ts} server sshd[1234]: Failed password for {user} "
        f"from {ip} port 54321 ssh2"
    )


def accepted_login(ip: str, user: str = "admin",
                   ts: str = "Apr 14 03:25:00") -> str:
    return (
        f"{ts} server sshd[1234]: Accepted password for {user} "
        f"from {ip} port 54321 ssh2"
    )


def invalid_user(ip: str, user: str = "oracle",
                 ts: str = "Apr 14 03:22:11") -> str:
    return (
        f"{ts} server sshd[1234]: Invalid user {user} "
        f"from {ip} port 54321"
    )


# ─────────────────────────────────────────────────────────────────────────────
# FORMAT TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestSSHFormatDetection:
    def test_detects_ssh_format(self):
        path = make_ssh_log([failed_login("10.0.0.1")])
        try:
            assert detect_format(path) == "ssh"
        finally:
            cleanup(path)

    def test_accepted_login_detected_as_ssh(self):
        path = make_ssh_log([accepted_login("10.0.0.1")])
        try:
            assert detect_format(path) == "ssh"
        finally:
            cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# FAILED LOGIN TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestSSHFailedLogin:
    def test_single_failure_produces_low_event(self):
        path = make_ssh_log([failed_login("1.2.3.4")])
        try:
            events = list(parse_ssh(path, str(path)))
            fail_events = [e for e in events
                           if e.category == "SSH Failed Login"
                           and e.source_ip == "1.2.3.4"]
            assert len(fail_events) == 1
            assert fail_events[0].threat == ThreatLevel.LOW
        finally:
            cleanup(path)

    def test_failed_login_captures_username(self):
        path = make_ssh_log([failed_login("1.2.3.4", user="testuser")])
        try:
            events = list(parse_ssh(path, str(path)))
            fail_events = [e for e in events if e.category == "SSH Failed Login"]
            assert any(e.extra.get("username") == "testuser" for e in fail_events)
        finally:
            cleanup(path)

    def test_failed_login_captures_source_ip(self):
        path = make_ssh_log([failed_login("185.220.101.47")])
        try:
            events = list(parse_ssh(path, str(path)))
            assert any(e.source_ip == "185.220.101.47" for e in events)
        finally:
            cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# BRUTE-FORCE TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestSSHBruteForce:
    def _make_brute_force(self, ip: str, count: int) -> Path:
        lines = [failed_login(ip, user=f"user{i}") for i in range(count)]
        return make_ssh_log(lines)

    def test_below_threshold_no_brute_force_event(self):
        count = SSH_BRUTE_THRESHOLD - 1
        path  = self._make_brute_force("1.2.3.4", count)
        try:
            events = list(parse_ssh(path, str(path)))
            bf_events = [e for e in events if e.category == "SSH Brute Force"]
            assert len(bf_events) == 0
        finally:
            cleanup(path)

    def test_at_threshold_brute_force_detected(self):
        path = self._make_brute_force("185.220.101.47", SSH_BRUTE_THRESHOLD)
        try:
            events = list(parse_ssh(path, str(path)))
            bf_events = [e for e in events
                         if e.category == "SSH Brute Force"
                         and e.source_ip == "185.220.101.47"]
            assert len(bf_events) >= 1
            assert bf_events[0].threat == ThreatLevel.CRITICAL
        finally:
            cleanup(path)

    def test_brute_force_event_has_total_failures(self):
        count = SSH_BRUTE_THRESHOLD + 3
        path  = self._make_brute_force("10.10.10.1", count)
        try:
            events = list(parse_ssh(path, str(path)))
            bf_events = [e for e in events if e.category == "SSH Brute Force"]
            assert len(bf_events) >= 1
            assert bf_events[0].extra.get("total_failures") == count
        finally:
            cleanup(path)

    def test_multiple_ips_tracked_independently(self):
        lines = (
            [failed_login("1.1.1.1") for _ in range(SSH_BRUTE_THRESHOLD + 2)] +
            [failed_login("2.2.2.2") for _ in range(SSH_BRUTE_THRESHOLD - 1)]
        )
        path = make_ssh_log(lines)
        try:
            events = list(parse_ssh(path, str(path)))
            bf_ips = {e.source_ip for e in events if e.category == "SSH Brute Force"}
            assert "1.1.1.1" in bf_ips
            assert "2.2.2.2" not in bf_ips
        finally:
            cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# SUCCESSFUL LOGIN TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestSSHSuccessfulLogin:
    def test_login_after_no_failures_is_info(self):
        path = make_ssh_log([accepted_login("192.168.1.100")])
        try:
            events = list(parse_ssh(path, str(path)))
            accepted = [e for e in events if "Successful" in e.category]
            assert len(accepted) >= 1
            assert accepted[0].threat == ThreatLevel.INFO
        finally:
            cleanup(path)

    def test_login_after_brute_force_is_critical(self):
        """A successful login after >= threshold failures → CRITICAL."""
        ip    = "185.220.101.47"
        lines = [failed_login(ip) for _ in range(SSH_BRUTE_THRESHOLD)]
        lines.append(accepted_login(ip))
        path = make_ssh_log(lines)
        try:
            events = list(parse_ssh(path, str(path)))
            post_bf = [e for e in events
                       if "Brute Force Success" in e.category
                       and e.source_ip == ip]
            assert len(post_bf) >= 1
            assert post_bf[0].threat == ThreatLevel.CRITICAL
        finally:
            cleanup(path)

    def test_login_after_brute_force_records_previous_failures(self):
        ip    = "10.0.0.99"
        count = SSH_BRUTE_THRESHOLD + 2
        lines = [failed_login(ip) for _ in range(count)]
        lines.append(accepted_login(ip))
        path = make_ssh_log(lines)
        try:
            events = list(parse_ssh(path, str(path)))
            success = [e for e in events if "Success" in e.category]
            assert any(e.extra.get("previous_failures") == count for e in success)
        finally:
            cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# INVALID USER TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestSSHInvalidUser:
    def test_invalid_user_detected_as_medium(self):
        path = make_ssh_log([invalid_user("5.6.7.8", "oracle")])
        try:
            events = list(parse_ssh(path, str(path)))
            inv = [e for e in events if e.category == "SSH Invalid User"]
            assert len(inv) >= 1
            assert inv[0].threat == ThreatLevel.MEDIUM
        finally:
            cleanup(path)

    def test_invalid_user_captures_username(self):
        path = make_ssh_log([invalid_user("5.6.7.8", "postgres")])
        try:
            events = list(parse_ssh(path, str(path)))
            inv    = [e for e in events if e.category == "SSH Invalid User"]
            assert any(e.extra.get("username") == "postgres" for e in inv)
        finally:
            cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# REPORT TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestSSHReport:
    def test_report_counts_match_events(self):
        ip    = "203.0.113.42"
        lines = [failed_login(ip) for _ in range(SSH_BRUTE_THRESHOLD + 5)]
        lines.append(accepted_login(ip))
        path = make_ssh_log(lines)
        try:
            events = list(parse_ssh(path, str(path)))
            report = build_report(str(path), "ssh", events, len(lines))
            total_in_by_threat = sum(report.by_threat.values())
            assert total_in_by_threat == report.total_events
        finally:
            cleanup(path)

    def test_brute_force_attack_produces_nonzero_risk_score(self):
        ip    = "1.1.1.1"
        lines = [failed_login(ip) for _ in range(SSH_BRUTE_THRESHOLD + 10)]
        path  = make_ssh_log(lines)
        try:
            events = list(parse_ssh(path, str(path)))
            report = build_report(str(path), "ssh", events, len(lines))
            assert report.risk_score > 0
        finally:
            cleanup(path)

    def test_top_ips_contains_most_active_attacker(self):
        ip1   = "10.10.10.1"
        ip2   = "10.10.10.2"
        lines = (
            [failed_login(ip1) for _ in range(SSH_BRUTE_THRESHOLD + 5)] +
            [failed_login(ip2) for _ in range(2)]
        )
        path = make_ssh_log(lines)
        try:
            events = list(parse_ssh(path, str(path)))
            report = build_report(str(path), "ssh", events, len(lines))
            assert ip1 in report.top_ips
        finally:
            cleanup(path)

"""
tests/test_parser_apache.py
===========================================================================
Author  : Márcio Coutinho — Cybersecurity Specialist
Date    : 12/03/2026
===========================================================================
Unit tests for the Log-Sentinel Apache/Nginx parser.
Covers: web attack detection, field parsing, and risk scoring.
"""

import json
import os
import sys
import tempfile
import pytest

# Add the project root directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_sentinel import (
    parse_apache,
    detect_format,
    build_report,
    ThreatLevel,
    LogEvent,
)

# ─────────────────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

def make_apache_log(lines: list[str]) -> str:
    """Create a temporary log file and return its path."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, prefix="sentinel_test_"
    )
    tmp.write("\n".join(lines) + "\n")
    tmp.close()
    return tmp.name


# Valid Apache log line — normal request
NORMAL_LINE = (
    '192.168.1.1 - - [14/Apr/2024:03:22:11 +0000] '
    '"GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
)

# Line with SQL Injection
SQLI_LINE = (
    '203.0.113.42 - - [14/Apr/2024:03:22:12 +0000] '
    '"GET /search?q=\' OR \'1\'=\'1 HTTP/1.1" 200 512 "-" "curl/7.68"'
)

# Line with Path Traversal
TRAVERSAL_LINE = (
    '185.220.101.47 - - [14/Apr/2024:03:22:13 +0000] '
    '"GET /download?file=../../etc/passwd HTTP/1.1" 200 2048 "-" "python-requests/2.28"'
)

# Line with XSS
XSS_LINE = (
    '10.0.0.55 - - [14/Apr/2024:03:22:14 +0000] '
    '"GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
)

# Line with Nikto scanner in the User-Agent
SCANNER_LINE = (
    '203.0.113.42 - - [14/Apr/2024:03:22:15 +0000] '
    '"GET /robots.txt HTTP/1.1" 200 45 "-" '
    '"Mozilla/5.0 (compatible; Nikto/2.1.6; +https://cirt.net/Nikto2)"'
)

# Line accessing a sensitive file
SENSITIVE_LINE = (
    '203.0.113.42 - - [14/Apr/2024:03:22:16 +0000] '
    '"GET /.env HTTP/1.1" 200 128 "-" "Go-http-client/1.1"'
)

# Line with Command Injection
CMDINJ_LINE = (
    '10.0.0.99 - - [14/Apr/2024:03:22:17 +0000] '
    '"GET /ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1" 200 4096 "-" "curl/7.68"'
)

# Line with Template Injection
SSTI_LINE = (
    '10.0.0.99 - - [14/Apr/2024:03:22:18 +0000] '
    '"GET /search?q={{7*7}} HTTP/1.1" 200 256 "-" "Mozilla/5.0"'
)


# ─────────────────────────────────────────────────────────────────────────────
# FORMAT TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectFormat:
    def test_detects_apache_format(self):
        path = make_apache_log([NORMAL_LINE])
        try:
            assert detect_format(__import__("pathlib").Path(path)) == "apache"
        finally:
            os.unlink(path)

    def test_unknown_format_returns_unknown(self):
        path = make_apache_log(["this is not a log line"])
        try:
            result = detect_format(__import__("pathlib").Path(path))
            assert result == "unknown"
        finally:
            os.unlink(path)

    def test_empty_file_returns_unknown(self):
        path = make_apache_log([""])
        try:
            result = detect_format(__import__("pathlib").Path(path))
            assert result == "unknown"
        finally:
            os.unlink(path)


# ─────────────────────────────────────────────────────────────────────────────
# PARSING TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestApacheParsing:
    def _parse(self, lines: list[str]) -> list[LogEvent]:
        from pathlib import Path
        path = make_apache_log(lines)
        try:
            return list(parse_apache(Path(path), path))
        finally:
            os.unlink(path)

    def test_normal_request_produces_no_events(self):
        events = self._parse([NORMAL_LINE])
        # A normal request (200, no attack pattern) should not generate attack events
        attack_events = [e for e in events if e.threat in (
            ThreatLevel.CRITICAL, ThreatLevel.HIGH
        )]
        assert len(attack_events) == 0

    def test_sqli_detected_as_critical(self):
        events = self._parse([SQLI_LINE])
        sqli_events = [e for e in events if e.threat == ThreatLevel.CRITICAL
                       and "SQL" in e.category]
        assert len(sqli_events) >= 1

    def test_path_traversal_detected_as_high(self):
        events = self._parse([TRAVERSAL_LINE])
        traversal_events = [e for e in events
                            if e.threat in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
                            and "Traversal" in e.category]
        assert len(traversal_events) >= 1

    def test_xss_detected(self):
        events = self._parse([XSS_LINE])
        xss_events = [e for e in events if "XSS" in e.category]
        assert len(xss_events) >= 1

    def test_scanner_user_agent_detected(self):
        events = self._parse([SCANNER_LINE])
        scanner_events = [e for e in events if "Scanner" in e.category]
        assert len(scanner_events) >= 1

    def test_sensitive_file_detected(self):
        events = self._parse([SENSITIVE_LINE])
        sensitive_events = [e for e in events
                            if "Sensitive" in e.category or "Config" in e.category or "Admin" in e.category]
        assert len(sensitive_events) >= 1

    def test_command_injection_detected_as_critical(self):
        events = self._parse([CMDINJ_LINE])
        cmd_events = [e for e in events
                      if e.threat == ThreatLevel.CRITICAL and "Command" in e.category]
        assert len(cmd_events) >= 1

    def test_template_injection_detected(self):
        events = self._parse([SSTI_LINE])
        ssti_events = [e for e in events if "Template" in e.category or "Injection" in e.category]
        assert len(ssti_events) >= 1

    def test_event_has_correct_source_ip(self):
        events = self._parse([SQLI_LINE])
        assert any(e.source_ip == "203.0.113.42" for e in events)

    def test_event_has_line_number(self):
        events = self._parse([NORMAL_LINE, SQLI_LINE])
        for e in events:
            assert e.line_number >= 1

    def test_multiple_attacks_detected_in_bulk(self):
        lines = [SQLI_LINE, TRAVERSAL_LINE, XSS_LINE,
                 SCANNER_LINE, SENSITIVE_LINE, CMDINJ_LINE]
        events = self._parse(lines)
        assert len(events) >= 5

    def test_high_volume_ip_flagged(self):
        """An IP with more than 200 requests should generate a High Volume event."""
        ip = "203.0.113.42"
        lines = []
        for i in range(210):
            lines.append(
                f'{ip} - - [14/Apr/2024:03:22:11 +0000] '
                f'"GET /page{i}.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
            )
        events = self._parse(lines)
        high_vol = [e for e in events if "High Volume" in e.category]
        assert len(high_vol) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# SERIALIZATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestEventSerialization:
    def _get_event(self) -> LogEvent:
        from pathlib import Path
        path = make_apache_log([SQLI_LINE])
        try:
            events = list(parse_apache(Path(path), path))
        finally:
            os.unlink(path)
        return events[0]

    def test_to_dict_has_required_keys(self):
        event = self._get_event()
        d = event.to_dict()
        for key in ("timestamp", "source_ip", "threat", "category",
                    "description", "raw_line", "source_file", "line_number"):
            assert key in d, f"Missing field: {key}"

    def test_threat_serialized_as_string(self):
        event = self._get_event()
        d = event.to_dict()
        assert isinstance(d["threat"], str)
        assert d["threat"] in [l.value for l in ThreatLevel]

    def test_event_is_json_serializable(self):
        event = self._get_event()
        serialized = json.dumps(event.to_dict())
        assert isinstance(serialized, str)
        parsed = json.loads(serialized)
        assert parsed["threat"] == "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORE TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskScore:
    def test_critical_events_increase_score(self):
        from pathlib import Path
        path = make_apache_log([SQLI_LINE, CMDINJ_LINE])
        try:
            events = list(parse_apache(Path(path), path))
        finally:
            os.unlink(path)

        report = build_report("test", "apache", events, 2)
        assert report.risk_score > 0

    def test_score_higher_with_more_criticals(self):
        from pathlib import Path

        path1 = make_apache_log([NORMAL_LINE])
        path2 = make_apache_log([SQLI_LINE, CMDINJ_LINE, TRAVERSAL_LINE])

        try:
            events1 = list(parse_apache(Path(path1), path1))
            events2 = list(parse_apache(Path(path2), path2))
        finally:
            os.unlink(path1)
            os.unlink(path2)

        report1 = build_report("test1", "apache", events1, 1)
        report2 = build_report("test2", "apache", events2, 3)

        assert report2.risk_score > report1.risk_score

    def test_report_summary_counts_match(self):
        from pathlib import Path
        path = make_apache_log([SQLI_LINE, TRAVERSAL_LINE, XSS_LINE])
        try:
            events = list(parse_apache(Path(path), path))
        finally:
            os.unlink(path)

        report = build_report("test", "apache", events, 3)
        total_in_summary = sum(report.by_threat.values())
        assert total_in_summary == report.total_events

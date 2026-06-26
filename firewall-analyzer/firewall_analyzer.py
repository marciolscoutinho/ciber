#!/usr/bin/env python3
"""
firewall_analyzer.py — Firewall Rule Analyzer v1.0.0
=====================================================

Analyzes firewall rules from iptables and UFW outputs and detects permissive
policies, exposed high-risk ports, redundant rules, missing logging, and other
security gaps.

Author      : Marcio Coutinho — Cybersecurity Specialist
Date        : 13/06/2025
Requirements: Python 3.8+ | Zero external dependencies
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
 ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗
 ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║
 █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║
 ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║
 ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
 ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝{C.RESET}
{C.DIM} v{__version__} — Firewall Rule Analyzer | iptables · UFW | CIS-oriented checks{C.RESET}
"""

SEP = "━" * 68
SEP2 = "═" * 68


@dataclass
class FirewallRule:
    line_no: int
    chain: str
    action: str
    proto: str
    src: str
    dst: str
    sport: str
    dport: str
    iface_in: str
    iface_out: str
    raw: str


@dataclass
class RuleFinding:
    severity: str
    category: str
    rule: FirewallRule
    description: str
    remediation: str

    @property
    def title(self) -> str:
        return self.category

    @property
    def evidence(self) -> str:
        return self.rule.raw


@dataclass
class FirewallReport:
    source: str
    fw_type: str
    timestamp: str
    rules: List[FirewallRule]
    findings: List[RuleFinding]
    default_policies: Dict[str, str]
    score: float

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "firewall_type": self.fw_type,
            "timestamp": self.timestamp,
            "score": self.score,
            "total_rules": len(self.rules),
            "default_policies": self.default_policies,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "description": f.description,
                    "remediation": f.remediation,
                    "rule": {
                        "line": f.rule.line_no,
                        "chain": f.rule.chain,
                        "action": f.rule.action,
                        "proto": f.rule.proto,
                        "src": f.rule.src,
                        "dst": f.rule.dst,
                        "sport": f.rule.sport,
                        "dport": f.rule.dport,
                        "raw": f.rule.raw,
                    },
                }
                for f in self.findings
            ],
        }


HIGH_RISK_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    135: "MS-RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS-SSN",
    161: "SNMP",
    389: "LDAP",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker API",
    2376: "Docker API with TLS",
    3306: "MySQL",
    3389: "RDP",
    4444: "Common reverse-shell listener",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

PRIVATE_RANGES = [
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
]


def _is_any(src: str) -> bool:
    return src.lower() in ("0.0.0.0/0", "0.0.0.0", "any", "anywhere", "", "::/0", "*")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in PRIVATE_RANGES)


def _parse_port(port_str: str) -> Optional[int]:
    try:
        return int(str(port_str).split(":")[0].split(",")[0])
    except (ValueError, TypeError):
        return None


def parse_iptables(content: str) -> Tuple[List[FirewallRule], Dict[str, str]]:
    """Parse output from: iptables -L -n --line-numbers."""
    rules: List[FirewallRule] = []
    policies: Dict[str, str] = {}
    current_chain = ""
    synthetic_line_no = 0

    for raw_line in content.splitlines():
        line = raw_line.strip()

        chain_match = re.match(r"Chain\s+(\w+)\s+\(policy\s+(\w+)", line)
        if chain_match:
            current_chain = chain_match.group(1)
            policies[current_chain] = chain_match.group(2).upper()
            synthetic_line_no = 0
            continue

        if not line or line.startswith(("pkts", "num", "target", "Chain")):
            continue

        # Verbose and numbered format:
        # num pkts bytes target prot opt in out source destination extras
        numbered = re.match(
            r"(\d+)\s+\S+\s+\S+\s+(\w+)\s+(\w+)\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(.*)",
            line,
        )
        if numbered:
            extras = numbered.group(8)
            dport = re.search(r"dpt:(\S+)", extras)
            sport = re.search(r"spt:(\S+)", extras)
            rules.append(
                FirewallRule(
                    line_no=int(numbered.group(1)),
                    chain=current_chain,
                    action=numbered.group(2).upper(),
                    proto=numbered.group(3).lower(),
                    iface_in=numbered.group(4),
                    iface_out=numbered.group(5),
                    src=numbered.group(6),
                    dst=numbered.group(7),
                    sport=sport.group(1) if sport else "",
                    dport=dport.group(1) if dport else "",
                    raw=line,
                )
            )
            continue

        # Common non-verbose format:
        # target prot opt source destination extras
        simple = re.match(r"(\w+)\s+(\w+)\s+--\s+(\S+)\s+(\S+)(.*)", line)
        if simple:
            synthetic_line_no += 1
            extras = simple.group(5)
            dport = re.search(r"dpt:(\S+)", extras)
            sport = re.search(r"spt:(\S+)", extras)
            rules.append(
                FirewallRule(
                    line_no=synthetic_line_no,
                    chain=current_chain,
                    action=simple.group(1).upper(),
                    proto=simple.group(2).lower(),
                    src=simple.group(3),
                    dst=simple.group(4),
                    sport=sport.group(1) if sport else "",
                    dport=dport.group(1) if dport else "",
                    iface_in="",
                    iface_out="",
                    raw=line,
                )
            )

    return rules, policies


def parse_ufw_status(content: str) -> Tuple[List[FirewallRule], Dict[str, str]]:
    """Parse output from: ufw status numbered."""
    rules: List[FirewallRule] = []
    policies = {"INPUT": "DROP", "OUTPUT": "ACCEPT", "FORWARD": "DROP"}

    for raw_line in content.splitlines():
        line = raw_line.strip()

        default_match = re.match(r"Default:\s+(\w+)\s+\((\w+)\)", line, re.I)
        if default_match:
            direction = default_match.group(2).upper()
            policy = default_match.group(1).upper()
            if direction == "INCOMING":
                policies["INPUT"] = "ACCEPT" if policy == "ALLOW" else "DROP"
            elif direction == "OUTGOING":
                policies["OUTPUT"] = "ACCEPT" if policy == "ALLOW" else "DROP"
            continue

        rule_match = re.match(
            r"\[\s*(\d+)\]\s+(\S+)\s+(ALLOW|DENY|REJECT|LIMIT)\s*(IN|OUT|FWD)?\s*(.*)",
            line,
            re.I,
        )
        if not rule_match:
            continue

        number = int(rule_match.group(1))
        port_proto = rule_match.group(2)
        action_token = rule_match.group(3).upper()
        action = "ACCEPT" if action_token in ("ALLOW", "LIMIT") else "DROP"
        direction = (rule_match.group(4) or "IN").upper()
        source = rule_match.group(5).strip() or "Anywhere"

        if "/" in port_proto:
            dport, proto = port_proto.split("/", 1)
        else:
            dport, proto = port_proto, "tcp"

        rules.append(
            FirewallRule(
                line_no=number,
                chain="INPUT" if direction == "IN" else "OUTPUT",
                action=action,
                proto=proto.lower(),
                src="0.0.0.0/0" if "anywhere" in source.lower() else source,
                dst="0.0.0.0/0",
                sport="",
                dport=dport,
                iface_in="",
                iface_out="",
                raw=line,
            )
        )

    return rules, policies


def get_live_iptables() -> str:
    for command in (["iptables", "-L", "-n", "--line-numbers"], ["sudo", "iptables", "-L", "-n", "--line-numbers"]):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except Exception:
            pass
    return ""


def get_live_ufw() -> str:
    for command in (["ufw", "status", "numbered"], ["sudo", "ufw", "status", "numbered"]):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except Exception:
            pass
    return ""


def analyze_rules(rules: List[FirewallRule], policies: Dict[str, str]) -> List[RuleFinding]:
    findings: List[RuleFinding] = []

    def add(severity: str, category: str, rule: FirewallRule, description: str, remediation: str) -> None:
        findings.append(RuleFinding(severity, category, rule, description, remediation))

    for chain, policy in policies.items():
        if chain == "INPUT" and policy not in ("DROP", "REJECT"):
            fake = FirewallRule(0, chain, policy, "all", "any", "any", "", "", "", "", f"Default {chain} policy: {policy}")
            add(
                "CRITICAL",
                "Permissive default policy",
                fake,
                f"The {chain} chain has default policy {policy}. Inbound traffic may be accepted by default.",
                f"Set a deny-by-default policy: iptables -P {chain} DROP",
            )

        if chain == "FORWARD" and policy == "ACCEPT":
            fake = FirewallRule(0, chain, policy, "all", "any", "any", "", "", "", "", f"Default {chain} policy: {policy}")
            add(
                "HIGH",
                "Permissive forwarding policy",
                fake,
                "The FORWARD chain default policy is ACCEPT, allowing traffic forwarding between interfaces.",
                "Set the forwarding policy to DROP unless forwarding is explicitly required.",
            )

    for rule in rules:
        if rule.action != "ACCEPT":
            continue

        src_any = _is_any(rule.src)
        dst_any = _is_any(rule.dst)
        port = _parse_port(rule.dport)

        if src_any and port and port in HIGH_RISK_PORTS:
            service = HIGH_RISK_PORTS[port]
            severity = "CRITICAL" if port in (3389, 445, 2375, 4444, 69, 512, 513, 514) else "HIGH"
            add(
                severity,
                "High-risk port exposed",
                rule,
                f"Port {port} ({service}) accepts connections from any source address.",
                f"Restrict the rule to trusted source IPs: -s <TRUSTED_IP> -p {rule.proto} --dport {port} -j ACCEPT",
            )

        if src_any and dst_any and rule.proto == "all" and not rule.dport:
            add(
                "CRITICAL",
                "Allow-all rule",
                rule,
                "The rule accepts all traffic without source, destination, protocol, or port restrictions.",
                "Remove this rule and replace it with explicit, least-privilege allow rules.",
            )

        if src_any and rule.proto in ("tcp", "udp") and not rule.dport and rule.chain == "INPUT":
            add(
                "HIGH",
                "ACCEPT without destination port filter",
                rule,
                f"The rule accepts all {rule.proto.upper()} ports from any source address.",
                "Specify an explicit destination port and restrict the source address.",
            )

    legacy_ports = {21: "FTP", 23: "Telnet", 512: "rexec", 513: "rlogin", 514: "rsh"}
    for rule in rules:
        if rule.action != "ACCEPT":
            continue
        port = _parse_port(rule.dport)
        if port and port in legacy_ports:
            service = legacy_ports[port]
            add(
                "HIGH",
                "Insecure legacy protocol exposed",
                rule,
                f"{service} on port {port} is exposed. This protocol does not provide adequate transport security.",
                f"Disable {service} and use a secure alternative such as SSH or SFTP.",
            )

    for rule in rules:
        if rule.action == "ACCEPT" and _parse_port(rule.dport) == 161 and _is_any(rule.src):
            add(
                "HIGH",
                "SNMP publicly exposed",
                rule,
                "SNMP on port 161 accepts traffic from any source address and may leak network information.",
                "Restrict SNMP to the management server and use SNMPv3 with authentication and encryption.",
            )

    for rule in rules:
        if rule.action == "ACCEPT":
            port = _parse_port(rule.dport)
            if port in (2375, 2376) and _is_any(rule.src):
                add(
                    "CRITICAL",
                    "Docker API exposed",
                    rule,
                    f"Docker API port {port} is reachable from any source. This may allow host-level control.",
                    "Do not expose Docker API to untrusted networks. Use a local Unix socket or authenticated TLS on a restricted interface.",
                )

    seen_rules: Dict[Tuple[str, str, str, str, str], int] = {}
    for rule in rules:
        key = (rule.chain, rule.action, rule.proto, rule.src, rule.dport)
        if key in seen_rules:
            add(
                "LOW",
                "Duplicate or redundant rule",
                rule,
                f"This rule duplicates rule #{seen_rules[key]} in the same chain.",
                "Remove duplicate rules to simplify the ruleset and reduce operational risk.",
            )
        else:
            seen_rules[key] = rule.line_no

    icmp_rules = [r for r in rules if r.proto == "icmp"]
    drop_all_icmp = any(r.action in ("DROP", "REJECT") and not r.dport for r in icmp_rules)
    if drop_all_icmp:
        fake = FirewallRule(0, "INPUT", "DROP", "icmp", "any", "any", "", "", "", "", "DROP all ICMP")
        add(
            "MEDIUM",
            "ICMP fully blocked",
            fake,
            "Blocking all ICMP can break network diagnostics and path MTU discovery.",
            "Allow necessary ICMP types, such as echo-reply, unreachable, and fragmentation-needed.",
        )

    chains_with_drop = {r.chain for r in rules if r.action in ("DROP", "REJECT")}
    chains_with_log = {r.chain for r in rules if r.action == "LOG"}
    for chain in chains_with_drop - chains_with_log:
        fake = FirewallRule(0, chain, "DROP", "all", "any", "any", "", "", "", "", f"Chain {chain} without LOG")
        add(
            "MEDIUM",
            "Dropped traffic is not logged",
            fake,
            f"The {chain} chain drops or rejects traffic without logging it first.",
            f"Add a LOG rule before DROP/REJECT rules: iptables -A {chain} -j LOG --log-prefix '[FW-DROP] '",
        )

    return findings


def compute_score(rules: List[FirewallRule], findings: List[RuleFinding], policies: Dict[str, str]) -> float:
    if not rules and not policies:
        return 0.0

    weights = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 5, "LOW": 1}
    deductions = sum(weights.get(f.severity, 0) for f in findings)

    bonus = 0
    if policies.get("INPUT") in ("DROP", "REJECT"):
        bonus += 20
    if policies.get("FORWARD") == "DROP":
        bonus += 10

    return round(max(0.0, min(100.0, 100 - deductions + bonus)), 1)


def exit_code_for_findings(findings: List[RuleFinding]) -> int:
    if any(f.severity == "CRITICAL" for f in findings):
        return 2
    if any(f.severity in ("HIGH", "MEDIUM") for f in findings):
        return 1
    return 0


SEV_COL = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN, "LOW": C.GREEN}


def print_findings(findings: List[RuleFinding]) -> None:
    if not findings:
        print(f"\n  {C.GREEN}No relevant firewall issues detected.{C.RESET}")
        return

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for finding in sorted(findings, key=lambda item: severity_order.index(item.severity) if item.severity in severity_order else 99):
        color = SEV_COL.get(finding.severity, "")
        print(f"\n  {color}[{finding.severity}]{C.RESET} {C.BOLD}{finding.category}{C.RESET}")
        print(f"  {C.DIM}Rule   :{C.RESET} {finding.rule.raw[:100]}")
        print(f"  {C.DIM}Issue  :{C.RESET} {finding.description}")
        print(f"  {C.DIM}Fix    :{C.RESET} {finding.remediation[:120]}")


def print_summary(report: FirewallReport) -> None:
    score_color = C.GREEN if report.score >= 80 else C.YELLOW if report.score >= 60 else C.RED
    bar_len = int(report.score / 100 * 40)
    bar = "█" * bar_len + "░" * (40 - bar_len)

    by_severity: Dict[str, int] = {}
    for finding in report.findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}FIREWALL ANALYSIS SUMMARY{C.RESET}")
    print(f"  Source   : {report.source}")
    print(f"  Type     : {report.fw_type}")
    print(f"  Rules    : {len(report.rules)}")
    print(f"  Findings : {len(report.findings)}")
    print(SEP)
    print("  Default policies:")
    for chain, policy in report.default_policies.items():
        policy_color = C.GREEN if policy in ("DROP", "REJECT") or chain == "OUTPUT" else C.RED
        print(f"    {chain:<10} {policy_color}{policy}{C.RESET}")
    print(SEP)
    print(f"  {score_color}{C.BOLD}Score: {report.score:.0f}/100{C.RESET}  [{bar}]")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = by_severity.get(severity, 0)
        if count:
            color = SEV_COL.get(severity, "")
            print(f"  {color}{severity:<10}{C.RESET} {'█' * min(count, 20)} {count}")
    print(SEP2)


def generate_markdown(report: FirewallReport) -> str:
    lines = [
        "# 🔥 Firewall Analysis Report",
        f"**Source:** {report.source} | **Type:** {report.fw_type} | **Score:** {report.score:.0f}/100",
        f"**Rules:** {len(report.rules)} | **Findings:** {len(report.findings)} | **Date:** {report.timestamp[:16]}",
        "",
        "## Default Policies",
        "",
        "| Chain | Policy |",
        "|---|:---:|",
    ]

    for chain, policy in report.default_policies.items():
        lines.append(f"| {chain} | **{policy}** |")

    lines += [
        "",
        f"## Findings ({len(report.findings)})",
        "",
        "| Severity | Category | Rule | Remediation |",
        "|:---:|---|---|---|",
    ]

    for finding in report.findings:
        raw = finding.rule.raw.replace("|", "\\|")
        remediation = finding.remediation.replace("|", "\\|")
        lines.append(f"| **{finding.severity}** | {finding.category} | `{raw[:90]}` | {remediation} |")

    lines += ["", f"*Generated by firewall-analyzer v{__version__}*"]
    return "\n".join(lines)


def generate_demo_content() -> str:
    return """Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num  pkts bytes target     prot opt in     out     source               destination
1       0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
2       0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3389
3       0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3306
4       0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:23
5       0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:161
6       0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:2375
7       0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0
8       0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)"""


def load_rules(args: argparse.Namespace) -> Tuple[str, str, str]:
    if args.demo or (not args.file and not args.live):
        return generate_demo_content(), "iptables", "demo-insecure-ruleset"

    if args.live:
        ufw_output = get_live_ufw()
        iptables_output = get_live_iptables()
        if ufw_output and "Status: active" in ufw_output:
            return ufw_output, "ufw", "local-system"
        if iptables_output:
            return iptables_output, "iptables", "local-system"
        raise RuntimeError("Unable to read local firewall rules. Try running with appropriate permissions.")

    source = args.file
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Rules file not found: {source}")
    content = path.read_text(errors="replace")
    fw_type = args.type

    if fw_type == "auto":
        fw_type = "ufw" if "Status:" in content or "ufw" in content.lower() else "iptables"

    return content, fw_type, source


def build_report_from_content(content: str, fw_type: str, source: str) -> FirewallReport:
    if fw_type == "ufw":
        rules, policies = parse_ufw_status(content)
    else:
        rules, policies = parse_iptables(content)

    findings = analyze_rules(rules, policies)
    score = compute_score(rules, findings, policies)

    return FirewallReport(
        source=source,
        fw_type=fw_type,
        timestamp=datetime.now().isoformat(),
        rules=rules,
        findings=findings,
        default_policies=policies,
        score=score,
    )


def write_output_file(path: str, report: FirewallReport, json_mode: bool) -> None:
    output_path = Path(path)
    if json_mode:
        output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    else:
        output_path.write_text(generate_markdown(report), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="firewall-analyzer",
        description="Firewall Rule Analyzer — iptables and UFW rule review",
    )
    parser.add_argument("file", nargs="?", help="File containing firewall rules")
    parser.add_argument("--type", choices=["iptables", "ufw", "auto"], default="auto", help="Firewall rule format")
    parser.add_argument("--live", action="store_true", help="Read rules from the local system")
    parser.add_argument("--demo", action="store_true", help="Analyze an intentionally insecure demo ruleset")
    parser.add_argument("-o", "--output", help="Save report to a file; JSON when --json is used, Markdown otherwise")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Write JSON to stdout or to --output")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version=f"firewall-analyzer {__version__}")
    args = parser.parse_args()

    if not args.no_banner and not args.json_out:
        print(BANNER)

    try:
        content, fw_type, source = load_rules(args)
        report = build_report_from_content(content, fw_type, source)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        write_output_file(args.output, report, args.json_out)

    if args.json_out:
        if not args.output:
            print(json.dumps(report.to_dict(), indent=2))
    else:
        print_findings(report.findings)
        print_summary(report)
        if args.output:
            print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    sys.exit(exit_code_for_findings(report.findings))


if __name__ == "__main__":
    main()

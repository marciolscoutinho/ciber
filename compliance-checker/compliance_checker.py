#!/usr/bin/env python3
"""
compliance_checker.py — Compliance Checker v1.1.0
===================================================
Assesses compliance against GDPR, ISO/IEC 27001:2022, and the NIS2 Directive.
Generates a structured gap analysis report with a prioritized remediation plan.

Author      : Marcio Coutinho — Cybersecurity Specialist
Date        : 02/12/2023
Requirements: Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List

__version__ = "1.1.0"


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
  ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗     ██╗ █████╗ ███╗   ██╗ ██████╗███████╗
 ██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║     ██║██╔══██╗████╗  ██║██╔════╝██╔════╝
 ██║     ██║   ██║██╔████╔██║██████╔╝██║     ██║███████║██╔██╗ ██║██║     █████╗
 ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║     ██║██╔══██║██║╚██╗██║██║     ██╔══╝
 ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗██║██║  ██║██║ ╚████║╚██████╗███████╗
  ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝{C.RESET}
{C.DIM} v{__version__} — GDPR · ISO/IEC 27001:2022 · NIS2 | Gap Analysis | Remediation Plan{C.RESET}
"""

SEP = "━" * 72
SEP2 = "═" * 72


@dataclass(frozen=True)
class Control:
    id: str
    framework: str
    title: str
    description: str
    category: str
    mandatory: bool
    question: str
    remediation: str
    effort: str
    references: List[str] = field(default_factory=list)


@dataclass
class ControlResult:
    control: Control
    status: str
    notes: str = ""
    score: float = 0.0


@dataclass
class ComplianceReport:
    org_name: str
    framework: str
    date: str
    results: List[ControlResult]
    score: float
    compliant: int
    partial: int
    non_compliant: int
    na: int

    def to_dict(self) -> dict:
        return {
            "organization": self.org_name,
            "framework": self.framework,
            "date": self.date,
            "score": self.score,
            "summary": {
                "compliant": self.compliant,
                "partial": self.partial,
                "non_compliant": self.non_compliant,
                "not_applicable": self.na,
                "total": len(self.results),
            },
            "controls": [
                {
                    "id": r.control.id,
                    "framework": r.control.framework,
                    "title": r.control.title,
                    "category": r.control.category,
                    "mandatory": r.control.mandatory,
                    "status": r.status,
                    "score": r.score,
                    "effort": r.control.effort,
                    "notes": r.notes,
                    "remediation": r.control.remediation,
                    "references": r.control.references,
                }
                for r in self.results
            ],
        }


GDPR_CONTROLS: List[Control] = [
    Control(
        "GDPR-Art5",
        "GDPR",
        "Data Processing Principles",
        "Personal data is processed lawfully, fairly, and transparently, and collected for specified purposes.",
        "Core Principles",
        True,
        "Do you have a documented data protection policy with clearly defined processing purposes?",
        "Document all processing purposes and implement a clear privacy policy aligned with GDPR principles.",
        "Medium",
        ["GDPR Article 5"],
    ),
    Control(
        "GDPR-Art6",
        "GDPR",
        "Lawful Basis for Processing",
        "Every personal data processing activity has an identified lawful basis, such as consent, contract, or legal obligation.",
        "Lawful Basis",
        True,
        "Do you maintain a record of processing activities with the lawful basis for each data category?",
        "Create and maintain a Record of Processing Activities (ROPA) and map each activity to a lawful basis.",
        "Medium",
        ["GDPR Article 6", "GDPR Article 30"],
    ),
    Control(
        "GDPR-Art12",
        "GDPR",
        "Transparency and Communication",
        "Information is provided to data subjects in a concise, transparent, intelligible, and easily accessible form.",
        "Data Subject Rights",
        True,
        "Is your privacy notice clear, accessible, and complete enough to cover data subject rights?",
        "Review and simplify privacy notices. Ensure Articles 13 and 14 information requirements are covered.",
        "Low",
        ["GDPR Articles 12-14"],
    ),
    Control(
        "GDPR-Art17",
        "GDPR",
        "Right to Erasure",
        "There is a defined procedure for responding to personal data erasure requests.",
        "Data Subject Rights",
        True,
        "Do you have a documented process to respond to erasure requests within one month?",
        "Implement an erasure request workflow, ownership model, verification step, and evidence trail.",
        "High",
        ["GDPR Article 17", "GDPR Article 12(3)"],
    ),
    Control(
        "GDPR-Art25",
        "GDPR",
        "Data Protection by Design and by Default",
        "Privacy and data protection are embedded into systems and processes from the design phase.",
        "Privacy Engineering",
        True,
        "Do new systems include privacy requirements and data minimization from the design stage?",
        "Add privacy-by-design gates to project delivery, including DPIA screening and data minimization checks.",
        "High",
        ["GDPR Article 25"],
    ),
    Control(
        "GDPR-Art28",
        "GDPR",
        "Processor Contracts",
        "Processor relationships are governed by contracts that include mandatory GDPR processing terms.",
        "Third-Party Management",
        True,
        "Do all processors handling personal data have a signed Data Processing Agreement (DPA)?",
        "Audit suppliers, sign DPAs, validate subprocessors, and review international transfer mechanisms.",
        "Medium",
        ["GDPR Article 28"],
    ),
    Control(
        "GDPR-Art32",
        "GDPR",
        "Security of Processing",
        "Appropriate technical and organizational measures protect personal data against unauthorized access and loss.",
        "Security Controls",
        True,
        "Are encryption, access control, logging, and resilience measures implemented for personal data?",
        "Implement encryption at rest and in transit, RBAC, access logging, backup controls, and resilience testing.",
        "High",
        ["GDPR Article 32"],
    ),
    Control(
        "GDPR-Art33",
        "GDPR",
        "Personal Data Breach Notification",
        "There is a procedure to notify the supervisory authority without undue delay and, where feasible, within 72 hours.",
        "Incident Response",
        True,
        "Do you have a documented personal data breach notification procedure aligned with the 72-hour requirement?",
        "Create a breach notification workflow, escalation matrix, evidence template, and supervisory authority contact list.",
        "Medium",
        ["GDPR Articles 33-34"],
    ),
    Control(
        "GDPR-Art35",
        "GDPR",
        "Data Protection Impact Assessment",
        "DPIAs are performed for processing activities likely to result in high risk to individuals.",
        "Risk Assessment",
        False,
        "Do high-risk processing activities, such as biometrics or large-scale monitoring, have documented DPIAs?",
        "Identify high-risk processing, perform DPIAs, document residual risk, and consult the authority if required.",
        "High",
        ["GDPR Article 35"],
    ),
]

ISO27001_CONTROLS: List[Control] = [
    Control(
        "ISO-A5.1",
        "ISO27001",
        "Information Security Policies",
        "Information security policies are approved by management, published, communicated, and reviewed.",
        "A.5 Organizational Controls",
        True,
        "Do you have an information security policy approved by management and communicated to all relevant parties?",
        "Draft, approve, publish, and annually review the information security policy and supporting procedures.",
        "Medium",
        ["ISO/IEC 27001:2022 Annex A.5.1"],
    ),
    Control(
        "ISO-A5.9",
        "ISO27001",
        "Inventory of Information and Other Associated Assets",
        "An accurate and current inventory of information assets is maintained with assigned ownership.",
        "A.5 Organizational Controls",
        True,
        "Do you maintain an up-to-date asset inventory with asset owners and criticality ratings?",
        "Create an asset inventory, assign owners, classify assets, and review it at defined intervals.",
        "Medium",
        ["ISO/IEC 27001:2022 Annex A.5.9"],
    ),
    Control(
        "ISO-A5.15",
        "ISO27001",
        "Access Control",
        "Access control rules are based on business and information security requirements.",
        "A.5 Organizational Controls",
        True,
        "Is access managed through least privilege, RBAC, and periodic access reviews?",
        "Implement RBAC, quarterly access reviews, joiner-mover-leaver workflows, and inactive account cleanup.",
        "High",
        ["ISO/IEC 27001:2022 Annex A.5.15"],
    ),
    Control(
        "ISO-A6.3",
        "ISO27001",
        "Information Security Awareness, Education, and Training",
        "Personnel receive appropriate security awareness, education, and training.",
        "A.6 People Controls",
        True,
        "Do all staff receive security awareness training at least annually?",
        "Implement an awareness program with onboarding training, annual refreshers, and phishing simulations.",
        "Low",
        ["ISO/IEC 27001:2022 Annex A.6.3"],
    ),
    Control(
        "ISO-A7.2",
        "ISO27001",
        "Physical Entry Controls",
        "Secure areas are protected by appropriate entry controls and access monitoring.",
        "A.7 Physical Controls",
        True,
        "Are secure areas protected by access control, visitor logging, and periodic review?",
        "Define secure areas, enforce badge-based access, maintain visitor logs, and review access regularly.",
        "Medium",
        ["ISO/IEC 27001:2022 Annex A.7.2"],
    ),
    Control(
        "ISO-A8.2",
        "ISO27001",
        "Privileged Access Rights",
        "Privileged access rights are restricted, managed, monitored, and reviewed.",
        "A.8 Technological Controls",
        True,
        "Are privileged accounts managed through MFA, approval workflows, logging, and periodic review?",
        "Implement privileged access management, enforce MFA, log privileged sessions, and review admin access.",
        "High",
        ["ISO/IEC 27001:2022 Annex A.8.2"],
    ),
    Control(
        "ISO-A8.7",
        "ISO27001",
        "Protection Against Malware",
        "Protection against malware is implemented and supported by awareness and detection controls.",
        "A.8 Technological Controls",
        True,
        "Do endpoints and servers have centrally managed anti-malware or EDR protection?",
        "Deploy EDR or anti-malware to all supported systems and monitor alerts centrally.",
        "Medium",
        ["ISO/IEC 27001:2022 Annex A.8.7"],
    ),
    Control(
        "ISO-A8.13",
        "ISO27001",
        "Information Backup",
        "Backup copies of information, software, and systems are maintained and tested.",
        "A.8 Technological Controls",
        True,
        "Are backups encrypted, regularly performed, and restoration-tested at least quarterly?",
        "Implement a 3-2-1 backup strategy, encrypt backups, and document restoration tests.",
        "Medium",
        ["ISO/IEC 27001:2022 Annex A.8.13"],
    ),
    Control(
        "ISO-A8.16",
        "ISO27001",
        "Monitoring Activities",
        "Networks, systems, and applications are monitored for anomalous behavior and security events.",
        "A.8 Technological Controls",
        True,
        "Do you have centralized logging or SIEM monitoring with alerts for suspicious activity?",
        "Deploy SIEM or centralized logging, define detection use cases, and configure real-time alerting.",
        "High",
        ["ISO/IEC 27001:2022 Annex A.8.16"],
    ),
    Control(
        "ISO-A8.23",
        "ISO27001",
        "Web Filtering",
        "Access to external websites is managed to reduce exposure to malicious content.",
        "A.8 Technological Controls",
        False,
        "Do you use DNS or web filtering to block malicious domains and risky content categories?",
        "Implement DNS or web filtering and document acceptable use and exception handling rules.",
        "Low",
        ["ISO/IEC 27001:2022 Annex A.8.23"],
    ),
]

NIS2_CONTROLS: List[Control] = [
    Control(
        "NIS2-Art21-a",
        "NIS2",
        "Risk Analysis and Information System Security Policies",
        "Policies are maintained for risk analysis and information system security.",
        "Article 21 Security Measures",
        True,
        "Have you performed a formal and documented cyber risk assessment in the last 12 months?",
        "Implement a formal risk management process, document risk ownership, and review risk treatment annually.",
        "High",
        ["NIS2 Article 21(2)(a)"],
    ),
    Control(
        "NIS2-Art21-b",
        "NIS2",
        "Incident Handling",
        "Incident handling processes include detection, response, escalation, and reporting procedures.",
        "Article 21 Security Measures",
        True,
        "Do you have documented incident response procedures with defined notification responsibilities?",
        "Create incident response playbooks, define RACI, maintain evidence templates, and test the process.",
        "High",
        ["NIS2 Article 21(2)(b)", "NIS2 Article 23"],
    ),
    Control(
        "NIS2-Art21-c",
        "NIS2",
        "Business Continuity and Crisis Management",
        "Business continuity, backup management, disaster recovery, and crisis management are addressed.",
        "Article 21 Security Measures",
        True,
        "Do you have a tested business continuity plan and disaster recovery plan with defined RTO/RPO?",
        "Create and test BCP/DRP, define critical services, and verify recovery objectives annually.",
        "High",
        ["NIS2 Article 21(2)(c)"],
    ),
    Control(
        "NIS2-Art21-d",
        "NIS2",
        "Supply Chain Security",
        "Security aspects of relationships with suppliers and service providers are managed.",
        "Article 21 Security Measures",
        True,
        "Do you assess critical suppliers and include cybersecurity requirements in contracts?",
        "Implement supplier security assessment, contract clauses, review cycles, and critical supplier monitoring.",
        "High",
        ["NIS2 Article 21(2)(d)"],
    ),
    Control(
        "NIS2-Art21-e",
        "NIS2",
        "Security in Network and Information Systems Acquisition and Development",
        "Security is integrated into system acquisition, development, and maintenance.",
        "Article 21 Security Measures",
        True,
        "Are SAST, DAST, dependency scanning, or penetration testing integrated into your development lifecycle?",
        "Implement DevSecOps controls, security gates in CI/CD, vulnerability scanning, and release risk reviews.",
        "High",
        ["NIS2 Article 21(2)(e)"],
    ),
    Control(
        "NIS2-Art21-f",
        "NIS2",
        "Vulnerability Handling and Disclosure",
        "Policies and procedures exist to assess control effectiveness and manage vulnerabilities.",
        "Article 21 Security Measures",
        True,
        "Do you have a vulnerability management process with defined patching SLAs?",
        "Define SLAs, perform recurring scans, track remediation, and validate patch deployment.",
        "Medium",
        ["NIS2 Article 21(2)(f)"],
    ),
    Control(
        "NIS2-Art21-g",
        "NIS2",
        "Cyber Hygiene and Cybersecurity Training",
        "Basic cyber hygiene practices and cybersecurity training are implemented.",
        "Article 21 Security Measures",
        True,
        "Do all staff, including management, receive cybersecurity training?",
        "Implement mandatory awareness training, management training, and recurring effectiveness checks.",
        "Low",
        ["NIS2 Article 21(2)(g)"],
    ),
    Control(
        "NIS2-Art21-h",
        "NIS2",
        "Cryptography and Encryption",
        "Cryptography and encryption are used where appropriate to protect information assets.",
        "Article 21 Security Measures",
        True,
        "Are sensitive data encrypted at rest and in transit using modern protocols and managed keys?",
        "Implement encryption at rest and in transit, key management, certificate lifecycle management, and rotation.",
        "Medium",
        ["NIS2 Article 21(2)(h)"],
    ),
    Control(
        "NIS2-Art21-i",
        "NIS2",
        "Multi-Factor Authentication",
        "Multi-factor authentication or continuous authentication solutions are used where appropriate.",
        "Article 21 Security Measures",
        True,
        "Is MFA enforced for remote access, privileged accounts, and critical systems?",
        "Deploy phishing-resistant MFA where possible and enforce MFA for remote and privileged access.",
        "Medium",
        ["NIS2 Article 21(2)(i)"],
    ),
    Control(
        "NIS2-Art23",
        "NIS2",
        "Significant Incident Notification",
        "Significant incidents are reported to the competent authority according to NIS2 timelines.",
        "Article 23 Reporting",
        True,
        "Do you know and document the early warning and incident notification process for significant incidents?",
        "Document NIS2 reporting criteria, reporting contacts, evidence requirements, and internal escalation timelines.",
        "High",
        ["NIS2 Article 23"],
    ),
]

ALL_FRAMEWORKS: Dict[str, List[Control]] = {
    "gdpr": GDPR_CONTROLS,
    "rgpd": GDPR_CONTROLS,  # backward-compatible alias
    "iso27001": ISO27001_CONTROLS,
    "nis2": NIS2_CONTROLS,
    "all": GDPR_CONTROLS + ISO27001_CONTROLS + NIS2_CONTROLS,
}

FRAMEWORK_LABELS = {
    "gdpr": "GDPR",
    "rgpd": "GDPR",
    "iso27001": "ISO/IEC 27001:2022",
    "nis2": "NIS2",
    "all": "All Frameworks",
}

STATUS_SCORE = {"Compliant": 1.0, "Partial": 0.5, "Non-Compliant": 0.0, "N/A": 0.0}


def compute_score(results: List[ControlResult]) -> float:
    """Return the weighted compliance score for all applicable results."""
    applicable = [r for r in results if r.status != "N/A"]
    if not applicable:
        return 0.0
    return round(sum(r.score for r in applicable) / len(applicable) * 100, 1)


def quick_assess(controls: List[Control]) -> List[ControlResult]:
    """Generate deterministic demo assessment results."""
    results: List[ControlResult] = []
    statuses = ["Compliant", "Compliant", "Partial", "Non-Compliant", "Partial"]
    notes_by_status = {
        "Compliant": "Control implemented and documented.",
        "Partial": "Partially implemented; formal documentation or full coverage is still missing.",
        "Non-Compliant": "Control not implemented. Immediate remediation is required.",
    }
    for i, ctrl in enumerate(controls):
        status = statuses[i % len(statuses)]
        results.append(ControlResult(ctrl, status, notes_by_status.get(status, ""), STATUS_SCORE[status]))
    return results


def interactive_assess(controls: List[Control]) -> List[ControlResult]:
    """Run an interactive assessment, asking one question per control."""
    results: List[ControlResult] = []
    total = len(controls)
    for i, ctrl in enumerate(controls, 1):
        print(f"\n{SEP}")
        print(f"  {C.BOLD}[{i}/{total}] {ctrl.id} — {ctrl.title}{C.RESET}")
        print(
            f"  {C.DIM}Framework: {ctrl.framework} | Mandatory: "
            f"{'Yes' if ctrl.mandatory else 'No'} | Effort: {ctrl.effort}{C.RESET}"
        )
        print(f"\n  {ctrl.question}")
        print(f"\n  {C.DIM}[1] Compliant  [2] Partial  [3] Non-Compliant  [4] N/A{C.RESET}")
        while True:
            try:
                choice = input("  Answer: ").strip()
                status = {"1": "Compliant", "2": "Partial", "3": "Non-Compliant", "4": "N/A"}.get(choice)
                if status:
                    break
                print("  Invalid option. Enter 1, 2, 3, or 4.")
            except (KeyboardInterrupt, EOFError):
                print("\n  Assessment interrupted.")
                sys.exit(0)

        notes = ""
        if status != "Compliant":
            notes = input("  Notes (optional): ").strip() or ctrl.remediation[:120]

        score = STATUS_SCORE[status]
        results.append(ControlResult(ctrl, status, notes, score))
        col = C.GREEN if status == "Compliant" else C.YELLOW if status == "Partial" else C.RED
        print(f"  {col}→ {status}{C.RESET}")
    return results


def build_report(org: str, framework: str, results: List[ControlResult]) -> ComplianceReport:
    return ComplianceReport(
        org_name=org,
        framework=FRAMEWORK_LABELS.get(framework, framework.upper()),
        date=datetime.now().strftime("%Y-%m-%d"),
        results=results,
        score=compute_score(results),
        compliant=sum(1 for r in results if r.status == "Compliant"),
        partial=sum(1 for r in results if r.status == "Partial"),
        non_compliant=sum(1 for r in results if r.status == "Non-Compliant"),
        na=sum(1 for r in results if r.status == "N/A"),
    )


def score_label(score: float) -> str:
    if score < 50:
        return "Critical"
    if score < 70:
        return "Low"
    if score < 85:
        return "Moderate"
    return "Good"


def generate_markdown(report: ComplianceReport) -> str:
    label = score_label(report.score)
    emoji = {"Critical": "🔴", "Low": "🟠", "Moderate": "🟡", "Good": "🟢"}[label]

    lines = [
        f"# 📋 Compliance Report — {report.framework}",
        f"**Organization:** {report.org_name} | **Date:** {report.date}",
        "",
        "---",
        "",
        "## Overall Result",
        "",
        f"### {emoji} Compliance Score: **{report.score}%** ({label})",
        "",
        "| Status | Controls |",
        "|---|:---:|",
        f"| ✅ Compliant | {report.compliant} |",
        f"| ⚠️ Partial | {report.partial} |",
        f"| ❌ Non-Compliant | {report.non_compliant} |",
        f"| ➖ N/A | {report.na} |",
        f"| **Total** | **{len(report.results)}** |",
        "",
    ]

    gaps = [r for r in report.results if r.status == "Non-Compliant"]
    partials = [r for r in report.results if r.status == "Partial"]

    if gaps:
        lines.append(f"## ❌ Critical Gaps ({len(gaps)} controls)\n")
        for r in gaps:
            lines.extend(
                [
                    f"### {r.control.id} — {r.control.title}",
                    f"**Framework:** {r.control.framework} | **Effort:** {r.control.effort} | "
                    f"**Mandatory:** {'Yes' if r.control.mandatory else 'No'}",
                    "",
                    f"**Current status:** {r.notes}",
                    "",
                    f"**Remediation:** {r.control.remediation}",
                    "",
                ]
            )

    if partials:
        lines.append(f"## ⚠️ Partial Compliance ({len(partials)} controls)\n")
        for r in partials:
            lines.extend(
                [
                    f"### {r.control.id} — {r.control.title}",
                    f"**Current status:** {r.notes}",
                    "",
                    f"**Required action:** {r.control.remediation}",
                    "",
                ]
            )

    priority_items = sorted(
        gaps + partials,
        key=lambda r: (
            0 if r.control.mandatory else 1,
            {"High": 0, "Medium": 1, "Low": 2}.get(r.control.effort, 3),
            r.control.framework,
            r.control.id,
        ),
    )
    effort_deadline = {"Low": "30 days", "Medium": "60 days", "High": "90 days"}

    lines.extend(
        [
            "## 🗓️ Remediation Plan",
            "",
            "| Priority | Framework | Control | Effort | Target Deadline |",
            "|:---:|---|---|:---:|---|",
        ]
    )
    for i, r in enumerate(priority_items[:15], 1):
        title = r.control.title[:60]
        lines.append(
            f"| {i} | {r.control.framework} | {r.control.id} — {title} | "
            f"{r.control.effort} | {effort_deadline.get(r.control.effort, '90 days')} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 📚 References",
            "- [GDPR — Regulation (EU) 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng)",
            "- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)",
            "- [NIS2 Directive — Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng)",
            "- [CNPD — Portuguese Data Protection Authority](https://www.cnpd.pt/)",
            "- [CNCS — Portuguese National Cybersecurity Centre](https://www.cncs.gov.pt/)",
            "",
            f"*Generated by compliance-checker v{__version__} — {datetime.now().isoformat()}*",
        ]
    )
    return "\n".join(lines)


def print_summary(report: ComplianceReport) -> None:
    score_col = C.GREEN if report.score >= 85 else C.YELLOW if report.score >= 70 else C.RED
    bar_len = int(report.score / 100 * 40)
    bar = "█" * bar_len + "░" * (40 - bar_len)
    print(f"\n{SEP2}")
    print(f"  {C.BOLD}COMPLIANCE REPORT — {report.framework.upper()}{C.RESET}")
    print(f"  Organization : {report.org_name}")
    print(SEP)
    print(f"  {score_col}{C.BOLD}Score: {report.score}%{C.RESET}  [{bar}]")
    print(
        f"  ✅ Compliant: {report.compliant}  ⚠ Partial: {report.partial}  "
        f"❌ Non-Compliant: {report.non_compliant}  ➖ N/A: {report.na}"
    )
    print(SEP)
    if report.non_compliant > 0:
        print(f"\n  {C.RED}Critical gaps:{C.RESET}")
        for r in report.results:
            if r.status == "Non-Compliant":
                mandatory = f"{C.RED}[MANDATORY]{C.RESET} " if r.control.mandatory else ""
                print(f"  ❌ {mandatory}{r.control.id} — {r.control.title}")
    print(SEP2)


def write_output(path: str, content: str) -> None:
    Path(path).write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="compliance-checker",
        description="Compliance Checker — GDPR · ISO/IEC 27001:2022 · NIS2",
    )
    parser.add_argument(
        "--framework",
        choices=list(ALL_FRAMEWORKS.keys()),
        default="all",
        help="Framework to assess: gdpr, iso27001, nis2, all. The legacy alias rgpd is also accepted.",
    )
    parser.add_argument("--org", default="Organization", help="Organization name")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run an interactive assessment")
    parser.add_argument("--demo", action="store_true", help="Generate deterministic demo assessment results")
    parser.add_argument("-o", "--output", help="Output file path (.md by default, .json when --json is used)")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Print JSON output")
    parser.add_argument("--list", action="store_true", help="List all available controls")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument("--version", action="version", version=f"compliance-checker {__version__}")
    args = parser.parse_args()

    stream = sys.stderr if args.json_out else sys.stdout
    if not args.no_banner:
        print(BANNER, file=stream)

    controls = ALL_FRAMEWORKS.get(args.framework, [])

    if args.list:
        print(f"\n  {C.BOLD}Available controls — {FRAMEWORK_LABELS.get(args.framework, args.framework)}:{C.RESET}\n")
        for ctrl in controls:
            mand = f"{C.RED}[M]{C.RESET}" if ctrl.mandatory else f"{C.DIM}[ ]{C.RESET}"
            print(f"  {mand} {ctrl.id:<15} {ctrl.framework:<10} {ctrl.title}")
        print(f"\n  Total: {len(controls)} controls")
        return

    if args.json_out:
        print(
            f"Framework: {FRAMEWORK_LABELS.get(args.framework, args.framework)} | Controls: {len(controls)}",
            file=sys.stderr,
        )
    else:
        print(f"  {C.DIM}Framework: {FRAMEWORK_LABELS.get(args.framework, args.framework)} | Controls: {len(controls)}{C.RESET}")

    if args.interactive:
        results = interactive_assess(controls)
    else:
        results = quick_assess(controls)

    report = build_report(args.org, args.framework, results)

    if args.json_out:
        json_text = json.dumps(report.to_dict(), indent=2)
        print(json_text)
        if args.output:
            write_output(args.output, json_text + "\n")
            print(f"Report written to: {args.output}", file=sys.stderr)
    else:
        print_summary(report)
        md = generate_markdown(report)
        out = args.output or f"compliance_{args.framework}_{datetime.now().strftime('%Y%m%d')}.md"
        write_output(out, md + "\n")
        print(f"\n  {C.GREEN}[✓] Markdown report: {out}{C.RESET}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
ir_checklist.py — Incident Response Checklist Generator v1.0.0
===============================================================
Generates dynamic incident response checklists based on the incident type,
aligned with NIST SP 800-61, SANS PICERL, and MITRE ATT&CK.

Types: ransomware · data-breach · phishing · malware · ddos · insider ·
       supply-chain · web-compromise · credential-stuffing · zero-day

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 14/06/2026
Req.   : Python 3.8+ | Zero external dependencies
"""
from __future__ import annotations
import argparse, json, sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
 ██╗██████╗      ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗██╗     ██╗███████╗████████╗
 ██║██╔══██╗    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██║     ██║██╔════╝╚══██╔══╝
 ██║██████╔╝    ██║     ███████║█████╗  ██║     █████╔╝ ██║     ██║███████╗   ██║
 ██║██╔══██╗    ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██║     ██║╚════██║   ██║
 ██║██║  ██║    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║███████║   ██║
 ╚═╝╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝╚══════╝   ╚═╝{C.RESET}
{C.DIM} v{__version__} — IR Checklist Generator | NIST SP 800-61 | SANS PICERL | MITRE ATT&CK{C.RESET}
"""

SEP  = "━"*72
SEP2 = "═"*72

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ChecklistItem:
    phase:       str      # Preparation/Identification/Containment/Eradication/Recovery/Lessons
    priority:    str      # IMMEDIATE / HIGH / MEDIUM / LOW
    action:      str
    responsible: str      # IR Lead / SOC / IT / Management / Legal / Communications
    time_target: str      # < 15min / < 1h / < 4h / < 24h / < 72h
    notes:       str = ""
    mitre:       str = ""
    completed:   bool = False

@dataclass
class IRChecklist:
    incident_type: str
    severity:      str
    timestamp:     str
    analyst:       str
    org:           str
    items:         List[ChecklistItem]
    metadata:      dict = field(default_factory=dict)

    @property
    def by_phase(self) -> Dict[str, List[ChecklistItem]]:
        phases: Dict[str, List[ChecklistItem]] = {}
        for item in self.items:
            phases.setdefault(item.phase, []).append(item)
        return phases

    def to_dict(self) -> dict:
        return {
            "incident_type": self.incident_type,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "analyst": self.analyst,
            "org": self.org,
            "metadata": self.metadata,
            "items": [{
                "phase": i.phase, "priority": i.priority,
                "action": i.action, "responsible": i.responsible,
                "time_target": i.time_target, "completed": i.completed,
            } for i in self.items],
        }

# ══════════════════════════════════════════════════════════════════════════════
# PHASE LABELS (NIST SP 800-61 + SANS PICERL)
# ══════════════════════════════════════════════════════════════════════════════

PHASES = [
    "Preparation",
    "Identification",
    "Containment",
    "Eradication",
    "Recovery",
    "Lessons Learned",
]

PHASE_ICONS = {
    "Preparation":     "🛡️",
    "Identification":  "🔍",
    "Containment":     "🔒",
    "Eradication":     "🗑️",
    "Recovery":        "🔄",
    "Lessons Learned": "📚",
}

# ══════════════════════════════════════════════════════════════════════════════
# COMMON ITEMS (all categories)
# ══════════════════════════════════════════════════════════════════════════════

COMMON_ITEMS: List[ChecklistItem] = [
    # Identification
    ChecklistItem("Identification","IMMEDIATE",
        "Record detection date/time, who detected it, and how it was detected",
        "IR Lead","< 15min",
        "Document: timestamp, alert source (SIEM/user/partner), detection method"),
    ChecklistItem("Identification","IMMEDIATE",
        "Assign a ticket/case number to the incident",
        "IR Lead","< 15min",
        "Use a ticketing system (Jira, ServiceNow). Format: INC-YYYY-NNNN"),
    ChecklistItem("Identification","IMMEDIATE",
        "Classify initial severity (P1/P2/P3/P4)",
        "IR Lead","< 15min",
        "P1: critical impact/services down. P2: high impact. P3: medium. P4: low"),
    ChecklistItem("Identification","HIGH",
        "Notify the chain of command and relevant stakeholders",
        "IR Lead","< 1h",
        "P1/P2: immediately notify the CISO, CTO, and senior management"),
    ChecklistItem("Identification","HIGH",
        "Open a dedicated incident communication channel (Slack/Teams)",
        "IR Lead","< 1h",
        "#incident-NNNN — keep separate from normal operational channels"),

    # Containment
    ChecklistItem("Containment","IMMEDIATE",
        "Preserve evidence before taking any containment action",
        "IR Lead / SOC","< 15min",
        "Photograph screens, export logs, and capture memory if necessary"),
    ChecklistItem("Containment","HIGH",
        "Document all containment actions with timestamps",
        "IR Lead","< 1h",
        "Action log: who did what, when, and why — chain of custody"),

    # Lessons Learned
    ChecklistItem("Lessons Learned","MEDIUM",
        "Schedule a post-mortem meeting (within 5 business days)",
        "IR Lead","< 72h after resolution",
        "Include: IR team, IT, affected management, CISO"),
    ChecklistItem("Lessons Learned","MEDIUM",
        "Document the complete incident timeline",
        "IR Lead","< 72h after resolution",
        "From the first indicator to full resolution"),
    ChecklistItem("Lessons Learned","MEDIUM",
        "Identify the root cause and gaps in security controls",
        "IR Lead","< 1 week",
        "5 Whys analysis. Map to MITRE ATT&CK"),
    ChecklistItem("Lessons Learned","MEDIUM",
        "Update runbooks and playbooks based on the incident",
        "IR Lead","< 2 weeks",
        "Improve detection, containment, and response for future incidents"),
    ChecklistItem("Lessons Learned","LOW",
        "Submit IOCs to threat intelligence platforms (MISP, OTX)",
        "SOC","< 1 week",
        "Share sanitized indicators for the benefit of the community"),
]

# ══════════════════════════════════════════════════════════════════════════════
# INCIDENT-SPECIFIC CHECKLISTS
# ══════════════════════════════════════════════════════════════════════════════

INCIDENT_CHECKLISTS: Dict[str, List[ChecklistItem]] = {

    "ransomware": [
        # Identification
        ChecklistItem("Identification","IMMEDIATE",
            "Confirm the presence of encrypted files and a ransom note",
            "SOC / IR Lead","< 15min",
            "Check for changed extensions, README_DECRYPT.txt, and altered wallpaper",
            "T1486 — Data Encrypted for Impact"),
        ChecklistItem("Identification","IMMEDIATE",
            "Identify affected systems and the scope of encryption",
            "IT / SOC","< 15min",
            "List all systems with files modified in the last few hours"),
        ChecklistItem("Identification","HIGH",
            "Check whether shadow copies were deleted",
            "IT","< 1h",
            "vssadmin list shadows — if empty after the attack: shadow copies were deleted",
            "T1490 — Inhibit System Recovery"),
        ChecklistItem("Identification","HIGH",
            "Identify the initial access vector (phishing, RDP, vulnerability)",
            "IR Lead / SOC","< 4h",
            "Analyze email, authentication, and remote-access logs"),

        # Containment
        ChecklistItem("Containment","IMMEDIATE",
            "IMMEDIATELY ISOLATE affected systems from the network (cable and Wi-Fi)",
            "IT / IR Lead","< 15min",
            "⚠ HIGHEST PRIORITY — every minute means more encrypted files",
            "T1486"),
        ChecklistItem("Containment","IMMEDIATE",
            "Disable network shares and mapped drives on affected systems",
            "IT","< 15min",
            "Prevent propagation to network files and connected backups"),
        ChecklistItem("Containment","IMMEDIATE",
            "Block identified C2 IPs on the perimeter firewall",
            "IT / SOC","< 15min",
            "Extract IPs from the ransom note and network traffic for the blocklist"),
        ChecklistItem("Containment","HIGH",
            "Suspend (do not power off) affected systems to preserve RAM",
            "IT","< 1h",
            "RAM may contain the encryption key — useful for decryption tools"),
        ChecklistItem("Containment","HIGH",
            "Revoke compromised credentials and force password resets",
            "IT","< 1h",
            "Especially revoke privileged accounts"),
        ChecklistItem("Containment","HIGH",
            "Verify and protect offline backups — ensure they were not affected",
            "IT","< 1h",
            "If cloud backups are connected, check whether encrypted files were synchronized"),

        # Eradication
        ChecklistItem("Eradication","HIGH",
            "Identify the ransomware family",
            "SOC / IR Lead","< 4h",
            "Check the hash on VirusTotal and the extension/note format on ID-Ransomware.malwarehunterteam.com"),
        ChecklistItem("Eradication","HIGH",
            "Check whether a free decryption tool is available at nomoreransom.org",
            "IR Lead","< 4h",
            "Before considering any other option — free and legitimate"),
        ChecklistItem("Eradication","HIGH",
            "Remove ransomware persistence mechanisms",
            "IT / SOC","< 4h",
            "Run keys, scheduled tasks, services, modified GPOs",
            "T1053, T1543"),
        ChecklistItem("Eradication","MEDIUM",
            "Reimage compromised systems (preferred over manual removal)",
            "IT","< 24h",
            "Clean gold image + updated patches before reconnecting"),

        # Recovery
        ChecklistItem("Recovery","HIGH",
            "Restore data from verified clean backups",
            "IT","< 24h",
            "Verify backup hashes. Confirm they predate the compromise"),
        ChecklistItem("Recovery","HIGH",
            "Test restored systems in an isolated environment before reconnecting",
            "IT / SOC","< 24h",
            "Verify integrity, functionality, and absence of malware"),
        ChecklistItem("Recovery","MEDIUM",
            "Assess regulatory notification obligations (GDPR, NIS2, sector-specific)",
            "Legal / Compliance","< 72h",
            "GDPR Art.33: 72h to notify CNPD if personal data is affected. NIS2: 24h initial alert"),
        ChecklistItem("Recovery","MEDIUM",
            "Contact the insurer (if cyber insurance exists) and legal counsel",
            "Management / Legal","< 24h",
            "Document everything before communicating externally"),
    ],

    "data-breach": [
        ChecklistItem("Identification","IMMEDIATE",
            "Confirm and classify affected data (personal, financial, IP, credentials)",
            "IR Lead / Legal","< 15min",
            "Determine whether the data includes personal data (GDPR), health data, or financial data (PCI)"),
        ChecklistItem("Identification","IMMEDIATE",
            "Estimate the number of affected records/data subjects",
            "IR Lead / DBA","< 1h",
            "Initial estimate — refine throughout the investigation"),
        ChecklistItem("Identification","HIGH",
            "Identify the access vector and exposure duration",
            "SOC / IR Lead","< 4h",
            "When did the first unauthorized access occur? Review database, application, and network logs"),
        ChecklistItem("Identification","HIGH",
            "Determine whether data has already been exfiltrated or published",
            "SOC","< 4h",
            "Monitor paste sites, dark web sources, and threat-intelligence forums"),

        # Containment
        ChecklistItem("Containment","IMMEDIATE",
            "Revoke compromised credentials/tokens that enabled access",
            "IT / SOC","< 15min",
            "API keys, session tokens, and passwords for compromised accounts"),
        ChecklistItem("Containment","IMMEDIATE",
            "Block the identified exfiltration IP/channel",
            "IT / SOC","< 15min",""),
        ChecklistItem("Containment","HIGH",
            "Restrict access to the affected database to the minimum necessary",
            "DBA / IT","< 1h",
            "Review and revoke excessive permissions"),
        ChecklistItem("Containment","HIGH",
            "Preserve database access logs for forensic investigation",
            "DBA / SOC","< 1h",
            "Export and preserve logs before they are overwritten"),

        # Legal & Regulatory
        ChecklistItem("Eradication","IMMEDIATE",
            "⚠ GDPR Art.33: Assess whether CNPD notification is required within 72h",
            "Legal / DPO","< 1h",
            "If personal data is affected: notify CNPD within 72h. Prepare the initial notification"),
        ChecklistItem("Eradication","HIGH",
            "Assess whether data subjects must be notified (GDPR Art.34)",
            "Legal / DPO / Communications","< 24h",
            "If there is a high risk to data subjects: individual notification is mandatory"),
        ChecklistItem("Eradication","HIGH",
            "Document the entire investigation for the regulatory report",
            "IR Lead / Legal","< 24h",
            "Timeline, affected data, actions taken, and future preventive measures"),
        ChecklistItem("Recovery","HIGH",
            "Remediate the vulnerability that enabled access",
            "IT / Dev","< 24h",""),
        ChecklistItem("Recovery","MEDIUM",
            "Implement additional monitoring on affected databases",
            "SOC / DBA","< 72h",
            "Query logging, anomalous-access alerts, DLP"),
    ],

    "phishing": [
        ChecklistItem("Identification","IMMEDIATE",
            "Obtain the original email (full headers + attachments) for analysis",
            "SOC","< 15min",
            "Request the full .eml from the user — not just a screenshot"),
        ChecklistItem("Identification","IMMEDIATE",
            "Check whether the user clicked the link or opened the attachment",
            "SOC / IR Lead","< 15min",
            "Conduct a quick user interview — establish urgency without causing alarm"),
        ChecklistItem("Identification","IMMEDIATE",
            "Identify all users who received the same email",
            "IT / SOC","< 15min",
            "Search the email gateway by subject, sender, and attachment hash"),
        ChecklistItem("Identification","HIGH",
            "Analyze the URL and attachment in a sandbox (Any.Run, VirusTotal, Hybrid-Analysis)",
            "SOC","< 1h",
            "Do not open on a production system. Use an isolated sandbox"),
        ChecklistItem("Identification","HIGH",
            "Check whether credentials were entered into the fake page",
            "SOC / IR Lead","< 1h",
            "If yes: treat as credential compromise — escalate"),

        # Containment
        ChecklistItem("Containment","IMMEDIATE",
            "Block the malicious URL/domain in the proxy/DNS/email gateway",
            "IT / SOC","< 15min",
            "Add to the blocklist: URL, domain, and phishing-server IP"),
        ChecklistItem("Containment","IMMEDIATE",
            "Remove the email from ALL mailboxes in the organization",
            "IT","< 15min",
            "Microsoft Purview / Google Vault: search & delete by message-id"),
        ChecklistItem("Containment","HIGH",
            "If credentials were entered: revoke and force an immediate reset",
            "IT","< 1h",
            "Enable MFA if not already enabled. Review active sessions"),
        ChecklistItem("Containment","HIGH",
            "Isolate the user's system if the attachment was opened",
            "IT","< 1h",
            "Treat as a confirmed compromise — follow malware procedures"),

        # Eradication
        ChecklistItem("Eradication","HIGH",
            "Review email-gateway rules to prevent similar emails",
            "IT","< 4h",
            "SPF, DKIM, DMARC — verify the sender domain configuration"),
        ChecklistItem("Eradication","MEDIUM",
            "Report the phishing domain to the registrar and hosting provider",
            "IR Lead","< 24h",
            "NCSC, Google Safe Browsing, Microsoft SmartScreen — takedown request"),

        # Recovery
        ChecklistItem("Recovery","MEDIUM",
            "Send a security alert to all users about the attack",
            "Communications / IR Lead","< 4h",
            "Tone: informative, not alarmist. Include indicators users should report"),
        ChecklistItem("Recovery","LOW",
            "Run a simulated phishing exercise within 30 days to assess awareness",
            "IR Lead / Security Team","< 1 month",""),
    ],

    "ddos": [
        ChecklistItem("Identification","IMMEDIATE",
            "Confirm that this is a DDoS attack and not an internal infrastructure failure",
            "IT / SOC","< 15min",
            "Check network metrics, server CPU/RAM, and internal service status"),
        ChecklistItem("Identification","IMMEDIATE",
            "Identify the attack type: volumetric, protocol, or layer 7",
            "SOC / IR Lead","< 15min",
            "Volumetric: Gbps. Protocol: pps (SYN flood). L7: req/s (HTTP flood)"),
        ChecklistItem("Identification","HIGH",
            "Capture a sample of malicious traffic for analysis",
            "SOC","< 1h",
            "tcpdump/Wireshark — identify IPs, ports, and the attack signature"),

        # Containment
        ChecklistItem("Containment","IMMEDIATE",
            "Enable DDoS protection on the CDN/ISP/cloud provider",
            "IT","< 15min",
            "Cloudflare Under Attack Mode, AWS Shield, Azure DDoS Protection"),
        ChecklistItem("Containment","IMMEDIATE",
            "Implement emergency rate limiting on the load balancer/WAF",
            "IT","< 15min",""),
        ChecklistItem("Containment","HIGH",
            "Contact the ISP/upstream provider for traffic blackholing",
            "IT / Management","< 1h",
            "BGP blackholing for volumetric attacks — fast mitigation but it takes the service offline"),
        ChecklistItem("Containment","HIGH",
            "Block top attacking IPs/ASNs if the attack uses fixed IPs",
            "IT / SOC","< 1h",
            "Caution: botnets use legitimate IPs — verify before blocking CIDRs"),
        ChecklistItem("Containment","HIGH",
            "Enable geo-blocking for regions not used by the organization",
            "IT","< 1h",
            "If the business operates only in PT/EU: temporarily block the rest of the world"),

        # Recovery
        ChecklistItem("Recovery","HIGH",
            "Monitor network and service metrics after mitigation",
            "SOC / IT","< 1h",""),
        ChecklistItem("Recovery","MEDIUM",
            "Review and adjust infrastructure capacity (auto-scaling)",
            "IT","< 24h",""),
        ChecklistItem("Recovery","MEDIUM",
            "Report the attack to CNCS and register it in the incident platform",
            "IR Lead","< 24h",""),
    ],

    "insider-threat": [
        ChecklistItem("Identification","IMMEDIATE",
            "⚠ MAXIMUM CONFIDENTIALITY — involve only the IR Lead, CISO, and HR/Legal",
            "IR Lead / Management","< 15min",
            "Do not alert other IT members who may know the suspect"),
        ChecklistItem("Identification","IMMEDIATE",
            "Document initial evidence without confronting the suspect",
            "IR Lead / Legal","< 15min",
            "Preserve digital evidence before taking any action"),
        ChecklistItem("Identification","HIGH",
            "Review the suspect user's access logs for sensitive data",
            "IR Lead / SOC","< 4h",
            "After-hours access, bulk downloads, and access to data outside the user's role"),
        ChecklistItem("Identification","HIGH",
            "Analyze emails sent by the suspect to external accounts",
            "IR Lead / Legal","< 4h",
            "Legal authorization may be required in some countries — check with Legal first"),

        # Containment
        ChecklistItem("Containment","HIGH",
            "Silently revoke access or wait for legal instruction",
            "IT / Legal","< 4h",
            "The decision to revoke vs. monitor must be made with Legal and HR"),
        ChecklistItem("Containment","HIGH",
            "Preserve all logs and evidence in a secure location",
            "IR Lead / SOC","< 4h",
            "Chain of custody — immutable logs, digitally signed if possible"),
        ChecklistItem("Eradication","HIGH",
            "Coordinate with HR and Legal for disciplinary/legal proceedings",
            "Management / Legal / RH","< 24h",""),
        ChecklistItem("Recovery","MEDIUM",
            "Review access policies (least privilege, segregation of duties)",
            "IT / IR Lead","< 1 week",""),
    ],

    "web-compromise": [
        ChecklistItem("Identification","IMMEDIATE",
            "Identify the type of compromise: defacement, webshell, malware injection",
            "SOC / IR Lead","< 15min",""),
        ChecklistItem("Identification","HIGH",
            "Check whether a webshell is installed and identify its location",
            "SOC / Dev","< 1h",
            "grep -r 'eval\\|base64_decode\\|system\\|passthru' /var/www/"),
        ChecklistItem("Identification","HIGH",
            "Analyze web-server logs to identify the entry vector",
            "SOC","< 1h",
            "access.log and error.log — look for suspicious uploads, SQLi, and path traversal"),

        # Containment
        ChecklistItem("Containment","IMMEDIATE",
            "Place the website in maintenance mode / offline",
            "IT","< 15min",
            "Prevent visitors from being affected by injected malware"),
        ChecklistItem("Containment","IMMEDIATE",
            "Remove identified webshells and malicious files",
            "Dev / IT","< 1h",""),
        ChecklistItem("Containment","HIGH",
            "Change all web-application credentials (DB, admin, API keys)",
            "IT / Dev","< 1h",""),
        ChecklistItem("Eradication","HIGH",
            "Restore application files from a clean repository/backup",
            "Dev / IT","< 4h",
            "Compare hashes with a known-good production version"),
        ChecklistItem("Eradication","HIGH",
            "Remediate the exploited vulnerability and apply patches",
            "Dev","< 4h",""),
        ChecklistItem("Recovery","HIGH",
            "Perform a full security scan before returning to production",
            "SOC / Dev","< 24h",
            "OWASP ZAP, Nikto, and manual review of modified code"),
    ],

    "zero-day": [
        ChecklistItem("Identification","IMMEDIATE",
            "Confirm this is a zero-day (no patch available) vs. a known unpatched vulnerability",
            "IR Lead / SOC","< 15min",""),
        ChecklistItem("Identification","HIGH",
            "Identify all systems running the vulnerable software/version",
            "IT / SOC","< 1h",
            "Asset inventory — all systems containing the affected component"),
        ChecklistItem("Identification","HIGH",
            "Monitor vendor/CERT communications for a patch or mitigation",
            "IR Lead","< 1h",
            "Subscribe to alerts: CNCS, CERT.PT, vendor advisories, CISA"),

        # Containment
        ChecklistItem("Containment","IMMEDIATE",
            "Implement available temporary mitigations (WAF rules, disable feature)",
            "IT / SOC","< 1h",""),
        ChecklistItem("Containment","HIGH",
            "Isolate critical vulnerable systems until a patch is available",
            "IT","< 4h",""),
        ChecklistItem("Containment","HIGH",
            "Increase monitoring on vulnerable systems (specific IOCs)",
            "SOC","< 4h",""),
        ChecklistItem("Eradication","HIGH",
            "Apply the vendor patch as soon as it is available and tested",
            "IT","< 24h after patch",""),
        ChecklistItem("Eradication","HIGH",
            "Check whether exploitation occurred before detection",
            "SOC / IR Lead","< 24h",
            "Review historical logs using vulnerability-specific IOCs"),
    ],
}

# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_checklist(incident_type: str, severity: str,
                     analyst: str, org: str,
                     custom_items: List[dict] = None) -> IRChecklist:
    specific = INCIDENT_CHECKLISTS.get(incident_type, [])
    items    = specific + COMMON_ITEMS

    if custom_items:
        for ci in custom_items:
            items.append(ChecklistItem(**ci))

    # Sort by phase (PICERL order), then by priority
    phase_order    = {p: i for i, p in enumerate(PHASES)}
    priority_order = {"IMMEDIATE":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    items.sort(key=lambda i: (
        phase_order.get(i.phase, 99),
        priority_order.get(i.priority, 99)
    ))

    metadata = {
        "incident_type": incident_type,
        "severity": severity,
        "framework": "NIST SP 800-61 Rev.2 + SANS PICERL",
        "total_items": len(items),
        "immediate_actions": sum(1 for i in items if i.priority == "IMMEDIATE"),
    }

    return IRChecklist(incident_type, severity,
                        datetime.now().isoformat(), analyst, org,
                        items, metadata)

# ══════════════════════════════════════════════════════════════════════════════
# MARKDOWN GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_markdown(checklist: IRChecklist) -> str:
    sev_emoji = {"P1":"🔴","P2":"🟠","P3":"🟡","P4":"🟢"}.get(checklist.severity,"🔴")
    lines = [
        f"# {sev_emoji} IR Checklist — {checklist.incident_type.replace('-',' ').title()}",
        f"",
        f"| Field | Detail |",
        f"|---|---|",
        f"| **Incident Type** | {checklist.incident_type.replace('-',' ').title()} |",
        f"| **Severity** | {checklist.severity} |",
        f"| **Analyst** | {checklist.analyst} |",
        f"| **Organization** | {checklist.org} |",
        f"| **Generated At** | {checklist.timestamp[:19]} |",
        f"| **Framework** | NIST SP 800-61 Rev.2 + SANS PICERL |",
        f"| **Total Actions** | {len(checklist.items)} |",
        f"",
        f"> ⚠️ **Immediate:** {checklist.metadata.get('immediate_actions',0)} IMMEDIATE actions — execute within the first 15 minutes.",
        f"",
        f"---",
        f"",
    ]

    pri_em = {"IMMEDIATE":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    resp_em = {"IR Lead":"👤","SOC":"🔭","IT":"💻","Management":"👔",
               "Legal":"⚖️","DPO":"🔐","Communications":"📢","Dev":"👨‍💻"}

    for phase in PHASES:
        phase_items = checklist.by_phase.get(phase, [])
        if not phase_items:
            continue
        icon = PHASE_ICONS.get(phase,"")
        lines += [
            f"## {icon} {phase}",
            f"",
            f"| # | Priority | Action | Responsible | Deadline | ✅ |",
            f"|:---:|:---:|---|---|:---:|:---:|",
        ]
        for i, item in enumerate(phase_items, 1):
            pri  = pri_em.get(item.priority,"")
            resp = resp_em.get(item.responsible.split("/")[0].strip(),"👤")
            lines.append(
                f"| {i} | {pri} {item.priority} | {item.action} "
                f"| {resp} {item.responsible} | {item.time_target} | ☐ |")
            if item.notes:
                lines.append(f"| | | *{item.notes[:100]}* | | | |")
        lines.append("")

    lines += [
        f"---",
        f"",
        f"## 📞 Emergency Contacts",
        f"",
        f"| Role | Name | Contact |",
        f"|---|---|---|",
        f"| IR Lead | | |",
        f"| CISO | | |",
        f"| IT Manager | | |",
        f"| Legal | | |",
        f"| DPO | | |",
        f"| CNCS (PT) | CERT.PT | +351 211 120 109 |",
        f"| CNPD (PT) | Data Protection | geral@cnpd.pt |",
        f"",
        f"## 📋 Action Log",
        f"",
        f"| Timestamp | Action | Responsible | Notes |",
        f"|---|---|---|---|",
        f"| | | | |",
        f"",
        f"---",
        f"*Generated by ir-checklist v{__version__} — {checklist.timestamp[:10]}*",
    ]
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# TERMINAL OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

PRI_COL = {"IMMEDIATE":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN}

def print_checklist(checklist: IRChecklist, phase_filter: str = None) -> None:
    sev_col = {"P1":C.RED,"P2":C.YELLOW,"P3":C.CYAN,"P4":C.GREEN}.get(checklist.severity,C.RED)
    print(f"\n{SEP2}")
    print(f"  {C.BOLD}IR CHECKLIST — {checklist.incident_type.upper()}{C.RESET}  "
          f"{sev_col}{checklist.severity}{C.RESET}")
    print(f"  Analyst: {checklist.analyst} | Org: {checklist.org}")
    print(f"  Total: {len(checklist.items)} actions | "
          f"Immediate: {checklist.metadata.get('immediate_actions',0)}")
    print(SEP2)

    for phase in PHASES:
        if phase_filter and phase.lower() != phase_filter.lower():
            continue
        items = checklist.by_phase.get(phase, [])
        if not items:
            continue
        icon = PHASE_ICONS.get(phase,"")
        print(f"\n  {C.BOLD}{icon} {phase.upper()}{C.RESET}")
        print(f"  {'─'*64}")
        for i, item in enumerate(items, 1):
            col = PRI_COL.get(item.priority, "")
            print(f"  {col}[{item.priority:<9}]{C.RESET} ☐  {item.action}")
            print(f"               {C.DIM}→ {item.responsible} | {item.time_target}{C.RESET}")
            if item.notes:
                print(f"               {C.DIM}💡 {item.notes[:80]}{C.RESET}")

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

INCIDENT_TYPES = list(INCIDENT_CHECKLISTS.keys())

def main() -> None:
    parser = argparse.ArgumentParser(prog="ir-checklist",
        description="IR Checklist Generator — NIST SP 800-61 | SANS PICERL")
    parser.add_argument("type", nargs="?",
        choices=INCIDENT_TYPES + ["list"],
        default="list", help="Incident type")
    parser.add_argument("--severity","-s",
        choices=["P1","P2","P3","P4"], default="P1")
    parser.add_argument("--analyst",  default="IR Lead")
    parser.add_argument("--org",      default="Organization")
    parser.add_argument("--phase",    choices=[p.lower() for p in PHASES],
        help="Filter by PICERL phase")
    parser.add_argument("-o","--output", help="Output .md file")
    parser.add_argument("--json",     action="store_true", dest="json_out")
    parser.add_argument("--no-banner",action="store_true")
    parser.add_argument("--version",  action="version", version=f"ir-checklist {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    if args.type == "list" or not args.type:
        print(f"\n  {C.BOLD}Available incident types:{C.RESET}\n")
        for itype in INCIDENT_TYPES:
            count = len(INCIDENT_CHECKLISTS[itype]) + len(COMMON_ITEMS)
            print(f"  {C.CYAN}●{C.RESET} {itype:<25} ({count} actions)")
        print(f"\n  Usage: ir-checklist ransomware --severity P1 -o checklist.md")
        return

    checklist = build_checklist(args.type, args.severity, args.analyst, args.org)

    if args.json_out:
        print(json.dumps(checklist.to_dict(), indent=2, ensure_ascii=False))
    else:
        print_checklist(checklist, phase_filter=args.phase)

    out = args.output or f"ir_{args.type}_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
    md  = generate_markdown(checklist)
    Path(out).write_text(md, encoding="utf-8")
    print(f"\n  {C.GREEN}[✓] Markdown checklist: {out}{C.RESET}")
    print(f"  {C.DIM}{len(checklist.items)} actions | "
          f"{checklist.metadata.get('immediate_actions',0)} IMMEDIATE{C.RESET}")

if __name__ == "__main__":
    main()

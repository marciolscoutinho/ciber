#!/usr/bin/env python3
"""
cloud_scanner.py — Cloud Misconfiguration Scanner v1.0.1
=========================================================
Detects common security misconfigurations in cloud environments.

The scanner performs static analysis of Terraform files for AWS, Azure, and
Google Cloud Platform resources. It can also run a small set of live AWS checks
through the AWS CLI when credentials are already configured locally.

Author      : Marcio Coutinho — Cybersecurity Specialist, Porto, Portugal
Date        : 26/06/2023
Requirements: Python 3.8+ | Zero external Python dependencies
Optional    : AWS CLI for live AWS checks
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
from typing import Dict, List, Optional, Sequence, Tuple

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
  ██████╗██╗      ██████╗ ██╗   ██╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║     ██║     ██║   ██║██║   ██║██║  ██║    ███████╗██║     ███████║██╔██╗ ██║
 ██║     ██║     ██║   ██║██║   ██║██║  ██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{C.RESET}
{C.DIM} v{__version__} — Cloud Misconfiguration Scanner | Terraform · AWS Live | Authorized Use Only{C.RESET}
"""

SEP = "━" * 72
SEP2 = "═" * 72
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COL = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN, "LOW": C.GREEN, "INFO": C.DIM}


@dataclass
class CloudFinding:
    severity: str
    provider: str
    service: str
    rule_id: str
    title: str
    resource: str
    description: str
    evidence: str
    remediation: str
    cis_ref: str = ""
    file: str = ""
    line: int = 0


@dataclass
class CloudReport:
    scan_type: str
    target: str
    timestamp: str
    provider: str
    findings: List[CloudFinding]
    score: float
    resources_checked: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "timestamp": self.timestamp,
            "provider": self.provider,
            "score": self.score,
            "resources_checked": self.resources_checked,
            "findings": [finding.__dict__ for finding in self.findings],
        }


class TerraformScanner:
    """Scans .tf files for common cloud security misconfigurations."""

    def scan_file(self, path: Path) -> List[CloudFinding]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        findings: List[CloudFinding] = []
        lines = content.splitlines()
        self._scan_security_groups(path, lines, findings)
        self._scan_s3(path, lines, findings)
        self._scan_iam(path, lines, findings)
        self._scan_rds(path, lines, findings)
        self._scan_ec2(path, lines, findings)
        self._scan_cloudtrail(path, lines, findings)
        self._scan_azure_storage(path, lines, findings)
        self._scan_gcp_storage(path, lines, findings)
        return findings

    def scan_directory(self, path: str) -> Tuple[List[CloudFinding], int]:
        root = Path(path)
        if root.is_file() and root.suffix == ".tf":
            return self.scan_file(root), 1
        if not root.exists():
            return [], 0

        tf_files = [
            f for f in root.rglob("*.tf")
            if not any(part in f.parts for part in (".terraform", "node_modules", ".git"))
        ]
        findings: List[CloudFinding] = []
        for tf_file in tf_files:
            findings.extend(self.scan_file(tf_file))
        return findings, len(tf_files)

    @staticmethod
    def _window(lines: List[str], start_index: int, size: int = 35) -> str:
        return "\n".join(lines[start_index:min(start_index + size, len(lines))])

    @staticmethod
    def _line_resource(resource_type: str, line: int) -> str:
        return f"{resource_type} (line {line})"

    def _scan_security_groups(self, path: Path, lines: List[str], findings: List[CloudFinding]) -> None:
        for idx, line in enumerate(lines):
            if not re.search(r'resource\s+"aws_security_group"', line):
                continue
            resource_line = idx + 1
            resource_block = self._window(lines, idx, 120)
            for match in re.finditer(r'ingress\s*\{(?P<body>.*?)\n\s*\}', resource_block, re.DOTALL | re.IGNORECASE):
                body = match.group("body")
                if not re.search(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', body, re.IGNORECASE):
                    continue
                from_port = self._extract_numeric_value(body, "from_port", default="0")
                to_port = self._extract_numeric_value(body, "to_port", default="65535")
                severity = "CRITICAL" if from_port in {"0", "22", "3389"} else "HIGH"
                findings.append(CloudFinding(
                    severity=severity,
                    provider="AWS",
                    service="Security Group",
                    rule_id="TF-AWS-001",
                    title=f"Security Group allows 0.0.0.0/0 ingress on port {from_port}-{to_port}",
                    resource=self._line_resource("aws_security_group", resource_line),
                    description="The ingress rule allows traffic from any public IPv4 address.",
                    evidence=f'cidr_blocks = ["0.0.0.0/0"] port {from_port}-{to_port}',
                    remediation="Restrict cidr_blocks to the minimum required administrator, VPN, or trusted CIDR range.",
                    cis_ref="CIS AWS 5.2",
                    file=str(path),
                    line=resource_line,
                ))

    @staticmethod
    def _extract_numeric_value(block: str, key: str, default: str) -> str:
        match = re.search(rf'{re.escape(key)}\s*=\s*(\d+)', block)
        return match.group(1) if match else default

    def _scan_s3(self, path: Path, lines: List[str], findings: List[CloudFinding]) -> None:
        for i, line in enumerate(lines, 1):
            if re.search(r'acl\s*=\s*"public-read"', line, re.IGNORECASE):
                findings.append(CloudFinding(
                    "CRITICAL", "AWS", "S3", "TF-AWS-002",
                    "S3 bucket ACL is set to public-read",
                    self._line_resource("aws_s3_bucket", i),
                    "The bucket ACL exposes objects publicly on the internet.",
                    'acl = "public-read"',
                    'Use private ACLs and explicit, narrowly scoped bucket policies. Do not use public-read in production.',
                    "CIS AWS 2.1.5", str(path), i,
                ))

            if re.search(r'block_public_(acls|policy)\s*=\s*false', line, re.IGNORECASE):
                findings.append(CloudFinding(
                    "HIGH", "AWS", "S3", "TF-AWS-003",
                    "S3 Block Public Access is disabled",
                    self._line_resource("aws_s3_bucket_public_access_block", i),
                    "Block Public Access is disabled, which may allow public ACLs or policies to be applied.",
                    line.strip(),
                    "Set all block_public_* and restrict_public_buckets controls to true unless a documented exception exists.",
                    "CIS AWS 2.1.5", str(path), i,
                ))

    def _scan_iam(self, path: Path, lines: List[str], findings: List[CloudFinding]) -> None:
        content = "\n".join(lines)
        # Terraform heredocs, jsonencode blocks, and inline JSON commonly contain these exact tokens.
        if re.search(r'"Action"\s*:\s*"\*"', content, re.IGNORECASE) or re.search(r'actions\s*=\s*\[\s*"\*"\s*\]', content, re.IGNORECASE):
            line_number = self._first_matching_line(lines, r'"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]')
            findings.append(CloudFinding(
                "CRITICAL", "AWS", "IAM", "TF-AWS-004",
                "IAM policy grants wildcard actions",
                self._line_resource("aws_iam_policy", line_number),
                "The policy grants all actions, which violates the principle of least privilege.",
                'Action = "*"',
                "Replace wildcard actions with the exact API actions required by the workload.",
                "CIS AWS 1.16", str(path), line_number,
            ))

    @staticmethod
    def _first_matching_line(lines: List[str], pattern: str) -> int:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                return i
        return 1

    def _scan_rds(self, path: Path, lines: List[str], findings: List[CloudFinding]) -> None:
        for idx, line in enumerate(lines):
            if not re.search(r'resource\s+"aws_db_instance"', line):
                continue
            block = self._window(lines, idx, 80)
            if not re.search(r'storage_encrypted\s*=\s*true', block, re.IGNORECASE):
                resource_line = idx + 1
                findings.append(CloudFinding(
                    "HIGH", "AWS", "RDS", "TF-AWS-005",
                    "RDS instance storage encryption is not enabled",
                    self._line_resource("aws_db_instance", resource_line),
                    "The RDS instance does not explicitly enable encrypted storage.",
                    "storage_encrypted is missing or false",
                    "Set storage_encrypted = true. For existing databases, plan a snapshot and restore into an encrypted instance.",
                    "CIS AWS 2.3.1", str(path), resource_line,
                ))

    def _scan_ec2(self, path: Path, lines: List[str], findings: List[CloudFinding]) -> None:
        for i, line in enumerate(lines, 1):
            if re.search(r'associate_public_ip_address\s*=\s*true', line, re.IGNORECASE):
                findings.append(CloudFinding(
                    "MEDIUM", "AWS", "EC2", "TF-AWS-006",
                    "EC2 instance is configured with an automatic public IP address",
                    self._line_resource("aws_instance", i),
                    "A public IP address may expose the instance directly to the internet.",
                    "associate_public_ip_address = true",
                    "Use private subnets with NAT Gateway and expose workloads through a load balancer or controlled access path.",
                    "CIS AWS 5.1", str(path), i,
                ))

    def _scan_cloudtrail(self, path: Path, lines: List[str], findings: List[CloudFinding]) -> None:
        for idx, line in enumerate(lines):
            if not re.search(r'resource\s+"aws_cloudtrail"', line):
                continue
            block = self._window(lines, idx, 80)
            if re.search(r'enable_logging\s*=\s*false', block, re.IGNORECASE):
                resource_line = idx + 1
                findings.append(CloudFinding(
                    "HIGH", "AWS", "CloudTrail", "TF-AWS-007",
                    "CloudTrail logging is disabled",
                    self._line_resource("aws_cloudtrail", resource_line),
                    "CloudTrail is not recording events, reducing auditability and incident response visibility.",
                    "enable_logging = false",
                    "Set enable_logging = true and use a multi-region trail with log file validation.",
                    "CIS AWS 3.1", str(path), resource_line,
                ))

    def _scan_azure_storage(self, path: Path, lines: List[str], findings: List[CloudFinding]) -> None:
        for i, line in enumerate(lines, 1):
            if re.search(r'allow_blob_public_access\s*=\s*true', line, re.IGNORECASE):
                findings.append(CloudFinding(
                    "HIGH", "Azure", "Storage Account", "TF-AZ-001",
                    "Azure Storage Account allows public blob access",
                    self._line_resource("azurerm_storage_account", i),
                    "Blobs may be accessible publicly without authentication.",
                    "allow_blob_public_access = true",
                    "Set allow_blob_public_access = false and use least-privilege SAS tokens or managed identities.",
                    "CIS Azure 3.1", str(path), i,
                ))

            if re.search(r'min_tls_version\s*=\s*"TLS1_[01]"', line, re.IGNORECASE):
                findings.append(CloudFinding(
                    "HIGH", "Azure", "Storage Account", "TF-AZ-002",
                    "Azure Storage Account permits TLS 1.0/1.1",
                    self._line_resource("azurerm_storage_account", i),
                    "TLS 1.0 and TLS 1.1 are deprecated and should not be accepted for storage access.",
                    line.strip(),
                    'Set min_tls_version = "TLS1_2" or newer where supported.',
                    "CIS Azure 3.15", str(path), i,
                ))

    def _scan_gcp_storage(self, path: Path, lines: List[str], findings: List[CloudFinding]) -> None:
        for idx, line in enumerate(lines):
            if not re.search(r'resource\s+"google_storage_bucket_iam_(member|binding)"', line):
                continue
            block = self._window(lines, idx, 50)
            if "allUsers" in block or "allAuthenticatedUsers" in block:
                resource_line = idx + 1
                findings.append(CloudFinding(
                    "CRITICAL", "GCP", "Cloud Storage", "TF-GCP-001",
                    "GCP Storage bucket grants public access",
                    self._line_resource("google_storage_bucket_iam_member", resource_line),
                    "The bucket IAM policy grants access to all internet users or all authenticated Google users.",
                    "member = allUsers or allAuthenticatedUsers",
                    "Remove public IAM bindings and grant access only to specific users, groups, or service accounts.",
                    "CIS GCP 5.1", str(path), resource_line,
                ))


class AWSLiveScanner:
    """Runs live AWS checks through the AWS CLI."""

    def _run(self, args: Sequence[str]) -> Optional[Dict[str, object]]:
        try:
            result = subprocess.run(
                list(args),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
        return None

    def check_s3_public_access(self) -> List[CloudFinding]:
        findings: List[CloudFinding] = []
        data = self._run(["aws", "s3api", "list-buckets", "--output", "json"])
        if not data:
            return findings

        for bucket in data.get("Buckets", []):
            name = str(bucket.get("Name", ""))
            if not name:
                continue
            acl = self._run(["aws", "s3api", "get-bucket-acl", "--bucket", name, "--output", "json"])
            if not acl:
                continue
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = str(grantee.get("URI", ""))
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings.append(CloudFinding(
                        "CRITICAL", "AWS", "S3", "AWS-LIVE-001",
                        f"S3 bucket '{name}' is public",
                        f"s3://{name}",
                        "The bucket ACL grants public access.",
                        f"Grantee URI: {uri}",
                        f"Run: aws s3api put-bucket-acl --bucket {name} --acl private",
                        "CIS AWS 2.1.5",
                    ))
        return findings

    def check_security_groups(self) -> List[CloudFinding]:
        findings: List[CloudFinding] = []
        data = self._run(["aws", "ec2", "describe-security-groups", "--output", "json"])
        if not data:
            return findings

        dangerous_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 2375: "Docker API"}
        for sg in data.get("SecurityGroups", []):
            sg_id = str(sg.get("GroupId", ""))
            sg_name = str(sg.get("GroupName", sg_id))
            for permission in sg.get("IpPermissions", []):
                from_port = int(permission.get("FromPort", 0) or 0)
                to_port = int(permission.get("ToPort", 65535) or 65535)
                for cidr in permission.get("IpRanges", []):
                    if cidr.get("CidrIp") != "0.0.0.0/0":
                        continue
                    if from_port == 0 and to_port == 65535:
                        severity = "CRITICAL"
                        title = f"Security Group {sg_name} allows all traffic from 0.0.0.0/0"
                    elif from_port in dangerous_ports:
                        severity = "CRITICAL" if from_port in {22, 3389} else "HIGH"
                        title = f"Security Group {sg_name}: {dangerous_ports[from_port]} ({from_port}) is exposed to the internet"
                    else:
                        severity = "MEDIUM"
                        title = f"Security Group {sg_name}: port {from_port}-{to_port} is internet-exposed"

                    findings.append(CloudFinding(
                        severity, "AWS", "Security Group", "AWS-LIVE-002",
                        title,
                        sg_id,
                        "The ingress rule allows traffic from any public IPv4 address.",
                        f"Port {from_port}-{to_port} -> 0.0.0.0/0",
                        "Restrict the source CIDR to the minimum required range.",
                        "CIS AWS 5.2",
                    ))
        return findings

    def check_iam_root_usage(self) -> List[CloudFinding]:
        findings: List[CloudFinding] = []
        data = self._run(["aws", "iam", "get-account-summary", "--output", "json"])
        if not data:
            return findings

        summary = data.get("SummaryMap", {})
        if int(summary.get("AccountAccessKeysPresent", 0) or 0) > 0:
            findings.append(CloudFinding(
                "CRITICAL", "AWS", "IAM", "AWS-LIVE-003",
                "Root account has active access keys",
                "AWS Root Account",
                "Active root access keys create a high-impact account takeover risk.",
                "AccountAccessKeysPresent > 0",
                "Delete root access keys and use IAM identities with MFA and least privilege.",
                "CIS AWS 1.4",
            ))

        if int(summary.get("AccountMFAEnabled", 0) or 0) == 0:
            findings.append(CloudFinding(
                "CRITICAL", "AWS", "IAM", "AWS-LIVE-004",
                "MFA is not enabled on the root account",
                "AWS Root Account",
                "The root account can be accessed without a second factor.",
                "AccountMFAEnabled = 0",
                "Enable virtual or hardware MFA on the root account immediately.",
                "CIS AWS 1.5",
            ))
        return findings

    def check_cloudtrail(self) -> List[CloudFinding]:
        findings: List[CloudFinding] = []
        data = self._run(["aws", "cloudtrail", "describe-trails", "--output", "json"])
        if not data:
            return findings

        trails = data.get("trailList", [])
        if not trails:
            findings.append(CloudFinding(
                "CRITICAL", "AWS", "CloudTrail", "AWS-LIVE-005",
                "CloudTrail is not configured",
                "AWS Account",
                "No CloudTrail trail was found, reducing API audit coverage.",
                "No trails found",
                "Create a multi-region trail with S3 encryption and log file validation enabled.",
                "CIS AWS 3.1",
            ))
            return findings

        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                findings.append(CloudFinding(
                    "MEDIUM", "AWS", "CloudTrail", "AWS-LIVE-006",
                    f"CloudTrail '{trail.get('Name', '')}' is not multi-region",
                    str(trail.get("TrailARN", "")),
                    "A single-region trail does not capture events from all AWS regions.",
                    "IsMultiRegionTrail: False",
                    "Update the trail to be multi-region.",
                    "CIS AWS 3.1",
                ))
        return findings

    def scan_all(self) -> Tuple[List[CloudFinding], int]:
        checks = [
            self.check_s3_public_access,
            self.check_security_groups,
            self.check_iam_root_usage,
            self.check_cloudtrail,
        ]
        findings: List[CloudFinding] = []
        for check in checks:
            findings.extend(check())
        return findings, len(checks)


def generate_demo_findings() -> List[CloudFinding]:
    return [
        CloudFinding("CRITICAL", "AWS", "S3", "DEMO-001", "S3 bucket 'prod-backups-2024' is public", "s3://prod-backups-2024", "The bucket ACL exposes backup data publicly.", 'acl = "public-read"', "Make the bucket private and enforce S3 Block Public Access.", "CIS AWS 2.1.5", "main.tf", 12),
        CloudFinding("CRITICAL", "AWS", "Security Group", "DEMO-002", "Security Group 'sg-prod-web' allows SSH from 0.0.0.0/0", "sg-0abc123def456", "Port 22 is accessible from any internet address.", "from_port=22 cidr=0.0.0.0/0", "Restrict SSH to an administrator IP, VPN, or AWS Systems Manager Session Manager.", "CIS AWS 5.2", "security_groups.tf", 45),
        CloudFinding("CRITICAL", "AWS", "IAM", "DEMO-003", "IAM policy 'dev-access' grants Action: *", "arn:aws:iam::123456789:policy/dev-access", "The policy grants full permissions across AWS services.", '"Action": "*", "Resource": "*"', "Apply least privilege and list only the required API actions.", "CIS AWS 1.16", "iam.tf", 78),
        CloudFinding("HIGH", "AWS", "RDS", "DEMO-004", "RDS instance 'prod-mysql' is not encrypted", "prod-mysql.rds.amazonaws.com", "The production database does not have encrypted storage enabled.", "storage_encrypted is missing", "Enable encryption by restoring from a snapshot into an encrypted instance.", "CIS AWS 2.3.1", "database.tf", 23),
        CloudFinding("HIGH", "Azure", "Storage Account", "DEMO-005", "Azure Storage Account 'prodstorageacct' allows public blob access", "/subscriptions/.../prodstorageacct", "Blobs may be accessible publicly without authentication.", "allow_blob_public_access = true", "Set allow_blob_public_access = false.", "CIS Azure 3.1", "azure_storage.tf", 15),
        CloudFinding("CRITICAL", "GCP", "Cloud Storage", "DEMO-006", "GCP bucket 'company-data-lake' grants allUsers access", "gs://company-data-lake", "Anyone on the internet can access the bucket.", "member = allUsers", "Remove public IAM bindings and use specific service accounts.", "CIS GCP 5.1", "gcp_storage.tf", 34),
        CloudFinding("HIGH", "AWS", "CloudTrail", "DEMO-007", "CloudTrail is not multi-region", "arn:aws:cloudtrail:eu-west-1:...:trail/prod-trail", "Events from other regions are not audited.", "IsMultiRegionTrail: False", "Update the trail to be multi-region.", "CIS AWS 3.1", "cloudtrail.tf", 8),
        CloudFinding("MEDIUM", "AWS", "EC2", "DEMO-008", "EC2 instance has associate_public_ip_address = true", "aws_instance.web_server", "The instance receives a direct public IP address.", "associate_public_ip_address = true", "Use private subnets with NAT Gateway and an Application Load Balancer.", "CIS AWS 5.1", "ec2.tf", 67),
    ]


def compute_score(findings: List[CloudFinding], *_args: object, **_kwargs: object) -> float:
    if not findings:
        return 100.0
    weights = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}
    deductions = sum(weights.get(f.severity, 0) for f in findings)
    return max(0.0, round(100.0 - deductions, 1))


def exit_code_for_findings(findings: List[CloudFinding]) -> int:
    if any(f.severity == "CRITICAL" for f in findings):
        return 2
    if any(f.severity in {"HIGH", "MEDIUM"} for f in findings):
        return 1
    return 0


def print_findings(findings: List[CloudFinding]) -> None:
    for finding in sorted(findings, key=lambda item: SEVERITY_ORDER.index(item.severity) if item.severity in SEVERITY_ORDER else 99):
        col = SEV_COL.get(finding.severity, "")
        print(f"\n{SEP}")
        print(f"  {col}{C.BOLD}[{finding.severity}]{C.RESET}  [{finding.provider}/{finding.service}]  {finding.title}")
        print(f"  {C.DIM}Rule        :{C.RESET} {finding.rule_id}")
        print(f"  {C.DIM}Resource    :{C.RESET} {finding.resource}")
        if finding.file:
            suffix = f":{finding.line}" if finding.line else ""
            print(f"  {C.DIM}File        :{C.RESET} {finding.file}{suffix}")
        print(f"  {C.DIM}Evidence    :{C.RESET} {C.YELLOW}{finding.evidence[:120]}{C.RESET}")
        print(f"  {C.DIM}Description :{C.RESET} {finding.description}")
        print(f"  {C.DIM}Fix         :{C.RESET} {finding.remediation[:160]}")
        if finding.cis_ref:
            print(f"  {C.DIM}CIS Ref     :{C.RESET} {finding.cis_ref}")


def print_summary(report: CloudReport) -> None:
    by_sev: Dict[str, int] = {}
    by_provider: Dict[str, int] = {}
    by_service: Dict[str, int] = {}
    for finding in report.findings:
        by_sev[finding.severity] = by_sev.get(finding.severity, 0) + 1
        by_provider[finding.provider] = by_provider.get(finding.provider, 0) + 1
        by_service[finding.service] = by_service.get(finding.service, 0) + 1

    score_col = C.GREEN if report.score >= 80 else C.YELLOW if report.score >= 60 else C.RED
    bar_len = int(report.score / 100 * 40)
    bar = "█" * bar_len + "░" * (40 - bar_len)

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}CLOUD SECURITY SCAN SUMMARY{C.RESET}")
    print(f"  Target    : {report.target}")
    print(f"  Type      : {report.scan_type}")
    print(f"  Resources : {report.resources_checked}")
    print(f"  Findings  : {len(report.findings)}")
    print(SEP)
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = by_sev.get(severity, 0)
        if count:
            col = SEV_COL.get(severity, "")
            print(f"  {col}{severity:<10}{C.RESET} {'█' * min(count, 20)} {count}")
    print(SEP)
    print(f"  {score_col}{C.BOLD}Cloud Security Score: {report.score}/100{C.RESET}  [{bar}]")
    print(SEP)

    if by_provider:
        print(f"\n  {C.BOLD}By Provider:{C.RESET}")
        for provider, count in sorted(by_provider.items(), key=lambda x: -x[1]):
            print(f"  {C.CYAN}{provider:<12}{C.RESET} {count}")

    if by_service:
        print(f"\n  {C.BOLD}By Service:{C.RESET}")
        for service, count in sorted(by_service.items(), key=lambda x: -x[1])[:8]:
            print(f"  {C.DIM}{service:<25}{C.RESET} {count}")
    print(SEP2)


def generate_markdown(report: CloudReport) -> str:
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
    lines = [
        "# ☁️ Cloud Security Scan Report",
        f"**Target:** `{report.target}`  ",
        f"**Scan type:** `{report.scan_type}`  ",
        f"**Provider filter:** `{report.provider}`  ",
        f"**Score:** `{report.score}/100`  ",
        f"**Generated:** `{report.timestamp}`",
        "",
        f"## Findings ({len(report.findings)})",
        "",
        "| Severity | Provider | Service | Rule | Title | CIS |",
        "|:---:|---|---|---|---|---|",
    ]
    for finding in report.findings:
        title = finding.title.replace("|", "\\|")
        lines.append(f"| {icon.get(finding.severity, '')} {finding.severity} | {finding.provider} | {finding.service} | {finding.rule_id} | {title} | {finding.cis_ref} |")

    criticals = [f for f in report.findings if f.severity == "CRITICAL"]
    highs = [f for f in report.findings if f.severity == "HIGH"]
    prioritized = (criticals + highs)[:10]
    if prioritized:
        lines.extend(["", "## Priority Remediation", ""])
        for i, finding in enumerate(prioritized, 1):
            lines.append(f"{i}. **{finding.title}** — {finding.remediation}")

    lines.extend(["", f"*Generated by cloud-scanner v{__version__}.*"])
    return "\n".join(lines) + "\n"


def run_scan(args: argparse.Namespace) -> CloudReport:
    findings: List[CloudFinding] = []
    resources = 0
    scan_type = args.mode
    provider_str = args.provider.upper()

    if args.mode == "demo":
        print(f"  {C.YELLOW}Demo mode — using synthetic cloud misconfiguration findings.{C.RESET}", file=sys.stderr)
        findings = generate_demo_findings()
        resources = 8
    elif args.mode == "terraform":
        print(f"  {C.DIM}Scanning Terraform files in: {args.target}{C.RESET}", file=sys.stderr)
        findings, resources = TerraformScanner().scan_directory(args.target)
        if not findings and resources == 0:
            print(f"  {C.YELLOW}No .tf files found. Use --mode demo to see sample findings.{C.RESET}", file=sys.stderr)
    elif args.mode == "aws-live":
        print(f"  {C.DIM}Running live AWS checks through the AWS CLI...{C.RESET}", file=sys.stderr)
        findings, resources = AWSLiveScanner().scan_all()
        if not findings:
            print(f"  {C.YELLOW}AWS CLI is unavailable, unconfigured, or returned no findings.{C.RESET}", file=sys.stderr)

    if args.provider != "all":
        findings = [f for f in findings if f.provider.lower() == args.provider.lower()]

    score = compute_score(findings)
    return CloudReport(
        scan_type=scan_type,
        target=args.target,
        timestamp=datetime.now().isoformat(timespec="seconds"),
        provider=provider_str,
        findings=findings,
        score=score,
        resources_checked=resources,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-scanner",
        description="Cloud Misconfiguration Scanner — Terraform static checks and AWS live checks",
    )
    parser.add_argument("target", nargs="?", default=".", help="Directory or .tf file to scan")
    parser.add_argument("--mode", choices=["terraform", "aws-live", "demo"], default="terraform", help="Scan mode")
    parser.add_argument("--provider", choices=["aws", "azure", "gcp", "all"], default="all", help="Filter findings by cloud provider")
    parser.add_argument("-o", "--output", help="Save the report to a file. JSON is written when --json is used; otherwise Markdown is written.")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Print report as JSON")
    parser.add_argument("--no-banner", action="store_true", help="Do not print the ASCII banner")
    parser.add_argument("--version", action="version", version=f"cloud-scanner {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.no_banner:
        print(BANNER)

    report = run_scan(args)

    if args.json_out:
        json_text = json.dumps(report.to_dict(), indent=2)
        print(json_text)
        if args.output:
            Path(args.output).write_text(json_text + "\n", encoding="utf-8")
            print(f"\n  {C.GREEN}[✓] JSON report: {args.output}{C.RESET}", file=sys.stderr)
    else:
        print_findings(report.findings)
        print_summary(report)
        if args.output:
            Path(args.output).write_text(generate_markdown(report), encoding="utf-8")
            print(f"\n  {C.GREEN}[✓] Markdown report: {args.output}{C.RESET}")

    return exit_code_for_findings(report.findings)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
docker_audit.py — Docker Security Auditor v1.0.0
=================================================

Audits Dockerfiles and running container configurations against practical
container security checks inspired by the CIS Docker Benchmark.

Features:
- Dockerfile static analysis
- Running container inspection through the Docker CLI
- JSON and Markdown reports
- Zero external Python dependencies

Author      : Marcio Coutinho — Cybersecurity Specialist
Date        : 21/09/2024
Requirements: Python 3.8+
              Docker CLI is optional and only required for runtime audits.
"""
import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
 ██████╗  ██████╗  ██████╗██╗  ██╗███████╗██████╗
 ██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
 ██║  ██║██║   ██║██║     █████╔╝ █████╗  ██████╔╝
 ██║  ██║██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ██████╔╝╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║
 ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{C.RESET}
{C.DIM} v{__version__} — Docker Security Auditor | Dockerfile · Runtime · CIS-inspired checks{C.RESET}
"""

SEP = "━" * 72
SEP2 = "═" * 72

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COL = {
    "CRITICAL": C.RED,
    "HIGH": C.YELLOW,
    "MEDIUM": C.CYAN,
    "LOW": C.GREEN,
    "INFO": C.DIM,
}
SEV_PENALTY = {
    "CRITICAL": 18.0,
    "HIGH": 10.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFO": 0.5,
}


@dataclass(frozen=True)
class CheckDefinition:
    check_id: str
    severity: str
    title: str
    cis_ref: str = ""


@dataclass
class AuditFinding:
    check_id: str
    severity: str
    title: str
    description: str
    evidence: str
    remediation: str
    cis_ref: str = ""
    line: int = 0
    file: str = ""


@dataclass
class AuditReport:
    target: str
    audit_type: str
    timestamp: str
    findings: List[AuditFinding]
    score: float
    total_checks: int
    passed: int
    failed: int
    warnings: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "audit_type": self.audit_type,
            "timestamp": self.timestamp,
            "score": self.score,
            "total_checks": self.total_checks,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "findings": [finding.__dict__ for finding in self.findings],
        }


@dataclass
class DockerInstruction:
    command: str
    args: str
    line_no: int
    raw: str


DOCKERFILE_CHECKS: List[CheckDefinition] = [
    CheckDefinition("DI-001", "HIGH", "Base image tag must be pinned", "CIS DI 4.1"),
    CheckDefinition("DI-002", "HIGH", "Container should not run as root", "CIS DI 4.1"),
    CheckDefinition("DI-003", "LOW", "Use COPY instead of ADD when possible", "CIS DI 4.9"),
    CheckDefinition("DI-004", "LOW", "COPY should set explicit ownership"),
    CheckDefinition("DI-005", "CRITICAL", "Do not store secrets in ENV or ARG", "CIS DI 4.10"),
    CheckDefinition("DI-006", "LOW", "Pin package versions and clean package caches", "CIS DI 4.7"),
    CheckDefinition("DI-007", "HIGH", "Avoid downloading scripts directly into shells", "CIS DI 4.3"),
    CheckDefinition("DI-008", "MEDIUM", "Avoid world-writable permissions"),
    CheckDefinition("DI-009", "LOW", "Define a HEALTHCHECK"),
    CheckDefinition("DI-010", "LOW", "Avoid process managers as PID 1", "CIS DI 4.9"),
    CheckDefinition("DI-011", "MEDIUM", "Avoid privileged exposed ports"),
    CheckDefinition("DI-012", "LOW", "Use absolute WORKDIR paths"),
    CheckDefinition("DI-013", "CRITICAL", "Do not embed credentials in RUN instructions", "CIS DI 4.10"),
    CheckDefinition("DI-014", "MEDIUM", "Use multi-stage builds when build tools are installed", "CIS DI 4.3"),
    CheckDefinition("DI-015", "LOW", "Use a .dockerignore file"),
]

RUNTIME_CHECKS: List[CheckDefinition] = [
    CheckDefinition("RT-001", "CRITICAL", "Do not run containers in privileged mode", "CIS DT 5.4"),
    CheckDefinition("RT-002", "HIGH", "Avoid dangerous Linux capabilities", "CIS DT 5.3"),
    CheckDefinition("RT-003", "MEDIUM", "Use a read-only root filesystem", "CIS DT 5.12"),
    CheckDefinition("RT-004", "HIGH", "Avoid host network mode", "CIS DT 5.14"),
    CheckDefinition("RT-005", "HIGH", "Avoid host PID namespace", "CIS DT 5.15"),
    CheckDefinition("RT-006", "MEDIUM", "Set a memory limit", "CIS DT 5.10"),
    CheckDefinition("RT-007", "LOW", "Set a CPU limit", "CIS DT 5.11"),
    CheckDefinition("RT-008", "CRITICAL", "Avoid sensitive host bind mounts", "CIS DT 5.5"),
    CheckDefinition("RT-009", "CRITICAL", "Do not mount the Docker socket", "CIS DT 5.5"),
    CheckDefinition("RT-010", "HIGH", "Do not expose secrets through environment variables", "CIS DT 4.10"),
    CheckDefinition("RT-011", "MEDIUM", "Enable no-new-privileges", "CIS DT 5.25"),
]


def log(message: str, *, quiet: bool = False) -> None:
    if not quiet:
        print(message, file=sys.stderr)


def parse_dockerfile(content: str) -> List[DockerInstruction]:
    """Parse Dockerfile instructions, including simple backslash continuations."""
    instructions: List[DockerInstruction] = []
    lines = content.splitlines()
    index = 0

    while index < len(lines):
        raw_line = lines[index]
        stripped = raw_line.strip()

        if not stripped or stripped.startswith("#"):
            index += 1
            continue

        start_line = index + 1
        full_line = stripped

        while full_line.endswith("\\") and index + 1 < len(lines):
            index += 1
            continuation = lines[index].strip()
            full_line = full_line[:-1].rstrip() + " " + continuation

        parts = full_line.split(None, 1)
        if parts:
            command = parts[0].upper()
            args = parts[1] if len(parts) > 1 else ""
            instructions.append(DockerInstruction(command, args, start_line, full_line))

        index += 1

    return instructions


def _find_all(instructions: Iterable[DockerInstruction], command: str) -> List[DockerInstruction]:
    return [instruction for instruction in instructions if instruction.command == command.upper()]


def audit_dockerfile(content: str, filepath: str = "Dockerfile") -> Tuple[List[AuditFinding], int]:
    """Audit a Dockerfile string and return findings plus the number of checks run."""
    findings: List[AuditFinding] = []
    instructions = parse_dockerfile(content)
    checks_run = len(DOCKERFILE_CHECKS)
    dockerfile_path = Path(filepath)

    def add(
        check_id: str,
        severity: str,
        title: str,
        description: str,
        evidence: str,
        remediation: str,
        cis_ref: str = "",
        line: int = 0,
    ) -> None:
        findings.append(
            AuditFinding(
                check_id=check_id,
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                remediation=remediation,
                cis_ref=cis_ref,
                line=line,
                file=str(filepath),
            )
        )

    from_instructions = _find_all(instructions, "FROM")
    for instruction in from_instructions:
        image = instruction.args.split()[0] if instruction.args else ""
        if image and ":" not in image and "@" not in image:
            add(
                "DI-001",
                "HIGH",
                "Base image has no explicit tag",
                "The image implicitly uses ':latest', which makes builds non-reproducible and may pull unreviewed changes.",
                f"FROM {image}",
                "Pin a specific image tag or digest, for example: FROM python:3.12.3-slim.",
                "CIS DI 4.1",
                instruction.line_no,
            )
        elif ":latest" in image:
            add(
                "DI-001",
                "MEDIUM",
                "Base image uses the ':latest' tag",
                "The ':latest' tag is mutable and can break reproducibility or introduce unreviewed vulnerabilities.",
                f"FROM {image}",
                "Use a versioned tag or immutable digest.",
                "CIS DI 4.1",
                instruction.line_no,
            )

    user_instructions = _find_all(instructions, "USER")
    if not user_instructions:
        add(
            "DI-002",
            "HIGH",
            "Container runs as root by default",
            "No USER instruction is present, so the container will run as root unless overridden at runtime.",
            "USER instruction is missing",
            "Create and switch to a dedicated non-root user before CMD/ENTRYPOINT.",
            "CIS DI 4.1",
        )
    else:
        for instruction in user_instructions:
            user_value = instruction.args.strip().lower()
            if user_value in {"root", "0", "root:root", "0:0"}:
                add(
                    "DI-002",
                    "CRITICAL",
                    "Container explicitly runs as root",
                    "The Dockerfile explicitly configures the container to run as root.",
                    f"USER {instruction.args}",
                    "Use a non-privileged user such as 'USER appuser'.",
                    "CIS DI 4.1",
                    instruction.line_no,
                )

    for instruction in _find_all(instructions, "ADD"):
        args_lower = instruction.args.lower()
        if not args_lower.startswith(("http://", "https://")) and not args_lower.endswith((".tar", ".tar.gz", ".tgz")):
            add(
                "DI-003",
                "LOW",
                "ADD is used where COPY is safer",
                "ADD has extra behaviours such as archive extraction and remote URL handling. COPY is clearer for simple file copies.",
                f"ADD {instruction.args[:100]}",
                "Use COPY unless ADD-specific behaviour is required.",
                "CIS DI 4.9",
                instruction.line_no,
            )

    for instruction in _find_all(instructions, "COPY"):
        if "--from=" in instruction.args:
            continue
        if "--chown" not in instruction.args:
            add(
                "DI-004",
                "LOW",
                "COPY does not set explicit ownership",
                "Copied files may be owned by root or inherit unexpected ownership.",
                f"COPY {instruction.args[:100]}",
                "Use COPY --chown=appuser:appuser where appropriate.",
                "",
                instruction.line_no,
            )

    secret_pattern = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|auth|credential|private[_-]?key)")
    for instruction in _find_all(instructions, "ENV") + _find_all(instructions, "ARG"):
        if secret_pattern.search(instruction.args):
            add(
                "DI-005",
                "CRITICAL",
                "Possible secret in ENV or ARG",
                "ENV values are visible through image metadata and docker inspect. ARG values can leak through build logs and image history.",
                f"{instruction.command} {instruction.args[:100]}",
                "Use BuildKit secrets, Docker secrets, or runtime secret injection through an orchestrator.",
                "CIS DI 4.10",
                instruction.line_no,
            )

    package_install_re = re.compile(r"\b(apt-get\s+install|apt\s+install|apk\s+add|yum\s+install|dnf\s+install)\b", re.I)
    for instruction in _find_all(instructions, "RUN"):
        args = instruction.args
        if package_install_re.search(args):
            if not re.search(r"=[A-Za-z0-9_.:+~\-]+", args):
                add(
                    "DI-006",
                    "LOW",
                    "Packages are installed without version pinning",
                    "Unpinned packages reduce build reproducibility and can unexpectedly introduce vulnerable versions.",
                    args[:120],
                    "Pin package versions where practical and rebuild regularly through a controlled pipeline.",
                    "CIS DI 4.7",
                    instruction.line_no,
                )
            if "apt-get install" in args and "rm -rf /var/lib/apt/lists" not in args:
                add(
                    "DI-006b",
                    "LOW",
                    "APT cache is not cleaned",
                    "Leaving APT package lists in the image increases image size and keeps unnecessary metadata.",
                    "apt-get install without /var/lib/apt/lists cleanup",
                    "Add 'rm -rf /var/lib/apt/lists/*' in the same RUN instruction.",
                    "",
                    instruction.line_no,
                )

    for instruction in _find_all(instructions, "RUN"):
        if re.search(r"\b(curl|wget)\b.+\|\s*(bash|sh|python|perl)\b", instruction.args, re.I):
            add(
                "DI-007",
                "HIGH",
                "Downloaded script is piped directly into a shell",
                "Downloading and executing remote scripts in a single pipeline prevents integrity verification.",
                instruction.args[:120],
                "Download the script, verify its checksum or signature, then execute it explicitly.",
                "CIS DI 4.3",
                instruction.line_no,
            )

    for instruction in _find_all(instructions, "RUN"):
        if re.search(r"\bchmod\s+(-R\s+)?(777|a\+rwx|ugo\+rwx)\b", instruction.args):
            add(
                "DI-008",
                "MEDIUM",
                "World-writable permissions are used",
                "chmod 777 grants write access to every user and increases the impact of application compromise.",
                instruction.args[:120],
                "Use the minimum required permissions, such as 755 for executables and 644 for files.",
                "",
                instruction.line_no,
            )

    if not _find_all(instructions, "HEALTHCHECK"):
        add(
            "DI-009",
            "LOW",
            "HEALTHCHECK is not defined",
            "Without HEALTHCHECK, container platforms have less visibility into application health.",
            "No HEALTHCHECK instruction found",
            "Add a HEALTHCHECK that validates the application is responding correctly.",
        )

    for instruction in _find_all(instructions, "CMD") + _find_all(instructions, "ENTRYPOINT"):
        if any(process_manager in instruction.args.lower() for process_manager in ["supervisord", "s6", "runit", "pm2"]):
            add(
                "DI-010",
                "LOW",
                "Process manager is used as PID 1",
                "Running multiple long-lived services in one container can complicate isolation and lifecycle management.",
                instruction.args[:120],
                "Prefer one service per container. Use a minimal init such as tini only when required.",
                "CIS DI 4.9",
                instruction.line_no,
            )

    for instruction in _find_all(instructions, "EXPOSE"):
        for port in re.findall(r"\d+", instruction.args):
            if int(port) < 1024:
                add(
                    "DI-011",
                    "MEDIUM",
                    f"Privileged port exposed: {port}",
                    "Ports below 1024 typically require elevated privileges inside the container.",
                    f"EXPOSE {port}",
                    "Use an unprivileged internal port and place a reverse proxy or load balancer in front.",
                    "",
                    instruction.line_no,
                )

    workdir_instructions = _find_all(instructions, "WORKDIR")
    if not workdir_instructions:
        add(
            "DI-012",
            "LOW",
            "WORKDIR is not defined",
            "Without WORKDIR, later commands may run from the filesystem root or from an unexpected directory.",
            "No WORKDIR instruction found",
            "Set an absolute work directory, for example: WORKDIR /app.",
        )
    else:
        for instruction in workdir_instructions:
            workdir = instruction.args.strip()
            if workdir and not workdir.startswith("/") and not workdir.startswith("$"):
                add(
                    "DI-012",
                    "LOW",
                    "WORKDIR uses a relative path",
                    "Relative WORKDIR values can produce unexpected paths across multiple Dockerfile instructions.",
                    f"WORKDIR {instruction.args}",
                    "Use an absolute path, for example: WORKDIR /app.",
                    "",
                    instruction.line_no,
                )

    credential_assignment_re = re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*['\"]?[^'\"\s]+")
    for instruction in _find_all(instructions, "RUN"):
        if credential_assignment_re.search(instruction.args):
            add(
                "DI-013",
                "CRITICAL",
                "Possible credential in RUN instruction",
                "Credentials in RUN instructions can remain visible in image history and build logs.",
                instruction.args[:120],
                "Use BuildKit --secret or runtime secret management instead of embedding credentials in image layers.",
                "CIS DI 4.10",
                instruction.line_no,
            )

    if len(from_instructions) == 1:
        build_tools = ["gcc", "g++", "make", "cmake", "cargo", "mvn", "gradle", "build-essential", "apk add build-base"]
        for instruction in _find_all(instructions, "RUN"):
            lower_args = instruction.args.lower()
            if any(tool in lower_args for tool in build_tools):
                add(
                    "DI-014",
                    "MEDIUM",
                    "Build tools appear to be installed in the final image",
                    "Build tools increase image size and attack surface when they remain in the runtime image.",
                    instruction.args[:120],
                    "Use multi-stage builds and copy only runtime artifacts into the final image.",
                    "CIS DI 4.3",
                    instruction.line_no,
                )
                break

    if dockerfile_path.name and dockerfile_path.parent.exists():
        dockerignore = dockerfile_path.parent / ".dockerignore"
        if not dockerignore.exists():
            add(
                "DI-015",
                "LOW",
                ".dockerignore file is missing",
                "Without .dockerignore, sensitive or unnecessary files may be sent to the Docker build context.",
                f"No .dockerignore found next to {dockerfile_path.name}",
                "Add a .dockerignore file excluding secrets, VCS metadata, caches, and local environment files.",
            )

    return findings, checks_run


def run_cmd(command: List[str]) -> Optional[str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    except Exception:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def audit_running_container(container_id: str, *, quiet: bool = False) -> Tuple[List[AuditFinding], int]:
    """Audit a running or existing container through docker inspect."""
    findings: List[AuditFinding] = []
    checks_run = len(RUNTIME_CHECKS)

    inspect_raw = run_cmd(["docker", "inspect", container_id])
    if not inspect_raw:
        log(f"  {C.RED}[ERROR] Could not inspect container '{container_id}'.{C.RESET}", quiet=quiet)
        log(f"  {C.DIM}Check that Docker is running and the container exists.{C.RESET}", quiet=quiet)
        return [], 0

    try:
        inspected = json.loads(inspect_raw)
        data = inspected[0]
    except (json.JSONDecodeError, IndexError, TypeError):
        return [], 0

    config = data.get("Config", {}) or {}
    host_config = data.get("HostConfig", {}) or {}
    mounts = data.get("Mounts", []) or []

    def add(
        check_id: str,
        severity: str,
        title: str,
        description: str,
        evidence: str,
        remediation: str,
        cis_ref: str = "",
    ) -> None:
        findings.append(AuditFinding(check_id, severity, title, description, evidence, remediation, cis_ref))

    if host_config.get("Privileged"):
        add(
            "RT-001",
            "CRITICAL",
            "Container runs in privileged mode",
            "--privileged disables important container isolation boundaries and can provide host-level access.",
            "Privileged: true",
            "Remove --privileged. Add only the specific capabilities and devices that are required.",
            "CIS DT 5.4",
        )

    dangerous_capabilities = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}
    for capability in host_config.get("CapAdd") or []:
        if str(capability).upper() in dangerous_capabilities:
            add(
                "RT-002",
                "HIGH",
                f"Dangerous Linux capability added: {capability}",
                "The container has an elevated Linux capability that may weaken isolation.",
                f"CapAdd: {capability}",
                "Start from --cap-drop ALL and add only capabilities that are strictly required.",
                "CIS DT 5.3",
            )

    if not host_config.get("ReadonlyRootfs"):
        add(
            "RT-003",
            "MEDIUM",
            "Root filesystem is writable",
            "A writable root filesystem can support persistence or in-container tampering after compromise.",
            "ReadonlyRootfs: false",
            "Run with --read-only and mount explicit writable volumes for required data paths.",
            "CIS DT 5.12",
        )

    if host_config.get("NetworkMode") == "host":
        add(
            "RT-004",
            "HIGH",
            "Host network mode is enabled",
            "--network host shares the host network namespace with the container.",
            "NetworkMode: host",
            "Use bridge networking or a dedicated Docker network unless host networking is strictly required.",
            "CIS DT 5.14",
        )

    if host_config.get("PidMode") == "host":
        add(
            "RT-005",
            "HIGH",
            "Host PID namespace is enabled",
            "--pid host allows the container to observe host processes.",
            "PidMode: host",
            "Use the default isolated PID namespace.",
            "CIS DT 5.15",
        )

    if not host_config.get("Memory"):
        add(
            "RT-006",
            "MEDIUM",
            "No memory limit is configured",
            "A container without a memory limit can consume host memory and cause denial of service.",
            "Memory: 0",
            "Set an appropriate memory limit, for example --memory 512m.",
            "CIS DT 5.10",
        )

    if not host_config.get("CpuQuota") and not host_config.get("CpuShares"):
        add(
            "RT-007",
            "LOW",
            "No CPU limit is configured",
            "A container without CPU controls can compete aggressively with other workloads.",
            "CpuQuota: 0, CpuShares: 0",
            "Set a CPU quota or CPU share value appropriate for the workload.",
            "CIS DT 5.11",
        )

    sensitive_paths = {"/", "/etc", "/proc", "/sys", "/var/run/docker.sock"}
    for mount in mounts:
        source = mount.get("Source", "")
        destination = mount.get("Destination", "")
        if any(source == path or source.startswith(path + "/") for path in sensitive_paths if path != "/"):
            add(
                "RT-008",
                "CRITICAL" if source == "/var/run/docker.sock" else "HIGH",
                f"Sensitive host path is mounted: {source}",
                "Mounting sensitive host paths can expose host configuration, processes, devices, or control sockets.",
                f"{source} -> {destination}",
                "Remove the bind mount or replace it with a narrow, read-only mount where appropriate.",
                "CIS DT 5.5",
            )
        elif source == "/":
            add(
                "RT-008",
                "CRITICAL",
                "Host root filesystem is mounted",
                "Mounting '/' gives the container broad access to host files.",
                f"{source} -> {destination}",
                "Do not mount the host root filesystem into containers.",
                "CIS DT 5.5",
            )

    for mount in mounts:
        if mount.get("Source") == "/var/run/docker.sock":
            add(
                "RT-009",
                "CRITICAL",
                "Docker socket is mounted inside the container",
                "Access to docker.sock usually allows full control of the Docker host.",
                "Mount: /var/run/docker.sock",
                "Remove the Docker socket mount. Use a restricted API proxy or orchestrator-native integration if needed.",
                "CIS DT 5.5",
            )

    secret_re = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|auth|credential)=")
    for env_value in config.get("Env") or []:
        if secret_re.search(env_value):
            variable_name = env_value.split("=", 1)[0]
            add(
                "RT-010",
                "HIGH",
                f"Secret-like environment variable exposed: {variable_name}",
                "Secrets in environment variables are visible through docker inspect and may leak into logs.",
                f"{variable_name}=***",
                "Use Docker secrets, Kubernetes Secrets, or a dedicated secret manager.",
                "CIS DT 4.10",
            )

    security_opts = host_config.get("SecurityOpt") or []
    if not any("no-new-privileges" in str(option) for option in security_opts):
        add(
            "RT-011",
            "MEDIUM",
            "no-new-privileges is not enabled",
            "Without no-new-privileges, setuid/setgid binaries may allow processes to gain additional privileges.",
            "SecurityOpt does not include no-new-privileges",
            "Run with --security-opt no-new-privileges:true.",
            "CIS DT 5.25",
        )

    return findings, checks_run


def build_report(target: str, audit_type: str, findings: List[AuditFinding], total_checks: int) -> AuditReport:
    by_severity: Dict[str, int] = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    failed = by_severity.get("CRITICAL", 0) + by_severity.get("HIGH", 0)
    warnings = by_severity.get("MEDIUM", 0) + by_severity.get("LOW", 0)
    passed = max(total_checks - len(findings), 0)

    if total_checks <= 0:
        score = 100.0
    else:
        penalty = sum(SEV_PENALTY.get(finding.severity, 0.0) for finding in findings)
        score = round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    return AuditReport(
        target=target,
        audit_type=audit_type,
        timestamp=datetime.now().isoformat(),
        findings=findings,
        score=score,
        total_checks=total_checks,
        passed=passed,
        failed=failed,
        warnings=warnings,
    )


def merge_reports(target: str, audit_type: str, reports: List[AuditReport]) -> AuditReport:
    findings: List[AuditFinding] = []
    total_checks = 0
    for report in reports:
        findings.extend(report.findings)
        total_checks += report.total_checks
    return build_report(target, audit_type, findings, total_checks)


def print_finding(finding: AuditFinding) -> None:
    color = SEV_COL.get(finding.severity, "")
    print(f"\n{SEP}")
    print(f"  {color}[{finding.severity}]{C.RESET} {C.BOLD}{finding.title}{C.RESET}  {C.DIM}({finding.check_id}){C.RESET}")
    if finding.cis_ref:
        print(f"  {C.DIM}CIS Ref    :{C.RESET} {finding.cis_ref}")
    if finding.file:
        location = finding.file + (f":{finding.line}" if finding.line else "")
        print(f"  {C.DIM}Location   :{C.RESET} {location}")
    elif finding.line:
        print(f"  {C.DIM}Line       :{C.RESET} {finding.line}")
    print(f"  {C.DIM}Evidence   :{C.RESET} {C.YELLOW}{finding.evidence[:140]}{C.RESET}")
    print(f"  {C.DIM}Description:{C.RESET} {finding.description}")
    print(f"  {C.DIM}Remediation:{C.RESET} {finding.remediation}")


def print_summary(report: AuditReport) -> None:
    score_color = C.GREEN if report.score >= 80 else C.YELLOW if report.score >= 60 else C.RED
    bar_length = int(report.score / 100 * 40)
    bar = "█" * bar_length + "░" * (40 - bar_length)

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}DOCKER SECURITY AUDIT REPORT{C.RESET}")
    print(f"  Target      : {report.target}")
    print(f"  Audit type  : {report.audit_type}")
    print(SEP)
    print(f"  {score_color}{C.BOLD}Security Score: {report.score}/100{C.RESET}  [{bar}]")
    print(f"  Passed: {report.passed}  Failed: {report.failed}  Warnings: {report.warnings}")
    print(SEP)

    counts: Dict[str, int] = {}
    for finding in report.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    for severity in SEVERITY_ORDER:
        count = counts.get(severity, 0)
        if count:
            color = SEV_COL.get(severity, "")
            print(f"  {color}{severity:<10}{C.RESET} {'█' * min(count, 30)} {count}")

    print(SEP2)


def generate_markdown(report: AuditReport) -> str:
    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "INFO": "⚪",
    }

    lines = [
        "# 🐳 Docker Security Audit Report",
        "",
        f"**Target:** `{report.target}`  ",
        f"**Audit type:** {report.audit_type}  ",
        f"**Date:** {report.timestamp[:19]}  ",
        f"**Security score:** **{report.score}/100**",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|:---:|",
        f"| Total checks | {report.total_checks} |",
        f"| Passed | {report.passed} |",
        f"| Failed | {report.failed} |",
        f"| Warnings | {report.warnings} |",
        f"| Findings | {len(report.findings)} |",
        "",
        "## Findings",
        "",
        "| Severity | Check | Title | Location | Evidence |",
        "|:---:|---|---|---|---|",
    ]

    for finding in sorted_findings(report.findings):
        location = finding.file + (f":{finding.line}" if finding.line else "") if finding.file else (str(finding.line) if finding.line else "")
        evidence = finding.evidence.replace("|", "\\|")
        lines.append(
            f"| {severity_emoji.get(finding.severity, '')} {finding.severity} "
            f"| {finding.check_id} "
            f"| {finding.title} "
            f"| `{location}` "
            f"| `{evidence[:90]}` |"
        )

    if report.findings:
        lines += ["", "## Remediation Details", ""]
        for finding in sorted_findings(report.findings):
            lines += [
                f"### {severity_emoji.get(finding.severity, '')} {finding.check_id} — {finding.title}",
                "",
                f"**Description:** {finding.description}",
                "",
                f"**Evidence:** `{finding.evidence}`",
                "",
                f"**Remediation:** {finding.remediation}",
                "",
            ]

    lines += ["", f"*Generated by docker-audit v{__version__}*"]
    return "\n".join(lines)


def sorted_findings(findings: Iterable[AuditFinding]) -> List[AuditFinding]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.index(finding.severity) if finding.severity in SEVERITY_ORDER else 99,
            finding.check_id,
            finding.line,
        ),
    )


def write_report(path: str, report: AuditReport, *, json_output: bool) -> None:
    output_path = Path(path)
    if json_output or output_path.suffix.lower() == ".json":
        output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    else:
        output_path.write_text(generate_markdown(report), encoding="utf-8")


def exit_code_for_report(report: AuditReport) -> int:
    severities = {finding.severity for finding in report.findings}
    if "CRITICAL" in severities:
        return 2
    if "HIGH" in severities or "MEDIUM" in severities:
        return 1
    return 0


def audit_dockerfile_path(path: Path) -> AuditReport:
    content = path.read_text(errors="replace")
    findings, checks = audit_dockerfile(content, str(path))
    return build_report(str(path), "dockerfile", findings, checks)


def audit_directory(directory: Path) -> AuditReport:
    dockerfiles = (
        list(directory.rglob("Dockerfile"))
        + list(directory.rglob("Dockerfile.*"))
        + list(directory.rglob("*.dockerfile"))
    )
    reports = [audit_dockerfile_path(path) for path in sorted(set(dockerfiles))]
    return merge_reports(str(directory), "directory-scan", reports)


def list_checks() -> None:
    print("# Dockerfile checks")
    for check in DOCKERFILE_CHECKS:
        print(f"{check.check_id:8} {check.severity:9} {check.title}")
    print()
    print("# Runtime checks")
    for check in RUNTIME_CHECKS:
        print(f"{check.check_id:8} {check.severity:9} {check.title}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docker-audit",
        description="Docker Security Auditor — CIS-inspired Dockerfile and runtime checks",
    )

    subparsers = parser.add_subparsers(dest="command")

    def add_common_output_options(command_parser: argparse.ArgumentParser) -> None:
        command_parser.add_argument("-o", "--output", help="Write report to file")
        command_parser.add_argument("--json", action="store_true", dest="json_output", help="Print/write JSON output")
        command_parser.add_argument("--no-banner", action="store_true", help="Do not print the banner")

    dockerfile_parser = subparsers.add_parser("dockerfile", aliases=["df"], help="Audit a Dockerfile")
    dockerfile_parser.add_argument("path", help="Path to the Dockerfile")
    add_common_output_options(dockerfile_parser)

    runtime_parser = subparsers.add_parser("runtime", aliases=["rt"], help="Audit a running/existing container")
    runtime_parser.add_argument("container", help="Container name or ID")
    add_common_output_options(runtime_parser)

    scan_parser = subparsers.add_parser("scan", help="Audit all Dockerfiles in a directory")
    scan_parser.add_argument("directory", help="Directory to scan")
    add_common_output_options(scan_parser)

    parser.add_argument("--dockerfile", help="Compatibility mode: audit this Dockerfile path")
    parser.add_argument("--runtime", action="store_true", help="Compatibility mode: audit runtime container(s)")
    parser.add_argument("--container", help="Container name or ID for --runtime")
    parser.add_argument("--scan", help="Compatibility mode: audit Dockerfiles in this directory")
    parser.add_argument("--list-checks", action="store_true", help="List implemented checks and exit")
    parser.add_argument("--demo", action="store_true", help="Run a demo audit against an intentionally insecure Dockerfile")
    parser.add_argument("--no-banner", action="store_true", help="Do not print the banner")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Print/write JSON instead of terminal/Markdown output")
    parser.add_argument("-o", "--output", help="Write report to file")
    parser.add_argument("--version", action="version", version=f"docker-audit {__version__}")

    return parser


def demo_report() -> AuditReport:
    insecure_dockerfile = """FROM ubuntu:latest
ENV DATABASE_PASSWORD=supersecret123
RUN apt-get update && apt-get install -y curl wget gcc make
RUN curl -s https://example.invalid/install.sh | bash
COPY . /app
RUN chmod -R 777 /app
ADD config /app/config
EXPOSE 22
CMD ["bash"]
"""
    findings, checks = audit_dockerfile(insecure_dockerfile, "demo/Dockerfile")
    return build_report("demo/Dockerfile", "dockerfile-demo", findings, checks)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    json_mode = bool(args.json_output)

    if not args.no_banner and not json_mode:
        print(BANNER)

    if args.list_checks:
        list_checks()
        return

    report: Optional[AuditReport] = None

    if args.demo:
        report = demo_report()

    elif args.dockerfile:
        path = Path(args.dockerfile)
        if not path.exists():
            print(f"{C.RED}[ERROR] File not found: {path}{C.RESET}", file=sys.stderr)
            sys.exit(1)
        log(f"  {C.DIM}Auditing Dockerfile: {path}{C.RESET}", quiet=json_mode)
        report = audit_dockerfile_path(path)

    elif args.runtime:
        if not args.container:
            print(f"{C.RED}[ERROR] --runtime requires --container <name-or-id>.{C.RESET}", file=sys.stderr)
            sys.exit(1)
        log(f"  {C.DIM}Inspecting container: {args.container}{C.RESET}", quiet=json_mode)
        findings, checks = audit_running_container(args.container, quiet=json_mode)
        report = build_report(args.container, "runtime", findings, checks)

    elif args.scan:
        directory = Path(args.scan)
        if not directory.exists():
            print(f"{C.RED}[ERROR] Directory not found: {directory}{C.RESET}", file=sys.stderr)
            sys.exit(1)
        log(f"  {C.DIM}Scanning directory: {directory}{C.RESET}", quiet=json_mode)
        report = audit_directory(directory)

    elif args.command in {"dockerfile", "df"}:
        path = Path(args.path)
        if not path.exists():
            print(f"{C.RED}[ERROR] File not found: {path}{C.RESET}", file=sys.stderr)
            sys.exit(1)
        log(f"  {C.DIM}Auditing Dockerfile: {path}{C.RESET}", quiet=json_mode)
        report = audit_dockerfile_path(path)

    elif args.command in {"runtime", "rt"}:
        log(f"  {C.DIM}Inspecting container: {args.container}{C.RESET}", quiet=json_mode)
        findings, checks = audit_running_container(args.container, quiet=json_mode)
        report = build_report(args.container, "runtime", findings, checks)

    elif args.command == "scan":
        directory = Path(args.directory)
        if not directory.exists():
            print(f"{C.RED}[ERROR] Directory not found: {directory}{C.RESET}", file=sys.stderr)
            sys.exit(1)
        log(f"  {C.DIM}Scanning directory: {directory}{C.RESET}", quiet=json_mode)
        report = audit_directory(directory)

    else:
        parser.print_help()
        sys.exit(1)

    if report is None:
        parser.print_help()
        sys.exit(1)

    if json_mode:
        if args.output:
            write_report(args.output, report, json_output=True)
        else:
            print(json.dumps(report.to_dict(), indent=2))
    else:
        for finding in sorted_findings(report.findings):
            print_finding(finding)
        print_summary(report)
        if args.output:
            write_report(args.output, report, json_output=False)
            print(f"\n  {C.GREEN}[✓] Report written to: {args.output}{C.RESET}")

    sys.exit(exit_code_for_report(report))


if __name__ == "__main__":
    main()

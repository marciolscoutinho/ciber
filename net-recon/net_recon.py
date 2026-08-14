#!/usr/bin/env python3
"""
net_recon.py — Network Recon Scanner v1.0.0
=============================================
Pure-Python network reconnaissance scanner (TCP connect + banner grabbing).
For use only on authorized networks and systems.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 03/03/2023
Reqs.  : Python 3.8+ | Zero external dependencies | Run only with authorization
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

__version__ = "1.0.0"


class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


# ══════════════════════════════════════════════════════════════════════════════
# SERVICE DATABASE
# ══════════════════════════════════════════════════════════════════════════════

KNOWN_SERVICES: Dict[int, str] = {
    21: "FTP",         22: "SSH",         23: "Telnet",
    25: "SMTP",        53: "DNS",         67: "DHCP",
    69: "TFTP",        80: "HTTP",        88: "Kerberos",
    110: "POP3",       111: "RPC",        119: "NNTP",
    123: "NTP",        135: "MS-RPC",     137: "NetBIOS-NS",
    138: "NetBIOS-DGM",139: "NetBIOS-SSN",143: "IMAP",
    161: "SNMP",       179: "BGP",        389: "LDAP",
    443: "HTTPS",      445: "SMB",        465: "SMTPS",
    500: "IKE/VPN",    587: "SMTP-Sub",   631: "IPP",
    636: "LDAPS",      873: "rsync",      993: "IMAPS",
    995: "POP3S",      1080: "SOCKS",     1433: "MSSQL",
    1521: "Oracle",    1723: "PPTP",      2049: "NFS",
    2375: "Docker",    2376: "Docker-TLS",3000: "Dev/Grafana",
    3306: "MySQL",     3389: "RDP",       3690: "SVN",
    4444: "Metasploit",4848: "GlassFish", 5000: "Dev/Flask",
    5432: "PostgreSQL",5900: "VNC",       5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",6379: "Redis",   7070: "AJP/Dev",
    8000: "Dev-HTTP",  8080: "HTTP-Alt",  8081: "HTTP-Alt2",
    8443: "HTTPS-Alt", 8888: "Jupyter",   9000: "PHP-FPM",
    9090: "Prometheus",9200: "Elasticsearch",9300: "ES-Transport",
    27017: "MongoDB",  27018: "MongoDB",  50070: "Hadoop",
}

# High-risk ports — require special attention
HIGH_RISK_PORTS = {
    21, 23, 69, 135, 137, 138, 139, 161, 445,
    1433, 2375, 3389, 4444, 5900, 6379, 9200, 27017,
}


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PortResult:
    port:     int
    state:    str          # open / closed / filtered
    service:  str
    banner:   str = ""
    risk:     str = "LOW"  # HIGH / MEDIUM / LOW


@dataclass
class HostResult:
    host:      str
    ip:        str
    hostname:  str
    is_up:     bool
    os_hint:   str
    open_ports: List[PortResult] = field(default_factory=list)
    scan_time: str = ""

    @property
    def risk_score(self) -> int:
        score = 0
        for p in self.open_ports:
            if p.risk == "HIGH":   score += 30
            elif p.risk == "MEDIUM": score += 10
            else:                    score += 2
        return score


# ══════════════════════════════════════════════════════════════════════════════
# SCANNING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """TCP connect scan — determines whether a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def banner_grab(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempts to retrieve the service banner."""
    probes = {
        80:  b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
        443: b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
        21:  b"",          # FTP sends a banner without a prompt
        22:  b"",          # SSH sends a banner without a prompt
        25:  b"",          # SMTP sends a banner without a prompt
        110: b"",          # POP3 sends a banner without a prompt
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        probe = probes.get(port, b"\r\n")
        if probe:
            sock.send(probe)

        banner = sock.recv(512).decode(errors="ignore").strip()
        sock.close()
        # Clean and truncate
        banner = banner.split("\n")[0].strip()
        return banner[:120] if banner else ""
    except Exception:
        return ""


def os_fingerprint_hint(open_ports: List[PortResult]) -> str:
    """Simple OS heuristic based on open ports."""
    ports = {p.port for p in open_ports}

    if 3389 in ports or 445 in ports or 135 in ports:
        return "Windows (likely)"
    if 22 in ports and 3389 not in ports:
        if 111 in ports or 2049 in ports:
            return "Linux/Unix (NFS exposed)"
        return "Linux/Unix (likely)"
    if 548 in ports:
        return "macOS (AFP)"
    if len(ports) == 0:
        return "Unknown / Filtered"
    return "Unknown"


def classify_risk(port: int) -> str:
    if port in HIGH_RISK_PORTS:
        return "HIGH"
    if port in {25, 110, 143, 161, 389, 636, 873, 1521, 2049, 5900}:
        return "MEDIUM"
    return "LOW"


def scan_port_worker(host: str, port: int, timeout: float,
                     grab_banners: bool) -> Optional[PortResult]:
    if not tcp_connect(host, port, timeout):
        return None

    service = KNOWN_SERVICES.get(port, "Unknown")
    banner  = banner_grab(host, port) if grab_banners else ""
    risk    = classify_risk(port)

    return PortResult(
        port    = port,
        state   = "open",
        service = service,
        banner  = banner,
        risk    = risk,
    )


def scan_host(host: str, ports: List[int], timeout: float = 1.0,
              max_threads: int = 100, grab_banners: bool = True,
              verbose: bool = False) -> HostResult:
    """Performs a complete scan of a host."""
    # Resolve hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return HostResult(host=host, ip="", hostname="", is_up=False, os_hint="")

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = ""

    # Check whether the host is up (ICMP unavailable without root — use TCP)
    is_up = any(tcp_connect(ip, p, timeout=0.5) for p in [80, 443, 22, 445][:4])
    if not is_up:
        is_up = tcp_connect(ip, ports[0] if ports else 80, timeout=1.0)

    open_ports: List[PortResult] = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port_worker, ip, port, timeout, grab_banners): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                if verbose:
                    risk_col = C.RED if result.risk == "HIGH" else C.YELLOW if result.risk == "MEDIUM" else C.GREEN
                    print(f"  {risk_col}●{C.RESET} {result.port:<6} {result.service:<15} {result.banner[:50]}")

    open_ports.sort(key=lambda p: p.port)
    os_hint = os_fingerprint_hint(open_ports)

    return HostResult(
        host       = host,
        ip         = ip,
        hostname   = hostname,
        is_up      = is_up or len(open_ports) > 0,
        os_hint    = os_hint,
        open_ports = open_ports,
        scan_time  = datetime.now().isoformat(),
    )


# ══════════════════════════════════════════════════════════════════════════════
# PORT RANGE PARSER
# ══════════════════════════════════════════════════════════════════════════════

TOP_100_PORTS = [
    21,22,23,25,53,80,88,110,111,119,123,135,137,138,139,143,161,
    179,389,443,445,465,500,587,631,636,873,993,995,1080,1433,1521,
    1723,2049,2375,2376,3000,3306,3389,3690,4444,4848,5000,5432,
    5900,5985,5986,6379,7070,8000,8080,8081,8443,8888,9000,9090,
    9200,9300,27017,27018,50070,
]


def parse_ports(port_str: str) -> List[int]:
    """Parses a port string: 22,80,443 / 1-1024 / top100."""
    if port_str == "top100":
        return TOP_100_PORTS
    if port_str == "common":
        return list(KNOWN_SERVICES.keys())
    if port_str == "all":
        return list(range(1, 65536))

    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def expand_targets(target: str) -> List[str]:
    """Expands CIDR notation into a list of IP addresses."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [target]


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

BANNER = f"""
{C.CYAN}{C.BOLD}
  ███╗   ██╗███████╗████████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║       ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║       ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{C.RESET}
{C.DIM}  v{__version__} — Network Recon Scanner | TCP Connect | Banner Grab | Zero Deps{C.RESET}
{C.YELLOW}  ⚠  Use ONLY on systems and networks with explicit authorization.{C.RESET}
"""


def print_host_result(result: HostResult) -> None:
    SEP = "━" * 68
    up_str = f"{C.GREEN}UP{C.RESET}" if result.is_up else f"{C.RED}DOWN{C.RESET}"
    score_col = C.RED if result.risk_score > 60 else C.YELLOW if result.risk_score > 20 else C.GREEN

    print(f"\n{SEP}")
    print(f"  {C.BOLD}Host:{C.RESET} {result.host}  ({result.ip})")
    if result.hostname and result.hostname != result.host:
        print(f"  {C.DIM}rDNS:{C.RESET}  {result.hostname}")
    print(f"  Status: {up_str}  |  OS hint: {C.DIM}{result.os_hint}{C.RESET}  |  "
          f"Risk Score: {score_col}{result.risk_score}{C.RESET}")
    print(f"{SEP}")

    if not result.open_ports:
        print(f"  {C.DIM}No open ports found.{C.RESET}")
        return

    print(f"  {'Port':<8} {'Service':<15} {'Risk':<8} Banner")
    print(f"  {'─'*64}")
    for p in result.open_ports:
        risk_col = C.RED if p.risk == "HIGH" else C.YELLOW if p.risk == "MEDIUM" else C.GREEN
        banner   = f"{C.DIM}{p.banner[:50]}{C.RESET}" if p.banner else ""
        print(f"  {C.GREEN}●{C.RESET} {p.port:<6} {p.service:<15} {risk_col}{p.risk:<8}{C.RESET} {banner}")


def print_summary(results: List[HostResult]) -> None:
    total_open  = sum(len(r.open_ports) for r in results)
    hosts_up    = sum(1 for r in results if r.is_up)
    high_risk   = sum(1 for r in results for p in r.open_ports if p.risk == "HIGH")

    print(f"\n{'═'*68}")
    print(f"  {C.BOLD}SCAN SUMMARY{C.RESET}")
    print(f"{'═'*68}")
    print(f"  Target hosts  : {len(results)}")
    print(f"  Hosts UP      : {C.GREEN}{hosts_up}{C.RESET}")
    print(f"  Open ports    : {total_open}")
    print(f"  High-risk     : {C.RED}{high_risk}{C.RESET}")

    if high_risk > 0:
        print(f"\n  {C.RED}{C.BOLD}⚠ High-risk ports:{C.RESET}")
        for r in results:
            for p in r.open_ports:
                if p.risk == "HIGH":
                    print(f"    {r.host}:{p.port} ({p.service})")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="net-recon",
        description="Network Recon Scanner — TCP Connect | Banner Grab"
    )
    parser.add_argument("targets",    nargs="+", help="Hosts/IPs/CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",   default="common",
                        help="Ports: 22,80 / 1-1024 / common / top100 / all (default: common)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout TCP (default: 1.0s)")
    parser.add_argument("--threads",       type=int, default=100,   help="Parallel threads (default: 100)")
    parser.add_argument("--no-banner",     action="store_true",     help="Disable banner grabbing")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json",          action="store_true", dest="json_out")
    parser.add_argument("-o", "--output",  help="Save JSON output to a file")
    parser.add_argument("--version",       action="version", version=f"net-recon {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    ports   = parse_ports(args.ports)
    targets = []
    for t in args.targets:
        targets.extend(expand_targets(t))

    print(f"  {C.DIM}Targets: {len(targets)} hosts | Ports: {len(ports)} | "
          f"Threads: {args.threads} | Timeout: {args.timeout}s{C.RESET}\n")

    all_results = []
    for target in targets:
        if args.verbose:
            print(f"\n  {C.CYAN}[*] Scanning {target}...{C.RESET}")
        result = scan_host(
            host        = target,
            ports       = ports,
            timeout     = args.timeout,
            max_threads = args.threads,
            grab_banners= not args.no_banner,
            verbose     = args.verbose,
        )
        all_results.append(result)
        if not args.json_out:
            print_host_result(result)

    if not args.json_out:
        print_summary(all_results)

    # JSON output
    if args.json_out or args.output:
        out = []
        for r in all_results:
            out.append({
                "host":      r.host,
                "ip":        r.ip,
                "hostname":  r.hostname,
                "is_up":     r.is_up,
                "os_hint":   r.os_hint,
                "risk_score":r.risk_score,
                "open_ports":[{
                    "port":    p.port,
                    "service": p.service,
                    "risk":    p.risk,
                    "banner":  p.banner,
                } for p in r.open_ports],
                "scan_time": r.scan_time,
            })

        json_str = json.dumps(out, indent=2, ensure_ascii=False)
        if args.json_out:
            print(json_str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(json_str)
            print(f"\n  {C.GREEN}[✓] Result saved: {args.output}{C.RESET}")


if __name__ == "__main__":
    main()

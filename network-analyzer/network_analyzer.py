#!/usr/bin/env python3
"""
network_analyzer.py — Network Traffic Analyzer v1.0.0
======================================================
Analyzes PCAP files and network traffic.
Detects anomalies: port scans, brute-force attacks, DNS tunneling, and C2 beaconing.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 23/12/2025
Requires: Python 3.8+ | Zero external dependencies
          tshark (optional) for real PCAP analysis
"""
from __future__ import annotations
import argparse, collections, json, math, re, struct, sys
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
 ███╗   ██╗███████╗████████╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗
 ████╗  ██║██╔════╝╚══██╔══╝   ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚════██║██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║      ███████║██╔██╗ ██║███████║██║   ╚████╔╝     ██╔╝█████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║      ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝     ██╔╝ ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║      ██║  ██║██║ ╚████║██║  ██║███████╗██║      ██║  ███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═╝  ╚══════╝╚═╝  ╚═╝{C.RESET}
{C.DIM} v{__version__} — PCAP Analyzer | Port Scan · Brute Force · DNS Tunnel · C2 Beaconing{C.RESET}
"""

SEP  = "━"*72
SEP2 = "═"*72

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Packet:
    timestamp: float
    src_ip:    str
    dst_ip:    str
    src_port:  int
    dst_port:  int
    protocol:  str   # TCP/UDP/ICMP/ARP/DNS
    length:    int
    flags:     str   # TCP flags: SYN,ACK,RST,FIN,PSH,URG
    payload:   bytes = field(default=b"", repr=False)
    dns_query: str   = ""
    http_host: str   = ""
    http_method:str  = ""

@dataclass
class Anomaly:
    category:  str
    severity:  str
    src_ip:    str
    dst_ip:    str
    port:      int
    description: str
    evidence:  str
    count:     int = 1
    first_seen:float = 0.0
    last_seen: float = 0.0

# ══════════════════════════════════════════════════════════════════════════════
# PCAP PARSER (lightweight, zero deps)
# ══════════════════════════════════════════════════════════════════════════════

PCAP_GLOBAL_HEADER = struct.Struct("<IHHiIII")  # 24 bytes
PCAP_PKT_HEADER    = struct.Struct("<IIII")      # 16 bytes

PROTO_MAP = {1:"ICMP", 6:"TCP", 17:"UDP", 41:"IPv6"}

TCP_FLAGS = {
    0x01:"FIN", 0x02:"SYN", 0x04:"RST", 0x08:"PSH",
    0x10:"ACK", 0x20:"URG", 0x40:"ECE", 0x80:"CWR"
}

def _parse_flags(flags_byte: int) -> str:
    return ",".join(name for bit, name in TCP_FLAGS.items() if flags_byte & bit)

def _parse_ipv4(data: bytes, offset: int) -> Tuple[str,str,int,int,int,str,bytes]:
    """Parse IPv4 header. Returns (src,dst,src_port,dst_port,proto,flags,payload)."""
    if offset + 20 > len(data):
        return "","",0,0,0,"",b""
    ihl      = (data[offset] & 0x0f) * 4
    proto_id = data[offset+9]
    proto    = PROTO_MAP.get(proto_id, str(proto_id))
    src_ip   = ".".join(str(b) for b in data[offset+12:offset+16])
    dst_ip   = ".".join(str(b) for b in data[offset+16:offset+20])
    transport = data[offset+ihl:]
    src_port = dst_port = 0
    flags = ""
    payload = b""

    if proto_id == 6 and len(transport) >= 20:   # TCP
        src_port = struct.unpack_from(">H", transport, 0)[0]
        dst_port = struct.unpack_from(">H", transport, 2)[0]
        data_offset = (transport[12] >> 4) * 4
        flags = _parse_flags(transport[13])
        payload = transport[data_offset:]
    elif proto_id == 17 and len(transport) >= 8: # UDP
        src_port = struct.unpack_from(">H", transport, 0)[0]
        dst_port = struct.unpack_from(">H", transport, 2)[0]
        payload  = transport[8:]
    return src_ip, dst_ip, src_port, dst_port, proto_id, flags, payload

def _parse_dns_query(data: bytes) -> str:
    """Extract the DNS query name from the UDP payload."""
    try:
        if len(data) < 12: return ""
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0: break
            if (length & 0xc0) == 0xc0: break  # pointer
            offset += 1
            labels.append(data[offset:offset+length].decode(errors="replace"))
            offset += length
        return ".".join(labels)
    except Exception:
        return ""

def parse_pcap(filepath: str) -> List[Packet]:
    packets: List[Packet] = []
    try:
        raw = Path(filepath).read_bytes()
    except Exception as e:
        print(f"  {C.RED}[ERROR] {e}{C.RESET}")
        return []

    if len(raw) < 24:
        return []

    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic not in (0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d):
        print(f"  {C.RED}[ERROR] Not a valid PCAP file (magic: 0x{magic:08x}){C.RESET}")
        return []

    gh = PCAP_GLOBAL_HEADER.unpack_from(raw, 0)
    link_type = gh[6]  # 1 = Ethernet
    offset    = 24

    while offset + 16 <= len(raw):
        ph = PCAP_PKT_HEADER.unpack_from(raw, offset)
        ts_sec, ts_usec, incl_len, orig_len = ph
        ts = ts_sec + ts_usec / 1e6
        offset += 16
        pkt_data = raw[offset:offset+incl_len]
        offset  += incl_len

        # Ethernet header (14 bytes) → IPv4
        if link_type == 1 and len(pkt_data) >= 14:
            eth_type = struct.unpack_from(">H", pkt_data, 12)[0]
            if eth_type == 0x0800:  # IPv4
                src, dst, sp, dp, proto_id, flags, payload = _parse_ipv4(pkt_data, 14)
                proto = PROTO_MAP.get(proto_id, str(proto_id))

                dns_query = ""
                if dp == 53 or sp == 53:
                    proto = "DNS"
                    dns_query = _parse_dns_query(payload)

                http_host = http_method = ""
                if dp == 80 or dp == 8080:
                    try:
                        text = payload[:512].decode(errors="replace")
                        m = re.search(r"^(GET|POST|PUT|DELETE|PATCH|HEAD) ", text)
                        if m: http_method = m.group(1)
                        m = re.search(r"Host: ([^\r\n]+)", text)
                        if m: http_host = m.group(1).strip()
                    except Exception: pass

                packets.append(Packet(
                    timestamp=ts, src_ip=src, dst_ip=dst,
                    src_port=sp, dst_port=dp, protocol=proto,
                    length=orig_len, flags=flags, payload=payload[:64],
                    dns_query=dns_query, http_host=http_host, http_method=http_method,
                ))

    return packets

# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTORS
# ══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    # Thresholds
    PORT_SCAN_THRESHOLD   = 15   # unique ports in < 5s
    BRUTE_FORCE_THRESHOLD = 20   # attempts per minute
    DNS_ENTROPY_THRESHOLD = 3.8  # entropy bits per label
    BEACON_TOLERANCE      = 0.15 # ±15% regular interval
    HIGH_VOLUME_THRESHOLD = 500  # packets/min from a single IP

    def __init__(self):
        self.anomalies: List[Anomaly] = []

    def _add(self, cat: str, sev: str, src: str, dst: str,
             port: int, desc: str, evidence: str,
             count: int = 1, first: float = 0, last: float = 0):
        self.anomalies.append(Anomaly(
            cat, sev, src, dst, port, desc, evidence, count, first, last
        ))

    def detect_port_scan(self, packets: List[Packet]) -> None:
        """Detect port scanning: many unique ports within a short time window."""
        # Group by (src, dst) → unique ports within 5-second windows
        flows: Dict[Tuple, List] = collections.defaultdict(list)
        for p in packets:
            if p.protocol == "TCP" and "SYN" in p.flags and "ACK" not in p.flags:
                flows[(p.src_ip, p.dst_ip)].append((p.timestamp, p.dst_port))

        for (src, dst), events in flows.items():
            events.sort()
            # 5-second sliding window
            for i, (t0, _) in enumerate(events):
                window = [e for e in events if t0 <= e[0] <= t0 + 5]
                ports  = set(e[1] for e in window)
                if len(ports) >= self.PORT_SCAN_THRESHOLD:
                    self._add("Port Scan","HIGH", src, dst, 0,
                        f"Port scan detected: {len(ports)} unique ports in 5s",
                        f"Ports: {sorted(ports)[:15]}...",
                        len(ports), t0, window[-1][0])
                    break  # one report per src/dst pair

    def detect_brute_force(self, packets: List[Packet]) -> None:
        """Detect SSH/FTP/HTTP brute force: many failed connection attempts."""
        # Rapid RST or FIN = refused/closed connection = possible brute force
        attempts: Dict[Tuple, List[float]] = collections.defaultdict(list)
        for p in packets:
            if p.dst_port in (22, 21, 3389, 23, 110, 143, 5900):
                if "SYN" in p.flags:
                    attempts[(p.src_ip, p.dst_ip, p.dst_port)].append(p.timestamp)

        for (src, dst, port), timestamps in attempts.items():
            if len(timestamps) < self.BRUTE_FORCE_THRESHOLD:
                continue
            timestamps.sort()
            # Rate per minute
            duration = max(timestamps[-1] - timestamps[0], 1)
            rate     = len(timestamps) / duration * 60
            if rate >= self.BRUTE_FORCE_THRESHOLD:
                service = {22:"SSH",21:"FTP",3389:"RDP",23:"Telnet",
                           5900:"VNC"}.get(port, str(port))
                self._add("Brute Force","HIGH", src, dst, port,
                    f"Brute force against {service}: {len(timestamps)} attempts ({rate:.0f}/min)",
                    f"{len(timestamps)} SYNs in {duration:.0f}s → port {port}",
                    len(timestamps), timestamps[0], timestamps[-1])

    def detect_dns_tunneling(self, packets: List[Packet]) -> None:
        """Detect DNS tunneling: queries with high-entropy or unusually long labels."""
        dns_by_src: Dict[str, List[str]] = collections.defaultdict(list)
        for p in packets:
            if p.protocol == "DNS" and p.dns_query:
                dns_by_src[p.src_ip].append(p.dns_query)

        for src, queries in dns_by_src.items():
            suspicious = []
            for q in queries:
                parts = q.split(".")
                if not parts: continue
                label = parts[0]
                # Very long label
                if len(label) > 30:
                    suspicious.append(q)
                    continue
                # High entropy
                if len(label) > 6:
                    freq    = collections.Counter(label)
                    entropy = -sum((f/len(label))*math.log2(f/len(label))
                                   for f in freq.values() if f)
                    if entropy > self.DNS_ENTROPY_THRESHOLD:
                        suspicious.append(q)

            if len(suspicious) >= 5:
                self._add("DNS Tunneling","HIGH", src, "DNS Server", 53,
                    f"Possible DNS tunneling: {len(suspicious)} suspicious queries",
                    f"Example: {suspicious[0][:80]}",
                    len(suspicious))

    def detect_beaconing(self, packets: List[Packet]) -> None:
        """Detect C2 beaconing: connections at regular intervals."""
        # Group by (src, dst, dport)
        flows: Dict[Tuple, List[float]] = collections.defaultdict(list)
        for p in packets:
            if p.protocol == "TCP" and "SYN" in p.flags and p.dst_port not in (80,443,8080,8443):
                flows[(p.src_ip, p.dst_ip, p.dst_port)].append(p.timestamp)

        for (src, dst, port), timestamps in flows.items():
            if len(timestamps) < 5:
                continue
            timestamps.sort()
            intervals = [timestamps[i+1]-timestamps[i] for i in range(len(timestamps)-1)]
            if not intervals: continue
            avg = sum(intervals)/len(intervals)
            if avg < 5: continue  # too fast for beaconing
            # Coefficient of variation (regularity)
            std  = math.sqrt(sum((x-avg)**2 for x in intervals)/len(intervals))
            cv   = std / avg if avg else 1
            if cv < self.BEACON_TOLERANCE and len(timestamps) >= 8:
                self._add("C2 Beaconing","CRITICAL", src, dst, port,
                    f"Possible C2 beaconing: {len(timestamps)} connections approximately every {avg:.0f}s (CV={cv:.2f})",
                    f"Destination port: {port} | Average interval: {avg:.1f}s | Regularity: {cv:.3f}",
                    len(timestamps), timestamps[0], timestamps[-1])

    def detect_high_volume(self, packets: List[Packet]) -> None:
        """Detect anomalously high traffic volume (possible DoS/DDoS)."""
        by_src: Dict[str, List[float]] = collections.defaultdict(list)
        for p in packets:
            by_src[p.src_ip].append(p.timestamp)

        for src, timestamps in by_src.items():
            if len(timestamps) < 50: continue
            timestamps.sort()
            # 60-second window with > HIGH_VOLUME_THRESHOLD packets
            for i, t0 in enumerate(timestamps):
                window = [t for t in timestamps if t0 <= t <= t0+60]
                if len(window) >= self.HIGH_VOLUME_THRESHOLD:
                    # Verificar se é para múltiplos destinos (DDoS)
                    dst_set = set(p.dst_ip for p in packets
                                  if p.src_ip == src and t0 <= p.timestamp <= t0+60)
                    desc = (f"High-volume traffic: {len(window)} packets/min"
                            + (f" to {len(dst_set)} destinations" if len(dst_set) > 1 else ""))
                    self._add("High Volume / DoS","HIGH", src, "*", 0,
                        desc, f"{len(window)} pkts/min", len(window), t0, t0+60)
                    break

    def detect_data_exfiltration(self, packets: List[Packet]) -> None:
        """Heuristic: large volumes of data sent to uncommon external IP addresses."""
        # Data volume by (src_ip, dst_ip)
        outbound: Dict[Tuple[str,str], int] = collections.defaultdict(int)
        for p in packets:
            if p.dst_port not in (80,443,8080,8443,53):
                outbound[(p.src_ip, p.dst_ip)] += p.length

        for (src, dst), total_bytes in outbound.items():
            if total_bytes > 50 * 1024 * 1024:  # > 50 MB
                self._add("Data Exfiltration","MEDIUM", src, dst, 0,
                    f"Large transfer to external destination: {total_bytes//1024//1024}MB",
                    f"{src} → {dst}: {total_bytes:,} bytes",
                    1)

    def run_all(self, packets: List[Packet]) -> None:
        self.detect_port_scan(packets)
        self.detect_brute_force(packets)
        self.detect_dns_tunneling(packets)
        self.detect_beaconing(packets)
        self.detect_high_volume(packets)
        self.detect_data_exfiltration(packets)

# ══════════════════════════════════════════════════════════════════════════════
# STATISTICS
# ══════════════════════════════════════════════════════════════════════════════

def compute_stats(packets: List[Packet]) -> dict:
    if not packets: return {}
    by_proto    = collections.Counter(p.protocol for p in packets)
    by_src_ip   = collections.Counter(p.src_ip for p in packets)
    by_dst_port = collections.Counter(p.dst_port for p in packets
                                       if p.dst_port > 0)
    dns_queries = collections.Counter(p.dns_query for p in packets
                                       if p.dns_query)
    total_bytes = sum(p.length for p in packets)
    duration    = packets[-1].timestamp - packets[0].timestamp if len(packets) > 1 else 0

    return {
        "total_packets":  len(packets),
        "total_bytes":    total_bytes,
        "duration_sec":   round(duration, 2),
        "packets_per_sec":round(len(packets)/max(duration,1), 1),
        "protocols":      dict(by_proto.most_common(10)),
        "top_src_ips":    dict(by_src_ip.most_common(10)),
        "top_dst_ports":  dict(by_dst_port.most_common(15)),
        "top_dns_queries":dict(dns_queries.most_common(10)),
        "unique_src_ips": len(set(p.src_ip for p in packets)),
        "unique_dst_ips": len(set(p.dst_ip for p in packets)),
    }

# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN}

def print_stats(stats: dict) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}TRAFFIC STATISTICS{C.RESET}")
    print(f"  Packets     : {stats['total_packets']:,}")
    print(f"  Total bytes : {stats['total_bytes']:,} ({stats['total_bytes']//1024//1024}MB)")
    print(f"  Duration    : {stats['duration_sec']:.1f}s")
    print(f"  Rate        : {stats['packets_per_sec']} pkt/s")
    print(f"  Unique IPs  : {stats['unique_src_ips']} src / {stats['unique_dst_ips']} dst")

    print(f"\n  {C.BOLD}Protocol Distribution:{C.RESET}")
    total = stats["total_packets"] or 1
    for proto, count in stats["protocols"].items():
        pct = count/total*100
        bar = "█" * int(pct/3)
        print(f"  {C.CYAN}{proto:<8}{C.RESET} {bar:<20} {count:>6} ({pct:.1f}%)")

    print(f"\n  {C.BOLD}Top Source IPs:{C.RESET}")
    for ip, count in list(stats["top_src_ips"].items())[:5]:
        print(f"  {C.DIM}{ip:<18}{C.RESET} {count:>6} packets")

    print(f"\n  {C.BOLD}Top Destination Ports:{C.RESET}")
    COMMON_PORTS = {22:"SSH",80:"HTTP",443:"HTTPS",53:"DNS",3389:"RDP",
                    21:"FTP",25:"SMTP",3306:"MySQL",8080:"HTTP-Alt"}
    for port, count in list(stats["top_dst_ports"].items())[:8]:
        svc = COMMON_PORTS.get(port,"")
        print(f"  {C.CYAN}:{port:<6}{C.RESET} {svc:<10} {count:>6} packets")

def print_anomalies(anomalies: List[Anomaly]) -> None:
    print(f"\n{SEP2}")
    print(f"  {C.BOLD}ANOMALY DETECTION — {len(anomalies)} findings{C.RESET}")
    print(SEP2)
    if not anomalies:
        print(f"  {C.GREEN}✅ No anomalies detected.{C.RESET}")
        return
    for a in sorted(anomalies,
                    key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity)
                    if x.severity in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99):
        col = SEV_COL.get(a.severity, "")
        print(f"\n  {col}[{a.severity}]{C.RESET} {C.BOLD}{a.category}{C.RESET}")
        print(f"  {C.DIM}Src:{C.RESET} {a.src_ip}  →  {C.DIM}Dst:{C.RESET} {a.dst_ip}"
              + (f":{a.port}" if a.port else ""))
        print(f"  {a.description}")
        print(f"  {C.DIM}Evidence:{C.RESET} {a.evidence[:100]}")

def generate_report(packets: List[Packet], anomalies: List[Anomaly],
                    stats: dict, filepath: str) -> str:
    lines = [
        f"# 🌐 Network Traffic Analysis Report",
        f"**File:** {filepath} | **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"",
        f"## Statistics",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Total packets | {stats.get('total_packets',0):,} |",
        f"| Total bytes | {stats.get('total_bytes',0):,} |",
        f"| Duration | {stats.get('duration_sec',0):.1f}s |",
        f"| Unique source IPs | {stats.get('unique_src_ips',0)} |",
        f"",
        f"## Detected Anomalies ({len(anomalies)})",
        f"",
        f"| Severity | Category | Source IP | Description |",
        f"|:---:|---|---|---|",
    ]
    sev_em = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    for a in anomalies:
        em = sev_em.get(a.severity,"")
        lines.append(f"| {em} {a.severity} | {a.category} | {a.src_ip} | {a.description[:80]} |")
    lines += ["",f"*Generated by network-analyzer v{__version__}*"]
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# DEMO MODE (synthetic packets for testing)
# ══════════════════════════════════════════════════════════════════════════════

def generate_demo_packets() -> List[Packet]:
    """Generate synthetic packets for demonstration purposes."""
    import random
    random.seed(42)
    packets: List[Packet] = []
    base_ts = 1700000000.0

    # Normal HTTP/HTTPS traffic
    for i in range(200):
        packets.append(Packet(
            timestamp=base_ts + i*0.5, src_ip="192.168.1.10",
            dst_ip="93.184.216.34", src_port=random.randint(49152,65535),
            dst_port=443, protocol="TCP", length=random.randint(200,1500),
            flags="SYN" if i%10==0 else "ACK"))

    # Port scan (attacker)
    for port in range(1, 50):
        packets.append(Packet(
            timestamp=base_ts + 10 + port*0.05, src_ip="185.220.101.47",
            dst_ip="192.168.1.10", src_port=55000, dst_port=port,
            protocol="TCP", length=60, flags="SYN"))

    # SSH brute force
    for i in range(80):
        packets.append(Packet(
            timestamp=base_ts + 50 + i*0.3, src_ip="203.0.113.42",
            dst_ip="192.168.1.1", src_port=random.randint(49152,65535),
            dst_port=22, protocol="TCP", length=74, flags="SYN"))

    # DNS tunneling (high-entropy queries)
    import base64
    for i in range(20):
        label = base64.b32encode(bytes(range(i,i+20))).decode().lower()
        packets.append(Packet(
            timestamp=base_ts + 100 + i*2, src_ip="192.168.1.55",
            dst_ip="8.8.8.8", src_port=random.randint(49152,65535),
            dst_port=53, protocol="DNS", length=100,
            flags="", dns_query=f"{label}.evil-c2.xyz"))

    # C2 beaconing (regular intervals)
    for i in range(15):
        packets.append(Packet(
            timestamp=base_ts + 200 + i*30 + random.uniform(-1,1),
            src_ip="192.168.1.33", dst_ip="198.51.100.10",
            src_port=random.randint(49152,65535), dst_port=4444,
            protocol="TCP", length=200, flags="SYN"))

    return sorted(packets, key=lambda p: p.timestamp)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="network-analyzer",
        description="Network Traffic Analyzer — PCAP · Port Scan · Brute Force · DNS Tunnel · C2")
    parser.add_argument("pcap", nargs="?", help="PCAP file to analyze")
    parser.add_argument("--demo",    action="store_true", help="Demo mode (synthetic packets)")
    parser.add_argument("--stats",   action="store_true", default=True, help="Show statistics")
    parser.add_argument("--no-detect", action="store_true", help="Disable anomaly detection")
    parser.add_argument("-o","--output", help="Save Markdown report")
    parser.add_argument("--json",    action="store_true", dest="json_out")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version=f"network-analyzer {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    if args.demo or not args.pcap:
        print(f"  {C.DIM}Demo mode — generating {200+50+80+20+15} synthetic packets...{C.RESET}")
        packets = generate_demo_packets()
        filepath = "demo_traffic"
    else:
        if not Path(args.pcap).exists():
            print(f"  {C.RED}[ERROR] File not found: {args.pcap}{C.RESET}")
            sys.exit(1)
        print(f"  {C.DIM}Parsing PCAP: {args.pcap}...{C.RESET}")
        packets = parse_pcap(args.pcap)
        filepath = args.pcap

    if not packets:
        print(f"  {C.YELLOW}No packets analyzed.{C.RESET}")
        sys.exit(0)

    print(f"  {C.GREEN}{len(packets):,} packets loaded.{C.RESET}")

    stats = compute_stats(packets)
    if args.stats:
        print_stats(stats)

    anomalies: List[Anomaly] = []
    if not args.no_detect:
        print(f"\n  {C.DIM}Running anomaly detectors...{C.RESET}")
        detector = AnomalyDetector()
        detector.run_all(packets)
        anomalies = detector.anomalies
        print_anomalies(anomalies)

    if args.json_out:
        out = {
            "file": filepath, "timestamp": datetime.now().isoformat(),
            "stats": stats,
            "anomalies": [a.__dict__ for a in anomalies],
        }
        print(json.dumps(out, indent=2))

    if args.output:
        md = generate_report(packets, anomalies, stats, filepath)
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    sys.exit(2 if any(a.severity=="CRITICAL" for a in anomalies) else 0)

if __name__ == "__main__":
    main()

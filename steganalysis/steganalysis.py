#!/usr/bin/env python3
"""
steganalysis.py — Steganalysis Tool v1.0.0
============================================
Detection of hidden data in images (LSB steganography, metadata, strings).
Forensic analysis tool for CTFs and digital forensics.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 01/08/2025
Req.   : Python 3.8+ | Zero external dependencies (stdlib only)
"""

from __future__ import annotations

import argparse
import binascii
import json
import math
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

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
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    category:    str
    severity:    str   # HIGH / MEDIUM / LOW / INFO
    description: str
    detail:      str   = ""
    data:        bytes = field(default=b"", repr=False)


@dataclass
class StegReport:
    filepath:    str
    filesize:    int
    filetype:    str
    findings:    List[Finding]
    metadata:    dict
    strings:     List[str]
    entropy:     float
    risk_score:  int


# ══════════════════════════════════════════════════════════════════════════════
# FILE TYPE DETECTION
# ══════════════════════════════════════════════════════════════════════════════

MAGIC_BYTES = {
    b"\xff\xd8\xff":         "JPEG",
    b"\x89PNG\r\n\x1a\n":   "PNG",
    b"GIF87a":               "GIF",
    b"GIF89a":               "GIF",
    b"BM":                   "BMP",
    b"RIFF":                 "WAV/AVI",
    b"PK\x03\x04":           "ZIP",
    b"\x1f\x8b":             "GZIP",
    b"Rar!":                 "RAR",
    b"7z\xbc\xaf'":          "7ZIP",
    b"%PDF":                 "PDF",
    b"\x00\x00\x00\x0cftyp": "MP4",
}


def detect_filetype(data: bytes) -> str:
    for magic, ftype in MAGIC_BYTES.items():
        if data[:len(magic)] == magic:
            return ftype
    return "Unknown"


# ══════════════════════════════════════════════════════════════════════════════
# ENTROPY ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of the data (bits per byte)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    n = len(data)
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


def entropy_verdict(entropy: float) -> tuple[str, str]:
    """Interpret the entropy value."""
    if entropy > 7.9:
        return "VERY HIGH", "Data may be compressed or encrypted"
    if entropy > 7.0:
        return "HIGH", "High entropy — possible hidden or compressed content"
    if entropy > 6.0:
        return "MEDIUM", "Normal entropy for a compressed image"
    if entropy > 4.0:
        return "LOW", "Low entropy — simple image"
    return "VERY LOW", "Very low entropy — possible synthetic image"


# ══════════════════════════════════════════════════════════════════════════════
# PNG ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def analyze_png(data: bytes) -> tuple[dict, List[Finding]]:
    """Analyze PNG chunks — detect hidden chunks and metadata."""
    findings: List[Finding] = []
    metadata: dict = {}
    offset = 8  # skip PNG signature

    chunks = []
    standard_chunks = {b"IHDR", b"IDAT", b"IEND", b"PLTE", b"tRNS",
                       b"cHRM", b"gAMA", b"sRGB", b"bKGD", b"hIST",
                       b"tEXt", b"zTXt", b"iTXt", b"pHYs", b"sBIT",
                       b"sPLT", b"tIME"}

    while offset < len(data) - 8:
        try:
            chunk_len  = struct.unpack(">I", data[offset:offset+4])[0]
            chunk_type = data[offset+4:offset+8]
            chunk_data = data[offset+8:offset+8+chunk_len]
            chunk_crc  = data[offset+8+chunk_len:offset+12+chunk_len]

            # Verify CRC
            expected_crc = struct.pack(">I", zlib.crc32(chunk_type + chunk_data) & 0xffffffff)
            crc_ok = chunk_crc == expected_crc

            chunks.append({
                "type":   chunk_type.decode(errors="replace"),
                "length": chunk_len,
                "crc_ok": crc_ok,
            })

            # Text in tEXt/zTXt/iTXt chunks
            if chunk_type in (b"tEXt", b"zTXt", b"iTXt"):
                try:
                    text = chunk_data.decode(errors="replace")
                    metadata[f"PNG_{chunk_type.decode()}"] = text[:500]
                    findings.append(Finding(
                        "PNG Metadata", "INFO",
                        f"Chunk {chunk_type.decode()} contains embedded text",
                        text[:200],
                    ))
                except Exception:
                    pass

            # Non-standard chunk
            if chunk_type not in standard_chunks and chunk_type != b"IEND":
                findings.append(Finding(
                    "Unknown PNG Chunk", "HIGH",
                    f"Non-standard chunk: {chunk_type!r} ({chunk_len} bytes)",
                    "May contain hidden data",
                ))

            # Invalid CRC
            if not crc_ok and chunk_type != b"IEND":
                findings.append(Finding(
                    "PNG CRC Mismatch", "MEDIUM",
                    f"Invalid CRC in chunk {chunk_type.decode(errors='replace')}",
                    "Possible corruption or intentional manipulation",
                ))

            offset += 12 + chunk_len
            if chunk_type == b"IEND":
                break

        except struct.error:
            break

    # Data after IEND (appended data)
    iend_pos = data.rfind(b"IEND\xaeB`\x82")
    if iend_pos != -1:
        trailing = data[iend_pos + 8:]
        if trailing:
            ftype = detect_filetype(trailing)
            findings.append(Finding(
                "Trailing Data After IEND", "HIGH",
                f"{len(trailing)} bytes after the end of the PNG",
                f"Detected type: {ftype}" if ftype != "Unknown" else f"First bytes: {trailing[:16].hex()}",
                trailing,
            ))

    metadata["png_chunks"] = chunks
    return metadata, findings


# ══════════════════════════════════════════════════════════════════════════════
# JPEG ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def analyze_jpeg(data: bytes) -> tuple[dict, List[Finding]]:
    """Analyze JPEG segments and EXIF metadata."""
    findings: List[Finding] = []
    metadata: dict = {}

    # EXIF marker
    exif_pos = data.find(b"Exif\x00\x00")
    if exif_pos != -1:
        metadata["has_exif"] = True
        findings.append(Finding(
            "JPEG EXIF Metadata", "INFO",
            "EXIF metadata found",
            f"Offset: {exif_pos}",
        ))
        # Search for GPS data inside EXIF
        gps_pos = data.find(b"GPS", exif_pos, exif_pos + 4096)
        if gps_pos != -1:
            findings.append(Finding(
                "GPS Data in EXIF", "MEDIUM",
                "GPS coordinates may be present in the metadata",
                "Privacy risk — embedded geographic location",
            ))
    else:
        metadata["has_exif"] = False

    # Comment marker (0xFFFE)
    comment_pos = data.find(b"\xff\xfe")
    if comment_pos != -1:
        try:
            comment_len = struct.unpack(">H", data[comment_pos+2:comment_pos+4])[0]
            comment     = data[comment_pos+4:comment_pos+2+comment_len].decode(errors="replace")
            metadata["comment"] = comment
            findings.append(Finding(
                "JPEG Comment", "INFO",
                f"JPEG comment: {comment[:100]}",
            ))
        except Exception:
            pass

    # Data after EOI (0xFFD9)
    eoi_pos = data.rfind(b"\xff\xd9")
    if eoi_pos != -1:
        trailing = data[eoi_pos + 2:]
        if trailing:
            ftype = detect_filetype(trailing)
            findings.append(Finding(
                "Trailing Data After EOI", "HIGH",
                f"{len(trailing)} bytes after the end of the JPEG",
                f"Detected type: {ftype}",
                trailing,
            ))

    # Adobe / XMP markers
    xmp_pos = data.find(b"http://ns.adobe.com/xap/")
    if xmp_pos != -1:
        metadata["has_xmp"] = True
        findings.append(Finding("XMP Metadata", "INFO", "Adobe XMP metadata found"))

    return metadata, findings


# ══════════════════════════════════════════════════════════════════════════════
# STRING EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def extract_strings(data: bytes, min_len: int = 6) -> List[str]:
    """Extract ASCII/UTF-8 strings from the binary data."""
    strings  = []
    current  = []

    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                s = "".join(current)
                strings.append(s)
            current = []

    if len(current) >= min_len:
        strings.append("".join(current))

    # Deduplicate and sort by length
    seen  = set()
    dedup = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            dedup.append(s)

    return sorted(dedup, key=len, reverse=True)


def find_interesting_strings(strings: List[str]) -> List[Finding]:
    """Identify strings that may be relevant."""
    import re
    findings = []

    patterns = [
        (r"FLAG\{[^}]+\}",            "CTF Flag",          "HIGH"),
        (r"https?://[^\s]{10,}",       "URL",               "INFO"),
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email", "INFO"),
        (r"[A-Z0-9]{20,}",             "Possible Key/Token","MEDIUM"),
        (r"password|passwd|secret|key|token|api", "Sensitive keyword", "MEDIUM"),
        (r"-----BEGIN [A-Z ]+-----",   "PEM Key/Cert",      "HIGH"),
        (r"[a-f0-9]{32,}",             "Possible Hash",     "INFO"),
    ]

    for s in strings[:500]:  # limit to 500 strings
        for pattern, label, severity in patterns:
            if re.search(pattern, s, re.IGNORECASE):
                findings.append(Finding(
                    f"Interesting String — {label}", severity,
                    f"Suspicious string found: {s[:120]}",
                ))
                break

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# EMBEDDED FILE DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def find_embedded_files(data: bytes) -> List[Finding]:
    """Search for magic bytes from other formats inside the file."""
    findings = []
    search_from = 16  # ignore the main file header

    for magic, ftype in MAGIC_BYTES.items():
        pos = 0
        while True:
            pos = data.find(magic, max(pos, search_from))
            if pos == -1:
                break
            findings.append(Finding(
                "Embedded File Signature", "HIGH",
                f"{ftype} signature found at offset {pos} (0x{pos:x})",
                f"Magic bytes: {magic.hex()}",
                data[pos:pos+64],
            ))
            pos += len(magic)

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

def analyze(filepath: str, extract_dir: Optional[str] = None) -> StegReport:
    path = Path(filepath)
    if not path.exists():
        print(f"{C.RED}[ERROR] File not found: {filepath}{C.RESET}")
        sys.exit(1)

    data      = path.read_bytes()
    filetype  = detect_filetype(data)
    entropy   = shannon_entropy(data)
    findings: List[Finding] = []
    metadata: dict = {
        "filename": path.name,
        "filesize": len(data),
        "filetype": filetype,
        "md5":      __import__("hashlib").md5(data).hexdigest(),
        "sha256":   __import__("hashlib").sha256(data).hexdigest(),
        "entropy":  round(entropy, 4),
    }

    # Type-specific analysis
    if filetype == "PNG":
        meta, type_findings = analyze_png(data)
        metadata.update(meta)
        findings.extend(type_findings)
    elif filetype == "JPEG":
        meta, type_findings = analyze_jpeg(data)
        metadata.update(meta)
        findings.extend(type_findings)

    # Embedded files
    embed_findings = find_embedded_files(data)
    findings.extend(embed_findings)

    # Strings
    strings = extract_strings(data)
    str_findings = find_interesting_strings(strings)
    findings.extend(str_findings)

    # Entropy
    e_level, e_desc = entropy_verdict(entropy)
    if e_level in ("VERY HIGH",):
        findings.append(Finding(
            "High Entropy", "MEDIUM",
            f"Entropia: {entropy:.4f}/8.0 — {e_desc}",
        ))

    # Extract embedded files if requested
    if extract_dir and embed_findings:
        os.makedirs(extract_dir, exist_ok=True)
        for i, f in enumerate(embed_findings):
            if f.data:
                out = Path(extract_dir) / f"extracted_{i:02d}.bin"
                out.write_bytes(f.data)
                print(f"{C.GREEN}[✓] Extracted: {out}{C.RESET}")

    # Risk score
    severity_weights = {"HIGH": 30, "MEDIUM": 10, "LOW": 5, "INFO": 1}
    risk = sum(severity_weights.get(f.severity, 0) for f in findings)

    return StegReport(
        filepath   = str(path),
        filesize   = len(data),
        filetype   = filetype,
        findings   = findings,
        metadata   = metadata,
        strings    = strings[:50],
        entropy    = entropy,
        risk_score = risk,
    )


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEVERITY_COLOURS = {
    "HIGH":   C.RED,
    "MEDIUM": C.YELLOW,
    "LOW":    C.GREEN,
    "INFO":   C.DIM,
}

BANNER = f"""
{C.CYAN}{C.BOLD}  ███████╗████████╗███████╗ ██████╗
  ██╔════╝╚══██╔══╝██╔════╝██╔════╝
  ███████╗   ██║   █████╗  ██║  ███╗
  ╚════██║   ██║   ██╔══╝  ██║   ██║
  ███████║   ██║   ███████╗╚██████╔╝
  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝{C.RESET}
{C.DIM}  v{__version__} — Steganalysis Tool | PNG · JPEG · Embedded Files · Strings{C.RESET}
"""


def print_report(report: StegReport, verbose: bool = False) -> None:
    SEP = "━" * 68
    print(f"\n{'═'*68}")
    print(f"  {C.BOLD}STEGANALYSIS REPORT{C.RESET}")
    print(f"{'═'*68}")
    print(f"  File      : {report.filepath}")
    print(f"  Type      : {report.filetype}")
    print(f"  Size      : {report.filesize:,} bytes")
    print(f"  Entropy   : {report.entropy:.4f}/8.0")
    print(f"  MD5       : {report.metadata.get('md5', '—')}")
    print(f"  SHA-256   : {report.metadata.get('sha256', '—')}")
    print(f"{'═'*68}")

    score_col = C.RED if report.risk_score > 50 else C.YELLOW if report.risk_score > 20 else C.GREEN
    print(f"  Risk Score: {score_col}{C.BOLD}{report.risk_score}{C.RESET}  |  "
          f"Findings: {len(report.findings)}")

    if not report.findings:
        print(f"\n  {C.GREEN}✅ No suspicious indicators found.{C.RESET}")
        return

    print(f"\n  {C.BOLD}Findings:{C.RESET}")
    for f in sorted(report.findings, key=lambda x: ["HIGH","MEDIUM","LOW","INFO"].index(x.severity)):
        col = SEVERITY_COLOURS.get(f.severity, "")
        print(f"\n  {col}[{f.severity}]{C.RESET} {f.category}")
        print(f"    {f.description}")
        if f.detail and verbose:
            print(f"    {C.DIM}{f.detail}{C.RESET}")

    if verbose and report.strings:
        print(f"\n  {C.BOLD}Notable Strings (top 10):{C.RESET}")
        for s in report.strings[:10]:
            print(f"    {C.DIM}{s[:100]}{C.RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="steganalysis",
        description="Steganalysis Tool — Detection of hidden data in files"
    )
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-v", "--verbose",   action="store_true")
    parser.add_argument("-e", "--extract",   metavar="DIR", help="Extract embedded files to DIR")
    parser.add_argument("-s", "--strings",   action="store_true", help="Show extracted strings")
    parser.add_argument("--json",            action="store_true", dest="json_out")
    parser.add_argument("--no-banner",       action="store_true")
    parser.add_argument("--version",         action="version", version=f"steganalysis {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    report = analyze(args.file, extract_dir=args.extract)

    if args.json_out:
        out = {
            "filepath":   report.filepath,
            "filetype":   report.filetype,
            "filesize":   report.filesize,
            "entropy":    report.entropy,
            "risk_score": report.risk_score,
            "metadata":   {k: v for k, v in report.metadata.items() if k != "png_chunks"},
            "findings":   [{"category": f.category, "severity": f.severity,
                            "description": f.description} for f in report.findings],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_report(report, verbose=args.verbose)
        if args.strings:
            print(f"\n  {C.BOLD}Extracted Strings (top 20):{C.RESET}")
            for s in report.strings[:20]:
                print(f"    {C.DIM}{s[:120]}{C.RESET}")


if __name__ == "__main__":
    main()

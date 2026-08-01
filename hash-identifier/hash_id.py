#!/usr/bin/env python3
"""
hash_id.py — Hash Identifier & Analyzer v1.0.0
================================================
Identifies hash types by pattern/length and analyzes their properties.
Useful for CTFs, digital forensics, and compromised credential analysis.

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 15/08/2024
Req.   : Python 3.8+ | Zero external dependencies
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

__version__ = "1.0.0"


# ══════════════════════════════════════════════════════════════════════════════
# ANSI
# ══════════════════════════════════════════════════════════════════════════════

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


# ══════════════════════════════════════════════════════════════════════════════
# HASH DATABASE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class HashType:
    name:        str
    length:      Optional[int]      # None = variable
    regex:       Optional[str]      # additional pattern beyond length
    hashcat_mode: Optional[int]
    john_format: Optional[str]
    crackable:   bool               # whether it appears in rainbow-table databases
    notes:       str


HASH_DB: list[HashType] = [
    # MD5 family
    HashType("MD5",              32,  r"^[a-f0-9]{32}$",          0,    "raw-md5",    True,  "Cryptographically broken — CWE-327"),
    HashType("MD4",              32,  r"^[a-f0-9]{32}$",          900,  "raw-md4",    True,  "Obsolete, used in NTLM"),
    HashType("MD5 (WordPress)",  34,  r"^\$P\$[a-zA-Z0-9./]{31}$", 400, "phpass",     True,  "PHPass with salt"),
    HashType("MD5 (phpBB3)",     34,  r"^\$H\$[a-zA-Z0-9./]{31}$", 400, "phpass",     True,  "PHPass with salt"),

    # SHA family
    HashType("SHA-1",            40,  r"^[a-f0-9]{40}$",          100,  "raw-sha1",   True,  "Cryptographically weak since 2005"),
    HashType("SHA-224",          56,  r"^[a-f0-9]{56}$",          1300, None,          False, "SHA-2 — acceptable"),
    HashType("SHA-256",          64,  r"^[a-f0-9]{64}$",          1400, "raw-sha256", False, "SHA-2 — recommended"),
    HashType("SHA-384",          96,  r"^[a-f0-9]{96}$",          10800,None,          False, "SHA-2 — strong"),
    HashType("SHA-512",          128, r"^[a-f0-9]{128}$",         1700, "raw-sha512", False, "SHA-2 — strong"),
    HashType("SHA3-256",         64,  r"^[a-f0-9]{64}$",          17300,None,          False, "SHA-3 — resistant to length-extension attacks"),
    HashType("SHA3-512",         128, r"^[a-f0-9]{128}$",         17500,None,          False, "SHA-3 — very strong"),

    # Windows
    HashType("NTLM",             32,  r"^[a-f0-9]{32}$",          1000, "nt",         True,  "Windows NT hash — unsalted, rainbow tables available"),
    HashType("LM",               32,  r"^[a-f0-9]{32}$",          3000, "lm",         True,  "Windows LAN Manager — extremely weak"),
    HashType("NetNTLMv1",        None,r"^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]{16}$",
                                                                   5500, "netntlm",   True,  "Captured via Responder — relay attacks"),
    HashType("NetNTLMv2",        None,r"^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$",
                                                                   5600, "netntlmv2", True,  "More secure than v1 but still crackable"),

    # Unix/Linux
    HashType("bcrypt",           60,  r"^\$2[aby]\$\d{2}\$[a-zA-Z0-9./]{53}$",
                                                                   3200, "bcrypt",    False, "Recommended for passwords — adaptive cost"),
    HashType("SHA-512 (crypt)",  None,r"^\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}$",
                                                                   1800, "sha512crypt",False,"Linux /etc/shadow — uses salt"),
    HashType("SHA-256 (crypt)",  None,r"^\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}$",
                                                                   7400, "sha256crypt",False,"Linux /etc/shadow — uses salt"),
    HashType("MD5 (crypt)",      None,r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$",
                                                                   500,  "md5crypt",  True,  "Linux legacy — weak"),
    HashType("DES (crypt)",      13,  r"^[a-zA-Z0-9./]{13}$",     1500, "descrypt",  True,  "Very old — do not use"),

    # Web / Frameworks
    HashType("MySQL 3.x",        16,  r"^[a-f0-9]{16}$",          200,  "mysql",     True,  "Legacy MySQL — simple XOR"),
    HashType("MySQL 4.1+",       40,  r"^\*[A-F0-9]{40}$",        300,  "mysql-sha1",True,  "Modern MySQL — double SHA-1"),
    HashType("Django (SHA-256)", None,r"^sha256\$[a-zA-Z0-9]+\$[a-f0-9]{64}$",
                                                                   None, None,        False, "Django password hasher"),
    HashType("Django (bcrypt)",  None,r"^bcrypt\$\$2[aby]\$",      None, None,        False, "Django with bcrypt"),

    # BLAKE
    HashType("BLAKE2b-256",      64,  r"^[a-f0-9]{64}$",          600,  None,        False, "Fast and secure — SHA-3 alternative"),
    HashType("BLAKE2b-512",      128, r"^[a-f0-9]{128}$",         None, None,        False, "Full BLAKE2b"),

    # Other types commonly seen in CTFs
    HashType("CRC32",            8,   r"^[a-f0-9]{8}$",           11500,None,        True,  "Checksum — not a cryptographic hash function"),
    HashType("Whirlpool",        128, r"^[a-f0-9]{128}$",         6100, "whirlpool", False, "ISO/IEC 10118-3"),
    HashType("RIPEMD-160",       40,  r"^[a-f0-9]{40}$",          6000, "ripemd-160",False, "SHA-1 alternative — more secure"),
    HashType("Keccak-256",       64,  r"^[a-f0-9]{64}$",          17800,None,        False, "SHA-3 predecessor — different from standard SHA3-256"),
]


# ══════════════════════════════════════════════════════════════════════════════
# IDENTIFICATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def is_hex(s: str) -> bool:
    return bool(re.match(r"^[a-fA-F0-9]+$", s))


def identify(hash_str: str) -> list[HashType]:
    """Return possible hash types ordered by likelihood."""
    h       = hash_str.strip()
    length  = len(h)
    matches = []

    for ht in HASH_DB:
        if ht.regex and re.match(ht.regex, h, re.IGNORECASE):
            matches.append(ht)
        elif ht.regex is None and ht.length == length and is_hex(h):
            matches.append(ht)

    # Deduplicate by name
    seen  = set()
    dedup = []
    for m in matches:
        if m.name not in seen:
            seen.add(m.name)
            dedup.append(m)

    return dedup


def analyze_properties(hash_str: str) -> dict:
    h      = hash_str.strip()
    length = len(h)

    props = {
        "length":       length,
        "is_hex":       is_hex(h),
        "is_base64":    bool(re.match(r"^[A-Za-z0-9+/]+=*$", h)) and length % 4 == 0,
        "has_prefix":   h.startswith("$"),
        "prefix":       h[:3] if h.startswith("$") else None,
        "charset":      _detect_charset(h),
        "entropy_bits": length * 4 if is_hex(h) else length * 6,
    }
    return props


def _detect_charset(h: str) -> str:
    if re.match(r"^[0-9]+$", h):            return "numeric"
    if re.match(r"^[a-f0-9]+$", h, re.I):  return "hexadecimal"
    if re.match(r"^[a-z0-9]+$", h):        return "alphanumeric-lower"
    if re.match(r"^[A-Z0-9]+$", h):        return "alphanumeric-upper"
    if re.match(r"^[A-Za-z0-9]+$", h):     return "alphanumeric-mixed"
    if re.match(r"^[A-Za-z0-9+/=]+$", h):  return "base64"
    return "mixed"


# ══════════════════════════════════════════════════════════════════════════════
# HASH GENERATION
# ══════════════════════════════════════════════════════════════════════════════

SUPPORTED_ALGOS = {
    "md5":       hashlib.md5,
    "sha1":      hashlib.sha1,
    "sha224":    hashlib.sha224,
    "sha256":    hashlib.sha256,
    "sha384":    hashlib.sha384,
    "sha512":    hashlib.sha512,
    "sha3_256":  hashlib.sha3_256,
    "sha3_512":  hashlib.sha3_512,
    "blake2b":   lambda: hashlib.new("blake2b"),
    "blake2s":   lambda: hashlib.new("blake2s"),
}


def generate_hash(text: str, algo: str) -> Optional[str]:
    algo = algo.lower().replace("-", "_")
    if algo not in SUPPORTED_ALGOS:
        return None
    try:
        h = SUPPORTED_ALGOS[algo]()
        h.update(text.encode("utf-8"))
        return h.hexdigest()
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

BANNER = f"""
{C.CYAN}{C.BOLD}  ██╗  ██╗ █████╗ ███████╗██╗  ██╗    ██╗██████╗
  ██║  ██║██╔══██╗██╔════╝██║  ██║    ██║██╔══██╗
  ███████║███████║███████╗███████║    ██║██║  ██║
  ██╔══██║██╔══██║╚════██║██╔══██║    ██║██║  ██║
  ██║  ██║██║  ██║███████║██║  ██║    ██║██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝╚═════╝{C.RESET}
{C.DIM}  v{__version__} — Hash Identifier & Analyzer | CTF · Forensics · Blue Team{C.RESET}
"""


def print_identification(hash_str: str, matches: list[HashType],
                         props: dict, verbose: bool) -> None:
    h = hash_str.strip()
    print(f"\n{'━'*68}")
    print(f"  {C.BOLD}Hash:{C.RESET} {C.CYAN}{h[:80]}{'...' if len(h) > 80 else ''}{C.RESET}")
    print(f"  {C.DIM}Length: {props['length']} chars | Charset: {props['charset']} | "
          f"Estimated entropy: ~{props['entropy_bits']} bits{C.RESET}")

    if props["has_prefix"]:
        print(f"  {C.DIM}Prefix: {props['prefix']}...{C.RESET}")

    if not matches:
        print(f"\n  {C.YELLOW}⚠ Hash type not identified in the database.{C.RESET}")
        print(f"  {C.DIM}Length {props['length']} does not match a known pattern.{C.RESET}")
        return

    print(f"\n  {C.BOLD}Possible Types:{C.RESET}")
    for i, ht in enumerate(matches):
        crack_icon = f"{C.RED}🔓 Crackable{C.RESET}" if ht.crackable else f"{C.GREEN}🔒 Resistant{C.RESET}"
        print(f"\n  {C.BOLD}[{i+1}] {ht.name}{C.RESET}  {crack_icon}")
        print(f"      {C.DIM}Notes:   {C.RESET}{ht.notes}")
        if ht.hashcat_mode is not None:
            print(f"      {C.DIM}Hashcat: {C.RESET}-m {ht.hashcat_mode}")
        if ht.john_format:
            print(f"      {C.DIM}John:    {C.RESET}--format={ht.john_format}")

    if verbose:
        print(f"\n  {C.BOLD}Properties:{C.RESET}")
        for k, v in props.items():
            print(f"    {k:<20}: {v}")


def print_generation(text: str, algos: list[str]) -> None:
    print(f"\n  {C.BOLD}Hashes for: {C.CYAN}\"{text}\"{C.RESET}")
    print(f"  {'─'*60}")
    for algo in algos:
        result = generate_hash(text, algo)
        if result:
            print(f"  {C.DIM}{algo.upper():<12}{C.RESET} {result}")
        else:
            print(f"  {C.DIM}{algo.upper():<12}{C.RESET} {C.RED}Unsupported{C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hash-id",
        description="Hash Identifier & Analyzer — CTF · Forensics · Blue Team"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Subcommand: identify
    id_p = sub.add_parser("identify", aliases=["id"],
                           help="Identify hash type")
    id_p.add_argument("hash", nargs="?", help="Hash to identify")
    id_p.add_argument("-f", "--file", help="File containing hashes (one per line)")
    id_p.add_argument("-v", "--verbose", action="store_true")
    id_p.add_argument("--json", action="store_true", dest="json_out")

    # Subcommand: generate
    gen_p = sub.add_parser("generate", aliases=["gen"],
                            help="Generate hashes from text")
    gen_p.add_argument("text", help="Text to hash")
    gen_p.add_argument("-a", "--algo", nargs="+",
                       default=["md5", "sha1", "sha256", "sha512"],
                       help="Algorithms (default: md5 sha1 sha256 sha512)")

    # Subcommand: list
    sub.add_parser("list", help="List all supported hash types")

    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version=f"hash-id {__version__}")

    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    cmd = args.command if args.command else ""

    if cmd in ("identify", "id"):
        hashes = []
        if args.hash:
            hashes = [args.hash]
        elif args.file:
            hashes = [l.strip() for l in open(args.file) if l.strip()]
        else:
            print("  Enter a hash (Ctrl+D to finish):")
            try:
                while True:
                    h = input("  > ").strip()
                    if h:
                        hashes.append(h)
            except EOFError:
                pass

        results = []
        for h in hashes:
            matches = identify(h)
            props   = analyze_properties(h)
            if args.json_out:
                results.append({
                    "hash":    h,
                    "matches": [m.name for m in matches],
                    "props":   props,
                })
            else:
                print_identification(h, matches, props, args.verbose)

        if args.json_out:
            print(json.dumps(results, indent=2))

    elif cmd in ("generate", "gen"):
        print_generation(args.text, args.algo)

    elif cmd == "list":
        print(f"\n  {'Name':<25} {'Len':>5}  {'Hashcat':>8}  {'John':<15}  Notes")
        print(f"  {'─'*90}")
        for ht in sorted(HASH_DB, key=lambda h: h.name):
            length   = str(ht.length) if ht.length else "var"
            hc_mode  = str(ht.hashcat_mode) if ht.hashcat_mode is not None else "—"
            jf       = ht.john_format or "—"
            crack    = "🔓" if ht.crackable else "🔒"
            print(f"  {crack} {ht.name:<23} {length:>5}  {hc_mode:>8}  {jf:<15}  {ht.notes[:40]}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
password_analyzer.py — Password Strength Analyzer v1.0.0
==========================================================
Analyzes password strength and generates custom wordlists for security
testing on authorized systems (audits, CTFs, penetration tests).

Author : Márcio Coutinho — Cybersecurity Specialist
Date   : 03/04/2025
Req.   : Python 3.8+ | Zero external dependencies
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import re
import string
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

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
# COMMON PATTERNS DATABASE
# ══════════════════════════════════════════════════════════════════════════════

# Most common passwords — top 50 from public lists (HaveIBeenPwned, RockYou)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "111111",
    "1234567", "sunshine", "qwerty", "iloveyou", "princess", "admin",
    "welcome", "666666", "abc123", "football", "123123", "monkey",
    "654321", "superman", "1qaz2wsx", "master", "login", "hello",
    "dragon", "passw0rd", "shadow", "master", "michael", "jessica",
    "password1", "ashley", "bailey", "baseball", "batman", "charlie",
    "donald", "freedom", "george", "harley", "hunter", "jordan",
    "letmein", "mustang", "password123", "robert", "soccer", "thomas",
}

KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
    "1qaz2wsx", "qazwsx", "1234qwer", "qwer1234",
]

LEET_MAP = {
    "a": ["4", "@"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"],
    "b": ["8"],
    "g": ["9"],
    "l": ["1"],
}

COMMON_SUFFIXES = [
    "123", "1234", "12345", "!", "!!", "1", "2", ".", "#",
    "2024", "2023", "2022", "2021", "2020", "01", "123!",
]

COMMON_PREFIXES = [
    "!", "1", "The", "the", "My", "my",
]


# ══════════════════════════════════════════════════════════════════════════════
# STRENGTH ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PasswordAnalysis:
    password:         str
    length:           int
    score:            int          # 0–100
    strength:         str          # VERY WEAK / WEAK / FAIR / STRONG / VERY STRONG
    entropy_bits:     float
    charset_size:     int
    issues:           List[str]    = field(default_factory=list)
    suggestions:      List[str]    = field(default_factory=list)
    crack_time_est:   str          = ""
    is_common:        bool         = False
    has_keyboard_walk: bool        = False
    has_leet:         bool         = False
    patterns_found:   List[str]    = field(default_factory=list)


def calculate_charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):     size += 26
    if re.search(r"[A-Z]", password):     size += 26
    if re.search(r"[0-9]", password):     size += 10
    if re.search(r"[^a-zA-Z0-9]", password): size += 32
    return max(size, 1)


def calculate_entropy(password: str) -> float:
    charset_size = calculate_charset_size(password)
    return len(password) * math.log2(charset_size)


def estimate_crack_time(entropy_bits: float) -> str:
    """Estimate offline cracking time (modern GPU — 10B hashes/sec)."""
    combinations = 2 ** entropy_bits
    hashes_per_sec = 10_000_000_000  # 10 GH/s (hashcat, RTX 4090, MD5)
    seconds = combinations / hashes_per_sec

    if seconds < 1:          return "Instant"
    if seconds < 60:         return f"{seconds:.0f} seconds"
    if seconds < 3600:       return f"{seconds/60:.0f} minutes"
    if seconds < 86400:      return f"{seconds/3600:.1f} hours"
    if seconds < 2592000:    return f"{seconds/86400:.0f} days"
    if seconds < 31536000:   return f"{seconds/2592000:.0f} months"
    if seconds < 3153600000: return f"{seconds/31536000:.0f} years"
    return f"{seconds/31536000:.2e} years (practically unbreakable)"


def analyze_password(password: str) -> PasswordAnalysis:
    issues      = []
    suggestions = []
    patterns    = []
    score       = 0
    pw_lower    = password.lower()

    # Length
    length = len(password)
    if length < 8:
        issues.append("Too short (< 8 characters)")
    elif length < 12:
        score += 15
        suggestions.append("Increase to at least 12 characters")
    elif length < 16:
        score += 25
    else:
        score += 35

    # Character diversity
    has_lower   = bool(re.search(r"[a-z]",       password))
    has_upper   = bool(re.search(r"[A-Z]",       password))
    has_digit   = bool(re.search(r"[0-9]",       password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    diversity = sum([has_lower, has_upper, has_digit, has_special])
    score += diversity * 10

    if not has_upper:
        issues.append("No uppercase letters")
        suggestions.append("Add uppercase letters")
    if not has_digit:
        issues.append("No digits")
        suggestions.append("Add numbers")
    if not has_special:
        issues.append("No special characters")
        suggestions.append("Add symbols (!@#$%)")

    # Common password
    is_common = pw_lower in COMMON_PASSWORDS
    if is_common:
        issues.append("Password appears in common-password lists (RockYou/HIBP)")
        score = max(score - 40, 0)
        patterns.append("COMMON_PASSWORD")

    # Keyboard walk
    has_kw = any(walk in pw_lower for walk in KEYBOARD_WALKS)
    if has_kw:
        issues.append("Keyboard sequence detected (e.g., qwerty, 1qaz)")
        score = max(score - 20, 0)
        patterns.append("KEYBOARD_WALK")

    # Repetitive patterns
    if re.search(r"(.)\1{2,}", password):
        issues.append("Repeated characters (e.g., aaa, 111)")
        score = max(score - 10, 0)
        patterns.append("REPEATED_CHARS")

    # Numeric sequences
    if re.search(r"(012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210)", password):
        issues.append("Simple numeric sequence")
        score = max(score - 10, 0)
        patterns.append("NUMERIC_SEQUENCE")

    # Leet speak
    has_leet = any(
        any(l in password.lower() for l in leets)
        for char, leets in LEET_MAP.items()
        if char in pw_lower
    )
    if has_leet:
        patterns.append("LEET_SUBSTITUTION")
        suggestions.append("Leet speak is easily detected by modern password crackers")

    # Numeric suffix only
    if re.match(r"^[a-zA-Z]+[0-9]{1,4}[!.#]?$", password):
        issues.append("Word + number pattern (e.g., password123) — very common")
        score = max(score - 15, 0)
        patterns.append("WORD_PLUS_NUMBER")

    # Entropy
    entropy = calculate_entropy(password)
    if entropy < 28:
        score = max(score - 20, 0)
    elif entropy > 60:
        score += 15

    score = min(max(score, 0), 100)

    # Strength label
    if score < 20:      strength = "VERY WEAK"
    elif score < 40:    strength = "WEAK"
    elif score < 60:    strength = "FAIR"
    elif score < 80:    strength = "STRONG"
    else:               strength = "VERY STRONG"

    crack_time = estimate_crack_time(entropy)

    return PasswordAnalysis(
        password          = "•" * len(password),   # never display in plain text
        length            = length,
        score             = score,
        strength          = strength,
        entropy_bits      = round(entropy, 2),
        charset_size      = calculate_charset_size(password),
        issues            = issues,
        suggestions       = suggestions,
        crack_time_est    = crack_time,
        is_common         = is_common,
        has_keyboard_walk = has_kw,
        has_leet          = has_leet,
        patterns_found    = patterns,
    )


# ══════════════════════════════════════════════════════════════════════════════
# WORDLIST GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_wordlist(words: List[str], output_file: str,
                      max_words: int = 10000) -> int:
    """
    Generates a custom wordlist using variations of the supplied words.
    Useful for authorized security audits and CTF environments.
    """
    generated = set()

    for word in words:
        w = word.strip()
        if not w:
            continue

        # Base variants
        generated.add(w)
        generated.add(w.lower())
        generated.add(w.upper())
        generated.add(w.capitalize())

        # With common suffixes
        for suffix in COMMON_SUFFIXES:
            generated.add(w + suffix)
            generated.add(w.lower() + suffix)
            generated.add(w.capitalize() + suffix)

        # With common prefixes
        for prefix in COMMON_PREFIXES:
            generated.add(prefix + w)

        # Leet speak (level 1)
        leet_word = w.lower()
        for char, replacements in LEET_MAP.items():
            leet_word = leet_word.replace(char, replacements[0])
        generated.add(leet_word)
        generated.add(leet_word.capitalize())
        generated.add(leet_word + "!")
        generated.add(leet_word + "123")

        # Reversal
        generated.add(w[::-1])
        generated.add(w.lower()[::-1])

        # Two-word combinations
        if len(words) > 1:
            for w2 in words[:5]:
                if w2 != w:
                    generated.add(w.capitalize() + w2.capitalize())
                    generated.add(w.lower() + w2.lower())
                    generated.add(w + "_" + w2)

        if len(generated) >= max_words:
            break

    # Write to file
    with open(output_file, "w", encoding="utf-8") as f:
        for word in sorted(generated)[:max_words]:
            f.write(word + "\n")

    return min(len(generated), max_words)


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

BANNER = f"""
{C.CYAN}{C.BOLD}  ██████╗  █████╗ ███████╗███████╗██╗    ██╗██████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔══██╗
  ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║  ██║
  ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║  ██║
  ██║     ██║  ██║███████║███████║╚███╔███╔╝██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝ ╚═════╝{C.RESET}
{C.DIM}  v{__version__} — Password Strength Analyzer | Wordlist Generator | CTF / Audit{C.RESET}
"""

STRENGTH_COLOURS = {
    "VERY WEAK": C.RED,
    "WEAK":       C.RED,
    "FAIR":       C.YELLOW,
    "STRONG":     C.GREEN,
    "VERY STRONG": C.GREEN,
}


def print_analysis(analysis: PasswordAnalysis) -> None:
    col  = STRENGTH_COLOURS.get(analysis.strength, "")
    bar_len = analysis.score // 5
    bar  = "█" * bar_len + "░" * (20 - bar_len)

    print(f"\n{'━'*60}")
    print(f"  {C.BOLD}Password Analysis{C.RESET}")
    print(f"{'━'*60}")
    print(f"  Length        : {analysis.length} characters")
    print(f"  Charset size  : {analysis.charset_size} possible symbols")
    print(f"  Entropy       : {analysis.entropy_bits:.1f} bits")
    print(f"  Strength      : {col}{C.BOLD}{analysis.strength}{C.RESET}")
    print(f"  Score         : {col}{analysis.score}/100{C.RESET}  [{bar}]")
    print(f"  Crack time    : {C.YELLOW}{analysis.crack_time_est}{C.RESET}")
    print(f"{'─'*60}")

    if analysis.issues:
        print(f"  {C.RED}Issues:{C.RESET}")
        for issue in analysis.issues:
            print(f"    ✗ {issue}")

    if analysis.suggestions:
        print(f"  {C.YELLOW}Suggestions:{C.RESET}")
        for sug in analysis.suggestions:
            print(f"    → {sug}")

    if analysis.patterns_found:
        print(f"  {C.DIM}Patterns detected: {', '.join(analysis.patterns_found)}{C.RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="password-analyzer",
        description="Password Strength Analyzer & Wordlist Generator"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Subcommand: analyze
    a = sub.add_parser("analyze", aliases=["a"], help="Analyze password strength")
    a.add_argument("password", nargs="?", help="Password (omit to use a secure prompt)")
    a.add_argument("--json", action="store_true", dest="json_out")

    # Subcommand: wordlist
    w = sub.add_parser("wordlist", aliases=["wl"], help="Generate a custom wordlist")
    w.add_argument("words", nargs="+", help="Base words (e.g., name company year)")
    w.add_argument("-o", "--output", default="wordlist.txt", help="Output file")
    w.add_argument("--max", type=int, default=10000, dest="max_words")

    # Subcommand: batch
    b = sub.add_parser("batch", help="Analyze multiple passwords from a file")
    b.add_argument("file", help="File containing passwords (one per line)")
    b.add_argument("--json", action="store_true", dest="json_out")

    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version=f"password-analyzer {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    cmd = args.command

    if cmd in ("analyze", "a"):
        if args.password:
            pw = args.password
        else:
            import getpass
            pw = getpass.getpass("  Password (hidden): ")

        result = analyze_password(pw)

        if args.json_out:
            d = {k: v for k, v in result.__dict__.items()
                 if k != "password"}
            print(json.dumps(d, indent=2, ensure_ascii=False))
        else:
            print_analysis(result)

    elif cmd in ("wordlist", "wl"):
        print(f"  {C.DIM}Generating wordlist from: {', '.join(args.words)}{C.RESET}")
        count = generate_wordlist(args.words, args.output, args.max_words)
        print(f"  {C.GREEN}✅ {count} words generated → {args.output}{C.RESET}")
        print(f"  {C.DIM}⚠ Use only on authorized systems (audits, CTFs){C.RESET}")

    elif cmd == "batch":
        passwords = [l.strip() for l in open(args.file) if l.strip()]
        results   = []
        weak_count = 0

        for pw in passwords:
            r = analyze_password(pw)
            results.append(r)
            if r.score < 40:
                weak_count += 1

        if args.json_out:
            out = [{"score": r.score, "strength": r.strength,
                    "entropy": r.entropy_bits, "patterns": r.patterns_found}
                   for r in results]
            print(json.dumps(out, indent=2))
        else:
            print(f"\n  {C.BOLD}Batch Analysis — {len(results)} passwords{C.RESET}")
            print(f"  Weak (score < 40): {C.RED}{weak_count}{C.RESET}/{len(results)}")
            for r in results:
                col = STRENGTH_COLOURS.get(r.strength, "")
                print(f"  {col}{r.strength:<12}{C.RESET} score={r.score:>3} "
                      f"entropy={r.entropy_bits:>6.1f}b  {', '.join(r.patterns_found) or '—'}")


if __name__ == "__main__":
    main()

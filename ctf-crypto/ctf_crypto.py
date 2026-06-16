#!/usr/bin/env python3
"""
ctf_crypto.py — CTF Crypto Toolkit v1.0.0
==========================================
Encoder, decoder, and lightweight cryptanalysis toolkit for CTF challenges
and digital forensics training.

It covers classical ciphers, common encodings, frequency analysis, and XOR
operations. Built for authorized labs, competitions, and educational use.

Author  : Marcio Coutinho — Cybersecurity Specialist
Date    : 26/11/2023
Requires: Python 3.8+ | Zero external dependencies
"""

from __future__ import annotations

import argparse
import base64
import collections
import json
import string
import sys
from typing import Any, Dict, List, Tuple

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
{C.CYAN}{C.BOLD}  ██████╗████████╗███████╗     ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗
 ██╔════╝╚══██╔══╝██╔════╝    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
 ██║        ██║   █████╗      ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
 ██║        ██║   ██╔══╝      ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
 ╚██████╗   ██║   ██║         ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝
  ╚═════╝   ╚═╝   ╚═╝          ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝{C.RESET}
{C.DIM} v{__version__} — CTF Crypto Toolkit | Caesar · Vigenere · XOR · Base* · Frequency Analysis{C.RESET}
"""

SEP = "━" * 68

# English letter frequency reference table.
ENGLISH_FREQ = {
    "e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0, "n": 6.7,
    "s": 6.3, "h": 6.1, "r": 6.0, "d": 4.3, "l": 4.0, "c": 2.8,
    "u": 2.8, "m": 2.4, "w": 2.4, "f": 2.2, "g": 2.0, "y": 2.0,
    "p": 1.9, "b": 1.5, "v": 1.0, "k": 0.8, "j": 0.2, "x": 0.2,
    "q": 0.1, "z": 0.1,
}


# ══════════════════════════════════════════════════════════════════════════════
# ENCODINGS
# ══════════════════════════════════════════════════════════════════════════════

def _pad_base64(text: str) -> str:
    return text + "=" * ((4 - len(text) % 4) % 4)


def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def b64_decode(text: str) -> str:
    try:
        return base64.b64decode(_pad_base64(text)).decode(errors="replace")
    except Exception as exc:
        return f"[ERROR] {exc}"


def b32_encode(text: str) -> str:
    return base64.b32encode(text.encode()).decode()


def b32_decode(text: str) -> str:
    try:
        padded = text + "=" * ((8 - len(text) % 8) % 8)
        return base64.b32decode(padded.upper()).decode(errors="replace")
    except Exception as exc:
        return f"[ERROR] {exc}"


def b16_encode(text: str) -> str:
    return text.encode().hex().upper()


def b16_decode(text: str) -> str:
    try:
        return bytes.fromhex(text.replace(" ", "")).decode(errors="replace")
    except Exception as exc:
        return f"[ERROR] {exc}"


def url_encode(text: str) -> str:
    safe = string.ascii_letters + string.digits + "-._~"
    result = ""
    for char in text:
        if char in safe:
            result += char
        else:
            result += "%" + format(ord(char), "02X")
    return result


def url_decode(text: str) -> str:
    result = ""
    i = 0
    while i < len(text):
        if text[i] == "%" and i + 2 < len(text):
            try:
                result += chr(int(text[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        result += text[i]
        i += 1
    return result


def html_encode(text: str) -> str:
    replacements = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def html_decode(text: str) -> str:
    replacements = {"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#x27;": "'", "&apos;": "'"}
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def to_binary(text: str) -> str:
    return " ".join(format(ord(char), "08b") for char in text)


def from_binary(text: str) -> str:
    bits = text.replace(" ", "")
    if len(bits) % 8 != 0:
        return "[ERROR] Binary input length must be a multiple of 8 bits"
    try:
        return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8))
    except Exception as exc:
        return f"[ERROR] {exc}"


def to_octal(text: str) -> str:
    return " ".join(format(ord(char), "o") for char in text)


def from_octal(text: str) -> str:
    try:
        return "".join(chr(int(item, 8)) for item in text.split())
    except Exception as exc:
        return f"[ERROR] {exc}"


def to_decimal(text: str) -> str:
    return " ".join(str(ord(char)) for char in text)


def from_decimal(text: str) -> str:
    try:
        return "".join(chr(int(item)) for item in text.split())
    except Exception as exc:
        return f"[ERROR] {exc}"


def rot13(text: str) -> str:
    result = ""
    for char in text:
        if "a" <= char <= "z":
            result += chr((ord(char) - ord("a") + 13) % 26 + ord("a"))
        elif "A" <= char <= "Z":
            result += chr((ord(char) - ord("A") + 13) % 26 + ord("A"))
        else:
            result += char
    return result


def morse_encode(text: str) -> str:
    morse = {
        "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
        "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
        "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
        "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
        "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
        "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
        "8": "---..", "9": "----.", " ": "/", ".": ".-.-.-", ",": "--..--",
        "?": "..--..", "!": "-.-.--",
    }
    return " ".join(morse.get(char.upper(), "?") for char in text)


def morse_decode(text: str) -> str:
    morse_rev = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
        "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
        "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
        "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
        "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
        "---..": "8", "----.": "9", "/": " ", ".-.-.-": ".", "--..--": ",",
        "..--..": "?", "-.-.--": "!",
    }
    return "".join(morse_rev.get(token, "?") for token in text.split())


# ══════════════════════════════════════════════════════════════════════════════
# CLASSICAL CIPHERS
# ══════════════════════════════════════════════════════════════════════════════

def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
    if decrypt:
        shift = -shift
    result = ""
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result


def caesar_brute(text: str) -> List[Tuple[int, str, float]]:
    """Try all 25 Caesar shifts and score each output against English frequency."""
    results = []
    for shift in range(1, 26):
        decrypted = caesar_cipher(text, shift, decrypt=True)
        score = frequency_score(decrypted)
        results.append((shift, decrypted, score))
    return sorted(results, key=lambda item: item[2], reverse=True)


def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
    if not key or not any(char.isalpha() for char in key):
        return "[ERROR] Vigenere key must contain at least one alphabetic character"
    key = "".join(char for char in key.upper() if char.isalpha())
    result = ""
    key_idx = 0
    for char in text:
        if char.isalpha():
            offset = ord(key[key_idx % len(key)]) - ord("A")
            if decrypt:
                offset = -offset
            base = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - base + offset) % 26 + base)
            key_idx += 1
        else:
            result += char
    return result


def atbash(text: str) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr(ord("Z") - (ord(char) - ord("A")))
            else:
                result += chr(ord("z") - (ord(char) - ord("a")))
        else:
            result += char
    return result


def rail_fence_encrypt(text: str, rails: int) -> str:
    if rails < 2:
        return text
    fence = [""] * rails
    rail, direction = 0, 1
    for char in text:
        fence[rail] += char
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return "".join(fence)


def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    if rails < 2:
        return ciphertext
    n = len(ciphertext)
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    indices = sorted(range(n), key=lambda idx: pattern[idx])
    result = [""] * n
    for idx, char in zip(indices, ciphertext):
        result[idx] = char
    return "".join(result)


def substitution_encode(text: str, key: str) -> str:
    """Simple substitution cipher. The key is the substituted alphabet with 26 letters."""
    key = key.strip()
    if len(key) != 26 or not key.isalpha():
        return "[ERROR] Substitution key must contain exactly 26 alphabetic characters"
    result = ""
    for char in text:
        if char.isalpha():
            idx = ord(char.upper()) - ord("A")
            sub = key[idx]
            result += sub.lower() if char.islower() else sub.upper()
        else:
            result += char
    return result


def substitution_decode(text: str, key: str) -> str:
    key = key.strip().upper()
    if len(key) != 26 or not key.isalpha() or len(set(key)) != 26:
        return "[ERROR] Substitution key must contain 26 unique alphabetic characters"
    reverse = {cipher: plain for plain, cipher in zip(string.ascii_uppercase, key)}
    result = ""
    for char in text:
        if char.isalpha():
            plain = reverse.get(char.upper(), char.upper())
            result += plain.lower() if char.islower() else plain
        else:
            result += char
    return result


# ══════════════════════════════════════════════════════════════════════════════
# XOR OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def xor_single_byte(data: bytes, key: int) -> bytes:
    return bytes(byte ^ key for byte in data)


def xor_repeating_key(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def xor_brute_single(ciphertext_hex: str) -> List[Tuple[int, str, float]]:
    """Try every possible single-byte XOR key."""
    try:
        data = bytes.fromhex(ciphertext_hex.replace(" ", ""))
    except ValueError:
        data = ciphertext_hex.encode()

    results = []
    for key in range(256):
        decrypted = xor_single_byte(data, key)
        text = decrypted.decode("utf-8", errors="replace")
        score = frequency_score(text)
        results.append((key, text, score))
    return sorted(results, key=lambda item: item[2], reverse=True)[:10]


def xor_hex(hex1: str, hex2: str) -> str:
    """XOR two hexadecimal values using the overlapping length."""
    try:
        b1 = bytes.fromhex(hex1.replace(" ", ""))
        b2 = bytes.fromhex(hex2.replace(" ", ""))
        return bytes(a ^ b for a, b in zip(b1, b2)).hex()
    except Exception as exc:
        return f"[ERROR] {exc}"


def recover_xor_key_from_known_plaintext(plaintext: str, ciphertext_hex: str) -> str:
    try:
        plain = plaintext.encode()
        cipher = bytes.fromhex(ciphertext_hex.replace(" ", ""))
        return bytes(c ^ p for p, c in zip(plain, cipher)).hex()
    except Exception as exc:
        return f"[ERROR] {exc}"


# ══════════════════════════════════════════════════════════════════════════════
# FREQUENCY ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def frequency_score(text: str) -> float:
    """Score text by similarity to English letter frequency. Higher is better."""
    text = text.lower()
    letter_count = sum(1 for char in text if char.isalpha())
    if letter_count == 0:
        return 0.0
    score = 0.0
    for char, expected_pct in ENGLISH_FREQ.items():
        actual_pct = text.count(char) / letter_count * 100
        score -= abs(actual_pct - expected_pct)
    common_bonus = sum(text.count(word) for word in (" the ", " and ", " of ", " to ", " in ")) * 4
    return round(score + common_bonus, 3)


def frequency_analysis(text: str) -> Dict[str, Dict[str, float]]:
    """Return letter frequency analysis for ciphertext or plaintext."""
    letters = [char.lower() for char in text if char.isalpha()]
    total = len(letters)
    if total == 0:
        return {}
    counter = collections.Counter(letters)
    return {
        char: {
            "count": counter[char],
            "percent": round(counter[char] / total * 100, 2),
            "english": ENGLISH_FREQ.get(char, 0),
            "delta": round(counter[char] / total * 100 - ENGLISH_FREQ.get(char, 0), 2),
        }
        for char in sorted(counter, key=lambda item: counter[item], reverse=True)
    }


def index_of_coincidence(text: str) -> float:
    """Index of Coincidence. English is usually near 0.065; random text near 0.038."""
    letters = [char.lower() for char in text if char.isalpha()]
    n = len(letters)
    if n <= 1:
        return 0.0
    counter = collections.Counter(letters)
    ic = sum(freq * (freq - 1) for freq in counter.values()) / (n * (n - 1))
    return round(ic, 4)


def guess_vigenere_key_length(ciphertext: str, max_len: int = 20) -> List[Tuple[int, float]]:
    """Estimate Vigenere key length using average Index of Coincidence."""
    text = "".join(char.lower() for char in ciphertext if char.isalpha())
    results = []
    for key_len in range(2, min(max_len + 1, max(2, len(text) // 2))):
        ics = []
        for offset in range(key_len):
            substring = text[offset::key_len]
            if len(substring) > 1:
                ics.append(index_of_coincidence(substring))
        avg_ic = sum(ics) / len(ics) if ics else 0
        results.append((key_len, round(avg_ic, 4)))
    results.sort(key=lambda item: abs(item[1] - 0.065))
    return results[:8]


# ══════════════════════════════════════════════════════════════════════════════
# AUTO-DETECT & DECODE
# ══════════════════════════════════════════════════════════════════════════════

def auto_decode(text: str) -> List[Tuple[str, str]]:
    """Try multiple encodings and lightweight cipher guesses."""
    results = []
    text = text.strip()

    try:
        decoded = base64.b64decode(_pad_base64(text)).decode("utf-8", errors="replace")
        if decoded and all(32 <= ord(char) <= 126 or char in "\n\r\t" for char in decoded[:50]):
            results.append(("Base64", decoded))
    except Exception:
        pass

    clean_hex = text.replace(" ", "").replace("0x", "")
    if clean_hex and all(char in "0123456789abcdefABCDEF" for char in clean_hex) and len(clean_hex) % 2 == 0:
        try:
            decoded = bytes.fromhex(clean_hex).decode("utf-8", errors="replace")
            if decoded and all(32 <= ord(char) <= 126 or char in "\n\r\t" for char in decoded[:50]):
                results.append(("Hex", decoded))
        except Exception:
            pass

    rotated = rot13(text)
    if rotated != text:
        results.append(("ROT13", rotated))

    if "%" in text:
        results.append(("URL Decode", url_decode(text)))

    clean_bin = text.replace(" ", "")
    if clean_bin and all(char in "01" for char in clean_bin) and len(clean_bin) % 8 == 0 and len(clean_bin) >= 8:
        decoded = from_binary(text)
        if not decoded.startswith("[ERROR]") and all(32 <= ord(char) <= 126 for char in decoded[:20] if char):
            results.append(("Binary", decoded))

    if text and all(char in ".- /" for char in text):
        results.append(("Morse", morse_decode(text)))

    if any(char.isalpha() for char in text):
        for shift, decoded, _score in caesar_brute(text)[:3]:
            results.append((f"Caesar shift={shift}", decoded))

    return results


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def emit_result(payload: Any, text_output: str, json_out: bool = False) -> None:
    if json_out:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(text_output)


def print_freq_analysis(text: str, json_out: bool = False) -> None:
    freq = frequency_analysis(text)
    ic = index_of_coincidence(text)
    if json_out:
        print(json.dumps({"index_of_coincidence": ic, "frequency": freq}, indent=2))
        return

    print(f"\n{SEP}")
    print(f"  {C.BOLD}Frequency Analysis{C.RESET}")
    print(f"  Index of Coincidence: {C.CYAN}{ic}{C.RESET}  (English ≈ 0.065 | Random ≈ 0.038)")
    print(f"  {'Char':<6} {'Count':>6} {'%':>7} {'EN%':>7} {'Delta':>7}")
    print(f"  {'─' * 44}")
    for char, data in list(freq.items())[:15]:
        bar = "█" * int(data["percent"] / 2)
        delta = data["delta"]
        delta_color = C.RED if abs(delta) > 3 else C.DIM
        print(
            f"  {C.BOLD}{char.upper()}{C.RESET}     {data['count']:>6}  "
            f"{data['percent']:>6.1f}%  {data['english']:>6.1f}%  "
            f"{delta_color}{delta:>+6.1f}%{C.RESET}  {C.DIM}{bar}{C.RESET}"
        )


def print_xor_brute(results: List[Tuple[int, str, float]], json_out: bool = False) -> None:
    if json_out:
        print(json.dumps([{"key": key, "hex": f"0x{key:02x}", "decoded": text, "score": score} for key, text, score in results], indent=2))
        return

    print(f"\n{SEP}")
    print(f"  {C.BOLD}XOR Brute Force (top 10 by English frequency score){C.RESET}")
    print(f"  {'Key':>6} {'Hex':>4} {'Decoded (first 60 chars)'}")
    print(f"  {'─' * 64}")
    for key, text, _score in results:
        preview = text[:60].replace("\n", "↵").replace("\r", "")
        print(f"  {C.CYAN}{key:>6}{C.RESET} {C.DIM}0x{key:02x}{C.RESET} {preview}")


def _parse_xor_key(key: str) -> bytes:
    if key.startswith("0x"):
        return bytes.fromhex(key[2:])
    if "," in key:
        return bytes(int(item.strip()) for item in key.split(","))
    return bytes([int(key)])


def _parse_data_as_hex_or_text(value: str) -> bytes:
    try:
        if value and all(char in "0123456789abcdefABCDEF " for char in value):
            return bytes.fromhex(value.replace(" ", ""))
    except ValueError:
        pass
    return value.encode()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-crypto",
        description="CTF Crypto Toolkit — Caesar · Vigenere · XOR · Encodings · Frequency Analysis",
    )
    parser.add_argument("--no-banner", action="store_true", help="Suppress the banner")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Emit machine-readable JSON where supported")
    parser.add_argument("--version", action="version", version=f"ctf-crypto {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode", help="Encode text")
    enc.add_argument("text")
    enc.add_argument("-m", "--method", choices=["b64", "b32", "b16", "hex", "url", "html", "binary", "octal", "decimal", "rot13", "morse"], default="b64")

    dec = sub.add_parser("decode", help="Decode text")
    dec.add_argument("text")
    dec.add_argument("-m", "--method", choices=["b64", "b32", "b16", "hex", "url", "html", "binary", "octal", "decimal", "rot13", "morse"], default="b64")

    auto = sub.add_parser("auto", help="Auto-detect and decode common encodings/ciphers")
    auto.add_argument("text")

    caesar = sub.add_parser("caesar", help="Caesar cipher")
    caesar.add_argument("text")
    caesar.add_argument("-s", "--shift", type=int, default=13)
    caesar.add_argument("-d", "--decrypt", action="store_true")
    caesar.add_argument("--brute", action="store_true", help="Try every Caesar shift")

    vig = sub.add_parser("vigenere", help="Vigenere cipher")
    vig.add_argument("text")
    vig.add_argument("-k", "--key", default="", help="Cipher key")
    vig.add_argument("-d", "--decrypt", action="store_true")
    vig.add_argument("--guess-keylen", action="store_true", help="Estimate key length using Index of Coincidence")

    at = sub.add_parser("atbash", help="Atbash cipher")
    at.add_argument("text")

    rf = sub.add_parser("railfence", help="Rail Fence transposition cipher")
    rf.add_argument("text")
    rf.add_argument("-r", "--rails", type=int, default=3)
    rf.add_argument("-d", "--decrypt", action="store_true")

    sub_cmd = sub.add_parser("substitution", help="Simple substitution cipher with a 26-letter key")
    sub_cmd.add_argument("text")
    sub_cmd.add_argument("-k", "--key", required=True, help="Substitution alphabet, exactly 26 letters")
    sub_cmd.add_argument("-d", "--decrypt", action="store_true")

    xor = sub.add_parser("xor", help="XOR operations")
    xor.add_argument("data", help="Input data as hex or text")
    xor.add_argument("-k", "--key", help="Key: decimal byte, 0x-prefixed hex bytes, or comma-separated bytes")
    xor.add_argument("--brute", action="store_true", help="Brute-force single-byte XOR")
    xor.add_argument("--hex2", help="Second hex value for fixed XOR")
    xor.add_argument("--known-plain", help="Known plaintext used to recover XOR key material")

    freq = sub.add_parser("freq", help="Frequency analysis")
    freq.add_argument("text")

    morse = sub.add_parser("morse", help="Morse code")
    morse.add_argument("text")
    morse.add_argument("-d", "--decode", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner and not args.json_out:
        print(BANNER)

    encode_methods = {
        "b64": b64_encode,
        "b32": b32_encode,
        "b16": b16_encode,
        "hex": lambda text: text.encode().hex(),
        "url": url_encode,
        "html": html_encode,
        "binary": to_binary,
        "octal": to_octal,
        "decimal": to_decimal,
        "rot13": rot13,
        "morse": morse_encode,
    }
    decode_methods = {
        "b64": b64_decode,
        "b32": b32_decode,
        "b16": b16_decode,
        "hex": b16_decode,
        "url": url_decode,
        "html": html_decode,
        "binary": from_binary,
        "octal": from_octal,
        "decimal": from_decimal,
        "rot13": rot13,
        "morse": morse_decode,
    }

    cmd = args.command

    if cmd == "encode":
        result = encode_methods[args.method](args.text)
        emit_result({"method": args.method, "result": result}, f"\n  {C.DIM}[{args.method.upper()}]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)

    elif cmd == "decode":
        result = decode_methods[args.method](args.text)
        emit_result({"method": args.method, "result": result}, f"\n  {C.DIM}[{args.method.upper()} decoded]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)

    elif cmd == "auto":
        results = auto_decode(args.text)
        if args.json_out:
            print(json.dumps([{"method": method, "result": result} for method, result in results], indent=2))
        else:
            print(f"\n{SEP}")
            print(f"  {C.BOLD}Auto-Decode Results for: {C.DIM}{args.text[:60]}{C.RESET}")
            print(SEP)
            for method, result in results:
                print(f"\n  {C.CYAN}[{method}]{C.RESET}")
                print(f"  {C.GREEN}{result[:120]}{C.RESET}")

    elif cmd == "caesar":
        if args.brute:
            results = caesar_brute(args.text)
            if args.json_out:
                print(json.dumps([{"shift": shift, "decoded": decoded, "score": score} for shift, decoded, score in results], indent=2))
            else:
                print(f"\n{SEP}")
                print(f"  {C.BOLD}Caesar Brute Force (top 5){C.RESET}")
                print(f"  {'Shift':>7}  {'Decoded (60 chars)'}")
                print(f"  {'─' * 60}")
                for shift, decoded, _score in results[:5]:
                    print(f"  {C.CYAN}shift={shift:>2}{C.RESET}  {decoded[:60]}")
        else:
            result = caesar_cipher(args.text, args.shift, args.decrypt)
            mode = "decrypt" if args.decrypt else "encrypt"
            emit_result({"mode": mode, "shift": args.shift, "result": result}, f"\n  {C.DIM}[Caesar {mode} shift={args.shift}]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)

    elif cmd == "vigenere":
        if args.guess_keylen:
            guesses = guess_vigenere_key_length(args.text)
            if args.json_out:
                print(json.dumps([{"key_length": key_len, "index_of_coincidence": ic} for key_len, ic in guesses], indent=2))
            else:
                print(f"\n{SEP}")
                print(f"  {C.BOLD}Vigenere Key Length Estimation (IC method){C.RESET}")
                for key_len, ic in guesses[:6]:
                    bar = "█" * int(ic * 400)
                    marker = "← English-like" if abs(ic - 0.065) < 0.005 else ""
                    print(f"  Key len {C.CYAN}{key_len:>3}{C.RESET}: IC={ic}  {C.DIM}{bar}{C.RESET} {C.GREEN}{marker}{C.RESET}")
        else:
            if not args.key:
                parser.error("vigenere requires --key unless --guess-keylen is used")
            result = vigenere_cipher(args.text, args.key, args.decrypt)
            mode = "decrypt" if args.decrypt else "encrypt"
            emit_result({"mode": mode, "key": args.key, "result": result}, f"\n  {C.DIM}[Vigenere {mode} key={args.key}]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)

    elif cmd == "atbash":
        result = atbash(args.text)
        emit_result({"method": "atbash", "result": result}, f"\n  {C.DIM}[Atbash]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)

    elif cmd == "railfence":
        result = rail_fence_decrypt(args.text, args.rails) if args.decrypt else rail_fence_encrypt(args.text, args.rails)
        mode = "decrypt" if args.decrypt else "encrypt"
        emit_result({"mode": mode, "rails": args.rails, "result": result}, f"\n  {C.DIM}[Rail Fence {mode} rails={args.rails}]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)

    elif cmd == "substitution":
        result = substitution_decode(args.text, args.key) if args.decrypt else substitution_encode(args.text, args.key)
        mode = "decrypt" if args.decrypt else "encrypt"
        emit_result({"mode": mode, "key": args.key, "result": result}, f"\n  {C.DIM}[Substitution {mode}]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)

    elif cmd == "xor":
        if args.brute:
            print_xor_brute(xor_brute_single(args.data), args.json_out)
        elif args.hex2:
            result = xor_hex(args.data, args.hex2)
            emit_result({"operation": "fixed_xor", "result": result}, f"\n  {C.DIM}[XOR]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)
        elif args.known_plain:
            result = recover_xor_key_from_known_plaintext(args.known_plain, args.data)
            emit_result({"operation": "known_plaintext_key_recovery", "key_hex": result}, f"\n  {C.DIM}[Recovered XOR key material]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)
        elif args.key:
            try:
                key_bytes = _parse_xor_key(args.key)
                data = _parse_data_as_hex_or_text(args.data)
                result = xor_repeating_key(data, key_bytes)
                payload = {"operation": "xor", "key": args.key, "hex": result.hex(), "string": result.decode(errors="replace")}
                text = f"\n  {C.DIM}[XOR key={args.key}]{C.RESET}\n  Hex: {C.GREEN}{result.hex()}{C.RESET}\n  Str: {C.GREEN}{result.decode(errors='replace')}{C.RESET}"
                emit_result(payload, text, args.json_out)
            except Exception as exc:
                message = f"[ERROR] {exc}"
                emit_result({"error": str(exc)}, f"  {C.RED}{message}{C.RESET}", args.json_out)
        else:
            parser.error("xor requires --brute, --hex2, --known-plain, or --key")

    elif cmd == "freq":
        print_freq_analysis(args.text, args.json_out)

    elif cmd == "morse":
        result = morse_decode(args.text) if args.decode else morse_encode(args.text)
        mode = "decode" if args.decode else "encode"
        emit_result({"mode": mode, "result": result}, f"\n  {C.DIM}[Morse {mode}]{C.RESET} {C.GREEN}{result}{C.RESET}", args.json_out)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
yara_builder.py — YARA Rule Builder v1.0.0
============================================
Builds, validates, and tests YARA rules for malware and artifact detection.
Includes a library of sample rules and a basic scanner with no external dependencies.

Author      : Marcio Coutinho — Cybersecurity Specialist
Date        : 21/06/2024
Requirements: Python 3.8+ | Zero external dependencies
              For real scanning: pip install yara-python (optional)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
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


BANNER = f"""
{C.CYAN}{C.BOLD}
 ██╗   ██╗ █████╗ ██████╗  █████╗     ██████╗ ██╗   ██╗██╗██╗     ██████╗ ███████╗██████╗
 ╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗    ██╔══██╗██║   ██║██║██║     ██╔══██╗██╔════╝██╔══██╗
  ╚████╔╝ ███████║██████╔╝███████║    ██████╔╝██║   ██║██║██║     ██║  ██║█████╗  ██████╔╝
   ╚██╔╝  ██╔══██║██╔══██╗██╔══██║    ██╔══██╗██║   ██║██║██║     ██║  ██║██╔══╝  ██╔══██╗
    ██║   ██║  ██║██║  ██║██║  ██║    ██████╔╝╚██████╔╝██║███████╗██████╔╝███████╗██║  ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝{C.RESET}
{C.DIM} v{__version__} — YARA Rule Builder | Validator | Template Library | Pattern Scanner{C.RESET}
"""


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class YaraString:
    identifier: str       # e.g. $shell_cmd
    value:      str       # content
    stype:      str       # text | hex | regex
    modifiers:  List[str] = field(default_factory=list)  # nocase, wide, ascii, fullword

    def render(self) -> str:
        mods = " ".join(self.modifiers)
        if self.stype == "text":
            return f'        {self.identifier} = "{self.value}"{" " + mods if mods else ""}'
        elif self.stype == "hex":
            return f'        {self.identifier} = {{ {self.value} }}{" " + mods if mods else ""}'
        elif self.stype == "regex":
            return f'        {self.identifier} = /{self.value}/{mods if mods else ""}'
        return f'        {self.identifier} = "{self.value}"'


@dataclass
class YaraMeta:
    author:      str = ""
    description: str = ""
    date:        str = ""
    version:     str = "1.0"
    tlp:         str = "WHITE"
    reference:   str = ""
    hash:        str = ""

    def render(self) -> str:
        lines = []
        if self.description: lines.append(f'        description = "{self.description}"')
        if self.author:      lines.append(f'        author      = "{self.author}"')
        if self.date:        lines.append(f'        date        = "{self.date}"')
        if self.version:     lines.append(f'        version     = "{self.version}"')
        if self.tlp:         lines.append(f'        tlp         = "{self.tlp}"')
        if self.reference:   lines.append(f'        reference   = "{self.reference}"')
        if self.hash:        lines.append(f'        hash        = "{self.hash}"')
        return "\n".join(lines)


@dataclass
class YaraRule:
    name:      str
    tags:      List[str]
    meta:      YaraMeta
    strings:   List[YaraString]
    condition: str
    imports:   List[str] = field(default_factory=list)

    def render(self) -> str:
        parts = []

        # Imports
        for imp in self.imports:
            parts.append(f'import "{imp}"')
        if self.imports:
            parts.append("")

        # Rule header
        tags_str = " ".join(self.tags)
        parts.append(f'rule {self.name}' + (f' : {tags_str}' if tags_str else ""))
        parts.append("{")

        # Meta
        if any([self.meta.author, self.meta.description, self.meta.date,
                self.meta.reference, self.meta.hash]):
            parts.append("    meta:")
            parts.append(self.meta.render())

        # Strings
        if self.strings:
            parts.append("    strings:")
            for s in self.strings:
                parts.append(s.render())

        # Condition
        parts.append("    condition:")
        parts.append(f"        {self.condition}")
        parts.append("}")

        return "\n".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# RULE TEMPLATES LIBRARY
# ══════════════════════════════════════════════════════════════════════════════

RULE_TEMPLATES: Dict[str, YaraRule] = {

    "reverse_shell": YaraRule(
        name="Reverse_Shell_Indicators",
        tags=["malware", "backdoor", "C2"],
        meta=YaraMeta(
            description="Detects common reverse shell indicators in scripts and binaries",
            author="Márcio Coutinho",
            date=datetime.now().strftime("%Y-%m-%d"),
            reference="https://attack.mitre.org/techniques/T1059/",
        ),
        strings=[
            YaraString("$bash_tcp",   "/bin/bash -i >& /dev/tcp/",     "text"),
            YaraString("$nc_exec",    "nc -e /bin/",                    "text"),
            YaraString("$ncat_exec",  "ncat -e /bin/",                  "text"),
            YaraString("$python_rev", "socket.connect",                 "text"),
            YaraString("$socat",      "socat exec:",                    "text"),
            YaraString("$mkfifo",     "mkfifo /tmp/",                   "text"),
            YaraString("$dev_tcp",    r"/dev/tcp/\d+\.\d+\.\d+\.\d+",  "regex"),
        ],
        condition="any of them",
    ),

    "webshell_php": YaraRule(
        name="PHP_Webshell",
        tags=["webshell", "php", "backdoor"],
        meta=YaraMeta(
            description="Detects common PHP webshells — eval, base64, and system calls with external input",
            author="Márcio Coutinho",
            date=datetime.now().strftime("%Y-%m-%d"),
            reference="https://attack.mitre.org/techniques/T1505/003/",
        ),
        strings=[
            YaraString("$eval_b64",   "eval(base64_decode(",            "text", ["nocase"]),
            YaraString("$eval_post",  "eval($_POST",                    "text", ["nocase"]),
            YaraString("$eval_get",   "eval($_GET",                     "text", ["nocase"]),
            YaraString("$eval_req",   "eval($_REQUEST",                 "text", ["nocase"]),
            YaraString("$system_req", "system($_REQUEST",               "text", ["nocase"]),
            YaraString("$passthru",   "passthru($_",                    "text", ["nocase"]),
            YaraString("$shell_exec", "shell_exec($_",                  "text", ["nocase"]),
            YaraString("$assert_req", "assert($_REQUEST",               "text", ["nocase"]),
            YaraString("$preg_rep",   'preg_replace("/.*/e"',           "text", ["nocase"]),
        ],
        condition="any of ($eval_*) or any of ($system_req, $passthru, $shell_exec, $assert_req, $preg_rep)",
    ),

    "ransomware_behavior": YaraRule(
        name="Ransomware_Behavioral_Indicators",
        tags=["ransomware", "malware", "destructive"],
        meta=YaraMeta(
            description="Ransomware behavioral indicators — mass encryption, shadow copies, and ransom notes",
            author="Márcio Coutinho",
            date=datetime.now().strftime("%Y-%m-%d"),
            reference="https://attack.mitre.org/techniques/T1486/",
        ),
        strings=[
            YaraString("$vss_delete1", "vssadmin delete shadows",       "text", ["nocase"]),
            YaraString("$vss_delete2", "wmic shadowcopy delete",        "text", ["nocase"]),
            YaraString("$bcdedit",     "bcdedit /set {default}",        "text", ["nocase"]),
            YaraString("$ransom_note1","your files have been encrypted", "text", ["nocase"]),
            YaraString("$ransom_note2","send bitcoin to",                "text", ["nocase"]),
            YaraString("$ransom_note3","README_DECRYPT",                 "text", ["nocase"]),
            YaraString("$ransom_note4","HOW_TO_RESTORE",                 "text", ["nocase"]),
            YaraString("$tor_addr",    r"[a-z2-7]{16,56}\.onion",       "regex"),
        ],
        condition="2 of ($vss_*) or 1 of ($ransom_note*) or ($tor_addr and 1 of ($ransom_note*))",
    ),

    "credential_dumping": YaraRule(
        name="Credential_Dumping_Tools",
        tags=["credential_access", "mimikatz", "T1003"],
        meta=YaraMeta(
            description="Detects strings associated with credential-dumping tools (Mimikatz, etc.)",
            author="Márcio Coutinho",
            date=datetime.now().strftime("%Y-%m-%d"),
            reference="https://attack.mitre.org/techniques/T1003/",
        ),
        strings=[
            YaraString("$mimi1",      "mimikatz",                       "text", ["nocase", "wide", "ascii"]),
            YaraString("$mimi2",      "sekurlsa::logonpasswords",       "text", ["nocase"]),
            YaraString("$mimi3",      "lsadump::sam",                   "text", ["nocase"]),
            YaraString("$mimi4",      "privilege::debug",               "text", ["nocase"]),
            YaraString("$mimi5",      "crypto::capi",                   "text", ["nocase"]),
            YaraString("$ntds",       "ntds.dit",                       "text", ["nocase"]),
            YaraString("$sam_reg",    "SYSTEM\\CurrentControlSet\\Control\\Lsa", "text", ["nocase"]),
            YaraString("$procdump",   "MiniDumpWriteDump",              "text"),
        ],
        condition="2 of ($mimi*) or ($ntds and $sam_reg) or ($procdump and $sam_reg)",
    ),

    "log4shell": YaraRule(
        name="Log4Shell_CVE_2021_44228",
        tags=["exploit", "CVE-2021-44228", "log4j", "CRITICAL"],
        meta=YaraMeta(
            description="Detects Log4Shell payloads in logs, configuration files, and captured traffic",
            author="Márcio Coutinho",
            date=datetime.now().strftime("%Y-%m-%d"),
            reference="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            hash="n/a",
        ),
        strings=[
            YaraString("$jndi1",  "${jndi:",                            "text", ["nocase"]),
            YaraString("$jndi2",  "${${lower:j}${lower:n}${lower:d}${lower:i}:", "text", ["nocase"]),
            YaraString("$jndi3",  "%24%7Bjndi:",                        "text", ["nocase"]),
            YaraString("$ldap1",  "ldap://",                            "text", ["nocase"]),
            YaraString("$ldap2",  "ldaps://",                           "text", ["nocase"]),
            YaraString("$rmi",    "rmi://",                             "text", ["nocase"]),
            YaraString("$dns_cb", "dns://",                             "text", ["nocase"]),
        ],
        condition="$jndi1 or $jndi2 or $jndi3",
    ),

    "powershell_obfuscation": YaraRule(
        name="PowerShell_Obfuscation",
        tags=["powershell", "obfuscation", "T1059.001"],
        meta=YaraMeta(
            description="Detects common obfuscation techniques in PowerShell scripts",
            author="Márcio Coutinho",
            date=datetime.now().strftime("%Y-%m-%d"),
            reference="https://attack.mitre.org/techniques/T1059/001/",
        ),
        strings=[
            YaraString("$enc1",   "-enc ",                              "text", ["nocase"]),
            YaraString("$enc2",   "-EncodedCommand",                    "text", ["nocase"]),
            YaraString("$bypass1","bypass",                             "text", ["nocase"]),
            YaraString("$bypass2","-nop",                               "text", ["nocase"]),
            YaraString("$hidden", "-w hidden",                          "text", ["nocase"]),
            YaraString("$iex",    "IEX",                                "text"),
            YaraString("$invoke", "Invoke-Expression",                  "text", ["nocase"]),
            YaraString("$dl_str", "DownloadString",                     "text", ["nocase"]),
            YaraString("$webcli", "Net.WebClient",                      "text", ["nocase"]),
            YaraString("$fromB64","FromBase64String",                   "text", ["nocase"]),
        ],
        condition="($enc1 or $enc2) and ($hidden or $bypass2) and ($iex or $invoke)",
    ),

    "network_scan_tool": YaraRule(
        name="Network_Scanner_Binary",
        tags=["reconnaissance", "tool", "T1046"],
        meta=YaraMeta(
            description="Detects network reconnaissance tool binaries (Nmap, masscan, etc.)",
            author="Márcio Coutinho",
            date=datetime.now().strftime("%Y-%m-%d"),
            reference="https://attack.mitre.org/techniques/T1046/",
        ),
        strings=[
            YaraString("$nmap",    "Nmap scan report",                  "text"),
            YaraString("$masscan", "masscan",                           "text", ["nocase"]),
            YaraString("$zmap",    "zmap",                              "text", ["nocase"]),
            YaraString("$syn_scan","SYN Stealth Scan",                  "text"),
            YaraString("$os_det",  "OS detection",                      "text", ["nocase"]),
        ],
        condition="2 of them",
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATOR (without yara-python — basic syntax validation)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ValidationResult:
    valid:    bool
    errors:   List[str]
    warnings: List[str]
    stats:    dict


def validate_rule_syntax(rule_text: str) -> ValidationResult:
    errors   = []
    warnings = []
    stats    = {}

    lines    = rule_text.split("\n")
    # Basic structure
    has_rule   = any(re.match(r"^\s*rule\s+\w+", l) for l in lines)
    has_open   = any(l.strip() == "{" for l in lines)
    has_close  = any(l.strip() == "}" for l in lines)
    has_cond   = any("condition:" in l for l in lines)
    has_strings= any("strings:" in l for l in lines)
    has_meta   = any("meta:" in l for l in lines)

    if not has_rule:    errors.append("Missing 'rule <name>' declaration")
    if not has_open:    errors.append("Missing '{' after the rule header")
    if not has_close:   errors.append("Missing '}' to close the rule")
    if not has_cond:    errors.append("Missing 'condition:' section")

    # Check string identifiers
    str_ids = re.findall(r"(\$\w+)\s*=", rule_text)
    cond    = ""
    in_cond = False
    for l in lines:
        if "condition:" in l:
            in_cond = True
        elif in_cond:
            cond += l + " "
            if "}" in l:
                break

    # Strings referenced but not defined
    cond_refs = re.findall(r"\$\w+", cond)
    for ref in cond_refs:
        if ref not in str_ids and ref != "$":
            # It may be a wildcard, e.g. $str*
            if not any(ref.rstrip("*") in sid for sid in str_ids):
                warnings.append(f"String '{ref}' is used in the condition but may not be defined")

    # Strings defined but not used
    for sid in str_ids:
        if sid not in cond and "any of" not in cond and "all of" not in cond and "them" not in cond:
            warnings.append(f"String '{sid}' is defined but not referenced in the condition")

    # Count elements
    stats = {
        "strings_defined": len(str_ids),
        "has_meta":        has_meta,
        "has_strings":     has_strings,
        "line_count":      len(lines),
    }

    # Quality recommendations
    if not has_meta:
        warnings.append("Recommended: add a 'meta:' section with description and author")
    if len(str_ids) == 0 and has_cond:
        warnings.append("Rule has no strings — only filesize/entrypoint/etc. conditions")

    return ValidationResult(
        valid    = len(errors) == 0,
        errors   = errors,
        warnings = warnings,
        stats    = stats,
    )


# ══════════════════════════════════════════════════════════════════════════════
# BASIC PATTERN SCANNER (without yara-python)
# ══════════════════════════════════════════════════════════════════════════════

def extract_strings_from_rule(rule_text: str) -> List[tuple]:
    """Extract strings from a YARA rule for manual scanning."""
    patterns = []

    # Text strings: $id = "value" [modifiers]
    for m in re.finditer(r'\$(\w+)\s*=\s*"([^"]+)"(\s+\w+)*', rule_text):
        patterns.append(("text", m.group(1), m.group(2), m.group(3) or ""))

    # Hex strings: $id = { bytes }
    for m in re.finditer(r'\$(\w+)\s*=\s*\{([^}]+)\}', rule_text):
        patterns.append(("hex", m.group(1), m.group(2).strip(), ""))

    # Regex strings: $id = /pattern/modifiers
    for m in re.finditer(r'\$(\w+)\s*=\s*/([^/]+)/(\w*)', rule_text):
        patterns.append(("regex", m.group(1), m.group(2), m.group(3)))

    return patterns


def scan_file_with_rule(filepath: str, rule_text: str) -> dict:
    """Basic scanner without yara-python — text string matching."""
    path = Path(filepath)
    if not path.exists():
        return {"error": f"File not found: {filepath}"}

    try:
        content = path.read_bytes()
        content_str = content.decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": str(e)}

    patterns  = extract_strings_from_rule(rule_text)
    matches   = []
    nocase_flag = re.IGNORECASE

    for ptype, pid, pval, mods in patterns:
        if ptype == "text":
            flags  = nocase_flag if "nocase" in mods else 0
            found  = [m.start() for m in re.finditer(re.escape(pval), content_str, flags)]
            if found:
                matches.append({
                    "string":  pid,
                    "value":   pval,
                    "offsets": found[:5],
                    "count":   len(found),
                })
        elif ptype == "regex":
            flags = nocase_flag if "i" in mods else 0
            try:
                found = [m.start() for m in re.finditer(pval, content_str, flags)]
                if found:
                    matches.append({
                        "string":  pid,
                        "value":   f"/{pval}/",
                        "offsets": found[:5],
                        "count":   len(found),
                    })
            except re.error:
                pass

    return {
        "file":    filepath,
        "size":    path.stat().st_size,
        "sha256":  hashlib.sha256(content).hexdigest(),
        "matches": matches,
        "matched": len(matches) > 0,
    }


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEP = "━" * 68


def print_validation(result: ValidationResult) -> None:
    status = f"{C.GREEN}✅ VALID{C.RESET}" if result.valid else f"{C.RED}❌ INVALID{C.RESET}"
    print(f"\n{SEP}")
    print(f"  {C.BOLD}Validation:{C.RESET} {status}")
    print(f"  Strings defined: {result.stats.get('strings_defined', 0)} | "
          f"Meta: {'✓' if result.stats.get('has_meta') else '✗'} | "
          f"Lines: {result.stats.get('line_count', 0)}")

    for err in result.errors:
        print(f"\n  {C.RED}[ERROR]{C.RESET} {err}")
    for warn in result.warnings:
        print(f"  {C.YELLOW}[WARN]{C.RESET} {warn}")


def print_scan_result(result: dict) -> None:
    if "error" in result:
        print(f"  {C.RED}[ERROR] {result['error']}{C.RESET}")
        return

    matched = result["matched"]
    icon    = f"{C.RED}⚠ MATCH{C.RESET}" if matched else f"{C.GREEN}✓ CLEAN{C.RESET}"
    print(f"\n{SEP}")
    print(f"  {icon}  {result['file']}")
    print(f"  SHA-256: {C.DIM}{result['sha256']}{C.RESET}  |  Size: {result['size']:,} bytes")

    for m in result["matches"]:
        print(f"\n  {C.YELLOW}[HIT]{C.RESET} {C.BOLD}{m['string']}{C.RESET} = {m['value'][:60]}")
        print(f"        {m['count']} occurrence(s) | offsets: {m['offsets']}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="yara-builder",
        description="YARA Rule Builder — Build · Validate · Scan"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # build
    b = sub.add_parser("build", help="Build a YARA rule interactively")
    b.add_argument("name", help="Rule name")
    b.add_argument("--desc",   default="", help="Description")
    b.add_argument("--author", default="Márcio Coutinho")
    b.add_argument("--tags",   nargs="*", default=[])
    b.add_argument("--strings", nargs="*", metavar="TEXT",
                   help="Strings to detect (plain text)")
    b.add_argument("--condition", default="any of them")
    b.add_argument("-o","--output", help="Output .yar file")

    # template
    t = sub.add_parser("template", help="Use a predefined template")
    t.add_argument("name", choices=list(RULE_TEMPLATES.keys()) + ["list"])
    t.add_argument("-o","--output", help="Output .yar file")

    # validate
    v = sub.add_parser("validate", help="Validate a YARA rule file")
    v.add_argument("file", help=".yar file")

    # scan
    s = sub.add_parser("scan", help="Basic file scan with a YARA rule")
    s.add_argument("rule", help=".yar file")
    s.add_argument("target", help="Target file or directory")
    s.add_argument("--json", action="store_true", dest="json_out")

    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version=f"yara-builder {__version__}")

    args = parser.parse_args()
    if not args.no_banner:
        print(BANNER)

    cmd = args.command

    if cmd == "build":
        strings = []
        for i, s_val in enumerate(args.strings or []):
            strings.append(YaraString(f"$str_{i+1:02d}", s_val, "text", ["nocase"]))

        rule = YaraRule(
            name      = args.name,
            tags      = args.tags,
            meta      = YaraMeta(
                description = args.desc,
                author      = args.author,
                date        = datetime.now().strftime("%Y-%m-%d"),
            ),
            strings   = strings,
            condition = args.condition,
        )
        rendered = rule.render()
        print(f"\n{C.DIM}{rendered}{C.RESET}")

        validation = validate_rule_syntax(rendered)
        print_validation(validation)

        if args.output:
            Path(args.output).write_text(rendered)
            print(f"\n  {C.GREEN}[✓] Rule saved: {args.output}{C.RESET}")

    elif cmd == "template":
        if args.name == "list":
            print(f"\n  {C.BOLD}Available templates:{C.RESET}\n")
            for name, rule in RULE_TEMPLATES.items():
                print(f"  {C.CYAN}{name:<30}{C.RESET} {rule.meta.description[:60]}")
            print(f"\n  Usage: yara-builder template <name> -o output.yar")
            return

        rule     = RULE_TEMPLATES[args.name]
        rendered = rule.render()
        print(f"\n{C.DIM}{rendered}{C.RESET}")

        validation = validate_rule_syntax(rendered)
        print_validation(validation)

        if args.output:
            Path(args.output).write_text(rendered)
            print(f"\n  {C.GREEN}[✓] Rule saved: {args.output}{C.RESET}")

    elif cmd == "validate":
        rule_text  = Path(args.file).read_text()
        validation = validate_rule_syntax(rule_text)
        print_validation(validation)

    elif cmd == "scan":
        rule_text = Path(args.rule).read_text()
        target    = Path(args.target)

        files = []
        if target.is_file():
            files = [str(target)]
        elif target.is_dir():
            files = [str(f) for f in target.rglob("*") if f.is_file()]

        all_results = []
        for fp in files[:100]:
            result = scan_file_with_rule(fp, rule_text)
            all_results.append(result)
            if not args.json_out:
                print_scan_result(result)

        if args.json_out:
            print(json.dumps(all_results, indent=2))
        else:
            matched = sum(1 for r in all_results if r.get("matched"))
            print(f"\n{SEP}")
            print(f"  Files scanned: {len(all_results)} | "
                  f"Matches: {C.RED if matched else C.GREEN}{matched}{C.RESET}")


if __name__ == "__main__":
    main()

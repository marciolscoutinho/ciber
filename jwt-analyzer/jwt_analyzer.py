#!/usr/bin/env python3
"""
jwt_analyzer.py — JWT Security Analyzer v1.0.0
================================================
Analisa segurança de JSON Web Tokens: decode, verificação de claims,
deteção de algoritmos inseguros, brute-force de secrets fracos.

Autor  : Márcio Coutinho — Cibersecurity Specialist
Date   : 11/02/2025
Requis.: Python 3.8+ | Zero dependências externas
"""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, re, sys, time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
       ██╗██╗    ██╗████████╗
       ██║██║    ██║╚══██╔══╝
       ██║██║ █╗ ██║   ██║
  ██   ██║██║███╗██║   ██║
  ╚█████╔╝╚███╔███╔╝   ██║
   ╚════╝  ╚══╝╚══╝    ╚═╝  {C.RESET}{C.BOLD}ANALYZER{C.RESET}
{C.DIM} v{__version__} — JWT Security Analyzer | Decode · Verify · CVEs · Brute-Force{C.RESET}
"""

SEP = "━"*68

# ══════════════════════════════════════════════════════════════════════════════
# JWT PARSING
# ══════════════════════════════════════════════════════════════════════════════

def b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def parse_jwt(token: str) -> Tuple[Optional[dict], Optional[dict], str]:
    """Retorna (header, payload, signature_b64)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None, None, ""
    try:
        header  = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception as e:
        return None, None, str(e)

# ══════════════════════════════════════════════════════════════════════════════
# SECURITY CHECKS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class JWTFinding:
    severity: str
    title:    str
    detail:   str
    cve:      str = ""
    fix:      str = ""

DANGEROUS_ALGORITHMS = {
    "none":   ("CRITICAL", "Algorithm None — CVE-2015-9235",
               "Aceitar alg:none permite forjar tokens sem assinatura.",
               "CVE-2015-9235"),
    "hs256":  ("LOW",      "HMAC-SHA256 — verificar força do secret", ""),
    "hs384":  ("LOW",      "HMAC-SHA384", ""),
    "hs512":  ("LOW",      "HMAC-SHA512", ""),
    "rs256":  ("INFO",     "RSA-SHA256 — algoritmo assimétrico seguro", ""),
    "rs384":  ("INFO",     "RSA-SHA384", ""),
    "rs512":  ("INFO",     "RSA-SHA512", ""),
    "es256":  ("INFO",     "ECDSA-SHA256 — algoritmo assimétrico seguro", ""),
    "ps256":  ("INFO",     "RSA-PSS-SHA256 — algoritmo recomendado", ""),
}

# Weak secrets wordlist (top common JWT secrets)
WEAK_SECRETS = [
    "secret","password","123456","changeme","dev-secret","jwt-secret",
    "supersecret","mysecret","topsecret","pass","admin","test","key",
    "private","secret123","password123","jwt","token","auth","qwerty",
    "letmein","welcome","abc123","master","default","app-secret",
    "flask-secret","django-secret","rails-secret","express-secret",
    "your-256-bit-secret","your-secret-key","my-secret","HS256",
    "","a","1","0","null","undefined","false","true",
]


def check_security(header: dict, payload: dict, token: str) -> List[JWTFinding]:
    findings: List[JWTFinding] = []
    parts = token.strip().split(".")
    alg   = header.get("alg","").lower()

    # 1. Algorithm check
    if alg == "none":
        findings.append(JWTFinding(
            "CRITICAL", "Algorithm 'none' — Token sem assinatura",
            "O token usa alg:none, permitindo forjar tokens sem conhecer o secret.",
            "CVE-2015-9235",
            "Rejeitar tokens com alg:none. Validar algoritmo na whitelist."))

    # 2. Algorithm confusion (RS → HS)
    if alg.startswith("hs") and header.get("typ","").upper() == "JWT":
        findings.append(JWTFinding(
            "HIGH", "Possível Algorithm Confusion Attack",
            "Se o servidor aceitar HS256 com a chave pública RSA como secret, "
            "um atacante pode assinar tokens com a chave pública.",
            "CVE-2016-5431",
            "Usar lista branca de algoritmos. Nunca aceitar ambos RS* e HS* no mesmo endpoint."))

    # 3. Expiration
    exp = payload.get("exp")
    if exp is None:
        findings.append(JWTFinding(
            "HIGH", "Token sem expiração (exp)",
            "Tokens sem 'exp' são válidos indefinidamente — risco de replay attacks.",
            "",
            "Sempre definir 'exp'. Tokens de acesso: ≤ 15 min. Refresh: ≤ 7 dias."))
    elif isinstance(exp, (int,float)):
        now = time.time()
        if exp < now:
            delta = now - exp
            findings.append(JWTFinding(
                "MEDIUM", f"Token EXPIRADO há {_fmt_seconds(delta)}",
                f"exp={datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()}",
                "",
                "Token não deve ser aceite. Verificar rotação de tokens."))
        elif exp - now > 86400 * 30:
            findings.append(JWTFinding(
                "MEDIUM", f"Expiração muito longa ({_fmt_seconds(exp-now)})",
                "Tokens de acesso com longa validade aumentam o risco de abuso.",
                "",
                "Usar tokens de curta duração com refresh tokens."))

    # 4. Issued at
    iat = payload.get("iat")
    if iat and isinstance(iat, (int,float)):
        age = time.time() - iat
        if age > 86400 * 365:
            findings.append(JWTFinding(
                "LOW", f"Token muito antigo (emitido há {_fmt_seconds(age)})",
                "Token foi emitido há muito tempo.",
                "",
                "Verificar se o token ainda é válido no contexto da aplicação."))

    # 5. Sensitive claims em payload
    sensitive_patterns = [
        (re.compile(r"passw|secret|key|token|cred", re.I), "password/secret em claim"),
        (re.compile(r"ssn|social.security|tax.id|credit.card|cvv", re.I), "dado PII sensível"),
    ]
    for k, v in payload.items():
        for pattern, label in sensitive_patterns:
            if pattern.search(str(k)) or (isinstance(v, str) and pattern.search(v)):
                findings.append(JWTFinding(
                    "MEDIUM", f"Dado sensível no payload: '{k}'",
                    f"O payload JWT não é encriptado — qualquer um com o token pode ler '{k}'.",
                    "",
                    "Mover dados sensíveis para servidor. Usar JWE para encriptação."))
                break

    # 6. Kid header injection
    kid = header.get("kid","")
    if kid and any(c in kid for c in ["'",'"',";","--","/"]):
        findings.append(JWTFinding(
            "CRITICAL", "Kid Header Injection",
            f"O campo 'kid' contém caracteres suspeitos: {kid[:50]}",
            "",
            "Validar e sanitizar o 'kid'. Nunca usar em queries SQL/filesystem directamente."))

    # 7. JKU / X5U header (server-side request forgery potential)
    for hdr_key in ["jku","x5u"]:
        val = header.get(hdr_key,"")
        if val:
            findings.append(JWTFinding(
                "HIGH", f"Header '{hdr_key}' aponta para URL externa: {val[:80]}",
                "Atacante pode controlar a URL para fornecer uma chave pública maliciosa.",
                "",
                "Validar que jku/x5u está numa whitelist de URLs confiáveis."))

    return findings


def _fmt_seconds(s: float) -> str:
    if s < 60:    return f"{s:.0f}s"
    if s < 3600:  return f"{s/60:.1f} min"
    if s < 86400: return f"{s/3600:.1f}h"
    return f"{s/86400:.1f} dias"


# ══════════════════════════════════════════════════════════════════════════════
# SIGNATURE VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def verify_hs(token: str, secret: str, alg: str = "HS256") -> bool:
    """Verifica assinatura HMAC do JWT."""
    hash_fns = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}
    hash_fn  = hash_fns.get(alg.lower())
    if not hash_fn:
        return False
    parts    = token.strip().split(".")
    msg      = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(secret.encode(), msg, hash_fn).digest()
    expected_b64 = b64url_encode(expected)
    return hmac.compare_digest(expected_b64, parts[2])


def brute_force_secret(token: str, header: dict,
                       wordlist: Optional[List[str]] = None,
                       verbose: bool = False) -> Optional[str]:
    """Tenta descobrir o secret HMAC por brute-force."""
    alg = header.get("alg","HS256")
    if not alg.upper().startswith("HS"):
        return None

    secrets = wordlist or WEAK_SECRETS
    for secret in secrets:
        if verify_hs(token, secret, alg):
            return secret
        if verbose:
            print(f"  {C.DIM}Testando: {secret[:20]}{C.RESET}", end="\r")
    return None


# ══════════════════════════════════════════════════════════════════════════════
# TOKEN FORGERY (alg:none demo)
# ══════════════════════════════════════════════════════════════════════════════

def forge_none_token(header: dict, payload: dict) -> str:
    """Gera token com alg:none para demonstrar a vulnerabilidade."""
    forged_header = {**header, "alg": "none"}
    h = b64url_encode(json.dumps(forged_header, separators=(',',':')).encode())
    p = b64url_encode(json.dumps(payload,        separators=(',',':')).encode())
    return f"{h}.{p}."


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN,"INFO":C.DIM}

def print_decoded(header: dict, payload: dict, findings: List[JWTFinding]) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}HEADER{C.RESET}")
    for k, v in header.items():
        alg_col = C.RED if str(v).lower() == "none" else C.CYAN if k == "alg" else C.DIM
        print(f"    {C.DIM}{k:<12}{C.RESET} {alg_col}{v}{C.RESET}")

    print(f"\n  {C.BOLD}PAYLOAD{C.RESET}")
    for k, v in payload.items():
        display = v
        if k in ("exp","iat","nbf") and isinstance(v,(int,float)):
            try:
                dt = datetime.fromtimestamp(v, tz=timezone.utc)
                display = f"{v}  ({dt.isoformat()})"
            except Exception:
                pass
        print(f"    {C.DIM}{k:<12}{C.RESET} {display}")

    print(f"\n{SEP}")
    print(f"  {C.BOLD}SECURITY FINDINGS ({len(findings)}){C.RESET}")
    if not findings:
        print(f"  {C.GREEN}✅ Nenhuma vulnerabilidade óbvia detetada.{C.RESET}")
    for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity)):
        col = SEV_COL.get(f.severity,"")
        print(f"\n  {col}[{f.severity}]{C.RESET} {C.BOLD}{f.title}{C.RESET}")
        if f.cve:
            print(f"  {C.DIM}CVE     :{C.RESET} {f.cve}")
        print(f"  {C.DIM}Detalhe :{C.RESET} {f.detail}")
        if f.fix:
            print(f"  {C.DIM}Fix     :{C.RESET} {f.fix}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="jwt-analyzer",
        description="JWT Security Analyzer — Decode · Verify · Brute-Force")
    parser.add_argument("token", nargs="?", help="JWT token (ou stdin)")
    parser.add_argument("-s","--secret",  help="Verificar assinatura com este secret")
    parser.add_argument("--brute",  action="store_true", help="Brute-force de secrets fracos")
    parser.add_argument("--wordlist", help="Ficheiro com secrets (um por linha)")
    parser.add_argument("--forge-none", action="store_true",
        help="Demonstrar alg:none — gerar token sem assinatura")
    parser.add_argument("--modify-claim", nargs=2, metavar=("KEY","VALUE"),
        help="Modificar claim e re-assinar (requer --secret)")
    parser.add_argument("-v","--verbose", action="store_true")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_out")
    parser.add_argument("--version", action="version", version=f"jwt-analyzer {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    # Ler token
    token = args.token
    if not token:
        if not sys.stdin.isatty():
            token = sys.stdin.read().strip()
        else:
            print("  Introduz o JWT: ", end="")
            token = input().strip()

    if not token:
        print(f"{C.RED}[ERRO] Token não fornecido.{C.RESET}")
        sys.exit(1)

    header, payload, sig = parse_jwt(token)
    if header is None:
        print(f"{C.RED}[ERRO] JWT inválido: {sig}{C.RESET}")
        sys.exit(1)

    findings = check_security(header, payload, token)

    if args.json_out:
        out = {
            "header": header, "payload": payload,
            "findings": [f.__dict__ for f in findings],
            "alg": header.get("alg"),
        }
        print(json.dumps(out, indent=2, default=str))
        return

    print_decoded(header, payload, findings)

    # Verificação de assinatura
    alg = header.get("alg","").upper()
    if args.secret and alg.startswith("HS"):
        print(f"\n{SEP}")
        valid = verify_hs(token, args.secret, alg)
        if valid:
            print(f"  {C.GREEN}✅ Assinatura VÁLIDA com o secret fornecido.{C.RESET}")
        else:
            print(f"  {C.RED}❌ Assinatura INVÁLIDA com o secret fornecido.{C.RESET}")

    # Brute-force
    if args.brute and alg.startswith("HS"):
        print(f"\n{SEP}")
        print(f"  {C.DIM}Iniciando brute-force de secrets...{C.RESET}")
        wordlist = None
        if args.wordlist:
            wordlist = [l.strip() for l in open(args.wordlist) if l.strip()]
            print(f"  {C.DIM}Wordlist: {len(wordlist)} secrets{C.RESET}")
        found = brute_force_secret(token, header, wordlist, verbose=args.verbose)
        if found:
            print(f"\n  {C.RED}{C.BOLD}⚠  SECRET ENCONTRADO: '{found}'{C.RESET}")
            print(f"  {C.YELLOW}O token pode ser forjado com este secret!{C.RESET}")
        else:
            print(f"  {C.GREEN}Secret não encontrado na wordlist.{C.RESET}")

    # Forge alg:none
    if args.forge_none:
        print(f"\n{SEP}")
        print(f"  {C.RED}{C.BOLD}⚠  ALG:NONE DEMO — Token forjado:{C.RESET}")
        forged = forge_none_token(header, payload)
        print(f"  {C.YELLOW}{forged}{C.RESET}")
        print(f"  {C.DIM}Este token não tem assinatura. Se o servidor aceitar, é vulnerável a CVE-2015-9235.{C.RESET}")

    # Modify claim
    if args.modify_claim and args.secret:
        key, val = args.modify_claim
        new_payload = {**payload}
        try: new_payload[key] = json.loads(val)
        except: new_payload[key] = val
        new_header = json.dumps(header, separators=(',',':')).encode()
        new_pay    = json.dumps(new_payload, separators=(',',':')).encode()
        h_enc = b64url_encode(new_header)
        p_enc = b64url_encode(new_pay)
        msg   = f"{h_enc}.{p_enc}".encode()
        hash_fns = {"HS256":hashlib.sha256,"HS384":hashlib.sha384,"HS512":hashlib.sha512}
        hfn   = hash_fns.get(alg, hashlib.sha256)
        sig_new = b64url_encode(hmac.new(args.secret.encode(), msg, hfn).digest())
        new_token = f"{h_enc}.{p_enc}.{sig_new}"
        print(f"\n{SEP}")
        print(f"  {C.YELLOW}Token modificado ({key}={val}):{C.RESET}")
        print(f"  {new_token}")

if __name__ == "__main__":
    main()

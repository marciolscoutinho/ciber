#!/usr/bin/env python3
"""
ssh_hardening.py — SSH Hardening Checker v1.0.0
================================================
Audita configurações SSH (sshd_config) contra CIS Benchmark,
NIST SP 800-53 e melhores práticas do setor.

Autor  : Márcio Coutinho — Cibersecurity Specialist
Date   : 10/11/2024
Requis.: Python 3.8+ | Zero dependências externas
"""
from __future__ import annotations
import argparse, json, re, subprocess, sys
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
  ███████╗███████╗██╗  ██╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗
  ██╔════╝██╔════╝██║  ██║    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║
  ███████╗███████╗███████║    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║
  ╚════██║╚════██║██╔══██║    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║
  ███████║███████║██║  ██║    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║
  ╚══════╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝{C.RESET}
{C.DIM} v{__version__} — SSH Hardening Checker | CIS Benchmark | NIST SP 800-53{C.RESET}
"""
SEP  = "━"*68
SEP2 = "═"*68

# ══════════════════════════════════════════════════════════════════════════════
# CHECK DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SSHCheck:
    id:          str
    severity:    str
    title:       str
    directive:   str          # nome da directiva sshd_config
    test:        str          # expected value / condition
    description: str
    remediation: str
    cis_ref:     str = ""
    default:     str = ""     # valor default do OpenSSH

@dataclass
class CheckResult:
    check:      SSHCheck
    status:     str           # PASS / FAIL / WARN / SKIP
    actual:     str           # valor encontrado
    expected:   str

SSH_CHECKS: List[SSHCheck] = [
    # ── Autenticação ─────────────────────────────────────────────────────────
    SSHCheck("SSH-001","CRITICAL","Root login desativado",
        "PermitRootLogin","no",
        "Permitir login direto como root expõe o sistema ao risco de acesso total sem MFA.",
        "Definir 'PermitRootLogin no' em sshd_config. Usar sudo para operações root.",
        "CIS 5.2.10", "prohibit-password"),
    SSHCheck("SSH-002","CRITICAL","Autenticação por password desativada",
        "PasswordAuthentication","no",
        "Autenticação por password é vulnerável a brute-force. Usar apenas chaves públicas.",
        "Definir 'PasswordAuthentication no'. Distribuir chaves públicas com ssh-copy-id.",
        "CIS 5.2.12", "yes"),
    SSHCheck("SSH-003","HIGH","Passwords vazias proibidas",
        "PermitEmptyPasswords","no",
        "Contas com password vazia representam risco imediato de comprometimento.",
        "Definir 'PermitEmptyPasswords no'.",
        "CIS 5.2.11", "no"),
    SSHCheck("SSH-004","HIGH","Autenticação por chave pública ativa",
        "PubkeyAuthentication","yes",
        "A autenticação por chave pública deve estar ativa para substituir passwords.",
        "Definir 'PubkeyAuthentication yes'.",
        "CIS 5.2.1", "yes"),
    SSHCheck("SSH-005","MEDIUM","Challenge-Response Authentication desativada",
        "ChallengeResponseAuthentication","no",
        "Pode permitir bypass de controlos de autenticação em certas configurações PAM.",
        "Definir 'ChallengeResponseAuthentication no'.",
        "CIS 5.2.14", "no"),
    SSHCheck("SSH-006","MEDIUM","Kerberos Authentication desativada (se não usada)",
        "KerberosAuthentication","no",
        "Se Kerberos não é usado, desativar reduz a superfície de ataque.",
        "Definir 'KerberosAuthentication no' se Kerberos não está em uso.",
        "", "no"),
    SSHCheck("SSH-007","MEDIUM","GSSAPI Authentication desativada (se não usada)",
        "GSSAPIAuthentication","no",
        "GSSAPI pode revelar nomes de utilizadores internos. Desativar se não necessário.",
        "Definir 'GSSAPIAuthentication no' se GSSAPI não é usado.",
        "CIS 5.2.15", "no"),

    # ── Protocolo e Criptografia ──────────────────────────────────────────────
    SSHCheck("SSH-010","CRITICAL","Algoritmos de chave fraca removidos",
        "HostKeyAlgorithms",
        "no-ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521",
        "Algoritmos NIST P-curve podem ter backdoors. Preferir Ed25519 e RSA-SHA2.",
        "HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
        "", ""),
    SSHCheck("SSH-011","HIGH","Ciphers seguros configurados",
        "Ciphers","chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        "Ciphers fracos como 3DES, RC4, ou CBC sem MAC podem ser vulneráveis.",
        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "CIS 5.2.2", ""),
    SSHCheck("SSH-012","HIGH","MACs seguros configurados",
        "MACs","hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
        "MACs fracos (MD5, SHA-1) são criptograficamente quebrados.",
        "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
        "CIS 5.2.3", ""),
    SSHCheck("SSH-013","HIGH","KexAlgorithms seguros configurados",
        "KexAlgorithms","curve25519-sha256,diffie-hellman-group16-sha512",
        "Algoritmos de troca de chave fracos permitem ataques Logjam/FREAK.",
        "KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
        "CIS 5.2.4", ""),

    # ── Timeouts e Limites ────────────────────────────────────────────────────
    SSHCheck("SSH-020","HIGH","Timeout de autenticação configurado",
        "LoginGraceTime","60",
        "Tempo longo de grace permite ataques prolongados de autenticação.",
        "Definir 'LoginGraceTime 60' (ou menos).",
        "CIS 5.2.16", "120"),
    SSHCheck("SSH-021","HIGH","Tentativas de autenticação limitadas",
        "MaxAuthTries","4",
        "Sem limite, brute-force pode testar muitas passwords por sessão.",
        "Definir 'MaxAuthTries 4' (ou menos).",
        "CIS 5.2.7", "6"),
    SSHCheck("SSH-022","MEDIUM","Sessões simultâneas limitadas",
        "MaxSessions","4",
        "Limitar sessões reduz impacto de compromisso e uso indevido de multiplexing.",
        "Definir 'MaxSessions 4'.",
        "CIS 5.2.8", "10"),
    SSHCheck("SSH-023","MEDIUM","Sessões inativas terminam automaticamente",
        "ClientAliveInterval","300",
        "Sessões inativas podem ser sequestradas. Definir timeout de atividade.",
        "Definir 'ClientAliveInterval 300' e 'ClientAliveCountMax 0'.",
        "CIS 5.2.6", "0"),
    SSHCheck("SSH-024","MEDIUM","ClientAliveCountMax configurado",
        "ClientAliveCountMax","0",
        "Com CountMax=0 e Interval>0, sessão é terminada após um intervalo sem atividade.",
        "Definir 'ClientAliveCountMax 0'.",
        "CIS 5.2.6", "3"),

    # ── Porto e Acesso ────────────────────────────────────────────────────────
    SSHCheck("SSH-030","MEDIUM","Porto SSH não padrão (recomendado)",
        "Port","22",
        "Porto 22 é o alvo de scanners automatizados. Mudar reduz ruído de logs.",
        "Considerar mudar para porto não padrão (ex: 2222). Não é medida de segurança primária.",
        "", "22"),
    SSHCheck("SSH-031","HIGH","ListenAddress restrito (se possível)",
        "ListenAddress","0.0.0.0",
        "Se SSH só é necessário em interfaces específicas, restringir reduz exposição.",
        "Definir 'ListenAddress <IP_interno>' se SSH não precisa de estar em todas as interfaces.",
        "", "0.0.0.0"),
    SSHCheck("SSH-032","HIGH","AllowUsers ou AllowGroups configurado",
        "AllowUsers","",
        "Sem AllowUsers/AllowGroups, qualquer utilizador válido pode tentar login SSH.",
        "Definir 'AllowUsers user1 user2' ou 'AllowGroups sshusers' para restringir acesso.",
        "CIS 5.2.18", ""),
    SSHCheck("SSH-033","MEDIUM","DenyUsers configurado para contas sensíveis",
        "DenyUsers","",
        "Explicitamente bloquear contas de sistema (daemon, bin, sys) de login SSH.",
        "Definir 'DenyUsers nobody daemon bin sys'.",
        "", ""),

    # ── Features de Segurança ─────────────────────────────────────────────────
    SSHCheck("SSH-040","HIGH","X11 Forwarding desativado",
        "X11Forwarding","no",
        "X11 Forwarding pode ser explorado para ataques de captura de input.",
        "Definir 'X11Forwarding no' se não é necessário.",
        "CIS 5.2.5", "no"),
    SSHCheck("SSH-041","MEDIUM","TCP Forwarding desativado",
        "AllowTcpForwarding","no",
        "TCP tunneling pode ser usado para bypass de controlos de rede.",
        "Definir 'AllowTcpForwarding no' se tunneling não é necessário.",
        "CIS 5.2.20", "yes"),
    SSHCheck("SSH-042","MEDIUM","Agent Forwarding desativado",
        "AllowAgentForwarding","no",
        "Agent forwarding expõe a chave privada a servidores comprometidos.",
        "Definir 'AllowAgentForwarding no'.",
        "CIS 5.2.21", "yes"),
    SSHCheck("SSH-043","MEDIUM","Banner de aviso configurado",
        "Banner","/etc/issue.net",
        "Banner legal notifica utilizadores não autorizados e pode ter valor legal.",
        "Definir 'Banner /etc/issue.net' e configurar mensagem de aviso legal.",
        "CIS 5.2.22", "none"),
    SSHCheck("SSH-044","LOW","PrintLastLog ativo",
        "PrintLastLog","yes",
        "Mostrar último login ajuda utilizadores a detetar acessos não autorizados.",
        "Definir 'PrintLastLog yes'.",
        "", "yes"),
    SSHCheck("SSH-045","HIGH","StrictModes ativo",
        "StrictModes","yes",
        "StrictModes verifica permissões dos ficheiros de configuração do utilizador.",
        "Definir 'StrictModes yes'.",
        "", "yes"),
    SSHCheck("SSH-046","MEDIUM","UsePrivilegeSeparation ativo",
        "UsePrivilegeSeparation","sandbox",
        "Separação de privilégios limita o impacto de vulnerabilidades no sshd.",
        "Definir 'UsePrivilegeSeparation sandbox' (OpenSSH >= 6.1).",
        "", "sandbox"),
    SSHCheck("SSH-047","MEDIUM","Compression desativada ou after-auth",
        "Compression","delayed",
        "Compressão antes de autenticação pode ser usada em ataques de oráculo.",
        "Definir 'Compression delayed' ou 'Compression no'.",
        "", "delayed"),
    SSHCheck("SSH-048","LOW","LogLevel configurado",
        "LogLevel","VERBOSE",
        "Logging verbose captura mais detalhes para análise de incidentes.",
        "Definir 'LogLevel VERBOSE' para auditoria completa.",
        "CIS 5.2.24", "INFO"),
    SSHCheck("SSH-049","HIGH","Ignore RhostsRSAAuthentication",
        "IgnoreRhosts","yes",
        "Ficheiros .rhosts permitem autenticação sem password — extremamente inseguro.",
        "Definir 'IgnoreRhosts yes'.",
        "CIS 5.2.9", "yes"),
    SSHCheck("SSH-050","HIGH","HostbasedAuthentication desativada",
        "HostbasedAuthentication","no",
        "Autenticação baseada em host é insegura pois confia no nome do host remoto.",
        "Definir 'HostbasedAuthentication no'.",
        "CIS 5.2.9", "no"),
]

# ══════════════════════════════════════════════════════════════════════════════
# PARSER
# ══════════════════════════════════════════════════════════════════════════════

def parse_sshd_config(content: str) -> Dict[str, str]:
    """Parse sshd_config em dict {directive: value}."""
    config: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            config[parts[0]] = parts[1].strip()
    return config

def get_live_config() -> Optional[str]:
    """Obtém configuração SSH ativa do sistema."""
    try:
        r = subprocess.run(["sshd","-T"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    # Tentar ler ficheiro diretamente
    for path in ["/etc/ssh/sshd_config", "/etc/sshd_config"]:
        p = Path(path)
        if p.exists():
            return p.read_text(errors="replace")
    return None

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _check_value(directive: str, actual: str,
                 expected: str, check_id: str) -> Tuple[str,str]:
    """Retorna (status, expected_display)."""
    if not actual:
        # Directiva não encontrada — usar default
        return "SKIP", f"não configurado (default: desconhecido)"

    actual_lower   = actual.lower()
    expected_lower = expected.lower()

    # Checks numéricos (<= ou >=)
    if check_id in ("SSH-020","SSH-021","SSH-022","SSH-023","SSH-024"):
        try:
            actual_n   = int(actual)
            expected_n = int(expected)
            # LoginGraceTime, MaxAuthTries, MaxSessions, ClientAliveCountMax → <=
            if check_id in ("SSH-020","SSH-021","SSH-022","SSH-024"):
                status = "PASS" if actual_n <= expected_n else "FAIL"
            else:  # ClientAliveInterval → > 0
                status = "PASS" if actual_n > 0 else "FAIL"
            return status, f"<= {expected_n}"
        except ValueError:
            pass

    # Check "not empty" (AllowUsers, AllowGroups)
    if check_id in ("SSH-032","SSH-033"):
        return ("PASS" if actual.strip() else "WARN"), "configurado"

    # Check "not 22" (porto)
    if check_id == "SSH-030":
        return ("WARN" if actual == "22" else "PASS"), "!= 22"

    # Check "not 0.0.0.0" (ListenAddress)
    if check_id == "SSH-031":
        return ("WARN" if actual in ("0.0.0.0","::") else "PASS"), "específico"

    # Check de presença de valores seguros (Ciphers, MACs, KexAlgorithms)
    if check_id in ("SSH-011","SSH-012","SSH-013"):
        # Verificar se não contém algoritmos inseguros
        weak_ciphers = ["3des","arcfour","rc4","blowfish","cast","aes128-cbc",
                        "aes192-cbc","aes256-cbc","md5","sha1-"]
        has_weak = any(w in actual_lower for w in weak_ciphers)
        return ("FAIL" if has_weak else "PASS"), f"sem algoritmos fracos"

    # Check de HostKeyAlgorithms
    if check_id == "SSH-010":
        weak = ["ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ssh-dss"]
        has_weak = any(w in actual_lower for w in weak)
        return ("FAIL" if has_weak else "PASS"), "sem ECDSA NIST/DSS"

    # Check simples de igualdade (yes/no)
    if actual_lower == expected_lower:
        return "PASS", expected
    # Alguns valores aceitáveis para "no"
    if expected_lower == "no" and actual_lower in ("no","false","0"):
        return "PASS", expected
    if expected_lower == "yes" and actual_lower in ("yes","true","1"):
        return "PASS", expected

    return "FAIL", expected


def run_audit(config: Dict[str, str]) -> List[CheckResult]:
    results: List[CheckResult] = []
    for check in SSH_CHECKS:
        # Case-insensitive directive lookup
        actual = ""
        for key, val in config.items():
            if key.lower() == check.directive.lower():
                actual = val
                break
        status, expected_display = _check_value(
            check.directive, actual, check.test, check.id)
        results.append(CheckResult(check, status, actual or "(não definido)", expected_display))
    return results

# ══════════════════════════════════════════════════════════════════════════════
# SCORING
# ══════════════════════════════════════════════════════════════════════════════

def compute_score(results: List[CheckResult]) -> float:
    weights = {"CRITICAL":3,"HIGH":2,"MEDIUM":1,"LOW":0.5}
    total_w  = sum(weights.get(r.check.severity,1) for r in results if r.status != "SKIP")
    passed_w = sum(weights.get(r.check.severity,1)
                   for r in results if r.status == "PASS")
    return round(passed_w / total_w * 100, 1) if total_w else 0.0

# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

SEV_COL = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN}
STATUS_COL = {"PASS":C.GREEN,"FAIL":C.RED,"WARN":C.YELLOW,"SKIP":C.DIM}
STATUS_ICON = {"PASS":"✅","FAIL":"❌","WARN":"⚠️ ","SKIP":"⏭️ "}

def print_results(results: List[CheckResult], show_pass: bool = False) -> None:
    for r in results:
        if r.status == "PASS" and not show_pass:
            continue
        sc = STATUS_COL.get(r.status, "")
        sv = SEV_COL.get(r.check.severity, "")
        icon = STATUS_ICON.get(r.status,"")
        print(f"\n  {icon} {sc}[{r.status}]{C.RESET}  "
              f"{sv}[{r.check.severity}]{C.RESET}  {C.BOLD}{r.check.title}{C.RESET}")
        print(f"     {C.DIM}Directiva:{C.RESET} {r.check.directive}")
        print(f"     {C.DIM}Actual   :{C.RESET} {C.YELLOW}{r.actual}{C.RESET}")
        print(f"     {C.DIM}Esperado :{C.RESET} {r.expected}")
        if r.status not in ("PASS","SKIP"):
            print(f"     {C.DIM}Fix      :{C.RESET} {r.check.remediation[:100]}")

def print_summary(results: List[CheckResult], score: float) -> None:
    score_col = C.GREEN if score>=80 else C.YELLOW if score>=60 else C.RED
    bar_len = int(score/100*40)
    bar = "█"*bar_len + "░"*(40-bar_len)
    by_status: Dict[str,int] = {}
    for r in results:
        by_status[r.status] = by_status.get(r.status,0)+1

    print(f"\n{SEP2}")
    print(f"  {C.BOLD}SSH HARDENING AUDIT SUMMARY{C.RESET}")
    print(SEP)
    print(f"  {score_col}{C.BOLD}Score: {score}/100{C.RESET}  [{bar}]")
    print(f"  ✅ PASS: {by_status.get('PASS',0)}  "
          f"❌ FAIL: {by_status.get('FAIL',0)}  "
          f"⚠️  WARN: {by_status.get('WARN',0)}  "
          f"⏭️  SKIP: {by_status.get('SKIP',0)}")
    print(SEP)
    fails = [r for r in results if r.status == "FAIL"]
    if fails:
        print(f"\n  {C.BOLD}Ações prioritárias:{C.RESET}")
        for r in sorted(fails, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.check.severity)):
            col = SEV_COL.get(r.check.severity,"")
            print(f"  {col}●{C.RESET} {r.check.directive:<35} → {r.check.remediation[:60]}")
    print(SEP2)

def generate_markdown(results: List[CheckResult], score: float,
                       source: str) -> str:
    lines = [
        f"# 🔐 SSH Hardening Report",
        f"**Fonte:** {source} | **Data:** {datetime.now().strftime('%Y-%m-%d %H:%M')} | **Score:** {score}/100",
        f"",
        f"## Resultado",
        f"",
        f"| Status | Count |",
        f"|---|:---:|",
    ]
    by_s: Dict[str,int] = {}
    for r in results:
        by_s[r.status] = by_s.get(r.status,0)+1
    em = {"PASS":"✅","FAIL":"❌","WARN":"⚠️","SKIP":"⏭️"}
    for s in ("PASS","FAIL","WARN","SKIP"):
        lines.append(f"| {em.get(s,'')} {s} | **{by_s.get(s,0)}** |")
    lines += ["","## Checks","",
              "| ID | Severidade | Directiva | Status | Actual | Fix |",
              "|---|:---:|---|:---:|---|---|"]
    sev_em = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    st_em  = {"PASS":"✅","FAIL":"❌","WARN":"⚠️","SKIP":"⏭️"}
    for r in results:
        lines.append(
            f"| {r.check.id} | {sev_em.get(r.check.severity,'')} {r.check.severity} "
            f"| `{r.check.directive}` | {st_em.get(r.status,'')} {r.status} "
            f"| `{r.actual[:30]}` | {r.check.remediation[:60]} |")
    lines += ["",f"*Gerado por ssh-hardening v{__version__}*"]
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="ssh-hardening",
        description="SSH Hardening Checker — CIS Benchmark | NIST SP 800-53")
    parser.add_argument("config", nargs="?", help="Ficheiro sshd_config (omitir = sistema local)")
    parser.add_argument("--live",     action="store_true", help="Ler config ativa (sshd -T)")
    parser.add_argument("--show-pass",action="store_true", help="Mostrar também checks OK")
    parser.add_argument("-o","--output", help="Guardar report Markdown")
    parser.add_argument("--json",     action="store_true", dest="json_out")
    parser.add_argument("--no-banner",action="store_true")
    parser.add_argument("--version",  action="version", version=f"ssh-hardening {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    # Obter configuração
    source = "sistema local"
    if args.config:
        source  = args.config
        content = Path(args.config).read_text(errors="replace")
    elif args.live:
        source  = "sshd -T (config ativa)"
        content = get_live_config()
        if not content:
            print(f"  {C.RED}[ERRO] Não foi possível obter config SSH.{C.RESET}")
            sys.exit(1)
    else:
        content = get_live_config()
        if not content:
            # Demo config insegura
            print(f"  {C.YELLOW}Config SSH não encontrada. Usando config de demonstração (insegura).{C.RESET}")
            source  = "demo (insegura)"
            content = """
Protocol 2
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding yes
MaxAuthTries 6
LoginGraceTime 120
ClientAliveInterval 0
AllowTcpForwarding yes
"""

    print(f"  {C.DIM}Fonte: {source}{C.RESET}")
    config  = parse_sshd_config(content)
    results = run_audit(config)
    score   = compute_score(results)

    if args.json_out:
        out = {
            "source": source, "timestamp": datetime.now().isoformat(),
            "score": score,
            "results": [{
                "id": r.check.id, "severity": r.check.severity,
                "directive": r.check.directive, "status": r.status,
                "actual": r.actual, "remediation": r.check.remediation,
            } for r in results],
        }
        print(json.dumps(out, indent=2))
    else:
        print_results(results, show_pass=args.show_pass)
        print_summary(results, score)

    if args.output:
        md = generate_markdown(results, score, source)
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"\n  {C.GREEN}[✓] Report: {args.output}{C.RESET}")

    fails = sum(1 for r in results if r.status=="FAIL"
                and r.check.severity in ("CRITICAL","HIGH"))
    sys.exit(2 if fails > 0 else 0)

if __name__ == "__main__":
    main()

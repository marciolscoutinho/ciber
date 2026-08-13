#!/usr/bin/env python3
"""
sbom_generator.py — SBOM Generator v1.0.0
==========================================
Gera Software Bill of Materials (SBOM) no formato CycloneDX 1.4 (JSON/XML).
Standard adotado por CISA, US Executive Order 14028, e NIS2.

Autor  : Márcio Coutinho — Cibersecurity Specialist
Date   : 23/04/2022
Requis.: Python 3.8+ | Zero dependências externas
"""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess, sys, uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

__version__ = "1.0.0"

class C:
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
  ███████╗██████╗  ██████╗ ███╗   ███╗
  ██╔════╝██╔══██╗██╔═══██╗████╗ ████║
  ███████╗██████╔╝██║   ██║██╔████╔██║
  ╚════██║██╔══██╗██║   ██║██║╚██╔╝██║
  ███████║██████╔╝╚██████╔╝██║ ╚═╝ ██║
  ╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝{C.RESET}
{C.DIM} v{__version__} — SBOM Generator | CycloneDX 1.4 | JSON + XML | SPDX-compatible{C.RESET}
{C.DIM} CISA SBOM Mandate | US EO 14028 | NIS2 Supply Chain{C.RESET}
"""

SEP = "━"*68

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS (CycloneDX 1.4)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Hash:
    alg:   str   # SHA-256, SHA-1, MD5
    value: str

@dataclass
class ExternalReference:
    type:  str   # vcs, website, advisories, distribution
    url:   str

@dataclass
class License:
    id:   str    # SPDX identifier
    name: str

@dataclass
class Component:
    type:        str          # library, framework, application, container
    bom_ref:     str          # unique reference
    name:        str
    version:     str
    purl:        str          # Package URL (pkg:pypi/name@version)
    description: str = ""
    author:      str = ""
    licenses:    List[License] = field(default_factory=list)
    hashes:      List[Hash]   = field(default_factory=list)
    ext_refs:    List[ExternalReference] = field(default_factory=list)
    properties:  Dict[str,str] = field(default_factory=dict)

@dataclass
class Metadata:
    timestamp:   str
    tools:       List[dict]
    component:   Optional[Component]
    authors:     List[str]

@dataclass
class SBOM:
    bom_format:  str = "CycloneDX"
    spec_version:str = "1.4"
    version:     int = 1
    serial_number:str = ""
    metadata:    Optional[Metadata] = None
    components:  List[Component] = field(default_factory=list)
    dependencies:List[dict]      = field(default_factory=list)

# ══════════════════════════════════════════════════════════════════════════════
# PURL BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_purl(ecosystem: str, name: str, version: str) -> str:
    """Constrói Package URL (purl) standard."""
    eco_map = {"pip":"pypi", "npm":"npm", "apt":"deb", "cargo":"cargo",
               "gem":"gem", "nuget":"nuget", "maven":"maven"}
    purl_eco = eco_map.get(ecosystem, ecosystem)
    ver_str  = f"@{version}" if version and version != "unknown" else ""
    name_enc = name.lower().replace(" ","-")
    return f"pkg:{purl_eco}/{name_enc}{ver_str}"

# ══════════════════════════════════════════════════════════════════════════════
# PACKAGE DISCOVERY
# ══════════════════════════════════════════════════════════════════════════════

def _run(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception: return ""

def collect_pip_packages() -> List[dict]:
    out = _run(f"{sys.executable} -m pip list --format=json")
    try:
        pkgs = json.loads(out)
        result = []
        for p in pkgs:
            name = p.get("name","")
            ver  = p.get("version","")
            # Tentar obter licença e URL
            info_out = _run(f"{sys.executable} -m pip show {name}")
            info: Dict[str,str] = {}
            for line in info_out.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    info[k.strip()] = v.strip()
            result.append({
                "name": name, "version": ver, "ecosystem": "pip",
                "license": info.get("License","UNKNOWN"),
                "home_page": info.get("Home-page",""),
                "author": info.get("Author",""),
                "summary": info.get("Summary",""),
            })
        return result
    except Exception: return []


def collect_npm_packages(project_path: str = ".") -> List[dict]:
    out = _run(f"npm list --json --prefix {project_path} 2>/dev/null")
    pkgs = []
    try:
        data = json.loads(out)
        for name, info in data.get("dependencies",{}).items():
            pkgs.append({
                "name": name,
                "version": info.get("version",""),
                "ecosystem": "npm",
                "license": "", "home_page": "", "author": "", "summary": "",
            })
    except Exception: pass
    return pkgs


def collect_from_manifests(project_path: str) -> List[dict]:
    """Recolhe dependências de ficheiros de manifesto sem execução."""
    from pathlib import Path as P
    root = P(project_path)
    pkgs = []
    skip = {"node_modules",".venv","venv","env",".git"}

    # requirements.txt
    for req in root.rglob("requirements*.txt"):
        if any(s in req.parts for s in skip): continue
        for line in req.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#","-")): continue
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!~^]+\s*[\w\.\*]+)?", line)
            if m:
                name = m.group(1)
                ver  = re.sub(r"[><=!~^]","", m.group(2) or "").strip()
                pkgs.append({"name":name,"version":ver or "unknown",
                             "ecosystem":"pip","license":"","home_page":"",
                             "author":"","summary":""})

    # package.json
    for pj in root.rglob("package.json"):
        if any(s in pj.parts for s in skip): continue
        try:
            data = json.loads(pj.read_text(errors="replace"))
            for sec in ("dependencies","devDependencies"):
                for name, ver in data.get(sec,{}).items():
                    pkgs.append({"name":name,"version":ver.lstrip("^~>=<"),
                                 "ecosystem":"npm","license":"","home_page":"",
                                 "author":"","summary":""})
        except Exception: pass

    # Deduplicar
    seen = set()
    unique = []
    for p in pkgs:
        key = (p["name"].lower(), p["ecosystem"])
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique

# ══════════════════════════════════════════════════════════════════════════════
# SBOM BUILDER
# ══════════════════════════════════════════════════════════════════════════════

SPDX_LICENSES = {
    "mit":"MIT","apache-2.0":"Apache-2.0","gpl-2.0":"GPL-2.0-only",
    "gpl-3.0":"GPL-3.0-only","lgpl-2.1":"LGPL-2.1-only","bsd-2-clause":"BSD-2-Clause",
    "bsd-3-clause":"BSD-3-Clause","isc":"ISC","mpl-2.0":"MPL-2.0",
    "agpl-3.0":"AGPL-3.0-only","cc0-1.0":"CC0-1.0","unlicense":"Unlicense",
    "unknown":"NOASSERTION","":"NOASSERTION",
}

def normalize_license(lic_str: str) -> str:
    return SPDX_LICENSES.get(lic_str.lower().strip(), lic_str or "NOASSERTION")


def build_sbom(pkgs: List[dict], project_name: str = "project",
                project_version: str = "1.0.0",
                author: str = "Márcio Coutinho") -> SBOM:
    serial = f"urn:uuid:{uuid.uuid4()}"
    ts     = datetime.now(timezone.utc).isoformat()

    # Root component (o próprio projeto)
    root_comp = Component(
        type        = "application",
        bom_ref     = "root-component",
        name        = project_name,
        version     = project_version,
        purl        = f"pkg:generic/{project_name.lower()}@{project_version}",
        description = f"Software project: {project_name}",
        author      = author,
    )

    metadata = Metadata(
        timestamp = ts,
        tools     = [{"vendor":"Márcio Coutinho",
                      "name":"sbom-generator",
                      "version":__version__}],
        component = root_comp,
        authors   = [author],
    )

    components: List[Component] = []
    dep_refs: List[str] = []

    for p in pkgs:
        name = p["name"]
        ver  = p.get("version","unknown")
        eco  = p.get("ecosystem","pip")
        ref  = f"comp-{name.lower().replace(' ','-')}-{eco}"

        lic_spdx = normalize_license(p.get("license",""))
        lic_list = [License(id=lic_spdx, name=lic_spdx)] if lic_spdx != "NOASSERTION" else []

        ext_refs = []
        if p.get("home_page"):
            ext_refs.append(ExternalReference("website", p["home_page"]))

        purl = build_purl(eco, name, ver)

        comp = Component(
            type        = "library",
            bom_ref     = ref,
            name        = name,
            version     = ver,
            purl        = purl,
            description = p.get("summary","")[:200],
            author      = p.get("author",""),
            licenses    = lic_list,
            ext_refs    = ext_refs,
            properties  = {"ecosystem": eco},
        )
        components.append(comp)
        dep_refs.append(ref)

    # Dependências (root depende de tudo)
    dependencies = [{"ref":"root-component","dependsOn":dep_refs}]
    for comp in components:
        dependencies.append({"ref":comp.bom_ref,"dependsOn":[]})

    return SBOM(
        serial_number = serial,
        metadata      = metadata,
        components    = components,
        dependencies  = dependencies,
    )

# ══════════════════════════════════════════════════════════════════════════════
# SERIALIZERS
# ══════════════════════════════════════════════════════════════════════════════

def to_cyclonedx_json(sbom: SBOM) -> dict:
    """Serializa SBOM para CycloneDX 1.4 JSON."""
    meta = sbom.metadata

    def comp_to_dict(c: Component) -> dict:
        d: dict = {
            "type":    c.type,
            "bom-ref": c.bom_ref,
            "name":    c.name,
            "version": c.version,
            "purl":    c.purl,
        }
        if c.description: d["description"] = c.description
        if c.author:      d["author"]      = c.author
        if c.licenses:
            d["licenses"] = [{"license":{"id":l.id,"name":l.name}} for l in c.licenses]
        if c.hashes:
            d["hashes"] = [{"alg":h.alg,"content":h.value} for h in c.hashes]
        if c.ext_refs:
            d["externalReferences"] = [{"type":r.type,"url":r.url} for r in c.ext_refs]
        if c.properties:
            d["properties"] = [{"name":k,"value":v} for k,v in c.properties.items()]
        return d

    out = {
        "bomFormat":    sbom.bom_format,
        "specVersion":  sbom.spec_version,
        "version":      sbom.version,
        "serialNumber": sbom.serial_number,
        "metadata": {
            "timestamp": meta.timestamp,
            "tools": meta.tools,
            "component": comp_to_dict(meta.component) if meta.component else {},
            "authors": [{"name": a} for a in meta.authors],
        },
        "components":   [comp_to_dict(c) for c in sbom.components],
        "dependencies": sbom.dependencies,
    }
    return out


def to_cyclonedx_xml(sbom: SBOM) -> str:
    """Serializa SBOM para CycloneDX 1.4 XML."""
    meta = sbom.metadata
    ts   = meta.timestamp if meta else datetime.now(timezone.utc).isoformat()

    def esc(s: str) -> str:
        return (s.replace("&","&amp;").replace("<","&lt;")
                 .replace(">","&gt;").replace('"',"&quot;"))

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<bom xmlns="http://cyclonedx.org/schema/bom/1.4"',
        f'     version="{sbom.version}"',
        f'     serialNumber="{esc(sbom.serial_number)}">',
        f'  <metadata>',
        f'    <timestamp>{esc(ts)}</timestamp>',
        f'    <tools>',
    ]
    for tool in meta.tools:
        lines += [
            f'      <tool>',
            f'        <vendor>{esc(tool.get("vendor",""))}</vendor>',
            f'        <name>{esc(tool.get("name",""))}</name>',
            f'        <version>{esc(tool.get("version",""))}</version>',
            f'      </tool>',
        ]
    lines.append(f'    </tools>')

    if meta.component:
        c = meta.component
        lines += [
            f'    <component type="{c.type}" bom-ref="{esc(c.bom_ref)}">',
            f'      <name>{esc(c.name)}</name>',
            f'      <version>{esc(c.version)}</version>',
            f'      <purl>{esc(c.purl)}</purl>',
            f'    </component>',
        ]
    lines.append(f'  </metadata>')
    lines.append(f'  <components>')

    for comp in sbom.components:
        lines += [
            f'    <component type="{comp.type}" bom-ref="{esc(comp.bom_ref)}">',
            f'      <name>{esc(comp.name)}</name>',
            f'      <version>{esc(comp.version)}</version>',
            f'      <purl>{esc(comp.purl)}</purl>',
        ]
        if comp.description:
            lines.append(f'      <description>{esc(comp.description[:200])}</description>')
        if comp.licenses:
            lines.append(f'      <licenses>')
            for lic in comp.licenses:
                lines.append(f'        <license><id>{esc(lic.id)}</id></license>')
            lines.append(f'      </licenses>')
        if comp.properties:
            lines.append(f'      <properties>')
            for k, v in comp.properties.items():
                lines.append(f'        <property name="{esc(k)}">{esc(v)}</property>')
            lines.append(f'      </properties>')
        lines.append(f'    </component>')

    lines.append(f'  </components>')
    lines.append(f'  <dependencies>')
    for dep in sbom.dependencies:
        ref  = esc(dep.get("ref",""))
        deps = dep.get("dependsOn",[])
        if deps:
            lines.append(f'    <dependency ref="{ref}">')
            for d in deps:
                lines.append(f'      <dependency ref="{esc(d)}"/>')
            lines.append(f'    </dependency>')
        else:
            lines.append(f'    <dependency ref="{ref}"/>')
    lines.append(f'  </dependencies>')
    lines.append(f'</bom>')
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# STATS & OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

def compute_stats(sbom: SBOM) -> dict:
    by_eco: Dict[str,int]  = {}
    by_lic: Dict[str,int]  = {}
    no_lic = 0

    for c in sbom.components:
        eco = c.properties.get("ecosystem","unknown")
        by_eco[eco] = by_eco.get(eco,0)+1
        if c.licenses:
            for l in c.licenses:
                by_lic[l.id] = by_lic.get(l.id,0)+1
        else:
            no_lic += 1

    return {
        "total_components": len(sbom.components),
        "by_ecosystem":     by_eco,
        "by_license":       dict(sorted(by_lic.items(), key=lambda x: -x[1])[:10]),
        "no_license":       no_lic,
        "license_risk":     [k for k in by_lic if "GPL" in k and "LGPL" not in k],
    }


def print_stats(sbom: SBOM, stats: dict) -> None:
    print(f"\n{SEP}")
    print(f"  {C.BOLD}SBOM STATISTICS{C.RESET}")
    print(f"  Serial      : {sbom.serial_number}")
    print(f"  Spec        : CycloneDX {sbom.spec_version}")
    print(f"  Components  : {stats['total_components']}")
    print(f"  Sem licença : {stats['no_license']}")

    if stats["by_ecosystem"]:
        print(f"\n  {C.BOLD}Por ecossistema:{C.RESET}")
        for eco, count in stats["by_ecosystem"].items():
            print(f"    {C.CYAN}{eco:<10}{C.RESET} {count}")

    if stats["by_license"]:
        print(f"\n  {C.BOLD}Licenças mais comuns:{C.RESET}")
        for lic, count in list(stats["by_license"].items())[:6]:
            print(f"    {C.DIM}{lic:<25}{C.RESET} {count}")

    if stats["license_risk"]:
        print(f"\n  {C.YELLOW}⚠ Licenças copyleft (GPL) — verificar compatibilidade:{C.RESET}")
        for lic in stats["license_risk"]:
            print(f"    {C.YELLOW}●{C.RESET} {lic}")
    print(SEP)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(prog="sbom-generator",
        description="SBOM Generator — CycloneDX 1.4 | JSON + XML | CISA Mandate")
    parser.add_argument("path", nargs="?", default=".",
        help="Caminho do projeto (default: .)")
    parser.add_argument("--name",    default="projeto", help="Nome do projeto")
    parser.add_argument("--version", default="1.0.0",   help="Versão do projeto")
    parser.add_argument("--author",  default="Márcio Coutinho")
    parser.add_argument("--format",  choices=["json","xml","both"], default="both")
    parser.add_argument("--live",    action="store_true",
        help="Usar pip/npm list (mais completo, requer ambiente ativo)")
    parser.add_argument("-o","--output", default="sbom",
        help="Nome base dos ficheiros de output (default: sbom)")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--ver",     action="version",
        version=f"sbom-generator {__version__}")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    print(f"  {C.DIM}Recolhendo dependências de: {args.path}{C.RESET}")

    if args.live:
        pkgs  = collect_pip_packages()
        pkgs += collect_npm_packages(args.path)
    else:
        pkgs = collect_from_manifests(args.path)

    if not pkgs:
        print(f"  {C.YELLOW}Nenhuma dependência encontrada — usando demo.{C.RESET}")
        pkgs = [
            {"name":"flask","version":"2.3.0","ecosystem":"pip","license":"BSD-3-Clause",
             "home_page":"https://flask.palletsprojects.com","author":"Armin Ronacher","summary":"A simple framework for building complex web applications."},
            {"name":"requests","version":"2.31.0","ecosystem":"pip","license":"Apache-2.0",
             "home_page":"https://requests.readthedocs.io","author":"Kenneth Reitz","summary":"Python HTTP for Humans."},
            {"name":"cryptography","version":"41.0.6","ecosystem":"pip","license":"Apache-2.0",
             "home_page":"https://cryptography.io","author":"","summary":"cryptography is a package which provides cryptographic recipes and primitives to Python developers."},
            {"name":"pyyaml","version":"6.0.1","ecosystem":"pip","license":"MIT",
             "home_page":"https://pyyaml.org","author":"Kirill Simonov","summary":"YAML parser and emitter for Python"},
            {"name":"express","version":"4.18.2","ecosystem":"npm","license":"MIT",
             "home_page":"https://expressjs.com","author":"TJ Holowaychuk","summary":"Fast, unopinionated, minimalist web framework"},
            {"name":"lodash","version":"4.17.21","ecosystem":"npm","license":"MIT",
             "home_page":"https://lodash.com","author":"John-David Dalton","summary":"Lodash modular utilities."},
        ]

    print(f"  {C.DIM}{len(pkgs)} componentes encontrados.{C.RESET}")
    sbom  = build_sbom(pkgs, args.name, args.version, args.author)
    stats = compute_stats(sbom)
    print_stats(sbom, stats)

    # JSON
    if args.format in ("json","both"):
        json_path = f"{args.output}.json"
        with open(json_path,"w") as f:
            json.dump(to_cyclonedx_json(sbom), f, indent=2, ensure_ascii=False)
        sha = hashlib.sha256(Path(json_path).read_bytes()).hexdigest()[:16]
        print(f"  {C.GREEN}[✓] CycloneDX JSON: {json_path}  (sha256:{sha}...){C.RESET}")

    # XML
    if args.format in ("xml","both"):
        xml_path  = f"{args.output}.xml"
        xml_content = to_cyclonedx_xml(sbom)
        Path(xml_path).write_text(xml_content, encoding="utf-8")
        print(f"  {C.GREEN}[✓] CycloneDX XML : {xml_path}{C.RESET}")

    print(f"\n  {C.DIM}SBOM gerado com {len(sbom.components)} componentes "
          f"(serial: {sbom.serial_number}){C.RESET}")


if __name__ == "__main__":
    main()

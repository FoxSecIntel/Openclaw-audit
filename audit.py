#!/usr/bin/env python3
"""OpenClaw deployment auditor.

Barbell strategy implementation:
- Core logic is intentionally simple, robust, and dependency-light.
- Findings are focused on high-value checks for common misconfigurations and two CVE-linked conditions.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

MIN_SAFE_VERSION = "2026.1.29"  # below this is vulnerable to CVE-2026-25253
HIDDEN_MESSAGE_B64 = "wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="


class Colour:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


@dataclass
class Finding:
    severity: str  # PASS, WARN, CRITICAL, INFO
    check: str
    details: str


CRITICAL_SKILL_INDICATORS = ["sudo", "exec: true", "chmod", "base64", "/bin/bash", "ssh-add"]
MODERATE_SKILL_INDICATORS = ["curl", "wget", "http", "api_key", "token", "requests"]


def parse_version(ver: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", ver)
    return tuple(int(p) for p in parts[:3]) if parts else (0, 0, 0)


def is_below(v1: str, v2: str) -> bool:
    a = parse_version(v1)
    b = parse_version(v2)
    # normalise to 3 parts
    a = (a + (0, 0, 0))[:3]
    b = (b + (0, 0, 0))[:3]
    return a < b


def get_openclaw_version() -> str | None:
    if not shutil.which("openclaw"):
        return None
    try:
        out = subprocess.check_output(["openclaw", "--version"], text=True, stderr=subprocess.STDOUT).strip()
        m = re.search(r"\d+\.\d+\.\d+", out)
        return m.group(0) if m else out.splitlines()[0].strip()
    except Exception:
        return None


def load_config(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def resolve_config(explicit_config: str | None) -> tuple[dict[str, Any] | None, Path | None, list[Path]]:
    home = Path(os.path.expanduser("~"))
    attempted: list[Path] = []

    if explicit_config:
        p = Path(explicit_config).expanduser().resolve()
        attempted.append(p)
        cfg = load_config(p)
        return cfg, (p if cfg else None), attempted

    candidates = [
        home / ".openclaw" / "config.json",
        home / ".openclaw" / "openclaw.json",
        Path("/root/.openclaw/openclaw.json"),
        Path("/root/.openclaw/config.json"),
    ]

    for p in candidates:
        attempted.append(p)
        cfg = load_config(p)
        if cfg is not None:
            return cfg, p, attempted

    return None, None, attempted


def walk_items(obj: Any, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            yield from walk_items(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{prefix}[{i}]"
            yield from walk_items(v, p)
    else:
        yield prefix, obj


def find_plaintext_keys(config: dict[str, Any]) -> list[str]:
    hits: list[str] = []
    key_name_re = re.compile(r"(api[_-]?key|token|secret|password)", re.IGNORECASE)
    value_re = re.compile(r"^(sk-[A-Za-z0-9\-_]{12,}|[A-Fa-f0-9]{32,})$")

    for path, value in walk_items(config):
        if not isinstance(value, str):
            continue
        name = path.split(".")[-1]
        if key_name_re.search(name) and value.strip():
            if value.startswith("${") and value.endswith("}"):
                continue
            if value_re.match(value.strip()) or len(value.strip()) > 20:
                hits.append(path)
    return hits


def check_gateway_bind(config: dict[str, Any] | None, config_hint: str) -> Finding:
    if not config:
        return Finding("WARN", "Gateway bind", f"Could not read OpenClaw config ({config_hint})")

    bind = (
        config.get("gateway", {}).get("bind")
        if isinstance(config.get("gateway"), dict)
        else None
    )
    if bind in {"0.0.0.0", "::", "all", "public"}:
        return Finding("CRITICAL", "Gateway bind", f"Gateway appears publicly bound ({bind})")
    if bind in {"127.0.0.1", "loopback", "localhost", "::1"}:
        return Finding("PASS", "Gateway bind", f"Gateway is local-only ({bind})")
    return Finding("WARN", "Gateway bind", f"Bind value is {bind!r}; verify exposure policy")


def check_feishu(config: dict[str, Any] | None, home: Path) -> Finding:
    if config:
        plugins = config.get("plugins", {}).get("entries", {})
        if isinstance(plugins, dict):
            for name, meta in plugins.items():
                if "feishu" in str(name).lower():
                    enabled = isinstance(meta, dict) and bool(meta.get("enabled", False))
                    sev = "CRITICAL" if enabled else "WARN"
                    return Finding(sev, "Feishu extension", f"Feishu entry found in config (enabled={enabled})")

    ext_dir = home / ".openclaw" / "extensions"
    if ext_dir.exists():
        for p in ext_dir.glob("*feishu*"):
            return Finding("WARN", "Feishu extension", f"Feishu-related extension path detected: {p}")

    return Finding("PASS", "Feishu extension", "No Feishu extension indicator found")


def check_version() -> Finding:
    v = get_openclaw_version()
    if not v:
        return Finding("WARN", "OpenClaw version", "Could not determine version from openclaw --version")
    if is_below(v, MIN_SAFE_VERSION):
        return Finding("CRITICAL", "OpenClaw version", f"Version {v} is below {MIN_SAFE_VERSION} (CVE-2026-25253 risk)")
    return Finding("PASS", "OpenClaw version", f"Version {v} is at or above {MIN_SAFE_VERSION}")


def check_plaintext_api_keys(config: dict[str, Any] | None, config_hint: str) -> Finding:
    if not config:
        return Finding("WARN", "Plaintext API keys", f"Could not read OpenClaw config ({config_hint})")
    hits = find_plaintext_keys(config)
    if hits:
        preview = ", ".join(hits[:5])
        extra = "" if len(hits) <= 5 else f" (+{len(hits)-5} more)"
        return Finding("CRITICAL", "Plaintext API keys", f"Potential unencrypted secrets at: {preview}{extra}")
    return Finding("PASS", "Plaintext API keys", "No obvious plaintext API key fields detected")


def check_openclaw_dir_permissions(home: Path) -> Finding:
    openclaw_dir = home / ".openclaw"
    if not openclaw_dir.exists():
        return Finding("WARN", "OpenClaw directory permissions", f"Directory not found: {openclaw_dir}")

    try:
        mode = openclaw_dir.stat().st_mode & 0o777
    except Exception as exc:
        return Finding("WARN", "OpenClaw directory permissions", f"Could not read permissions for {openclaw_dir}: {exc}")

    mode_str = oct(mode)

    if mode == 0o700:
        return Finding("PASS", "OpenClaw directory permissions", f"{openclaw_dir} is locked down ({mode_str})")

    # Group/other readable, writable, or executable bits present
    if (mode & 0o077) != 0:
        return Finding("CRITICAL", "OpenClaw directory permissions", f"{openclaw_dir} is too permissive ({mode_str}); expected 0o700")

    return Finding("WARN", "OpenClaw directory permissions", f"{openclaw_dir} mode is {mode_str}; recommended 0o700")


def analyse_skill_content(content: str) -> tuple[str, List[str]]:
    text = content.lower()
    indicators: List[str] = []

    critical_hits = [k for k in CRITICAL_SKILL_INDICATORS if k in text]
    moderate_hits = [k for k in MODERATE_SKILL_INDICATORS if k in text]

    indicators.extend(critical_hits)
    indicators.extend([k for k in moderate_hits if k not in indicators])

    if critical_hits:
        return "CRITICAL", indicators
    if moderate_hits:
        return "MODERATE", indicators
    return "LOW", indicators


def scan_skill_permission_heatmap(home: Path) -> tuple[List[Dict[str, Any]], Finding]:
    skills_dir = home / ".openclaw" / "skills"
    rows: List[Dict[str, Any]] = []

    if not skills_dir.exists():
        return rows, Finding("WARN", "Skill Permission Heatmap", f"Skills directory not found: {skills_dir}")

    if not skills_dir.is_dir():
        return rows, Finding("WARN", "Skill Permission Heatmap", f"Skills path is not a directory: {skills_dir}")

    for child in sorted(skills_dir.iterdir()):
        if not child.is_dir():
            continue

        skill_md = child / "SKILL.md"
        if not skill_md.exists():
            continue

        try:
            content = skill_md.read_text(encoding="utf-8", errors="ignore")
            risk, indicators = analyse_skill_content(content)
            rows.append(
                {
                    "skill": child.name,
                    "risk": risk,
                    "indicators": indicators,
                    "path": str(skill_md),
                }
            )
        except Exception as exc:
            rows.append(
                {
                    "skill": child.name,
                    "risk": "UNKNOWN",
                    "indicators": [f"read_error:{exc}"],
                    "path": str(skill_md),
                }
            )

    if not rows:
        return rows, Finding("INFO", "Skill Permission Heatmap", f"No SKILL.md files found under {skills_dir}")

    critical_count = sum(1 for r in rows if r["risk"] == "CRITICAL")
    moderate_count = sum(1 for r in rows if r["risk"] == "MODERATE")
    low_count = sum(1 for r in rows if r["risk"] == "LOW")

    severity = "WARN" if critical_count > 0 else "PASS"
    details = (
        f"Analysed {len(rows)} skills: critical={critical_count}, moderate={moderate_count}, low={low_count}"
    )
    return rows, Finding(severity, "Skill Permission Heatmap", details)


def print_skill_heatmap(rows: List[Dict[str, Any]]) -> None:
    print("\n## Skill Permission Heatmap")
    if not rows:
        print("No skill data available.")
        return

    print("| Skill Name | Risk Level | Indicators Found |")
    print("|---|---|---|")
    for row in rows:
        indicators = ", ".join(row.get("indicators", [])) if row.get("indicators") else "none"
        print(f"| {row.get('skill','unknown')} | {row.get('risk','UNKNOWN')} | {indicators} |")


def colour_for(sev: str) -> str:
    return {
        "PASS": Colour.GREEN,
        "CRITICAL": Colour.RED,
        "WARN": Colour.YELLOW,
        "INFO": Colour.CYAN,
    }.get(sev, Colour.RESET)


def print_findings(findings: list[Finding]) -> None:
    print(f"{Colour.CYAN}OpenClaw Deployment Audit{Colour.RESET}")
    print("=" * 80)
    for f in findings:
        c = colour_for(f.severity)
        print(f"{c}[{f.severity:<8}]{Colour.RESET} {f.check:<22} {f.details}")

    crit = sum(1 for x in findings if x.severity == "CRITICAL")
    warn = sum(1 for x in findings if x.severity == "WARN")
    passed = sum(1 for x in findings if x.severity == "PASS")
    print("-" * 80)
    print(f"{Colour.RED}Critical: {crit}{Colour.RESET}  {Colour.YELLOW}Warnings: {warn}{Colour.RESET}  {Colour.GREEN}Pass: {passed}{Colour.RESET}")


def findings_to_json(
    findings: list[Finding],
    config_path: Path | None,
    attempted: list[Path],
    skill_heatmap: List[Dict[str, Any]],
    exit_code: int,
) -> dict[str, Any]:
    crit = sum(1 for x in findings if x.severity == "CRITICAL")
    warn = sum(1 for x in findings if x.severity == "WARN")
    passed = sum(1 for x in findings if x.severity == "PASS")

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config_path_used": str(config_path) if config_path else None,
        "config_paths_attempted": [str(p) for p in attempted],
        "findings": [
            {"severity": f.severity, "check": f.check, "details": f.details}
            for f in findings
        ],
        "summary": {
            "critical": crit,
            "warnings": warn,
            "pass": passed,
            "total": len(findings),
        },
        "skill_permission_heatmap": skill_heatmap,
        "exit_code": exit_code,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit OpenClaw deployment security posture")
    parser.add_argument("--config", help="Path to OpenClaw config file (optional)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("-m", action="store_true", help="Print hidden message")
    args = parser.parse_args()

    if args.m:
        print(base64.b64decode(HIDDEN_MESSAGE_B64).decode("utf-8", errors="replace"), end="")
        return 0

    home = Path(os.path.expanduser("~"))
    config, config_path, attempted = resolve_config(args.config)
    hint = str(config_path) if config_path else f"tried: {', '.join(str(p) for p in attempted)}"

    skill_rows, skill_finding = scan_skill_permission_heatmap(home)

    findings: list[Finding] = [
        check_version(),
        check_plaintext_api_keys(config, hint),
        check_gateway_bind(config, hint),
        check_openclaw_dir_permissions(home),
        check_feishu(config, home),
        skill_finding,
    ]

    exit_code = 2 if any(f.severity == "CRITICAL" for f in findings) else 0

    if args.json:
        print(json.dumps(findings_to_json(findings, config_path, attempted, skill_rows, exit_code), indent=2))
    else:
        print_findings(findings)
        print_skill_heatmap(skill_rows)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())

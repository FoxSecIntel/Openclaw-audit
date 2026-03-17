#!/usr/bin/env python3
"""OpenClaw deployment auditor.

Security-focused host audit for OpenClaw with structured findings.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

MIN_SAFE_VERSION = "2026.1.29"


class Colour:
    # ANSI standard palette for terminal hierarchy
    CRITICAL = "\033[1;31m"  # bold red
    WARN = "\033[0;33m"      # yellow
    PASS = "\033[0;32m"      # green
    INFO = "\033[0;36m"      # cyan
    LABEL = "\033[1;37m"     # bold white
    RESET = "\033[0m"


@dataclass
class Finding:
    severity: str  # PASS, WARN, CRITICAL, INFO
    check: str
    details: str
    confidence: str  # low, medium, high
    data_source: str
    remediation: str
    rollback: str
    impact: str


CRITICAL_SKILL_INDICATORS = ["sudo", "exec: true", "chmod", "base64", "/bin/bash", "ssh-add"]
MODERATE_SKILL_INDICATORS = ["curl", "wget", "http", "api_key", "token", "requests"]


def parse_version(ver: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", ver)
    return tuple(int(p) for p in parts[:3]) if parts else (0, 0, 0)


def is_below(v1: str, v2: str) -> bool:
    a = (parse_version(v1) + (0, 0, 0))[:3]
    b = (parse_version(v2) + (0, 0, 0))[:3]
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


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    n = len(value)
    ent = 0.0
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent


def find_plaintext_secrets(config: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return tuples: path, value, quality(weak|strong)."""
    hits = []
    key_name_re = re.compile(r"(api[_-]?key|token|secret|password)", re.IGNORECASE)

    for path, value in walk_items(config):
        if not isinstance(value, str):
            continue

        name = path.split(".")[-1]
        raw = value.strip()
        if not key_name_re.search(name):
            continue
        if not raw:
            continue
        if raw.startswith("${") and raw.endswith("}"):
            continue

        ent = shannon_entropy(raw)
        weak = len(raw) < 20 or ent < 3.5 or raw.lower() in {"changeme", "password", "admin", "token", "secret"}
        hits.append((path, raw, "weak" if weak else "strong"))

    return hits


def check_version() -> Finding:
    v = get_openclaw_version()
    if not v:
        return Finding("WARN", "OpenClaw version", "Could not determine version from openclaw --version", "medium", "cli:openclaw", "Install OpenClaw CLI or ensure binary is in PATH, then re-run.", "No rollback needed.", "Unknown patch posture may hide known CVE exposure.")

    if is_below(v, MIN_SAFE_VERSION):
        return Finding("CRITICAL", "OpenClaw version", f"Version {v} is below {MIN_SAFE_VERSION} (CVE-2026-25253 risk)", "high", "cli:openclaw", f"Upgrade OpenClaw to {MIN_SAFE_VERSION} or newer and verify version post-restart.", "If instability occurs, roll back package to last known stable patched release.", "Known exploitable path remains until patched.")

    return Finding("PASS", "OpenClaw version", f"Version {v} is at or above {MIN_SAFE_VERSION}", "high", "cli:openclaw", "No action required.", "No rollback needed.", "Patched baseline observed for this CVE gate.")


def check_plaintext_api_keys(config: dict[str, Any] | None, config_hint: str) -> Finding:
    if not config:
        return Finding("WARN", "Plaintext API keys", f"Could not read OpenClaw config ({config_hint})", "low", "file:config", "Provide a valid config path with --config and re-run audit.", "No rollback needed.", "Secret posture unknown.")

    hits = find_plaintext_secrets(config)
    if not hits:
        return Finding("PASS", "Plaintext API keys", "No obvious plaintext secret fields detected", "medium", "file:config", "No action required.", "No rollback needed.", "No direct plaintext secret exposure detected.")

    weak_hits = [h for h in hits if h[2] == "weak"]
    preview = ", ".join(h[0] for h in hits[:5])
    extra = "" if len(hits) <= 5 else f" (+{len(hits)-5} more)"

    if weak_hits:
        sev = "CRITICAL"
        impact = "Weak plaintext credentials materially increase takeover likelihood if config is exposed."
    else:
        sev = "CRITICAL"
        impact = "Plaintext secrets increase credential exposure risk if host or file access is compromised."

    return Finding(
        sev,
        "Plaintext API keys",
        f"Potential plaintext secrets at: {preview}{extra}",
        "high",
        "file:config",
        "Move secrets to environment variables or a secret manager and rotate exposed keys immediately.",
        "Restore previous config from backup after redacting secrets if rollback is required.",
        impact,
    )


def _get_gateway_bind(config: dict[str, Any]) -> str | None:
    gateway = config.get("gateway")
    if isinstance(gateway, dict):
        bind = gateway.get("bind")
        if isinstance(bind, str):
            return bind
    return None


def check_gateway_bind(config: dict[str, Any] | None, config_hint: str) -> Finding:
    if not config:
        return Finding("WARN", "Gateway bind", f"Could not read OpenClaw config ({config_hint})", "low", "file:config", "Provide --config path and re-run.", "No rollback needed.", "Network exposure cannot be confirmed.")

    bind = _get_gateway_bind(config)
    if bind in {"0.0.0.0", "::", "all", "public"}:
        return Finding("CRITICAL", "Gateway bind", f"Gateway appears publicly bound ({bind})", "high", "file:config", "Bind gateway to loopback and expose only through controlled reverse proxy with auth controls.", "Revert bind setting to previous value if service becomes unreachable.", "Public bind can expose management plane to untrusted networks.")
    if bind in {"127.0.0.1", "loopback", "localhost", "::1"}:
        return Finding("PASS", "Gateway bind", f"Gateway is local-only ({bind})", "high", "file:config", "No action required.", "No rollback needed.", "Local-only bind reduces direct exposure.")

    return Finding("WARN", "Gateway bind", f"Bind value is {bind!r}; verify exposure policy", "medium", "file:config", "Confirm intended network exposure and document policy.", "No rollback needed.", "Ambiguous bind may unintentionally expose control endpoints.")


def check_control_ui_policy(config: dict[str, Any] | None, config_hint: str) -> list[Finding]:
    findings: list[Finding] = []
    if not config:
        findings.append(Finding("WARN", "Control UI origins", f"Could not read OpenClaw config ({config_hint})", "low", "file:config", "Provide --config and re-run.", "No rollback needed.", "Origin allowlist posture unknown."))
        return findings

    gateway = config.get("gateway") if isinstance(config.get("gateway"), dict) else {}
    control_ui = gateway.get("controlUi") if isinstance(gateway, dict) and isinstance(gateway.get("controlUi"), dict) else {}
    allowed = control_ui.get("allowedOrigins")

    if not isinstance(allowed, list) or len(allowed) == 0:
        findings.append(Finding("WARN", "Control UI origins", "No allowedOrigins configured for gateway.controlUi", "high", "file:config", "Set gateway.controlUi.allowedOrigins to explicit trusted UI origins.", "Restore prior allowlist entries if UI access breaks.", "Missing allowlist can cause instability or policy bypass attempts depending on defaults."))
    else:
        wildcard = any(str(x).strip() in {"*", "http://*", "https://*"} for x in allowed)
        if wildcard:
            findings.append(Finding("CRITICAL", "Control UI origins", f"Wildcard origin present in allowedOrigins: {allowed}", "high", "file:config", "Replace wildcard origins with explicit trusted origins only.", "Reinsert prior values if trusted UI clients are blocked.", "Wildcard origin trust increases cross-origin attack surface."))
        else:
            findings.append(Finding("PASS", "Control UI origins", f"Explicit origin allowlist configured ({len(allowed)} entries)", "high", "file:config", "No action required.", "No rollback needed.", "Explicit allowlist lowers origin abuse risk."))

    proxies = gateway.get("trustedProxies") if isinstance(gateway, dict) else None
    if proxies is None:
        findings.append(Finding("WARN", "Trusted proxies", "gateway.trustedProxies not set", "medium", "file:config", "Set gateway.trustedProxies when deploying behind reverse proxies.", "Remove proxy list if not required.", "Missing proxy trust config may break origin/IP interpretation behind proxies."))
    elif isinstance(proxies, list) and len(proxies) == 0:
        findings.append(Finding("WARN", "Trusted proxies", "gateway.trustedProxies is empty", "medium", "file:config", "Populate trusted proxy ranges if reverse proxy headers are used.", "Clear entries to disable trust if misconfigured.", "Empty proxy trust may cause auth or origin handling issues."))
    else:
        findings.append(Finding("PASS", "Trusted proxies", "gateway.trustedProxies configured", "medium", "file:config", "No action required if values are accurate.", "No rollback needed.", "Proxy trust list present for header chain handling."))

    return findings


def check_openclaw_path_permissions(home: Path, config_path: Path | None) -> list[Finding]:
    findings: list[Finding] = []
    targets = [
        (home / ".openclaw", "OpenClaw home directory", 0o700),
        (home / ".openclaw" / "logs", "OpenClaw logs directory", 0o700),
        (home / ".openclaw" / "sessions", "OpenClaw sessions directory", 0o700),
    ]

    if config_path is not None:
        targets.append((config_path, "OpenClaw config file", 0o600))

    for path, label, recommended in targets:
        if not path.exists():
            findings.append(Finding("INFO", label, f"Path not found: {path}", "medium", "filesystem", f"Create path with restrictive permissions ({oct(recommended)}), if used.", "No rollback needed.", "Missing optional path; no direct exposure inferred."))
            continue

        try:
            mode = path.stat().st_mode & 0o777
        except Exception as exc:
            findings.append(Finding("WARN", label, f"Could not read permissions for {path}: {exc}", "low", "filesystem", "Validate path ownership and permissions manually.", "No rollback needed.", "Permission posture unknown for this path."))
            continue

        if mode == recommended:
            findings.append(Finding("PASS", label, f"{path} permissions are {oct(mode)}", "high", "filesystem", "No action required.", "No rollback needed.", "Permission posture matches recommended baseline."))
            continue

        if (mode & 0o022) != 0 or (mode & 0o077) != 0:
            sev = "CRITICAL"
            impact = "Writable or world/group-readable access can allow tampering or data leakage."
        else:
            sev = "WARN"
            impact = "Permissions are not ideal and may increase operational risk."

        findings.append(Finding(
            sev,
            label,
            f"{path} permissions are {oct(mode)}; recommended {oct(recommended)}",
            "high",
            "filesystem",
            f"Apply: chmod {oct(recommended)[2:]} {path}",
            f"Rollback: chmod {oct(mode)[2:]} {path}",
            impact,
        ))

    return findings


def check_feishu(config: dict[str, Any] | None, home: Path) -> Finding:
    if config:
        plugins = config.get("plugins", {}).get("entries", {})
        if isinstance(plugins, dict):
            for name, meta in plugins.items():
                if "feishu" in str(name).lower():
                    enabled = isinstance(meta, dict) and bool(meta.get("enabled", False))
                    sev = "CRITICAL" if enabled else "WARN"
                    return Finding(
                        sev,
                        "Feishu extension",
                        f"Feishu entry found in config (enabled={enabled})",
                        "high",
                        "file:config",
                        "Disable Feishu plugin unless explicitly required and patched.",
                        "Re-enable plugin entry if business dependency requires it.",
                        "Unneeded extension surface increases plugin-related risk.",
                    )

    ext_dir = home / ".openclaw" / "extensions"
    if ext_dir.exists():
        for p in ext_dir.glob("*feishu*"):
            return Finding(
                "WARN",
                "Feishu extension",
                f"Feishu-related extension path detected: {p}",
                "medium",
                "filesystem",
                "Review extension necessity and patch state; remove if not required.",
                "Restore extension from backup if required by workflow.",
                "Additional extension path may broaden attack surface.",
            )

    return Finding("PASS", "Feishu extension", "No Feishu extension indicator found", "medium", "file:config+filesystem", "No action required.", "No rollback needed.", "No Feishu extension signal observed.")


def analyse_skill_content(content: str) -> tuple[str, List[str]]:
    text = content.lower()
    critical_hits = [k for k in CRITICAL_SKILL_INDICATORS if k in text]
    moderate_hits = [k for k in MODERATE_SKILL_INDICATORS if k in text]

    indicators = critical_hits + [k for k in moderate_hits if k not in critical_hits]

    if critical_hits:
        return "CRITICAL", indicators
    if moderate_hits:
        return "MODERATE", indicators
    return "LOW", indicators


def scan_skill_permission_heatmap(home: Path) -> tuple[List[Dict[str, Any]], Finding]:
    skills_dir = home / ".openclaw" / "skills"
    rows: List[Dict[str, Any]] = []

    if not skills_dir.exists():
        return rows, Finding("WARN", "Skill Permission Heatmap", f"Skills directory not found: {skills_dir}", "low", "filesystem", "Create or mount expected skills directory if skills are used.", "No rollback needed.", "Skill risk visibility unavailable.")

    for child in sorted(skills_dir.iterdir()):
        if not child.is_dir():
            continue
        skill_md = child / "SKILL.md"
        if not skill_md.exists():
            continue
        try:
            content = skill_md.read_text(encoding="utf-8", errors="ignore")
            risk, indicators = analyse_skill_content(content)
            rows.append({"skill": child.name, "risk": risk, "indicators": indicators, "path": str(skill_md)})
        except Exception as exc:
            rows.append({"skill": child.name, "risk": "UNKNOWN", "indicators": [f"read_error:{exc}"], "path": str(skill_md)})

    if not rows:
        return rows, Finding("INFO", "Skill Permission Heatmap", f"No SKILL.md files found under {skills_dir}", "medium", "filesystem", "No action required.", "No rollback needed.", "No skill manifests discovered.")

    critical_count = sum(1 for r in rows if r["risk"] == "CRITICAL")
    moderate_count = sum(1 for r in rows if r["risk"] == "MODERATE")
    low_count = sum(1 for r in rows if r["risk"] == "LOW")

    severity = "WARN" if critical_count > 0 else "PASS"
    details = f"Analysed {len(rows)} skills: critical={critical_count}, moderate={moderate_count}, low={low_count}"
    remediation = "Review and reduce privileged skill directives, especially shell execution and privilege escalation indicators."
    rollback = "Restore prior SKILL.md from source control if a mitigation breaks workflow."
    impact = "High-risk skill composition can amplify execution and privilege abuse paths."

    return rows, Finding(severity, "Skill Permission Heatmap", details, "medium", "filesystem:SKILL.md", remediation, rollback, impact)


def build_signature(findings: list[Finding]) -> list[str]:
    keys = []
    for f in findings:
        if f.severity in {"CRITICAL", "WARN"}:
            keys.append(f"{f.check}|{f.severity}|{f.details}")
    return sorted(keys)


def check_regression_snapshot(findings: list[Finding], baseline_path: Path) -> Finding:
    current = {"timestamp": datetime.now(timezone.utc).isoformat(), "signature": build_signature(findings)}

    previous = None
    if baseline_path.exists():
        try:
            previous = json.loads(baseline_path.read_text(encoding="utf-8"))
        except Exception:
            previous = None

    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(current, indent=2), encoding="utf-8")

    if not previous or not isinstance(previous, dict):
        return Finding("INFO", "Regression snapshot", f"Initial baseline saved to {baseline_path}", "high", "file:baseline", "Run audit again after changes to evaluate deltas.", "Restore previous baseline file if needed.", "No prior baseline available for comparison.")

    prev_sig = set(previous.get("signature", []))
    cur_sig = set(current.get("signature", []))

    added = sorted(cur_sig - prev_sig)
    removed = sorted(prev_sig - cur_sig)

    if not added and not removed:
        return Finding("PASS", "Regression snapshot", "No security regression delta versus previous baseline", "high", "file:baseline", "No action required.", "No rollback needed.", "No net change in warning or critical footprint.")

    details = f"Delta detected: +{len(added)} new, -{len(removed)} resolved high-risk signatures"
    return Finding("WARN", "Regression snapshot", details, "high", "file:baseline", "Review newly introduced findings before deployment promotion.", "Restore prior known-good configuration snapshot if regression is unacceptable.", "Regression indicates changed risk posture requiring review.")


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
        "PASS": Colour.PASS,
        "CRITICAL": Colour.CRITICAL,
        "WARN": Colour.WARN,
        "INFO": Colour.INFO,
    }.get(sev, Colour.RESET)


def severity_order(sev: str) -> int:
    return {"CRITICAL": 0, "WARN": 1, "PASS": 2, "INFO": 3}.get(sev, 4)


def symbol_for(sev: str) -> str:
    return {"CRITICAL": "[!]", "WARN": "[?]", "PASS": "[✓]", "INFO": "[i]"}.get(sev, "[ ]")


def location_for(f: Finding) -> str:
    # Keep a clear location label even when the source is abstract.
    return f.data_source


def print_section(title: str) -> None:
    print(f"{Colour.LABEL}-- {title} --{Colour.RESET}")


def print_findings(findings: list[Finding]) -> None:
    today = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d")
    print(f"{Colour.LABEL}OpenClaw Deployment Audit | {today}{Colour.RESET}")
    print("=" * 110)

    sorted_findings = sorted(findings, key=lambda x: (severity_order(x.severity), x.check.lower()))
    criticals = [f for f in sorted_findings if f.severity == "CRITICAL"]
    warns = [f for f in sorted_findings if f.severity == "WARN"]
    passes = [f for f in sorted_findings if f.severity in {"PASS", "INFO"}]

    if criticals:
        print_section("CRITICAL")
        for f in criticals:
            c = colour_for(f.severity)
            print(f"{c}{symbol_for(f.severity)} {f.check}: {f.details}{Colour.RESET}")
            print(f"    {Colour.LABEL}Location:{Colour.RESET} {location_for(f)}")
            print(f"    {Colour.LABEL}Source:{Colour.RESET} {f.data_source}")
            print(f"    {Colour.LABEL}FIX:{Colour.RESET} {f.remediation}")
            print(f"    {Colour.LABEL}IMPACT:{Colour.RESET} {f.impact}")

    if warns:
        print_section("WARN")
        for f in warns:
            c = colour_for(f.severity)
            print(f"{c}{symbol_for(f.severity)} {f.check}: {f.details}{Colour.RESET}")
            print(f"    {Colour.LABEL}Location:{Colour.RESET} {location_for(f)}")
            print(f"    {Colour.LABEL}Source:{Colour.RESET} {f.data_source}")
            print(f"    {Colour.LABEL}FIX:{Colour.RESET} {f.remediation}")
            print(f"    {Colour.LABEL}IMPACT:{Colour.RESET} {f.impact}")

    if passes:
        print_section("PASS & INFO")
        for f in passes:
            c = colour_for(f.severity)
            detail = f" ({f.details})" if f.severity == "PASS" else f" - {f.details}"
            print(f"{c}{symbol_for(f.severity)} {f.check}{detail}{Colour.RESET}")

    crit = len(criticals)
    warn = len(warns)
    passed = sum(1 for x in sorted_findings if x.severity == "PASS")
    info = sum(1 for x in sorted_findings if x.severity == "INFO")
    print("-" * 110)
    print(
        f"{Colour.CRITICAL}Critical: {crit}{Colour.RESET}  "
        f"{Colour.WARN}Warnings: {warn}{Colour.RESET}  "
        f"{Colour.PASS}Pass: {passed}{Colour.RESET}  "
        f"{Colour.INFO}Info: {info}{Colour.RESET}"
    )
    print(f"{Colour.LABEL}Audit the Noise. Secure the Signal.{Colour.RESET}")


def findings_to_json(findings: list[Finding], config_path: Path | None, attempted: list[Path], skill_heatmap: List[Dict[str, Any]], exit_code: int) -> dict[str, Any]:
    crit = sum(1 for x in findings if x.severity == "CRITICAL")
    warn = sum(1 for x in findings if x.severity == "WARN")
    passed = sum(1 for x in findings if x.severity == "PASS")

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config_path_used": str(config_path) if config_path else None,
        "config_paths_attempted": [str(p) for p in attempted],
        "findings": [asdict(f) for f in findings],
        "summary": {"critical": crit, "warnings": warn, "pass": passed, "total": len(findings)},
        "skill_permission_heatmap": skill_heatmap,
        "exit_code": exit_code,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit OpenClaw deployment security posture")
    parser.add_argument("--config", help="Path to OpenClaw config file (optional)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--baseline", default=str(Path(os.path.expanduser("~")) / ".openclaw" / "audit-baseline.json"), help="Path to regression baseline file")
    args = parser.parse_args()

    home = Path(os.path.expanduser("~"))
    config, config_path, attempted = resolve_config(args.config)
    hint = str(config_path) if config_path else f"tried: {', '.join(str(p) for p in attempted)}"

    skill_rows, skill_finding = scan_skill_permission_heatmap(home)

    findings: list[Finding] = [
        check_version(),
        check_plaintext_api_keys(config, hint),
        check_gateway_bind(config, hint),
        *check_control_ui_policy(config, hint),
        *check_openclaw_path_permissions(home, config_path),
        check_feishu(config, home),
        skill_finding,
    ]

    baseline_finding = check_regression_snapshot(findings, Path(args.baseline).expanduser())
    findings.append(baseline_finding)

    # CI-compatible: 1 when any critical finding is present, else 0.
    exit_code = 1 if any(f.severity == "CRITICAL" for f in findings) else 0

    if args.json:
        print(json.dumps(findings_to_json(findings, config_path, attempted, skill_rows, exit_code), indent=2))
    else:
        print_findings(findings)
        print_skill_heatmap(skill_rows)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())

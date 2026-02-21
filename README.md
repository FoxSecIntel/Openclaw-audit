# openclaw-audit

A Python deployment auditor for OpenClaw security posture checks.

## Project overview

`openclaw-audit` is a lightweight host-side auditing tool for engineering teams running OpenClaw in production or lab environments. It focuses on high-value checks that map directly to known operational risks and selected CVEs.

The project follows a barbell strategy.

- The core script is intentionally simple, deterministic, and dependency-light.
- The threat model and remediation guidance are detailed, explicit, and suitable for governance and security review.

## Scope of checks

The current `audit.py` release evaluates:

1. **Version exposure check**
   - Flags OpenClaw versions below `2026.1.29` as vulnerable to **CVE-2026-25253**.
2. **Secret handling check**
   - Scans `~/.openclaw/config.json` for likely plaintext API keys and secrets.
3. **Gateway exposure check**
   - Detects risky bind settings such as `0.0.0.0`.
4. **Feishu extension check**
   - Detects Feishu extension indicators linked to **CVE-2026-26321** review requirements.

## Architecture

```mermaid
flowchart TD
    A[audit.py] --> B[Version probe via openclaw --version]
    A --> C[Config parser ~/.openclaw/config.json]
    C --> D[Secret pattern scan]
    C --> E[Gateway bind assessment]
    C --> F[Plugin and Feishu checks]
    A --> G[Coloured terminal findings]
    G --> H[Critical, warning, pass summary]
```

## Threat model

### Assets

- OpenClaw control plane exposure posture
- API credentials and secrets in local configuration
- Plugin and extension trust boundary
- Version hygiene and vulnerability exposure

### Adversaries

- External attackers scanning public control interfaces
- Opportunistic actors abusing exposed API keys
- Supply chain or plugin abuse paths
- Internal misuse due to insecure defaults and poor segregation

### Trust boundaries

- Local host to OpenClaw gateway
- Configuration file to runtime process
- Plugin ecosystem to core agent execution
- Human operators to automation pipelines

### Primary attack paths

1. Public gateway binding exposes control endpoints.
2. Plaintext keys are exfiltrated from local config.
3. Outdated versions remain unpatched against known CVEs.
4. Risky or unreviewed extensions increase attack surface.

### Security assumptions

- Audit runs with local read access to user OpenClaw config.
- Findings are advisory and should be paired with change control.
- CVE mapping is point-in-time and must be maintained over time.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 audit.py
```

Exit code behaviour:

- `0`: no critical findings
- `2`: one or more critical findings

## Remediation matrix

| Finding | Risk level | Fix |
|---|---|---|
| OpenClaw version below 2026.1.29 | Critical | Upgrade OpenClaw to a patched release and validate runtime version post-deploy |
| Potential plaintext API keys in config | Critical | Move secrets to environment or secret manager, rotate exposed keys, remove plaintext values |
| Gateway bound to 0.0.0.0 | Critical | Bind to loopback (`127.0.0.1` or `loopback`) and expose only through controlled proxy or private network |
| Feishu extension detected | Warning/Critical | Disable or remove Feishu integration unless explicitly required and patched; review extension source and access scope |

## Engineering notes

- No heavy third-party libraries are required.
- Script is designed for predictable behaviour in CI and server shells.
- Extend checks by adding pure functions that return structured findings.

## Licence

Apache 2.0

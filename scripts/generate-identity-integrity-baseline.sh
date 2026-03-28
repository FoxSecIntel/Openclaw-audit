#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${HOME}/.openclaw/workspace"
OUT_FILE="${HOME}/.openclaw/identity-integrity.json"

mkdir -p "$(dirname "$OUT_FILE")"

python3 - << 'PY'
import hashlib, json, os
from pathlib import Path

workspace = Path(os.path.expanduser('~/.openclaw/workspace'))
out_file = Path(os.path.expanduser('~/.openclaw/identity-integrity.json'))
targets = ['AGENTS.md', 'SOUL.md', 'MEMORY.md']

baseline = {}
for name in targets:
    p = workspace / name
    if not p.exists():
        continue
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    baseline[name] = h.hexdigest()

out_file.write_text(json.dumps(baseline, indent=2) + '\n', encoding='utf-8')
print(f'Wrote baseline: {out_file}')
print(json.dumps(baseline, indent=2))
PY

echo "Done. Re-run openclaw-audit to validate integrity against this baseline."

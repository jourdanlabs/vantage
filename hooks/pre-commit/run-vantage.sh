#!/usr/bin/env bash
# VANTAGE pre-commit gate
# Compatible with the pre-commit framework (https://pre-commit.com).
#
# Install:
#   repos:
#     - repo: https://github.com/jourdanlabs/vantage
#       rev: v1.0.0
#       hooks:
#         - id: vantage-gate

set -euo pipefail

PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REPORT_FILE="$PROJECT_ROOT/vantage-report.json"

# Locate vantage via bash array so paths-with-spaces don't split.
VANTAGE_CMD=()
if command -v vantage >/dev/null 2>&1; then
  VANTAGE_CMD=(vantage)
elif [ -x "$PROJECT_ROOT/node_modules/.bin/vantage" ]; then
  VANTAGE_CMD=("$PROJECT_ROOT/node_modules/.bin/vantage")
elif [ -f "$PROJECT_ROOT/bin/vantage.js" ]; then
  VANTAGE_CMD=(node "$PROJECT_ROOT/bin/vantage.js")
fi

if [ ${#VANTAGE_CMD[@]} -eq 0 ]; then
  echo "⚠  VANTAGE not found — install with: npm install -g vantage-cli"
  echo "   Skipping code quality gate."
  exit 0
fi

echo "▸ VANTAGE analyzing $PROJECT_ROOT ..."

if ! "${VANTAGE_CMD[@]}" analyze "$PROJECT_ROOT" --output "$REPORT_FILE" 2>&1; then
  echo "⚠  VANTAGE analysis failed — skipping gate."
  exit 0
fi

VERDICT=$(python3 - "$REPORT_FILE" <<'PY' 2>/dev/null || echo "UNKNOWN"
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print((d.get('aurora', {}) or {}).get('verdict', 'UNKNOWN'))
except Exception:
    print('UNKNOWN')
PY
)

SCORE=$(python3 - "$REPORT_FILE" <<'PY' 2>/dev/null || echo "0%"
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    s = (d.get('aurora', {}) or {}).get('score', 0)
    print(f"{s*100:.1f}%")
except Exception:
    print("0%")
PY
)

if [ "$VERDICT" = "APPROVED" ]; then
  echo "✓ VANTAGE APPROVED ($SCORE)"
  exit 0
fi

if [ "$VERDICT" = "REJECTED" ]; then
  echo "✗ VANTAGE REJECTED ($SCORE)"
  echo
  echo "Top issues:"
  python3 - "$REPORT_FILE" <<'PY' 2>/dev/null || echo "  (see vantage-report.json)"
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    for i in (d.get('aurora', {}) or {}).get('topIssues', [])[:5]:
        fname = (i.get('file') or '').split('/')[-1]
        print(f"  [{i.get('severity')}] {fname}: {i.get('description', '')}")
except Exception:
    print("  (see vantage-report.json)")
PY
  echo
  echo "Fix HIGH severity issues above, then retry the commit."
  echo "To bypass: git commit --no-verify (use sparingly)"
  exit 1
fi

echo "⚠  VANTAGE returned unknown verdict: $VERDICT — allowing commit."
exit 0

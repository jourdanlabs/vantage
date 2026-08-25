#!/usr/bin/env bash
# VANTAGE PreToolUse hook — gates git commit / git push when AURORA score is below threshold.
#
# Claude Code invokes this hook before any Bash tool call. Tool input JSON arrives on stdin.
#   Exit 0 + {"decision":"approve", ...}  → allow the command
#   Exit 2 + {"decision":"block",   ...}  → block and show reason to the agent
#
# Escape hatch: commit message containing [vantage-skip] is allowed through with a warning.
# Gate applies to `git commit` (primary) and `git push` (backstop for --no-verify'd commits).

set -euo pipefail

# ── Read tool call from stdin ────────────────────────────────────────────────
TOOL_INPUT=$(cat)

COMMAND=$(printf '%s' "$TOOL_INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print((d.get('command','') or d.get('cmd','')).strip())
except Exception:
    print('')
" 2>/dev/null || echo "")

# Only intercept git commit / git push
GATE_KIND=""
if echo "$COMMAND" | grep -qE '^git[[:space:]]+commit(\b|$)'; then
  GATE_KIND="commit"
elif echo "$COMMAND" | grep -qE '^git[[:space:]]+push(\b|$)'; then
  GATE_KIND="push"
else
  exit 0
fi

# Escape hatch — check *this* commit message for `git commit -m`, else latest for `git push`
if echo "$COMMAND" | grep -q '\[vantage-skip\]'; then
  printf '{"decision":"approve","reason":"[vantage-skip] escape hatch present"}\n' >&2
  exit 0
fi

# ── Locate project root + VANTAGE binary ─────────────────────────────────────
PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

# Use a bash array so nothing is word-split; handles paths with spaces.
VANTAGE_CMD=()
if command -v vantage >/dev/null 2>&1; then
  VANTAGE_CMD=(vantage)
elif [ -x "$PROJECT_ROOT/node_modules/.bin/vantage" ]; then
  VANTAGE_CMD=("$PROJECT_ROOT/node_modules/.bin/vantage")
elif [ -f "$PROJECT_ROOT/bin/vantage.js" ]; then
  VANTAGE_CMD=(node "$PROJECT_ROOT/bin/vantage.js")
fi

if [ ${#VANTAGE_CMD[@]} -eq 0 ]; then
  printf '{"decision":"approve","reason":"VANTAGE not found on PATH — skipping gate. Install with: npm install -g vantage-cli"}\n' >&2
  exit 0
fi

# ── Run analysis ─────────────────────────────────────────────────────────────
REPORT_FILE=$(mktemp -t vantage-gate.XXXXXX.json)
trap 'rm -f "$REPORT_FILE"' EXIT

if ! "${VANTAGE_CMD[@]}" analyze "$PROJECT_ROOT" --output "$REPORT_FILE" >/dev/null 2>&1; then
  # Analysis failed — fail open with a diagnostic so the user notices.
  printf '{"decision":"approve","reason":"VANTAGE analysis failed (project may be too large, CLI misconfigured, or unsupported). Gate skipped."}\n' >&2
  exit 0
fi

# ── Parse verdict ────────────────────────────────────────────────────────────
#
# We surface the PULSAR finding list in a form that an MCP-capable agent
# (Claude Code, Cursor) can feed directly into generate_fix.  We recompute
# the stable finding IDs here using the same algorithm as
# src/mcp/finding-id.ts so the IDs match what generate_fix expects.
VERDICT_JSON=$(python3 - "$REPORT_FILE" "$PROJECT_ROOT" <<'PY' 2>/dev/null || printf '{"verdict":"ERROR"}'
import hashlib, json, os, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    project_root = sys.argv[2]
    aurora = data.get('aurora', {}) or {}
    pulsar = data.get('pulsar', {}) or {}
    top = aurora.get('topIssues', []) or []

    def norm_file(file_path):
        if not file_path:
            return ''
        abs_path = file_path if os.path.isabs(file_path) else os.path.abspath(file_path)
        try:
            rel = os.path.relpath(abs_path, project_root)
            if rel and not rel.startswith('..'):
                return rel.replace(os.sep, '/')
        except ValueError:
            pass
        parts = abs_path.replace('\\', '/').split('/')
        for marker in ('src', 'app', 'lib', 'routes', 'packages'):
            if marker in parts:
                i = parts.index(marker)
                return '/'.join(parts[i:])
        return os.path.basename(abs_path)

    def finding_id(source, file_path, line, type_, description):
        # Mirror computeFindingId() in src/mcp/finding-id.ts
        canonical = '|'.join([
            source,
            norm_file(file_path),
            str(line or 0),
            (type_ or '').lower(),
            (description or '').strip(),
        ])
        h = hashlib.sha1(canonical.encode('utf-8')).hexdigest()[:12]
        return f'{source.lower()}_{h}'

    pulsar_findings = []
    for f in (pulsar.get('adversarialFindings') or [])[:10]:
        pulsar_findings.append({
            'id': finding_id('PULSAR', f.get('file', ''), f.get('line'),
                             f.get('type', ''), f.get('description', '')),
            'severity': f.get('severity'),
            'file': (f.get('file') or '').split('/')[-1],
            'line': f.get('line'),
            'type': f.get('type'),
            'description': f.get('description', ''),
        })

    out = {
        'verdict': aurora.get('verdict', 'UNKNOWN'),
        'score': aurora.get('score', 0),
        'topIssues': [
            {
                'severity': i.get('severity'),
                'file': (i.get('file', '') or '').split('/')[-1],
                'description': i.get('description', ''),
            } for i in top[:5]
        ],
        'pulsarFindings': pulsar_findings,
    }
    print(json.dumps(out))
except Exception as e:
    print(json.dumps({'verdict': 'ERROR', 'error': str(e)}))
PY
)

VERDICT_VAL=$(printf '%s' "$VERDICT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verdict','UNKNOWN'))" 2>/dev/null || echo "UNKNOWN")
SCORE=$(printf '%s' "$VERDICT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"{d.get('score',0)*100:.1f}%\")" 2>/dev/null || echo "0%")

if [ "$VERDICT_VAL" = "APPROVED" ]; then
  printf '%s' "{\"decision\":\"approve\",\"reason\":\"VANTAGE APPROVED ($SCORE)\"}" >&2
  exit 0
fi

if [ "$VERDICT_VAL" = "REJECTED" ]; then
  TOP_ISSUES=$(printf '%s' "$VERDICT_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
lines = [f\"  [{i['severity']}] {i['file']}: {i['description']}\" for i in d.get('topIssues', [])]
print('\n'.join(lines) if lines else '  (see vantage-report.json for details)')
" 2>/dev/null || echo "  (see vantage-report.json for details)")

  # Surface PULSAR finding IDs so the agent can chain generate_fix without
  # re-running analyze. If no findings, skip the auto-fix hint entirely.
  AUTOFIX_HINT=$(printf '%s' "$VERDICT_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
fs = d.get('pulsarFindings', []) or []
if not fs:
    print('')
    sys.exit(0)
# Only hint at findings we can actually auto-fix (null-safety, error-boundary)
fixable = [f for f in fs if f.get('type') in ('null-safety', 'error-boundary', 'missing-error-handling')]
if not fixable:
    print('')
    sys.exit(0)
lines = ['', 'Auto-fix available. If you have the vantage MCP server wired up, you can:']
for f in fixable[:5]:
    lines.append(f\"  • generate_fix(finding_id='{f['id']}') — {f['description'][:70]}\")
lines.append('After each successful generate_fix, apply the returned patch (or call open_fix_pr) and retry this commit.')
print('\n'.join(lines))
" 2>/dev/null || echo "")

  # Different tone for commit vs push — commit is the primary gate, push is last-chance.
  if [ "$GATE_KIND" = "commit" ]; then
    HEADLINE="VANTAGE REJECTED this commit (score: $SCORE)."
    FOOTER="Fix the HIGH severity issues above, then retry. To bypass: add [vantage-skip] to your commit message."
  else
    HEADLINE="VANTAGE REJECTED this push (score: $SCORE). One or more commits appear to have bypassed the commit-time gate."
    FOOTER="Either amend the offending commits to address the issues, or add [vantage-skip] to the git push command (at your own risk)."
  fi

  BLOCK_MSG="$HEADLINE

AURORA found issues that must be addressed:
$TOP_ISSUES
$AUTOFIX_HINT

$FOOTER
Full report: $REPORT_FILE"

  printf '%s' "$BLOCK_MSG" | python3 -c "
import sys, json
print(json.dumps({'decision': 'block', 'reason': sys.stdin.read()}))
" >&2

  exit 2
fi

# Unknown verdict — fail open, noisy.
printf '%s' "{\"decision\":\"approve\",\"reason\":\"VANTAGE status unknown ($VERDICT_VAL) — allowing\"}" >&2
exit 0

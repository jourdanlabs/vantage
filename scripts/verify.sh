#!/usr/bin/env bash
# VANTAGE verification — the contract that says "the tree is shippable."
#
# Runs compile + all test suites + boot checks. Any step that fails causes
# the script to exit non-zero, so CI (and pre-commit, and anyone who runs
# `npm run verify`) gets a single source of truth.
#
# Designed to be fast: target is <60 seconds on a recent laptop.

set -euo pipefail

cd "$(dirname "$0")/.."

ok() { printf '  \e[32m✓\e[0m %s\n' "$1"; }
fail() { printf '  \e[31m✗\e[0m %s\n' "$1"; exit 1; }
step() { printf '\n\e[1m==> %s\e[0m\n' "$1"; }

# Track timing per step so regressions in any one area are visible
T0=$(date +%s)

# ── Step 1: compile the MCP build ───────────────────────────────────────────
step "compile (tsconfig.mcp.json)"
if npx tsc -p tsconfig.mcp.json 2>&1; then
  ok "MCP + engines + CLI compile clean"
else
  fail "MCP compile failed — see output above"
fi

# ── Step 2: fix-template unit tests ─────────────────────────────────────────
step "fix-template tests"
if npx ts-node src/mcp/fix-templates/templates.test.ts 2>&1 | tee /tmp/verify-templates.log; then
  # ts-node exits 0 but let's also grep for the expected footer
  if grep -q "0 fail" /tmp/verify-templates.log; then
    ok "all template cases pass"
  else
    fail "template tests reported failures"
  fi
else
  fail "template test runner errored"
fi

# ── Step 3: NEBULA correctness tests ────────────────────────────────────────
step "NEBULA correctness tests"
if npx ts-node src/engines/nebula/nebula.test.ts 2>&1 | tee /tmp/verify-nebula.log; then
  if grep -q "0 fail" /tmp/verify-nebula.log; then
    ok "NEBULA cases pass (taint caught, sanitizer respected, literal ignored)"
  else
    fail "NEBULA tests reported failures"
  fi
else
  fail "NEBULA test runner errored"
fi

# ── Step 3a: HTTP API auth / bind / path allowlist ─────────────────────────
step "HTTP API auth tests"
if npx ts-node src/api.test.ts 2>&1 | tee /tmp/verify-api.log; then
  if grep -q "0 fail" /tmp/verify-api.log; then
    ok "HTTP API: Bearer required, loopback bind, path allowlist"
  else
    fail "HTTP API tests reported failures"
  fi
else
  fail "HTTP API test runner errored"
fi

# ── Step 4: scoring correctness tests ───────────────────────────────────────
step "bench scoring tests"
pushd packages/vantage-bench >/dev/null
if npx ts-node tests/scoring.test.ts 2>&1 | tee /tmp/verify-scoring.log; then
  if grep -q "0 fail" /tmp/verify-scoring.log; then
    ok "scoring rule cases pass (strict matching, scope, no line-0 leak)"
  else
    fail "scoring tests reported failures"
  fi
else
  fail "scoring test runner errored"
fi
popd >/dev/null

# ── Step 5: MCP server boots ────────────────────────────────────────────────
step "MCP server boots from compiled output"
if timeout 3 node dist/mcp/server.js < /dev/null; then
  ok "vantage-mcp server boots clean"
else
  status=$?
  # 124 = timeout expired (expected — we kill it after 3s) OR 0 = clean exit
  if [ $status -eq 124 ] || [ $status -eq 143 ]; then
    ok "vantage-mcp server boots clean (timeout after 3s as expected)"
  else
    fail "MCP server failed to start (exit $status)"
  fi
fi

# ── Step 6: CLI bin runs and prints help ────────────────────────────────────
step "vantage CLI runs from compiled output"
if node bin/vantage.js --help > /tmp/verify-help.txt 2>&1; then
  if grep -q "Autonomous Code Evolution Engine" /tmp/verify-help.txt; then
    ok "vantage CLI help output renders"
  else
    fail "CLI help output missing expected banner — see /tmp/verify-help.txt"
  fi
else
  fail "CLI --help exited non-zero"
fi

# ── Step 7: end-to-end analyze on self ──────────────────────────────────────
step "end-to-end analyze (vantage on its own src/engines)"
if node bin/vantage.js analyze src/engines --output /tmp/verify-selfscan.json >/dev/null 2>&1; then
  if [ -s /tmp/verify-selfscan.json ]; then
    VERDICT=$(python3 -c "import json; print(json.load(open('/tmp/verify-selfscan.json'))['aurora']['verdict'])")
    SCORE=$(python3 -c "import json; print(f\"{json.load(open('/tmp/verify-selfscan.json'))['aurora']['score']:.3f}\")")
    ok "self-scan produces report (verdict=$VERDICT, score=$SCORE)"
  else
    fail "self-scan report file is empty"
  fi
else
  fail "self-scan analyze exited non-zero"
fi

T1=$(date +%s)
printf '\n\e[1m==> verify complete in %ss\e[0m\n' $((T1 - T0))

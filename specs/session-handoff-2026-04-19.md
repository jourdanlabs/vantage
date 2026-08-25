# VANTAGE session handoff — 2026-04-19

Context for Videl (or any Claude Code session) picking up the repo after today's work.

## What changed in this session

### Brick 1 — Distribution (existed; hardened + extended)

All the scaffolding you built earlier is still in place. This session fixed the ship-blockers surfaced by an actual fresh-install test and added missing surfaces.

**Fixed:**
- `hooks/claude-code/pre-commit-gate.sh` and `hooks/pre-commit/run-vantage.sh` — were calling `$VANTAGE_BIN "$PROJECT_ROOT"` without the `analyze` subcommand (would have silently approved every commit). Rewrote with bash arrays (spaces-in-paths safety), explicit `analyze` subcommand, and differentiated commit-vs-push messaging. Both pass `bash -n`.
- `bin/vantage-mcp.js` and `bin/vantage.js` — were registering ts-node at runtime (fresh installs would fail without typescript installed globally). Now resolve `dist/mcp/server.js` / `dist/cli.js` first, with ts-node fallback only in dev checkouts.
- `package.json` — `main` now points at `dist/cli.js` (was `dist/main/index.js` — electron). Moved `typescript` to dependencies (NEBULA imports it at runtime). Removed electron-era cors/express. Added `engines.node >= 18`, `repository`, `homepage`, `bugs`, launch-quality keywords, `prepublishOnly` script.
- `tsconfig.mcp.json` — now includes `src/cli.ts` so the CLI compiles into `dist/`.

**Added:**
- `--semantic` CLI flag on `vantage analyze` (parity with the MCP tool's `options.semantic`)
- Autofix hints in the Claude Code hook — when a commit is blocked, the JSON block message now includes `generate_fix(finding_id='...')` suggestions with stable SHA1 finding IDs that match what the MCP server computes.
- `.github/actions/vantage/action.yml` gained an `autofix: true` input and an `autofix.js` runner that commits verified fixes to the PR branch and re-runs analyze.
- Root `README.md` completely rewritten — launch-quality. Leads with the agentic story, shows all 6 engines, documents the dual pattern/semantic modes.
- `src/mcp/README.md` — full MCP tool reference with install instructions for Claude Code, Cursor, Aider.

### Brick 2 — Auto-fix closed loop (new this session)

Design in `specs/adr-0001-auto-fix-loop.md`. Implementation:

- `src/mcp/fix-templates/` — three deterministic templates: `null-safety.ts` (optional-chaining rewrite), `error-boundary.ts` (JSON.parse try/catch wrap, JS/TS-aware), `hardcoded-secret.ts` (secret → env var). All extend `FixTemplate` interface in `types.ts`.
- `src/mcp/fix-templates/templates.test.ts` — 17 cases, all passing. Includes the JS-vs-TS syntax regression case I caught testing against NodeBB (`err.message` vs `(err as Error).message`).
- `src/mcp/tools/generate-fix.ts` — new MCP tool. Composes templates + `verify_fix` gate. Every candidate patch applies to a temp copy, re-runs the full pipeline, and is only returned if the original finding resolved with no new HIGH/CRITICAL.
- `src/mcp/tools/open-fix-pr.ts` — new MCP tool. Uses `gh` CLI with a manual-command fallback. Branch name defaults to `vantage/autofix-<random>`; commit message includes the verification result.
- `src/mcp/tools/verify-fix.ts` — rewrote the broken finding-ID parsing. Now uses stable SHA1 IDs from `src/mcp/finding-id.ts` keyed on `source|normalizedFile|line|type|description` so IDs survive the temp-copy `cp -r`.
- `src/mcp/tools/get-findings.ts` — fixed a dedup bug where AURORA top-issues were being re-added as synthetic ECLIPSE entries alongside the PULSAR entries they were promoted from.

### Brick 3 — NEBULA semantic engine (new this session)

Design in `specs/adr-0002-semantic-engine.md`. Implementation:

**Core engine:**
- `src/engines/nebula/ir.ts` — minimal IR (Statement: Assign/FieldAssign/ExpressionStmt/Return/Conditional/Loop/TryCatch/Throw; Value: Literal/Variable/FieldAccess/Call/Template/Binary/Unknown; ModuleIR with functions + topLevel).
- `src/engines/nebula/analyzer.ts` — intraprocedural flow-sensitive taint analyzer. Per-variable taint labels, conservative env join at branch/loop/try boundaries, method-call receiver-taint propagation, sanitizer-clears-taint semantics.
- `src/engines/nebula/index.ts` — orchestrator. Walks directory, dispatches `.ts/.tsx/.js/.jsx/.mjs` to TypeScript frontend, dispatches `.py` to Python subprocess frontend, runs analyzer, returns findings.
- `src/engines/nebula/nebula.test.ts` — 9 cases, all passing.

**TypeScript frontend:**
- `src/engines/nebula/frontend-typescript.ts` — uses the `typescript` npm package to parse, lowers AST to IR.

**Python frontend (added late in session — the "full mosey"):**
- `src/engines/nebula/frontend-python.ts` — Node-side dispatcher. Spawns `python3 -m vantage.nebula_frontend --batch` with file list on stdin, reads IR JSON from stdout. Gracefully degrades when python3 or vantage-x isn't available (logs a note, continues).
- `src/vantage/nebula_frontend.py` — Python-side parser. Uses stdlib `ast`. Ships inside the `vantage-x` PyPI package so pip installs get it automatically. Handles FunctionDef, AsyncFunctionDef, ClassDef (lifts methods), Assign/FieldAssign, Return, If, While, For, Try, Raise, With, BinOp, JoinedStr (f-strings), Attribute, Subscript, Call. Unknown constructs return `{kind: 'Unknown'}` with a note.

**Catalog (`src/engines/nebula/catalog/javascript.ts`):**
- 38 total source entries (Express, Koa, Fastify, Hapi, AWS Lambda for JS; Flask, Django, sys, os for Python)
- 47 total sink entries (code exec, deserialization, command exec, SQL, template injection, filesystem, SSRF, redirect across both languages)
- 20 total sanitizer entries (type coercion, URL encoding, SQL escapers, shell quoters, path validators, safe YAML, json.loads across both languages)

**Pipeline integration:**
- `src/engines/index.ts` — runs NEBULA after PULSAR when `opts.semantic === true`. Merges NEBULA findings into `pulsar.adversarialFindings` with `[NEBULA]` prefix and dedups against existing PULSAR entries on `(file, line, type)`.
- `src/mcp/schemas.ts` — `AnalyzeInput.options.semantic: boolean`.
- `src/mcp/tools/analyze.ts` — plumbs semantic through. Cache key includes semantic so pattern/semantic results don't collide.

### Brick 4 — Leaderboard (existed; credibility-hardened)

All the scoring issues from the punch list are fixed:
- `packages/vantage-bench/src/scoring.ts` rewritten — strict `endsWith` with path-segment boundary (no basename fallback), explicit `scope: 'file' | 'project'` field instead of the line=0 wildcard, null-propagating F1 aggregation.
- `packages/vantage-bench/src/ground-truth/schema.ts` — `Vulnerability.scope` field added.
- `packages/vantage-bench/src/runners/base.ts` — `toCorpusRelativePosix()` helper called at the runner boundary in all four runners (VANTAGE, Semgrep, SonarQube, CodeQL).
- `packages/vantage-bench/tests/scoring.test.ts` — 8 cases locking in the new behavior, including basename-collision-rejected and no-line-0-wildcard-leak.

**Weekly workflow** (`.github/workflows/benchmark-weekly.yml`) runs all four tools in parallel with continue-on-error. Merge-and-commit job consolidates artifacts into `sites/leaderboard/src/data/results.json`.

**Leaderboard site** (`sites/leaderboard/`) renders two VANTAGE rows (pattern and semantic) plus Semgrep and SonarQube. Semgrep/SonarQube still show v1 numbers with "pending rerun" badges until the first real CI run.

### PyPI package (new this session)

- `pyproject.toml` at repo root — hatchling build, zero runtime dependencies, properly classified for PyPI.
- `src/vantage/analyzer.py` — updated to use `vantage analyze` subcommand (was `run`) and pass `--semantic` flag when requested.
- `src/vantage/cli.py` — added `--semantic` argparse flag.
- `_find_vantage_bin()` now searches PATH, `$VANTAGE_BIN` env var, `node_modules/.bin`, npm-global, nvm (scans version dirs), volta, yarn, pnpm, homebrew, `/usr/local/bin`. Falls through with a helpful install message if not found.
- Entry point: `vantage-py` (to avoid colliding with the `vantage` node binary).
- Python API unchanged: `from vantage import analyze; analyze(path, semantic=True)` returns a typed `VantageReport`.

### Tooling + docs

- `scripts/verify.sh` — single-command test runner. 7 steps, ~5 seconds, exits non-zero on any failure. Wired to `npm run verify` and `npm test`.
- `CONTRIBUTING.md` — covers adding a NEBULA source/sink/sanitizer, adding a fix template, adding a leaderboard runner, disputing a GT entry.
- `benchmarks/SCORING_V2_DELTA.md` — documents the v1 → v2 scoring rule change with every number that moved and why.
- `benchmarks/NEBULA_V0_DELTA.md` — documents the semantic-mode delta, the Juice Shop SSTI catch, the PyGoat Python receipts, and the discipline of not expanding GT to recover F1 on our own findings.
- `launch/` — blog post, maintainer heads-up emails, 90-second demo shot list, publish checklist, receipts doc. All ready to go.

## Current numbers (v2 scoring)

| | NodeGoat F1 | Juice Shop F1 | Aggregate | Runtime |
|---|---|---|---|---|
| VANTAGE pattern | 100.0% | 72.0% | **83.7%** | ~200ms |
| VANTAGE semantic | 80.0% | 54.5% | **64.9%** | ~600ms |
| Semgrep (v1, pending) | 21.1% | 7.1% | 12.8% | ~18s |
| SonarQube (v1, pending) | 0.0% | 5.8% | 2.9% | ~38s |

**Real-world receipts:**
- NodeBB (150k LOC TS/JS): 100 findings, 31 auto-fixable under templates, 3/5 tested generate_fix calls succeeded
- PyGoat (Python): 7 NEBULA findings — pickle RCE (Flask + Django), subprocess injection, YAML deserialization RCE, path traversal, arbitrary file read, SSRF. 173ms.
- Juice Shop semantic mode catches SSTI in `routes/userProfile.ts:87` (the headline pug.compile bug) that Semgrep/Sonar/PULSAR-pattern all miss.

## How to run things

```bash
# Single-command sanity check
npm run verify                    # compile + all tests + boot + self-scan in ~5s

# Build
npm run build:mcp                 # compiles src/mcp, src/engines, src/cli → dist/

# Test individual suites
npx ts-node src/mcp/fix-templates/templates.test.ts    # 17 cases
npx ts-node src/engines/nebula/nebula.test.ts          # 9 cases
cd packages/vantage-bench && npx ts-node tests/scoring.test.ts   # 8 cases

# CLI
node bin/vantage.js analyze <path>                  # pattern-only
node bin/vantage.js analyze <path> --semantic       # + NEBULA

# MCP server (stdio)
node bin/vantage-mcp.js

# E2E fix loop on a real repo
node scripts/e2e-real-repo.js /tmp/receipts/NodeBB

# Bench harness
cd packages/vantage-bench && node bin/vantage-bench.js run --tool VANTAGE

# Python
pip install -e .                  # or: pip install vantage-x once published
vantage-py <path> --semantic      # or: from vantage import analyze
PYTHONPATH=src python3 -m vantage.nebula_frontend <file.py>    # IR JSON to stdout
```

## Known gaps / not-yet-done

**Code-level, fixable:**
- The two NodeGoat NEBULA "FPs" (contributions.js:34 extra eval, index.js:72 open redirect) are real vulnerabilities the GT doesn't document. Do NOT add them to `juice-shop.json` or `nodegoat.json` to "fix" the F1. Wait for community review PRs.
- Python frontend doesn't handle lambdas, list/dict/set comprehensions, generator expressions, or walrus operator — returns Unknown for those nodes. Tracked as v0.3 catalog/frontend expansion.
- NEBULA's sanitizer semantics are coarse — if a sanitizer is matched on a call, the return value drops ALL taint labels. A more precise implementation would tag labels as "neutralized against danger-class X" and recheck at sink time.
- No fix templates for NEBULA taint findings yet. Sanitizer-insertion templates are their own sub-project (see ADR-0002).

**Scope, v1.1+:**
- Interprocedural NEBULA (cross-function taint). Currently intraprocedural only — if taint passes through a helper function, it's dropped on the call boundary.
- LLM fallback for `generate_fix`. Covers the ~60% of finding types no template can express. Stubbed today with clean "no template matches" response.
- Swift frontend for NEBULA (Leland's Helix iOS work needs this).
- Field-sensitivity (`obj.a` tainted vs `obj.b` independently tracked).

**Launch-day, human-touch:**
- `npm publish vantage` and `npm publish vantage-mcp`
- `pip install twine && python -m twine upload dist/*` for vantage-x after `python -m build`
- Deploy `sites/leaderboard/dist/` to Cloudflare Pages or Vercel; DNS `benchmark.vantage.dev`
- Trigger `gh workflow run benchmark-weekly.yml` to populate Semgrep/Sonar v2 numbers
- Record the 90-second demo video per `launch/demo-script.md`
- Send the four maintainer heads-up emails (templates in `launch/maintainer-emails.md`)

## Repo layout quick reference

```
src/
  cli.ts                         # vantage CLI entry (analyze, report, --semantic)
  engines/
    index.ts                     # pipeline orchestrator
    meteor.ts nova.ts eclipse.ts pulsar.ts aurora.ts   # existing engines
    nebula/
      ir.ts                      # shared IR schema
      analyzer.ts                # intraprocedural taint analyzer
      frontend-typescript.ts     # TS/JS AST → IR
      frontend-python.ts         # Node dispatcher to Python subprocess
      catalog/javascript.ts      # 38 sources, 47 sinks, 20 sanitizers (JS+Py)
      index.ts                   # orchestrator, per-file dispatch
      nebula.test.ts             # 9 correctness cases
  mcp/
    server.ts                    # MCP server, registers 5 tools
    schemas.ts                   # zod input schemas
    cache.ts                     # ~/.vantage/cache/ report cache
    finding-id.ts                # stable SHA1 finding IDs
    tools/
      analyze.ts verify-fix.ts get-findings.ts
      generate-fix.ts            # NEW: composes templates + verify_fix
      open-fix-pr.ts             # NEW: gh CLI branch-commit-push-PR
    fix-templates/
      types.ts diff.ts index.ts
      null-safety.ts error-boundary.ts hardcoded-secret.ts
      templates.test.ts          # 17 correctness cases
  vantage/
    __init__.py analyzer.py cli.py models.py
    nebula_frontend.py           # NEW: Python AST → IR JSON

packages/vantage-bench/          # benchmark harness (fixed scoring)
  src/scoring.ts runners/ ground-truth/
  tests/scoring.test.ts

bin/
  vantage.js                     # CLI shim (dist-first, ts-node fallback)
  vantage-mcp.js                 # MCP shim (same pattern)
  install-hook.js                # Claude Code hook installer

hooks/
  claude-code/pre-commit-gate.sh   # PreToolUse hook for Claude Code
  pre-commit/run-vantage.sh        # pre-commit framework hook

.github/
  actions/vantage/                 # GitHub Action (with autofix: true)
  workflows/benchmark-weekly.yml   # parallel 4-tool bench, weekly cron

sites/leaderboard/                 # Astro site, builds clean to dist/

scripts/
  verify.sh                       # single-command test runner
  e2e-real-repo.js                # clone real repo → find → fix → report

specs/
  ROADMAP.md                      # 4-brick strategic plan
  adr-0001-auto-fix-loop.md
  adr-0002-semantic-engine.md
  brick-1-distribution.md
  brick-4-leaderboard.md
  PUNCHLIST.md                    # audit trail of bugs caught and fixed
  session-handoff-2026-04-19.md   # this file

benchmarks/
  SCORING_V2_DELTA.md             # v1 → v2 scoring change + receipts
  NEBULA_V0_DELTA.md              # semantic mode delta + PyGoat receipts
  receipts-hunt.js                # OSS repo scanner

launch/
  blog-post.md maintainer-emails.md demo-script.md
  publish-checklist.md receipts.md receipts-data.json

CONTRIBUTING.md                   # how to add sources/sinks/templates/runners
README.md                         # launch-ready root README
pyproject.toml                    # vantage-x PyPI package
```

## TL;DR for the next session

VANTAGE 1.0 is technically complete for v1 of the roadmap. The system is polyglot (JS/TS + Python), has a verified auto-fix loop with 3 shipped templates, catches real OWASP vulnerabilities in both JS and Python corpora, has an open strict-scored leaderboard, compiles cleanly, installs cleanly from a fresh tarball, and has 34 test assertions all passing.

What's left is mostly human-touch launch work (publish to npm/PyPI, deploy site, send emails, record video). The technical backlog is all explicitly-v1.1-or-v2 ADR-scoped items.

If you're picking this up: run `npm run verify` first to confirm the tree is clean, then read `specs/ROADMAP.md` and `benchmarks/NEBULA_V0_DELTA.md` to get the current state. Everything else falls out from there.

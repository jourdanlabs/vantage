# VANTAGE

**Autonomous Code Evolution Engine.** Finds bugs, gates commits, and — where a template exists — proposes a verified patch.

The product path is **CLI + MCP** (`vantage` / `vantage-mcp`). That is what agents and CI invoke. There is also a leftover local HTTP door (`src/api.ts`, port 7474) for old benchmark harnesses. It is not the published interface: it binds loopback only, requires `VANTAGE_API_TOKEN`, and will not listen if the token is unset.

What is actually true, without the three-pillar overclaim:

1. **Semantic taint (NEBULA)** can catch flows pattern matchers miss. The named example is Juice Shop SSTI at `routes/userProfile.ts:87` (`pug.compile` after many assignments). On the published OWASP catalog, turning NEBULA on **drops** strict F1 because extra findings are scored as FP until GT review lands. Dual-track numbers live in [`benchmarks/NEBULA_V0_DELTA.md`](benchmarks/NEBULA_V0_DELTA.md) — they are not "in review" as a way to hide the drop.
2. **Verified auto-fix** exists for **three template families** in v1 (null-safety via optional chaining, JSON.parse via try/catch, hardcoded secrets via env extraction). Every other finding type returns `"no template matches"`. Do not read "verified auto-fix" as coverage of the detector catalog.
3. **Agentic integration** is the load-bearing product surface: MCP tools, a Claude Code commit hook, and a GitHub Action. That claim does not depend on the HTTP door.

The named-incumbent evidence that belongs in a diligence conversation is the sealed Kaioken Python hold-outs against **Bandit**, not the n=4 / n=9 OWASP table below. See **Benchmarks**.

---

## Quick start

### CLI

```bash
npm install -g vantage
vantage analyze /path/to/your/project
```

Runs the full pipeline, prints the AURORA verdict, saves a JSON report. On a 10k-LOC repo this takes about a second.

### With semantic mode

```bash
vantage analyze /path/to/your/project --semantic
```

Adds intraprocedural taint tracking via the NEBULA engine. Roughly 3–5× slower, catches a class of bugs pattern matchers cannot.

### VS Code extension

```bash
npm run build:mcp
cd packages/vantage-vscode && npm install && npm run compile
# F5 in VS Code with this folder open, or package a .vsix
```

Commands: **VANTAGE: Scan Workspace** · diagnostics in Problems · settings for `surface` / `semantic`.  
Details: [`packages/vantage-vscode/README.md`](packages/vantage-vscode/README.md).

### MCP server (Claude Code, Cursor, Aider, …)

```bash
npm install -g vantage-mcp
```

Then in `~/.claude/settings.json`:

```json
{ "mcpServers": { "vantage": { "command": "vantage-mcp" } } }
```

Restart your agent. VANTAGE's five tools — `analyze`, `get_findings`, `verify_fix`, `generate_fix`, `open_fix_pr` — appear in the tool namespace. The agent can run the whole find-and-fix loop with no custom integration work.

### Claude Code commit gate

```bash
vantage-mcp install-hook
```

Installs a `PreToolUse` hook into `.claude/settings.json`. Any `git commit` the agent runs is gated by AURORA's verdict. Below threshold → commit blocked with a structured reason that includes auto-fix hints the agent can action directly.

### Local HTTP door (optional, not the product)

```bash
export VANTAGE_API_TOKEN='a long random secret'
# optional: export VANTAGE_ALLOWED_ROOT=/path/you/may/scan
npx ts-node src/api.ts
```

Listens on `127.0.0.1:7474` only. `GET /vantage/health` is unauthenticated liveness. `POST /vantage/analyze` and `/vantage/quick` require `Authorization: Bearer $VANTAGE_API_TOKEN` and will 403 any path outside `VANTAGE_ALLOWED_ROOT` (default: cwd). If the token is unset, the process refuses to listen. Do not bind this to a public interface; the code will throw if you try.

### GitHub Action

```yaml
- uses: jourdanlabs/vantage-action@v1
  with:
    target: '.'
    threshold: '0.80'
    autofix: 'true'   # optional: open fix commits automatically
```

Runs on every PR. If the verdict is REJECTED and `autofix: true`, VANTAGE generates verified patches and commits them to the PR branch; CI re-runs and the post-fix verdict determines pass/fail.

---

## The five engines

VANTAGE's pipeline is named engine by engine for a reason — each stage answers a different question:

| Engine | Asks | Output |
|---|---|---|
| **METEOR** | What's in the codebase? | Files, functions, complexity, LOC, TODOs |
| **NOVA** | How do the pieces connect? | Dependency graph, circular deps, god modules |
| **ECLIPSE** | Which files are risky? | Per-file risk score 0.0–1.0 |
| **PULSAR** | What could break this? | Adversarial findings (injection, null-safety, error-boundary, etc.) |
| **NEBULA** *(opt-in)* | Where does user data flow unsafely? | Taint findings from source → sink |
| **AURORA** | Is this ship-safe? | Verdict: APPROVED or REJECTED, with score |

The full pipeline runs in ~100ms on typical repos. NEBULA adds seconds because it requires AST lowering and flow analysis; it's opt-in via `--semantic` for that reason.

---

## The find-and-fix loop

Here's what a Claude Code agent does when it detects a problem in the working tree:

```
analyze(target) → reportId, verdict: REJECTED

get_findings(reportId, { severity: "HIGH" }) → [
  { id: "pulsar_a813b1ac26e9", type: "error-boundary", file: "src/handler.ts", line: 14, ... }
]

generate_fix(reportId, "pulsar_a813b1ac26e9") → {
  success: true,
  templateId: "error-boundary-jsonparse-trycatch",
  patch: "... unified diff ...",
  verification: { verdict: "APPROVED", resolved: 1, remaining: 0, newFindings: 0 }
}

# Apply patch, commit, push. Or:
open_fix_pr(target, patch, title) → { prUrl: "https://github.com/.../pull/1234" }
```

Three template families ship in v1 (null-safety via optional chaining, JSON.parse via try/catch, hardcoded secrets via env var extraction). Other finding types currently return a "no template matches" response; that is the v1 coverage, not a footnote. An LLM fallback is not in this tree as a shipped path.

---

## Benchmarks

Do not fuse these boards. Different corpora, different scorers, different incumbents.

### Named incumbent — sealed Python vs Bandit (Kaioken)

These are the numbers to lead with when someone asks whether VANTAGE beats a real SAST. Same scorer (`score_sarif.py --match-mode cwe`), one-shot sealed hold-out, **Bandit only**. Not "beats every SAST." Not 100/0.

| Slice | VANTAGE Youden | Bandit Youden | Source in this tree |
|---|---:|---:|---|
| FastAPI sealed | **+31.4%** (TPR 39.3% / FPR 7.9%) | **+8.1%** (TPR 10.7% / FPR 2.7%) | `receipts/sealed-holdout/python-v2-fastapi-2026-08-17/OPENED.md` |

Django sealed (+42.7% vs Bandit +8.4%, same scorer, SSTI still 0) is in the chamber gate packet, not yet an `OPENED.md` in this repository. Do not paste Django into a public README until that receipt is in-tree.

What did **not** transfer on FastAPI, and is product truth rather than leftover: **SSTI (CWE-1336) is 0** and **redirect (CWE-601) is 0**. Crypto / cookie / pickle-yaml gates transferred; framework-API sinks did not. FPR is higher than Bandit's (7.9% vs 2.7%) — Youden win, not precision win.

Snyk is untested in public because their terms prohibit publication. SonarQube and Semgrep on this Python slice are not the Bandit row above.

### OWASP JS/TS table (n=4 + n=9)

Ground truth: OWASP NodeGoat (4 scoreable entries) + OWASP Juice Shop (9 scoreable entries). This is a tiny board. It is not the diligence headline. Methodology: `benchmarks/` and [benchmark.vantage.dev/methodology](https://benchmark.vantage.dev/methodology).

Under v2 scoring (strict `endsWith` + ±5-line):

|  | NodeGoat F1 | Juice Shop F1 | Aggregate | Runtime |
|---|---|---|---|---|
| **VANTAGE** (pattern-only) | **100.0%** | **72.0%** | **83.7%** | ~200ms–1.2s depending on run |
| **VANTAGE** (+ NEBULA) | **80.0%** | **54.5%** | **64.9%** | ~600ms |
| Semgrep (OWASP + nodejs + javascript) | 21.1% | 7.1% | 12.8% | ~18s |
| SonarQube Community | 0.0% | 5.8% | 2.9% | ~38s |

NEBULA's drop is the published dual-track in [`benchmarks/NEBULA_V0_DELTA.md`](benchmarks/NEBULA_V0_DELTA.md): extra findings vs the conservative GT catalog, including the Juice Shop SSTI that pattern-only misses. We do not expand GT after the run to recover F1.

Semgrep and SonarQube rows on this table are the v2 board as published; some older write-ups still cite v1.

---

## Installation (from source)

```bash
git clone https://github.com/jourdanlabs/vantage && cd vantage
npm install
npm run build:mcp     # compile the MCP server to dist/
npm link              # expose vantage + vantage-mcp globally
```

---

## Documentation

- **Design decisions:** [`specs/`](specs/) — ADR-0001 (auto-fix loop), ADR-0002 (semantic engine / NEBULA), plus the original build specs and punch list.
- **MCP tool reference:** [`src/mcp/README.md`](src/mcp/README.md).
- **Benchmark methodology & scoring rules:** [`benchmarks/SCORING_V2_DELTA.md`](benchmarks/SCORING_V2_DELTA.md).
- **NEBULA v0 delta:** [`benchmarks/NEBULA_V0_DELTA.md`](benchmarks/NEBULA_V0_DELTA.md).

---

## License

Apache-2.0. Benchmark ground-truth catalogs under CC-BY-4.0.

Built by JourdanLabs.

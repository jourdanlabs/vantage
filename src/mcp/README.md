# VANTAGE MCP server

A Model Context Protocol server that exposes VANTAGE's static-analysis pipeline to any MCP-aware client — Claude Code, Cursor, Aider, Cline, Zed, etc. Wraps the existing `vantage` CLI so there's one source of truth for analysis logic.

The server exposes five tools that compose cleanly: `analyze` produces a report, `get_findings` filters it by severity or file, `verify_fix` applies and verifies a candidate patch, `generate_fix` produces a verified patch from a finding, and `open_fix_pr` commits a patch to a new branch and opens a PR.

## Install

```bash
npm install -g vantage vantage-mcp
```

For local development from a source checkout:

```bash
git clone https://github.com/jourdanlabs/vantage && cd vantage
npm install && npm run build:mcp
npm link    # exposes `vantage-mcp` globally
```

## Wire up to Claude Code

Add to `~/.claude/settings.json` (or the project-level `.claude/settings.json`):

```json
{
  "mcpServers": {
    "vantage": {
      "command": "vantage-mcp"
    }
  }
}
```

Restart Claude Code. All five tools appear under the `mcp__vantage_*` namespace.

To also install the PreToolUse gate that blocks commits below threshold:

```bash
vantage-mcp install-hook
```

## Wire up to Cursor

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "vantage": { "command": "vantage-mcp" }
  }
}
```

Reload the IDE. Tools appear in Cursor's agent tool list.

## Wire up to Aider / Cline / Zed / any MCP client

The server speaks stdio transport. Any client that takes a command string for an MCP server accepts `vantage-mcp` directly.

---

## Tools

### `analyze`

Runs the full COSMIC pipeline against a project directory and returns the AURORA verdict, top issues, breakdown scores, and a `reportId` that other tools reference.

**Input:**

```json
{
  "target_path": "/absolute/path/to/project",
  "options": {
    "engine": "PULSAR",
    "threshold": 0.80,
    "semantic": false,
    "surface": "security",
    "includeTests": false
  }
}
```

| Option | Default | Notes |
|--------|---------|--------|
| `semantic` | `false` | NEBULA taint (slower) |
| `surface` | `all` | `security` \| `quality` \| `all` — use `security` in IDE demos |
| `includeTests` | `false` | Keep test/spec paths when true |

**Output** — structured JSON + a human-readable text block, both as MCP content:

```json
{
  "reportId": "e7b4a1a2-...",
  "verdict": "APPROVED",
  "score": 0.92,
  "scorePct": "92.0%",
  "topIssues": [
    { "severity": "MED", "file": "src/handler.ts", "line": 14, "description": "JSON.parse() without try/catch" }
  ],
  "summary": "Analyzed 42 files, 177 functions, 9,746 lines of code...",
  "breakdown": { "complexityScore": 0.83, "dependencyScore": 1.00, "riskScore": 0.85, "adversarialScore": 1.00 },
  "metrics": { "files": 42, "functions": 177, "linesOfCode": 9746, "circularDeps": 0, "findings": 2, "todos": 6 },
  "cached": false,
  "durationMs": 1199
}
```

Repeated calls on the same directory return cached results (content-hash keyed in `~/.vantage/cache/`) in under 50ms.

### `get_findings`

Returns a filtered subset of findings from a previous `analyze` call. Use this instead of re-reading the full report — the report JSON can be 100KB+.

**Input:**

```json
{
  "report_id": "e7b4a1a2-...",
  "filters": {
    "severity": "HIGH",
    "engine": "PULSAR",
    "file": "handler.ts"
  }
}
```

**Output:** a list of findings with stable content-addressed IDs:

```json
{
  "reportId": "e7b4a1a2-...",
  "findings": [
    {
      "id": "pulsar_a813b1ac26e9",
      "source": "PULSAR",
      "severity": "MED",
      "file": "src/handler.ts",
      "line": 14,
      "type": "error-boundary",
      "description": "JSON.parse() without try/catch"
    }
  ],
  "total": 2,
  "filtered": 1
}
```

Finding IDs are SHA1-based and stable across re-runs, so they're safe to reference in follow-up tool calls.

### `verify_fix`

Applies a patch to a temp copy of the target, re-runs the full pipeline, and reports which of the original findings are resolved, which remain, and which (if any) are new. This is the gate that protects every auto-generated fix.

**Input:**

```json
{
  "target_path": "/absolute/path/to/project",
  "patch": "<unified diff>",
  "report_id": "e7b4a1a2-...",
  "original_findings": ["pulsar_a813b1ac26e9"],
  "threshold": 0.80
}
```

**Output:**

```json
{
  "resolvedFindings": ["pulsar_a813b1ac26e9"],
  "remainingFindings": [],
  "newFindings": [],
  "verdict": "APPROVED",
  "score": 0.92,
  "scorePct": "92.0%",
  "patchApplied": true
}
```

The temp copy is cleaned up after the re-analysis. The user's working tree is never touched.

### `generate_fix`

Takes a finding ID and produces a verified patch — or, if no template matches, returns a clear "no fix available" response. Every candidate patch passes through `verify_fix` before being returned, so a successful response means the patch has already been verified to resolve the target finding without introducing new HIGH/CRITICAL issues.

**Input:**

```json
{
  "target_path": "/absolute/path/to/project",
  "report_id": "e7b4a1a2-...",
  "finding_id": "pulsar_a813b1ac26e9",
  "threshold": 0.80,
  "allow_llm_fallback": false
}
```

**Output** — success case:

```json
{
  "success": true,
  "findingId": "pulsar_a813b1ac26e9",
  "templateId": "error-boundary-jsonparse-trycatch",
  "rationale": "Hoisted `config` declaration and wrapped `JSON.parse` in a try/catch that re-throws with context.",
  "patch": "--- a/src/handler.ts\n+++ b/src/handler.ts\n@@ -10,7 +10,13 @@\n...",
  "verification": {
    "verdict": "APPROVED",
    "score": 0.922,
    "resolvedFindings": ["pulsar_a813b1ac26e9"],
    "remainingFindings": [],
    "newFindings": []
  },
  "attemptedTemplates": [
    { "templateId": "error-boundary-jsonparse-trycatch", "applied": true, "verified": true }
  ]
}
```

Failure case returns `success: false` with a `reason` and the list of templates that were attempted.

**Templates shipping in v1:** `null-safety-optional-chaining` (deep-property-access → optional chaining), `error-boundary-jsonparse-trycatch` (unguarded `JSON.parse` → try/catch wrap).

LLM fallback (`allow_llm_fallback: true`) is stubbed in v1 and ships in v2.

### `open_fix_pr`

Takes a verified patch, applies it to a fresh branch, commits it, pushes, and opens a PR via the `gh` CLI. If `gh` isn't installed or auth isn't configured, returns `success: true` with a `manualNextStep` string the user can copy-paste.

**Input:**

```json
{
  "target_path": "/absolute/path/to/project",
  "patch": "<unified diff>",
  "title": "Fix: wrap JSON.parse in try/catch (VANTAGE auto-fix)",
  "body": "Auto-generated by VANTAGE. See commit message for verification details.",
  "branch": "vantage/autofix-a1b2c3",
  "base": "main"
}
```

**Output:**

```json
{
  "success": true,
  "branch": "vantage/autofix-a1b2c3",
  "commitSha": "abcdef1234",
  "prUrl": "https://github.com/org/repo/pull/1234"
}
```

The branch name, base branch, and body are all optional. Branch name defaults to `vantage/autofix-<random>`; base branch defaults to `origin/HEAD` (usually `main`). The commit message always includes the provenance ("VANTAGE auto-fix, passed the four-gate verification") so you can trace a landed fix back to the `verify_fix` run that approved it.

---

## Canonical agent flow

The intended pattern for an agent (or a human with an MCP-aware IDE) that wants to find and fix issues:

1. `analyze(target_path)` → `reportId`
2. `get_findings(reportId, { severity: "HIGH" })` → list of finding IDs
3. For each finding: `generate_fix(reportId, finding_id)` → verified patch or "no fix available"
4. For each successful fix: either apply to the working tree locally, or `open_fix_pr(patch, ...)` to land it as a PR

Each step is independent. Agents that only want findings stop at step 2; agents that do end-to-end auto-remediation run all four.

## Performance envelope

`analyze` on a 10k-LOC TypeScript project: 1–2 seconds cold, <50ms cached. `get_findings`: <10ms (reads the cached report, applies filters in memory). `verify_fix`: dominated by the re-analysis — 1–2 seconds plus patch-apply overhead. `generate_fix`: template-path ~50ms for template generation + 1–2 seconds for verification; total typically <3 seconds. `open_fix_pr`: dominated by network latency to GitHub — 5–10 seconds in practice.

All numbers are single-file-system-local. Network-attached filesystems can be slower; the cache helps on repeat calls.

## Cache

`~/.vantage/cache/` stores analysis results keyed by a content hash of the target directory (mtimes + sizes of all source files, plus the options). Invalidated automatically when any file changes. To clear manually:

```bash
rm -rf ~/.vantage/cache
```

No TTL or size cap yet. If the cache grows unbounded on a busy machine, that's a reasonable feature request — open an issue.

## Reporting issues

Bugs, false positives on the template fixes, or unexpected analysis results: file a GitHub issue with the smallest repro. The `report_id` from the bad run and the output of `vantage analyze <target> --output report.json` are the most useful attachments.

Security issues: email security@jourdanlabs.ai instead of filing publicly.

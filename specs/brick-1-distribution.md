# Brick 1 — Distribution: MCP server + agentic stack hooks

**Goal:** make VANTAGE the default code-quality gate that every agentic coding tool auto-invokes. By end of build, a developer using Claude Code, Cursor, Aider, or any MCP-aware client should have VANTAGE in the critical path of every commit, with no per-tool integration work required.

**Success criteria:**
- An MCP server that exposes `analyze`, `verify_fix`, and `get_findings` tools over stdio, installable via `npm install -g @jourdanlabs/vantage-mcp` (or equivalent).
- A Claude Code `PreToolUse` hook that intercepts `git commit` and blocks it if the AURORA score for changed files is below threshold.
- A GitHub Action `jourdanlabs/vantage-action@v1` that gates pull requests.
- A pre-commit hook compatible with the `pre-commit` framework for solo devs not using AI tools.
- The Cowork plugin (already drafted at `/sessions/practical-confident-dirac/skills/vantage/`) packaged and listed in the Cowork plugin marketplace.

---

## Sub-spec 1: MCP server

### Deliverable

A Node.js package `vantage-mcp` that runs as a stdio MCP server and wraps the existing `npm run analyze` CLI.

### Tools to expose

`analyze(target_path: string, options?: { engine?: string; threshold?: number })`
Runs the full VANTAGE pipeline against `target_path`. Returns the parsed AURORA verdict, score, top issues, and a report ID that can be used with `get_findings`. Internally invokes `vantage analyze <target> --output /tmp/vantage-<uuid>.json --json` and parses the result.

`verify_fix(target_path: string, patch: string, original_findings: string[])`
Applies the patch to a working copy of `target_path`, re-runs VANTAGE, and returns whether the original findings (referenced by ID) are gone and whether any new findings appeared. This is the primitive Brick 2 (auto-fix) will lean on heavily — getting the API shape right now matters.

`get_findings(report_id: string, filters?: { severity?: string; engine?: string; file?: string })`
Returns a filtered subset of findings from a previous `analyze` call. Avoids returning the full 100KB+ JSON over MCP every time.

### Implementation notes

Use `@modelcontextprotocol/sdk` (the official TypeScript SDK). Server entrypoint at `src/mcp/server.ts`. Register tools with `server.tool()` using zod schemas for input validation. Return outputs as MCP `content` blocks — for `analyze`, return both a structured JSON block and a human-readable text summary so dumb clients can still display something useful.

Cache report JSONs by content hash of the target directory + options, keyed in `~/.vantage/cache/`. Repeat `analyze` calls on unchanged targets should return in <50ms. Cache invalidation on any file mtime change in the target.

`verify_fix` should operate on a temp working copy (`cp -r` or git worktree) so it never mutates the user's actual files. Apply the patch with `git apply` for robustness; fall back to `patch -p1` if not a git target.

### Files to create

```
src/mcp/
├── server.ts           # MCP server entrypoint, tool registrations
├── tools/
│   ├── analyze.ts      # Wraps CLI, parses JSON, caches result
│   ├── verify-fix.ts   # Temp-copy + re-analyze + diff findings
│   └── get-findings.ts # Filter cached report JSON
├── cache.ts            # Content-hash-keyed cache in ~/.vantage/cache/
└── schemas.ts          # zod input schemas for each tool

bin/
└── vantage-mcp.js      # #!/usr/bin/env node executable

package.json            # add bin entry, @modelcontextprotocol/sdk dep
```

### Test plan

Unit tests for each tool with mocked CLI output. Integration test that spins up the server, sends `analyze` for the existing `vantage-report.json` test fixture, asserts the response shape matches the MCP content spec. End-to-end smoke test: use Claude Code or `mcp-inspector` to connect to the server and run `analyze` on the vantage repo's own `src/` directory; assert verdict matches the CLI output.

---

## Sub-spec 2: Claude Code hook

### Deliverable

A `PreToolUse` hook configuration shipped as part of `vantage-mcp` that, when added to a project's `.claude/settings.json`, blocks `git commit` invocations if AURORA score is below threshold.

### Behavior

When the user (or an agent) runs a `Bash(git commit)` tool call, the hook fires before the command executes. The hook script:

1. Identifies the changed files via `git diff --cached --name-only`.
2. Determines the project root and runs `vantage analyze <root> --quiet --json`.
3. If `aurora.verdict === "REJECTED"`, returns exit code 2 with a JSON block describing which findings blocked the commit and what the agent should do about them. Claude Code surfaces this to the agent as a tool failure with reasoning.
4. If `aurora.verdict === "APPROVED"`, returns exit code 0 silently.
5. Provides an escape hatch: if the commit message contains `[vantage-skip]`, allow through with a warning.

### Files to create

```
hooks/
├── claude-code/
│   ├── pre-commit-gate.sh        # The hook script
│   └── settings.example.json     # Drop-in example config block
└── README.md                     # Install instructions
```

### Install UX

`npx vantage-mcp install-hook` should detect the user's project, write the hook config into `.claude/settings.json` (preserving existing config), and chmod the script. One command, done.

---

## Sub-spec 3: GitHub Action

### Deliverable

`jourdanlabs/vantage-action@v1` published to the GitHub Marketplace.

### Behavior

Standard composite action. Inputs: `target` (default `.`), `threshold` (default `0.80`), `fail-on-reject` (default `true`). Runs `npm install -g vantage-cli && vantage analyze ${{ inputs.target }} --json --output vantage-report.json`. Posts a PR comment with the AURORA verdict, score, and top findings. If verdict is REJECTED and `fail-on-reject` is true, fails the check.

### Files to create

```
.github/actions/vantage/
├── action.yml          # Composite action definition
├── post-comment.js     # Formats and posts PR comment
└── README.md           # Usage docs

.github/workflows/
└── self-test.yml       # Test the action against this repo's own src/
```

Publish to Marketplace via the standard GH Marketplace flow. Tag `v1.0.0` once self-test passes.

---

## Sub-spec 4: Pre-commit framework hook

### Deliverable

A `.pre-commit-hooks.yaml` entry so users of the `pre-commit` framework can add VANTAGE with one line in their `.pre-commit-config.yaml`.

### Files to create

```
.pre-commit-hooks.yaml          # Hook registration
hooks/pre-commit/
└── run-vantage.sh              # Same gate logic as Claude Code hook, no agent-specific JSON
```

Document install in README: `repos: [- repo: https://github.com/jourdanlabs/vantage, hooks: [- id: vantage-gate]]`.

---

## Sub-spec 5: Cowork plugin packaging

### Deliverable

The VANTAGE skill drafted at `/sessions/practical-confident-dirac/skills/vantage/` packaged as a `.skill` file and submitted to the Cowork plugin marketplace.

### Steps

Run skill-creator's `package_skill.py` against the skill folder. Verify the resulting `.skill` installs cleanly in a fresh Cowork session. Submit to marketplace with a short listing — pitch is "AI-powered code review for your projects, powered by VANTAGE."

---

## Sequencing within Brick 1

The MCP server is the foundation. Build it first because every other sub-spec depends on the CLI being callable through a stable interface. Order: MCP server → Claude Code hook → pre-commit hook → GitHub Action → Cowork plugin. The Cowork plugin can actually ship in parallel since the skill draft is already done — just needs packaging.

Realistic timeline for a focused builder: MCP server v0 in 3–4 days, Claude Code hook in 1 day, pre-commit and GitHub Action together in 1 day, Cowork plugin in an hour. Call it a focused week of work to have all five surfaces shipped.

## Open questions

Should `analyze` support streaming partial results (i.e., return METEOR results as soon as they're done, then NOVA, etc.) so agents can react to early findings without waiting for the full pipeline? Probably yes for v2; v0 can be synchronous.

Should the Claude Code hook gate `git push` instead of (or in addition to) `git commit`? Push-gating is safer because it catches `--no-verify` commits, but commit-gating gives faster feedback. Suggest: gate both, with `git commit` blocking by default and `git push` as a backstop with a louder warning.

What's the AURORA threshold for the default GitHub Action? 0.80 matches the CLI default but might be too strict for OSS projects with legacy code. Consider shipping a `--mode strict|standard|advisory` flag where standard is 0.80 and advisory just comments without failing.

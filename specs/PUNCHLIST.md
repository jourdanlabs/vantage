# VANTAGE Build — Punch List

Review of the brick 1 + brick 4 builds against the specs, with smoke-test results. Ordered by severity. Specifics below include file:line references so you can jump straight in.

## What actually worked

The MCP server type-checks clean and boots cleanly over stdio — `npx ts-node src/mcp/server.ts` exits 0 with no errors. The server exposes `analyze`, `verify_fix`, and `get_findings` as specced, returns dual text + JSON content blocks, has proper error boundaries, and uses the official `@modelcontextprotocol/sdk` correctly. The zod schemas are sensible. The content of `cache.ts`, `schemas.ts`, and the tool implementations are coherent even where individual lines are buggy.

The bench harness also type-checks clean and the CLI runs — `node bin/vantage-bench.js list-tools` lists VANTAGE, Semgrep, SonarQube, CodeQL; `list-corpora` correctly reports NodeGoat and Juice Shop as not-yet-cloned. The runner interface is clean and extensible. The Astro site structure matches the spec, the ground-truth JSON files are present and validate against their schema.

The scaffolding is real. The bugs below are surgical, not structural.

## P0 — Blockers (ship-breakers)

**Hook scripts call the CLI wrong.** Both `hooks/claude-code/pre-commit-gate.sh:60` and `hooks/pre-commit/run-vantage.sh:35` run `$VANTAGE_BIN "$PROJECT_ROOT" --output "$REPORT_FILE"` — but the VANTAGE CLI is `vantage analyze <target>`, not `vantage <target>`. Every hook invocation falls through to the error handler which silently returns "approve." Result: the gate approves everything. This is the single most important fix; without it, brick 1 doesn't gate anything, even though it appears to.

**`vantage-mcp.js` registers ts-node at runtime.** `bin/vantage-mcp.js:12` does `require('ts-node').register(...); require('../src/mcp/server')` — which means the published npm package needs ts-node as a runtime dep (it's currently devDependency) and ships uncompiled TypeScript. A `npm install -g vantage-mcp` won't work on a clean machine. Fix: compile with `tsc` on publish, ship `dist/mcp/server.js`, have the bin require the compiled path. Update `package.json` `files` field and `prepublishOnly` script accordingly.

**`verify_fix` lookup logic is broken.** `src/mcp/tools/verify-fix.ts:86-106` tries to look up the original report by splitting finding IDs on `_` and using the first segment — but finding IDs are `<engine>_<hash>` so the "report ID" it extracts is always just the engine name (`"pulsar"`, `"aurora"`, etc.). Every lookup fails. The `resolvedFindings` / `remainingFindings` / `newFindings` output is therefore garbage in every case. Fix: track the original report ID on the input, not in the finding IDs, or key findings by stable hash of `file+line+type+description`.

**`newFindings` collects all post-patch findings, not net-new.** Same file, lines 108-112. Should diff the post-patch finding set against the original, not list every finding in the patched tree. Currently the tool tells you every finding still exists even if the patch fixed the target one.

## P1 — Credibility risks (brick 4 leaderboard)

These matter disproportionately because the leaderboard's only moat is trust. If a reader can argue "this is rigged," the whole brick collapses. Fix before any pre-launch outreach.

**File matching is too permissive.** `packages/vantage-bench/src/scoring.ts:54-56` accepts a file match if the normalized finding path `endsWith`, `includes`, *or* shares a basename with the ground-truth file. Basename matching is the problem: if GT says the bug is in `app/foo/bar.js` and a tool reports a finding in `app/baz/bar.js`, it still gets credit. This inflates TP counts unpredictably and the direction of bias depends on each tool's path-reporting conventions. Fix: require `endsWith` only, drop the `includes` and basename fallbacks, then audit each runner's path normalization to match.

**`line === 0` is a silent wildcard in scoring.** `scoring.ts:60` — `if (fileMatch && typeMatch && (lineMatch || gtEntry.line === 0))`. A ground-truth entry with line 0 matches at any line. This is undocumented in the methodology page and it's live in some entries in the `.json` files. If it's intentional (e.g., "project-wide vulnerability"), document it explicitly on the methodology page and add a `scope: "file" | "project"` field to the GT schema. If not, fix the line-0 entries to real line numbers.

**Path normalization is asymmetric across runners.** `scoring.ts:90-95` uses `path.relative(targetPath, filePath)` which behaves differently if the finding path is absolute (VANTAGE: yes), relative (Semgrep and CodeQL often), or constructed by joining `targetPath` + relative (SonarQube, `sonarqube.ts:64`). Tools that report paths differently get systematically different TP rates for reasons that have nothing to do with detection quality. Fix: normalize all runner outputs to corpus-relative posix paths at the runner boundary, before scoring.

**SonarQube and CodeQL are missing from the weekly workflow.** `.github/workflows/benchmark-weekly.yml:51` hardcodes `TOOLS="${TOOL_ARG:-VANTAGE,Semgrep}"` and line 83 gates SonarQube on `workflow_dispatch` only. The leaderboard will show stale or missing data for half the competitors while VANTAGE refreshes weekly. This reads as rigged even if it isn't. Include all four in the weekly run; separate jobs are fine if SonarQube is slow.

**Semgrep config isn't `auto`.** `packages/vantage-bench/src/runners/semgrep.ts:10` runs `p/owasp-top-ten p/nodejs p/javascript` instead of `--config auto`. That's a defensible choice for a security benchmark but it's not documented in the methodology. Either run `auto` (their default) or add a paragraph to `/methodology` explaining why you picked the targeted ruleset and what the comparison would look like under `auto`.

**Hardcoded vulnerability counts on the homepage.** `sites/leaderboard/src/pages/index.astro:27` references "13 GT vulnerabilities" but `juice-shop.json` has a different count. Either derive the count from the JSON at build time or regenerate on every GT edit.

## P1 — Brick 1 correctness

**Hook gates both `git commit` and `git push` identically.** `pre-commit-gate.sh:38` — `^git (commit|push)`. Spec said commit is the primary gate with push as a louder backstop. Currently both block with the same message. Either keep both at the same severity and explicitly document that, or differentiate push with a "commit slipped through, this is your last chance" message.

**Threshold hardcoded at 0.80 in `verify_fix`.** `verify-fix.ts:70` — no way to override. If the MCP caller wants a stricter or looser gate, tough. Add a `threshold?: number` to `VerifyFixInput` and plumb it through.

**GitHub Action ignores `threshold` input.** `.github/actions/vantage/action.yml` declares the input but never passes it to the CLI. Pass `--threshold ${{ inputs.threshold }}` in the analyze step. Relatedly, `fail-on-reject` isn't honored — the action always fails on REJECTED regardless.

**`install-hook.js` uses fragile idempotency check.** It greps for the substring `vantage` in existing hook commands to decide whether to install. A user with a Python script named `vantage-something-unrelated` will be silently skipped. Use a marker comment like `# @vantage/hook` or check the specific hook command path.

**Shell word-splitting in hook scripts.** `pre-commit-gate.sh:48` — `VANTAGE_BIN="node $PROJECT_ROOT/bin/vantage.js"` then later `$VANTAGE_BIN "$PROJECT_ROOT"` splits unpredictably if `$PROJECT_ROOT` contains spaces. Switch to a bash array: `VANTAGE_BIN=(node "$PROJECT_ROOT/bin/vantage.js")` then `"${VANTAGE_BIN[@]}" "$PROJECT_ROOT"`.

## P2 — Polish

**TypeScript strict mode is off in both packages.** Root `tsconfig.json` has `"strict": false`; `packages/vantage-bench/tsconfig.json` same. Turn on strict and fix the fallout before shipping. Silent undefined corruption in the SonarQube runner (`sonarqube.ts:64` — `(issue.component ?? '').replace(...)`) is exactly the class of bug strict mode catches.

**No tests.** Spec called for unit tests on each MCP tool and an integration test for the server; none exist. Same for bench scoring. The scoring function in particular should have a test fixture — one with known ground truth and synthesized findings that exercise every edge case (perfect match, off-by-one within tolerance, off-by-many, basename collision, line=0).

**Cache has no eviction.** `src/mcp/cache.ts` stores reports in `~/.vantage/cache/` indefinitely. Add a TTL or size cap. 100 reports × ~100KB each isn't much, but over years on an active machine this accumulates.

**Finding IDs aren't stable across runs.** `src/mcp/tools/get-findings.ts:108-116` uses a non-cryptographic JavaScript string hash. If the finding order changes between runs (engines iterate files non-deterministically), the IDs change, which breaks any external system that tracks findings over time. Use SHA1 of `file + line + type + description` — deterministic and stable.

**Missing `/tools/[slug]` pages.** Spec called for per-tool detail pages. Site only has `/`, `/methodology`, `/submit`. Low priority — homepage table already shows the key numbers — but worth picking up before launch.

**No README for the MCP server specifically.** Spec called for one. Add a short one under `src/mcp/` explaining how to run, how to connect via `mcp-inspector`, what each tool does, and example JSON-RPC request/response for each.

**Hardcoded domain in Astro config.** `sites/leaderboard/astro.config.mjs:4` — `site: 'https://benchmark.vantage.dev'`. Wrap in env var so staging is possible without a code change.

**Missing @types for MCP SDK.** The SDK ships its own types, so this works today, but strict mode might complain. Worth checking after you turn strict on.

## Suggested fix order

Half a day of work gets you shippable:

1. Fix the CLI invocation in both hook scripts (P0) — 15 minutes.
2. Fix `vantage-mcp.js` to use compiled output (P0) — 30 minutes plus a verify.
3. Fix `verify_fix` lookup and `newFindings` diff (P0) — 1-2 hours.
4. Fix file matching + line=0 + path normalization in scoring (P1 credibility) — 2 hours plus test fixtures.
5. Add all four tools to the weekly workflow (P1) — 30 minutes.
6. Document the Semgrep ruleset choice on methodology page (P1) — 15 minutes.

Then a separate pass for P2 polish when you're in a less tired mood. Tests belong in that pass too — write them *after* the P0/P1 fixes so the tests encode the fixed behavior rather than the current buggy behavior.

## One strategic note

The credibility fixes in brick 4 are not optional. The pre-launch outreach plan in the original spec (inviting Semgrep, SonarSource, GitHub maintainers to review methodology two weeks before launch) is *exactly* the right move — and they will spot these exact issues within an hour of looking. Better to fix them now than have them pointed out in the review round. The leaderboard's credibility compounds with each public-reviewed-and-addressed issue; it does not survive a "this was obviously rigged" hot take.

The MCP server and Cowork plugin path, by contrast, are much lower stakes — you can ship a buggy v0 and iterate. Brick 1 is product, brick 4 is reputation. Fix with that in mind.

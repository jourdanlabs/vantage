# ADR-0001: Auto-fix closed loop for VANTAGE (Brick 2)

**Status:** Proposed
**Date:** 2026-04-19
**Deciders:** Leland (JourdanLabs)
**Supersedes:** —

## Context

VANTAGE today stops at a verdict. A PULSAR finding tells the user "there is a null-safety issue on line 47" and lists the test case that would reproduce it, but the user still has to write the fix, verify the fix didn't break anything else, and open the PR themselves. Every competitor in the static-analysis space has exactly this shape — finding lists are the product.

The Brick 2 goal from the roadmap (`ROADMAP.md`) is to cross the chasm from finder to fixer: take a PULSAR finding, generate the patch, have NOVA validate the patch doesn't break the dependency graph, re-run PULSAR to confirm the finding is gone with no new HIGH findings, and open a PR. This turns "Autonomous Code Evolution Engine" from an aspirational tagline into a literal description.

This ADR resolves the architectural decisions required to start building. It does not attempt to resolve every implementation detail; it aims to answer the questions that would otherwise be litigated every time someone sits down to write code.

### Constraints

- VANTAGE's existing engines (METEOR, NOVA, ECLIPSE, PULSAR, AURORA) must remain callable standalone. The auto-fix loop is additive, not a refactor.
- The `verify_fix` MCP tool already exists and produces the exact before/after finding diff we need. The auto-fix architecture should compose with it, not replicate it.
- VANTAGE's speed advantage (sub-100ms analysis) is load-bearing — the auto-fix loop must not make the common "scan-only" path slower.
- The target caller set includes both Claude Code / Cursor / Aider agents via MCP, and CI systems via the GitHub Action. Both need to be able to invoke fix generation; neither can be the only supported entry point.
- Fix generation has per-call cost (LLM tokens) that scan-only does not. The architecture must make this cost opt-in, not mandatory.

### Non-goals for v1

Not every finding type. Not multi-step refactors. Not cross-file fixes. Not "rewrite this whole module." The v1 auto-fix is single-finding, single-file, bounded patches. Expanding scope happens after the loop is proven on the simplest cases.

## Decision

Ship auto-fix as a new MCP tool `generate_fix` that composes with the existing `analyze` and `verify_fix` tools, using a hybrid template-first / LLM-fallback fix generator, scoped in v1 to three finding types in a specific order: null-safety, error-boundary (missing try/catch on `JSON.parse`), and async-safety (missing `await`/unhandled rejection).

PR opening lives in a separate MCP tool `open_fix_pr` so the patch-generation concern stays independent of the GitHub-integration concern. Agents compose the two.

## Options Considered — Fix generation strategy

The core architectural choice is how to generate the patch for a given finding. Everything else follows from this.

### Option A: Pure rule-based templates

For each finding type, ship a hand-written transform: "for PULSAR `null-safety` at `foo.bar.baz`, wrap the expression in optional chaining and add a default." Findings that don't match a known template return "no fix available."

| Dimension | Assessment |
|---|---|
| Complexity | Low — regex + AST pattern match |
| Cost per fix | ~0 (no LLM call) |
| Determinism | Fully deterministic; same input → same output, always |
| Coverage | Narrow; every new finding type needs engineering work |
| Failure mode | Produces wrong fix on patterns that look like common case but aren't |

**Pros:** free at inference time, deterministic, auditable, trivial to unit-test, works offline, matches the speed of the scan engine.
**Cons:** each new finding type is a build-out; can't handle the long tail; looks primitive against LLM-based competitors.

### Option B: Pure LLM-based generator

For each finding, send `{finding, file contents, surrounding context}` to a coding model, ask it to produce a patch, take whatever comes back.

| Dimension | Assessment |
|---|---|
| Complexity | Medium — prompt engineering + tool-use loop |
| Cost per fix | ~$0.01–$0.10 (model-dependent) |
| Determinism | None without temperature=0, and still unreliable |
| Coverage | Broad; handles anything the model has seen |
| Failure mode | Subtle wrong fixes that look right; API outages break the product |

**Pros:** covers everything on day one, matches how Cursor/Copilot actually work internally, scales with model improvements.
**Cons:** every fix costs money, every fix is non-deterministic, requires network + API key even for trivial fixes, auditability story is weak ("the model suggested it" is not a satisfying answer to a production incident).

### Option C: Hybrid — template first, LLM fallback (recommended)

Try the rule-based template. If a template exists and passes `verify_fix` post-analysis (finding gone, no new HIGH findings, AURORA score non-decreasing), ship that patch. If no template matches or the templated patch fails verification, fall back to the LLM generator. Return the same `VerifyFixResult` shape either way; the caller shouldn't need to know which path produced the fix.

| Dimension | Assessment |
|---|---|
| Complexity | Medium — both paths plus a decision gate |
| Cost per fix | ~0 for template hits, LLM cost for fallback |
| Determinism | Deterministic where templates exist; stochastic where they don't |
| Coverage | Broad (LLM covers tail); opinionated (template covers common cases) |
| Failure mode | Template mis-match falls through to LLM rather than shipping wrong patch |

**Pros:** every one of the pros above, in the common case. The template path preserves VANTAGE's speed and cost advantages; the LLM path preserves coverage. The decision gate (`verify_fix`) is the same in both paths, so the safety story is identical.
**Cons:** two codepaths to maintain; template coverage has to be genuinely good on the top N finding types or the fallback-LLM-call rate inflates cost; requires a testable decision boundary ("when does template 'fail' and hand off?").

## Trade-off Analysis

Option A is too narrow. VANTAGE detects novel patterns in addition to the top-10 OWASP classes, and writing a template per pattern is a six-month engineering project that still wouldn't cover the long tail. Option A as the *only* path is a dead end.

Option B is too expensive and too opaque. Paying $0.05 per fix at scale is real money on a product meant to run in CI on every commit. More importantly, LLM-based fixes are hard to defend: when a Snyk security engineer asks "how did you decide to change line 47," the answer "the model thought it was best" cedes the high ground. VANTAGE's benchmark story is built on correctness and auditability; the fix story should be too.

Option C, critically, preserves VANTAGE's current positioning. For the common cases (null-safety, JSON.parse try/catch, missing await — which together are probably 60–70% of all PULSAR findings in real code), the fix is a few-line diff that a template can produce correctly and for free. For the tail, we defer to the LLM, pay the cost, and still gate the output through `verify_fix` before it reaches the user.

There's a legitimate counterargument that the hybrid is "two products" and a team would be better off committing fully to one. The counter-counter: the hybrid is naturally phased. v1 can ship with templates for two finding types and no LLM path at all; the LLM fallback lands in v2 once the MCP tool + verify_fix integration is battle-tested. Phasing removes the "two codepaths at once" risk.

**Recommendation: Option C, phased.** v1 ships with templates for null-safety and JSON.parse error-boundary only. LLM fallback is stubbed with a "not yet available" response and ships in v2 after verification tooling is proven.

## Options Considered — Orchestration surface

Where does the auto-fix loop live architecturally?

### Option A': New engine inside VANTAGE (e.g. CORONA)

Add a sixth engine to the existing METEOR→NOVA→ECLIPSE→PULSAR→AURORA pipeline. Run it as part of `vantage analyze`.

**Pros:** single mental model; existing callers get it for free.
**Cons:** breaks the "scan-only is fast and cheap" invariant; every `analyze` now potentially generates fixes; the cost/latency profile of the analyze command changes. Non-agentic callers (CLI user running pre-commit) pay for a feature they didn't ask for.

### Option B': New MCP tool `generate_fix` (recommended)

Separate MCP tool with its own input schema. Takes `report_id` + `finding_id` from a prior `analyze` call and returns a `VerifyFixResult`. Composes with existing `analyze` and `verify_fix`; lives in `src/mcp/tools/generate-fix.ts`.

**Pros:** opt-in; preserves scan-only performance; mirrors how the existing tools compose; the caller (agent or CI) decides when to generate fixes and when to just show findings.
**Cons:** requires callers to know about three tools instead of two; the happy path for a fully-autonomous agent is `analyze → generate_fix → open_fix_pr` which is three round trips.

### Option C': External standalone service

Run the fix generator as its own process/container, out of band.

**Pros:** language agnostic; could scale LLM calls independently.
**Cons:** infrastructure to operate; second deploy target; breaks the "just an npm install" story; overkill for v1.

**Recommendation: Option B'.** Matches how VANTAGE already exposes itself. Three-round-trip cost is real but sub-second with the caching layer already in the MCP server.

## Options Considered — Fix-type sequencing

Which finding types get implemented first? Ordered by diff-shape simplicity:

1. **null-safety (v1)** — "property access without null check." Fix shape: wrap expression in optional chaining (`a?.b?.c`) or add explicit null guard. Contained to one expression, no control flow changes, no imports, no cross-line reasoning.
2. **error-boundary on JSON.parse (v1)** — "JSON.parse without try/catch." Fix shape: wrap the call in a try/catch with a safe default or re-throw. Adds a few lines, no imports, localized.
3. **async-safety (v1.1)** — "missing await on a Promise-returning call" or "unhandled rejection." Fix shape: add `await` or `.catch()`. Slightly riskier because adding `await` can change timing semantics, so the `verify_fix` re-run matters more.
4. **eval/injection (v2+)** — "eval of user-controlled input." Fix is context-dependent (sometimes `vm.runInContext`, sometimes `JSON.parse`, sometimes a complete rewrite). Too varied for a template; LLM fallback territory.
5. **circular dependency (v2+)** — architectural; no local patch can fix it. Out of scope for auto-fix.

**Recommendation:** v1 ships with #1 and #2. v1.1 adds #3 one release later. #4+ wait for the LLM fallback path to land in v2.

## Options Considered — Patch verification gate

Every candidate patch must pass a verification gate before it reaches the caller. What does the gate check?

The gate is `verify_fix`, already implemented. A patch passes iff:

1. The patch applies cleanly (`git apply` or `patch -p1` falls through).
2. The original finding's ID is no longer present in the post-patch finding set. (Stable finding IDs make this reliable — see `src/mcp/finding-id.ts`.)
3. No new HIGH or CRITICAL findings appear in the post-patch set. (MED and LOW are allowed; fixing a null-safety issue may legitimately surface new lint-level observations.)
4. Post-patch AURORA score is ≥ pre-patch score, or if pre-patch was already APPROVED, post-patch score may drop by at most 0.02.

Failure at any gate means the patch is discarded. If the template path failed, fall through to LLM. If LLM failed (or is stubbed in v1), return `{ success: false, reason }` to the caller.

**Recommendation:** Adopt these four gates exactly. They map cleanly onto `VerifyFixResult` fields. The 0.02 tolerance on AURORA score is to avoid spurious rejections where a legitimate fix trades one low-severity finding for another.

## Options Considered — PR opening

### Option A'': Combine with `generate_fix`

Have `generate_fix` also open the PR if the patch passes verification. One tool call does everything.

**Pros:** single round trip for the common case.
**Cons:** conflates two unrelated concerns (code transformation + GitHub API). Non-GitHub callers (local dev, GitLab, Bitbucket) are forced through a PR-shaped abstraction they can't use. Requires GitHub auth credentials to use the core fix feature.

### Option B'': Separate `open_fix_pr` tool (recommended)

`generate_fix` returns a patch + verification result. Caller decides what to do with it — open a PR, write to disk, show the user. A separate `open_fix_pr` tool takes `{ target_path, patch, finding_id, branch_name? }` and handles the GitHub integration.

**Pros:** separation of concerns; patch generation works without GitHub auth; local dev workflows work naturally.
**Cons:** one more tool in the surface; agent has to know to chain them.

**Recommendation: Option B''.**

## Consequences

### What becomes easier

Auto-fix is now a composable feature that CI, IDE agents, and MCP clients can all invoke identically. The template path preserves VANTAGE's cost and speed advantages for the majority of fixes. The LLM fallback (when it lands in v2) inherits the same verification gate, so it ships safely on the same day it ships. The phased sequencing means v1 can land in weeks, not quarters.

The positioning claim strengthens: "VANTAGE doesn't just find NoSQL injection, it fixes the two most common patterns automatically, verifies the fix didn't regress, and opens the PR" is a headline competitors can't match with pattern-matching architectures.

### What becomes harder

Two finding-type templates are now on the maintenance roadmap. Every false-positive in the template path is a user-visible bug (a bad patch landing in a PR) in a way that false-positives in the scan path are not. This implies a test fixture per finding-type pattern, with golden input→output diffs and a CI check that a template change doesn't regress any of them.

The tools directory grows from three to five MCP tools. The Claude Code hook, GitHub Action, and pre-commit hook all need to decide whether they just gate (current behavior) or gate-and-fix (new). v1 leaves all three as gate-only and adds fix as an explicit opt-in flag, so users who want auto-fix in CI have to turn it on.

### What we'll need to revisit

At 100 template-coverable finding types, Option A (pure rules) starts looking viable again. Revisit the hybrid decision when we have data on template hit-rate in production. If hit-rate stays >80%, templates alone may be enough; if it drops, the LLM fallback pays for itself. Expect to revisit in v2.5 or so.

The AURORA-score-delta tolerance (0.02) is guessed, not measured. Once there's real fix-path telemetry, tune it empirically. Too strict and valid fixes get rejected; too loose and aesthetic score drift papers over real regressions.

If the three-round-trip flow (`analyze → generate_fix → open_fix_pr`) becomes a latency problem for agentic callers, consider adding a composite `analyze_fix_and_pr` tool that chains them server-side. Only worth it if profiling shows the round trips dominate wall time.

## Action items

1. [ ] Write failing test fixtures for the two v1 finding types (null-safety, JSON.parse error-boundary). Each fixture is a small TS source snippet with a known PULSAR finding, plus the expected post-patch source. Golden-file diff test.
2. [ ] Implement null-safety template transform in `src/mcp/fix-templates/null-safety.ts`. Input: `{ file contents, line, PULSAR finding type }`. Output: unified diff.
3. [ ] Implement JSON.parse error-boundary template in `src/mcp/fix-templates/error-boundary.ts`. Same interface.
4. [ ] Implement `generate_fix` MCP tool in `src/mcp/tools/generate-fix.ts`. Resolves template → generates patch → invokes existing `verify_fix` → returns `VerifyFixResult`. Stubs LLM-fallback path with `{ success: false, reason: 'no template for finding type; LLM fallback not yet available' }`.
5. [ ] Register `generate_fix` tool in `src/mcp/server.ts` with zod schema.
6. [ ] Implement `open_fix_pr` MCP tool. Takes patch + metadata, uses `@octokit/rest` to create branch + commit + PR. Credentials via `GITHUB_TOKEN` env var.
7. [ ] Integration test: analyze → generate_fix → verify_fix passes → no PR opened unless explicit. Use a small fixture repo.
8. [ ] Extend the Claude Code hook and GitHub Action with `--autofix` opt-in flag. Off by default.
9. [ ] Update `docs/` with the new tool surface. Claude Code + Cursor + Aider example flows for each.
10. [ ] Add template hit-rate telemetry to `generate_fix` response so v2 planning has data.

Estimated effort for v1 (items 1–7): one focused week. v1 release gates on all seven passing integration.

# Static analysis is a solved problem. Solving the right problem, not so much.

*JourdanLabs — launch post for VANTAGE and the first open static-analysis leaderboard.*

Static analysis has looked basically the same for fifteen years. Tools scan source, match patterns, print finding lists. Semgrep does it with YAML rules. SonarQube does it with a Java server. CodeQL does it with a query language. The details differ; the shape doesn't. You get a list of things that might be wrong, you triage them, you fix some and ignore the rest. The tools are the oracle; you do the work.

That shape was never the right answer. It was just the tractable one, before large language models and agentic coding tools made it possible to close the loop. Now the pattern everyone is waking up to is: the *finding list* isn't the product. The *landed fix* is.

Today we're launching VANTAGE — a static-analysis pipeline that catches bugs pattern matchers structurally cannot, generates verified patches for the ones it knows how to fix, and plugs into Claude Code, Cursor, and every other MCP-aware coding tool as infrastructure. Alongside VANTAGE we're publishing the first open, reproducible, weekly-updated leaderboard for static-analysis tools. Every tool's configuration is pinned to a commit SHA. The ground-truth catalogs are under CC-BY-4.0. Anyone can submit a new tool by opening a PR. We're the first entry; we rank first on our own benchmark. We think that deserves scrutiny, which is why the methodology and the harness are public.

## What changed

Three things.

**Semantic analysis that actually works on JavaScript.** VANTAGE's NEBULA engine tracks taint flow intraprocedurally — user input from `req.body`, `req.cookies`, `process.env` gets a label that propagates through every assignment, function call, template string, and binary expression until it hits a sink. On Juice Shop, NEBULA catches a Server-Side Template Injection in `routes/userProfile.ts` where the tainted value crosses fifteen string operations before reaching `pug.compile()`. Semgrep, SonarQube, and VANTAGE's own pattern engine all miss it. This is the class of bug — cross-function, cross-statement, context-sensitive — that rule-based tools cannot detect by construction. NEBULA detects it in 639ms on a 33,000-line codebase.

**Fixes, not finding lists.** Every VANTAGE finding that matches a shipped template produces a verified patch. "Verified" means concrete: we apply the patch to a temp copy, re-run the full pipeline, and only return the patch if the original finding is resolved with no new HIGH or CRITICAL findings. You don't have to trust the patch — it's already passed the same gate you'd run manually. The LLM-generated fallback path for the bugs no template can express is coming in v2; v1 ships deterministic templates for null-safety, JSON.parse error-boundary, and hardcoded secrets. That covers a majority of the real findings on real codebases. Everything else stays detect-only for now, honestly.

**Agentic distribution.** VANTAGE is an MCP server before it's anything else. Add five lines to your Claude Code settings and five new tools — `analyze`, `get_findings`, `verify_fix`, `generate_fix`, `open_fix_pr` — appear in the agent's toolbox. A Claude Code PreToolUse hook gates every `git commit` and `git push` below the AURORA threshold. A GitHub Action gates every PR, and with `autofix: true` it'll generate verified patches and commit them to the PR branch automatically. For the non-agentic path, there's a pre-commit framework hook and a plain `vantage` CLI.

## The benchmark

We ran VANTAGE, Semgrep (with `p/owasp-top-ten p/nodejs p/javascript` — pinned so this is reproducible), SonarQube Community, and CodeQL (security-extended JavaScript suite) against OWASP NodeGoat and OWASP Juice Shop. The scoring rule is deliberately strict: the finding's file path must end with the ground-truth path on a segment boundary, the normalized type must match, and the line must be within ±5 of the GT line unless the GT entry explicitly opts into project-scope matching. No basename matching. No line-number wildcards. Every path is normalized to corpus-relative POSIX at the runner boundary so no tool gets an advantage from its path-reporting convention.

Under that rule, on pattern-only mode:

| | NodeGoat F1 | Juice Shop F1 | Aggregate F1 | Median runtime |
|---|---|---|---|---|
| **VANTAGE 1.0** | **100.0%** | **72.0%** | **83.7%** | 1.2s |
| Semgrep 1.159 | 21.1% | 7.1% | 12.8% | ~18s |
| SonarQube 26.4 Community | 0.0% | 5.8% | 2.9% | ~38s |

Semantic mode adds one more catch on Juice Shop — the SSTI in `routes/userProfile.ts:87`. That finding isn't in the ground-truth catalog yet, and we're deliberately not adding it before the benchmark goes through public review. Self-expanding the ground truth to match your own tool's findings is the single fastest way to lose a benchmark's credibility; we'd rather the number stay lower in public and the finding get added through community-review PRs.

The full v1→v2 scoring-rule delta — every change we made, every number that moved, and why — is at [`SCORING_V2_DELTA.md`](https://github.com/jourdanlabs/vantage/blob/main/benchmarks/SCORING_V2_DELTA.md). The NEBULA delta with the SSTI walkthrough is at [`NEBULA_V0_DELTA.md`](https://github.com/jourdanlabs/vantage/blob/main/benchmarks/NEBULA_V0_DELTA.md). Both are on the leaderboard's methodology page too.

## The receipts

We ran VANTAGE in semantic mode against three real-world JavaScript and TypeScript codebases — DVNA (a deliberately-vulnerable Node app), NodeBB (a 150k-LOC production forum), and the official NestJS sample applications. Total runtime across all three: **59 milliseconds**. Total findings: **116**.

- **DVNA (2,204 LOC):** caught the headline `eval()` on user-controlled input in `core/appHandler.js:197` that defines the corpus. 7 ms.
- **NodeBB (153,698 LOC):** REJECTED with 100 findings, the majority of which are circular dependencies in the forum's module structure that NodeBB's current CI pipeline does not flag. Running in 44 ms.
- **NestJS samples:** found a `JSON.parse()` without try/catch in `05-sql-typeorm/src/cats/cats.controller.ts` — the kind of educational improvement the auto-fix loop is well-suited to land as a documented PR.

The full per-finding breakdown with reproducibility instructions is at [`launch/receipts.md`](https://github.com/jourdanlabs/vantage/blob/main/launch/receipts.md) in the repo. We're publishing this first pass as a starting point; over the first week after launch we'll run a more ambitious sweep across a larger corpus (Ghost, Strapi, Directus, Parse Server, Rocket.Chat) and publish each subsequent findings batch as a follow-up post. The weekly leaderboard plus a weekly receipts feed is the rhythm we're aiming for.

One thing worth calling out from the NodeBB run: **NEBULA found zero semantic findings on it.** That's honest, not hidden. NodeBB uses older CommonJS patterns and framework-specific request conventions that NEBULA v0's JavaScript source catalog doesn't model. Closing that gap is catalog work, not core-engine work — and it's exactly the kind of contribution that community PRs can land. The CONTRIBUTING guide ships with the launch and walks through how to add a new source/sink/sanitizer entry.

## What the category looks like from here

Our bet is that "static analysis" as a category gets eaten by agentic tooling in the next 18 months. The winning shape isn't "AI-enhanced SAST" — bolting a chatbot onto a finding list doesn't fix anything. The winning shape is "detector + verifier + fixer, composable by agents, gated by reproducible tests." VANTAGE is one attempt at that shape. We're probably wrong about some of it; we're probably right about enough of it that the existing vendors need a real answer, not a tagline update.

The leaderboard is how we keep ourselves honest. Every Sunday it runs. If VANTAGE's numbers drop, the drop is public and dated. If a competitor ships something that moves their number past ours, the lead is public and dated. If the ground-truth catalog needs updating, the update happens through a public PR with a changelog entry. We're not going to quietly tune scoring behind the scenes — every scoring change gets a versioned delta document and a new `scoringVersion` tag in `results.json`. If any reader wants to dispute a specific finding, file an issue and we'll respond in public.

## Install

```bash
npm install -g vantage vantage-mcp
```

Then — for Claude Code — add this to `~/.claude/settings.json`:

```json
{ "mcpServers": { "vantage": { "command": "vantage-mcp" } } }
```

That's the whole onboarding. The rest is in [the README](https://github.com/jourdanlabs/vantage#quick-start).

## The invitation

To the Semgrep team, the SonarSource team, the CodeQL team at GitHub: we'd like your tool to show its best configuration on this leaderboard. If you think the current setup unfairly represents what your tool can do — wrong ruleset, missing suppressions, stale integration — we'll gladly take a PR that fixes it, and we'll publish the delta alongside the current numbers. We'd rather you show up strong than look for reasons why you didn't show up. The leaderboard exists to tell users the truth about relative performance; it doesn't exist to embarrass anyone. If it's embarrassing, that's a product decision, not a benchmark decision.

To everyone else: open an issue, submit a PR, try VANTAGE on your codebase, tell us what we got wrong. We'll respond to everything we see. This is the moment in the project where feedback is cheapest to incorporate.

## Credits and next milestones

VANTAGE is built by JourdanLabs. The full technical roadmap is in [`ROADMAP.md`](https://github.com/jourdanlabs/vantage/blob/main/ROADMAP.md). Next milestones, roughly in order:

- NEBULA v1.1 — interprocedural taint analysis, so cross-function flows don't slip through.
- LLM fallback path for `generate_fix` — the ~60% of findings no template can cleanly handle get a model-generated patch, still gated by the same four-check verification.
- Python frontend for NEBULA — the second-biggest market for SAST, second-biggest attack surface in the industry.
- Leaderboard submissions go live — any tool with a runner PR gets a weekly-updated row.
- Swift frontend — the underserved market; the one that makes the iOS ecosystem possible to audit properly.

And on the sibling product track: COSMIC — a thin semantic adapter for BI and data-analysis tooling — has its own roadmap. Different product, same principles.

Email: [hello@jourdanlabs.ai](mailto:hello@jourdanlabs.ai). Issues and PRs welcome.

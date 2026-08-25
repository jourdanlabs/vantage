# VANTAGE — Next Level Plan

*Captured from conversation, April 18, 2026.*

## The frame

Today VANTAGE is the fastest, most accurate static analyzer in the OWASP-style benchmark category. Real, but bounded — that category has a ceiling, and at this rate competitors will catch up on raw accuracy within 18 months even if their architectures stay rule-based. The next level isn't "win the same race harder." It's to make the race itself irrelevant by becoming the trust primitive in the agentic coding stack, the only static-analysis tool that actually closes the loop, and the technical reference implementation everyone else benchmarks against.

Four bricks, ordered by leverage. The first two run in parallel. The third is a longer technical bet started concurrently. The fourth is marketing leverage that should be live before the others fully land.

## Brick 1 — Distribution: own the agentic coding workflow

The biggest unclaimed category in software right now is "trust layer for AI-generated code." Cursor, Claude Code, Aider, Cline, Devin, and every agentic IDE in flight are all producing commits that need a verdict before they ship. Today there is no default. Whoever becomes the default within the next 12 months will be embedded in the workflow of every developer using AI to write code — which is most of them, soon.

The wedge is an MCP server. Once VANTAGE speaks MCP, every agentic coding tool can auto-invoke it without bespoke integration. Pair that with a Claude Code post-tool hook that refuses to commit code below an AURORA threshold, a GitHub Action for CI, and a pre-commit hook for solo devs. The pitch externalizes cleanly: "AI wrote it, VANTAGE approved it." That's a phrase every CTO worried about AI-generated code wants to be able to say.

Concrete deliverables in priority order: MCP server exposing `analyze`, `verify_fix`, and `get_findings` tools; Claude Code hook that gates commits; GitHub Action; pre-commit hook; Cowork plugin (the VANTAGE skill we drafted is already brick one of this — package and ship it). v0 of the MCP server is probably a week of work given the CLI already produces clean JSON.

## Brick 2 — Auto-fix: cross from finder to fixer

The "Autonomous Code Evolution Engine" tagline is currently aspirational. Today AURORA stops at a verdict. The version that ends the positioning war takes a PULSAR finding, generates a patch, has NOVA verify the patch doesn't break the dependency graph, re-runs PULSAR to confirm the finding is gone, and opens a PR. Once that's shippable for even one finding type, every competitor's positioning becomes "we find issues" and yours becomes "we fix them, automatically, with proof."

Start with null-safety findings — the diff shape is clean, the verification loop is tight, and the success rate will be high enough to publish. Then expand to error-boundary issues, then to async safety. Treat each finding type as its own ship. By the time the third type lands, the auto-fix loop is the headline feature, not the static analysis.

This is also where the agentic positioning compounds with brick 1: if the MCP server can not just gate commits but propose fixes, you become an active participant in the agentic coding loop, not just a referee.

## Brick 3 — Semantic engine: the technical moat

Semgrep and SonarQube are pattern matchers with type hints bolted on. They cannot, by construction, find bugs that require reasoning about what the code does at runtime. The 15% of Juice Shop you're missing today is mostly hiding in that gap, and so is the entire class of vulnerabilities that produce the case studies that get bought.

The investment is real abstract interpretation, lightweight symbolic execution, and cross-function (eventually cross-language) taint tracking. This is a multi-quarter project, not a sprint. But it's the brick that makes the technical lead permanent — once you can find bugs that competitors fundamentally cannot detect, the benchmark stops being close.

Start scoping it now even if the full build slips behind the others. The first useful artifact is probably a constraint-based taint tracker for the JS/TS subset you already analyze — gets you cross-function flow without the full symbolic execution machinery.

## Brick 4 — Leaderboard: own the benchmark

Right now you're a contestant who happens to win the benchmark you publish in your own README. That's good marketing but weak moat. The categorical move is to publish the VANTAGE benchmark harness as a reproducible public leaderboard — SWE-bench style — with the ground-truth catalogs open and a weekly-updated ranking. Now you're the referee, not a contestant. Every competitor either shows up and publicly loses or refuses to show up, which is also losing. This is how arc-agi and SWE-bench locked in their categories.

This is the cheapest brick to build and the highest leverage on positioning. It can ship before brick 2 or 3 fully lands, and it changes how every conversation about you happens. Worth doing now while the benchmarks are still asymmetric in your favor.

## Sequencing this week

Brick 1 starts now. The MCP server is a tractable first artifact — the CLI already produces JSON, so the work is mostly protocol scaffolding plus the Claude Code hook integration. Goal for the week is a working v0 MCP server plus the VANTAGE skill packaged and installable in Cowork.

Brick 4 is the second parallel start because it's mostly packaging — the harness exists, you just need to lift it out of the repo, polish it, and ship a leaderboard site. A few days of work, big positioning payoff.

Brick 2 starts as a design exercise this week and a build next week. Use the engineering:architecture skill to draft an ADR on the auto-fix loop architecture before writing the first line of the PULSAR-to-AURORA patch generator.

Brick 3 stays in scoping until the auto-fix prototype is real. Premature investment here is the trap.

## Open questions to revisit

What's the polyglot order? TS/JS is the demo language, but the iOS Helix work shows Swift is already a real target. Python is the obvious next given the data-science adjacency. Need to commit to a sequence so the semantic engine work isn't language-shaped to the wrong substrate.

Licensing: VANTAGE is proprietary. Ground-truth catalogs stay under their upstream licenses. The hosted leaderboard is the public surface; the engine is not open source.

How does this interact with the COSMIC + thin-semantic-adapter track? Same company strategy, different product surface — needs its own plan, not folded into this one. Worth a separate consensus session.

When does this stop being a one-person operation? Some of these bricks (brick 3 especially) need real engineering hours. Worth deciding now whether the 18-month plan is solo, with-a-cofounder, or funded.

## Sibling tracks (noted, separate plans needed)

**COSMIC + thin semantic adapter.** Strategy agreed: thin adapter, open contract, reference implementations for dbt and Snowflake. Not a full semantic layer. Distinct customer and motion from VANTAGE. Needs its own roadmap doc.

**The VANTAGE skill (Cowork).** Drafted in `/sessions/practical-confident-dirac/skills/vantage/`, ready to package via skill-creator's `package_skill.py` whenever you want it shipped. Counts as part of brick 1 distribution.

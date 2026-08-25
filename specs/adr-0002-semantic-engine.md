# ADR-0002: Semantic engine for VANTAGE (Brick 3)

**Status:** Proposed
**Date:** 2026-04-19
**Deciders:** Leland (JourdanLabs)
**Supersedes:** —
**Related:** ADR-0001 (auto-fix loop)

## Context

VANTAGE's current engines are pattern matchers with language-aware heuristics. PULSAR finds `eval()` on lines that look like they came from `req.body`; NOVA flags circular imports; METEOR counts TODOs. This class of analysis is fast (sub-100ms on medium repos), auditable (every rule has a text pattern you can point at), and has taken VANTAGE to 100% recall on NodeGoat and the documented Juice Shop GT. It will not, however, scale to the class of bugs that require understanding *what the code does*, not what it looks like. The Juice Shop findings we *don't* catch are almost all in that second class: data flows from a source (request body, URL param) through three function calls before reaching a sink (SQL execution, template compilation, eval); a reasonable-looking regex against either endpoint won't find them.

The Brick 3 goal from the roadmap (`ROADMAP.md`) is to build the engine that finds those. This is a multi-quarter investment rather than a single-sprint feature, and the architecture decisions locked in now constrain the next 18 months of technical direction. This ADR resolves the scope, the core analysis technique, the language strategy, and how the new engine integrates with the existing pipeline.

### Constraints

- **VANTAGE's performance advantage is load-bearing.** Today's scan is sub-100ms. A semantic analysis that takes 30 seconds per file destroys the "runs on every keystroke in the IDE" story and makes the MCP-server-as-default-gate positioning (brick 1) untenable. The semantic engine must either run in sub-second time on typical files, or run asynchronously in a way that doesn't block the existing fast path.
- **Explainability is load-bearing.** Every PULSAR finding today ships with a file, a line, and a natural-language description of the exact pattern detected. The semantic engine's findings have to meet the same bar, or we lose the defensibility that's carrying the leaderboard.
- **Polyglot is a near-term target, not a nice-to-have.** The user's Helix iOS work is Swift; COSMIC's semantic adapter will touch SQL; the agentic coding tools we want to integrate with produce code in every language. An architecture that locks us into TS/JS is dead within a year.
- **The existing engines must keep working.** METEOR/NOVA/ECLIPSE/PULSAR/AURORA stay. The semantic engine is additive, not a replacement.
- **Budget realism.** This is a multi-quarter project for a team of one. Architectures that require a three-person compiler team to maintain are non-starters.

### Non-goals for v1

- Full program verification. We're not trying to prove absence of bugs, we're trying to find specific classes of bugs that rule-based tools can't.
- Unsound analysis is acceptable, as long as soundness claims are honest. PULSAR is already unsound (patterns miss things); adding a semantic layer that is also unsound-but-better-than-patterns is a win.
- Cross-repo / cross-service analysis. First version is single-repo, possibly single-package.
- Runtime instrumentation. Static only.

## Decision

Ship the semantic engine as a new VANTAGE stage called **NEBULA**, running after NOVA and before ECLIPSE in the pipeline. Implement it using **intraprocedural taint tracking with explicit source/sink/sanitizer catalogs**, built on top of a **hand-rolled lightweight IR** (not a compiler-grade CFG, not a symbolic executor) that is per-language-pluggable. Ship TypeScript/JavaScript support in v1; Python in v1.1; Swift in v2 behind a language-plugin architecture that lets polyglot expansion happen without re-architecting.

NEBULA is opt-in via a CLI flag and MCP tool option. The fast-path `analyze` (no NEBULA) remains sub-100ms; the semantic-path `analyze --semantic` adds 1–10 seconds per file depending on size. Findings produced by NEBULA feed PULSAR's adversarial-findings list with `source: 'NEBULA'` and appear in AURORA's verdict and the existing fix-loop.

## Options Considered — Core analysis technique

### Option A: Symbolic execution

Execute the program abstractly over symbolic values. Track constraints on inputs; find paths that reach a sink under constraints that admit attacker-controlled values. KLEE, angr, Manticore territory — all for compiled languages; for JS/TS you'd build this yourself on top of the V8 AST or a custom interpreter.

| Dimension | Assessment |
|---|---|
| Coverage | Very high — finds bugs that require reasoning about values, not just flow |
| Performance | Exponential in branch depth; minutes per file is typical |
| Engineering cost | Enormous — symbolic executors are multi-year team projects |
| Explainability | Excellent — every finding comes with a concrete input that triggers it |
| Maturity in JS/TS | Almost nil; symbolic JS is a research problem |
| Soundness story | Unsound under most practical configurations (loop unrolling limits, heap approximations) |

**Pros:** the gold standard for finding deep semantic bugs; the one approach that could produce actual proof-of-concept exploits alongside findings.
**Cons:** does not fit the performance constraint; does not fit the engineering-budget constraint; doesn't fit the "team of one" constraint. Saying "we built a symbolic executor" is impressive until you have to maintain it.

### Option B: Abstract interpretation

Compute abstract values (intervals, types, taint labels, ownership) over the program lattice and iterate to fixpoint. Mature theory (Cousot et al., 1970s), proven industrial tools (Astrée, Coverity internally), scales to large programs when lattices are chosen well.

| Dimension | Assessment |
|---|---|
| Coverage | High — with the right abstract domain, catches what we need |
| Performance | Polynomial in lattice depth; seconds to minutes on large programs |
| Engineering cost | High but tractable — academic literature is rich, some off-the-shelf frameworks exist (though not for JS/TS) |
| Explainability | Moderate — abstract domains are harder to surface as human-readable findings |
| Maturity in JS/TS | Sparse. TAJS (Jensen et al.) is a research abstract interpreter; no production equivalent |
| Soundness story | Sound under explicit assumptions; this is AI's killer feature vs symbolic/pattern |

**Pros:** the theoretically clean answer; sound analysis is genuinely differentiating.
**Cons:** without an existing framework, building the abstract-interpretation plumbing is a 6–12 month project before we have our first finding. The abstract-domain design choice is itself a research problem. The market doesn't yet distinguish between "sound" and "works well" — customers want findings, not proofs.

### Option C: Taint tracking (intraprocedural first, interprocedural in v2) — recommended

Track whether values flow from user-controlled sources (request body, URL params, env vars) to dangerous sinks (eval, exec, SQL raw query, template compile). Classify findings when source-reaches-sink without passing through a sanitizer. This is what CodeQL does, what Semgrep's `taint:` mode does, what Pysa does, what Infer does for null-pointer analysis.

| Dimension | Assessment |
|---|---|
| Coverage | Hits the exact class of bugs rule-based tools miss: data-flow from source to sink across function boundaries |
| Performance | Linear in program size for intraprocedural; quadratic for call-graph-aware interprocedural. Targetable at sub-second on typical files |
| Engineering cost | Moderate — well-understood algorithm, rich prior art, tractable to build in tiers (intraprocedural v1, interprocedural v1.1, field-sensitive v2) |
| Explainability | Excellent — every finding comes with the source statement, the sink statement, and the chain of assignments between them |
| Maturity in JS/TS | CodeQL's JS taint analysis is a well-documented reference implementation; plenty to learn from |
| Soundness story | Unsound by default (function modeling is always approximate), but the imprecision is localized and documentable — "we miss taint through eval-constructed functions" is a clear caveat |

**Pros:** the pragmatic sweet spot. Matches what competitors actually ship (CodeQL, Pysa) so the market knows how to buy it. Tractable with a team of one. Explainable findings translate directly into actionable PR-ready fixes (ADR-0001's auto-fix loop consumes these cleanly). Tiered build-out: v1 ships intraprocedural, which already finds real bugs; interprocedural comes later without architectural change.
**Cons:** the source/sink/sanitizer catalogs are a perpetual maintenance tax — every new framework needs modeling. The intraprocedural v1 misses cross-function flows (which are most real-world cases). Requires a proper intermediate representation we don't have yet.

## Trade-off Analysis

Option A is technically dazzling but operationally infeasible for this team. Symbolic execution's appeal is that each finding comes with a concrete exploit, which is fantastic for a marketing demo. But the engineering cost is measured in person-decades, and performance is an order of magnitude off what VANTAGE needs to stay fast. The honest version of "let's build a JS symbolic executor" is "let's delete the product for three years." Reject.

Option B is theoretically correct but market-timing-wrong. Sound abstract interpretation is genuinely the future of static analysis, but customers today buy "finds bugs CodeQL misses," not "proves absence of bugs under the following assumptions." The framework gap in JS/TS means we'd be building both the tool and the research infrastructure at the same time. Revisit in 2028 when industrial abstract interpretation for JS has matured (Meta and Google both have internal projects moving that direction).

Option C is the answer because it wins on every constraint that matters today. Performance: fits in the budget. Engineering cost: buildable in 2-3 quarters by one person. Market legibility: CodeQL users already understand "taint analysis" as a category. Explainability: source→sink→chain is the most PR-ready format. And critically, it composes with ADR-0001's auto-fix loop: the fix for a taint finding is usually "insert a sanitizer at this point," which is a templatable transform.

The main counterargument to Option C — "it's the same thing everyone else does" — cuts the other way here. We're not trying to be more technically exotic than competitors; we're trying to be better at what customers can evaluate. Taint analysis is table stakes for the category; VANTAGE not having it is the current technical gap.

**Recommendation: Option C, intraprocedural in v1, interprocedural in v1.1, field-sensitivity in v2.**

## Options Considered — IR / analysis substrate

### Option D: Use an existing compiler toolchain

Import TypeScript's own AST (via the `typescript` package) and walk it. Use Babel for JS-only. Existing analyzers (ESLint, jscodeshift, ts-morph) show this is viable. For Python, use the `ast` module; for Swift, use SwiftSyntax.

| Dimension | Assessment |
|---|---|
| Engineering cost | Low — reuse battle-tested parsers |
| Performance | Good — parsers are fast |
| Language symmetry | None — each language is a separate toolchain with separate idioms |
| Evolvability | Bounded by what each toolchain exposes |
| Fit for taint analysis | Workable for intraprocedural; clunky for interprocedural because each toolchain has its own call-graph notion |

### Option E: Hand-roll a small common IR — recommended

Define a minimal IR tailored to taint tracking: statements are assignments, calls, conditionals; values carry taint labels; basic blocks are explicit. Write a frontend per language that lowers the native AST into this IR. All analysis happens against the IR, not against the native AST.

| Dimension | Assessment |
|---|---|
| Engineering cost | Higher upfront — frontend-per-language to write — but lower cumulative |
| Performance | Comparable; IR is a thin layer over the AST |
| Language symmetry | High — analysis is written once and runs on every language |
| Evolvability | Easy to add new analyses on the existing IR |
| Fit for taint analysis | Excellent — IR is designed for it |

**Recommendation: Option E.** The extra upfront cost is paid back by the second supported language. Language frontend is a per-language ~1-2k-line effort; taint analyzer is shared.

## Options Considered — Integration with existing pipeline

### Option F: New engine (NEBULA) between NOVA and ECLIPSE — recommended

NEBULA runs after NOVA (which gives us the module graph, useful for interprocedural analysis later) and before ECLIPSE (which scores risk using, among other things, NEBULA's findings). Output is a list of taint findings in the same shape as PULSAR's adversarialFindings, merged into the PULSAR finding list before the fix loop sees it.

**Pros:** clean insertion point; doesn't perturb the other engines; score contribution is well-defined.
**Cons:** the name convention is now 6 engines (METEOR/NOVA/NEBULA/ECLIPSE/PULSAR/AURORA), but the names are the brand — adding one is fine.

### Option G: Subsume into PULSAR

Make PULSAR do both pattern-matching and taint analysis. One engine, two modes.

**Pros:** one less name; conceptually "PULSAR finds adversarial issues" regardless of how.
**Cons:** muddles the engine responsibilities; makes it harder to benchmark pattern-match vs semantic separately (which we'll want to show in marketing); breaks the "METEOR scans, NOVA models, NEBULA traces, ECLIPSE scores, PULSAR tests, AURORA verdicts" ladder that makes the pipeline easy to explain.

**Recommendation: Option F.** The ladder narrative is part of the brand.

## Options Considered — Language sequencing

1. **TypeScript/JavaScript (v1).** Biggest corpus, matches the OWASP benchmark corpora, biggest existing VANTAGE market.
2. **Python (v1.1).** Second-biggest market for security static analysis; large attack surface (Flask, FastAPI, Django); Pysa provides a clear reference implementation.
3. **Swift (v2).** The user's Helix iOS work; a market no static analysis vendor currently serves well; differentiates VANTAGE.
4. **Go (v2.1), Rust (v2.2).** Substantial corpora, vocal communities, tractable given a working framework.
5. **SQL (composed into COSMIC).** Out of scope for the code-security product; belongs to the sibling track.

**Recommendation:** ship the above order. Each new frontend is ~2–4 weeks once the IR and analysis are stable.

## Consequences

### What becomes easier

VANTAGE stops being "a pattern matcher with engine names" and starts being "a semantic analysis platform with pattern-matching as one of its engines." That repositioning is what enables the Brick 2 auto-fix story at scale and the Brick 4 leaderboard dominance. Every taint finding produced by NEBULA is automatically a candidate for the auto-fix loop; sanitizer insertion is a templatable transform. The polyglot story becomes credible — adding Python adds a new market rather than forcing a ground-up rewrite.

The benchmark numbers move. Expect F1 on Juice Shop to jump from the current 72% toward 90%+ as the cross-function taint findings get caught. The methodology page will need an update to describe the NEBULA-enabled scoring path; the old pattern-only scores should be kept alongside for historical comparison.

### What becomes harder

The source/sink/sanitizer catalogs are the perpetual cost. Every new Express middleware, every new ORM, every new template engine is a modeling task. This is manageable with community contributions (CodeQL's ecosystem survives on them), but it's a real overhead we don't currently pay. Plan to ship v1 with catalogs for Express, the top 5 SQL libraries, and the top 3 template engines; add more through user requests.

The v1 intraprocedural limitation will be a visible gap. Real-world vulnerabilities usually cross at least one function boundary. The v1 release messaging has to be honest about this — "intraprocedural v1, interprocedural v1.1 planned" — and the roadmap has to credibly deliver 1.1 within 2 quarters. If interprocedural slips, the honest thing is to say so; if it ships on time, it's the biggest precision jump in VANTAGE's history.

Compilation and test time doubles-plus. Every frontend needs its own test fixtures; the IR needs its own invariant checks; the analysis needs tests for taint-through-every-combinator. Budget 30% of the NEBULA engineering time for testing infrastructure. That's not optional.

### What we'll need to revisit

Interprocedural analysis makes the call graph load-bearing. NOVA's current graph is designed for "does file A depend on file B"; interprocedural taint needs "can value x flow from function F in file A to function G in file B". These are close but not identical. Revisit NOVA's output shape in v1.1 planning.

The performance target. 1–10 seconds per file is acceptable for CI and acceptable for "opt-in via --semantic"; it is NOT acceptable for the "runs on every keystroke" IDE story. If we want that to survive NEBULA, we need an incremental-reanalysis layer that reuses prior results for unchanged files. Worth scoping after v1 lands so we have data on where the time actually goes.

The language-plugin ABI. We'll write the TS frontend to the IR before the spec is fully stable, and the abstractions will be wrong the first time. Expect one breaking IR change between v1 and v1.1; design the Python frontend against the refined spec and backport changes to TS.

## Action items

1. [ ] Define the IR schema in `src/engines/nebula/ir.ts`. Statement types: Assign, Call, Conditional, Return. Value types: Literal, Variable, FieldAccess. Label types: TaintLabel (source-tagged), SanitizerLabel (sink-specific).
2. [ ] Implement the TypeScript frontend in `src/engines/nebula/frontend-typescript.ts`. Use the `typescript` npm package (already a dep) to parse files and lower the AST to IR.
3. [ ] Write the initial source/sink/sanitizer catalog in `src/engines/nebula/catalog/javascript.ts`. Start with: Express `req.body`/`req.params`/`req.query` as sources; `eval`, `Function` constructor, `vm.runInNewContext`, `child_process.exec`, `child_process.execSync`, raw SQL execution in the top 3 ORMs as sinks; `encodeURIComponent`, `JSON.stringify`, parameterized query builders as sanitizers.
4. [ ] Implement the intraprocedural taint analyzer in `src/engines/nebula/analyzer.ts`. For each function: walk the IR, propagate taint labels through assignments and calls (calls with unknown models pass taint through all arguments conservatively), emit findings when tainted values reach sinks.
5. [ ] Integrate NEBULA into the pipeline in `src/engines/index.ts`. Add after NOVA, before ECLIPSE. Only run when the new `--semantic` flag is set.
6. [ ] Add `semantic: boolean` option to the MCP `analyze` tool input. Wire through to the engine pipeline.
7. [ ] Update `benchmarks/VANTAGE_BENCHMARK_REPORT.md` with semantic-path numbers. Update `sites/leaderboard/src/pages/methodology.astro` to explain the two paths.
8. [ ] Write test fixtures: one tainted-flow-to-eval, one tainted-flow-to-raw-SQL, one tainted-flow-with-correct-sanitizer (should NOT flag), one tainted-flow-via-multiple-assignments.
9. [ ] Benchmark NEBULA against Juice Shop. Capture new F1 number. Publish the delta alongside existing v2 scoring numbers — never replace the pattern-only numbers, keep both for historical audit.
10. [ ] Publish a NEBULA design note (blog post or benchmark page addendum) once v1 lands. The market-legibility play is "VANTAGE has taint analysis now, here's what it found that the v1 scan missed."

**Out of scope for v1 (explicitly revisited later):** interprocedural flow (v1.1), field-sensitivity (v2), Python frontend (v1.1), Swift frontend (v2), incremental reanalysis (v2).

**Estimated effort for v1 (items 1–9):** 8–12 focused weeks. This is a quarter-plus of work; the ADR-0001 auto-fix loop is a one-week project by comparison. Sequence them that way — auto-fix first, NEBULA second — so we have momentum before starting the long build.

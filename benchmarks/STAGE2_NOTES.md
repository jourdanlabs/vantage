# VANTAGE Stage 2 Benchmark — Correctness Notes

**Run date**: 2026-04-16  
**Source data**: `benchmarks/results/stage2.json`  
**Purpose**: Correctness assessment — PULSAR precision/recall on vulnerable corpora, NOVA structural correctness.

---

## Suite A — PULSAR on Vulnerable Corpora

### A1. OWASP/NodeGoat

**Pipeline output**:

| Metric | Pre-fix | Post-fix |
|--------|---------|----------|
| Files | 53 | **47** (6 vendor files excluded) |
| LOC | 4,113 | **3,382** |
| Functions detected | 55 | **46** |
| Avg function complexity | 98.73 | **4.8** |
| AURORA | REJECTED (72%) | **APPROVED (94%)** |
| Complexity score | **0%** | **87%** |
| Dependency score | 95% | 95% |
| Risk score | 94% | 96% |
| Adversarial score | 100% | 100% |
| ECLIPSE high-risk files | 0 | 0 |
| ECLIPSE med-risk files | 0 | 0 |
| PULSAR targets | 0 files | 0 files |
| PULSAR findings | 0 | 0 |

**PULSAR Tier-1 (PULSAR scope) precision/recall**: Not applicable — NodeGoat is Express callback-style (no `async/await`, no `.then()`). PULSAR's patterns (`findAsyncWithoutErrorHandling`, `findMissingErrorBoundaries`) are specific to promise-based code. Callback-based Node.js is outside the detection window.

**PULSAR Tier-2 capability gap (5 intentional OWASP vulns)**:

| File | Line | Category | PULSAR-detectable |
|------|------|----------|------------------|
| `app/routes/contributions.js` | 32-34 | code-injection (`eval()` on user input) | No |
| `app/data/allocations-dao.js` | 73, 78 | nosql-injection (`$where` template literal) | No |

All 5 known vulnerabilities are outside PULSAR scope. PULSAR does not detect `eval()`, injection patterns, or template literal injection.

**Critical finding — vendor file contamination**:

METEOR is scanning `app/assets/vendor/` — third-party minified JS libraries:
- `jquery.min.js`: functions with complexity 778, 1474, 682
- `raphael-min.js`: function with complexity 1,632
- `bootstrap.js`: function with complexity 311

These inflate the average function complexity to **98.73**, which drives the AURORA complexity score to **0%** (`score = max(0, 1 - min(1, (98.73 - 1) / 30)) = 0`). The actual application functions (routes, data layer) have normal complexity — the contamination is entirely from vendor code.

**Fix implemented** (`src/engines/meteor.ts`):
- Added `vendor` to the `alwaysIgnore` directory list (same treatment as `node_modules`)
- Added minified file skip in `walkDir`: files matching `*.min.js`, `*.min.ts`, `*-min.js` are excluded at scan time

**Impact on Stage 1 corpora** (audited before fix):
- react, typescript, superset, vscode: 0 vendor/minified files — **no change to Stage 1 scores**
- express: 2 files in `examples/public/` — 0 functions extracted from them, **no complexity impact**, score unchanged
- Stage 1 does **not** need re-run

**NodeGoat AURORA pre-fix: REJECTED (72%)** — driven by vendor artifact. **Post-fix: APPROVED (94%)** — correct assessment of the application code.

---

### A2. bkimminich/juice-shop

**Pipeline output**:

| Metric | Value |
|--------|-------|
| Files | 385 |
| LOC | 33,411 |
| Functions detected | 532 |
| AURORA | REJECTED (67%) |
| Complexity score | 91% |
| Dependency score | **0%** |
| Risk score | 97% |
| Adversarial score | 100% |
| ECLIPSE high-risk files | 0 |
| ECLIPSE med-risk files | 0 |
| PULSAR targets | 0 files |
| PULSAR findings | 0 |

**PULSAR Tier-1 precision/recall**:

| Metric | Value |
|--------|-------|
| Ground truth entries | 6 |
| True Positives | 0 |
| False Positives | 0 |
| False Negatives | 6 |
| Precision | N/A |
| **Recall** | **0.0%** |
| F1 | N/A |

All 6 ground truth entries were missed (FN). The complete miss list:

| File | Type | Confirmed issue |
|------|------|----------------|
| `routes/languages.ts` | error-boundary | `JSON.parse()` at L18 without try/catch |
| `routes/verify.ts` | error-boundary | `JSON.parse()` at L128 without try/catch |
| `routes/chatbot.ts` | error-boundary | `JSON.parse()` of training set without try/catch |
| `routes/recycles.ts` | error-boundary | `JSON.parse()` on `req.params.id` without try/catch |
| `routes/trackOrder.ts` | error-boundary | `.then()` on NoSQL query without `.catch()` |
| `routes/showProductReviews.ts` | error-boundary | `.then()` on NoSQL query without `.catch()` |

**Root cause — ECLIPSE risk gate**: PULSAR only runs on files that ECLIPSE marks as high-risk (≥ 0.65) or medium-risk (≥ 0.40). The maximum ECLIPSE risk score across all 385 Juice Shop files is **0.285**. No file clears the medium threshold.

Why Juice Shop scores so low with ECLIPSE:

- **Complexity** (30% weight): Juice Shop functions are modern TypeScript — small, focused, well-named. Average function complexity is low → `scoreComplexity` returns 0.0–0.3.
- **Test coverage** (20% weight): Juice Shop has a dense `test/` directory. `hasTestFile()` matches most source files, returning 0.0 (no risk) for coverage.
- **Function size** (15% weight): Max function lengths are ≤ 60 lines for most files → `scoreFunctionSize` returns 0.0–0.2.
- **Coupling** (25% weight): Most route files are imported by 0–3 other files → `scoreCoupling` returns 0.0–0.1.

The highest-scoring files (`routes/dataExport.ts`, `routes/order.ts` at 0.285) are still well below the 0.40 medium threshold.

**This is not an ECLIPSE scoring error** — Juice Shop is genuinely a well-structured, tested codebase. The issue is architectural: **PULSAR's coverage is entirely dependent on ECLIPSE's risk tier**. If ECLIPSE doesn't flag a file, PULSAR never examines it, regardless of whether that file contains injection vulnerabilities or hardcoded secrets.

**PULSAR Tier-2 capability gap (5 intentional vulns)**:

| File | Line | Category | PULSAR-detectable |
|------|------|----------|------------------|
| `lib/insecurity.ts` | 24 | hardcoded RSA private key (2048-bit, full PEM) | No |
| `lib/insecurity.ts` | 46 | hardcoded HMAC secret (`pa4qacea4VK9t9nGv7yZtwmj`) | No |
| `routes/trackOrder.ts` | 18 | nosql-injection (`$where` template literal) | No |
| `routes/showProductReviews.ts` | 36 | nosql-injection (`$where` string concat) | No |
| `lib/codingChallenges.ts` | 76 | redos (user-controlled `new RegExp()`) | No |

All 5 are outside PULSAR scope. Even if ECLIPSE surfaced these files, PULSAR's four pattern functions would not detect injection or hardcoded secrets.

**Juice Shop AURORA REJECTED (67%)** — driven by dependency score 0% (circular dependency inflation, same as VS Code finding from Stage 1 verification).

---

### A3. Summary: PULSAR Capability Map

PULSAR's detection scope covers **async robustness and error boundary patterns**. Its four detection categories:

| PULSAR Category | Detects |
|----------------|---------|
| `async-race` | Async functions without try/catch or .catch() |
| `null-safety` | Force unwraps, deep property access without null check |
| `edge-case` | Array index access, division by zero |
| `error-boundary` | JSON.parse without try/catch, Swift throwing without try |

**Known capability gaps** — discovered through this testing, not pre-documented:

| Gap Category | Examples in tested corpora |
|-------------|---------------------------|
| Code injection | `eval()` on user input (NodeGoat) |
| NoSQL injection | `$where` template literals (NodeGoat, Juice Shop) |
| Hardcoded secrets | RSA keys, HMAC secrets in source (Juice Shop) |
| ReDoS | User-controlled `new RegExp()` (Juice Shop) |
| SQL injection | Not tested but same structural gap |
| XSS | Not tested but same structural gap |

**Known gap — not a design choice**: PULSAR does not detect security vulnerabilities. This was not a deliberate scope exclusion stated upfront — it is a gap revealed by testing against real vulnerable corpora. Any documentation or positioning that implies security coverage must be corrected. Tools like Semgrep or CodeQL occupy the security scanning space; VANTAGE/PULSAR does not.

---

## Suite B — NOVA Circular Dependency Detection

**Result: 5/5 PASS**

| Scenario | Expected cycles | Detected | Result |
|----------|-----------------|----------|--------|
| `linear-no-cycle`: A→B | 0 | 0 | ✓ PASS |
| `two-cycle`: A→B→A | ≥1 | 1 | ✓ PASS |
| `three-cycle`: A→B→C→A | ≥1 | 1 | ✓ PASS |
| `diamond-no-cycle`: A→B, A→C, B→D, C→D | 0 | 0 | ✓ PASS |
| `embedded-cycle`: A→B→C and B→A | ≥1 | 1 | ✓ PASS |

NOVA's DFS-based cycle detection is correct on clean synthetic TypeScript with explicit named imports.

**Caveat**: These synthetic tests use simple relative imports. The known failure mode (barrel-file phantom cycles, documented in CALIBRATION_NOTES.md) is not tested here — it requires re-export chains that resolve ambiguously via the bidirectional `endsWith` matching in `resolveImportPath`. That remains a Stage 3 investigation item.

---

## Suite C — NOVA God Module Boundary Conditions

**Result: 4/5 PASS**

| Scenario | Lines (METEOR) | Exports | Expected | Detected | Result |
|----------|----------------|---------|----------|----------|--------|
| below-line-threshold | 499 | 9 | NOT god | NOT god | ✓ PASS |
| at-line-threshold | **501** | 9 | NOT god | IS god | ✗ FAIL |
| below-export-threshold | 501 | 8 | NOT god | NOT god | ✓ PASS |
| both-above-threshold | 501 | 9 | IS god | IS god | ✓ PASS |
| stress-large | 501 | 50 | IS god | IS god | ✓ PASS |

**Root-cause: METEOR over-counting, not a test calibration error or a NOVA bug.**

The `at-line-threshold` scenario passes a 500-line file to METEOR. `buildGodModuleFile(500, 9)` returns `parts.join('\n') + '\n'` — 500 content lines followed by a trailing newline (POSIX-standard). METEOR then counts lines as:

```ts
// src/engines/meteor.ts:319
const lines = content.split('\n').length;
```

`content.split('\n')` on any file ending in `\n` produces one extra empty element. A 500-line file reads as 501. NOVA's `file.lines > 500` check then fires: 501 > 500 → true → flagged as god module.

**The bug is in METEOR, not in the test expectation or NOVA's comparison.** A file with 500 content lines should report 500 lines. The `at-line-threshold` scenario is correctly calibrated (500 lines, `> 500` should be false); METEOR's count is wrong.

The benchmark code in `stage2.ts` implicitly acknowledges this: line ~598 computes `content.split('\n').length - 1 // trailing \n adds one` for display — but the same correction is not applied inside METEOR itself.

**Fix must go in METEOR** (`src/engines/meteor.ts:319`):

```ts
// Before
const lines = content.split('\n').length;

// After
const lines = content.endsWith('\n')
  ? content.split('\n').length - 1
  : content.split('\n').length;
```

**Blast radius**: `file.lines` from METEOR feeds ECLIPSE (risk scoring uses LOC bands), AURORA (total LOC metric), and NOVA (god module threshold). All three are affected — every well-formed text file has its line count over-reported by 1. The practical impact on Stage 1 numbers is likely small (1-line inflation per file), but needs verification (see item 5 in fix plan below).

**Verified thresholds** (from `src/engines/nova.ts`):
- God module fires when: `file.lines > 500` **AND** `exportMatches.length > 8`
- "exports" counts `/\bexport\b/g` matches — includes `export const`, `export function`, `export default`, etc.

---

## Suite D — Clean Baseline Regression

**Result: PASS**

| Check | Result |
|-------|--------|
| expressjs/express APPROVED | ✓ PASS |
| Score (96%) consistent with Stage 1 | ✓ |
| Breakdown (complexity=98%, dep=90%, risk=97%, adversarial=100%) | ✓ |

No regression introduced by any changes since Stage 1.

---

## Open Issues for Stage 3 / Product Decisions

| Issue | Severity | Type |
|-------|----------|------|
| METEOR vendor/minified file exclusion | HIGH | Bug fix |
| METEOR line-count over-counting (trailing newline) | HIGH | Bug fix — affects ECLIPSE, AURORA, NOVA god module detection |
| PULSAR coverage gated entirely by ECLIPSE threshold | HIGH | Architecture |
| PULSAR security detection gap (injection, secrets, ReDoS) | HIGH | Known gap — requires documentation correction |
| NOVA barrel-file phantom cycles (from CALIBRATION_NOTES) | HIGH | Bug fix |
| ECLIPSE risk threshold (0.40 med) too conservative for modern TS | MEDIUM | Calibration |

---

## Fix Plan (pre-Stage 3)

Fixes must be applied and Stage 2 re-run before the final report compiles. Do not start Stage 3 until real precision/recall numbers are produced from clean runs.

1. **METEOR vendor/minified exclusion** — add `vendor`, `assets`, `dist`, `build`, `public` to directory exclude list; skip `*.min.js` / `*-min.js` explicitly. Fixes NodeGoat AURORA false rejection.
2. **PULSAR capability map documentation** — reframe all existing documentation and positioning copy that implies security coverage. Mark injection, secrets, and ReDoS detection as known gaps, not out-of-scope by design.
3. **METEOR line-count trailing-newline fix** — patch `src/engines/meteor.ts:319` (see Suite C above). Root-cause: `content.split('\n').length` over-counts by 1 for POSIX-standard files ending in `\n`. Fix in METEOR; do not patch the test.
4. **Stage 2 re-run** — after fixes 1–3 are applied, re-run all of Stage 2 (Suites A–D) and record updated precision/recall numbers.
5. **Stage 1 re-run for React, TypeScript, Superset, VS Code, Express** — after the METEOR fix (item 3), re-run Stage 1 corpora to verify god module counts and LOC figures are not materially changed. If METEOR was over-counting by 1 per file, Stage 1 aggregate numbers may be slightly inflated. Cheap safety check before final report compilation.

---

## Key Numbers for the Report

| Corpus | AURORA | Complexity | Dependency | Risk | Adversarial | PULSAR findings |
|--------|--------|-----------|-----------|------|-------------|----------------|
| NodeGoat | APPROVED 94% (post-fix) | 87% (pre-fix: 0%, vendor contamination) | 95% | 96% | 100% | 0 |
| Juice Shop | REJECTED 67% | 91% | 0% (circ dep inflation) | 97% | 100% | 0 |
| express (baseline) | APPROVED 96% | 98% | 90% | 97% | 100% | — |

# VANTAGE Stage 2 Benchmark — Correctness Notes

**Run date**: 2026-04-16  
**Source data**: `benchmarks/results/stage2.json`  
**Purpose**: Correctness assessment — PULSAR precision/recall on vulnerable corpora, NOVA structural correctness.

---

## Suite A — PULSAR on Vulnerable Corpora

### A1. OWASP/NodeGoat

**Pipeline output**:

| Metric | Value |
|--------|-------|
| Files | 53 |
| LOC | 4,113 |
| Functions detected | 55 |
| AURORA | REJECTED (72%) |
| Complexity score | **0%** |
| Dependency score | 95% |
| Risk score | 94% |
| Adversarial score | 100% |
| ECLIPSE high-risk files | 0 |
| ECLIPSE med-risk files | 0 |
| PULSAR targets | 0 files |
| PULSAR findings | 0 |

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

**Recommended fix** (not implemented): Add `vendor`, `assets`, `dist`, `build`, `public` to METEOR's directory exclude list. Currently only `node_modules` and `.git` are excluded. Minified files (matching `*.min.js`, `-min.js`) should also be skipped explicitly.

**NodeGoat AURORA: REJECTED (72%)** — the rejection is driven by a vendor-file artifact, not actual application code quality.

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

PULSAR is a **robustness stress tester**, not a **security vulnerability scanner**. Its four detection categories:

| PULSAR Category | Detects |
|----------------|---------|
| `async-race` | Async functions without try/catch or .catch() |
| `null-safety` | Force unwraps, deep property access without null check |
| `edge-case` | Array index access, division by zero |
| `error-boundary` | JSON.parse without try/catch, Swift throwing without try |

What PULSAR does **not** detect (and makes no claim to):

| Gap Category | Examples in tested corpora |
|-------------|---------------------------|
| Code injection | `eval()` on user input (NodeGoat) |
| NoSQL injection | `$where` template literals (NodeGoat, Juice Shop) |
| Hardcoded secrets | RSA keys, HMAC secrets in source (Juice Shop) |
| ReDoS | User-controlled `new RegExp()` (Juice Shop) |
| SQL injection | Not tested but same structural gap |
| XSS | Not tested but same structural gap |

**Implication for positioning**: VANTAGE/PULSAR should not be positioned as a security vulnerability scanner. Its value proposition is maintainability risk (async crash vectors, error boundary gaps), which is orthogonal to OWASP Top-10 security scanning. Tools like Semgrep or CodeQL address the security scanning space.

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

**The one failure is a test calibration error, not a NOVA bug.**

The `at-line-threshold` scenario was designed to produce a file with exactly 500 lines of content. However, the test utility `buildGodModuleFile(500, 9)` generates content ending with a trailing `\n`. When METEOR counts lines via `content.split('\n')`, this produces 501 elements (the trailing newline creates an empty final element). NOVA's threshold is `file.lines > 500`, so 501 > 500 = true → correctly flagged as god module.

The scenario expectation was wrong: `500` content lines as generated → `501` METEOR lines. NOVA behavior is correct.

**Verified thresholds** (from `src/engines/nova.ts`):
- God module fires when: `file.lines > 500` **AND** `exportMatches.length > 8`
- "lines" is METEOR's line count (content.split('\n').length, including trailing empty element)
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
| PULSAR coverage gated entirely by ECLIPSE threshold | HIGH | Architecture |
| PULSAR has no security detection (injection, secrets) | HIGH | Capability gap |
| NOVA barrel-file phantom cycles (from CALIBRATION_NOTES) | HIGH | Bug fix |
| ECLIPSE risk threshold (0.40 med) too conservative for modern TS | MEDIUM | Calibration |
| NOVA god module test calibration off-by-one (trailing newline) | LOW | Test fix |

---

## Key Numbers for the Report

| Corpus | AURORA | Complexity | Dependency | Risk | Adversarial | PULSAR findings |
|--------|--------|-----------|-----------|------|-------------|----------------|
| NodeGoat | REJECTED 72% | 0% (vendor contamination) | 95% | 94% | 100% | 0 |
| Juice Shop | REJECTED 67% | 91% | 0% (circ dep inflation) | 97% | 100% | 0 |
| express (baseline) | APPROVED 96% | 98% | 90% | 97% | 100% | — |

# VANTAGE Calibration Notes

**Status**: Observations only. No code changes made.  
**Purpose**: Flag scoring weight and threshold concerns for product-level decisions.  
**Source data**: Stage 1 benchmarks (5 corpora) + verification run (VS Code).

---

## 1. NOVA — Circular Dependency Penalty Is Too Aggressive

**Formula** (`aurora.ts`):
```
const circDepPenalty = Math.min(1, nova.circularDeps.length * 0.15);
```

**Effect**: 7 circular dependencies = dependency score of **0**. Score of 0 on a 30%-weighted component caps the AURORA total at 70% regardless of how clean everything else is.

**Observed data**:

| Corpus | Circular deps | Dep score | AURORA |
|--------|--------------|-----------|--------|
| express | 0 | 0.90 | 96% APPROVED |
| react | 4 | 0.40 | 69% REJECTED |
| TypeScript compiler | 0 | 0.72 | 62% REJECTED |
| superset | 17 | 0 | 64% REJECTED |
| VS Code src/vs | 4,856 | 0 | 59% REJECTED |

**Problem**: 4,856 detected cycles on VS Code is almost certainly over-counting. VS Code is a shipped production product with a large test suite. Barrel files (`index.ts` re-exporting from sub-modules) can create phantom cycles in a naive import-resolution graph. The 0.15× penalty per cycle was likely calibrated for genuine circular deps in small-to-medium repos; it doesn't scale to large TypeScript monorepos with complex re-export patterns.

**Recommendation options** (pick one, product decision):
- Cap the cycle count used for scoring at a reasonable ceiling (e.g., `Math.min(circularDeps.length, 20) * 0.15`), treating any repo with 20+ cycles as "maximum dependency concern" rather than compounding the penalty linearly.
- Reduce the per-cycle penalty (e.g., 0.05 per cycle → 20 cycles to zero out).
- Separate genuine cycles (A→B→A) from long-chain cycles (A→B→…→A with depth ≥ 5) and weight them differently.
- Address NOVA's import resolution first (barrel file phantom cycles) before changing the penalty formula.

---

## 2. NOVA — Likely Over-Counting Cycles on Large TypeScript Repos

**Observation**: VS Code `src/vs` reports 4,856 circular dependencies. React reports 4. TypeScript compiler (src/compiler) reports 0. These numbers don't track with intuition about codebase quality.

**Likely root cause**: NOVA's `resolveImportPath` probes the first candidate extension match and returns it regardless of whether the file exists on disk (`fs.stat` is never called). In a large repo with barrel files:
```
// packages/foo/index.ts
export { A } from './a';
export { B } from './b';
```
If `a.ts` and `b.ts` both import from `../utils/index.ts`, and `index.ts` is resolved to `packages/foo` in some contexts, this creates phantom cycles.

**Recommended fix** (not implemented here): In `nova.ts`, before adding a dependency edge, verify the resolved path actually exists in `meteor.files`. Currently NOVA does check `knownFiles.find(k => k === toNorm || k.endsWith(toNorm) || toNorm.endsWith(k))` — the `endsWith` bidirectional matching may be the culprit (a short path like `src/utils` could match a longer canonical path in both directions).

---

## 3. ECLIPSE — Per-File Git Subprocess Is O(n) and Dominates at Scale

**Formula**: `getLastModifiedDays` runs `git log --follow -1 --format="%ai" -- <file>` via `execSync` for each file.

**Observed timing**:

| Corpus | Files | ECLIPSE time | ms/file |
|--------|-------|-------------|---------|
| express | 141 | 8ms | 0.06ms |
| react | 82 | 3ms | 0.04ms |
| TypeScript | 77 | 9ms | 0.11ms |
| superset | 2,942 | 3,491ms | 1.19ms |
| linux | 6,158 | 17,467ms | 2.84ms |
| VS Code | 5,729 | ~8,000ms est. | ~1.4ms |

**Effect**: ECLIPSE is 85% of total pipeline time on superset, 65% on Linux. At 10k+ files, ECLIPSE will take 15–30 seconds.

**Recommendation options** (not implemented):
- Batch `git log` calls: `git log --name-only --format="%ai"` once per directory, cache results in a map, look up per file. Reduces subprocess count from O(n_files) to O(n_dirs).
- Use `git diff --name-only HEAD~N` to mark recently-modified files, skip git for the rest.
- Make last-modified-days scoring optional/configurable; many users don't have git initialized in the analysis target.
- The staleness factor currently contributes to ECLIPSE's coupling score via `getLastModifiedDays` but the actual weight impact is minor. Consider whether the git call is worth its runtime cost.

---

## 4. AURORA — Dependency Score Weight (30%) Disproportionate

The four AURORA components are weighted:

| Component | Weight |
|-----------|--------|
| Complexity (METEOR) | 25% |
| **Dependency (NOVA)** | **30%** |
| Risk (ECLIPSE) | 25% |
| Adversarial (PULSAR) | 20% |

Dependency gets the highest weight, but NOVA's dependency score is the most volatile: a single god module or a handful of circular deps swings it dramatically. Meanwhile, ECLIPSE's risk score (which is based on actual file-level analysis with 5 factors) gets 25%.

**Observation**: The TypeScript compiler scores 62% despite:
- 0 circular dependencies
- 0 coupling issues
- 0 god modules (wait — it has 36 god modules)

Let me correct that: TypeScript compiler has 36 god modules. God module penalty: `Math.min(0.2, 36 * 0.05) = 0.2` → 20% reduction to dependency score. Plus 0 circular deps and 0 coupling → `dependencyScore = 1 - 0 - 0 - 0.2 = 0.80`. But TypeScript compiler scores 62%...

The 62% on TypeScript comes from the complexity component:
- 8,901 functions, avg complexity much higher than 1
- `avgComplexity = totalComplexity / functions.length`
- `complexityScore = max(0, 1 - min(1, (avgComplexity - 1) / 30))`
- If complexityScore comes out low on a codebase with many very complex functions (checker.ts is ~50k LOC), that 25% weight drives the score down.

**No change recommended here** — just noting the interaction. TypeScript's compiler being REJECTED is defensible (it is objectively a highly complex piece of software). The question is whether VANTAGE's role is to assess "code quality by conventional standards" vs "this is risky to change."

---

## 5. PULSAR — PULSAR Finds Almost Nothing on Typed Codebases

**Observation**: PULSAR took 0ms on React, 14ms on TypeScript, 1ms on superset. Findings:
- React: negligible (0.006ms)
- TypeScript compiler: 51 findings but only 14ms (against 8,901 functions)
- Superset: 1ms

PULSAR's patterns (`findAsyncWithoutErrorHandling`, `findNullSafetyIssues`, etc.) are heavily JS/TS-specific and depend on surface-level regex. On well-typed TypeScript codebases, TypeScript's own compiler catches most of what PULSAR would find. PULSAR's value is higher on JavaScript (untyped) codebases.

**Recommendation**: PULSAR's 20% weight in AURORA may be appropriate for JS, but for strict TypeScript codebases the findings will be systematically low. Consider language-aware weight adjustment (future work).

---

## 6. ECLIPSE — High-Risk File Count = 0 on VS Code (Anomalous)

VS Code `src/vs`: 5,729 files, 0 high-risk files. This is suspicious.

**Likely cause**: VS Code has a dense `test/` directory structure. ECLIPSE's test-coverage scoring (`hasTestFile`) looks for matching test files, and VS Code's test organization likely grants most source files a "has tests" pass. Combined with moderate function sizes (VS Code functions tend to be smaller and more focused), the ECLIPSE risk score stays under the 0.65 threshold for all files.

**Effect**: ECLIPSE reports 0 high-risk files → PULSAR only scans 0 targeted files → adversarial findings are from medium-risk files only → PULSAR takes 51ms instead of potential seconds.

**This may actually be correct** — VS Code is a well-tested codebase. But it's worth validating that the test-file detection is not giving false positives (marking files as "tested" when the test file matches only incidentally by name).

---

## Summary Table

| Issue | Severity | Change Type | Effort |
|-------|----------|-------------|--------|
| Circular dep penalty 0.15× too aggressive | HIGH | Calibration | Low |
| NOVA barrel-file phantom cycles | HIGH | Bug fix | Medium |
| ECLIPSE per-file git subprocess | MEDIUM | Performance | Medium |
| AURORA dependency weight 30% | LOW | Calibration | Low |
| PULSAR JS-centric patterns | LOW | Feature | High |
| ECLIPSE test-file false positives | LOW | Correctness | Medium |

None of the above are implemented in this commit. All require product-level decisions on acceptable score ranges and tradeoffs before touching weights.

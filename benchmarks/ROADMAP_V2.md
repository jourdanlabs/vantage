# VANTAGE Roadmap V2 — Capability Expansion

**Filed**: 2026-04-16  
**Source**: Gaps identified in `benchmarks/VANTAGE_BENCHMARK_REPORT.md` §4.5 and §5.1  
**Status**: Scoped, not started. Ready to execute in next focused session.

---

## Summary

| Item | Effort | Closes Gap Against | Priority |
|------|--------|--------------------|----------|
| [1] PULSAR vulnerability coverage expansion | 3–5 days (per batch) | Semgrep (§5.1 tier-2 gaps) | 3rd |
| [2] Code duplication detection | 4–6 days | SonarQube (§4.5) | 2nd |
| [3] Test coverage integration | 2–3 days | SonarQube (§4.5) | 1st |

**Recommended execution order**: 3 → 2 → 1. Items 3 and 2 together close the "SonarQube does things VANTAGE doesn't" footnote from §4.5. Item 1 expands adversarial recall and is best done iteratively driven by corpus evidence.

After all three: VANTAGE has no meaningful capability gap against either competitor on the dimensions benchmarked, while retaining its native advantages (APPROVED/REJECTED verdict, 100–500× speed, architectural analysis, deterministic runs, zero infrastructure).

---

## Item 1 — PULSAR Vulnerability Coverage Expansion

### What it does

Promotes the tier-2 patterns from §5.1 to tier-1 by implementing six new PULSAR detection families. Current PULSAR covers: eval/NoSQL injection, hardcoded secrets, ReDoS, JSON.parse error boundary. These patterns cover the remainder of OWASP Top 10 as applicable to server-side JS/TS.

### Patterns to add

#### 1a. XSS (reflected/stored)
- **Signal**: `res.send()`, `res.write()`, `res.end()` with `req.query.*`, `req.body.*`, `req.params.*` in the argument, without sanitization (no DOMPurify/escapeHtml/encode call in scope).
- **Template literal variant**: `` res.send(`<div>${req.query.name}</div>`) ``
- **Severity**: HIGH if user input flows directly into response; MED if through an intermediate variable.
- **Pipeline tier**: Security-unconditional (same as injection).
- **Validation corpus**: Juice Shop — `routes/videoHandler.ts` (XSS in video subtitle), `routes/userProfile.ts` (XSS via username).
- **FP risk**: Medium. Any `res.send(variable)` risks false-firing on variables not sourced from req.*. Taint tracking is needed for precision — in v1, limit to direct req.* access without intermediate assignment.

#### 1b. SQL injection (string concatenation)
- **Signal**: `db.query(`, `connection.query(`, `sequelize.query(`, `knex.raw(` with a template literal containing `${req.` or string concatenation containing `req.` or `+ req.`.
- **Distinct from existing**: The existing `$where` pattern is MongoDB operator injection. This is relational SQL string injection.
- **Severity**: HIGH if req.* appears in concatenation; MED if through a variable.
- **Pipeline tier**: Security-unconditional.
- **Validation corpus**: Juice Shop — `routes/login.ts:34` (`sequelize.query` with template literal, currently a Semgrep FP that's actually real), `routes/search.ts:23`.
- **FP risk**: Low-medium. `sequelize.query` with parameterized `?` or `:named` bindings is safe — the pattern should only fire on string-building, not on parameterized forms.

#### 1c. Path traversal
- **Signal**: `fs.readFile(`, `fs.readFileSync(`, `fs.createReadStream(`, `require(`, `res.sendFile(` where the first argument contains `req.params.`, `req.query.`, or `req.body.` directly or through a variable, without a preceding `path.resolve()` + comparison against a trusted base path.
- **Severity**: HIGH if unresolved user path; MED if resolved but no boundary check.
- **Pipeline tier**: Security-unconditional.
- **Validation corpus**: Juice Shop — `routes/fileServer.ts`, `routes/logfileServer.ts`, `routes/keyServer.ts` (all currently Semgrep findings for `express-res-sendfile`).
- **FP risk**: Medium. `path.join(__dirname, req.params.file)` is dangerous but so common that any unflagged pattern will have FPs. Safe invocations use `path.resolve` + explicit allowlist check — detect absence of both.

#### 1d. CSRF (missing middleware — architectural absence pattern)
- **Signal**: Express app registers state-changing routes (POST/PUT/DELETE handlers) before any `csurf()`, `csrf()`, `doubleCsrf()`, or `csrfMiddleware` call appears in the router chain.
- **Architecture note**: This is a *negative* pattern — detecting something absent rather than something present. Current PULSAR rules all detect positive code patterns. CSRF requires whole-file or whole-app reasoning about middleware registration order.
- **Design decision required** (see Deferred Questions §7): Does this live in PULSAR as a new `findMissingCsrfMiddleware()` function (scanning app.js/server.js for middleware registration), or in a new engine layer that reasons about "architectural absence" patterns? The PULSAR model works well for per-file code patterns but CSRF absence is an app-level property. Recommend scoping as a PULSAR function that scans the entry-point file for express middleware registration order.
- **Severity**: MED (CSRF is real but requires user interaction to exploit; lower severity than direct injection).
- **Pipeline tier**: Security-unconditional, but only runs on files matching `app.js`, `server.js`, `index.js`, `app.ts`, `server.ts` to avoid noise.
- **Validation corpus**: NodeGoat `server.js` (csurf referenced but currently scored as INFO by Semgrep because it's present).
- **FP risk**: High without careful scoping. Exclude files that clearly set up API-only routes (no session state, no cookies).

#### 1e. Weak crypto
- **Signal**:
  - `crypto.createHash('md5')` or `crypto.createHash('sha1')` — weak hash for security-sensitive use
  - `jwt.sign(payload, secret, { algorithm: 'none' })` or `algorithm: 'HS256'` with a secret under 32 chars
  - Password storage without bcrypt/argon2/scrypt: `crypto.createHash` on a password string
- **Severity**: HIGH for MD5/SHA1 on passwords; MED for weak JWT algorithm; LOW for MD5 in non-security contexts (e.g., cache keys).
- **Pipeline tier**: Security-unconditional.
- **Validation corpus**: Juice Shop `lib/insecurity.ts` — already has hardcoded secrets caught by PULSAR; JWT algorithm is `RS256` (safe); need a corpus with weak algo. NodeGoat `models/` for password hashing patterns.
- **FP risk**: Low for the hash-on-password form. Higher for generic `createHash('md5')` which is legitimately used for cache keys, ETags, and checksums. Limit HIGH severity to cases where the hash result feeds into an authentication or storage context.

#### 1f. Insecure deserialization
- **Signal**:
  - `eval(JSON.parse(...))` — partially covered by existing eval detection, but the JSON.parse wrapper may suppress current pattern matching. Verify and patch dedup logic.
  - `Function(userInput)()` — dynamic function construction from user input
  - `setTimeout(req.body.callback, ...)` or `setInterval(req.body.fn, ...)` — string-form timer with user input
- **Overlap with existing eval**: The current `findInjectionVulnerabilities()` catches `eval(req.*)`. The `eval(JSON.parse(...))` form may not match because the immediate argument is `JSON.parse(...)` not `req.*`. Scope the dedup: add a second-order check that looks one function call deep.
- **Severity**: HIGH for all forms.
- **Pipeline tier**: Security-unconditional.
- **Validation corpus**: Juice Shop `routes/b2bOrder.ts` (notevil usage — `b2bOrder` challenge uses eval-like execution of user-supplied code).
- **FP risk**: Low. `eval(JSON.parse(staticString))` is safe but rare; `Function(req.*)` is almost always dangerous.

### Calibration risk

The main calibration concern across all six patterns: **FP rate on clean TypeScript codebases**. The expressjs/express clean baseline must remain APPROVED at ≥95% after these additions. Test against the Suite D clean baseline before merging any pattern batch.

Secondary concern: pattern batches should be added incrementally, not all at once, so regression can be isolated.

### Effort estimate

3–5 days per batch of 2–3 patterns, including calibration against NodeGoat, Juice Shop, and the express clean baseline. Recommend batching: {XSS + SQL injection} → {path traversal + weak crypto} → {CSRF + insecure deserialization}.

---

## Item 2 — Code Duplication Detection

### What it does

Detects duplicate code blocks across the codebase and reports a duplication percentage — closing the SonarQube capability gap from §4.5 ("Code duplication: No" for VANTAGE).

### Architecture decision

**Which engine owns this?**

- **Option A: Extend METEOR** — METEOR already has file content. Add duplicate-block detection as a final pass after function extraction. Keeps the pipeline linear (one ingest, one AST pass, one set of outputs).
- **Option B: New engine NEBULA** (between METEOR and NOVA) — a dedicated redundancy engine. Cleaner separation of concerns; easier to iterate on detection strategy without touching METEOR's existing logic.
- **Option C: Extend NOVA** — wrong fit; NOVA reasons about inter-file *relationships* (imports/deps), not content similarity.

**Recommendation**: Option A (extend METEOR) for v1. The implementation is a second pass over already-read file content; it doesn't need a new pipeline stage. Promote to NEBULA as a separate engine if complexity warrants it.

### Detection strategy

**Two-phase approach**:

1. **Token-hash sliding window** (fast, O(n) with rolling hash): Normalize each file's text (strip whitespace/comments, lowercase identifiers), compute rolling hashes over 10-token windows, store in a hash map. Collision = candidate duplicate.
2. **Line-block confirmation** (precision step): For candidate duplicates, confirm with a line-level comparison of the raw block (≥10 lines matching). This eliminates hash collisions and gives an exact line range for reporting.

v1 can skip step 2 and use token-hash only — acceptable precision for an initial implementation, with a known caveat that very short code blocks may produce false positives.

**Variable renaming**: Token-hash on normalized tokens (e.g., all variable names replaced with `VAR`) catches copy-paste with renames. This is the main v1 use case. AST subtree comparison is deferred to v2.

### Minimum viable output

- `MeteorOutput.duplicateBlocks: DuplicateBlock[]` where each entry has `fileA`, `startA`, `fileB`, `startB`, `lines`, `similarity`.
- `MeteorOutput.metrics.duplicationPct` — total duplicated LOC / total LOC.
- Top 5 worst offenders surfaced in AURORA `topIssues` as MED severity.
- New AURORA score component or fold into `riskScore` — **deferred decision** (see §7).

### Output compatibility

Match SonarQube's duplication format for recognizability: report as a percentage with a configurable threshold (default: flag files with >3% duplication). SonarQube's default threshold is 3%.

### Effort estimate

4–6 days. Token-hash implementation is ~1 day. The calibration, AURORA integration, and output formatting are the real work (3–4 days). The "should it be its own engine" design question adds a day if the answer changes mid-implementation.

---

## Item 3 — Test Coverage Integration

### What it does

VANTAGE currently uses `hasTestFile()` as a coarse proxy for test coverage in ECLIPSE risk scoring. This replaces that proxy with actual coverage data when available, and adds risk-weighted coverage analysis to AURORA output — closing the SonarQube capability gap from §4.5.

### Scope

#### 3a. Coverage format parsers

Implement readers for the two most common formats:

- **LCOV** (`lcov.info`, `coverage/lcov.info`): Line-based format, universally produced by Jest/Mocha/Istanbul. Each `SF:` entry is a file; `DA:line,hits` gives per-line coverage. Parse into `{file, lineCoverage, branchCoverage, functionCoverage}`.
- **Istanbul JSON** (`coverage-summary.json`, `coverage/coverage-summary.json`): Native Jest output. JSON map of file path → `{lines: {pct}, branches: {pct}, functions: {pct}}`. Easiest to parse.
- **Cobertura XML** (`coverage.xml`): Common in Java, also produced by some JS tools. Lower priority — add in v2 if needed.

Auto-discover coverage files: scan for `coverage/lcov.info`, `lcov.info`, `coverage/coverage-summary.json` relative to the target root before the pipeline runs. If found, load. If not found, fall back to `hasTestFile()` behavior.

#### 3b. ECLIPSE integration

ECLIPSE's current `testCoverage` factor uses `hasTestFile()` which returns 0 (has tests) or 1 (no tests). Replace with:

```
testCoverageScore = 1 - (actualLineCoverage ?? (hasTestFile ? 0.5 : 0))
```

This makes the scoring continuous: 100% coverage → score 0 (no penalty), 0% coverage → score 1 (full penalty), no data → score 0.5 (same as "has test file" today).

Only apply actual coverage when the coverage file matches the METEOR-inventoried file path (handle relative vs absolute path normalization).

#### 3c. AURORA output additions

New fields in `AuroraOutput` (or extend `breakdown`):

- `coverageSummary?: { overallLinePct, overallBranchPct, uncoveredHighRiskFiles: string[] }`
- Surface uncovered high-risk files (files in `eclipse.highRisk` with coverage < 30%) as HIGH severity `topIssues` entries.
- Add to summary line: "X% line coverage across Y files."

#### 3d. Risk-weighted coverage

A high-risk file with 0% coverage is more dangerous than a low-risk file with 0% coverage. The ECLIPSE integration in §3b handles this implicitly because ECLIPSE already weights `testCoverage` against the other risk factors for that file. No additional math needed — the weighting is free once we have accurate per-file coverage.

### What this unlocks

When a project has coverage data, VANTAGE can make statements like: "high-risk file `src/auth/session.ts` has 12% line coverage — consider adding tests before shipping." SonarQube makes this statement. VANTAGE currently cannot.

### Effort estimate

2–3 days. LCOV and Istanbul JSON parsers are trivial (1 day). ECLIPSE integration is ~4 hours. AURORA output additions and path normalization are ~1 day. End-to-end calibration (verify Suite D express still passes at ≥95%) is another half-day.

---

## Deferred Questions — Product Input Required

The following questions need a decision before implementation begins on the relevant items. They should be resolved at the start of each item's session, not during implementation.

| # | Question | Relevant Item | Options |
|---|----------|---------------|---------|
| D1 | Should CSRF detection live in PULSAR (per-file) or a new "architectural absence" engine? | Item 1d | PULSAR (`findMissingCsrfMiddleware` on entry-point files) vs. new engine |
| D2 | Should code duplication be a METEOR extension or a new NEBULA engine? | Item 2 | METEOR extension (simpler, less clean) vs. NEBULA (clean separation, more work) |
| D3 | Should the duplication score feed into AURORA as a new 5th component, or fold into `riskScore`? | Item 2 | New component changes the score formula and breaks Stage 1/2 baseline numbers; folding it in is safer for continuity |
| D4 | Should coverage integration add a new `coverageScore` component to AURORA, or just improve ECLIPSE's existing `testCoverage` factor? | Item 3 | Adding a component changes the formula; improving ECLIPSE is non-breaking |
| D5 | Should PULSAR pattern additions be guarded behind a `--extended-security` flag or always-on? | Item 1 | Always-on matches current design; flag allows opt-in for noisier patterns (XSS, CSRF) |

---

## Validation Plan

Before any item is considered done, it must pass:

1. **Suite D regression**: `expressjs/express` must remain APPROVED at ≥95% AURORA score.
2. **Stage 2 regression**: NodeGoat and Juice Shop precision/recall must not decrease on existing GT entries. New patterns may add new TPs; no existing TP should become FN.
3. **Structural tests**: Suite B (circular deps) and Suite C (god module boundary) must remain 5/5. These are unrelated to these items but serve as a canary for pipeline regressions.
4. **Item-specific validation**: Each item has a corpus callout above — validate against that corpus before merging.

---

*This roadmap is the planning artifact for the next focused work session. Do not begin implementation from this document alone — resolve Deferred Questions first, then execute items in the recommended order (3 → 2 → 1).*

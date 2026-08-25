# VANTAGE HEAD-TO-HEAD vs FREE RUNNABLE COMPETITORS — 2026-06-10

> ⚠️ **SUPERSEDED IN PART — read `HEAD-TO-HEAD-FAIR-2026-06-10.md` first.**
> This report's §3b predicted that running CodeQL with `npm ci` (full build) would
> shed the 82 `js/syntax-error` Juice Shop FPs and possibly raise its score. The fair
> re-run (2026-06-10, deps installed, 617 `.ts` files extracted) **falsified that
> prediction**: the 82 syntax-errors are `data/static/codefixes/**` *fixture* files
> (unparseable by design; tsconfig-excluded), so they persisted identically and the
> build did not change CodeQL's detection. Honest fair security-lens aggregate is
> **9–12%** (not the ~12.5% estimated here, and CodeQL gained nothing from the build).
> VANTAGE still wins 72.7% vs 9–12%, and all net-new catches (SSTI, RSA key, ReDoS)
> survived a properly-built CodeQL. The tables below are retained as the original
> record; quote the FAIR report for any CodeQL number.

**Matched v2 scoring. Real numbers, losses included. No doctoring.**

This run answers one question: how does VANTAGE (pattern + NEBULA semantic) score
against the **free, runnable** competitors — **CodeQL CLI** and **Snyk Code (free
tier)** — on the same JS/TS corpora, through the identical scoring pipeline?

It is the cross-tool companion to `INTERNAL_BASELINE_2026-06-10.md` (which covered
VANTAGE + Semgrep). Same harness (`packages/vantage-bench`), same ground truth,
same corpus snapshots, same v2 rules (strict suffix path match + type match + ±5
line tolerance, null-propagating harmonic aggregate). Every tool below was scored
by `benchmarks/run-codeql-headtohead-2026-06-10.js` / `run-internal-baseline-2026-06-10.js`
against the **same** GT files — never v2-vs-stale-v1.

---

## TL;DR — publishability and result, per tool

| Tool | Ran? | Aggregate F1 (matched v2) | Publishable to third parties (Scott → labs)? |
|---|---|---|---|
| **VANTAGE 1.0.0 (pattern)** | yes | **72.7%** | **YES** — our own tool |
| **VANTAGE 1.0.0 + NEBULA (`--semantic`)** | yes | **55.2%** | **YES** — our own tool |
| **CodeQL CLI 2.25.6** | **yes** (both corpora) | 2.9% (full suite) / see caveats | **CONDITIONAL — must anonymize the tool name.** Running on OSI-licensed OSS is licensed; *naming "CodeQL"/"GitHub" in published material is a trademark violation* without written permission. |
| **Snyk Code (free tier)** | **NO — auth wall** | n/a (could not run) | **INTERNAL-ONLY.** Snyk ToS expressly forbids competitors from benchmarking the Services. JL is a SAST vendor → a competitor. Do not publish, even if it had run. |

> **Headline, stated honestly:** VANTAGE wins the matched head-to-head against
> CodeQL **on this corpus and this conservative, security-focused ground truth.**
> CodeQL's low F1 is *real* but is heavily depressed by two artifacts documented
> below (quality-lint noise + a TS parse failure in this harness). Both effects are
> flagged, not hidden. The genuinely load-bearing, non-artifact result is the
> **recall / net-new** story: VANTAGE catches 5 Juice Shop GT vulns and the NEBULA
> SSTI that CodeQL's security suite does not report at all.

---

## Corpus snapshots (pinned — identical to tonight's baseline)

| Corpus | License | SHA | GT entries |
|---|---|---|---|
| OWASP NodeGoat | Apache-2.0 | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | 4 |
| OWASP Juice Shop (master, Jun-5) | MIT | `160f3062d6d7c30033ec505596b5b54d32932d8f` | 9 |

Both corpora are released under OSI-approved licenses — relevant to CodeQL's license
(see §4).

---

## 1 — Which competitors actually ran

### CodeQL CLI 2.25.6 — RAN on both corpora ✅
- Downloaded the official `codeql-bundle-osx64` (1.3 GB) from `github/codeql-action`
  releases. Bundle ships JavaScript pack `2.3.11`; the
  `javascript-security-and-quality.qls` suite resolves **204 queries**.
- For each corpus: `database create --language=javascript-typescript` then
  `database analyze … javascript-security-and-quality.qls --format=sarifv2.1.0`.
  SARIF parsed through the harness's existing CodeQL SARIF parser, normalized,
  scored v2. Raw SARIF kept at `benchmarks/results/codeql_{nodegoat,juiceshop}_2026-06-10.sarif`.
- **Caveat (flagged, affects fairness — see §3a):** the DB was built from raw source
  with **no `npm install` / tsconfig resolution** (the bench harness clones source
  only). CodeQL's TS extractor therefore emitted **82 `js/syntax-error`** results on
  Juice Shop — i.e., it could not fully parse the corpus. This both inflates FP count
  and likely suppresses real dataflow TPs.

### Snyk Code (free tier) — COULD NOT RUN ❌ (documented precisely)
- Installed Snyk CLI `1.1305.1` via npm (clean, no global).
- `snyk code test /tmp/vantage-bench/nodegoat --sarif-file-output=…` returns:
  **`ERROR Authentication error (SNYK-0005) … 401 Unauthorized … Use `snyk auth`.`**
- `snyk auth` (CLI ≥ 1.1293) "**opens a browser window** … to log in to your Snyk
  account and authenticate" (OAuth). There is **no headless/unauthenticated path**
  for `snyk code test`; it requires a Snyk account token obtained through an
  interactive browser flow. In this non-interactive environment it cannot run.
- **This is not a fabricated result. Snyk Code produced no findings because it
  refused to start without auth.** No numbers are invented for it.
- Even with a token, **publishing Snyk Code results is forbidden** (§4) — so the
  auth wall is moot for the publishable table.

---

## 2 — The real F1 table (matched v2, losses included)

Every cell below is from an actual run through the same scorer. **Losses are not
omitted.** VANTAGE's Juice Shop FPs (the `data/static/codefixes/**` challenge
variants) are shown; CodeQL's wins on NodeGoat code-injection are shown.

| Tool | NodeGoat F1 (TP/FP/FN) | Juice Shop F1 (TP/FP/FN) | Aggregate F1 | Median runtime |
|---|---|---|---|---|
| **VANTAGE 1.0.0 (pattern)** | **100.0%** (4/0/0) | **57.1%** (8/11/1) | **72.7%** | 186 ms |
| **VANTAGE 1.0.0 + NEBULA** | 80.0% (4/2/0) | 42.1% (8/21/1) | 55.2% | 364 ms |
| **CodeQL 2.25.6 — full security-and-quality** | 18.8% (3/25/1) | 1.6% (3/375/6) | **2.9%** | ~19.4 s |
| CodeQL 2.25.6 — *security-only re-score (fair lens, §3a)* | 33.3% (3/11/1) | 7.6% (3/67/6) | ~12.5% | ~19.4 s |
| Semgrep 1.136.0 *(from baseline, context only)* | 21.1% (2/13/2) | 0.0% (0/22/9) | 0.0% | 9.2 s |
| **Snyk Code (free)** | **DID NOT RUN — auth wall** | **DID NOT RUN — auth wall** | n/a | n/a |

VANTAGE pattern + semantic numbers **reproduce tonight's baseline exactly** (re-run
2026-06-10; pattern 100.0% / 57.1% / 72.7%, semantic 80.0% / 42.1% / 55.2%).

**v2 aggregate is harmonic-with-zero:** any corpus at 0% pins the aggregate to 0
(why Semgrep aggregates to 0.0%). CodeQL's two non-zero corpora aggregate normally.

---

## 3 — Adjudications (read before quoting any CodeQL number)

Same discipline as the baseline: we do **not** deflate a competitor via our own
harness's limitations, and we flag every artifact that moves a number.

### 3a — CodeQL's FP count is dominated by non-security noise (pro-competitor flag)
On Juice Shop, CodeQL emitted **378 raw findings**; only **3** hit our 9-entry GT,
producing 375 "FPs." But the FP set is overwhelmingly **not false security claims**:

| Rule class | Count | Nature |
|---|---|---|
| `js/unused-local-variable` | 150 | code-quality lint |
| `js/syntax-error` | 82 | **parse failure** (un-built TS — harness limitation, §1) |
| `js/missing-rate-limiting` | 35 | hardening advisory |
| `js/automatic-semicolon-insertion` | 29 | style lint |
| `js/useless-assignment-to-local` | 11 | quality lint |
| (genuinely security: path-injection, sql-injection, stack-trace-exposure, …) | ~67 | the real security surface |

**307 of 375 Juice FPs (and 12 of 25 NodeGoat FPs) are quality/parse noise**, not
false vulnerability reports. The `security-and-quality` suite is doing exactly what
it says — including the *quality* half — against a security-only GT.

To be fair to CodeQL, we re-scored it on the **security-relevant subset** (dropping
unused-var, syntax-error, ASI, rate-limiting, and similar quality rules; recall
unchanged because no TP/FN are quality rules):
- NodeGoat: 18.8% → **33.3%** (3/11/1)
- Juice Shop: 1.6% → **7.6%** (3/67/6)

Even on the generous security-only lens, **VANTAGE leads decisively** — but the
honest delta is "72.7% vs ~12.5% aggregate," not "72.7% vs 2.9%." Both numbers are
in the table; quote the security-only one when characterizing CodeQL's *detection*
rather than its raw output volume.

### 3b — The TS parse failure is a harness limitation, not a CodeQL weakness
The 82 `js/syntax-error` results mean CodeQL's extractor hit unresolved
modules/types because we did not run `npm ci` before `database create`. A
production CodeQL run (deps installed) would parse cleanly, shed those 82 FPs, and
**could surface additional real TPs** (its dataflow ran on incompletely-extracted
source). **We do not claim CodeQL is structurally this noisy.** This run measures
CodeQL *as the bench harness invokes it* (source-only, matching how every other
tool here is run). A "CodeQL with full build" row is future work and would only
*help* CodeQL.

### 3c — CodeQL's recall gap is the genuinely informative signal (not an artifact)
Unlike FP count, recall is not affected by quality-lint noise. CodeQL's misses are
real coverage differences:
- It **does not model `JSON.parse()` without try/catch** as a finding → missed all
  three live error-boundary GT entries (juiceshop-006/007/009).
- It missed the **hardcoded RSA private key** (juiceshop-001) and the
  **user-controlled `new RegExp()` ReDoS** (juiceshop-005) that VANTAGE flags.
- On NodeGoat it caught 3/4 injection entries (eval ×2 + one `$where`) but missed
  the second `$where` (nodegoat-003, line 73).

### 3d — VANTAGE's own losses are shown, not hidden
- **Juice Shop 11 pattern FPs / 21 semantic FPs:** mostly the intentionally-vulnerable
  `data/static/codefixes/*` challenge-variant fixtures (new on Jun-5 master) plus
  taint-to-sink extras. Same "conservative GT" phenomenon documented in the baseline.
- **NodeGoat semantic 2 FPs:** the `index.js:72` open-redirect taint catch +
  `contributions.js:34` — undocumented-but-real, scored FP against the 4-entry GT.
- **juiceshop-008 (chatbot.ts) is structurally dead** for *every* tool (file
  refactored to `chat.ts` upstream) → a shared 8/9 recall ceiling on Juice Shop.

### 3e — Matched-scoring integrity
CodeQL's correct findings are credited through the harness's existing type-alias /
fuzzy normalization (`js/code-injection` → `injection`, `js/insufficient-password-hash`
→ `hardcoded-secret`, etc.), verified by hand against the SARIF on the GT lines.
No CodeQL true positive was scored as an FP due to a normalization miss. (We applied
the same standard the baseline applied to Semgrep's `code-string-concat` alias.)

---

## 4 — Publishable vs internal, per tool (with the actual terms)

### CodeQL — CONDITIONAL: results publishable, but the **name is not**
From the bundle's own `LICENSE.md` (GitHub CodeQL Terms and Conditions, shipped in
`/tmp/codeql-install/codeql/LICENSE.md`, verbatim):

- **Use Rights** expressly permit: *"Use the Software to perform academic research,"*
  *"Use the Software to demonstrate the Software,"* and analysis "**on the Open
  Source Codebase.**" NodeGoat (Apache-2.0) and Juice Shop (MIT) are Open Source
  Codebases → **running CodeQL against them is licensed.**
- There is **no clause prohibiting publication of benchmark or comparison results.**
- **BUT the trademark clause is a hard stop on naming:** *"These Terms do not grant
  any right or license to use any of GitHub's trademarks or logos, including …
  the names GitHub and CodeQL … You agree not to display or use any of these
  trademarks or logos in any manner without GitHub's prior written permission."*

**Verdict:** numbers may be shared externally **only if the tool is anonymized**
(e.g., "a leading free SAST CLI" / "Competitor C"). Publishing a table that *names
CodeQL* in a Scott→labs deck risks the trademark restriction. For internal JL use,
naming it is fine. **Recommend: anonymize for anything that leaves the chamber, or
seek written permission from GitHub before naming.**

### Snyk Code — INTERNAL-ONLY (and it didn't run anyway)
Snyk's Terms of Service restrict competitive/benchmark use. Per Snyk's ToS
(quoted across Snyk's published EULA / G-Cloud ToS): direct competitors of Snyk are
prohibited from accessing or using the Services, and the Services *"may not be
accessed for purposes of monitoring their availability, performance or functionality,
**or for any other benchmarking or competitive purposes**."* Snyk's terms further
*"prohibit the use of the Services to perform any benchmarking activities."*

JL ships a SAST product (VANTAGE) → JL is a Snyk competitor → benchmarking Snyk
Code and publishing the comparison is a ToS violation.

**Verdict: INTERNAL-ONLY. Never publish Snyk Code comparison numbers.** (Moot for
this run — Snyk Code could not start without browser-OAuth auth — but the rule
stands for any future authenticated run.)

### VANTAGE — fully publishable (our own tool).

---

## 5 — Net-new vulns: what VANTAGE catches that CodeQL does not

These are GT-confirmed (or April-investigated) vulns that VANTAGE reports and CodeQL's
`security-and-quality` suite **did not report on this run**:

| Vuln | Location | VANTAGE | CodeQL (this run) |
|---|---|---|---|
| **SSTI — tainted cookie → `pug.compile`** | `routes/userProfile.ts:87` | ✅ **NEBULA** (`[NEBULA] Tainted value from Express request cookies reaches pug.compile`) | ❌ **zero findings in userProfile.ts** |
| Hardcoded RSA private key | `lib/insecurity.ts:23` | ✅ pattern | ❌ FN |
| ReDoS via user-controlled `new RegExp()` | `lib/codingChallenges.ts:76` | ✅ pattern | ❌ FN |
| `JSON.parse` w/o try/catch | `routes/languages.ts:18` | ✅ pattern | ❌ FN |
| `JSON.parse` w/o try/catch | `routes/verify.ts:128` | ✅ pattern | ❌ FN |
| `JSON.parse` on `req.params.id` w/o try/catch | `routes/recycles.ts:14` | ✅ pattern | ❌ FN |
| NoSQL `$where` (2nd site) | `app/data/allocations-dao.js:73` | ✅ pattern + semantic | ❌ FN (caught line 78 only) |

**The SSTI is the headline:** CodeQL returned **0 findings in `userProfile.ts`**;
its only template-injection hits were in an unrelated file (`dataErasure.ts`). The
pug-compile-from-cookies path is invisible to pattern mode *and* not surfaced by
CodeQL here. (Honesty note per §3b: CodeQL's SSTI miss may be partly the un-built-TS
parse failure; a full-build CodeQL run might catch it. Stated as net-new *for this
matched run*, not as a permanent capability gap.)

NEBULA's other taint catches on Juice Shop (SSRF via `profileImageUrlUpload` fetch,
arbitrary file write via `profileImageFileUpload`, `vulnCode*` file reads, a
`yaml.load` deserialization, and several open-redirects) reappear exactly as in the
April delta-doc; they score as FPs against the conservative GT but read as real
undocumented vulns on inspection.

---

## 6 — Environment & reproducibility

- **CodeQL:** v2.25.6, JS pack 2.3.11, suite `javascript-security-and-quality.qls`
  (204 queries). Bin: `/tmp/codeql-install/codeql/codeql`. DBs built source-only
  (no `npm ci`). Driver: `benchmarks/run-codeql-headtohead-2026-06-10.js`. Raw
  results: `benchmarks/results/codeql_headtohead_2026-06-10.json` +
  `codeql_{nodegoat,juiceshop}_2026-06-10.sarif`.
- **Snyk:** CLI 1.1305.1 (npm), unauthenticated → SNYK-0005 401. No results file.
- **VANTAGE:** repo-local `bin/vantage.js` @ `pan-nebula-rescue`, pattern + `--semantic`.
  Reproduced tonight's baseline; raw in `benchmarks/results/internal_baseline_2026-06-10.json`.
- **Node** v24.15.0. Run under CPU contention; **TP/FP/FN are deterministic**,
  durations indicative. No Java runtime on host → SonarQube still not run (unchanged).
- **Scoring:** v2 (`packages/vantage-bench/src/scoring.ts`) — strict suffix path
  match + type match + ±5 line tolerance, null-propagating harmonic aggregate.
  Identical pipeline for every tool.

## 7 — Before any external use
1. **Anonymize CodeQL** (and never name Snyk) in anything Scott-facing → labs.
2. **Add a CodeQL-with-`npm ci` row** to retire the parse-failure caveat and give
   CodeQL its fair detection ceiling (it can only improve CodeQL's number).
3. Repair/retire **juiceshop-008** (dead `chatbot.ts`) and consider GT-expansion PRs
   for the verified extras (SSTI, SSRF, login/search SQLi) before publishing recall
   claims.
4. Exclude `data/static/codefixes/**` (challenge fixtures) from scope, or document
   them as intentionally in-scope.

🐦‍⬛ + 🔑 — real numbers, losses and caveats included. The chamber holds.

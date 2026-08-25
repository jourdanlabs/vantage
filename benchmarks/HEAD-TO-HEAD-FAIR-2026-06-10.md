# VANTAGE vs CodeQL — FAIR RE-RUN (CodeQL properly built) — 2026-06-10

**Chamber law: we don't bullshit. The Captain flagged the prior result (VANTAGE
72.7% vs CodeQL ~12.5%) as too-good-to-be-true. He was right to. This re-run gives
CodeQL its fair shot — DB built AFTER `npm install`, full extraction — and reports
the honest number even where it goes against us.**

🐦‍⬛ + 🔑

---

## TL;DR — the blunt version

1. **The proper build did NOT fix the FP inflation the way the prior report
   predicted.** The prior report (§3b) claimed the 82 `js/syntax-error` results on
   Juice Shop were un-built-TS parse failures that "a production CodeQL run (deps
   installed) would parse cleanly, shed." **That was wrong.** With `npm install` run
   first (435 MB of deps, frontend built, server TS compiled — 617 `.ts` files
   extracted, all 61 `routes/*.ts` parsed), the **identical 82 syntax-errors across
   the identical 39 files persisted, byte-for-byte.**

2. **Why:** all 82 are in `data/static/codefixes/**` — Juice Shop's
   **intentionally-broken coding-challenge fix-snippet FIXTURES** (bare code
   fragments with no module wrapper). Juice Shop's own `tsconfig.json` lists
   `"exclude": ["data/static/codefixes/**"]` — they are **never meant to compile**.
   `npm install` cannot fix files that are unparseable by design. The prior report's
   central "give CodeQL a fair build and it improves" excuse does not hold.

3. **What the build actually changed:** essentially nothing for detection. CodeQL
   finds the **same 3 ground-truth vulns** on Juice Shop built or un-built, and
   **misses the same 6**. On NodeGoat the numbers are **identical** to the prior run
   (NodeGoat never had syntax errors — it's small and parsed fine both times). The
   built tree actually surfaced **more** quality-lint (588 raw findings vs 378), so
   the broad-suite F1 went *down* slightly, not up.

4. **VANTAGE still wins, and the lead did NOT collapse.** On the fair security lens
   it's **VANTAGE 72.7% vs CodeQL 9–12%**. The honest correction to the prior number
   is small and in CodeQL's *disfavor*: prior estimated ~12.5%, the fair measured
   security-only aggregate is **11.9%** (prior-parity filter) or **9.2%** (true
   `security-extended` suite).

5. **All net-new catches survived a fair CodeQL.** Properly-built CodeQL still
   returns **zero findings** for the SSTI in `userProfile.ts:87`, still misses the
   hardcoded RSA key (`insecurity.ts:23`), still misses the ReDoS
   (`codingChallenges.ts:76`). The honesty caveat the prior report attached to the
   SSTI ("might be the un-built-TS parse failure") is now **retired** — it was not
   the parse failure; CodeQL genuinely does not model that pug-from-cookies path
   here.

---

## Environment & method (reproducible)

- **CodeQL:** 2.25.6, JS pack 2.3.11, bundle at `/tmp/codeql-install/codeql/codeql`.
- **Corpora (pinned, identical SHAs to the prior run):**
  - NodeGoat `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` (Apache-2.0), GT = 4
  - Juice Shop `160f3062d6d7c30033ec505596b5b54d32932d8f` (MIT), GT = 9
- **The fix under test:** for **each** corpus, `npm install` was run FIRST
  (NodeGoat: 962 pkgs; Juice Shop: root + frontend deps + `postinstall` building
  frontend `dist` and compiling server TS to `build/*.js`), **then**
  `codeql database create --language=javascript-typescript`. The extractor saw the
  `.ts` originals and correctly ignored the compiled `build/*.js` (0 duplicate
  extraction). Juice Shop DB grew to **48,583 LoC** extracted vs the prior thin DB.
- **Suites run (both):**
  - `javascript-security-and-quality.qls` (204 queries) — the broad suite the prior
    run used.
  - `javascript-security-extended.qls` (106 queries) — the **true security-only
    suite** (the fairest detection lens; it does not even run `js/syntax-error`).
- **Scoring:** the SAME matched-v2 harness (`packages/vantage-bench/src/scoring.ts`)
  — strict suffix path match + type match (+ alias map) + ±5-line tolerance,
  null/zero-propagating harmonic aggregate. Identical pipeline to the prior run and
  to VANTAGE's own scoring.
- **Drivers / receipts (in repo):**
  - `benchmarks/run-codeql-fair-2026-06-10.js` (build + both suites + score)
  - `benchmarks/score-codeql-fair-lenses-2026-06-10.js` (lens recompute, no rebuild)
  - SARIFs: `benchmarks/results/codeql-fair_{nodegoat,juiceshop}_{security-and-quality,security-extended}_2026-06-10.sarif`
  - JSON: `benchmarks/results/codeql_fair_2026-06-10.json`, `codeql_fair_lenses_2026-06-10.json`

---

## The corrected head-to-head table — FAIR RE-RUN, CodeQL properly built

VANTAGE pattern/semantic rows are the reproduced baseline (unchanged — VANTAGE's run
was never mis-built). CodeQL rows are the new properly-built numbers.

| Tool / lens | NodeGoat F1 (TP/FP/FN) | Juice Shop F1 (TP/FP/FN) | Aggregate F1 |
|---|---|---|---|
| **VANTAGE 1.0.0 (pattern)** | **100.0%** (4/0/0) | **57.1%** (8/11/1) | **72.7%** |
| **VANTAGE 1.0.0 + NEBULA (`--semantic`)** | 80.0% (4/2/0) | 42.1% (8/21/1) | 55.2% |
| **CodeQL 2.25.6 — security-and-quality (broad)** | 18.8% (3/25/1) | 1.0% (3/585/6) | **1.9%** |
| **CodeQL 2.25.6 — security-and-quality, security-only filter** (prior-parity lens) | 30.0% (3/13/1) | 7.4% (3/69/6) | **11.9%** |
| **CodeQL 2.25.6 — security-extended suite (true security-only)** | 28.6% (3/14/1) | 5.5% (3/97/6) | **9.2%** |

**Headline, stated honestly:** on this corpus and this conservative,
security-focused ground truth, **VANTAGE wins the matched head-to-head decisively —
72.7% vs CodeQL's 9–12% on the security lens** — and giving CodeQL a fully-built tree
did not change that.

### Delta vs the prior (mis-run) numbers — explained honestly

| Cell | Prior (mis-run) | Fair (proper build) | What moved & why |
|---|---|---|---|
| NodeGoat S&Q full | 18.8% (3/25/1) | **18.8% (3/25/1)** | **Identical.** NodeGoat had no syntax errors in either run; small tree parsed fine both times. |
| NodeGoat security-only | 33.3% (3/11/1) | **28.6–30.0%** | Slightly **lower**. The built/dataflow run emitted a couple more security advisories (e.g. extra redos/url-redirection), nudging precision down. Not an improvement. |
| Juice S&Q full | 1.6% (3/375/6) | **1.0% (3/585/6)** | **Worse raw**, not better — the fully-built tree gave CodeQL *more* code to lint (588 vs 378 findings). |
| Juice security-only | 7.6% (3/67/6) | **5.5–7.4%** | Essentially flat / slightly lower. **Same 3 TPs, same 6 FNs.** The build did not unlock new detections. |
| **Aggregate (security-only)** | **~12.5% (est.)** | **9.2% (suite) / 11.9% (filter)** | The honest fair number is **at or below** the prior estimate. CodeQL did not gain from the build. |

**The FP inflation was NOT fixed by the build** because it was never caused by the
build. The 82 syntax-errors are corpus fixtures. The *correct* fix is a **scope
decision** (exclude `data/static/codefixes/**`), applied symmetrically below — and
even that barely moves CodeQL (it removes the 82 syntax-errors from the *broad*
suite, but they're already absent from the security-extended suite, so the security
F1 is unchanged: 5.5% → 5.6%).

---

## Net-new catches — re-verified against a FAIR, fully-built CodeQL

Re-checked directly in the properly-built `security-extended` SARIF (the security
suite, full extraction). **Every net-new catch survived.**

| Vuln | Location | VANTAGE | Properly-built CodeQL | Survives? |
|---|---|---|---|---|
| **SSTI — tainted cookie → `pug.compile`** | `routes/userProfile.ts:87` | ✅ NEBULA | ❌ **zero findings in userProfile.ts** (CodeQL's only template-injection hits are in `dataErasure.ts:107/123`, unrelated) | ✅ **YES** |
| Hardcoded RSA private key | `lib/insecurity.ts:23` | ✅ pattern | ❌ FN (CodeQL flags line 43 `insufficient-password-hash`, nothing at the `BEGIN RSA PRIVATE KEY` literal on 23) | ✅ **YES** |
| ReDoS via user-controlled `new RegExp()` | `lib/codingChallenges.ts:76` | ✅ pattern | ❌ FN (CodeQL flags line 29 `file-system-race`, nothing at 76) | ✅ **YES** |
| `JSON.parse` w/o try/catch ×3 | `routes/languages.ts:18`, `verify.ts:128`, `recycles.ts:14` | ✅ pattern | ❌ FN (CodeQL does not model `JSON.parse`-without-try/catch as a finding) | ✅ **YES** |

**The SSTI honesty caveat is now retired.** The prior report flagged that CodeQL's
SSTI miss "may be partly the un-built-TS parse failure; a full-build run might catch
it." A full-build run was done. It does not catch it. `userProfile.ts` parses
cleanly (it is not a codefixes fixture) and CodeQL still reports zero there.

---

## What CodeQL DOES catch (credit where due — not buried)

- **NodeGoat:** both `eval()` injections (`contributions.js:32,33`) and the
  `$where` NoSQL injection in `allocations-dao.js`. Its single consolidated
  `code-injection` finding at line 78 is scored as 1 TP + 1 FN only because the GT
  splits the two adjacent `$where` lines (73 and 78) into separate entries and the
  matcher is first-match-wins. **CodeQL's honest NodeGoat injection recall is 3/4**
  (it detects the `$where` region; VANTAGE gets 4/4 because pattern-matching fires
  per line). That FN is a GT-granularity artifact, not a coverage gap — stated
  plainly so we don't overclaim.
- **Juice Shop:** the two `$where` NoSQL injections (`trackOrder.ts:18`,
  `showProductReviews.ts:36`) and the weak password hash (`insecurity.ts:43`,
  matched to GT juiceshop-002). These are real, correct CodeQL findings, credited via
  the harness's existing alias normalization.
- CodeQL's broad suite also produces a large volume of **genuinely useful** security
  advisories that fall outside our 9/4-entry GT (path-injection, stack-trace
  exposure, missing rate-limiting, etc.). They score as "FP" only against a
  deliberately conservative GT — they are not false security claims. This is the same
  conservative-GT phenomenon that produces VANTAGE's own FPs.

---

## Symmetric scope correction (codefixes excluded) — applied to BOTH tools

Because the codefixes fixtures are intentionally-broken and **both** tools trip on
them (VANTAGE had **4** codefixes FPs on Juice Shop; CodeQL had the 82 syntax-errors
plus a couple more), the honest scope fix is to exclude `data/static/codefixes/**`
for **everyone**. Effect:

| Tool | Juice Shop F1 (full) | Juice Shop F1 (codefixes excluded) | Aggregate (codefixes excluded) |
|---|---|---|---|
| VANTAGE pattern | 57.1% (8/11/1) | **66.7%** (8/7/1) | **80.0%** |
| VANTAGE + NEBULA | 42.1% (8/21/1) | **47.1%** (8/17/1) | **59.3%** |
| CodeQL security-extended | 5.5% (3/97/6) | **5.6%** (3/96/6) | **9.3%** |

Excluding the fixtures **helps VANTAGE more than CodeQL** (VANTAGE pattern → 80.0%
aggregate) because VANTAGE's fixture FPs were a larger share of its small FP count,
whereas CodeQL's 82 fixture-syntax-errors live only in the broad suite and don't
touch its security-lens precision. Either way, the gap widens in VANTAGE's favor.

---

## The single honest claim we CAN make now

> **On the NodeGoat + Juice Shop corpora, under matched v2 scoring against a
> conservative security ground truth, VANTAGE substantially outscores a fully-built,
> deps-installed CodeQL 2.25.6 on F1 (72.7% vs 9–12% on the security lens), and
> VANTAGE/NEBULA catch a set of real vulnerabilities — the pug-from-cookies SSTI, the
> hardcoded RSA key, the user-controlled-RegExp ReDoS, and the unguarded
> `JSON.parse` error-boundary cases — that a properly-built CodeQL does not report.**

What we must NOT claim:
- We must **not** repeat "CodeQL is this noisy because it wasn't built." It was built;
  it is this noisy on the *broad* suite because the broad suite includes quality lint
  and the corpus ships unparseable fixtures. On the *security* suite it is far
  cleaner (97 Juice FPs, not 585) but still loses on F1 and still misses the net-new
  set.
- We must **not** imply the gap is "72.7% vs 2.9%." The fair, security-lens number is
  **9–12%**. Quote that.
- Publishability is unchanged from the prior report: **CodeQL results may be shared
  externally only if the tool is anonymized** (GitHub/CodeQL trademark clause; running
  on the OSI-licensed corpora is itself licensed). Snyk remains never-publish.

🐦‍⬛ + 🔑 — fair shot given, honest number reported, lead held. The chamber holds.

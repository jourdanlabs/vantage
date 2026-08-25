# INTERNAL BASELINE — 2026-06-10 (matched v2 scoring)

**INTERNAL EYES ONLY. Not for publication, decks, or external conversation.**
Commercial SAST EULAs (Veracode/Checkmarx/Fortify) carry DeWitt clauses; GitHub's
CodeQL terms restrict competitive benchmark publication. Everything in this file
is for internal calibration only.

**Run date:** 2026-06-10 (rescue night)
**Harness:** `packages/vantage-bench` @ rescue commit, scoring **v2** (strict suffix
path match + type match + ±5 line tolerance, null-propagating harmonic aggregate —
see `SCORING_V2_DELTA.md`)
**Driver:** `benchmarks/run-internal-baseline-2026-06-10.js`
**Raw results:** `benchmarks/results/internal_baseline_2026-06-10.json` (full TP/FP/FN details)

## Why this run exists

The prior cross-tool table (README "Current rankings") mixes **v2-scored VANTAGE
against v1-scored Semgrep/SonarQube** numbers from April. That mismatch must not
be quoted. This run scores every tool through the identical pipeline: same harness,
same ground truth, same corpus snapshots, same v2 rules.

## Corpus snapshots (pinned tonight — record these, the April run never recorded its SHAs)

| Corpus | SHA | GT entries |
|---|---|---|
| OWASP NodeGoat | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | 4 |
| OWASP Juice Shop (master, 2026-06-05) | `160f3062d6d7c30033ec505596b5b54d32932d8f` | 9 |

## Results (matched v2 scoring, tonight's snapshots, internal only)

| Tool | NodeGoat F1 | Juice Shop F1 | Aggregate F1 | Median runtime |
|---|---|---|---|---|
| VANTAGE 1.0.0 (pattern) | **100.0%** (4TP/0FP/0FN) | 57.1% (8TP/11FP/1FN) | **72.7%** | 186 ms |
| VANTAGE 1.0.0+NEBULA (`--semantic`) | 80.0% (4TP/2FP/0FN) | 42.1% (8TP/21FP/1FN) | 55.2% | 364 ms |
| Semgrep 1.136.0 (p/owasp-top-ten + p/nodejs + p/javascript) | 21.1% (2TP/13FP/2FN) | 0.0% (0TP/22FP/9FN) | 0.0%* | 9.2 s |
| SonarQube | **not run** — no local server (docker daemon down on this machine) | | | |
| CodeQL | **not run** — CLI not installed; runner has never been executed; CodeQL terms caution | | | |

\* v2 aggregate is harmonic-with-zero: any corpus at 0% pins the aggregate to 0.
Semgrep's NodeGoat 21.1% **exactly reproduces the April number** (same 2 TPs on
`contributions.js:32/33`, same 2 misses on the DAO `$where` pair) — strong evidence
the matched pipeline is sound.

## Adjudications made tonight (read before quoting any number)

1. **Semgrep type-alias fix (pro-competitor).** Semgrep 1.136.x resolves the OWASP
   pack's eval-pattern to `code-string-concat` (1.159.x emitted `eval-detected`).
   The harness alias map didn't know the new id, scoring Semgrep's *correct*
   NodeGoat findings as FPs (initial run: 0 TP). Added the alias in
   `runners/base.ts` — the fix can only raise competitor scores. We do not deflate
   competitors via our own bugs.

2. **Semgrep Juice Shop 0% is genuine, with context.** Its findings normalize
   correctly but hit none of the 9 GT entries. Its single April TP
   (`lib/insecurity.ts` hardcoded secret) no longer lines up — semgrep now flags
   only line 56; GT pins 23/44 (which VANTAGE still matches). Semgrep *does* flag
   real SQLi at `routes/login.ts:34` and `routes/search.ts:23` that our GT doesn't
   document — scored FP under GT, same "conservative GT" phenomenon as NEBULA's
   extras. An honest external table would need those GT gaps closed first.

3. **GT entry juiceshop-008 is structurally dead.** `routes/chatbot.ts` no longer
   exists on Jun-5 master (refactored to `chat.ts` upstream). Every tool faces the
   same 8/9 recall ceiling, so the table stays internally matched — but the entry
   must be re-pointed or retired before any external use.

4. **Numbers are NOT comparable to April's.** Juice Shop master moved Apr→Jun
   (new `data/static/codefixes/*` fixture files are intentionally-vulnerable
   challenge variants that pattern+semantic both flag → new "FPs"). April recorded
   no corpus SHAs, so April's exact snapshot is unrecoverable. Tonight's SHAs are
   recorded above; **recommend pinning `corpus.ts` to tonight's SHAs** so GT and
   corpus stop drifting apart.

## NEBULA validation (the rescued engine works)

Semantic mode on tonight's snapshot reproduces the April delta-doc story:

- **Headline catch holds:** `routes/userProfile.ts:87` — `[NEBULA] Tainted value
  from Express request cookies reaches pug.compile` — the Juice Shop SSTI, same
  line as April, invisible to pattern mode and to Semgrep's targeted packs.
- The taint-to-sink extras reappear (profileImage upload/URL SSRF + redirect +
  arbitrary file write, `vulnCode*` file reads, plus a new `python.yaml.load`
  taint catch). They score as FPs against the conservative GT; April's analysis
  (every investigated extra = real undocumented vuln) still reads correct.
- Strict-F1 cost of semantic mode (~-17pp aggregate) is the documented GT-coverage
  artifact, not an engine regression.

## Environment caveats

- Run under CPU contention (a concurrent agent session and an OMNIS `luna watch`
  process were active). Durations are indicative; TP/FP/FN are deterministic.
- Semgrep 1.136.0 via system pip (python 3.9 ceiling), not April's 1.159.0.
  NodeGoat reproduction suggests rule behavior is equivalent on this corpus.
- `packages/vantage-bench/benchmark-results.{json,md}` (untracked) are an all-null
  artifact of a concurrent harness invocation before corpora/semgrep existed on
  this machine — superseded by this run, safe to delete.

## Morning punchlist

1. **Migrate the repo out of iCloud** (`~/projects/vantage`). Tonight's evidence:
   a stale `.git/index.lock` dated **Apr 19 09:39** had been silently blocking all
   commits for ~7 weeks — almost certainly why NEBULA sat uncommitted. iCloud+git
   is the known ORION hazard; it nearly cost the engine.
2. Decide merge of `pan-nebula-rescue` (== `pan-nebula-commit`, same commit) to master.
3. Pin corpus SHAs in `corpus.ts`; repair/retire juiceshop-008; consider GT
   expansion PRs for the verified extras (login/search SQLi, NEBULA taint catches)
   before ANY external table.
4. Exclude `data/static/codefixes/**` (challenge fixture variants) from analysis
   scope, or document them as in-scope intentionally.
5. SonarQube + CodeQL matched runs require: docker daemon up + sonar-scanner, and
   a CodeQL CLI install + license read. Neither attempted tonight.

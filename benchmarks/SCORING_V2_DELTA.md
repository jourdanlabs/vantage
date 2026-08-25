# Scoring v1 → v2 Delta

**Date:** 2026-04-19
**Reason:** Brick 4 pre-launch credibility pass. Tightening scoring rules before any external maintainer review; publishing the delta so changes are auditable.

## What changed

| | v1 (pre-launch) | v2 (current) |
|---|---|---|
| File match | `endsWith` OR `includes` OR shared basename | `endsWith` with path-segment boundary only |
| Line match (file scope) | `|finding.line − gt.line| ≤ 5` | same |
| Line match (project scope) | Implicit wildcard if `gt.line === 0` | Explicit `gt.scope === 'project'` field required |
| Runner path normalization | Per-runner, inconsistent | All runners emit corpus-relative POSIX via `toCorpusRelativePosix()` at boundary |
| Aggregate F1 null handling | Nulls dropped from average | Nulls propagate; any failed corpus → aggregate is `null` |

## Why

- **Basename collision.** A finding in `app/baz/bar.js` could claim a GT entry in `app/foo/bar.js` under v1's basename fallback. This inflated true-positive counts unpredictably and biased toward tools with loose path reporting.
- **Line 0 wildcard.** A GT entry with `line: 0` silently matched a finding at any line in the same file, with no documentation. v2 replaces this with an explicit `scope: 'file' | 'project'` field that must be set in the ground-truth JSON, and is described on the methodology page.
- **Path bias.** VANTAGE emits absolute paths; Semgrep emits relative; SonarQube prefixes with project key; CodeQL uses `file://` URIs. v1 left normalization to the scoring layer, which meant tools with different conventions got systematically different match rates. v2 normalizes at the runner boundary.
- **Null in aggregate.** v1 dropped null F1 scores before averaging, which meant a tool that errored out on half the corpora got a free pass on its working corpora. v2 reports null aggregate when any corpus returned null — failure to run is itself information about the tool.

## Actual number changes (VANTAGE, same commit, same corpora)

| | v1 | v2 | Δ |
|---|---|---|---|
| NodeGoat F1 | 1.000 (4 TP / 0 FP / 0 FN) | 1.000 (4 TP / 0 FP / 0 FN) | no change |
| Juice Shop F1 | 0.857 (12 TP / 4 FP / 0 FN) | 0.720 (9 TP / 7 FP / 0 FN) | −13.7pp |
| Aggregate F1 | 0.9285 | 0.837 | −9.2pp |

The Juice Shop change decomposes as follows. Under v1, VANTAGE had 12 TPs — but only 9 distinct ground-truth entries exist for Juice Shop. The 3 "extra" TPs were duplicate findings that the basename-fallback let claim the same GT entry more than once (the de-duplication rule was present but the permissive matching let multiple findings match different GT paths sharing a basename).

Under v2: 9 TPs (one per GT entry, perfect recall), 7 FPs (findings in files not in the GT catalog).

Notably the 7 FPs include several findings that look like legitimate vulnerabilities not yet in the ground-truth catalog:
- `routes/chatbot.ts:49` — JSON.parse without try/catch
- `routes/languages.ts:32` — JSON.parse without try/catch
- `routes/userProfile.ts:62` — eval on user-controlled profile field
- `rsn/rsnUtil.ts:27` — JSON.parse without try/catch
- `server.ts:323` — JSON.parse without try/catch
- `lib/codingChallenges.ts:78` — ReDoS (GT has same file at line 76; already claimed)
- `routes/captcha.ts:22` — eval on math expression (debatable; documented on methodology page)

Some of these are candidates for future GT additions. We are deliberately not adding them now — the v2 numbers stand as "VANTAGE hits 100% recall on the documented GT with 56% precision; some of the non-GT findings appear to be real vulnerabilities pending GT expansion." Expanding the GT after the fact to boost precision would undermine the whole point of this exercise.

## Other tools

Semgrep and SonarQube numbers under v2 have not yet been computed in this environment (Semgrep needs `semgrep.dev` for rule downloads; SonarQube needs Docker; neither is available in the benchmark sandbox used here). They will update on the next weekly GH Actions run. Their v1 numbers are retained in `results.json` with `pendingRebench: true` and are surfaced on the site as "pending rerun" with dimmed styling so readers aren't misled.

Expected direction: v2 will likely move Semgrep and SonarQube numbers slightly downward for the same reasons they moved VANTAGE — the basename-fallback produced some loose matches. The relative ranking is not expected to change. But we will publish the actual v2 numbers whatever they are, not projected ones.

## Going forward

Any future scoring change gets a new delta file. `scoringVersion` in `results.json` tags every record with the scoring revision that produced it, so the leaderboard is auditable all the way back.

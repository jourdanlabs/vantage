# Maintainer heads-up emails — pre-launch

Send these **14 days before public launch**. Each one is short, factual, and invites engagement before the leaderboard goes live — which converts half the recipients from potential day-one critics into acknowledged participants, and gives a clean public paper trail for the other half.

Keep the tone professional. Don't oversell VANTAGE. The point isn't to make them mad; it's to make sure that when the leaderboard drops, nobody can say "you ambushed us."

**Subject line template for all four:** `Heads-up — we're publishing an open static-analysis benchmark in ~2 weeks, [TOOL NAME] is included`

Send each from a real human address (not a no-reply alias). Signed with a real name and a phone number, for bonus trust.

---

## 1 — Semgrep

**To:** security-research@semgrep.dev, plus whoever is currently head of their detection team (check their GitHub `CODEOWNERS` or recent blog posts)
**Subject:** Heads-up — we're publishing an open static-analysis benchmark in ~2 weeks, Semgrep is included

Hi [team],

I'm [Name], building an open-source static-analysis tool at JourdanLabs. In two weeks we're publishing a reproducible static-analysis leaderboard at benchmark.vantage.dev. Semgrep is one of the four tools we've benchmarked against OWASP NodeGoat and OWASP Juice Shop, and I wanted you to see the methodology and configuration before it goes public.

Full harness, ground-truth catalogs, and scoring rules are in the repo: https://github.com/jourdanlabs/vantage/tree/main/packages/vantage-bench

Your configuration is pinned to `--config p/owasp-top-ten p/nodejs p/javascript` (explicit, not `auto`). Our reasoning for not using `auto` is documented on the methodology page and in the launch post draft — the short version is that `auto` is opaque, non-reproducible from a commit SHA, and we wanted every leaderboard number to be recomputable indefinitely. If you'd prefer us to run both configs and publish both numbers side-by-side, or to swap in a different Semgrep-team-blessed ruleset, I'd welcome a PR. We'll gladly publish whatever you'd prefer to represent Semgrep's best configuration for this benchmark.

Under the current scoring rule (strict path-suffix matching, explicit scope field instead of line wildcards, per-runner path normalization) Semgrep's results against our v2 rule are:

- NodeGoat F1: 21.1%
- Juice Shop F1: 7.1%
- Aggregate F1: 12.8%

If you think any of those numbers misrepresent Semgrep's real capabilities on this corpus, please push back. I'd rather hear from you in the next two weeks than have a reviewer say so publicly after launch.

Planned publication date: [DATE].

Happy to do a video call if it's easier. My calendar is at [URL].

Thanks,
[Name]
[Phone]
[Company email]

---

## 2 — SonarSource

**To:** Whoever leads product / engineering for SonarQube (check their executive bios or recent org-chart mentions on their blog)
**CC:** community@sonarsource.com (the community support team tends to route mail usefully)
**Subject:** Heads-up — we're publishing an open static-analysis benchmark in ~2 weeks, SonarQube is included

Hi [team],

I'm [Name] from JourdanLabs. In about two weeks we're publishing an open reproducible static-analysis leaderboard at benchmark.vantage.dev. SonarQube Community is one of the four tools included; I wanted to share the methodology and our current results with you before the public launch.

The harness and scoring rules are public: https://github.com/jourdanlabs/vantage/tree/main/packages/vantage-bench

Our SonarQube runner boots the official Docker image (`sonarqube:community`) and uses `sonar-scanner` with the default JS/TS ruleset, excluding `node_modules`, `dist`, and `*.min.js`. Against OWASP NodeGoat and OWASP Juice Shop under v2 scoring:

- NodeGoat F1: 0.0%
- Juice Shop F1: 5.8%
- Aggregate F1: 2.9%

Those numbers are lower than I expected, and I want to be sure we're configuring the scan fairly. A couple of possibilities I'd like your read on:

1. The default Community ruleset may not be tuned for Node.js-specific patterns the OWASP corpora feature (`eval` on user input, `JSON.parse` without try/catch, NoSQL `$where` injection). Is there a ruleset we should point the scanner at that would better represent SonarQube's real-world performance on Node? We'll gladly re-run with whatever you suggest and publish both numbers.

2. We're running Community specifically, not Developer or Enterprise. If the Developer edition has meaningfully different detection coverage on the same corpora, we'd like to note that on the leaderboard page so readers understand the scoping.

If you'd prefer a different configuration, please send a PR or just describe the change in an issue — we'll incorporate before publication.

Planned publication date: [DATE].

Thanks,
[Name]
[Phone]
[Company email]

---

## 3 — GitHub CodeQL team

**To:** Whoever currently leads CodeQL research (check `github/codeql` CODEOWNERS for recent names)
**Subject:** Heads-up — we're publishing an open static-analysis benchmark in ~2 weeks, CodeQL is included

Hi [team],

[Name] at JourdanLabs. We're publishing an open static-analysis leaderboard at benchmark.vantage.dev in about two weeks. CodeQL's JavaScript security-extended suite is one of the four tools included. Pre-launch heads-up so you can push back on anything that doesn't accurately represent CodeQL's real-world performance.

Harness: https://github.com/jourdanlabs/vantage/tree/main/packages/vantage-bench. Runner at `src/runners/codeql.ts`.

We're using `javascript-security-extended.qls` via the CodeQL CLI (version pinned, latest release at publication time). Paths are normalized at the runner boundary. Ground truth is published under CC-BY-4.0.

Weekly automation runs all four tools in parallel on Sunday; if a run flakes, we mark the entry stale instead of dropping it. The cron, artifacts, and audit trail are all in the repo.

Anything you'd like configured differently — a different query suite, different exclusions, a different CLI version — file a PR or reply here. Results under the current v2 scoring rule are published alongside the configuration, so whatever lands is what goes on the leaderboard at launch.

Planned publication date: [DATE].

Thanks,
[Name]
[Phone]
[Company email]

---

## 4 — Snyk Code team

**To:** Someone on the Snyk Code product team (check their LinkedIn for current roster)
**Subject:** Heads-up — we're publishing an open static-analysis benchmark in ~2 weeks; we'd like to include Snyk Code

Hi [team],

[Name] at JourdanLabs. We're launching an open reproducible static-analysis leaderboard in about two weeks. The current v1 has four tools: VANTAGE (our own), Semgrep, SonarQube, and CodeQL. We'd like to include Snyk Code, but because Snyk Code requires an authenticated account and doesn't run as a one-shot CLI the way the others do, we haven't been able to benchmark it under the same reproducibility constraints (every result tagged with a commit SHA, re-runnable by anyone from the command line).

Two options we'd welcome your help with:

1. A time-boxed Snyk Code account/key for the benchmark repo so we can run it in CI alongside the others, with results subject to the same strict scoring rule. We'd run it on the same OWASP corpora (NodeGoat and Juice Shop) with whatever configuration your team recommends.

2. Snyk's own team running the benchmark and submitting the results as a PR — we'll review the configuration and publish the numbers. This is how we'd prefer to include any commercial tool where re-running externally isn't practical.

We'd rather have Snyk Code represented accurately than absent, but we also don't want to publish a half-configured run that doesn't reflect the product's real performance. Open to whatever works for you.

Planned publication date: [DATE]. If we haven't heard by [DATE minus 5], we'll launch without Snyk Code and note it as "not yet included, PR welcome."

Thanks,
[Name]
[Phone]
[Company email]

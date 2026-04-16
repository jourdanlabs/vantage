# VANTAGE — Autonomous Code Evolution Engine

Real static analysis CLI that runs a full COSMIC pipeline against any codebase.

## What it does

VANTAGE walks your codebase and runs 5 real analysis engines:

- **METEOR** — file scanner: complexity, imports, functions, TODOs
- **NOVA** — dependency graph: circular deps, tight coupling, god modules
- **ECLIPSE** — risk scoring: 0.0–1.0 per file
- **PULSAR** — adversarial stress test: async safety, null handling, error boundaries
- **AURORA** — final verdict: ≥0.80 APPROVED, <0.80 REJECTED

## Usage

```bash
npm run analyze /path/to/project
npm run analyze /path/to/project -- --engine PULSAR
npm run analyze /path/to/project -- --output report.json
```

## Example output

```
VANTAGE — Autonomous Code Evolution Engine
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▸ METEOR   scanning 57 files...           ✓ 482 functions, 11,998 LOC
▸ NOVA     building dependency graph...   ✓ 0 circular deps
▸ ECLIPSE  scoring risk...                ✓ 3 high-risk files
▸ PULSAR   adversarial stress test...     ✓ 6 TODOs flagged
▸ AURORA   final audit...                 ✓ 93.9% APPROVED

━━━ AURORA VERDICT ━━━━━━━━━━━━━━━━━━━━━━
Score: 0.939 / APPROVED ✓
```

## Install

```bash
npm install
npm run analyze /path/to/your/project
```

Built by JourdanLabs.

---

## Benchmarks

Tested against [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) and [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — two intentionally vulnerable Node.js/TypeScript apps with a known ground-truth vulnerability catalog.

| | VANTAGE | Semgrep (OWASP+nodejs+js) | SonarQube Community |
|---|---|---|---|
| NodeGoat precision | **100%** | 13.3% | 0% |
| NodeGoat recall | **100%** | 50% | 0% |
| NodeGoat F1 | **100%** | 21.1% | 0% |
| Juice Shop precision | **75%** | 5.6% | 3.4% |
| Juice Shop recall | **100%** | 10% | 20% |
| Juice Shop F1 | **85.7%** | 7.1% | 5.8% |
| NodeGoat runtime | **19 ms** | ~3,700 ms | ~11,000 ms |
| Juice Shop runtime | **107 ms** | ~14,500 ms | ~27,000 ms |
| Actionable verdict | **APPROVED / REJECTED** | finding list | Quality Gate |
| Circular dep detection | **Yes** | No | No |
| Requires server/infra | **No** | No | Yes (Java server) |

**194× faster than Semgrep. 579× faster than SonarQube. 100% recall on both corpora.**

Neither Semgrep nor SonarQube detected NoSQL `$where` injection or `JSON.parse` missing error boundaries — two of VANTAGE's core patterns. SonarQube's 56/58 Juice Shop vulnerability findings were test-fixture credentials; VANTAGE filters those by default.

Full methodology, ground truth catalog, and per-finding breakdowns: [`benchmarks/VANTAGE_BENCHMARK_REPORT.md`](benchmarks/VANTAGE_BENCHMARK_REPORT.md)

---

## Python Package (PyPI)

```bash
pip install vantage-x
```

```python
from vantage import analyze

report = analyze("/path/to/project")
print(report.verdict)    # APPROVED or REJECTED
print(report.score_pct)  # e.g. "87.4%"
```

Requires Node.js with `vantage` on PATH.

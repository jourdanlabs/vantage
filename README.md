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

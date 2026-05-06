# VANTAGE 2.0

VANTAGE 2.0 is a deterministic code auditor from JourdanLabs. It is not an LLM wrapper and it does not call the network. It scans local projects, emits auditable findings, detects duplicate project families, generates deterministic fix plans, and can run in `wrecking_crew` mode for aggressive review.

## Install

```bash
npm install
npm run build
```

## CLI

```bash
npm run vantage -- audit /path/to/project
npm run vantage -- audit /path/to/project fix
npm run vantage -- audit /path/to/project wrecking_crew
npm run vantage -- benchmark fixtures/vantage
```

After publishing or linking the package:

```bash
vantage audit /path/to/project
vantage benchmark
```

## Modes

- `report`: find and report; never mutates the workspace.
- `fix`: includes deterministic, low-risk fix plans.
- `wrecking_crew`: escalates scrutiny and reframes suggested actions as challenges.

## What It Catches

- package health drift
- missing build/test/lint/readme/license signals
- broad dependency versions and duplicated dependency sections
- direct `process.env` access
- child process usage
- destructive filesystem calls
- dynamic code execution
- hardcoded secret material
- NoSQL `$where` injection
- unsafe dynamic regular expressions
- circular dependencies
- long functions
- duplicate project families

## Verification

```bash
npm test
npm run build
```

The checked-in benchmark fixtures assert 100% expected finding recall, zero forbidden hits, zero severity mismatches, and deterministic audit hashes.

# Contributing to VANTAGE

Thanks for wanting to help. VANTAGE is open-source because the benchmark, the detection logic, and the fix templates all get better faster when the people who care about them can open PRs. This guide covers the three most common contribution types.

## Adding a NEBULA source/sink/sanitizer

NEBULA's taint-analysis catalog lives at `src/engines/nebula/catalog/javascript.ts` (for JavaScript and TypeScript; Python and Swift frontends are coming). Every entry is one object with a clear shape. Example:

```typescript
export const JAVASCRIPT_SOURCES: TaintSource[] = [
  {
    id: 'koa.ctx.request.body',
    fieldPath: ['ctx', 'request', 'body'],
    kind: 'user-input',
    description: 'Koa ctx.request.body — request body in Koa middleware',
  },
  // ...
];
```

To add one:

1. Fork the repo and check out a branch.
2. Add your entry to the appropriate array (sources, sinks, or sanitizers). Keep the `id` unique.
3. Add a test case under `src/engines/nebula/nebula.test.ts` that exercises the new entry — a small code snippet that should produce a finding (for sources/sinks) or should NOT produce one (for sanitizers).
4. Run the tests: `npx ts-node src/engines/nebula/nebula.test.ts`.
5. Open a PR. In the description, cite one real-world example of the pattern in public OSS — we'll confirm it and merge.

The standing invitation: if your tool, framework, or ORM has a source/sink/sanitizer pattern VANTAGE doesn't model, a 5-line PR gets it supported.

## Adding a fix template

Templates live at `src/mcp/fix-templates/<name>.ts`. Every template implements a single interface (`FixTemplate` from `types.ts`) and must be deterministic — same input always produces the same output. That's what makes the template path auditable compared to the LLM path (which ships in v2).

Template contract:

- Receive a `TemplateInput` (file path, file contents, finding line, finding type, finding description).
- Return a `TemplateOutput` that either produces a unified-diff patch or skips with a clear reason.
- Never throw. Return `applied: false` instead.
- Never mutate the filesystem. Templates produce diffs, nothing else.

Add the template to `src/mcp/fix-templates/index.ts`'s `ALL_TEMPLATES` array. Add a test to `src/mcp/fix-templates/templates.test.ts` with at least:

- One case the template must accept (exact expected output).
- One case it must skip (with the exact skip reason).
- One case it must refuse to touch (e.g., wrong finding type).

Run: `npx ts-node src/mcp/fix-templates/templates.test.ts`. Every existing test must continue to pass.

## Adding a tool to the leaderboard

The vantage-bench runner interface is at `packages/vantage-bench/src/runners/base.ts`. To add a tool:

1. Implement the `Runner` interface in `packages/vantage-bench/src/runners/<tool>.ts`. Normalize findings to corpus-relative POSIX paths via `toCorpusRelativePosix` — this is non-negotiable, it's what keeps the benchmark fair.
2. Register your runner in `packages/vantage-bench/src/index.ts`'s `ALL_RUNNERS` export.
3. Add a CI job to `.github/workflows/benchmark-weekly.yml` that runs your tool against both corpora in parallel with the existing four. Use `continue-on-error: true` if the tool is known to be flaky.
4. Open a PR. We'll review the configuration, run it manually once to verify, and merge. Once merged, your tool shows up on the leaderboard starting with the next Sunday run.

If your tool is commercial and can't be containerized, we can still include it — see the Snyk Code path in `launch/maintainer-emails.md` for the template.

## Disputing a ground-truth entry

The ground-truth catalogs at `packages/vantage-bench/src/ground-truth/*.json` are the spine of the benchmark. Every entry should be defensible against a security engineer's review. If you think an entry is wrong — wrong file, wrong line, wrong type, or should not count as a vulnerability — please open an issue before opening a PR. We'll discuss in public before anyone edits the file.

## Reporting a security issue in VANTAGE itself

Please email `security@jourdanlabs.ai` rather than filing publicly. We treat every such report as a 72-hour response SLA until we have a coordinated-disclosure policy formally set up.

## Code style

- TypeScript with strict mode on for new files (`tsconfig.strict.json` in-progress).
- No semicolons? Semicolons? — whatever the surrounding file uses. We'll set up `prettier` in a follow-up.
- Comments explain **why** the code is the way it is, not what it does. The existing NEBULA and fix-template files are a reasonable model.

## How we handle PRs

- Cosmetic / small PRs (typos, docs, tests): merged on sight if they're correct.
- Detection / catalog PRs (sources, sinks, sanitizers, templates): reviewed within 48 hours, merged within 96 hours absent objections.
- Architectural PRs (new engine stage, new language frontend, scoring-rule changes): require an ADR-style proposal first. Open an issue, we'll discuss. Don't write the implementation before the design is agreed.

Thanks for showing up.

# SCA parsers (parse only)

Directory walk + four manifest/lock parsers for npm and PyPI pins.

**Matching is not built.** No OSV, CVE lookup, scoring, or F1.
Not wired into `src/engines/index.ts` `runPipeline` / `EngineFilter`.

Emits `ParsedDep` rows (`ecosystem`, `name`, `version`, `sourceFile`, `sourceKind`).
When a loose manifest and a lock both name the same package, the lock version wins.

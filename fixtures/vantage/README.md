# VANTAGE 2.0 Benchmark Fixtures

Deterministic fixture corpus for `mirrorverse vantage-benchmark fixtures/vantage`.

Each child directory is a small project designed to test one behavior:

- `clean-node`: no false positives on a healthy TypeScript package.
- `package-hygiene`: missing package basics.
- `dependency-hygiene`: broad dependency versions and duplicated dependency sections.
- `runtime-danger`: runtime child process, dynamic execution, env access, and destructive filesystem calls.
- `test-harness-containment`: dangerous APIs inside tests should be downgraded.
- `architecture-shape`: circular dependency and long function detection.
- `benchmark-intent-zone`: exploit strings in benchmark comments should not become runtime findings.
- `same-a` and `same-b`: duplicate family detection across normalized package names.

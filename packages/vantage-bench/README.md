# @jourdanlabs/vantage-bench

The open benchmark harness for static analysis tools.

Runs any tool against [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) and [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) and scores it against a verified ground-truth vulnerability catalog.

**Results published at [benchmark.vantage.dev](https://benchmark.vantage.dev)**

---

## Quick start

```bash
# Install
npm install -g @jourdanlabs/vantage-bench

# Clone corpora and run VANTAGE
vantage-bench run --clone

# Run a specific tool
vantage-bench run --tool Semgrep --clone

# Run against a specific corpus only
vantage-bench run --corpus nodegoat

# Output to a specific file
vantage-bench run --output my-results.json
```

## Current rankings

| Tool | NodeGoat F1 | Juice Shop F1 | Aggregate F1 | Runtime |
|------|------------|---------------|--------------|---------|
| VANTAGE 1.0.0 | **100%** | **85.7%** | **92.9%** | 63 ms |
| Semgrep 1.159.0 | 21.1% | 7.1% | 12.8% | 9.1 s |
| SonarQube 26.4.0 | 0% | 5.8% | 2.9% | 19 s |

---

## Ground truth

The vulnerability catalogs are in `src/ground-truth/` and licensed **CC-BY-4.0**.

To add a new vulnerability to the catalog: open a PR with evidence (CVE, OWASP Challenge description, or code walkthrough). The catalog maintainers will review and merge.

## Adding a tool

1. Create `src/runners/<toolname>.ts` implementing the `Runner` interface:

```typescript
import { Runner, RunResult, normalizeType } from './base';

export class MyToolRunner implements Runner {
  name = 'MyTool';

  async run(targetPath: string): Promise<RunResult> {
    const start = Date.now();
    // run your tool, parse output...
    return {
      findings: [...],
      durationMs: Date.now() - start,
      toolVersion: '1.2.3',
    };
  }
}
```

2. Register it in `src/index.ts` `ALL_RUNNERS` array.
3. Open a PR with your runner and the output of `vantage-bench run --tool MyTool --clone` in the description.

## Reproducibility

Every published result includes the harness `commitSha`. To reproduce:

```bash
git clone https://github.com/jourdanlabs/vantage
git checkout <commitSha>
cd packages/vantage-bench
vantage-bench run --tool <name> --clone
```

## License

Harness: proprietary (Jourdan Labs). See the repo `LICENSE`.  
Ground truth catalogs: **CC-BY-4.0**  
OWASP NodeGoat: Apache-2.0 (upstream)  
OWASP Juice Shop: MIT (upstream)

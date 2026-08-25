// VANTAGE Benchmark Harness — Opengrep runner
// Smallest additive copy of semgrep.ts. Tool identity is Opengrep, not Semgrep.

import { execSync } from 'child_process';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { Runner, RunResult, Finding, normalizeType, toCorpusRelativePosix } from './base';

/** Default ruleset — pack-matched to the Semgrep matrix */
const DEFAULT_RULESETS = 'p/owasp-top-ten p/nodejs p/javascript';

export class OpengrepRunner implements Runner {
  name = 'Opengrep';
  private rulesets: string;

  constructor(rulesets = DEFAULT_RULESETS) {
    this.rulesets = rulesets;
  }

  async run(targetPath: string): Promise<RunResult> {
    const outFile = path.join(os.tmpdir(), `opengrep-bench-${Date.now()}.json`);
    const start = Date.now();
    let toolVersion = 'unknown';

    try {
      let bin = (process.env.OPENGREP_BIN || '').trim();
      if (!bin) {
        try { bin = execSync('which opengrep', { encoding: 'utf8' }).trim(); } catch {}
      }
      if (!bin) return { findings: [], durationMs: 0, toolVersion, error: 'opengrep not found' };

      try {
        const raw = execSync(`"${bin}" --version`, { encoding: 'utf8' }).trim();
        const lines = raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        const versionLike = lines.filter((l) => /\d+\.\d+/.test(l));
        toolVersion = (versionLike.pop() || lines.pop() || raw).replace(/^opengrep\s+/i, '');
      } catch {}

      const configFlags = this.rulesets.split(' ').map(r => `--config ${r}`).join(' ');
      execSync(
        `${bin} ${configFlags} "${targetPath}" --json -o "${outFile}" --no-autofix`,
        { stdio: 'pipe', timeout: 300_000 }
      );

      const durationMs = Date.now() - start;

      if (!fs.existsSync(outFile)) return { findings: [], durationMs, toolVersion };

      const raw = JSON.parse(fs.readFileSync(outFile, 'utf8'));
      const results = raw.results ?? [];

      const findings: Finding[] = results.map((r: any) => {
        const rawType = r.check_id ?? r.rule_id ?? '';
        const sev = (r.extra?.severity ?? r.severity ?? 'LOW').toUpperCase();
        return {
          file: toCorpusRelativePosix(targetPath, r.path ?? ''),
          line: r.start?.line ?? 0,
          type: normalizeType(rawType),
          severity: mapOpengrepSeverity(sev),
          description: r.extra?.message ?? r.message ?? rawType,
          rawType,
        };
      });

      return { findings, durationMs, toolVersion };
    } catch (err: any) {
      return { findings: [], durationMs: Date.now() - start, toolVersion, error: err.message };
    } finally {
      try { if (fs.existsSync(outFile)) fs.unlinkSync(outFile); } catch {}
    }
  }
}

function mapOpengrepSeverity(sev: string): Finding['severity'] {
  if (sev === 'ERROR' || sev === 'CRITICAL') return 'CRITICAL';
  if (sev === 'WARNING' || sev === 'HIGH') return 'HIGH';
  if (sev === 'INFO' || sev === 'MEDIUM' || sev === 'MED') return 'MED';
  return 'LOW';
}

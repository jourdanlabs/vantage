// VANTAGE Benchmark Harness — VANTAGE runner

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Runner, RunResult, Finding, normalizeType, toCorpusRelativePosix } from './base';

export class VantageRunner implements Runner {
  name = 'VANTAGE';

  async run(targetPath: string): Promise<RunResult> {
    const reportFile = path.join(os.tmpdir(), `vantage-bench-${Date.now()}.json`);
    const start = Date.now();
    let toolVersion = 'unknown';

    try {
      // Find vantage binary
      let bin = '';
      try { bin = execSync('which vantage', { encoding: 'utf8' }).trim(); } catch {}
      if (!bin) {
        const local = path.join(__dirname, '../../../../bin/vantage.js');
        if (fs.existsSync(local)) bin = `node ${local}`;
      }
      if (!bin) return { findings: [], durationMs: 0, toolVersion, error: 'vantage not found' };

      // Get version
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../../package.json'), 'utf8'));
        toolVersion = pkg.version ?? 'unknown';
      } catch {}

      execSync(`${bin} "${targetPath}" --output "${reportFile}"`, {
        stdio: 'pipe',
        timeout: 300_000,
      });

      if (!fs.existsSync(reportFile)) {
        return { findings: [], durationMs: Date.now() - start, toolVersion, error: 'no report generated' };
      }

      const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
      const durationMs = report.aurora?.totalMs ?? (Date.now() - start);

      const findings: Finding[] = (report.pulsar?.adversarialFindings ?? []).map((f: any) => ({
        file: toCorpusRelativePosix(targetPath, f.file ?? ''),
        line: f.line ?? 0,
        type: normalizeType(f.type ?? ''),
        severity: f.severity as Finding['severity'],
        description: f.description,
        rawType: f.type,
      }));

      return { findings, durationMs, toolVersion };
    } catch (err: any) {
      return {
        findings: [],
        durationMs: Date.now() - start,
        toolVersion,
        error: err.message,
      };
    } finally {
      try { if (fs.existsSync(reportFile)) fs.unlinkSync(reportFile); } catch {}
    }
  }
}

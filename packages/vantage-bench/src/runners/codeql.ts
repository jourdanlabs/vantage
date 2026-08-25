// VANTAGE Benchmark Harness — CodeQL runner
// Requires: codeql CLI on PATH, JavaScript query suite available.

import { execSync } from 'child_process';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { Runner, RunResult, Finding, normalizeType, toCorpusRelativePosix } from './base';

export class CodeQLRunner implements Runner {
  name = 'CodeQL';

  async run(targetPath: string): Promise<RunResult> {
    const tmpDir = path.join(os.tmpdir(), `codeql-bench-${Date.now()}`);
    const dbDir = path.join(tmpDir, 'db');
    const resultsDir = path.join(tmpDir, 'results');
    const start = Date.now();
    let toolVersion = 'unknown';

    try {
      let bin = '';
      try { bin = execSync('which codeql', { encoding: 'utf8' }).trim(); } catch {}
      if (!bin) return { findings: [], durationMs: 0, toolVersion, error: 'codeql not found' };

      try {
        toolVersion = execSync('codeql --version', { encoding: 'utf8' }).trim()
          .match(/CodeQL command-line toolchain release ([\d.]+)/)?.[1] ?? 'unknown';
      } catch {}

      fs.mkdirSync(dbDir, { recursive: true });
      fs.mkdirSync(resultsDir, { recursive: true });

      // Create database
      execSync(
        `${bin} database create "${dbDir}" --language=javascript-typescript --source-root="${targetPath}" --overwrite`,
        { stdio: 'pipe', timeout: 600_000, cwd: targetPath }
      );

      // Run security queries
      const sarifFile = path.join(resultsDir, 'results.sarif');
      execSync(
        `${bin} database analyze "${dbDir}" javascript-security-extended.qls --format=sarifv2.1.0 --output="${sarifFile}"`,
        { stdio: 'pipe', timeout: 600_000 }
      );

      const durationMs = Date.now() - start;

      if (!fs.existsSync(sarifFile)) {
        return { findings: [], durationMs, toolVersion, error: 'no SARIF output' };
      }

      const sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
      const findings: Finding[] = parseSarif(sarif, targetPath);

      return { findings, durationMs, toolVersion };
    } catch (err: any) {
      return { findings: [], durationMs: Date.now() - start, toolVersion, error: err.message };
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  }
}

function parseSarif(sarif: any, targetPath: string): Finding[] {
  const findings: Finding[] = [];
  for (const run of sarif.runs ?? []) {
    const rules: Record<string, any> = {};
    for (const rule of run.tool?.driver?.rules ?? []) {
      rules[rule.id] = rule;
    }
    for (const result of run.results ?? []) {
      const ruleId = result.ruleId ?? '';
      const rule = rules[ruleId] ?? {};
      const loc = result.locations?.[0]?.physicalLocation;
      const filePath = loc?.artifactLocation?.uri ?? '';
      const line = loc?.region?.startLine ?? 0;
      const severity = (result.level ?? rule.defaultConfiguration?.level ?? 'warning').toLowerCase();
      findings.push({
        file: toCorpusRelativePosix(targetPath, filePath),
        line,
        type: normalizeType(ruleId),
        severity: mapSarifLevel(severity),
        description: result.message?.text ?? rule.name ?? ruleId,
        rawType: ruleId,
      });
    }
  }
  return findings;
}

function mapSarifLevel(level: string): Finding['severity'] {
  if (level === 'error') return 'HIGH';
  if (level === 'warning') return 'MED';
  return 'LOW';
}

// VANTAGE Benchmark Harness — SonarQube runner
// Requires a running SonarQube server (SONAR_HOST_URL, default http://localhost:9000)
// and sonar-scanner on PATH.
//
// Wave 1: after GET /api/issues/search?types=VULNERABILITY, fetch CWE from
// /api/rules/show (securityStandards.cwe / tags). Type from CWE map ONLY
// (benchmarks/sonar-issues-to-sarif.js — one source of truth). Fail closed
// if no CWE or unmatched CWE. Do NOT type from message text.
// Emits SARIF 2.1.0 (uri = corpus-relative POSIX, region.startLine,
// rule.properties.tags includes `CWE-NNN: …`, properties.cwe: ["CWE-NNN"]).

import { execSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import { Runner, RunResult, Finding } from './base';

const DEFAULT_HOST = process.env.SONAR_HOST_URL || 'http://localhost:9000';
const DEFAULT_TOKEN = process.env.SONAR_TOKEN ?? 'admin:admin';

function resolveSonarSarifWriter(): string {
  const candidates = [
    path.resolve(__dirname, '..', '..', '..', '..', 'benchmarks', 'sonar-issues-to-sarif.js'),
    path.resolve(__dirname, '..', '..', '..', '..', '..', 'benchmarks', 'sonar-issues-to-sarif.js'),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  throw new Error('benchmarks/sonar-issues-to-sarif.js not found (Wave 1 Sonar adapter)');
}

// One source of truth for CWE map + SARIF 2.1.0 emit.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const sonarSarif = require(resolveSonarSarifWriter());

export class SonarQubeRunner implements Runner {
  name = 'SonarQube';
  private host: string;
  private token: string;

  constructor(host = DEFAULT_HOST, token = DEFAULT_TOKEN) {
    this.host = host;
    this.token = token;
  }

  async run(targetPath: string): Promise<RunResult> {
    const start = Date.now();
    let toolVersion = 'unknown';

    try {
      // Check sonar-scanner is available
      let scannerBin = '';
      try { scannerBin = execSync('which sonar-scanner', { encoding: 'utf8' }).trim(); } catch {}
      if (!scannerBin) return { findings: [], durationMs: 0, toolVersion, error: 'sonar-scanner not found' };

      // Project key based on directory name
      const projectKey = `bench-${path.basename(targetPath)}-${Date.now()}`;

      // Run scan
      const authFlag = this.token.includes(':')
        ? `-Dsonar.login=${this.token.split(':')[0]} -Dsonar.password=${this.token.split(':')[1]}`
        : `-Dsonar.token=${this.token}`;

      execSync(
        `cd "${targetPath}" && ${scannerBin} ` +
        `-Dsonar.projectKey=${projectKey} ` +
        `-Dsonar.sources=. ` +
        `-Dsonar.host.url=${this.host} ` +
        `${authFlag} ` +
        `-Dsonar.exclusions=**/node_modules/**,**/dist/**,**/*.min.js`,
        { stdio: 'pipe', timeout: 600_000 }
      );

      // Wait for analysis to complete (poll CE task)
      await this.waitForAnalysis(projectKey);

      // Fetch issues — VULNERABILITY only (Wave 1 contract)
      const issues = await this.fetchIssues(projectKey);
      const durationMs = Date.now() - start;

      try { toolVersion = await this.fetchVersion(); } catch {}

      const rulesByKey: Record<string, unknown> = {};
      const ruleKeys = Array.from(new Set(
        issues.map((issue: any) => issue.rule || issue.ruleKey).filter(Boolean)
      ));
      for (const key of ruleKeys) {
        try {
          rulesByKey[key] = await this.fetchRule(key);
        } catch {
          // Fail closed: missing rule show → no CWE → empty type
          rulesByKey[key] = {};
        }
      }

      const sarif = sonarSarif.issuesToSarif({
        issues,
        rulesByKey,
        projectKey,
        targetPath,
        toolVersion,
      });

      const sarifOut = resolveSarifOut(targetPath);
      if (sarifOut) {
        sonarSarif.writeSarifFile(sarif, sarifOut);
      }

      // Findings come from the SARIF so typing cannot drift from the writer.
      const findings: Finding[] = sonarSarif.sarifToFindings(sarif, targetPath);

      // Clean up the project after analysis
      try { await this.deleteProject(projectKey); } catch {}

      return { findings, durationMs, toolVersion };
    } catch (err: any) {
      return { findings: [], durationMs: Date.now() - start, toolVersion, error: err.message };
    }
  }

  private fetchVersion(): Promise<string> {
    return this.apiGet('/api/system/status').then((d: any) => d.version ?? 'unknown');
  }

  private fetchRule(ruleKey: string): Promise<unknown> {
    return this.apiGet(`/api/rules/show?key=${encodeURIComponent(ruleKey)}`);
  }

  private async waitForAnalysis(projectKey: string, maxWaitMs = 120_000): Promise<void> {
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      const data: any = await this.apiGet(`/api/ce/component?component=${projectKey}`).catch(() => null);
      const status = data?.queue?.[0]?.status ?? data?.current?.status;
      if (!status || status === 'SUCCESS') return;
      if (status === 'FAILED' || status === 'CANCELED') throw new Error(`SonarQube CE task ${status}`);
      await new Promise(r => setTimeout(r, 2000));
    }
    throw new Error('SonarQube analysis timed out');
  }

  private async fetchIssues(projectKey: string): Promise<any[]> {
    const all: any[] = [];
    let page = 1;
    while (true) {
      const data: any = await this.apiGet(
        `/api/issues/search?componentKeys=${projectKey}&types=VULNERABILITY&ps=500&p=${page}`
      );
      all.push(...(data.issues ?? []));
      if (all.length >= (data.total ?? 0)) break;
      page++;
    }
    return all;
  }

  private deleteProject(projectKey: string): Promise<void> {
    return this.apiPost(`/api/projects/delete?project=${projectKey}`).then(() => undefined);
  }

  private apiGet(endpoint: string): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const url = new URL(endpoint, this.host);
      const lib = url.protocol === 'https:' ? https : http;
      const [user, pass] = this.token.includes(':')
        ? this.token.split(':')
        : [this.token, ''];
      const auth = Buffer.from(`${user}:${pass}`).toString('base64');
      const req = lib.get(url.toString(), {
        headers: { Authorization: `Basic ${auth}` }
      }, res => {
        let body = '';
        res.on('data', d => body += d);
        res.on('end', () => {
          try { resolve(JSON.parse(body)); } catch { resolve({}); }
        });
      });
      req.on('error', reject);
    });
  }

  private apiPost(endpoint: string): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const url = new URL(endpoint, this.host);
      const lib = url.protocol === 'https:' ? https : http;
      const [user, pass] = this.token.includes(':') ? this.token.split(':') : [this.token, ''];
      const auth = Buffer.from(`${user}:${pass}`).toString('base64');
      const req = lib.request(url.toString(), { method: 'POST', headers: { Authorization: `Basic ${auth}` } }, res => {
        let body = '';
        res.on('data', d => body += d);
        res.on('end', () => resolve(body));
      });
      req.on('error', reject);
      req.end();
    });
  }
}

function resolveSarifOut(targetPath: string): string | null {
  if (process.env.SONAR_SARIF_OUT) return path.resolve(process.env.SONAR_SARIF_OUT);
  if (process.env.SONAR_SARIF_DIR) {
    const stem = path.basename(targetPath).replace(/[^\w.-]+/g, '_');
    return path.resolve(process.env.SONAR_SARIF_DIR, `sonarqube_${stem}.sarif`);
  }
  return null;
}

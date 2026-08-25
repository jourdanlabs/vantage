// VANTAGE Benchmark Harness — main orchestrator

import { Runner } from './runners/base';
import { VantageRunner } from './runners/vantage';
import { SemgrepRunner } from './runners/semgrep';
import { SonarQubeRunner } from './runners/sonarqube';
import { CodeQLRunner } from './runners/codeql';
import { OpengrepRunner } from './runners/opengrep';
import { getCorpora, ensureCorpora, CORPORA } from './corpus';
import { scoreFindings, ToolScore, BenchmarkResult, aggregateF1, medianDuration } from './scoring';
import { renderMarkdownReport, renderJsonResults, LeaderboardData } from './report';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

export { Runner, VantageRunner, SemgrepRunner, SonarQubeRunner, CodeQLRunner, OpengrepRunner };
export { CORPORA, getCorpora, ensureCorpora };
export { scoreFindings, renderMarkdownReport, renderJsonResults };
export type { BenchmarkResult, ToolScore, LeaderboardData };

/** All registered runners */
export const ALL_RUNNERS: Runner[] = [
  new VantageRunner(),
  new SemgrepRunner(),
  new SonarQubeRunner(),
  new CodeQLRunner(),
  new OpengrepRunner(),
];

/** Get current git commit SHA */
function getCommitSha(): string {
  try {
    return execSync('git rev-parse HEAD', { encoding: 'utf8', stdio: 'pipe' }).trim().slice(0, 12);
  } catch {
    return 'unknown';
  }
}

export interface RunOptions {
  /** Tool names to run (default: all available) */
  tools?: string[];
  /** Corpus IDs to run (default: all present locally) */
  corpora?: string[];
  /** Whether to clone missing corpora first */
  ensureCorpora?: boolean;
  /** Callback for progress reporting */
  onProgress?: (msg: string) => void;
}

/** Run the full benchmark suite and return results */
export async function runBenchmark(opts: RunOptions = {}): Promise<BenchmarkResult[]> {
  const log = opts.onProgress ?? console.log;

  // Optionally clone missing corpora
  if (opts.ensureCorpora) {
    log('Ensuring corpora are present...');
    ensureCorpora();
  }

  const corpusList = getCorpora(opts.corpora);
  if (corpusList.length === 0) {
    throw new Error('No corpora available. Run with --clone or clone them manually first.');
  }

  const runners = opts.tools
    ? ALL_RUNNERS.filter(r => opts.tools!.map(t => t.toLowerCase()).includes(r.name.toLowerCase()))
    : ALL_RUNNERS;

  const commitSha = getCommitSha();
  const results: BenchmarkResult[] = [];

  for (const runner of runners) {
    log(`\nRunning ${runner.name}...`);
    const scores: ToolScore[] = [];
    let resolvedVersion = 'unknown';

    for (const corpus of corpusList) {
      log(`  → ${corpus.label}`);
      const runResult = await runner.run(corpus.analysisPath);
      resolvedVersion = runResult.toolVersion;

      if (runResult.error) {
        log(`    Error: ${runResult.error}`);
      }

      const match = scoreFindings(runResult.findings, corpus.groundTruth, corpus.analysisPath);

      scores.push({
        tool: runner.name,
        toolVersion: runResult.toolVersion,
        corpus: corpus.id,
        corpusLabel: corpus.label,
        tp: match.tp.length,
        fp: match.fp.length,
        fn: match.fn.length,
        precision: match.precision,
        recall: match.recall,
        f1: match.f1,
        durationMs: runResult.durationMs,
        tpDetails: match.tp.map(t => ({ file: t.finding.file, line: t.finding.line, type: t.finding.type })),
        fpDetails: match.fp.map(f => ({ file: f.file, line: f.line, type: f.type, description: f.description })),
        fnDetails: match.fn.map(e => ({ id: e.id, file: e.file, line: e.line, type: e.type, description: e.description })),
      });

      log(`    P=${pct(match.precision)} R=${pct(match.recall)} F1=${pct(match.f1)} (${runResult.durationMs.toFixed(0)}ms)`);
    }

    results.push({
      tool: runner.name,
      toolVersion: resolvedVersion,
      runDate: new Date().toISOString(),
      commitSha,
      scores,
      aggregateF1: aggregateF1(scores),
      medianDurationMs: medianDuration(scores),
    });
  }

  return results;
}

function pct(n: number | null): string {
  if (n === null) return 'N/A';
  return `${(n * 100).toFixed(1)}%`;
}

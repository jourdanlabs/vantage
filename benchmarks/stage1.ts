/**
 * VANTAGE Stage 1 Benchmark — Performance & Scaling
 *
 * Runs the full METEOR→NOVA→ECLIPSE→PULSAR→AURORA pipeline against
 * five public repo corpora (pinned commits). Three runs per corpus,
 * median reported. Flags >20% variance from median as stability concerns.
 *
 * Usage:
 *   cd /Users/sokpyeon/projects/vantage
 *   npx ts-node benchmarks/stage1.ts
 *
 * Prerequisites:
 *   - Corpus repos cloned to /tmp/vantage-bench/ (see corpus.json)
 *   - VANTAGE API running on port 7474 (checked automatically)
 */

import * as path from 'path';
import * as fs from 'fs';
import * as http from 'http';

// Direct engine imports for per-engine timing (avoids HTTP round-trip noise)
import { runMETEOR } from '../src/engines/meteor';
import { runNOVA } from '../src/engines/nova';
import { runECLIPSE } from '../src/engines/eclipse';
import { runPULSAR } from '../src/engines/pulsar';
import { runAURORA } from '../src/engines/aurora';
import { MeteorOutput, NovaOutput, EclipseOutput, PulsarOutput } from '../src/types';

const CORPUS = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'corpus.json'), 'utf-8')
).corpora as Array<{
  id: string;
  label: string;
  localPath: string;
  expectedLOC: string;
  sha: string;
}>;

const RUNS_PER_CORPUS = 3;
const TIMEOUT_MS = 10 * 60 * 1000; // 10 min per run

// ── Utilities ────────────────────────────────────────────────────────────────

function rssBytes(): number {
  return process.memoryUsage().rss;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

function pctVariance(values: number[], med: number): number {
  if (med === 0) return 0;
  const maxDev = Math.max(...values.map(v => Math.abs(v - med)));
  return (maxDev / med) * 100;
}

function checkApiHealth(): Promise<boolean> {
  return new Promise(resolve => {
    http.get('http://localhost:7474/vantage/health', (res) => {
      resolve(res.statusCode === 200);
    }).on('error', () => resolve(false));
  });
}

function countSourceFiles(dir: string): { files: number; loc: number } {
  const EXTS = new Set([
    '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
    '.py', '.pyw', '.c', '.h', '.cpp', '.cc', '.cxx', '.hpp',
    '.go', '.rs', '.rb', '.java', '.kt', '.cs', '.php', '.swift',
    '.sh', '.bash', '.scala', '.sc'
  ]);
  let files = 0;
  let loc = 0;

  function walk(d: string) {
    const entries = fs.readdirSync(d, { withFileTypes: true });
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git' || e.name === '__pycache__') continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (EXTS.has(path.extname(e.name).toLowerCase())) {
        files++;
        try {
          const content = fs.readFileSync(full, 'utf-8');
          loc += content.split('\n').length;
        } catch {}
      }
    }
  }

  walk(dir);
  return { files, loc };
}

// ── Per-run benchmark ─────────────────────────────────────────────────────────

interface RunResult {
  runIndex: number;
  totalMs: number;
  engineMs: {
    METEOR: number;
    NOVA: number;
    ECLIPSE: number;
    PULSAR: number;
    AURORA: number;
  };
  peakRssBytes: number;
  baselineRssBytes: number;
  auroraScore: number;
  auroraVerdict: string;
  auroraBreakdown: {
    complexityScore: number;
    dependencyScore: number;
    riskScore: number;
    adversarialScore: number;
  };
  fileCount: number;
  locCount: number;
  functionCount: number;
  issuesBySeveity: { HIGH: number; MED: number; LOW: number };
  circularDeps: number;
  godModules: number;
  unsupportedFiles: { count: number; extensions: string[] };
  error?: string;
  timedOut?: boolean;
}

async function runOnce(targetPath: string, runIndex: number): Promise<RunResult> {
  const baselineRss = rssBytes();
  let peakRss = baselineRss;

  const sampleRss = () => {
    const cur = rssBytes();
    if (cur > peakRss) peakRss = cur;
    return cur;
  };

  const t0 = performance.now();

  const emptyBreakdown = { complexityScore: 0, dependencyScore: 0, riskScore: 0, adversarialScore: 0 };
  const emptyUnsupported = { count: 0, extensions: [] };

  // ── METEOR ──
  const tMeteorStart = performance.now();
  let meteor: MeteorOutput;
  try {
    meteor = await runMETEOR(targetPath);
  } catch (e: any) {
    return {
      runIndex, totalMs: performance.now() - t0,
      engineMs: { METEOR: 0, NOVA: 0, ECLIPSE: 0, PULSAR: 0, AURORA: 0 },
      peakRssBytes: sampleRss(), baselineRssBytes: baselineRss,
      auroraScore: 0, auroraVerdict: 'ERROR', auroraBreakdown: emptyBreakdown,
      fileCount: 0, locCount: 0, functionCount: 0,
      issuesBySeveity: { HIGH: 0, MED: 0, LOW: 0 },
      circularDeps: 0, godModules: 0, unsupportedFiles: emptyUnsupported,
      error: `METEOR: ${e.message}`
    };
  }
  const tMeteor = performance.now() - tMeteorStart;
  sampleRss();

  const unsupportedFiles = {
    count: meteor.unsupportedFiles.count,
    extensions: meteor.unsupportedFiles.extensions,
  };

  // ── NOVA ──
  const tNovaStart = performance.now();
  let nova: NovaOutput;
  try {
    nova = await runNOVA(meteor);
  } catch (e: any) {
    return {
      runIndex, totalMs: performance.now() - t0,
      engineMs: { METEOR: tMeteor, NOVA: 0, ECLIPSE: 0, PULSAR: 0, AURORA: 0 },
      peakRssBytes: sampleRss(), baselineRssBytes: baselineRss,
      auroraScore: 0, auroraVerdict: 'ERROR', auroraBreakdown: emptyBreakdown,
      fileCount: meteor.files.length,
      locCount: meteor.metrics.linesOfCode,
      functionCount: meteor.functions.length,
      issuesBySeveity: { HIGH: 0, MED: 0, LOW: 0 },
      circularDeps: 0, godModules: 0, unsupportedFiles,
      error: `NOVA: ${e.message}`
    };
  }
  const tNova = performance.now() - tNovaStart;
  sampleRss();

  // ── ECLIPSE ──
  const tEclipseStart = performance.now();
  let eclipse: EclipseOutput;
  try {
    eclipse = await runECLIPSE(meteor, nova);
  } catch (e: any) {
    return {
      runIndex, totalMs: performance.now() - t0,
      engineMs: { METEOR: tMeteor, NOVA: tNova, ECLIPSE: 0, PULSAR: 0, AURORA: 0 },
      peakRssBytes: sampleRss(), baselineRssBytes: baselineRss,
      auroraScore: 0, auroraVerdict: 'ERROR', auroraBreakdown: emptyBreakdown,
      fileCount: meteor.files.length,
      locCount: meteor.metrics.linesOfCode,
      functionCount: meteor.functions.length,
      issuesBySeveity: { HIGH: 0, MED: 0, LOW: 0 },
      circularDeps: nova.circularDeps.length,
      godModules: nova.godModules.length, unsupportedFiles,
      error: `ECLIPSE: ${e.message}`
    };
  }
  const tEclipse = performance.now() - tEclipseStart;
  sampleRss();

  // ── PULSAR ──
  const tPulsarStart = performance.now();
  let pulsar: PulsarOutput;
  try {
    pulsar = await runPULSAR(meteor, eclipse);
  } catch (e: any) {
    return {
      runIndex, totalMs: performance.now() - t0,
      engineMs: { METEOR: tMeteor, NOVA: tNova, ECLIPSE: tEclipse, PULSAR: 0, AURORA: 0 },
      peakRssBytes: sampleRss(), baselineRssBytes: baselineRss,
      auroraScore: 0, auroraVerdict: 'ERROR', auroraBreakdown: emptyBreakdown,
      fileCount: meteor.files.length,
      locCount: meteor.metrics.linesOfCode,
      functionCount: meteor.functions.length,
      issuesBySeveity: { HIGH: 0, MED: 0, LOW: 0 },
      circularDeps: nova.circularDeps.length,
      godModules: nova.godModules.length, unsupportedFiles,
      error: `PULSAR: ${e.message}`
    };
  }
  const tPulsar = performance.now() - tPulsarStart;
  sampleRss();

  // ── AURORA ──
  const tAuroraStart = performance.now();
  let aurora;
  try {
    aurora = await runAURORA(meteor, nova, eclipse, pulsar);
  } catch (e: any) {
    return {
      runIndex, totalMs: performance.now() - t0,
      engineMs: { METEOR: tMeteor, NOVA: tNova, ECLIPSE: tEclipse, PULSAR: tPulsar, AURORA: 0 },
      peakRssBytes: sampleRss(), baselineRssBytes: baselineRss,
      auroraScore: 0, auroraVerdict: 'ERROR', auroraBreakdown: emptyBreakdown,
      fileCount: meteor.files.length,
      locCount: meteor.metrics.linesOfCode,
      functionCount: meteor.functions.length,
      issuesBySeveity: { HIGH: 0, MED: 0, LOW: 0 },
      circularDeps: nova.circularDeps.length,
      godModules: nova.godModules.length, unsupportedFiles,
      error: `AURORA: ${e.message}`
    };
  }
  const tAurora = performance.now() - tAuroraStart;
  sampleRss();

  const totalMs = performance.now() - t0;

  // Issue counts
  const findings = aurora.topIssues;
  const issuesBySeveity = {
    HIGH: findings.filter((i: any) => i.severity === 'HIGH').length,
    MED: findings.filter((i: any) => i.severity === 'MED').length,
    LOW: findings.filter((i: any) => i.severity === 'LOW').length,
  };

  return {
    runIndex,
    totalMs,
    engineMs: {
      METEOR: tMeteor,
      NOVA: tNova,
      ECLIPSE: tEclipse,
      PULSAR: tPulsar,
      AURORA: tAurora,
    },
    peakRssBytes: peakRss,
    baselineRssBytes: baselineRss,
    auroraScore: aurora.score,
    auroraVerdict: aurora.verdict,
    auroraBreakdown: aurora.breakdown,
    fileCount: meteor.files.length,
    locCount: meteor.metrics.linesOfCode,
    functionCount: meteor.functions.length,
    issuesBySeveity,
    circularDeps: nova.circularDeps.length,
    godModules: nova.godModules.length,
    unsupportedFiles,
  };
}

// ── Corpus benchmark ──────────────────────────────────────────────────────────

interface CorpusResult {
  id: string;
  label: string;
  sha: string;
  expectedLOC: string;
  actualFiles: number;
  actualLOC: number;
  runs: RunResult[];
  medianTotalMs: number;
  medianEngineMs: Record<string, number>;
  medianPeakRssMB: number;
  variancePct: number;
  stabilityFlag: boolean;
  summary: string;
  error?: string;
}

async function benchmarkCorpus(
  corpus: typeof CORPUS[0]
): Promise<CorpusResult> {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`CORPUS: ${corpus.label}`);
  console.log(`Path:   ${corpus.localPath}`);
  console.log(`${'─'.repeat(60)}`);

  if (!fs.existsSync(corpus.localPath)) {
    console.log(`  ✗ Path does not exist — skipping`);
    return {
      id: corpus.id, label: corpus.label, sha: corpus.sha,
      expectedLOC: corpus.expectedLOC,
      actualFiles: 0, actualLOC: 0, runs: [],
      medianTotalMs: 0, medianEngineMs: {},
      medianPeakRssMB: 0, variancePct: 0,
      stabilityFlag: false,
      summary: 'SKIPPED — path not found',
      error: 'corpus path not found'
    };
  }

  // Count actual files/LOC
  console.log(`  Counting files...`);
  const { files: actualFiles, loc: actualLOC } = countSourceFiles(corpus.localPath);
  console.log(`  Actual: ${actualFiles} files, ${actualLOC.toLocaleString()} LOC`);

  const runs: RunResult[] = [];

  for (let i = 0; i < RUNS_PER_CORPUS; i++) {
    console.log(`\n  Run ${i + 1}/${RUNS_PER_CORPUS}...`);

    // Wrap in timeout
    const runPromise = runOnce(corpus.localPath, i + 1);
    const timeoutPromise = new Promise<RunResult>((_, reject) =>
      setTimeout(() => reject(new Error(`TIMEOUT after ${TIMEOUT_MS / 1000}s`)), TIMEOUT_MS)
    );

    let result: RunResult;
    try {
      result = await Promise.race([runPromise, timeoutPromise]);
    } catch (e: any) {
      console.log(`  ✗ Run ${i + 1} failed: ${e.message}`);
      result = {
        runIndex: i + 1,
        totalMs: TIMEOUT_MS,
        engineMs: { METEOR: 0, NOVA: 0, ECLIPSE: 0, PULSAR: 0, AURORA: 0 },
        peakRssBytes: rssBytes(),
        baselineRssBytes: rssBytes(),
        auroraScore: 0, auroraVerdict: 'ERROR',
        fileCount: 0, locCount: 0, functionCount: 0,
        issuesBySeveity: { HIGH: 0, MED: 0, LOW: 0 },
        circularDeps: 0, godModules: 0,
        error: e.message,
        timedOut: e.message.includes('TIMEOUT'),
      };
    }

    if (result.error) {
      console.log(`  ✗ Error: ${result.error}`);
    } else {
      console.log(`  ✓ ${(result.totalMs / 1000).toFixed(2)}s | RSS +${((result.peakRssBytes - result.baselineRssBytes) / 1024 / 1024).toFixed(0)}MB | AURORA: ${result.auroraVerdict} (${(result.auroraScore * 100).toFixed(0)}%)`);
      console.log(`    METEOR ${(result.engineMs.METEOR / 1000).toFixed(2)}s  NOVA ${(result.engineMs.NOVA / 1000).toFixed(2)}s  ECLIPSE ${(result.engineMs.ECLIPSE / 1000).toFixed(2)}s  PULSAR ${(result.engineMs.PULSAR / 1000).toFixed(2)}s  AURORA ${(result.engineMs.AURORA / 1000).toFixed(2)}s`);
    }

    runs.push(result);

    // Allow GC between runs
    await new Promise(r => setTimeout(r, 500));
  }

  // Compute medians
  const successfulRuns = runs.filter(r => !r.error);
  const allRuns = runs;

  if (allRuns.length === 0) {
    return {
      id: corpus.id, label: corpus.label, sha: corpus.sha,
      expectedLOC: corpus.expectedLOC, actualFiles, actualLOC,
      runs, medianTotalMs: 0, medianEngineMs: {},
      medianPeakRssMB: 0, variancePct: 0, stabilityFlag: false,
      summary: 'ALL RUNS FAILED', error: 'no successful runs'
    };
  }

  const totalMsValues = allRuns.map(r => r.totalMs);
  const medianTotalMs = median(totalMsValues);
  const variancePct = pctVariance(totalMsValues, medianTotalMs);
  const stabilityFlag = variancePct > 20;

  const medianEngineMs: Record<string, number> = {};
  for (const engine of ['METEOR', 'NOVA', 'ECLIPSE', 'PULSAR', 'AURORA'] as const) {
    const vals = allRuns.map(r => r.engineMs[engine]);
    medianEngineMs[engine] = median(vals);
  }

  const medianPeakRssMB = median(allRuns.map(r => (r.peakRssBytes - r.baselineRssBytes) / 1024 / 1024));

  const representativeRun = successfulRuns[0] ?? allRuns[0];

  const summary = representativeRun.error
    ? `FAILED: ${representativeRun.error}`
    : `${representativeRun.auroraVerdict} (${(representativeRun.auroraScore * 100).toFixed(0)}%) | ${representativeRun.fileCount} files | ${representativeRun.locCount.toLocaleString()} LOC | ${representativeRun.functionCount} fns`;

  if (stabilityFlag) {
    console.log(`\n  ⚠ STABILITY FLAG: ${variancePct.toFixed(1)}% variance across runs (threshold: 20%)`);
  }

  return {
    id: corpus.id, label: corpus.label, sha: corpus.sha,
    expectedLOC: corpus.expectedLOC, actualFiles, actualLOC,
    runs, medianTotalMs, medianEngineMs, medianPeakRssMB,
    variancePct, stabilityFlag, summary,
  };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log('\nVANTAGE STAGE 1 BENCHMARK — Performance & Scaling');
  console.log('═'.repeat(60));
  console.log(`Timestamp: ${new Date().toISOString()}`);
  console.log(`Runs per corpus: ${RUNS_PER_CORPUS}`);
  console.log(`Timeout per run: ${TIMEOUT_MS / 1000}s`);

  // API health check
  const apiOk = await checkApiHealth();
  console.log(`\nVANTAGE API health check: ${apiOk ? '✓ ONLINE (port 7474)' : '✗ OFFLINE — benchmarks run direct (no HTTP overhead)'}`);

  const results: CorpusResult[] = [];

  for (const corpus of CORPUS) {
    const result = await benchmarkCorpus(corpus);
    results.push(result);
  }

  // Write results JSON
  const outPath = path.join(__dirname, 'results', 'stage1.json');
  fs.writeFileSync(outPath, JSON.stringify({ generatedAt: new Date().toISOString(), apiHealthy: apiOk, results }, null, 2));
  console.log(`\n\nResults written to: ${outPath}`);

  // Print summary table
  console.log('\n' + '═'.repeat(80));
  console.log('STAGE 1 SUMMARY');
  console.log('═'.repeat(80));
  console.log(`${'Corpus'.padEnd(30)} ${'Files'.padStart(6)} ${'LOC'.padStart(8)} ${'Time(s)'.padStart(8)} ${'RSS(MB)'.padStart(8)} ${'Verdict'.padStart(10)} ${'Var%'.padStart(6)}`);
  console.log('─'.repeat(80));
  for (const r of results) {
    const timeStr = r.medianTotalMs > 0 ? (r.medianTotalMs / 1000).toFixed(2) : 'FAIL';
    const rssStr = r.medianPeakRssMB > 0 ? r.medianPeakRssMB.toFixed(0) : '-';
    const verdict = r.runs.find(x => !x.error)?.auroraVerdict ?? (r.error ?? 'ERR');
    const varStr = r.variancePct.toFixed(1) + (r.stabilityFlag ? '⚠' : '');
    const locStr = r.actualLOC > 0 ? r.actualLOC.toLocaleString() : '-';
    console.log(
      `${r.id.padEnd(30)} ${String(r.actualFiles).padStart(6)} ${locStr.padStart(8)} ${timeStr.padStart(8)} ${rssStr.padStart(8)} ${verdict.padStart(10)} ${varStr.padStart(6)}`
    );
  }
  console.log('─'.repeat(80));
}

main().catch(e => {
  console.error('Fatal benchmark error:', e);
  process.exit(1);
});

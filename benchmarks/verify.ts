/**
 * VANTAGE Verification Run — Post-fix correctness check
 *
 * Tests three corpora after implementing Issues 1-3 fixes:
 *   1. expressjs/express — regression check (expect APPROVED ~0.959, no change)
 *   2. microsoft/vscode src/vs — large TS codebase (expect REJECTED, score 0.60–0.75)
 *   3. Synthetic C corpus — unsupported-language handling (10 .c files)
 *
 * Usage:
 *   cd /Users/sokpyeon/projects/vantage
 *   npx ts-node benchmarks/verify.ts
 */

import * as path from 'path';
import * as fs from 'fs';
import * as http from 'http';

import { runMETEOR } from '../src/engines/meteor';
import { runNOVA } from '../src/engines/nova';
import { runECLIPSE } from '../src/engines/eclipse';
import { runPULSAR } from '../src/engines/pulsar';
import { runAURORA } from '../src/engines/aurora';

const RUNS = 3;
const TIMEOUT_MS = 10 * 60 * 1000;

function rss(): number { return process.memoryUsage().rss; }
function median(v: number[]): number {
  const s = [...v].sort((a, b) => a - b);
  return s.length % 2 ? s[Math.floor(s.length / 2)] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
}

function checkApi(): Promise<boolean> {
  return new Promise(resolve => {
    http.get('http://localhost:7474/vantage/health', r => resolve(r.statusCode === 200))
      .on('error', () => resolve(false));
  });
}

// ── Single full pipeline run ──────────────────────────────────────────────────

async function runOnce(targetPath: string, runIdx: number) {
  const baseline = rss();
  let peak = baseline;
  const sample = () => { const c = rss(); if (c > peak) peak = c; };

  const t0 = performance.now();

  const tMs = performance.now();
  const meteor = await runMETEOR(targetPath);
  const meteorMs = performance.now() - tMs;
  sample();

  const tNs = performance.now();
  const nova = await runNOVA(meteor);
  const novaMs = performance.now() - tNs;
  sample();

  const tEs = performance.now();
  const eclipse = await runECLIPSE(meteor, nova);
  const eclipseMs = performance.now() - tEs;
  sample();

  const tPs = performance.now();
  const pulsar = await runPULSAR(meteor, eclipse);
  const pulsarMs = performance.now() - tPs;
  sample();

  const tAs = performance.now();
  const aurora = await runAURORA(meteor, nova, eclipse, pulsar);
  const auroraMs = performance.now() - tAs;
  sample();

  return {
    runIdx,
    totalMs: performance.now() - t0,
    engineMs: { METEOR: meteorMs, NOVA: novaMs, ECLIPSE: eclipseMs, PULSAR: pulsarMs, AURORA: auroraMs },
    peakRssMB: (peak - baseline) / 1024 / 1024,
    score: aurora.score,
    verdict: aurora.verdict,
    breakdown: aurora.breakdown,
    threshold: aurora.threshold,
    unsupportedFilesNote: aurora.unsupportedFilesNote,
    unsupportedFiles: meteor.unsupportedFiles,
    fileCount: meteor.files.length,
    locCount: meteor.metrics.linesOfCode,
    functionCount: meteor.functions.length,
    circularDeps: nova.circularDeps.length,
    godModules: nova.godModules.length,
    highRisk: eclipse.highRisk.length,
    pulsarFindings: pulsar.adversarialFindings.length,
    issues: {
      HIGH: aurora.topIssues.filter(i => i.severity === 'HIGH').length,
      MED: aurora.topIssues.filter(i => i.severity === 'MED').length,
    },
  };
}

// ── Corpus driver ─────────────────────────────────────────────────────────────

async function runCorpus(id: string, label: string, localPath: string, sha: string, checks: string[]) {
  console.log(`\n${'═'.repeat(64)}`);
  console.log(`CORPUS: ${label}`);
  console.log(`Path:   ${localPath}`);
  console.log(`SHA:    ${sha}`);
  console.log(`${'─'.repeat(64)}`);

  if (!fs.existsSync(localPath)) {
    console.log(`  ✗ Path not found — SKIPPED`);
    return { id, label, sha, status: 'SKIPPED', runs: [], checks: {} };
  }

  const runs: any[] = [];

  for (let i = 0; i < RUNS; i++) {
    process.stdout.write(`  Run ${i + 1}/${RUNS}... `);
    let result: any;
    try {
      const p = runOnce(localPath, i + 1);
      const t = new Promise((_, rej) => setTimeout(() => rej(new Error('TIMEOUT')), TIMEOUT_MS));
      result = await Promise.race([p, t]);
      console.log(`✓ ${(result.totalMs / 1000).toFixed(2)}s | ${result.verdict} (${(result.score * 100).toFixed(0)}%) | unsupported: ${result.unsupportedFiles.count} files`);
    } catch (e: any) {
      console.log(`✗ ${e.message}`);
      result = { runIdx: i + 1, error: e.message };
    }
    runs.push(result);
    await new Promise(r => setTimeout(r, 300));
  }

  const good = runs.filter(r => !r.error);
  const medTime = median(good.map((r: any) => r.totalMs));
  const rep = good[0] ?? runs[0];

  // Evaluate checks
  const checkResults: Record<string, { pass: boolean; detail: string }> = {};
  for (const chk of checks) {
    checkResults[chk] = evaluateCheck(chk, rep, id);
  }

  console.log(`\n  Median time: ${(medTime / 1000).toFixed(2)}s`);
  if (rep && !rep.error) {
    console.log(`  Score: ${(rep.score * 100).toFixed(1)}%  Verdict: ${rep.verdict}`);
    console.log(`  Breakdown: complexity=${(rep.breakdown.complexityScore * 100).toFixed(0)}% dep=${(rep.breakdown.dependencyScore * 100).toFixed(0)}% risk=${(rep.breakdown.riskScore * 100).toFixed(0)}% adversarial=${(rep.breakdown.adversarialScore * 100).toFixed(0)}%`);
    if (rep.unsupportedFilesNote) console.log(`  ⚠ ${rep.unsupportedFilesNote}`);
  }
  console.log(`\n  CHECKS:`);
  for (const [chk, res] of Object.entries(checkResults)) {
    console.log(`    ${res.pass ? '✓' : '✗'} ${chk}: ${res.detail}`);
  }

  return { id, label, sha, status: 'OK', runs, medianTotalMs: medTime, rep, checkResults };
}

function evaluateCheck(chk: string, rep: any, id: string): { pass: boolean; detail: string } {
  if (!rep || rep.error) return { pass: false, detail: `no valid run: ${rep?.error}` };

  switch (chk) {
    case 'APPROVED':
      return { pass: rep.verdict === 'APPROVED', detail: `verdict=${rep.verdict}` };
    case 'REJECTED':
      return { pass: rep.verdict === 'REJECTED', detail: `verdict=${rep.verdict}` };
    case 'SCORE_STABLE':
      return { pass: rep.score >= 0.90 && rep.score <= 0.999, detail: `score=${(rep.score * 100).toFixed(1)}%` };
    case 'SCORE_IN_RANGE_0.60_0.80':
      return { pass: rep.score >= 0.60 && rep.score <= 0.80, detail: `score=${(rep.score * 100).toFixed(1)}%` };
    case 'UNSUPPORTED_10':
      return { pass: rep.unsupportedFiles.count === 10, detail: `unsupported=${rep.unsupportedFiles.count}` };
    case 'UNSUPPORTED_EXT_C':
      return { pass: rep.unsupportedFiles.extensions.includes('.c'), detail: `extensions=${JSON.stringify(rep.unsupportedFiles.extensions)}` };
    case 'NOTE_PRESENT':
      return { pass: !!rep.unsupportedFilesNote, detail: rep.unsupportedFilesNote ? 'note present' : 'note MISSING' };
    case 'NO_CRASH':
      return { pass: true, detail: 'pipeline completed without exception' };
    case 'BREAKDOWN_PRESENT':
      return {
        pass: typeof rep.breakdown?.complexityScore === 'number',
        detail: `complexityScore=${rep.breakdown?.complexityScore?.toFixed(3)}`
      };
    default:
      return { pass: false, detail: `unknown check: ${chk}` };
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log('\nVANTAGE VERIFICATION RUN — Post-Issue-1/2/3 Fix');
  console.log('═'.repeat(64));
  console.log(`Timestamp: ${new Date().toISOString()}`);

  const apiOk = await checkApi();
  console.log(`API health: ${apiOk ? '✓ ONLINE (port 7474)' : '✗ OFFLINE'}`);

  const corpora = [
    {
      id: 'express',
      label: 'Regression — expressjs/express',
      localPath: '/tmp/vantage-bench/express',
      sha: '8e022edc9185f540a3fcecaf5e56b850d919cdac',
      checks: ['APPROVED', 'SCORE_STABLE', 'BREAKDOWN_PRESENT'],
    },
    {
      id: 'vscode',
      label: 'New large TS — microsoft/vscode (src/vs)',
      localPath: '/tmp/vantage-bench/vscode/src/vs',
      sha: 'd0eea83269b1c1b4e868089e17032b108cecd8be',
      checks: ['REJECTED', 'SCORE_IN_RANGE_0.60_0.80', 'BREAKDOWN_PRESENT'],
    },
    {
      id: 'synthetic-c',
      label: 'Unsupported language — 10 synthetic C files',
      localPath: '/tmp/vantage-bench/synthetic-c',
      sha: 'synthetic (copied from linux/drivers/net)',
      checks: ['NO_CRASH', 'UNSUPPORTED_10', 'UNSUPPORTED_EXT_C', 'NOTE_PRESENT'],
    },
  ];

  const allResults: any[] = [];
  for (const c of corpora) {
    const r = await runCorpus(c.id, c.label, c.localPath, c.sha, c.checks);
    allResults.push(r);
  }

  // Write JSON
  const outPath = path.join(__dirname, 'results', 'verification_run.json');
  fs.writeFileSync(outPath, JSON.stringify({ generatedAt: new Date().toISOString(), apiHealthy: apiOk, results: allResults }, null, 2));
  console.log(`\nResults: ${outPath}`);

  // Final pass/fail summary
  console.log('\n' + '═'.repeat(64));
  console.log('VERIFICATION SUMMARY');
  console.log('═'.repeat(64));
  let allPass = true;
  for (const r of allResults) {
    if (r.status === 'SKIPPED') { console.log(`  SKIP  ${r.id}`); continue; }
    const checks = Object.entries(r.checkResults ?? {});
    const passed = checks.filter(([, v]: any) => v.pass).length;
    const total = checks.length;
    const ok = passed === total;
    if (!ok) allPass = false;
    console.log(`  ${ok ? '✓ PASS' : '✗ FAIL'} ${r.id} (${passed}/${total} checks)`);
    if (!ok) {
      for (const [chk, v] of checks) {
        if (!(v as any).pass) console.log(`         ✗ ${chk}: ${(v as any).detail}`);
      }
    }
  }
  console.log('─'.repeat(64));
  console.log(allPass ? '  ALL CHECKS PASSED — proceed to Stage 2' : '  FAILURES DETECTED — do not proceed to Stage 2');
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });

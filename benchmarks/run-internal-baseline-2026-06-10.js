#!/usr/bin/env node
// INTERNAL baseline run — 2026-06-10 (Pan rescue-night)
// Matched-scoring run: every tool below goes through the SAME harness,
// SAME ground truth, SAME v2 scoring (packages/vantage-bench/src/scoring.ts),
// SAME corpus snapshots. No mixing with stale v1 numbers.
//
// INTERNAL EYES ONLY. Not for publication (commercial-SAST DeWitt clauses;
// CodeQL terms). See benchmarks/INTERNAL_BASELINE_2026-06-10.md.
//
// Usage: node benchmarks/run-internal-baseline-2026-06-10.js
// (PATH must include semgrep; corpora expected/cloned at /tmp/vantage-bench)

const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');
const os = require('os');

const BENCH = path.join(__dirname, '..', 'packages', 'vantage-bench');

require(path.join(BENCH, 'node_modules', 'ts-node')).register({
  project: path.join(BENCH, 'tsconfig.json'),
  transpileOnly: true,
});

const { ensureCorpora, getCorpora } = require(path.join(BENCH, 'src', 'corpus'));
const { scoreFindings, aggregateF1, medianDuration } = require(path.join(BENCH, 'src', 'scoring'));
const { VantageRunner } = require(path.join(BENCH, 'src', 'runners', 'vantage'));
const { SemgrepRunner } = require(path.join(BENCH, 'src', 'runners', 'semgrep'));
const { normalizeType, toCorpusRelativePosix } = require(path.join(BENCH, 'src', 'runners', 'base'));

// --- VANTAGE semantic-mode runner (subclass; adds --semantic, NEBULA engine on) ---
class SemanticVantageRunner {
  constructor() { this.name = 'VANTAGE-semantic'; }

  async run(targetPath) {
    const reportFile = path.join(os.tmpdir(), `vantage-bench-sem-${Date.now()}.json`);
    const start = Date.now();
    let toolVersion = 'unknown';
    try {
      const local = path.join(__dirname, '..', 'bin', 'vantage.js');
      if (!fs.existsSync(local)) return { findings: [], durationMs: 0, toolVersion, error: 'repo-local vantage not found' };
      const bin = `node "${local}"`;
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
        toolVersion = (pkg.version ?? 'unknown') + '+nebula';
      } catch {}

      execSync(`${bin} "${targetPath}" --semantic --output "${reportFile}"`, { stdio: 'pipe', timeout: 300000 });

      if (!fs.existsSync(reportFile)) return { findings: [], durationMs: Date.now() - start, toolVersion, error: 'no report generated' };
      const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
      const durationMs = report.aurora?.totalMs ?? (Date.now() - start);
      const findings = (report.pulsar?.adversarialFindings ?? []).map(f => ({
        file: toCorpusRelativePosix(targetPath, f.file ?? ''),
        line: f.line ?? 0,
        type: normalizeType(f.type ?? ''),
        severity: f.severity,
        description: f.description,
        rawType: f.type,
      }));
      return { findings, durationMs, toolVersion };
    } catch (err) {
      return { findings: [], durationMs: Date.now() - start, toolVersion, error: err.message };
    } finally {
      try { if (fs.existsSync(reportFile)) fs.unlinkSync(reportFile); } catch {}
    }
  }
}

// --- Repo-local-only VANTAGE pattern runner ---
// The stock VantageRunner prefers a global `vantage` from PATH; force the
// repo-local build so the rescued NEBULA-era code is what gets measured.
class LocalVantageRunner extends VantageRunner {
  async run(targetPath) {
    const reportFile = path.join(os.tmpdir(), `vantage-bench-pat-${Date.now()}.json`);
    const start = Date.now();
    let toolVersion = 'unknown';
    try {
      const local = path.join(__dirname, '..', 'bin', 'vantage.js');
      if (!fs.existsSync(local)) return { findings: [], durationMs: 0, toolVersion, error: 'repo-local vantage not found' };
      const bin = `node "${local}"`;
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
        toolVersion = pkg.version ?? 'unknown';
      } catch {}

      execSync(`${bin} "${targetPath}" --output "${reportFile}"`, { stdio: 'pipe', timeout: 300000 });

      if (!fs.existsSync(reportFile)) return { findings: [], durationMs: Date.now() - start, toolVersion, error: 'no report generated' };
      const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
      const durationMs = report.aurora?.totalMs ?? (Date.now() - start);
      const findings = (report.pulsar?.adversarialFindings ?? []).map(f => ({
        file: toCorpusRelativePosix(targetPath, f.file ?? ''),
        line: f.line ?? 0,
        type: normalizeType(f.type ?? ''),
        severity: f.severity,
        description: f.description,
        rawType: f.type,
      }));
      return { findings, durationMs, toolVersion };
    } catch (err) {
      return { findings: [], durationMs: Date.now() - start, toolVersion, error: err.message };
    } finally {
      try { if (fs.existsSync(reportFile)) fs.unlinkSync(reportFile); } catch {}
    }
  }
}

function gitSha(dir) {
  try { return execSync(`git -C "${dir}" rev-parse HEAD`, { encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
}

async function main() {
  ensureCorpora();
  const corpora = getCorpora();
  if (corpora.length !== 2) throw new Error(`expected 2 corpora, got ${corpora.length}`);

  const runners = [new LocalVantageRunner(), new SemanticVantageRunner(), new SemgrepRunner()];
  const results = [];

  for (const runner of runners) {
    console.log(`\n=== ${runner.name} ===`);
    const scores = [];
    let resolvedVersion = 'unknown';
    for (const corpus of corpora) {
      process.stdout.write(`  ${corpus.label} ... `);
      const rr = await runner.run(corpus.analysisPath);
      resolvedVersion = rr.toolVersion;
      if (rr.error) console.log(`ERROR: ${rr.error}`);
      const m = scoreFindings(rr.findings, corpus.groundTruth, corpus.analysisPath);
      scores.push({
        tool: runner.name, toolVersion: rr.toolVersion, corpus: corpus.id, corpusLabel: corpus.label,
        tp: m.tp.length, fp: m.fp.length, fn: m.fn.length,
        precision: m.precision, recall: m.recall, f1: m.f1, durationMs: rr.durationMs,
        tpDetails: m.tp.map(t => ({ file: t.finding.file, line: t.finding.line, type: t.finding.type })),
        fpDetails: m.fp.map(f => ({ file: f.file, line: f.line, type: f.type, description: f.description })),
        fnDetails: m.fn.map(e => ({ id: e.id, file: e.file, line: e.line, type: e.type, description: e.description })),
      });
      const pct = n => n === null ? 'N/A' : (n * 100).toFixed(1) + '%';
      console.log(`P=${pct(m.precision)} R=${pct(m.recall)} F1=${pct(m.f1)} TP=${m.tp.length} FP=${m.fp.length} FN=${m.fn.length} (${rr.durationMs.toFixed(0)}ms)`);
    }
    results.push({
      tool: runner.name, toolVersion: resolvedVersion, runDate: new Date().toISOString(),
      commitSha: gitSha(path.join(__dirname, '..')).slice(0, 12),
      scores, aggregateF1: aggregateF1(scores), medianDurationMs: medianDuration(scores),
    });
  }

  const out = {
    meta: {
      label: 'INTERNAL BASELINE 2026-06-10 — matched v2 scoring, internal eyes only',
      scoringVersion: 'v2 (strict suffix path match, type match, ±5 line, scope field, null-propagating aggregate)',
      harnessCommit: gitSha(path.join(__dirname, '..')),
      corpora: {
        nodegoat: { sha: gitSha('/tmp/vantage-bench/nodegoat'), gtEntries: 4 },
        'juice-shop': { sha: gitSha('/tmp/vantage-bench/juiceshop'), gtEntries: 9 },
      },
      environment: {
        node: process.version,
        caveat: 'Run under CPU contention (concurrent agent + luna watcher active). Durations are indicative only; TP/FP/FN counts are deterministic.',
      },
      notRun: {
        SonarQube: 'no local server (docker daemon down); April numbers were v1-scored and must not be compared',
        CodeQL: 'CLI not installed; runner never executed; GitHub CodeQL terms — internal-use caution, publication prohibited',
      },
    },
    results,
  };

  const outFile = path.join(__dirname, 'results', 'internal_baseline_2026-06-10.json');
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.log(`\nWritten: ${outFile}`);
}

main().catch(err => { console.error('FATAL:', err); process.exit(1); });

#!/usr/bin/env node
// CodeQL CLI head-to-head — 2026-06-10 (Pan).
// MATCHED scoring: reuses packages/vantage-bench scoring.ts + the SAME ground
// truth + the SAME corpus snapshots as benchmarks/run-internal-baseline-2026-06-10.js.
// Builds a CodeQL DB per JS/TS corpus, runs the security-and-quality suite,
// parses SARIF through the existing CodeQLRunner SARIF parser, scores v2.
//
// CodeQL binary is taken from CODEQL_BIN (or ./bin in the downloaded bundle).
// Usage: CODEQL_BIN=/tmp/codeql-install/codeql/codeql node benchmarks/run-codeql-headtohead-2026-06-10.js

const path = require('path');
const fs = require('fs');
const os = require('os');
const { execSync } = require('child_process');

const BENCH = path.join(__dirname, '..', 'packages', 'vantage-bench');
require(path.join(BENCH, 'node_modules', 'ts-node')).register({
  project: path.join(BENCH, 'tsconfig.json'),
  transpileOnly: true,
});

const { getCorpora } = require(path.join(BENCH, 'src', 'corpus'));
const { scoreFindings, aggregateF1, medianDuration } = require(path.join(BENCH, 'src', 'scoring'));
const { normalizeType, toCorpusRelativePosix } = require(path.join(BENCH, 'src', 'runners', 'base'));

const CODEQL_BIN = process.env.CODEQL_BIN || '/tmp/codeql-install/codeql/codeql';
// security-and-quality is the broad suite (security-extended ⊂ this). Use the
// pack-qualified suite name so it resolves from the bundle's bundled queries.
const SUITE = process.env.CODEQL_SUITE || 'codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls';

function mapSarifLevel(level) {
  if (level === 'error') return 'HIGH';
  if (level === 'warning') return 'MED';
  return 'LOW';
}

function parseSarif(sarif, targetPath) {
  const findings = [];
  for (const run of sarif.runs ?? []) {
    const rules = {};
    for (const rule of run.tool?.driver?.rules ?? []) rules[rule.id] = rule;
    for (const ext of run.tool?.extensions ?? []) {
      for (const rule of ext.rules ?? []) rules[rule.id] = rule;
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

async function runCodeQL(targetPath) {
  const tmpDir = path.join(os.tmpdir(), `codeql-bench-${Date.now()}`);
  const dbDir = path.join(tmpDir, 'db');
  const resultsDir = path.join(tmpDir, 'results');
  const start = Date.now();
  let toolVersion = 'unknown';
  try {
    if (!fs.existsSync(CODEQL_BIN)) {
      return { findings: [], durationMs: 0, toolVersion, error: `codeql binary not found at ${CODEQL_BIN}` };
    }
    try {
      toolVersion = execSync(`"${CODEQL_BIN}" version --format=terse`, { encoding: 'utf8' }).trim();
    } catch {}

    fs.mkdirSync(dbDir, { recursive: true });
    fs.mkdirSync(resultsDir, { recursive: true });

    console.log(`    creating DB (javascript-typescript) ...`);
    execSync(
      `"${CODEQL_BIN}" database create "${dbDir}" --language=javascript-typescript --source-root="${targetPath}" --overwrite`,
      { stdio: 'pipe', timeout: 1_200_000, cwd: targetPath }
    );

    console.log(`    analyzing (${SUITE}) ...`);
    const sarifFile = path.join(resultsDir, 'results.sarif');
    execSync(
      `"${CODEQL_BIN}" database analyze "${dbDir}" ${SUITE} --format=sarifv2.1.0 --output="${sarifFile}" --threads=0`,
      { stdio: 'pipe', timeout: 1_200_000 }
    );

    const durationMs = Date.now() - start;
    if (!fs.existsSync(sarifFile)) return { findings: [], durationMs, toolVersion, error: 'no SARIF output' };

    // persist a copy of the SARIF for the receipts
    const keep = path.join(__dirname, 'results', `codeql_${path.basename(targetPath)}_2026-06-10.sarif`);
    try { fs.copyFileSync(sarifFile, keep); } catch {}

    const sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
    const findings = parseSarif(sarif, targetPath);
    return { findings, durationMs, toolVersion, rawCount: (sarif.runs?.[0]?.results ?? []).length };
  } catch (err) {
    return { findings: [], durationMs: Date.now() - start, toolVersion, error: err.message };
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

function gitSha(dir) {
  try { return execSync(`git -C "${dir}" rev-parse HEAD`, { encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
}

async function main() {
  const corpora = getCorpora();
  if (corpora.length !== 2) throw new Error(`expected 2 corpora, got ${corpora.length}`);

  console.log(`\n=== CodeQL (bin: ${CODEQL_BIN}) ===`);
  const scores = [];
  let resolvedVersion = 'unknown';
  const perCorpusExtras = {};

  for (const corpus of corpora) {
    process.stdout.write(`  ${corpus.label} ...\n`);
    const rr = await runCodeQL(corpus.analysisPath);
    resolvedVersion = rr.toolVersion;
    if (rr.error) console.log(`  ERROR: ${rr.error}`);
    const m = scoreFindings(rr.findings, corpus.groundTruth, corpus.analysisPath);
    scores.push({
      tool: 'CodeQL', toolVersion: rr.toolVersion, corpus: corpus.id, corpusLabel: corpus.label,
      tp: m.tp.length, fp: m.fp.length, fn: m.fn.length,
      precision: m.precision, recall: m.recall, f1: m.f1, durationMs: rr.durationMs,
      rawFindingCount: rr.rawCount ?? null,
      tpDetails: m.tp.map(t => ({ file: t.finding.file, line: t.finding.line, type: t.finding.type, rawType: t.finding.rawType })),
      fpDetails: m.fp.map(f => ({ file: f.file, line: f.line, type: f.type, rawType: f.rawType, description: f.description })),
      fnDetails: m.fn.map(e => ({ id: e.id, file: e.file, line: e.line, type: e.type, description: e.description })),
    });
    const pct = n => n === null ? 'N/A' : (n * 100).toFixed(1) + '%';
    console.log(`  => P=${pct(m.precision)} R=${pct(m.recall)} F1=${pct(m.f1)} TP=${m.tp.length} FP=${m.fp.length} FN=${m.fn.length} rawFindings=${rr.rawCount ?? '?'} (${rr.durationMs.toFixed(0)}ms)`);
  }

  const out = {
    meta: {
      label: 'CodeQL head-to-head 2026-06-10 — matched v2 scoring, same GT/corpus as internal baseline',
      scoringVersion: 'v2 (strict suffix path match, type match, ±5 line, null-propagating aggregate)',
      suite: SUITE,
      codeqlBin: CODEQL_BIN,
      harnessCommit: gitSha(path.join(__dirname, '..')),
      corpora: {
        nodegoat: { sha: gitSha('/tmp/vantage-bench/nodegoat'), gtEntries: 4 },
        'juice-shop': { sha: gitSha('/tmp/vantage-bench/juiceshop'), gtEntries: 9 },
      },
      node: process.version,
    },
    result: {
      tool: 'CodeQL', toolVersion: resolvedVersion, runDate: new Date().toISOString(),
      scores, aggregateF1: aggregateF1(scores), medianDurationMs: medianDuration(scores),
    },
  };
  const outFile = path.join(__dirname, 'results', 'codeql_headtohead_2026-06-10.json');
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.log(`\nWritten: ${outFile}`);
  console.log(`Aggregate F1: ${out.result.aggregateF1 === null ? 'null' : (out.result.aggregateF1 * 100).toFixed(1) + '%'}`);
}

main().catch(err => { console.error('FATAL:', err); process.exit(1); });

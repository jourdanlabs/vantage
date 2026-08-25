#!/usr/bin/env node
// CodeQL FAIR re-run — 2026-06-10 (Pan).
// The prior head-to-head built the CodeQL DB WITHOUT `npm install`, so the JS/TS
// extractor failed and emitted ~82 js/syntax-error results that inflated FPs and
// tanked precision. This run installs deps FIRST (done out-of-band), builds the DB
// with full extraction, and re-scores through the SAME matched-v2 harness.
//
// It runs BOTH suites per corpus:
//   - security-and-quality  (204 queries) — the broad suite, comparable to the prior run
//   - security-extended     (106 queries) — true security-only suite (the fair detection lens)
// And it ALSO post-hoc filters the security-and-quality SARIF to the security-relevant
// subset (the exact lens the prior report's "security-only re-score" used), so the delta
// vs the prior (mis-run) number is apples-to-apples.
//
// DBs are expected pre-built at /tmp/cqdb-<corpusBasename>. If absent, this builds them.
// Usage: CODEQL_BIN=/tmp/codeql-install/codeql/codeql node benchmarks/run-codeql-fair-2026-06-10.js

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
const { scoreFindings } = require(path.join(BENCH, 'src', 'scoring'));
const { normalizeType, toCorpusRelativePosix } = require(path.join(BENCH, 'src', 'runners', 'base'));

const CODEQL_BIN = process.env.CODEQL_BIN || '/tmp/codeql-install/codeql/codeql';
const SUITES = {
  'security-and-quality': 'codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls',
  'security-extended': 'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
};

// Quality / non-security rule prefixes dropped for the "security-only re-score" lens.
// This mirrors the prior report's §3a filter exactly (unused-var, syntax-error, ASI,
// rate-limiting, useless-assignment, and other quality/style/hardening-advisory rules).
const QUALITY_RULES = new Set([
  'js/unused-local-variable',
  'js/syntax-error',
  'js/automatic-semicolon-insertion',
  'js/missing-rate-limiting',
  'js/useless-assignment-to-local',
  'js/useless-expression',
  'js/redundant-assignment',
  'js/comparison-between-incompatible-types',
  'js/duplicate-html-attribute',
  'js/unreachable-statement',
  'js/useless-comparison-test',
  'js/useless-conditional',
  'js/trivial-conditional',
  'js/unused-property',
  'js/duplicate-property',
  'js/identical-operands',
  'js/ignore-array-result',
  'js/property-access-on-non-object',
  'js/unneeded-defensive-code',
  'js/superfluous-trailing-arguments',
]);
function isQualityRule(ruleId) {
  if (QUALITY_RULES.has(ruleId)) return true;
  // belt-and-suspenders: any remaining lint-ish quality categories
  return /unused|automatic-semicolon|useless|redundant|unreachable|trivial-conditional|duplicate-/.test(ruleId);
}

function mapSarifLevel(level) {
  if (level === 'error') return 'HIGH';
  if (level === 'warning') return 'MED';
  return 'LOW';
}

function parseSarifResults(sarif, targetPath) {
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

function ruleTally(findings) {
  const c = {};
  for (const f of findings) c[f.rawType] = (c[f.rawType] || 0) + 1;
  return Object.entries(c).sort((a, b) => b[1] - a[1]);
}

function gitSha(dir) {
  try { return execSync(`git -C "${dir}" rev-parse HEAD`, { encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
}

function ensureDb(corpus) {
  const dbDir = `/tmp/cqdb-${path.basename(corpus.analysisPath)}`;
  if (fs.existsSync(path.join(dbDir, 'codeql-database.yml'))) {
    console.log(`    DB present: ${dbDir} (reusing)`);
    return dbDir;
  }
  console.log(`    building DB: ${dbDir} ...`);
  execSync(
    `"${CODEQL_BIN}" database create "${dbDir}" --language=javascript-typescript --source-root="${corpus.analysisPath}" --overwrite`,
    { stdio: 'pipe', timeout: 1_800_000, cwd: corpus.analysisPath }
  );
  return dbDir;
}

function analyze(dbDir, suiteRef, outFile) {
  execSync(
    `"${CODEQL_BIN}" database analyze "${dbDir}" ${suiteRef} --format=sarifv2.1.0 --output="${outFile}" --threads=0 --rerun`,
    { stdio: 'pipe', timeout: 1_800_000 }
  );
  return JSON.parse(fs.readFileSync(outFile, 'utf8'));
}

function scoreAndPack(label, findings, corpus) {
  const m = scoreFindings(findings, corpus.groundTruth, corpus.analysisPath);
  return {
    label,
    tp: m.tp.length, fp: m.fp.length, fn: m.fn.length,
    precision: m.precision, recall: m.recall, f1: m.f1,
    rawCount: findings.length,
    syntaxErrors: findings.filter(f => f.rawType === 'js/syntax-error').length,
    tpDetails: m.tp.map(t => ({ file: t.finding.file, line: t.finding.line, type: t.finding.type, rawType: t.finding.rawType, gtId: t.gt.id })),
    fnDetails: m.fn.map(e => ({ id: e.id, file: e.file, line: e.line, type: e.type })),
    fpTopRules: ruleTally(m.fp).slice(0, 12),
  };
}

async function main() {
  const corpora = getCorpora();
  const resultsDir = path.join(__dirname, 'results');
  fs.mkdirSync(resultsDir, { recursive: true });
  let toolVersion = 'unknown';
  try { toolVersion = execSync(`"${CODEQL_BIN}" version --format=terse`, { encoding: 'utf8' }).trim(); } catch {}

  console.log(`\n=== CodeQL FAIR re-run (v${toolVersion}, deps installed) ===`);
  const out = {
    meta: {
      label: 'CodeQL FAIR re-run 2026-06-10 — DB built WITH npm install (full extraction), matched v2 scoring',
      scoringVersion: 'v2 (strict suffix path match, type match, ±5 line, null-propagating aggregate)',
      codeqlBin: CODEQL_BIN, toolVersion,
      suites: SUITES,
      runDate: new Date().toISOString(),
      node: process.version,
      corpora: {},
    },
    results: {},
  };

  for (const corpus of corpora) {
    console.log(`\n  ${corpus.label}`);
    out.meta.corpora[corpus.id] = { sha: gitSha(corpus.localPath), gtEntries: corpus.groundTruth.vulnerabilities.length };
    const dbDir = ensureDb(corpus);
    const base = path.basename(corpus.analysisPath);
    out.results[corpus.id] = { corpusLabel: corpus.label };

    for (const [suiteName, suiteRef] of Object.entries(SUITES)) {
      const sarifFile = path.join(resultsDir, `codeql-fair_${base}_${suiteName}_2026-06-10.sarif`);
      console.log(`    analyze ${suiteName} ...`);
      const sarif = analyze(dbDir, suiteRef, sarifFile);
      const findings = parseSarifResults(sarif, corpus.analysisPath);

      const full = scoreAndPack(`${suiteName} (full)`, findings, corpus);
      out.results[corpus.id][suiteName] = full;
      const pct = n => n === null ? 'N/A' : (n * 100).toFixed(1) + '%';
      console.log(`      ${suiteName} FULL: P=${pct(full.precision)} R=${pct(full.recall)} F1=${pct(full.f1)} TP=${full.tp} FP=${full.fp} FN=${full.fn} raw=${full.rawCount} syntaxErr=${full.syntaxErrors}`);

      // Post-hoc security-only lens on the security-and-quality SARIF (prior-report parity)
      if (suiteName === 'security-and-quality') {
        const secFindings = findings.filter(f => !isQualityRule(f.rawType));
        const secOnly = scoreAndPack('security-and-quality (security-only filtered)', secFindings, corpus);
        out.results[corpus.id]['security-and-quality-filtered'] = secOnly;
        console.log(`      S&Q SEC-ONLY filter: P=${pct(secOnly.precision)} R=${pct(secOnly.recall)} F1=${pct(secOnly.f1)} TP=${secOnly.tp} FP=${secOnly.fp} FN=${secOnly.fn} raw=${secOnly.rawCount}`);
      }
    }
  }

  const outFile = path.join(resultsDir, 'codeql_fair_2026-06-10.json');
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.log(`\nWritten: ${outFile}`);
}

main().catch(err => { console.error('FATAL:', err); process.exit(1); });

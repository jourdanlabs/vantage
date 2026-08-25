#!/usr/bin/env node
/**
 * CodeQL refresh — 2026-08-02 (Toph · VANTAGE re-cert)
 *
 * Current CodeQL CLI, BOTH suites, matched-v2 scoring, pinned corpora.
 * Requires npm install already completed on each corpus (the fair-run lesson).
 *
 * Usage:
 *   CODEQL_BIN=/tmp/codeql-install/codeql/codeql \
 *   NODEGOAT=... JUICESHOP=... \
 *   node benchmarks/run-codeql-refresh-2026-08-02.js
 *
 * Publishability: CodeQL / GHAS numbers are anonymised for external publish
 * (trademark clause). This receipt is for Captain / internal gate only when
 * named; public table uses "Tool C" style labels.
 */

const path = require('path');
const fs = require('fs');
const { execSync, spawnSync } = require('child_process');

const REPO = path.resolve(__dirname, '..');
const BENCH = path.join(REPO, 'packages', 'vantage-bench');
const OUT_DIR = path.join(REPO, 'benchmarks', 'results', 'codeql-refresh-2026-08-02');
const CODEQL_BIN = process.env.CODEQL_BIN || '/tmp/codeql-install/codeql/codeql';

const SUITES = {
  'security-and-quality':
    'codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls',
  'security-extended':
    'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
};

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
  return /unused|automatic-semicolon|useless|redundant|unreachable|trivial-conditional|duplicate-/.test(
    ruleId
  );
}

require(path.join(BENCH, 'node_modules', 'ts-node')).register({
  project: path.join(BENCH, 'tsconfig.json'),
  transpileOnly: true,
});
const { scoreFindings } = require(path.join(BENCH, 'src', 'scoring'));
const { normalizeType, toCorpusRelativePosix } = require(path.join(BENCH, 'src', 'runners', 'base'));
const nodegoatGt = require(path.join(BENCH, 'src', 'ground-truth', 'nodegoat.json'));
const juiceshopGt = require(path.join(BENCH, 'src', 'ground-truth', 'juice-shop.json'));

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

function sh(cmd, opts = {}) {
  console.log(`$ ${cmd}`);
  return execSync(cmd, {
    encoding: 'utf8',
    stdio: opts.silent ? 'pipe' : 'inherit',
    maxBuffer: 64 * 1024 * 1024,
    ...opts,
  });
}

function codeqlVersion() {
  try {
    const out = execSync(`"${CODEQL_BIN}" version`, { encoding: 'utf8' });
    const m = out.match(/release\s+([\d.]+)/i) || out.match(/([\d]+\.[\d]+\.[\d]+)/);
    return m ? m[1] : out.trim().split('\n')[0];
  } catch (e) {
    return `error: ${e.message}`;
  }
}

function ensureDb(corpusPath, dbDir) {
  if (fs.existsSync(path.join(dbDir, 'codeql-database.yml')) || fs.existsSync(path.join(dbDir, 'db-javascript'))) {
    console.log(`  DB exists: ${dbDir}`);
    return;
  }
  fs.mkdirSync(path.dirname(dbDir), { recursive: true });
  if (fs.existsSync(dbDir)) fs.rmSync(dbDir, { recursive: true, force: true });
  sh(
    `"${CODEQL_BIN}" database create "${dbDir}" --language=javascript-typescript --source-root="${corpusPath}" --overwrite`
  );
}

function analyze(dbDir, suiteRef, outSarif) {
  fs.mkdirSync(path.dirname(outSarif), { recursive: true });
  sh(
    `"${CODEQL_BIN}" database analyze "${dbDir}" ${suiteRef} --format=sarifv2.1.0 --output="${outSarif}" --threads=0 --rerun`
  );
  return JSON.parse(fs.readFileSync(outSarif, 'utf8'));
}

function pct(x) {
  if (x == null || Number.isNaN(x)) return 'n/a';
  return (x * 100).toFixed(1) + '%';
}

function main() {
  if (!fs.existsSync(CODEQL_BIN)) {
    console.error('CODEQL_BIN not found:', CODEQL_BIN);
    process.exit(1);
  }
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const corpora = [
    {
      id: 'nodegoat',
      path: process.env.NODEGOAT || path.join(REPO, '..', 'corpus', 'owasp-pinned', 'NodeGoat'),
      gt: nodegoatGt,
    },
    {
      id: 'juice-shop',
      path: process.env.JUICESHOP || path.join(REPO, '..', 'corpus', 'owasp-pinned', 'juice-shop'),
      gt: juiceshopGt,
    },
  ];

  for (const c of corpora) {
    if (!fs.existsSync(c.path)) {
      console.error('Missing corpus', c.id, c.path);
      process.exit(1);
    }
    // hard requirement: npm install first
    if (!fs.existsSync(path.join(c.path, 'node_modules'))) {
      console.error(`REFUSE: ${c.id} has no node_modules. Run npm install first (fair-run lesson).`);
      process.exit(2);
    }
    try {
      c.sha = execSync('git rev-parse HEAD', { cwd: c.path, encoding: 'utf8' }).trim();
    } catch {
      c.sha = 'unknown';
    }
  }

  const version = codeqlVersion();
  const receipt = {
    date: new Date().toISOString(),
    driver: path.basename(__filename),
    codeqlBin: CODEQL_BIN,
    codeqlVersion: version,
    scoring: 'v2 packages/vantage-bench/src/scoring.ts',
    note: 'INTERNAL named numbers. External publish: anonymise as Tool C per trademark clause.',
    rows: [],
  };

  console.log(`CodeQL ${version}`);
  console.log(`Bin: ${CODEQL_BIN}`);

  for (const c of corpora) {
    const dbDir = path.join('/tmp', `cqdb-refresh-2026-08-02-${c.id}`);
    console.log(`\n=== ${c.id} (${c.sha.slice(0, 12)}) ===`);
    ensureDb(c.path, dbDir);

    for (const [suiteName, suiteRef] of Object.entries(SUITES)) {
      const sarifPath = path.join(OUT_DIR, `codeql_${c.id}_${suiteName}.sarif`);
      console.log(`  analyze ${suiteName}`);
      const started = Date.now();
      const sarif = analyze(dbDir, suiteRef, sarifPath);
      const durationMs = Date.now() - started;
      const findings = parseSarifResults(sarif, c.path);
      const match = scoreFindings(findings, c.gt, c.path);
      const row = {
        tool: 'CodeQL',
        codeqlVersion: version,
        corpus: c.id,
        corpusSha: c.sha,
        suite: suiteName,
        rawFindings: findings.length,
        tp: match.tp.length,
        fp: match.fp.length,
        fn: match.fn.length,
        precision: match.precision,
        recall: match.recall,
        f1: match.f1,
        durationMs,
        sarifPath,
      };
      console.log(
        `  ${suiteName}: F1=${pct(row.f1)} TP/FP/FN=${row.tp}/${row.fp}/${row.fn} raw=${row.rawFindings} ${durationMs}ms`
      );
      receipt.rows.push(row);

      if (suiteName === 'security-and-quality') {
        const filtered = findings.filter((f) => !isQualityRule(f.rawType || ''));
        const m2 = scoreFindings(filtered, c.gt, c.path);
        const row2 = {
          tool: 'CodeQL',
          codeqlVersion: version,
          corpus: c.id,
          corpusSha: c.sha,
          suite: 'security-and-quality+security-only-filter',
          rawFindings: filtered.length,
          tp: m2.tp.length,
          fp: m2.fp.length,
          fn: m2.fn.length,
          precision: m2.precision,
          recall: m2.recall,
          f1: m2.f1,
          durationMs: 0,
        };
        console.log(
          `  security-only-filter: F1=${pct(row2.f1)} TP/FP/FN=${row2.tp}/${row2.fp}/${row2.fn} raw=${row2.rawFindings}`
        );
        receipt.rows.push(row2);
      }
    }
  }

  // aggregates for security-extended
  const ext = receipt.rows.filter((r) => r.suite === 'security-extended' && r.f1 != null);
  if (ext.length === 2) {
    const [a, b] = ext.map((r) => r.f1);
    const harmonic = a > 0 && b > 0 ? 2 / (1 / a + 1 / b) : 0;
    receipt.aggregateSecurityExtendedF1 = harmonic;
    console.log(`\nAGGREGATE security-extended harmonic F1=${pct(harmonic)}`);
  }

  const outPath = path.join(OUT_DIR, 'receipt-codeql-refresh-2026-08-02.json');
  fs.writeFileSync(outPath, JSON.stringify(receipt, null, 2));
  console.log('Receipt:', outPath);
}

main();

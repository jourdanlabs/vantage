#!/usr/bin/env node
/**
 * Matched-v2 OSS re-run — 2026-08-02 (Toph · VANTAGE re-cert)
 *
 * Closes the vintage gap: Semgrep (and optionally SonarQube) under the SAME
 * packages/vantage-bench/src/scoring.ts v2 harness, on the SAME pinned corpus
 * SHAs as the fair CodeQL re-run.
 *
 * Pins (hard-coded; override with env):
 *   NodeGoat  c5cb68a7084e4ae7dcc60e6a98768720a81841e8
 *   JuiceShop 160f3062d6d7c30033ec505596b5b54d32932d8f
 *
 * Usage:
 *   NODEGOAT=/path/to/NodeGoat JUICESHOP=/path/to/juice-shop \
 *     node benchmarks/run-v2-matched-oss-2026-08-02.js
 *
 * Tools: VANTAGE pattern, VANTAGE semantic, Semgrep. SonarQube only if
 * SONAR_HOST_URL + token/scanner available (otherwise recorded as skipped).
 *
 * Publishability: Semgrep + SonarQube CE + VANTAGE numbers OK.
 * CodeQL numbers → anonymise for external publish (not this driver's job).
 */

const path = require('path');
const fs = require('fs');
const { execSync, spawnSync } = require('child_process');
const os = require('os');

const REPO = path.resolve(__dirname, '..');
const BENCH = path.join(REPO, 'packages', 'vantage-bench');
const OUT_DIR = path.join(REPO, 'benchmarks', 'results', 'v2-matched-oss-2026-08-02');

const PIN_NODEGOAT = process.env.NODEGOAT_SHA || 'c5cb68a7084e4ae7dcc60e6a98768720a81841e8';
const PIN_JUICE = process.env.JUICESHOP_SHA || '160f3062d6d7c30033ec505596b5b54d32932d8f';

require(path.join(BENCH, 'node_modules', 'ts-node')).register({
  project: path.join(BENCH, 'tsconfig.json'),
  transpileOnly: true,
});

const { scoreFindings, aggregateF1 } = require(path.join(BENCH, 'src', 'scoring'));
const { normalizeType, toCorpusRelativePosix } = require(path.join(BENCH, 'src', 'runners', 'base'));
const nodegoatGt = require(path.join(BENCH, 'src', 'ground-truth', 'nodegoat.json'));
const juiceshopGt = require(path.join(BENCH, 'src', 'ground-truth', 'juice-shop.json'));

function resolveCorpus(envKey, fallbacks, expectedSha) {
  const candidates = [];
  if (process.env[envKey]) candidates.push(process.env[envKey]);
  candidates.push(...fallbacks);
  for (const c of candidates) {
    if (c && fs.existsSync(c)) {
      let sha = 'unknown';
      try {
        sha = execSync('git rev-parse HEAD', { cwd: c, encoding: 'utf8' }).trim();
      } catch {}
      return { path: path.resolve(c), sha, expectedSha, shaMatch: sha === expectedSha };
    }
  }
  return null;
}

function runLocalVantage(targetPath, semantic) {
  const reportFile = path.join(os.tmpdir(), `vantage-v2-${Date.now()}.json`);
  const start = Date.now();
  let toolVersion = 'unknown';
  try {
    const local = path.join(REPO, 'bin', 'vantage.js');
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'package.json'), 'utf8'));
    toolVersion = pkg.version + (semantic ? '+nebula' : '');
    const args = [local, 'analyze', targetPath, '--output', reportFile];
    if (semantic) args.push('--semantic');
    const r = spawnSync(process.execPath, args, {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      timeout: 600_000,
    });
    if (r.status !== 0) {
      return {
        findings: [],
        durationMs: Date.now() - start,
        toolVersion,
        error: (r.stderr || r.stdout || 'vantage failed').slice(-2000),
      };
    }
    const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    const findings = (report.pulsar?.adversarialFindings ?? []).map((f) => ({
      file: toCorpusRelativePosix(targetPath, f.file ?? ''),
      line: f.line ?? 0,
      type: normalizeType(f.type ?? ''),
      severity: f.severity,
      description: f.description,
      rawType: f.type,
    }));
    return {
      findings,
      durationMs: Date.now() - start,
      toolVersion,
      rawCount: findings.length,
    };
  } catch (err) {
    return { findings: [], durationMs: Date.now() - start, toolVersion, error: err.message };
  } finally {
    try {
      fs.unlinkSync(reportFile);
    } catch {}
  }
}

function runSemgrep(targetPath) {
  const outFile = path.join(os.tmpdir(), `semgrep-v2-${Date.now()}.json`);
  const start = Date.now();
  let toolVersion = 'unknown';
  try {
    let bin = '';
    try {
      bin = execSync('which semgrep', { encoding: 'utf8' }).trim();
    } catch {}
    if (!bin) return { findings: [], durationMs: 0, toolVersion, error: 'semgrep not found' };
    try {
      toolVersion = execSync('semgrep --version', { encoding: 'utf8' })
        .trim()
        .split('\n')
        .filter((l) => /^\d+\.\d+/.test(l) || /semgrep/i.test(l))
        .pop();
    } catch {}
    // Also try pure version line
    try {
      const v = execSync('semgrep --version 2>/dev/null | tail -1', {
        encoding: 'utf8',
        shell: '/bin/bash',
      }).trim();
      if (v) toolVersion = v;
    } catch {}

    const r = spawnSync(
      bin,
      [
        '--config',
        'p/owasp-top-ten',
        '--config',
        'p/nodejs',
        '--config',
        'p/javascript',
        targetPath,
        '--json',
        '-o',
        outFile,
        '--no-autofix',
        '--quiet',
      ],
      { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 600_000 }
    );
    // semgrep exits 0 even with findings; non-zero may be config issues
    if (!fs.existsSync(outFile)) {
      return {
        findings: [],
        durationMs: Date.now() - start,
        toolVersion,
        error: (r.stderr || r.stdout || 'no json').slice(-2000),
      };
    }
    const raw = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    const results = raw.results ?? [];
    const findings = results.map((row) => {
      const rawType = row.check_id ?? row.rule_id ?? '';
      const sev = (row.extra?.severity ?? row.severity ?? 'LOW').toUpperCase();
      return {
        file: toCorpusRelativePosix(targetPath, row.path ?? ''),
        line: row.start?.line ?? 0,
        type: normalizeType(rawType),
        severity:
          sev === 'ERROR' || sev === 'CRITICAL'
            ? 'CRITICAL'
            : sev === 'WARNING' || sev === 'HIGH'
              ? 'HIGH'
              : sev === 'INFO' || sev === 'MEDIUM' || sev === 'MED'
                ? 'MED'
                : 'LOW',
        description: row.extra?.message ?? row.message ?? rawType,
        rawType,
      };
    });
    return { findings, durationMs: Date.now() - start, toolVersion, rawCount: findings.length };
  } catch (err) {
    return { findings: [], durationMs: Date.now() - start, toolVersion, error: err.message };
  } finally {
    try {
      fs.unlinkSync(outFile);
    } catch {}
  }
}

function scoreRow(tool, toolVersion, corpusId, corpusLabel, gt, targetPath, run) {
  if (run.error) {
    return {
      tool,
      toolVersion,
      corpus: corpusId,
      corpusLabel,
      error: run.error,
      durationMs: run.durationMs,
    };
  }
  const match = scoreFindings(run.findings, gt, targetPath);
  return {
    tool,
    toolVersion,
    corpus: corpusId,
    corpusLabel,
    tp: match.tp.length,
    fp: match.fp.length,
    fn: match.fn.length,
    precision: match.precision,
    recall: match.recall,
    f1: match.f1,
    durationMs: run.durationMs,
    rawCount: run.rawCount ?? run.findings.length,
    tpDetails: match.tp.map((t) => ({
      file: t.finding.file,
      line: t.finding.line,
      type: t.finding.type,
    })),
    fnDetails: match.fn.map((e) => ({
      id: e.id,
      file: e.file,
      line: e.line,
      type: e.type,
    })),
  };
}

function pct(x) {
  if (x == null || Number.isNaN(x)) return 'n/a';
  return (x * 100).toFixed(1) + '%';
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  // ensure ts-node deps
  if (!fs.existsSync(path.join(BENCH, 'node_modules', 'ts-node'))) {
    console.log('Installing vantage-bench deps...');
    execSync('npm install', { cwd: BENCH, stdio: 'inherit' });
  }

  const nodegoat = resolveCorpus(
    'NODEGOAT',
    [
      path.join(REPO, '..', 'corpus', 'owasp-pinned', 'NodeGoat'),
      '/tmp/vantage-bench/NodeGoat',
    ],
    PIN_NODEGOAT
  );
  const juiceshop = resolveCorpus(
    'JUICESHOP',
    [
      path.join(REPO, '..', 'corpus', 'owasp-pinned', 'juice-shop'),
      '/tmp/vantage-bench/juice-shop',
    ],
    PIN_JUICE
  );

  if (!nodegoat || !juiceshop) {
    console.error('Missing corpora. Set NODEGOAT and JUICESHOP env paths.');
    process.exit(1);
  }

  const corpora = [
    {
      id: 'nodegoat',
      label: 'OWASP NodeGoat',
      path: nodegoat.path,
      sha: nodegoat.sha,
      expectedSha: nodegoat.expectedSha,
      shaMatch: nodegoat.shaMatch,
      gt: nodegoatGt,
    },
    {
      id: 'juice-shop',
      label: 'OWASP Juice Shop',
      path: juiceshop.path,
      sha: juiceshop.sha,
      expectedSha: juiceshop.expectedSha,
      shaMatch: juiceshop.shaMatch,
      gt: juiceshopGt,
    },
  ];

  const tools = [
    { name: 'VANTAGE', mode: 'pattern', run: (p) => runLocalVantage(p, false) },
    { name: 'VANTAGE', mode: 'semantic', run: (p) => runLocalVantage(p, true) },
    { name: 'Semgrep', mode: 'default-packs', run: (p) => runSemgrep(p) },
  ];

  const receipt = {
    date: new Date().toISOString(),
    driver: path.basename(__filename),
    scoring: 'v2 packages/vantage-bench/src/scoring.ts (LINE_TOLERANCE=5, strict suffix path, type match)',
    vantageTip: execSync('git rev-parse HEAD', { cwd: REPO, encoding: 'utf8' }).trim(),
    node: process.version,
    corpora: corpora.map((c) => ({
      id: c.id,
      path: c.path,
      sha: c.sha,
      expectedSha: c.expectedSha,
      shaMatch: c.shaMatch,
      gtCount: c.gt.vulnerabilities.length,
    })),
    rows: [],
  };

  console.log('=== Matched-v2 OSS re-run 2026-08-02 ===');
  for (const c of corpora) {
    console.log(
      `  ${c.id}: ${c.sha.slice(0, 12)} pinMatch=${c.shaMatch} GT=${c.gt.vulnerabilities.length}`
    );
  }
  console.log();

  for (const tool of tools) {
    const perCorpus = [];
    for (const c of corpora) {
      console.log(`→ ${tool.name} [${tool.mode}] on ${c.id}`);
      const run = tool.run(c.path);
      const row = scoreRow(
        `${tool.name}${tool.mode !== 'default-packs' ? `-${tool.mode}` : ''}`,
        run.toolVersion,
        c.id,
        c.label,
        c.gt,
        c.path,
        run
      );
      console.log(
        `  F1=${pct(row.f1)} TP/FP/FN=${row.tp}/${row.fp}/${row.fn} raw=${row.rawCount ?? 0} ${row.durationMs}ms` +
          (row.error ? ` ERR=${row.error.slice(0, 120)}` : '')
      );
      perCorpus.push(row);
      receipt.rows.push({ ...row, mode: tool.mode });
    }
    const f1s = perCorpus.map((r) => r.f1).filter((x) => x != null && !Number.isNaN(x));
    if (f1s.length === 2) {
      const [a, b] = f1s;
      const harmonic =
        a > 0 && b > 0 ? 2 / (1 / a + 1 / b) : a === 0 && b === 0 ? 0 : a === 0 || b === 0 ? 0 : null;
      console.log(`  AGGREGATE harmonic F1=${pct(harmonic)}`);
      receipt.rows.push({
        tool: tool.name,
        mode: tool.mode,
        corpus: 'aggregate',
        f1: harmonic,
        note: 'harmonic mean of per-corpus F1',
      });
    }
    console.log();
  }

  // SonarQube probe
  let sonarStatus = 'skipped';
  try {
    execSync('which sonar-scanner', { stdio: 'pipe' });
    sonarStatus = 'scanner-present-not-run-needs-server';
  } catch {
    sonarStatus = 'scanner-not-found';
  }
  try {
    execSync('docker info', { stdio: 'pipe' });
    receipt.docker = 'available';
  } catch {
    receipt.docker = 'unavailable';
  }
  receipt.sonarQube = { status: sonarStatus };

  const outPath = path.join(OUT_DIR, 'receipt-v2-matched-oss-2026-08-02.json');
  fs.writeFileSync(outPath, JSON.stringify(receipt, null, 2));
  console.log('Receipt:', outPath);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

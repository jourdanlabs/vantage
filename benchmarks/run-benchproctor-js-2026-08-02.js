#!/usr/bin/env node
/**
 * BenchProctor JS/TS re-cert driver — 2026-08-02
 *
 * Runs VANTAGE (pattern and --semantic as SEPARATE rows) against pinned
 * BenchProctor suites, emits SARIF 2.1.0, scores with the shipped
 * score_sarif.py. Does not merge pattern/semantic.
 *
 * Usage:
 *   node benchmarks/run-benchproctor-js-2026-08-02.js \
 *     --corpus-root /path/to/corpus/js-quicktest \
 *     --out-dir /path/to/receipts/benchproctor \
 *     [--frameworks express,koa] \
 *     [--modes pattern,semantic] \
 *     [--match-mode cwe|filename|both]
 *
 * Environment:
 *   VANTAGE_BIN  optional override (default: node <repo>/bin/vantage.js)
 */

const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const REPO = path.resolve(__dirname, '..');
const VANTAGE_BIN = process.env.VANTAGE_BIN || `node ${path.join(REPO, 'bin', 'vantage.js')}`;
const DEFAULT_MATCH = 'both';

function parseArgs(argv) {
  const out = {
    corpusRoot: null,
    outDir: path.join(REPO, 'benchmarks', 'results', 'benchproctor-2026-08-02'),
    frameworks: null, // null = all dirs with testcode/
    modes: ['pattern', 'semantic'],
    matchMode: DEFAULT_MATCH,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--corpus-root') out.corpusRoot = path.resolve(argv[++i]);
    else if (a === '--out-dir') out.outDir = path.resolve(argv[++i]);
    else if (a === '--frameworks') out.frameworks = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--modes') out.modes = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--match-mode') out.matchMode = argv[++i];
    else if (a === '--help' || a === '-h') {
      console.log(fs.readFileSync(__filename, 'utf8').split('\n').slice(2, 22).join('\n'));
      process.exit(0);
    }
  }
  if (!out.corpusRoot) {
    console.error('Required: --corpus-root <dir containing express|koa|... suites>');
    process.exit(2);
  }
  return out;
}

function listFrameworks(corpusRoot, filter) {
  const entries = fs.readdirSync(corpusRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .filter((name) => fs.existsSync(path.join(corpusRoot, name, 'testcode')));
  if (!filter) return entries.sort();
  return filter.filter((f) => entries.includes(f));
}

function findScorer(corpusRoot) {
  const candidates = [
    path.join(corpusRoot, 'score_sarif.py'),
    path.join(corpusRoot, '..', 'score_sarif.py'),
    path.join(REPO, '..', 'BenchProctor', 'scripts', 'score_sarif.py'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return path.resolve(c);
  }
  throw new Error('score_sarif.py not found near corpus');
}

/**
 * Stage a scan root that contains only scored cases + small companions.
 * BenchProctor normal size ships multi-MB routes.js wiring files that are
 * NOT answer-key cases; analyzing them tanks NOVA/PULSAR and is out of scope
 * for scoring (companions are not labeled). We hardlink benchmark_test_* +
 * small shared.* only.
 */
function prepareScanRoot(testcode) {
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'bp-scan-'));
  const names = fs.readdirSync(testcode);
  let linked = 0;
  let skipped = 0;
  for (const name of names) {
    const src = path.join(testcode, name);
    let st;
    try {
      st = fs.statSync(src);
    } catch {
      continue;
    }
    if (!st.isFile()) continue;
    const isCase = /^benchmark_test_\d+\.(js|ts|mjs|cjs)$/i.test(name);
    const isSmallShared =
      /^shared\./i.test(name) && st.size < 100_000; // shared.js is ~2KB; routes.js is multi-MB
    if (!isCase && !isSmallShared) {
      skipped++;
      continue;
    }
    const dst = path.join(stage, name);
    try {
      fs.linkSync(src, dst);
    } catch {
      fs.copyFileSync(src, dst);
    }
    linked++;
  }
  return { stage, linked, skipped };
}

function runVantageJson(target, outJson, mode) {
  const args = ['analyze', target, '--format', 'json', '--output', outJson];
  if (mode === 'semantic') args.push('--semantic');
  const parts = VANTAGE_BIN.split(/\s+/);
  const cmd = parts[0];
  const baseArgs = parts.slice(1);
  const started = Date.now();
  const r = spawnSync(cmd, [...baseArgs, ...args], {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    env: {
      ...process.env,
      // Skip NOVA/ECLIPSE graph — BP only scores security SARIF findings.
      VANTAGE_BENCH_FAST: process.env.VANTAGE_BENCH_FAST || '1',
    },
  });
  const durationMs = Date.now() - started;
  if (r.status !== 0) {
    return {
      ok: false,
      durationMs,
      stderr: (r.stderr || r.stdout || '').slice(-4000),
      status: r.status,
    };
  }
  return { ok: true, durationMs, status: 0 };
}

function jsonToSarif(jsonPath, sarifPath, scanRoot, mode) {
  const r = spawnSync(
    process.execPath,
    [path.join(REPO, 'benchmarks', 'json-to-sarif.js'), jsonPath, sarifPath, scanRoot],
    {
      encoding: 'utf8',
      env: { ...process.env, VANTAGE_MODE: mode },
    }
  );
  if (r.status !== 0) {
    throw new Error(`json-to-sarif failed: ${r.stderr || r.stdout}`);
  }
  return JSON.parse(r.stdout || '{}');
}

function scoreSarif(scorer, sarif, csv, matchMode, logPath) {
  const args = [scorer, sarif, csv];
  if (matchMode && matchMode !== 'cwe') {
    args.push('--match-mode', matchMode);
  }
  const r = spawnSync('python3', args, {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  fs.writeFileSync(logPath, r.stdout + (r.stderr || ''));
  // Parse summary numbers
  const text = r.stdout || '';
  const flat = text.match(/Flat Score:\s+([+\-]?[\d.]+)%/);
  const macro = text.match(/Category-Averaged:\s+([+\-]?[\d.]+)%/);
  const totalLine = text.split('\n').find((l) => l.startsWith('TOTAL'));
  let tpr = null, fpr = null, tp = null, fp = null, fn = null, tn = null;
  if (totalLine) {
    // TOTAL                   132   88    2968  3012     4.3%    2.8%   +1.4%
    const m = totalLine.match(/TOTAL\s+\S*\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)%\s+([\d.]+)%\s+([+\-]?[\d.]+)%/);
    if (m) {
      tp = +m[1]; fp = +m[2]; fn = +m[3]; tn = +m[4];
      tpr = +m[5] / 100; fpr = +m[6] / 100;
    }
  }
  return {
    status: r.status,
    flatScorePct: flat ? +flat[1] : null,
    macroScorePct: macro ? +macro[1] : null,
    tpr, fpr, tp, fp, fn, tn,
    logPath,
  };
}

function vantageVersion() {
  try {
    return JSON.parse(fs.readFileSync(path.join(REPO, 'package.json'), 'utf8')).version;
  } catch {
    return 'unknown';
  }
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  fs.mkdirSync(opts.outDir, { recursive: true });
  const scorer = findScorer(opts.corpusRoot);
  const frameworks = listFrameworks(opts.corpusRoot, opts.frameworks);
  if (!frameworks.length) {
    console.error('No frameworks found under', opts.corpusRoot);
    process.exit(1);
  }

  const matchModes = opts.matchMode === 'both' ? ['cwe', 'filename'] : [opts.matchMode];
  const receipt = {
    date: new Date().toISOString(),
    driver: path.basename(__filename),
    vantageVersion: vantageVersion(),
    vantageTip: execSync('git rev-parse HEAD', { cwd: REPO, encoding: 'utf8' }).trim(),
    corpusRoot: opts.corpusRoot,
    scorer,
    node: process.version,
    platform: `${os.platform()} ${os.release()}`,
    rows: [],
  };

  console.log(`VANTAGE ${receipt.vantageVersion} @ ${receipt.vantageTip.slice(0, 8)}`);
  console.log(`Corpus: ${opts.corpusRoot}`);
  console.log(`Frameworks: ${frameworks.join(', ')}`);
  console.log(`Modes: ${opts.modes.join(', ')}`);
  console.log(`Match modes: ${matchModes.join(', ')}`);
  console.log();

  for (const fw of frameworks) {
    const testcode = path.join(opts.corpusRoot, fw, 'testcode');
    const csvCandidates = fs.readdirSync(path.join(opts.corpusRoot, fw))
      .filter((f) => f.startsWith('expectedresults') && f.endsWith('.csv'));
    if (!csvCandidates.length) {
      console.error(`No expectedresults CSV for ${fw}`);
      continue;
    }
    const csv = path.join(opts.corpusRoot, fw, csvCandidates[0]);

    for (const mode of opts.modes) {
      const tag = `${fw}-${mode}`;
      const sarifPath = path.join(opts.outDir, `vantage-${tag}.sarif`);
      const jsonPath = path.join(opts.outDir, `vantage-${tag}.json`);
      const staged = prepareScanRoot(testcode);
      console.log(
        `→ ${tag}: scanning ${staged.linked} case files (skipped ${staged.skipped} companions) from ${testcode}`
      );
      const run = runVantageJson(staged.stage, jsonPath, mode);
      if (!run.ok) {
        console.error(`  FAIL scan: status=${run.status}`);
        console.error(run.stderr);
        try {
          fs.rmSync(staged.stage, { recursive: true, force: true });
        } catch {}
        receipt.rows.push({ framework: fw, mode, error: run.stderr, durationMs: run.durationMs });
        continue;
      }
      let convertMeta = null;
      try {
        // URI base = staged root (relative paths are still benchmark_test_NNNNN.ext)
        convertMeta = jsonToSarif(jsonPath, sarifPath, staged.stage, mode);
      } catch (e) {
        console.error(`  FAIL sarif convert: ${e.message}`);
        try {
          fs.rmSync(staged.stage, { recursive: true, force: true });
        } catch {}
        receipt.rows.push({ framework: fw, mode, error: String(e), durationMs: run.durationMs });
        continue;
      }
      try {
        fs.rmSync(staged.stage, { recursive: true, force: true });
      } catch {}

      // hand-check N findings ↔ N results (same run)
      let handcheck = null;
      try {
        const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
        const report = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
        const nJson = (report.pulsar?.adversarialFindings || []).length;
        const nSarif = (sarif.runs?.[0]?.results || []).length;
        const sample = (report.pulsar?.adversarialFindings || []).slice(0, 5).map((f, i) => {
          const r = sarif.runs[0].results[i];
          const uri = r?.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
          const line = r?.locations?.[0]?.physicalLocation?.region?.startLine;
          return {
            type: f.type,
            jsonLine: f.line,
            sarifLine: line,
            uri,
            lineMatch: line === (f.line || 1),
            relative: uri && !uri.startsWith('file://') && !path.isAbsolute(uri),
          };
        });
        handcheck = {
          nJson,
          nSarif,
          countMatch: nJson === nSarif,
          sample,
          convertMeta,
        };
        console.log(`  findings JSON=${nJson} SARIF=${nSarif} match=${nJson === nSarif} (${run.durationMs} ms)`);
      } catch (e) {
        handcheck = { error: String(e) };
      }

      const scores = {};
      for (const mm of matchModes) {
        const logPath = path.join(opts.outDir, `score-${tag}-${mm}.txt`);
        scores[mm] = scoreSarif(scorer, sarifPath, csv, mm, logPath);
        console.log(
          `  score[${mm}]: flat=${scores[mm].flatScorePct}% TPR=${scores[mm].tpr} FPR=${scores[mm].fpr} ` +
          `TP/FP/FN/TN=${scores[mm].tp}/${scores[mm].fp}/${scores[mm].fn}/${scores[mm].tn}`
        );
      }

      receipt.rows.push({
        framework: fw,
        mode,
        durationMs: run.durationMs,
        sarifPath,
        jsonPath,
        csv,
        handcheck,
        scores,
      });
    }
  }

  const outJson = path.join(opts.outDir, 'receipt-benchproctor-2026-08-02.json');
  fs.writeFileSync(outJson, JSON.stringify(receipt, null, 2));
  console.log();
  console.log('Receipt:', outJson);
}

main();

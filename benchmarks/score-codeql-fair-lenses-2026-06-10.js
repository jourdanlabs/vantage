#!/usr/bin/env node
// Scoring-only pass over the FAIR re-run SARIFs (no DB rebuild).
// Produces three honest lenses per corpus from the PROPERLY-BUILT CodeQL DBs:
//   1. security-and-quality FULL          (broad suite, as the prior run used)
//   2. security-extended FULL             (true security-only suite)
//   3. codefixes-excluded                 (drop data/static/codefixes/** — Juice Shop's
//                                          intentionally-broken challenge-fix FIXTURE snippets,
//                                          which tsconfig itself excludes from the build and
//                                          which BOTH tools FP on; the documented honest scope).
// The codefixes-excluded lens is applied to the security-extended SARIF (the security lens)
// AND, for symmetry, re-derives VANTAGE pattern/semantic Juice Shop scores with codefixes dropped.

const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');

const BENCH = path.join(__dirname, '..', 'packages', 'vantage-bench');
require(path.join(BENCH, 'node_modules', 'ts-node')).register({
  project: path.join(BENCH, 'tsconfig.json'), transpileOnly: true,
});
const { getCorpora } = require(path.join(BENCH, 'src', 'corpus'));
const { scoreFindings } = require(path.join(BENCH, 'src', 'scoring'));
const { normalizeType, toCorpusRelativePosix } = require(path.join(BENCH, 'src', 'runners', 'base'));

const RESULTS = path.join(__dirname, 'results');
const CODEFIXES = 'data/static/codefixes/';

function parseSarif(file, targetPath) {
  const sarif = JSON.parse(fs.readFileSync(file, 'utf8'));
  const findings = [];
  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const loc = result.locations?.[0]?.physicalLocation;
      findings.push({
        file: toCorpusRelativePosix(targetPath, loc?.artifactLocation?.uri ?? ''),
        line: loc?.region?.startLine ?? 0,
        type: normalizeType(result.ruleId ?? ''),
        severity: 'MED',
        description: result.message?.text ?? result.ruleId,
        rawType: result.ruleId ?? '',
      });
    }
  }
  return findings;
}

function score(findings, corpus) {
  const m = scoreFindings(findings, corpus.groundTruth, corpus.analysisPath);
  return { tp: m.tp.length, fp: m.fp.length, fn: m.fn.length, precision: m.precision, recall: m.recall, f1: m.f1 };
}
const pct = n => n === null ? 'N/A' : (n * 100).toFixed(1) + '%';
const fmt = s => `F1=${pct(s.f1)} (TP=${s.tp}/FP=${s.fp}/FN=${s.fn}) P=${pct(s.precision)} R=${pct(s.recall)}`;

// harmonic aggregate matching the harness (any 0 → 0, any null → null)
function agg(f1s) {
  if (f1s.some(f => f === null)) return null;
  if (f1s.some(f => f === 0)) return 0;
  return f1s.length / f1s.reduce((a, b) => a + 1 / b, 0);
}

function main() {
  const corpora = getCorpora();
  const byId = Object.fromEntries(corpora.map(c => [c.id, c]));
  const out = {};

  for (const c of corpora) {
    const base = path.basename(c.analysisPath);
    const saqFile = path.join(RESULTS, `codeql-fair_${base}_security-and-quality_2026-06-10.sarif`);
    const secFile = path.join(RESULTS, `codeql-fair_${base}_security-extended_2026-06-10.sarif`);
    const saq = parseSarif(saqFile, c.analysisPath);
    const sec = parseSarif(secFile, c.analysisPath);

    const saqScore = score(saq, c);
    const secScore = score(sec, c);
    // codefixes-excluded on the security-extended findings
    const secNoCf = score(sec.filter(f => !f.file.startsWith(CODEFIXES)), c);

    out[c.id] = {
      label: c.corpusLabel || c.label,
      codeql_saq_full: saqScore,
      codeql_sec_full: secScore,
      codeql_sec_noCodefixes: secNoCf,
      syntaxErrorsInSaq: saq.filter(f => f.rawType === 'js/syntax-error').length,
      syntaxErrorsInSec: sec.filter(f => f.rawType === 'js/syntax-error').length,
    };
    console.log(`\n${c.label} — CodeQL (properly built)`);
    console.log(`  security-and-quality FULL : ${fmt(saqScore)}  [syntax-error findings: ${out[c.id].syntaxErrorsInSaq}]`);
    console.log(`  security-extended FULL     : ${fmt(secScore)}  [syntax-error findings: ${out[c.id].syntaxErrorsInSec}]`);
    console.log(`  security-extended − codefixes: ${fmt(secNoCf)}`);
  }

  // VANTAGE codefixes-excluded (symmetry): re-derive Juice Shop pattern + semantic with codefixes dropped.
  const vb = JSON.parse(fs.readFileSync(path.join(RESULTS, 'internal_baseline_2026-06-10.json'), 'utf8'));
  const vantageOut = {};
  for (const entry of vb.results) {
    const tool = entry.tool;
    if (!['VANTAGE', 'VANTAGE-semantic'].includes(tool)) continue;
    vantageOut[tool] = {};
    for (const s of entry.scores) {
      const c = byId[s.corpus];
      // reconstruct findings list from tp+fp details (fn are GT, not findings)
      const findings = [];
      for (const t of s.tpDetails) findings.push({ file: t.file, line: t.line, type: (t.type || '').toLowerCase(), rawType: t.type });
      for (const f of s.fpDetails) findings.push({ file: f.file, line: f.line, type: (f.type || '').toLowerCase(), rawType: f.type });
      const full = score(findings, c);
      const noCf = score(findings.filter(f => !f.file.startsWith(CODEFIXES)), c);
      vantageOut[tool][s.corpus] = { full, noCodefixes: noCf };
    }
  }
  out._vantage = vantageOut;

  // Aggregates for the headline comparison (codefixes-excluded, security-extended for CodeQL)
  const ng = out['nodegoat'], js = out['juice-shop'];
  const aggregates = {
    codeql_saq_full: agg([ng.codeql_saq_full.f1, js.codeql_saq_full.f1]),
    codeql_sec_full: agg([ng.codeql_sec_full.f1, js.codeql_sec_full.f1]),
    codeql_sec_noCodefixes: agg([ng.codeql_sec_noCodefixes.f1, js.codeql_sec_noCodefixes.f1]),
    vantage_pattern_full: agg([vantageOut['VANTAGE']['nodegoat'].full.f1, vantageOut['VANTAGE']['juice-shop'].full.f1]),
    vantage_pattern_noCodefixes: agg([vantageOut['VANTAGE']['nodegoat'].noCodefixes.f1, vantageOut['VANTAGE']['juice-shop'].noCodefixes.f1]),
    vantage_semantic_full: agg([vantageOut['VANTAGE-semantic']['nodegoat'].full.f1, vantageOut['VANTAGE-semantic']['juice-shop'].full.f1]),
    vantage_semantic_noCodefixes: agg([vantageOut['VANTAGE-semantic']['nodegoat'].noCodefixes.f1, vantageOut['VANTAGE-semantic']['juice-shop'].noCodefixes.f1]),
  };
  out._aggregates = aggregates;

  console.log(`\n=== AGGREGATE F1 (harmonic, null/zero-propagating) ===`);
  for (const [k, v] of Object.entries(aggregates)) console.log(`  ${k.padEnd(34)}: ${pct(v)}`);

  fs.writeFileSync(path.join(RESULTS, 'codeql_fair_lenses_2026-06-10.json'), JSON.stringify(out, null, 2));
  console.log(`\nWritten: ${path.join(RESULTS, 'codeql_fair_lenses_2026-06-10.json')}`);
}
main();

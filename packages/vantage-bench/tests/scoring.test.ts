// Quick correctness check for the new scoring rule.
// Run with: npx ts-node scoring-test.ts
// Exits 0 on pass, 1 on fail.

import { scoreFindings } from '../src/scoring';
import { Finding } from '../src/runners/base';
import { CorpusGroundTruth } from '../src/ground-truth/schema';

const targetPath = '/tmp/test-corpus';

const gt: CorpusGroundTruth = {
  corpus: 'test',
  label: 'Test',
  repo: '',
  sha: '',
  license: 'MIT',
  groundTruthLicense: 'CC-BY-4.0',
  groundTruthVersion: '2026-04-19',
  vulnerabilities: [
    {
      id: 'gt-1',
      file: 'app/foo/bar.js',
      line: 30,
      type: 'injection',
      category: 'eval-injection',
      description: 'real vuln in app/foo/bar.js',
    },
    {
      id: 'gt-2',
      file: 'lib/codingChallenges.ts',
      line: 76,
      type: 'injection',
      category: 'redos',
      description: 'redos in codingChallenges',
    },
    {
      id: 'gt-3',
      file: 'app/middleware/csrf.js',
      line: 0,
      type: 'csrf',
      category: 'missing-csrf',
      description: 'whole-file: no CSRF middleware',
      scope: 'project',
    },
  ],
};

type Case = { name: string; findings: Finding[]; expectTP: string[]; expectFP: number; expectFN: string[] };

const cases: Case[] = [
  {
    name: 'exact match → TP',
    findings: [{ file: 'app/foo/bar.js', line: 30, type: 'injection', severity: 'HIGH', description: 'x' }],
    expectTP: ['gt-1'],
    expectFP: 0,
    expectFN: ['gt-2', 'gt-3'],
  },
  {
    name: 'within ±5 lines → TP',
    findings: [{ file: 'app/foo/bar.js', line: 34, type: 'injection', severity: 'HIGH', description: 'x' }],
    expectTP: ['gt-1'],
    expectFP: 0,
    expectFN: ['gt-2', 'gt-3'],
  },
  {
    name: 'basename collision (same name, different dir) → FP + FN, NOT TP',
    findings: [{ file: 'app/baz/bar.js', line: 30, type: 'injection', severity: 'HIGH', description: 'x' }],
    expectTP: [],
    expectFP: 1,
    expectFN: ['gt-1', 'gt-2', 'gt-3'],
  },
  {
    name: 'path-prefix masquerade (foobar.js) → FP, NOT TP',
    findings: [{ file: 'app/foo/foobar.js', line: 30, type: 'injection', severity: 'HIGH', description: 'x' }],
    expectTP: [],
    expectFP: 1,
    expectFN: ['gt-1', 'gt-2', 'gt-3'],
  },
  {
    name: 'off-by-many lines (line 76 vs 50) → FP + FN',
    findings: [{ file: 'lib/codingChallenges.ts', line: 50, type: 'injection', severity: 'MED', description: 'x' }],
    expectTP: [],
    expectFP: 1,
    expectFN: ['gt-1', 'gt-2', 'gt-3'],
  },
  {
    name: 'project-scope GT matches any line in file',
    findings: [{ file: 'app/middleware/csrf.js', line: 999, type: 'csrf', severity: 'MED', description: 'missing csurf' }],
    expectTP: ['gt-3'],
    expectFP: 0,
    expectFN: ['gt-1', 'gt-2'],
  },
  {
    name: 'project-scope GT does NOT match a different file with line=0 (no wildcard leak)',
    findings: [{ file: 'app/other/thing.js', line: 0, type: 'csrf', severity: 'MED', description: 'unrelated' }],
    expectTP: [],
    expectFP: 1,
    expectFN: ['gt-1', 'gt-2', 'gt-3'],
  },
  {
    name: 'absolute path gets normalized → TP',
    findings: [{ file: '/tmp/test-corpus/app/foo/bar.js', line: 30, type: 'injection', severity: 'HIGH', description: 'x' }],
    expectTP: ['gt-1'],
    expectFP: 0,
    expectFN: ['gt-2', 'gt-3'],
  },
];

let pass = 0;
let fail = 0;

for (const c of cases) {
  const r = scoreFindings(c.findings, gt, targetPath);
  const gotTP = r.tp.map(t => t.gt.id).sort();
  const expectTPSorted = [...c.expectTP].sort();
  const gotFN = r.fn.map(e => e.id).sort();
  const expectFNSorted = [...c.expectFN].sort();

  const tpOk = JSON.stringify(gotTP) === JSON.stringify(expectTPSorted);
  const fpOk = r.fp.length === c.expectFP;
  const fnOk = JSON.stringify(gotFN) === JSON.stringify(expectFNSorted);

  if (tpOk && fpOk && fnOk) {
    console.log(`  ✓ ${c.name}`);
    pass++;
  } else {
    console.log(`  ✗ ${c.name}`);
    console.log(`    expected TP=${JSON.stringify(expectTPSorted)} FP=${c.expectFP} FN=${JSON.stringify(expectFNSorted)}`);
    console.log(`    got      TP=${JSON.stringify(gotTP)} FP=${r.fp.length} FN=${JSON.stringify(gotFN)}`);
    fail++;
  }
}

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);

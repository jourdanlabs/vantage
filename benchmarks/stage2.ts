/**
 * VANTAGE Stage 2 Benchmark — Correctness
 *
 * Four test suites:
 *
 *   A. PULSAR precision/recall on deliberately-vulnerable corpora
 *        - OWASP/NodeGoat  (callback-style Express, OWASP Top-10 intentional vulns)
 *        - bkimminich/juice-shop  (TypeScript, full challenge vuln set)
 *      Ground truth is broken into two tiers:
 *        Tier-1 (PULSAR scope): async error handling, JSON.parse, promise chains
 *        Tier-2 (out of PULSAR scope): injection, hardcoded secrets — documented as capability gap
 *
 *   B. NOVA circular-dependency detection — 5 synthetic TypeScript scenarios
 *        1. Linear chain A→B  (no cycle expected)
 *        2. 2-cycle  A→B→A  (1 cycle expected)
 *        3. 3-cycle  A→B→C→A  (1 cycle expected)
 *        4. Diamond  A→B, A→C, B→D, C→D  (no cycle expected)
 *        5. Embedded cycle  A→B→C, B→A  (1 cycle expected)
 *
 *   C. NOVA god-module boundary conditions
 *        499 lines + 9 exports   → NOT a god module
 *        500 lines + 9 exports   → NOT a god module (threshold is >500)
 *        501 lines + 8 exports   → NOT a god module (threshold is >8)
 *        501 lines + 9 exports   → IS a god module
 *        501 lines + 50 exports  → IS a god module (stress)
 *
 *   D. Clean-baseline regression
 *        expressjs/express — already APPROVED in Stage 1; must remain APPROVED
 *
 * Usage:
 *   cd /Users/sokpyeon/projects/vantage
 *   npx ts-node benchmarks/stage2.ts
 *
 * Output:
 *   benchmarks/results/stage2.json
 */

import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

import { runMETEOR } from '../src/engines/meteor';
import { runNOVA } from '../src/engines/nova';
import { runECLIPSE } from '../src/engines/eclipse';
import { runPULSAR } from '../src/engines/pulsar';
import { runAURORA } from '../src/engines/aurora';
import { MeteorOutput, NovaOutput, EclipseOutput, PulsarOutput } from '../src/types';

// ── Ground truth catalog ──────────────────────────────────────────────────────
//
// Tier-1: patterns PULSAR is designed to detect.
// Each entry: { file (relative to corpus root), type, note }
// A PULSAR finding is TP if its file path ends with or contains `file`
// and its `type` field matches.
//
// Tier-2: known security vulns outside PULSAR scope — documented only.

interface GroundTruthEntry {
  file: string;          // path fragment to match (substring of finding.file)
  type: string;          // PULSAR finding type
  description: string;
}

interface SecurityVuln {
  file: string;
  line: number;
  category: string;
  description: string;
  pulsarDetectable: boolean;
}

interface CorpusGroundTruth {
  id: string;
  tier1: GroundTruthEntry[];
  tier2SecurityVulns: SecurityVuln[];
}

const GROUND_TRUTH: CorpusGroundTruth[] = [
  {
    id: 'nodegoat',
    tier1: [
      // eval() on user-controlled input — 3 adjacent lines, dedup collapses L33+L34 → 2 PULSAR findings
      // (dedup uses floor(line/3) buckets; L32→10, L33→11, L34→11 → 2 unique findings expected)
      {
        file: 'app/routes/contributions.js',
        type: 'injection',
        description: 'eval() on user-controlled req.body.preTax — arbitrary JS execution (L32)',
      },
      {
        file: 'app/routes/contributions.js',
        type: 'injection',
        description: 'eval() on user-controlled req.body.afterTax/roth (L33-34, dedup to 1 finding)',
      },
      // NoSQL $where injection
      {
        file: 'app/data/allocations-dao.js',
        type: 'injection',
        description: '$where query with template literal from userId — NoSQL injection (L73)',
      },
      {
        file: 'app/data/allocations-dao.js',
        type: 'injection',
        description: '$where query with string concat from threshold — NoSQL injection (L78)',
      },
    ],
    tier2SecurityVulns: [
      // Remaining documented vulns still outside PULSAR scope
      {
        file: 'app/routes/session.js',
        line: 0,
        category: 'broken-authentication',
        description: 'Weak session management and CSRF — PULSAR has no CSRF detection',
        pulsarDetectable: false,
      },
    ],
  },
  {
    id: 'juiceshop',
    tier1: [
      // Hardcoded secrets — now detected by new patterns
      {
        file: 'lib/insecurity.ts',
        type: 'hardcoded-secret',
        description: 'RSA private key hardcoded (-----BEGIN RSA PRIVATE KEY-----) at L23',
      },
      {
        file: 'lib/insecurity.ts',
        type: 'hardcoded-secret',
        description: 'HMAC secret "pa4qacea4VK9t9nGv7yZtwmj" via createHmac() at L44',
      },
      // NoSQL $where injection
      {
        file: 'routes/trackOrder.ts',
        type: 'injection',
        description: '$where: `this.orderId === \'${id}\'` — NoSQL injection via template literal (L18)',
      },
      {
        file: 'routes/showProductReviews.ts',
        type: 'injection',
        description: "$where: 'this.product == ' + id — NoSQL injection via string concat (L36)",
      },
      // ReDoS
      {
        file: 'lib/codingChallenges.ts',
        type: 'injection',
        description: 'new RegExp() with user-controlled challengeKey — potential ReDoS (L76)',
      },
      // JSON.parse without try/catch — robustness findings
      {
        file: 'routes/languages.ts',
        type: 'error-boundary',
        description: 'JSON.parse() at L18 without try/catch',
      },
      {
        file: 'routes/verify.ts',
        type: 'error-boundary',
        description: 'JSON.parse() at L128 without try/catch',
      },
      {
        file: 'routes/chatbot.ts',
        type: 'error-boundary',
        description: 'JSON.parse() of training set without try/catch',
      },
      {
        file: 'routes/recycles.ts',
        type: 'error-boundary',
        description: 'JSON.parse() on req.params.id without try/catch',
      },
    ],
    tier2SecurityVulns: [
      // Still outside PULSAR detection scope
      {
        file: 'routes/login.ts',
        line: 34,
        category: 'sql-injection',
        description: 'Unparameterized Sequelize query: `SELECT * WHERE email = \'${req.body.email}\'` — SQL injection',
        pulsarDetectable: false,
      },
      // Note: insecurity.ts PEM key, insecurity.ts HMAC, trackOrder.ts $where,
      // showProductReviews.ts $where, and codingChallenges.ts ReDoS are now
      // detected (tier1) — removed from tier2 to avoid double-counting.

      {
        file: 'routes/userProfile.ts',
        line: 62,
        category: 'code-injection',
        description: 'eval(code) where code is from user-supplied profile field — username injection challenge',
        pulsarDetectable: true,  // detected as MED (variable name not in user-controlled keyword list)
      },
      {
        file: 'routes/captcha.ts',
        line: 22,
        category: 'eval-safe',
        description: 'eval(mathExpression) — expression is constructed from random numbers, NOT user-controlled',
        pulsarDetectable: true,  // FP: VANTAGE flags MED (correctly uncertain); actual impact: none
      },
    ],
  },
];

// ── Full pipeline run returning raw engine outputs ────────────────────────────

interface PipelineResult {
  meteor: MeteorOutput;
  nova: NovaOutput;
  eclipse: EclipseOutput;
  pulsar: PulsarOutput;
  aurora: Awaited<ReturnType<typeof runAURORA>>;
  totalMs: number;
  engineMs: Record<string, number>;
}

async function runPipeline(targetPath: string): Promise<PipelineResult> {
  const t0 = performance.now();

  const tM = performance.now();
  const meteor = await runMETEOR(targetPath);
  const meteorMs = performance.now() - tM;

  const tN = performance.now();
  const nova = await runNOVA(meteor);
  const novaMs = performance.now() - tN;

  const tE = performance.now();
  const eclipse = await runECLIPSE(meteor, nova);
  const eclipseMs = performance.now() - tE;

  const tP = performance.now();
  const pulsar = await runPULSAR(meteor, eclipse);
  const pulsarMs = performance.now() - tP;

  const tA = performance.now();
  const aurora = await runAURORA(meteor, nova, eclipse, pulsar);
  const auroraMs = performance.now() - tA;

  return {
    meteor, nova, eclipse, pulsar, aurora,
    totalMs: performance.now() - t0,
    engineMs: {
      METEOR: meteorMs, NOVA: novaMs, ECLIPSE: eclipseMs,
      PULSAR: pulsarMs, AURORA: auroraMs,
    },
  };
}

// ── PULSAR precision/recall computation ──────────────────────────────────────

interface PrecisionRecallResult {
  corpusId: string;
  label: string;
  pipelineStats: {
    files: number;
    loc: number;
    functions: number;
    circularDeps: number;
    godModules: number;
    highRiskFiles: number;
    medRiskFiles: number;
    pulsarTargetFiles: number;
    totalPulsarFindings: number;
    highFindings: number;
    medFindings: number;
    lowFindings: number;
  };
  auroraScore: number;
  auroraVerdict: string;
  auroraBreakdown: {
    complexityScore: number;
    dependencyScore: number;
    riskScore: number;
    adversarialScore: number;
  };
  tier1: {
    groundTruthCount: number;
    tp: number;
    fp: number;
    fn: number;
    precision: number | null;
    recall: number | null;
    f1: number | null;
    tpDetails: Array<{ file: string; type: string; line?: number }>;
    fpDetails: Array<{ file: string; type: string; line?: number }>;
    fnDetails: Array<{ file: string; type: string; description: string }>;
  };
  tier2CapabilityGap: {
    knownVulnCount: number;
    pulsarDetectableCount: number;
    pulsarUndetectableCount: number;
    vulns: SecurityVuln[];
  };
  totalMs: number;
  engineMs: Record<string, number>;
}

function computePrecisionRecall(
  corpusId: string,
  label: string,
  pipeline: PipelineResult,
  gt: CorpusGroundTruth
): PrecisionRecallResult {
  const { meteor, nova, eclipse, pulsar, aurora } = pipeline;
  const findings = pulsar.adversarialFindings;

  // Tier-1: map findings to ground truth
  const tier1GT = gt.tier1;

  const tpFindings: typeof findings = [];
  const fpFindings: typeof findings = [];

  for (const f of findings) {
    const isTP = tier1GT.some(gt =>
      f.file.includes(gt.file) && f.type === gt.type
    );
    if (isTP) {
      tpFindings.push(f);
    } else {
      fpFindings.push(f);
    }
  }

  // FN: ground truth entries that were NOT matched by any finding
  const fnEntries = tier1GT.filter(gtEntry =>
    !findings.some(f => f.file.includes(gtEntry.file) && f.type === gtEntry.type)
  );

  const tp = tpFindings.length;
  const fp = fpFindings.length;
  const fn = fnEntries.length;

  const precision = (tp + fp) > 0 ? tp / (tp + fp) : null;
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : null;
  const f1 = (precision !== null && recall !== null && (precision + recall) > 0)
    ? 2 * precision * recall / (precision + recall)
    : null;

  // Eclipse stats
  const highRisk = eclipse.highRisk ?? [];
  const medRisk = eclipse.medRisk ?? [];
  const pulsarTargetFiles = new Set([
    ...highRisk.map((r: any) => r.file),
    ...medRisk.map((r: any) => r.file),
  ]).size;

  return {
    corpusId,
    label,
    pipelineStats: {
      files: meteor.files.length,
      loc: meteor.metrics.linesOfCode,
      functions: meteor.functions.length,
      circularDeps: nova.circularDeps.length,
      godModules: nova.godModules.length,
      highRiskFiles: highRisk.length,
      medRiskFiles: medRisk.length,
      pulsarTargetFiles,
      totalPulsarFindings: findings.length,
      highFindings: findings.filter((f: any) => f.severity === 'HIGH').length,
      medFindings: findings.filter((f: any) => f.severity === 'MED').length,
      lowFindings: findings.filter((f: any) => f.severity === 'LOW').length,
    },
    auroraScore: aurora.score,
    auroraVerdict: aurora.verdict,
    auroraBreakdown: {
      complexityScore: aurora.breakdown.complexityScore,
      dependencyScore: aurora.breakdown.dependencyScore,
      riskScore: aurora.breakdown.riskScore,
      adversarialScore: aurora.breakdown.adversarialScore,
    },
    tier1: {
      groundTruthCount: tier1GT.length,
      tp, fp, fn,
      precision,
      recall,
      f1,
      tpDetails: tpFindings.map(f => ({ file: f.file, type: f.type, line: f.line })),
      fpDetails: fpFindings.map(f => ({ file: f.file, type: f.type, line: f.line })),
      fnDetails: fnEntries.map(e => ({ file: e.file, type: e.type, description: e.description })),
    },
    tier2CapabilityGap: {
      knownVulnCount: gt.tier2SecurityVulns.length,
      pulsarDetectableCount: gt.tier2SecurityVulns.filter(v => v.pulsarDetectable).length,
      pulsarUndetectableCount: gt.tier2SecurityVulns.filter(v => !v.pulsarDetectable).length,
      vulns: gt.tier2SecurityVulns,
    },
    totalMs: pipeline.totalMs,
    engineMs: pipeline.engineMs,
  };
}

// ── Suite B: NOVA circular dependency tests ──────────────────────────────────

interface CircDepScenario {
  id: string;
  description: string;
  expectedCycles: number;  // minimum expected (detected cycles may be more due to representation)
  files: Array<{ name: string; content: string }>;
}

const CIRC_DEP_SCENARIOS: CircDepScenario[] = [
  {
    id: 'linear-no-cycle',
    description: 'A imports B — no cycle',
    expectedCycles: 0,
    files: [
      { name: 'a.ts', content: `import { b } from './b';\nexport const a = 'A' + b;\n` },
      { name: 'b.ts', content: `export const b = 'B';\n` },
    ],
  },
  {
    id: 'two-cycle',
    description: 'A → B → A (2-node cycle)',
    expectedCycles: 1,
    files: [
      { name: 'a.ts', content: `import { b } from './b';\nexport const a = 'A';\n` },
      { name: 'b.ts', content: `import { a } from './a';\nexport const b = 'B';\n` },
    ],
  },
  {
    id: 'three-cycle',
    description: 'A → B → C → A (3-node cycle)',
    expectedCycles: 1,
    files: [
      { name: 'a.ts', content: `import { c } from './c';\nexport const a = 'A';\n` },
      { name: 'b.ts', content: `import { a } from './a';\nexport const b = 'B';\n` },
      { name: 'c.ts', content: `import { b } from './b';\nexport const c = 'C';\n` },
    ],
  },
  {
    id: 'diamond-no-cycle',
    description: 'Diamond: A→B, A→C, B→D, C→D (no cycle)',
    expectedCycles: 0,
    files: [
      { name: 'a.ts', content: `import { b } from './b';\nimport { c } from './c';\nexport const a = 'A';\n` },
      { name: 'b.ts', content: `import { d } from './d';\nexport const b = 'B';\n` },
      { name: 'c.ts', content: `import { d } from './d';\nexport const c = 'C';\n` },
      { name: 'd.ts', content: `export const d = 'D';\n` },
    ],
  },
  {
    id: 'embedded-cycle',
    description: 'A→B→C and B→A (cycle embedded in larger graph)',
    expectedCycles: 1,
    files: [
      { name: 'a.ts', content: `import { b } from './b';\nexport const a = 'A';\n` },
      { name: 'b.ts', content: `import { a } from './a';\nimport { c } from './c';\nexport const b = 'B';\n` },
      { name: 'c.ts', content: `export const c = 'C';\n` },
    ],
  },
];

interface CircDepTestResult {
  id: string;
  description: string;
  expectedCycles: number;
  detectedCycles: number;
  pass: boolean;
  note?: string;
}

async function runCircDepTests(): Promise<CircDepTestResult[]> {
  const results: CircDepTestResult[] = [];
  const tmpBase = path.join(os.tmpdir(), 'vantage-s2-circ');
  fs.mkdirSync(tmpBase, { recursive: true });

  for (const scenario of CIRC_DEP_SCENARIOS) {
    const scenarioDir = path.join(tmpBase, scenario.id);
    fs.mkdirSync(scenarioDir, { recursive: true });

    // Write synthetic files
    for (const f of scenario.files) {
      fs.writeFileSync(path.join(scenarioDir, f.name), f.content, 'utf-8');
    }

    try {
      const meteor = await runMETEOR(scenarioDir);
      const nova = await runNOVA(meteor);
      const detected = nova.circularDeps.length;
      const pass = scenario.expectedCycles === 0
        ? detected === 0
        : detected >= scenario.expectedCycles;

      results.push({
        id: scenario.id,
        description: scenario.description,
        expectedCycles: scenario.expectedCycles,
        detectedCycles: detected,
        pass,
        note: pass ? undefined : `Expected ${scenario.expectedCycles > 0 ? '≥' + scenario.expectedCycles : '0'}, got ${detected}`,
      });
    } catch (e: any) {
      results.push({
        id: scenario.id,
        description: scenario.description,
        expectedCycles: scenario.expectedCycles,
        detectedCycles: -1,
        pass: false,
        note: `Pipeline error: ${e.message}`,
      });
    }
  }

  // Cleanup
  fs.rmSync(tmpBase, { recursive: true, force: true });
  return results;
}

// ── Suite C: NOVA god module boundary tests ───────────────────────────────────

interface GodModuleScenario {
  id: string;
  lines: number;
  exports: number;
  shouldBeGodModule: boolean;
  description: string;
}

const GOD_MODULE_SCENARIOS: GodModuleScenario[] = [
  {
    id: 'below-line-threshold',
    lines: 499, exports: 9,
    shouldBeGodModule: false,
    description: '499 lines + 9 exports — lines not > 500, should NOT fire',
  },
  {
    id: 'at-line-threshold',
    lines: 500, exports: 9,
    shouldBeGodModule: false,
    description: '500 lines + 9 exports — lines = 500 not > 500, should NOT fire',
  },
  {
    id: 'below-export-threshold',
    lines: 501, exports: 8,
    shouldBeGodModule: false,
    description: '501 lines + 8 exports — exports not > 8, should NOT fire',
  },
  {
    id: 'both-above-threshold',
    lines: 501, exports: 9,
    shouldBeGodModule: true,
    description: '501 lines + 9 exports — both > threshold, SHOULD fire',
  },
  {
    id: 'stress-large',
    lines: 501, exports: 50,
    shouldBeGodModule: true,
    description: '501 lines + 50 exports — stress case, SHOULD fire',
  },
];

function buildGodModuleFile(lines: number, exports: number): string {
  // Build a TS file with `lines` total lines and `exports` export statements.
  // Export keywords are counted via /\bexport\b/g in nova.ts.
  const parts: string[] = [];
  parts.push('// synthetic god module test');
  parts.push('');

  // Add exports first (one per line)
  for (let i = 0; i < exports; i++) {
    parts.push(`export const val${i} = ${i};`);
  }

  // Pad to target line count with comment lines
  const currentLines = parts.length;
  const needed = lines - currentLines;
  for (let i = 0; i < needed; i++) {
    parts.push(`// padding line ${i}`);
  }

  // Trim or extend to exact line count
  while (parts.length > lines) parts.pop();
  while (parts.length < lines) parts.push(`// pad`);

  return parts.join('\n') + '\n';
}

interface GodModuleTestResult {
  id: string;
  description: string;
  lines: number;
  exports: number;
  shouldBeGodModule: boolean;
  detectedAsGodModule: boolean;
  pass: boolean;
  note?: string;
}

async function runGodModuleTests(): Promise<GodModuleTestResult[]> {
  const results: GodModuleTestResult[] = [];
  const tmpBase = path.join(os.tmpdir(), 'vantage-s2-god');
  fs.mkdirSync(tmpBase, { recursive: true });

  for (const scenario of GOD_MODULE_SCENARIOS) {
    const scenarioDir = path.join(tmpBase, scenario.id);
    fs.mkdirSync(scenarioDir, { recursive: true });

    const content = buildGodModuleFile(scenario.lines, scenario.exports);
    const actualLines = content.split('\n').length - 1; // trailing \n adds one
    fs.writeFileSync(path.join(scenarioDir, 'module.ts'), content, 'utf-8');

    try {
      const meteor = await runMETEOR(scenarioDir);
      const nova = await runNOVA(meteor);
      const detected = nova.godModules.length > 0;
      const pass = detected === scenario.shouldBeGodModule;

      results.push({
        id: scenario.id,
        description: scenario.description,
        lines: actualLines,
        exports: scenario.exports,
        shouldBeGodModule: scenario.shouldBeGodModule,
        detectedAsGodModule: detected,
        pass,
        note: pass ? undefined
          : `Expected godModule=${scenario.shouldBeGodModule}, got ${detected} (actual lines=${actualLines})`,
      });
    } catch (e: any) {
      results.push({
        id: scenario.id,
        description: scenario.description,
        lines: scenario.lines,
        exports: scenario.exports,
        shouldBeGodModule: scenario.shouldBeGodModule,
        detectedAsGodModule: false,
        pass: false,
        note: `Pipeline error: ${e.message}`,
      });
    }
  }

  fs.rmSync(tmpBase, { recursive: true, force: true });
  return results;
}

// ── Suite D: clean baseline ───────────────────────────────────────────────────

interface BaselineResult {
  corpus: string;
  auroraScore: number;
  auroraVerdict: string;
  auroraBreakdown: {
    complexityScore: number;
    dependencyScore: number;
    riskScore: number;
    adversarialScore: number;
  };
  pass: boolean;
  totalMs: number;
}

// ── Output helpers ────────────────────────────────────────────────────────────

function fmt(n: number | null, decimals = 0): string {
  if (n === null) return 'N/A';
  return (n * 100).toFixed(decimals) + '%';
}

function printDivider(char = '═', width = 72) {
  console.log(char.repeat(width));
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log('\nVANTAGE STAGE 2 BENCHMARK — Correctness');
  printDivider();
  console.log(`Timestamp: ${new Date().toISOString()}`);

  const output: Record<string, any> = { generatedAt: new Date().toISOString() };

  // ── SUITE A: PULSAR on vulnerable corpora ────────────────────────────────

  console.log('\n\nSUITE A — PULSAR Precision/Recall on Vulnerable Corpora');
  printDivider();

  const suiteAResults: PrecisionRecallResult[] = [];

  const vulnCorpora = [
    { id: 'nodegoat', label: 'OWASP/NodeGoat', path: '/tmp/vantage-bench/nodegoat' },
    { id: 'juiceshop', label: 'bkimminich/juice-shop', path: '/tmp/vantage-bench/juiceshop' },
  ];

  for (const corpus of vulnCorpora) {
    console.log(`\n${'─'.repeat(72)}`);
    console.log(`CORPUS: ${corpus.label}`);
    console.log(`Path:   ${corpus.path}`);
    console.log(`${'─'.repeat(72)}`);

    if (!fs.existsSync(corpus.path)) {
      console.log(`  ✗ Path not found — skipping`);
      continue;
    }

    console.log('  Running pipeline...');
    const pipeline = await runPipeline(corpus.path);
    const gt = GROUND_TRUTH.find(g => g.id === corpus.id)!;
    const result = computePrecisionRecall(corpus.id, corpus.label, pipeline, gt);
    suiteAResults.push(result);

    const s = result.pipelineStats;
    console.log(`  ✓ ${(result.totalMs / 1000).toFixed(2)}s | ${s.files} files | ${s.loc.toLocaleString()} LOC | ${s.functions} fns`);
    console.log(`    AURORA: ${result.auroraVerdict} (${fmt(result.auroraScore)})`);
    console.log(`    Breakdown: complexity=${fmt(result.auroraBreakdown.complexityScore)} dep=${fmt(result.auroraBreakdown.dependencyScore)} risk=${fmt(result.auroraBreakdown.riskScore)} adversarial=${fmt(result.auroraBreakdown.adversarialScore)}`);
    console.log(`    ECLIPSE: ${s.highRiskFiles} high-risk, ${s.medRiskFiles} med-risk → PULSAR targets ${s.pulsarTargetFiles} files`);
    console.log(`    PULSAR: ${s.totalPulsarFindings} findings (${s.highFindings} HIGH, ${s.medFindings} MED, ${s.lowFindings} LOW)`);

    if (result.tier1.groundTruthCount === 0) {
      console.log(`\n  Tier-1 (PULSAR scope): No ground truth defined — NodeGoat uses callback style,`);
      console.log(`    async/error-boundary patterns do not apply. See capability gap notes.`);
    } else {
      console.log(`\n  Tier-1 precision/recall (PULSAR scope):`);
      console.log(`    Ground truth: ${result.tier1.groundTruthCount} entries`);
      console.log(`    TP: ${result.tier1.tp}  FP: ${result.tier1.fp}  FN: ${result.tier1.fn}`);
      console.log(`    Precision: ${fmt(result.tier1.precision, 1)}  Recall: ${fmt(result.tier1.recall, 1)}  F1: ${fmt(result.tier1.f1, 1)}`);
      if (result.tier1.tpDetails.length > 0) {
        console.log(`    TP details:`);
        for (const tp of result.tier1.tpDetails.slice(0, 5)) {
          console.log(`      + ${tp.file.split('/').slice(-2).join('/')}:${tp.line} [${tp.type}]`);
        }
        if (result.tier1.tpDetails.length > 5) {
          console.log(`      ... +${result.tier1.tpDetails.length - 5} more`);
        }
      }
      if (result.tier1.fnDetails.length > 0) {
        console.log(`    FN (missed):`);
        for (const fn of result.tier1.fnDetails) {
          console.log(`      ✗ ${fn.file} [${fn.type}] — ${fn.description}`);
        }
      }
    }

    const gap = result.tier2CapabilityGap;
    console.log(`\n  Tier-2 capability gap (${gap.knownVulnCount} OWASP/intentional vulns):`);
    console.log(`    PULSAR-detectable: ${gap.pulsarDetectableCount}  Out-of-scope: ${gap.pulsarUndetectableCount}`);
    for (const v of gap.vulns) {
      const marker = v.pulsarDetectable ? '✓' : '✗';
      console.log(`    ${marker} ${v.file.split('/').slice(-1)[0]}:${v.line} [${v.category}] ${v.pulsarDetectable ? '(detectable)' : '(out of scope)'}`);
    }
  }

  output.suiteA = suiteAResults;

  // ── SUITE B: NOVA circular dependency tests ──────────────────────────────

  console.log(`\n\n${'═'.repeat(72)}`);
  console.log('SUITE B — NOVA Circular Dependency Detection');
  printDivider('─');
  console.log('  Running 5 synthetic scenarios...');

  const circDepResults = await runCircDepTests();

  let circPass = 0;
  for (const r of circDepResults) {
    const marker = r.pass ? '✓' : '✗';
    console.log(`  ${marker} [${r.id}] ${r.description}`);
    console.log(`      Expected ≥${r.expectedCycles > 0 ? r.expectedCycles : 'none'} cycles, detected ${r.detectedCycles}`);
    if (r.note) console.log(`      NOTE: ${r.note}`);
    if (r.pass) circPass++;
  }
  console.log(`\n  Result: ${circPass}/${circDepResults.length} passed`);
  output.suiteB = { circularDepTests: circDepResults, passed: circPass, total: circDepResults.length };

  // ── SUITE C: God module boundary tests ───────────────────────────────────

  console.log(`\n\n${'═'.repeat(72)}`);
  console.log('SUITE C — NOVA God Module Boundary Conditions');
  printDivider('─');
  console.log('  Running 5 boundary scenarios...');

  const godModResults = await runGodModuleTests();

  let godPass = 0;
  for (const r of godModResults) {
    const marker = r.pass ? '✓' : '✗';
    console.log(`  ${marker} [${r.id}] ${r.description}`);
    console.log(`      lines=${r.lines} exports=${r.exports} → shouldBe=${r.shouldBeGodModule} detected=${r.detectedAsGodModule}`);
    if (r.note) console.log(`      NOTE: ${r.note}`);
    if (r.pass) godPass++;
  }
  console.log(`\n  Result: ${godPass}/${godModResults.length} passed`);
  output.suiteC = { godModuleTests: godModResults, passed: godPass, total: godModResults.length };

  // ── SUITE D: Clean baseline ───────────────────────────────────────────────

  console.log(`\n\n${'═'.repeat(72)}`);
  console.log('SUITE D — Clean Baseline Regression');
  printDivider('─');

  const cleanPath = '/tmp/vantage-bench/express';
  console.log(`  Corpus: expressjs/express (${cleanPath})`);
  console.log('  Running pipeline...');

  let baselineResult: BaselineResult;
  if (fs.existsSync(cleanPath)) {
    const pipeline = await runPipeline(cleanPath);
    const pass = pipeline.aurora.verdict === 'APPROVED';
    baselineResult = {
      corpus: 'expressjs/express',
      auroraScore: pipeline.aurora.score,
      auroraVerdict: pipeline.aurora.verdict,
      auroraBreakdown: {
        complexityScore: pipeline.aurora.breakdown.complexityScore,
        dependencyScore: pipeline.aurora.breakdown.dependencyScore,
        riskScore: pipeline.aurora.breakdown.riskScore,
        adversarialScore: pipeline.aurora.breakdown.adversarialScore,
      },
      pass,
      totalMs: pipeline.totalMs,
    };
    const marker = pass ? '✓' : '✗';
    console.log(`  ${marker} AURORA: ${pipeline.aurora.verdict} (${fmt(pipeline.aurora.score)})`);
    console.log(`     Breakdown: complexity=${fmt(pipeline.aurora.breakdown.complexityScore)} dep=${fmt(pipeline.aurora.breakdown.dependencyScore)} risk=${fmt(pipeline.aurora.breakdown.riskScore)} adversarial=${fmt(pipeline.aurora.breakdown.adversarialScore)}`);
    if (!pass) console.log(`  REGRESSION DETECTED — express was APPROVED in Stage 1`);
  } else {
    console.log('  ✗ express path not found — skipping');
    baselineResult = {
      corpus: 'expressjs/express', auroraScore: 0, auroraVerdict: 'SKIPPED',
      auroraBreakdown: { complexityScore: 0, dependencyScore: 0, riskScore: 0, adversarialScore: 0 },
      pass: false, totalMs: 0,
    };
  }
  output.suiteD = baselineResult;

  // ── Write results JSON ────────────────────────────────────────────────────

  const outPath = path.join(__dirname, 'results', 'stage2.json');
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`\n\nResults written to: ${outPath}`);

  // ── Summary ───────────────────────────────────────────────────────────────

  console.log('\n' + '═'.repeat(72));
  console.log('STAGE 2 SUMMARY');
  console.log('═'.repeat(72));

  console.log('\nSuite A — PULSAR on Vulnerable Corpora:');
  for (const r of suiteAResults) {
    const t1 = r.tier1;
    if (t1.groundTruthCount === 0) {
      console.log(`  ${r.label.padEnd(35)} Tier-1 N/A (callback-style, no PULSAR scope patterns)`);
    } else {
      console.log(`  ${r.label.padEnd(35)} P=${fmt(t1.precision, 1)} R=${fmt(t1.recall, 1)} F1=${fmt(t1.f1, 1)} (${t1.tp} TP / ${t1.fp} FP / ${t1.fn} FN)`);
    }
    console.log(`  ${''.padEnd(35)} AURORA: ${r.auroraVerdict} (${fmt(r.auroraScore)}) | ${r.tier2CapabilityGap.pulsarUndetectableCount} vulns out of PULSAR scope`);
  }

  console.log(`\nSuite B — NOVA Circular Deps: ${circPass}/${circDepResults.length} passed`);
  console.log(`Suite C — God Module Boundary: ${godPass}/${godModResults.length} passed`);
  console.log(`Suite D — Clean Baseline: ${baselineResult.pass ? 'PASS' : 'FAIL'} (${baselineResult.auroraVerdict})`);

  const totalPassed = circPass + godPass + (baselineResult.pass ? 1 : 0);
  const totalTests = circDepResults.length + godModResults.length + 1;
  console.log(`\nStructural tests: ${totalPassed}/${totalTests} passed`);
  console.log('─'.repeat(72));
}

main().catch(e => {
  console.error('Fatal benchmark error:', e);
  process.exit(1);
});

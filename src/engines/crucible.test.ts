// CRUCIBLE v1 fixture proof + positive control.
// NOT a Checkov / Trivy / Hadolint board. NOT a public number.
//
// Proves: parser → config tree → declarative rule → finding {ruleId, uri, startLine}.
// Controls on the engine's own findings/SARIF:
//   path-corrupt      → 0 matches
//   rule-id-strip     → 0 matches
//   line-shift (±3)   → still matches within LINE_TOLERANCE=5
//
// If a control fails, this process exits 1. Do not score incumbents.

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  runCrucible,
  crucibleToSarif,
  evaluateRules,
  resourcesFromDocker,
  LINE_TOLERANCE,
  CrucibleFinding,
  StructuralRule,
  ConfigResource,
} from './crucible';
import { parseHcl, hclBlockToObject } from '../core/parsers/hcl';
import { parseDockerfile } from '../core/parsers/dockerfile';

const REPO = path.resolve(__dirname, '..', '..');
const FIX_TF = path.join(REPO, 'fixtures', 'crucible', 'insecure-bucket.tf');
const FIX_DK = path.join(REPO, 'fixtures', 'crucible', 'Dockerfile');

let pass = 0;
let fail = 0;

function ok(name: string, cond: boolean, detail?: string): void {
  if (cond) {
    console.log(`  ✓ ${name}`);
    pass++;
  } else {
    console.log(`  ✗ ${name}${detail ? ' — ' + detail : ''}`);
    fail++;
  }
}

interface Expected {
  fileSuffix: string;
  ruleId: string;
  line: number;
}

function uriOf(f: CrucibleFinding): string {
  return (f.uri || f.file || '').split(path.sep).join('/');
}

function matches(findings: CrucibleFinding[], expected: Expected[]): number {
  let n = 0;
  for (const exp of expected) {
    const hit = findings.some((f) => {
      const u = uriOf(f);
      // Exact relative URI only — suffix match would let CORRUPT/file.tf still hit.
      const pathOk = u === exp.fileSuffix;
      const idOk = f.ruleId === exp.ruleId && f.ruleId.length > 0;
      const lineOk = Math.abs((f.startLine || 0) - exp.line) <= LINE_TOLERANCE;
      return pathOk && idOk && lineOk;
    });
    if (hit) n++;
  }
  return n;
}

function fromSarif(sarif: ReturnType<typeof crucibleToSarif>): CrucibleFinding[] {
  const results = sarif.runs[0]?.results ?? [];
  return results.map((r) => ({
    ruleId: r.ruleId,
    file: r.locations[0]?.physicalLocation.artifactLocation.uri || '',
    uri: r.locations[0]?.physicalLocation.artifactLocation.uri || '',
    startLine: r.locations[0]?.physicalLocation.region.startLine || 0,
    message: r.message.text,
    severity: r.level === 'error' ? 'HIGH' : r.level === 'note' ? 'LOW' : 'MED',
    resourceType: '',
  }));
}

async function main(): Promise<void> {
  ok('fixture tf exists', fs.existsSync(FIX_TF), FIX_TF);
  ok('fixture dockerfile exists', fs.existsSync(FIX_DK), FIX_DK);

  const tfSrc = fs.readFileSync(FIX_TF, 'utf8');
  const dkSrc = fs.readFileSync(FIX_DK, 'utf8');

  // ── parser smoke ────────────────────────────────────────────────────────
  const hcl = parseHcl(tfSrc, FIX_TF);
  const resBlocks = hcl.blocks.filter((b) => b.blockType === 'resource');
  ok('hcl: one resource block', resBlocks.length === 1, `got ${resBlocks.length}`);
  ok('hcl: type aws_s3_bucket', resBlocks[0]?.labels[0] === 'aws_s3_bucket', String(resBlocks[0]?.labels));
  const attrs = resBlocks[0] ? hclBlockToObject(resBlocks[0]) : {};
  ok(
    'hcl: encryption attribute missing',
    attrs.server_side_encryption_configuration === undefined,
    JSON.stringify(attrs)
  );
  ok('hcl: startLine is 1-based resource line', (resBlocks[0]?.startLine ?? 0) >= 1);

  const dk = parseDockerfile(dkSrc, FIX_DK);
  const from = dk.instructions.find((i) => i.instruction === 'FROM');
  ok('dockerfile: FROM present', !!from);
  ok('dockerfile: tag is latest', from?.tag === 'latest', String(from?.tag));
  ok('dockerfile: FROM startLine >= 1', (from?.startLine ?? 0) >= 1);

  // ── engine on fixture dir ───────────────────────────────────────────────
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crucible-fix-'));
  fs.copyFileSync(FIX_TF, path.join(tmp, 'insecure-bucket.tf'));
  fs.copyFileSync(FIX_DK, path.join(tmp, 'Dockerfile'));

  const report = await runCrucible(tmp);
  const tfFinding = report.findings.find((f) => f.ruleId === 'CRUCIBLE.TF.S3_ENCRYPTION_MISSING');
  const dkFinding = report.findings.find((f) => f.ruleId === 'CRUCIBLE.DOCKER.FROM_LATEST');

  ok('engine: filesAnalyzed === 2', report.filesAnalyzed === 2, `got ${report.filesAnalyzed}`);
  ok('engine: S3 encryption rule fired', !!tfFinding, JSON.stringify(report.findings));
  ok('engine: FROM latest rule fired', !!dkFinding, JSON.stringify(report.findings));
  ok('engine: finding has ruleId', !!tfFinding?.ruleId && !!dkFinding?.ruleId);
  ok('engine: finding has uri', !!tfFinding?.uri && !!dkFinding?.uri);
  ok('engine: finding has startLine', (tfFinding?.startLine ?? 0) >= 1 && (dkFinding?.startLine ?? 0) >= 1);

  const expected: Expected[] = [
    {
      fileSuffix: 'insecure-bucket.tf',
      ruleId: 'CRUCIBLE.TF.S3_ENCRYPTION_MISSING',
      line: resBlocks[0].startLine,
    },
    {
      fileSuffix: 'Dockerfile',
      ruleId: 'CRUCIBLE.DOCKER.FROM_LATEST',
      line: from!.startLine,
    },
  ];

  const nativeHits = matches(report.findings, expected);
  ok(`native findings match both fixtures (${nativeHits}/2)`, nativeHits === 2, `hits=${nativeHits}`);

  const sarif = crucibleToSarif(report.findings);
  const sarifFindings = fromSarif(sarif);
  const sarifHits = matches(sarifFindings, expected);
  ok(`native SARIF match both fixtures (${sarifHits}/2)`, sarifHits === 2, `hits=${sarifHits}`);

  // ── positive controls ───────────────────────────────────────────────────
  const uriCorrupt: CrucibleFinding[] = report.findings.map((f) => ({
    ...f,
    uri: 'CORRUPT/' + f.uri,
    file: 'CORRUPT/' + path.basename(f.file),
  }));
  const uriHits = matches(uriCorrupt, expected);
  ok(`control uri-corrupt → 0 (got ${uriHits})`, uriHits === 0);

  const idStrip: CrucibleFinding[] = report.findings.map((f) => ({ ...f, ruleId: '' }));
  const idHits = matches(idStrip, expected);
  ok(`control rule-id-strip → 0 (got ${idHits})`, idHits === 0);

  const shifted: CrucibleFinding[] = report.findings.map((f) => ({
    ...f,
    startLine: f.startLine + 3,
  }));
  const shiftHits = matches(shifted, expected);
  ok(`control line-shift +3 → still matches within LINE_TOLERANCE=${LINE_TOLERANCE} (got ${shiftHits}/2)`, shiftHits === 2);

  const sarifCorrupt = fromSarif(sarif).map((f) => ({ ...f, uri: 'CORRUPT/' + f.uri, file: 'CORRUPT/' + f.file }));
  const sarifIdStrip = fromSarif(sarif).map((f) => ({ ...f, ruleId: '' }));
  const sarifShift = fromSarif(sarif).map((f) => ({ ...f, startLine: f.startLine + 3 }));
  ok(`SARIF uri-corrupt → 0 (got ${matches(sarifCorrupt, expected)})`, matches(sarifCorrupt, expected) === 0);
  ok(`SARIF rule-id-strip → 0 (got ${matches(sarifIdStrip, expected)})`, matches(sarifIdStrip, expected) === 0);
  ok(
    `SARIF line-shift +3 → ${expected.length} (got ${matches(sarifShift, expected)})`,
    matches(sarifShift, expected) === expected.length
  );

  // ── condition expressiveness (inline, not catalog) ──────────────────────
  const userMissing: StructuralRule = {
    ruleId: 'CRUCIBLE.DOCKER.USER_MISSING',
    resourceType: 'USER',
    condition: 'missing',
    message: 'Dockerfile has no USER instruction',
    severity: 'MED',
  };
  const noUser = parseDockerfile('FROM alpine:3.19\nCMD ["true"]\n', 'x.Dockerfile');
  const withUser = parseDockerfile('FROM alpine:3.19\nUSER nobody\nCMD ["true"]\n', 'y.Dockerfile');
  const miss = evaluateRules(resourcesFromDocker(noUser), [userMissing], '/');
  const nomiss = evaluateRules(resourcesFromDocker(withUser), [userMissing], '/');
  ok('condition missing (no USER) fires', miss.length === 1 && miss[0].ruleId === userMissing.ruleId);
  ok('condition missing (has USER) silent', nomiss.length === 0, JSON.stringify(nomiss));

  const eqRes: ConfigResource[] = [
    {
      resourceType: 'aws_s3_bucket',
      labels: ['aws_s3_bucket', 'pub'],
      attributes: { acl: 'public-read' },
      startLine: 4,
      file: '/tmp/eq.tf',
    },
  ];
  const eqRule: StructuralRule = {
    ruleId: 'CRUCIBLE.TF.ACL_PUBLIC',
    resourceType: 'aws_s3_bucket',
    attributePath: 'acl',
    condition: 'equals',
    value: 'public-read',
    message: 'acl is public-read',
  };
  const neRule: StructuralRule = { ...eqRule, ruleId: 'CRUCIBLE.TF.ACL_NOT_PRIVATE', condition: 'not-equals', value: 'private' };
  ok('condition equals', evaluateRules(eqRes, [eqRule], '/tmp').length === 1);
  ok('condition not-equals', evaluateRules(eqRes, [neRule], '/tmp').length === 1);

  const boolRes: ConfigResource[] = [
    {
      resourceType: 'aws_s3_bucket_versioning',
      labels: ['aws_s3_bucket_versioning', 'v'],
      attributes: { versioning_configuration: { status: true, enabled: false } },
      startLine: 1,
      file: '/tmp/bool.tf',
    },
  ];
  ok(
    'condition is-true',
    evaluateRules(
      boolRes,
      [{ ruleId: 'T', resourceType: 'aws_s3_bucket_versioning', attributePath: 'versioning_configuration.status', condition: 'is-true', message: 't' }],
      '/tmp'
    ).length === 1
  );
  ok(
    'condition is-false',
    evaluateRules(
      boolRes,
      [{ ruleId: 'F', resourceType: 'aws_s3_bucket_versioning', attributePath: 'versioning_configuration.enabled', condition: 'is-false', message: 'f' }],
      '/tmp'
    ).length === 1
  );

  console.log(`\nLINE_TOLERANCE=${LINE_TOLERANCE}`);
  console.log(`control uri-corrupt hits=${uriHits}`);
  console.log(`control rule-id-strip hits=${idHits}`);
  console.log(`control line-shift hits=${shiftHits}`);
  console.log(`\n${pass} pass, ${fail} fail`);

  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    /* ignore */
  }

  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

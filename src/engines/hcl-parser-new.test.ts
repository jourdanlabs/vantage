// NEW-files HCL parser proof. Not a hold-out score. Not a Checkov board.
// Fixtures under src/engines/fixtures/hcl-parser-new/ were written here.

import * as fs from 'fs';
import * as path from 'path';
import { parseHcl, hclBlockToObject } from '../core/parsers/hcl';
import { parseDockerfile } from '../core/parsers/dockerfile';

const REPO = path.resolve(__dirname, '..', '..');
const FIX = path.join(__dirname, 'fixtures', 'hcl-parser-new');

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

function parseBounded(file: string, timeoutMs: number) {
  const src = fs.readFileSync(file, 'utf8');
  const t0 = Date.now();
  const doc = parseHcl(src, path.basename(file), { timeoutMs });
  const ms = Date.now() - t0;
  return { doc, ms, bytes: Buffer.byteLength(src), src };
}

function main(): void {
  const fnFile = path.join(FIX, 'function-calls.tf');
  const interpFile = path.join(FIX, 'interpolations.tf');
  const forFile = path.join(FIX, 'for-expressions.tf');
  const largeFile = path.join(FIX, 'large-module.tf');

  ok('fixture function-calls.tf exists', fs.existsSync(fnFile), fnFile);
  ok('fixture interpolations.tf exists', fs.existsSync(interpFile), interpFile);
  ok('fixture for-expressions.tf exists', fs.existsSync(forFile), forFile);
  ok('fixture large-module.tf exists', fs.existsSync(largeFile), largeFile);

  const largeBytes = fs.statSync(largeFile).size;
  ok(
    `large-module.tf size in 50–200KB (got ${largeBytes})`,
    largeBytes >= 50 * 1024 && largeBytes <= 200 * 1024
  );

  // ── function calls ──────────────────────────────────────────────────────
  const fn = parseBounded(fnFile, 3000);
  ok(`function-calls returned in ${fn.ms}ms (<3000)`, fn.ms < 3000);
  ok('function-calls: no timeout note', !fn.doc.notes.some((n) => /budget exceeded/.test(n)), fn.doc.notes.join(' | '));
  const fnRes = fn.doc.blocks.filter((b) => b.blockType === 'resource');
  ok(`function-calls: 5 resource blocks (got ${fnRes.length})`, fnRes.length === 5, fnRes.map((b) => b.labels.join('.')).join(','));
  const types = fnRes.map((b) => b.labels[0]);
  ok('function-calls: aws_vpc present', types.includes('aws_vpc'));
  ok('function-calls: aws_subnet present', types.includes('aws_subnet'));
  ok('function-calls: aws_iam_role present', types.includes('aws_iam_role'));
  ok('function-calls: aws_iam_policy present', types.includes('aws_iam_policy'));
  ok('function-calls: aws_s3_bucket present', types.includes('aws_s3_bucket'));

  const role = fnRes.find((b) => b.labels[0] === 'aws_iam_role');
  const roleObj = role ? hclBlockToObject(role) : {};
  const policy = roleObj.assume_role_policy as Record<string, unknown> | undefined;
  ok(
    'function-calls: jsonencode unwrapped Version',
    !!(policy && policy.Version === '2012-10-17'),
    JSON.stringify(policy)
  );
  const subnet = fnRes.find((b) => b.labels[0] === 'aws_subnet');
  const subnetObj = subnet ? hclBlockToObject(subnet) : {};
  ok(
    'function-calls: cidrsubnet consumed (attr present)',
    subnetObj.cidr_block !== undefined,
    JSON.stringify(subnetObj.cidr_block)
  );

  // ── interpolations ──────────────────────────────────────────────────────
  const inter = parseBounded(interpFile, 3000);
  ok(`interpolations returned in ${inter.ms}ms (<3000)`, inter.ms < 3000);
  ok('interpolations: no timeout note', !inter.doc.notes.some((n) => /budget exceeded/.test(n)), inter.doc.notes.join(' | '));
  const interRes = inter.doc.blocks.filter((b) => b.blockType === 'resource');
  ok(`interpolations: 2 resource blocks (got ${interRes.length})`, interRes.length === 2);
  const bucket = interRes.find((b) => b.labels[0] === 'aws_s3_bucket');
  const bucketObj = bucket ? hclBlockToObject(bucket) : {};
  ok('interpolations: bucket attr is string', typeof bucketObj.bucket === 'string', String(bucketObj.bucket));
  ok('interpolations: nested format string kept', String(bucketObj.bucket).includes('format'), String(bucketObj.bucket));

  // ── for-expressions ─────────────────────────────────────────────────────
  const fe = parseBounded(forFile, 3000);
  ok(`for-expressions returned in ${fe.ms}ms (<3000)`, fe.ms < 3000);
  ok('for-expressions: no timeout note', !fe.doc.notes.some((n) => /budget exceeded/.test(n)), fe.doc.notes.join(' | '));
  const feRes = fe.doc.blocks.filter((b) => b.blockType === 'resource');
  ok(`for-expressions: 3 resource blocks (got ${feRes.length})`, feRes.length === 3, feRes.map((b) => b.labels.join('.')).join(','));
  const sg = feRes.find((b) => b.labels[0] === 'aws_security_group');
  ok('for-expressions: aws_security_group parsed', !!sg);
  const sgObj = sg ? hclBlockToObject(sg) : {};
  ok('for-expressions: ingress nested block present', sgObj.ingress !== undefined, JSON.stringify(sgObj.ingress));

  // ── large module ────────────────────────────────────────────────────────
  const large = parseBounded(largeFile, 8000);
  ok(`large-module returned in ${large.ms}ms (<8000)`, large.ms < 8000);
  ok('large-module: no timeout note', !large.doc.notes.some((n) => /budget exceeded/.test(n)), large.doc.notes.join(' | '));
  const largeRes = large.doc.blocks.filter((b) => b.blockType === 'resource');
  ok(`large-module: 560 resource blocks (got ${largeRes.length})`, largeRes.length === 560);
  const roles = largeRes.filter((b) => b.labels[0] === 'aws_iam_role');
  const subnets = largeRes.filter((b) => b.labels[0] === 'aws_subnet');
  ok(`large-module: 280 iam roles (got ${roles.length})`, roles.length === 280);
  ok(`large-module: 280 subnets (got ${subnets.length})`, subnets.length === 280);
  const firstRole = roles[0] ? hclBlockToObject(roles[0]) : {};
  const firstPolicy = firstRole.assume_role_policy as Record<string, unknown> | undefined;
  ok(
    'large-module: first jsonencode Version visible',
    !!(firstPolicy && firstPolicy.Version === '2012-10-17'),
    JSON.stringify(firstPolicy)
  );

  // ── hang-regression: leftover function-call parens (the original OOM) ───
  const hangSrc = `
resource "aws_subnet" "x" {
  vpc_id     = var.vpc_id
  cidr_block = cidrsubnet(var.vpc_cidr, 8, 1)
  tags = merge(local.common, { Name = format("%s-subnet", var.env) })
}
`;
  const hangT0 = Date.now();
  const hangDoc = parseHcl(hangSrc, 'hang-repro.tf', { timeoutMs: 2000 });
  const hangMs = Date.now() - hangT0;
  ok(`hang-repro returned in ${hangMs}ms (<2000)`, hangMs < 2000);
  ok('hang-repro: one resource', hangDoc.blocks.filter((b) => b.blockType === 'resource').length === 1);
  ok('hang-repro: no timeout note', !hangDoc.notes.some((n) => /budget exceeded/.test(n)), hangDoc.notes.join(' | '));

  // ── docker parser untouched smoke ───────────────────────────────────────
  const dk = parseDockerfile('FROM alpine:latest\nUSER nobody\n', 'x.Dockerfile');
  ok('docker parser: FROM present', dk.instructions.some((i) => i.instruction === 'FROM'));
  ok('docker parser: tag latest', dk.instructions[0]?.tag === 'latest', String(dk.instructions[0]?.tag));

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail === 0 ? 0 : 1);
}

main();

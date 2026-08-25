// CRUCIBLE v1 rule-pack unit fixtures. Not a Checkov/Trivy/Hadolint board.
// Fixtures are written here; not copied from hold-out.

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { runCrucible, evaluateRules, resourcesFromHclBlocks, resourcesFromDocker, DEFAULT_RULES } from './crucible';
import { V1_RULEPACK, packCounts } from './crucible-rules';
import { parseHcl } from '../core/parsers/hcl';
import { parseDockerfile } from '../core/parsers/dockerfile';

const REPO = path.resolve(__dirname, '..', '..');
const FIX = path.join(REPO, 'fixtures', 'crucible', 'v1');

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

function ids(findings: { ruleId: string }[]): string[] {
  return [...new Set(findings.map((f) => f.ruleId))].sort();
}

async function scanFile(rel: string) {
  const file = path.join(FIX, rel);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'crucible-v1-'));
  fs.copyFileSync(file, path.join(dir, path.basename(rel)));
  const report = await runCrucible(dir);
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
  return report;
}

function evalTf(src: string, file = 'x.tf') {
  const doc = parseHcl(src, file);
  return evaluateRules(resourcesFromHclBlocks(doc.blocks, file), DEFAULT_RULES, '/');
}

function evalDk(src: string, file = 'x.Dockerfile') {
  return evaluateRules(resourcesFromDocker(parseDockerfile(src, file)), DEFAULT_RULES, '/');
}

async function main(): Promise<void> {
  const counts = packCounts();
  console.log(`v1 pack: TF=${counts.tf} Docker=${counts.docker} total=${counts.total}`);
  ok('pack has TF rules', counts.tf >= 10, String(counts.tf));
  ok('pack has Docker rules', counts.docker >= 6, String(counts.docker));
  ok('every pack rule quotes an incumbent id', V1_RULEPACK.every((r) => (r.incumbentIds || []).length > 0));
  ok(
    'no invented CKV2 / CKV_K8S / AVD-KUBE ids',
    V1_RULEPACK.every((r) =>
      (r.incumbentIds || []).every((id) => !id.startsWith('CKV2_') && !id.startsWith('CKV_K8S') && !id.startsWith('AVD-KUBE'))
    )
  );

  const acl = await scanFile('public-acl.tf');
  ok(
    'CKV_AWS_20 fires on public-read',
    acl.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_20_BUCKET_ACL'),
    ids(acl.findings).join(',')
  );

  const pab = await scanFile('public-access-block.tf');
  for (const id of ['CRUCIBLE.TF.CKV_AWS_53', 'CRUCIBLE.TF.CKV_AWS_54', 'CRUCIBLE.TF.CKV_AWS_55', 'CRUCIBLE.TF.CKV_AWS_56']) {
    ok(`${id} fires on false public access block`, pab.findings.some((f) => f.ruleId === id), ids(pab.findings).join(','));
  }

  const ver = await scanFile('versioning-off.tf');
  ok(
    'CKV_AWS_21 fires on Suspended versioning resource',
    ver.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_21_RESOURCE'),
    ids(ver.findings).join(',')
  );
  ok(
    'CKV_AWS_21 bucket rule silent when sibling versioning resource exists',
    !ver.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_21_BUCKET'),
    ids(ver.findings).join(',')
  );

  const rds = await scanFile('rds-ebs.tf');
  ok('CKV_AWS_16 fires', rds.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_16'), ids(rds.findings).join(','));
  ok('CKV_AWS_17 fires', rds.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_17'), ids(rds.findings).join(','));
  ok('CKV_AWS_3 fires', rds.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_3'), ids(rds.findings).join(','));
  ok('CKV_AWS_96 fires', rds.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_96'), ids(rds.findings).join(','));

  const sg = await scanFile('sg-open-22.tf');
  ok('CKV_AWS_24 fires on 0.0.0.0/0:22', sg.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_24_SG'), ids(sg.findings).join(','));

  const iam = await scanFile('iam-star.tf');
  ok('CKV_AWS_63 fires on Action *', iam.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_63'), ids(iam.findings).join(','));
  ok('CKV_AWS_60 fires on Principal AWS *', iam.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_60'), ids(iam.findings).join(','));

  const secure = await scanFile('secure.tf');
  const securePack = secure.findings.filter((f) => f.ruleId.startsWith('CRUCIBLE.TF.CKV_'));
  ok('secure.tf pack rules silent', securePack.length === 0, ids(securePack).join(','));

  const add = await scanFile('add.Dockerfile');
  ok('AVD-DS-0005/DL3020 fires on ADD file', add.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.ADD_NOT_ARCHIVE'), ids(add.findings).join(','));

  const root = await scanFile('user-root.Dockerfile');
  ok('USER root fires', root.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.USER_ROOT'), ids(root.findings).join(','));
  ok('USER missing silent when USER present', !root.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.USER_MISSING'));

  const secrets = await scanFile('secrets.Dockerfile');
  ok('AVD-DS-0031 fires on ENV GITHUB_TOKEN', secrets.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.SECRET_ENV'), ids(secrets.findings).join(','));
  ok('AVD-DS-0031 fires on ARG AWS_SECRET_ACCESS_KEY', secrets.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.SECRET_ARG'), ids(secrets.findings).join(','));

  const pkg = await scanFile('apt-yum.Dockerfile');
  ok('DL3009 fires', pkg.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.APT_LISTS'), ids(pkg.findings).join(','));
  ok('AVD-DS-0015/DL3032 fires', pkg.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.YUM_CLEAN'), ids(pkg.findings).join(','));

  const cons = await scanFile('consecutive.Dockerfile');
  ok('DL3059 fires on consecutive RUN', cons.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.CONSECUTIVE_RUN'), ids(cons.findings).join(','));

  const unpin = await scanFile('unpinned.Dockerfile');
  ok('DL3006 fires on unpinned FROM', unpin.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.FROM_UNPINNED'), ids(unpin.findings).join(','));
  ok('FROM_LATEST also fires (omitted tag defaults to latest / AVD-DS-0001)', unpin.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.FROM_LATEST'));

  const dsec = await scanFile('secure.Dockerfile');
  const dsecPack = dsec.findings.filter((f) => f.ruleId.startsWith('CRUCIBLE.DOCKER.'));
  ok('secure.Dockerfile pack rules silent', dsecPack.length === 0, ids(dsecPack).join(','));

  // jsonencode unwrap smoke
  const iamSrc = fs.readFileSync(path.join(FIX, 'iam-star.tf'), 'utf8');
  const hcl = parseHcl(iamSrc, 'iam-star.tf');
  const pol = hcl.blocks.find((b) => b.labels[0] === 'aws_iam_policy');
  ok('hcl: iam policy block parsed', !!pol);
  const attrs = pol ? require('../core/parsers/hcl').hclBlockToObject(pol) : {};
  ok('hcl: jsonencode unwrapped to object', typeof attrs.policy === 'object' && attrs.policy !== null, JSON.stringify(attrs.policy));

  // self=true must not fire CKV_AWS_24
  const selfHits = evalTf(`
resource "aws_security_group" "selfish" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    self        = true
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`);
  ok('CKV_AWS_24 silent when ingress.self=true', !selfHits.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_24_SG'), ids(selfHits).join(','));

  const archiveAdd = evalDk('FROM alpine:3.19\nUSER nobody\nADD app.tar.gz /app/\n');
  ok('ADD archive does not fire AVD-DS-0005', !archiveAdd.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.ADD_NOT_ARCHIVE'), ids(archiveAdd).join(','));

  const pubKey = evalDk('FROM alpine:3.19\nUSER nobody\nENV PUBLIC_KEY=ssh-rsa-AAA\n');
  ok('PUBLIC_KEY does not fire AVD-DS-0031 (Trivy allowed token)', !pubKey.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.SECRET_ENV'), ids(pubKey).join(','));

  // ── v1b pack fixtures ──────────────────────────────────────────────────
  const enc = await scanFile('v1b-encryption.tf');
  for (const [id, label] of [
    ['CRUCIBLE.TF.CKV_AWS_26', 'SNS kms missing'],
    ['CRUCIBLE.TF.CKV_AWS_27', 'SQS unencrypted'],
    ['CRUCIBLE.TF.CKV_AWS_7', 'KMS rotation'],
    ['CRUCIBLE.TF.CKV_AWS_42', 'EFS encrypted'],
    ['CRUCIBLE.TF.CKV_AWS_28', 'DynamoDB PITR'],
    ['CRUCIBLE.TF.CKV_AWS_29', 'ElastiCache rest'],
    ['CRUCIBLE.TF.CKV_AWS_30', 'ElastiCache transit'],
    ['CRUCIBLE.TF.CKV_AWS_43_MISSING', 'Kinesis encryption_type'],
    ['CRUCIBLE.TF.CKV_AWS_44', 'Neptune storage_encrypted'],
    ['CRUCIBLE.TF.CKV_AWS_47', 'DAX SSE'],
    ['CRUCIBLE.TF.CKV_AWS_64', 'Redshift encrypted'],
    ['CRUCIBLE.TF.CKV_AWS_74', 'DocDB storage_encrypted'],
    ['CRUCIBLE.TF.CKV_AWS_51_MISSING', 'ECR mutability'],
    ['CRUCIBLE.TF.CKV_AWS_136', 'ECR KMS'],
    ['CRUCIBLE.TF.CKV_AWS_163', 'ECR scan_on_push'],
    ['CRUCIBLE.TF.CKV_AWS_173', 'Lambda env without kms'],
    ['CRUCIBLE.TF.CKV_AWS_5', 'ES encrypt_at_rest'],
  ] as const) {
    ok(`${label} (${id}) fires`, enc.findings.some((f) => f.ruleId === id), ids(enc.findings).join(','));
  }

  const log = await scanFile('v1b-logging.tf');
  for (const [id, label] of [
    ['CRUCIBLE.TF.CKV_AWS_35', 'CloudTrail kms'],
    ['CRUCIBLE.TF.CKV_AWS_36', 'CloudTrail validation'],
    ['CRUCIBLE.TF.CKV_AWS_67', 'CloudTrail multi-region'],
    ['CRUCIBLE.TF.CKV_AWS_66', 'CW retention'],
    ['CRUCIBLE.TF.CKV_AWS_158', 'CW kms'],
    ['CRUCIBLE.TF.CKV_AWS_91', 'ALB access logs'],
    ['CRUCIBLE.TF.CKV_AWS_92', 'ELB access logs'],
    ['CRUCIBLE.TF.CKV_AWS_76', 'APIGW access logs'],
    ['CRUCIBLE.TF.CKV_AWS_86', 'CloudFront logging'],
    ['CRUCIBLE.TF.CKV_AWS_2', 'ALB HTTP listener'],
    ['CRUCIBLE.TF.CKV_AWS_150', 'LB deletion protection'],
    ['CRUCIBLE.TF.CKV_AWS_131', 'ALB drop invalid headers'],
  ] as const) {
    ok(`${label} (${id}) fires`, log.findings.some((f) => f.ruleId === id), ids(log.findings).join(','));
  }

  const compute = await scanFile('v1b-compute.tf');
  ok('CKV_AWS_79 fires on missing metadata_options', compute.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_79'), ids(compute.findings).join(','));
  ok('CKV_AWS_8 fires on omitted root_block_device', compute.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_8'), ids(compute.findings).join(','));
  ok('CKV_AWS_88 fires on public IP', compute.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_88_INSTANCE'), ids(compute.findings).join(','));
  ok('CKV_AWS_40 fires on user policy', compute.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_40_USER'), ids(compute.findings).join(','));
  ok('CKV_AWS_57 fires on public-read-write', compute.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_57_BUCKET_ACL'), ids(compute.findings).join(','));
  ok('CKV_AWS_18 fires on bucket without logging', compute.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_18_BUCKET'), ids(compute.findings).join(','));
  ok('CKV_AWS_20 also fires on public-read-write (existing)', compute.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_20_BUCKET_ACL'), ids(compute.findings).join(','));

  const iam62 = await scanFile('iam-star.tf');
  ok('CKV_AWS_62 fires on Action * Resource *', iam62.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_62'), ids(iam62.findings).join(','));

  const rdsMore = await scanFile('rds-ebs.tf');
  ok('CKV_AWS_118 fires on missing monitoring_interval', rdsMore.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_118'), ids(rdsMore.findings).join(','));
  ok('CKV_AWS_157 fires on missing multi_az', rdsMore.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_157'), ids(rdsMore.findings).join(','));
  ok('CKV_AWS_293 fires on missing deletion_protection', rdsMore.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_293'), ids(rdsMore.findings).join(','));
  ok('CKV_AWS_353 fires on missing performance insights', rdsMore.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_353'), ids(rdsMore.findings).join(','));
  ok('CKV_AWS_139 fires on cluster deletion_protection', rdsMore.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_139'), ids(rdsMore.findings).join(','));
  ok('CKV_AWS_324 fires on cluster log exports', rdsMore.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_324'), ids(rdsMore.findings).join(','));

  const sgDesc = await scanFile('sg-open-22.tf');
  ok('CKV_AWS_23 fires on missing SG description', sgDesc.findings.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_23_GROUP'), ids(sgDesc.findings).join(','));

  const sudo = await scanFile('v1b-sudo.Dockerfile');
  ok('AVD-DS-0010/DL3004 fires on sudo', sudo.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.SUDO'), ids(sudo.findings).join(','));

  const wd = await scanFile('v1b-workdir.Dockerfile');
  ok('AVD-DS-0009/DL3000 fires on relative WORKDIR', wd.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.WORKDIR_RELATIVE'), ids(wd.findings).join(','));

  const multi = await scanFile('v1b-multi-cmd.Dockerfile');
  ok('AVD-DS-0016/DL4003 fires on second CMD', multi.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.MULTIPLE_CMD'), ids(multi.findings).join(','));

  const maint = await scanFile('v1b-maintainer.Dockerfile');
  ok('AVD-DS-0022/DL4000 fires on MAINTAINER', maint.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.MAINTAINER'), ids(maint.findings).join(','));

  const exp = await scanFile('v1b-expose.Dockerfile');
  ok('AVD-DS-0004 fires on EXPOSE 22', exp.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.EXPOSE_22'), ids(exp.findings).join(','));

  const noHc = await scanFile('add.Dockerfile');
  ok('AVD-DS-0026/DL3057 fires when HEALTHCHECK missing', noHc.findings.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.HEALTHCHECK_MISSING'), ids(noHc.findings).join(','));

  const rec = evalDk('FROM alpine:3.19\nUSER nobody\nRUN apt-get install curl\nHEALTHCHECK CMD true\n');
  ok('AVD-DS-0021/DL3014 fires on apt-get install without -y', rec.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.APT_YES'), ids(rec).join(','));
  ok('AVD-DS-0029/DL3015 fires on apt-get install without --no-install-recommends', rec.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.APT_NO_RECOMMENDS'), ids(rec).join(','));

  const apk = evalDk('FROM alpine:3.19\nUSER nobody\nRUN apk add curl\nHEALTHCHECK CMD true\n');
  ok('AVD-DS-0025/DL3019 fires on apk add without --no-cache', apk.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.APK_NO_CACHE'), ids(apk).join(','));

  const cdRun = evalDk('FROM alpine:3.19\nUSER nobody\nRUN cd /tmp && echo x\nHEALTHCHECK CMD true\n');
  ok('AVD-DS-0013/DL3003 fires on RUN cd', cdRun.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.RUN_CD'), ids(cdRun).join(','));

  const dist = evalDk('FROM debian:12\nUSER nobody\nRUN apt-get dist-upgrade\nHEALTHCHECK CMD true\n');
  ok('AVD-DS-0024/DL3005 fires on dist-upgrade', dist.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.DIST_UPGRADE'), ids(dist).join(','));

  const badPort = evalDk('FROM alpine:3.19\nUSER nobody\nEXPOSE 70000\nHEALTHCHECK CMD true\n');
  ok('AVD-DS-0008/DL3011 fires on EXPOSE 70000', badPort.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.EXPOSE_PORT_RANGE'), ids(badPort).join(','));

  const imdsOk = evalTf(`
resource "aws_instance" "ok" {
  ami           = "ami-123"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    encrypted = true
  }
}
`);
  ok('CKV_AWS_79 silent when http_tokens=required', !imdsOk.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_79'), ids(imdsOk).join(','));
  ok('CKV_AWS_8 silent when root_block_device.encrypted=true', !imdsOk.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_8'), ids(imdsOk).join(','));

  const sqsOk = evalTf(`
resource "aws_sqs_queue" "ok" {
  name                    = "ok"
  sqs_managed_sse_enabled = true
}
`);
  ok('CKV_AWS_27 silent when sqs_managed_sse_enabled=true', !sqsOk.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_27'), ids(sqsOk).join(','));

  const kmsAsym = evalTf(`
resource "aws_kms_key" "rsa" {
  customer_master_key_spec = "RSA_4096"
}
`);
  ok('CKV_AWS_7 silent for RSA_4096 (Checkov UNKNOWN)', !kmsAsym.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_7'), ids(kmsAsym).join(','));

  const httpsRedirect = evalTf(`
resource "aws_lb_listener" "redir" {
  protocol = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      protocol = "HTTPS"
      port     = "443"
      status_code = "HTTP_301"
    }
  }
}
`);
  ok('CKV_AWS_2 silent when HTTP redirects to HTTPS', !httpsRedirect.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_2'), ids(httpsRedirect).join(','));

  const backupZero = evalTf(`
resource "aws_db_instance" "zero" {
  instance_class          = "db.t3.micro"
  storage_encrypted       = true
  backup_retention_period = 0
  deletion_protection     = true
  multi_az                = true
  performance_insights_enabled = true
  monitoring_interval     = 60
}
`);
  ok('CKV_AWS_133 fires when backup_retention_period=0', backupZero.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_133'), ids(backupZero).join(','));

  const backupMissing = evalTf(`
resource "aws_db_instance" "def" {
  instance_class               = "db.t3.micro"
  storage_encrypted            = true
  deletion_protection          = true
  multi_az                     = true
  performance_insights_enabled = true
  monitoring_interval          = 60
}
`);
  ok('CKV_AWS_133 silent when backup_retention_period omitted (Checkov default 1 PASSES)', !backupMissing.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_133'), ids(backupMissing).join(','));

  // ── v1c pack fixtures ──────────────────────────────────────────────────
  const v1cAws = await scanFile('v1c-aws.tf');
  for (const [id, label] of [
    ['CRUCIBLE.TF.CKV_AWS_9', 'password max age'],
    ['CRUCIBLE.TF.CKV_AWS_10', 'password length'],
    ['CRUCIBLE.TF.CKV_AWS_11', 'password lowercase'],
    ['CRUCIBLE.TF.CKV_AWS_12', 'password numbers'],
    ['CRUCIBLE.TF.CKV_AWS_13', 'password reuse'],
    ['CRUCIBLE.TF.CKV_AWS_14', 'password symbols'],
    ['CRUCIBLE.TF.CKV_AWS_15', 'password uppercase'],
    ['CRUCIBLE.TF.CKV_AWS_22', 'SageMaker kms'],
    ['CRUCIBLE.TF.CKV_AWS_31', 'ElastiCache auth'],
    ['CRUCIBLE.TF.CKV_AWS_39', 'EKS public endpoint'],
    ['CRUCIBLE.TF.CKV_AWS_48', 'MQ logs'],
    ['CRUCIBLE.TF.CKV_AWS_50', 'Lambda xray'],
    ['CRUCIBLE.TF.CKV_AWS_58', 'EKS secrets encryption'],
    ['CRUCIBLE.TF.CKV_AWS_34_DEFAULT', 'CloudFront allow-all'],
    ['CRUCIBLE.TF.CKV_AWS_68', 'CloudFront WAF'],
    ['CRUCIBLE.TF.CKV_AWS_73', 'APIGW xray'],
    ['CRUCIBLE.TF.CKV_AWS_77', 'Athena db encryption'],
    ['CRUCIBLE.TF.CKV_AWS_82', 'Athena enforce config false'],
    ['CRUCIBLE.TF.CKV_AWS_89', 'DMS public'],
    ['CRUCIBLE.TF.CKV_AWS_120', 'APIGW cache'],
    ['CRUCIBLE.TF.CKV_AWS_123', 'VPC endpoint acceptance'],
    ['CRUCIBLE.TF.CKV_AWS_155', 'Workspace user vol'],
    ['CRUCIBLE.TF.CKV_AWS_156', 'Workspace root vol'],
    ['CRUCIBLE.TF.CKV_AWS_159', 'Athena workgroup encryption'],
    ['CRUCIBLE.TF.CKV_AWS_164', 'Transfer public'],
    ['CRUCIBLE.TF.CKV_AWS_166', 'Backup vault kms'],
    ['CRUCIBLE.TF.CKV_AWS_174', 'CloudFront TLS'],
    ['CRUCIBLE.TF.CKV_AWS_182', 'DocDB CMK'],
    ['CRUCIBLE.TF.CKV_AWS_216', 'CloudFront enabled'],
    ['CRUCIBLE.TF.CKV_AWS_226', 'RDS minor upgrade'],
    ['CRUCIBLE.TF.CKV_AWS_235', 'AMI copy encrypted'],
    ['CRUCIBLE.TF.CKV_AWS_239', 'DAX TLS'],
    ['CRUCIBLE.TF.CKV_AWS_251', 'CloudTrail logging false'],
    ['CRUCIBLE.TF.CKV_AWS_284', 'SFN xray'],
    ['CRUCIBLE.TF.CKV_AWS_285', 'SFN execution history'],
    ['CRUCIBLE.TF.CKV_AWS_305', 'CloudFront default root'],
    ['CRUCIBLE.TF.CKV_AWS_307', 'SageMaker root access'],
    ['CRUCIBLE.TF.CKV_AWS_309', 'APIGWv2 auth'],
    ['CRUCIBLE.TF.CKV_AWS_360', 'DocDB backup retention'],
    ['CRUCIBLE.TF.CKV_AWS_366', 'Cognito guest'],
    ['CRUCIBLE.TF.CKV_AWS_370', 'SageMaker isolation'],
  ] as const) {
    ok(`${label} (${id}) fires`, v1cAws.findings.some((f) => f.ruleId === id), ids(v1cAws.findings).join(','));
  }

  const v1cCloud = await scanFile('v1c-azure-gcp.tf');
  for (const [id, label] of [
    ['CRUCIBLE.TF.CKV_AZURE_3', 'Storage https false'],
    ['CRUCIBLE.TF.CKV_AZURE_14', 'App Service https_only'],
    ['CRUCIBLE.TF.CKV_AZURE_44', 'Storage min TLS'],
    ['CRUCIBLE.TF.CKV_AZURE_47', 'MariaDB SSL'],
    ['CRUCIBLE.TF.CKV_AZURE_53', 'MySQL public'],
    ['CRUCIBLE.TF.CKV_AZURE_73', 'Automation encrypted'],
    ['CRUCIBLE.TF.CKV_AZURE_110', 'Key Vault purge'],
    ['CRUCIBLE.TF.CKV_AZURE_115', 'AKS private cluster'],
    ['CRUCIBLE.TF.CKV_AZURE_139', 'ACR public'],
    ['CRUCIBLE.TF.CKV_GCP_20', 'GKE master authorized networks'],
    ['CRUCIBLE.TF.CKV_GCP_25', 'GKE private cluster'],
    ['CRUCIBLE.TF.CKV_GCP_29', 'GCS uniform access'],
    ['CRUCIBLE.TF.CKV_GCP_32', 'GCE block project SSH'],
    ['CRUCIBLE.TF.CKV_GCP_37', 'GCE disk CSEK'],
    ['CRUCIBLE.TF.CKV_GCP_74', 'Subnet private google access'],
    ['CRUCIBLE.TF.CKV_GCP_78', 'GCS versioning'],
    ['CRUCIBLE.TF.CKV_GCP_95', 'Redis AUTH'],
    ['CRUCIBLE.TF.CKV_GCP_97', 'Redis transit'],
    ['CRUCIBLE.TF.CKV_GCP_114', 'GCS public access prevention'],
  ] as const) {
    ok(`${label} (${id}) fires`, v1cCloud.findings.some((f) => f.ruleId === id), ids(v1cCloud.findings).join(','));
  }

  const v1cDk = await scanFile('v1c-docker.Dockerfile');
  for (const [id, label] of [
    ['CRUCIBLE.DOCKER.FROM_PLATFORM', 'FROM --platform'],
    ['CRUCIBLE.DOCKER.WORKDIR_SYS', 'WORKDIR /proc'],
    ['CRUCIBLE.DOCKER.COPY_MULTI_NO_SLASH', 'COPY multi no slash'],
    ['CRUCIBLE.DOCKER.ZYPPER_CLEAN', 'zypper clean'],
    ['CRUCIBLE.DOCKER.ZYPPER_YES', 'zypper -y'],
    ['CRUCIBLE.DOCKER.MICRODNF_CLEAN', 'microdnf clean'],
    ['CRUCIBLE.DOCKER.UPDATE_ALONE', 'apt-get update alone'],
    ['CRUCIBLE.DOCKER.DNF_YES', 'microdnf -y'],
  ] as const) {
    ok(`${label} (${id}) fires`, v1cDk.findings.some((f) => f.ruleId === id), ids(v1cDk.findings).join(','));
  }

  const pwOk = evalTf(`
resource "aws_iam_account_password_policy" "ok" {
  max_password_age             = 90
  minimum_password_length      = 14
  password_reuse_prevention    = 24
  require_lowercase_characters = true
  require_numbers              = true
  require_symbols              = true
  require_uppercase_characters = true
}
`);
  ok(
    'password policy silent when published values hold',
    !pwOk.some((f) => f.ruleId.startsWith('CRUCIBLE.TF.CKV_AWS_9') || ['CRUCIBLE.TF.CKV_AWS_10','CRUCIBLE.TF.CKV_AWS_11','CRUCIBLE.TF.CKV_AWS_12','CRUCIBLE.TF.CKV_AWS_13','CRUCIBLE.TF.CKV_AWS_14','CRUCIBLE.TF.CKV_AWS_15'].includes(f.ruleId)),
    ids(pwOk).join(',')
  );

  const httpsOmit = evalTf(`
resource "azurerm_storage_account" "def" {
  name                     = "ok"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}
`);
  ok('CKV_AZURE_3 silent when enable_https_traffic_only omitted (Checkov missing=PASS)', !httpsOmit.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AZURE_3'), ids(httpsOmit).join(','));
  ok('CKV_AZURE_44 silent when min_tls_version=TLS1_2', !httpsOmit.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AZURE_44'), ids(httpsOmit).join(','));

  const trailDef = evalTf(`
resource "aws_cloudtrail" "def" {
  name           = "ok"
  s3_bucket_name = "b"
}
`);
  ok('CKV_AWS_251 silent when enable_logging omitted (Checkov missing=PASS)', !trailDef.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_251'), ids(trailDef).join(','));

  const copyOk = evalDk('FROM alpine:3.19\\nUSER nobody\\nCOPY a.txt b.txt dest/\\nHEALTHCHECK CMD true\\n');
  ok('COPY dest/ does not fire DL3021', !copyOk.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.COPY_MULTI_NO_SLASH'), ids(copyOk).join(','));

  const twoCopy = evalDk('FROM alpine:3.19\\nUSER nobody\\nCOPY file.txt /app/file.txt\\nHEALTHCHECK CMD true\\n');
  ok('COPY two-arg does not fire DL3021', !twoCopy.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.COPY_MULTI_NO_SLASH'), ids(twoCopy).join(','));

  const cfTls = evalTf(`
resource "aws_cloudfront_distribution" "ok" {
  enabled             = true
  default_root_object = "index.html"
  web_acl_id          = "arn:aws:wafv2:us-east-1:1:global/webacl/x/x"
  origin {
    domain_name = "example.com"
    origin_id   = "o"
  }
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "o"
    viewer_protocol_policy = "https-only"
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }
  restrictions {
    geo_restriction { restriction_type = "none" }
  }
  viewer_certificate {
    acm_certificate_arn      = "arn:aws:acm:us-east-1:1:certificate/x"
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }
}
`);
  ok('CKV_AWS_34 silent when viewer_protocol_policy is https-only', !cfTls.some((f) => f.ruleId.startsWith('CRUCIBLE.TF.CKV_AWS_34')), ids(cfTls).join(','));
  ok('CKV_AWS_174 silent when TLSv1.2_2021', !cfTls.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_174'), ids(cfTls).join(','));
  ok('CKV_AWS_68 silent when web_acl_id present', !cfTls.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_68'), ids(cfTls).join(','));
  ok('CKV_AWS_216 silent when enabled=true', !cfTls.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_216'), ids(cfTls).join(','));
  ok('CKV_AWS_305 silent when default_root_object present', !cfTls.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_305'), ids(cfTls).join(','));

  // ── v1d pack fixtures ──────────────────────────────────────────────────
  const v1dAws = await scanFile('v1d-aws.tf');
  for (const [id, label] of [
    ['CRUCIBLE.TF.CKV_AWS_126', 'EC2 monitoring'],
    ['CRUCIBLE.TF.CKV_AWS_135', 'EC2 ebs_optimized'],
    ['CRUCIBLE.TF.CKV_AWS_214', 'AppSync cache rest'],
    ['CRUCIBLE.TF.CKV_AWS_215', 'AppSync cache transit'],
    ['CRUCIBLE.TF.CKV_AWS_220', 'CloudSearch https'],
    ['CRUCIBLE.TF.CKV_AWS_218', 'CloudSearch TLS'],
    ['CRUCIBLE.TF.CKV_AWS_222', 'DMS minor upgrade'],
    ['CRUCIBLE.TF.CKV_AWS_292', 'DocDB global encrypted'],
    ['CRUCIBLE.TF.CKV_AWS_83', 'ES enforce_https false'],
    ['CRUCIBLE.TF.CKV_AWS_228', 'ES TLS policy'],
    ['CRUCIBLE.TF.CKV_AWS_75', 'GA flow logs'],
    ['CRUCIBLE.TF.CKV_AWS_238', 'GuardDuty disabled'],
    ['CRUCIBLE.TF.CKV_AWS_227', 'KMS is_enabled false'],
    ['CRUCIBLE.TF.CKV_AWS_116', 'Lambda DLQ'],
    ['CRUCIBLE.TF.CKV_AWS_117', 'Lambda VPC'],
    ['CRUCIBLE.TF.CKV_AWS_272', 'Lambda code signing'],
    ['CRUCIBLE.TF.CKV_AWS_207', 'MQ minor upgrade'],
    ['CRUCIBLE.TF.CKV_AWS_242', 'MWAA scheduler logs'],
    ['CRUCIBLE.TF.CKV_AWS_243', 'MWAA worker logs'],
    ['CRUCIBLE.TF.CKV_AWS_244', 'MWAA webserver logs'],
    ['CRUCIBLE.TF.CKV_AWS_279', 'Neptune snapshot enc'],
    ['CRUCIBLE.TF.CKV_AWS_359', 'Neptune IAM auth'],
    ['CRUCIBLE.TF.CKV_AWS_362', 'Neptune copy tags'],
    ['CRUCIBLE.TF.CKV_AWS_344', 'Network Firewall delete prot'],
    ['CRUCIBLE.TF.CKV_AWS_170', 'QLDB permissions'],
    ['CRUCIBLE.TF.CKV_AWS_172', 'QLDB deletion false'],
    ['CRUCIBLE.TF.CKV_AWS_162', 'RDS cluster IAM'],
    ['CRUCIBLE.TF.CKV_AWS_146', 'RDS snapshot enc'],
    ['CRUCIBLE.TF.CKV_AWS_313', 'RDS copy tags'],
    ['CRUCIBLE.TF.CKV_AWS_141', 'Redshift version upgrade false'],
    ['CRUCIBLE.TF.CKV_AWS_321', 'Redshift enhanced VPC'],
    ['CRUCIBLE.TF.CKV_AWS_87', 'Redshift public'],
    ['CRUCIBLE.TF.CKV_AWS_122', 'SageMaker internet Enabled'],
    ['CRUCIBLE.TF.CKV_AWS_365', 'SES TLS'],
    ['CRUCIBLE.TF.CKV_AWS_206', 'APIGW domain TLS'],
    ['CRUCIBLE.TF.CKV_AWS_225', 'APIGW cache settings'],
    ['CRUCIBLE.TF.CKV_AWS_193', 'AppSync logging'],
    ['CRUCIBLE.TF.CKV_AWS_194', 'AppSync field logs'],
    ['CRUCIBLE.TF.CKV_AWS_390', 'EMR block public'],
    ['CRUCIBLE.TF.CKV_AWS_323', 'ElastiCache subnet'],
    ['CRUCIBLE.TF.CKV_AWS_138', 'ELB cross zone false'],
    ['CRUCIBLE.TF.CKV_AWS_371', 'SageMaker IMDS'],
    ['CRUCIBLE.TF.CKV_AWS_176', 'WAF logs'],
    ['CRUCIBLE.TF.CKV_AWS_137', 'ES VPC'],
    ['CRUCIBLE.TF.CKV_AWS_98', 'SageMaker endpoint kms'],
    ['CRUCIBLE.TF.CKV_AWS_306', 'SageMaker subnet'],
    ['CRUCIBLE.TF.CKV_AWS_160', 'Timestream kms'],
    ['CRUCIBLE.TF.CKV_AWS_195', 'Glue security config'],
    ['CRUCIBLE.TF.CKV_AWS_252', 'CloudTrail SNS'],
    ['CRUCIBLE.TF.CKV_AWS_373', 'Bedrock CMK'],
    ['CRUCIBLE.TF.CKV_AWS_383', 'Bedrock guardrail'],
    ['CRUCIBLE.TF.CKV_AWS_124', 'CFN notifications'],
    ['CRUCIBLE.TF.CKV_AWS_341', 'Launch template hop'],
  ] as const) {
    ok(`${label} (${id}) fires`, v1dAws.findings.some((f) => f.ruleId === id), ids(v1dAws.findings).join(','));
  }

  const v1dCloud = await scanFile('v1d-azure-gcp.tf');
  for (const [id, label] of [
    ['CRUCIBLE.TF.CKV_AZURE_141', 'AKS local admin'],
    ['CRUCIBLE.TF.CKV_AZURE_170', 'AKS sku'],
    ['CRUCIBLE.TF.CKV_AZURE_17', 'App Service client cert'],
    ['CRUCIBLE.TF.CKV_AZURE_18', 'App Service http2'],
    ['CRUCIBLE.TF.CKV_AZURE_78', 'App Service FTPS'],
    ['CRUCIBLE.TF.CKV_AZURE_15', 'App Service min TLS present'],
    ['CRUCIBLE.TF.CKV_AZURE_15_LINUX', 'Linux Web App min TLS'],
    ['CRUCIBLE.TF.CKV_AZURE_72', 'remote debugging true'],
    ['CRUCIBLE.TF.CKV_AZURE_222', 'Web App public'],
    ['CRUCIBLE.TF.CKV_AZURE_153', 'slot https_only'],
    ['CRUCIBLE.TF.CKV_AZURE_124', 'Search public'],
    ['CRUCIBLE.TF.CKV_AZURE_134', 'Cognitive public'],
    ['CRUCIBLE.TF.CKV_AZURE_236', 'Cognitive local auth'],
    ['CRUCIBLE.TF.CKV_AZURE_101', 'Cosmos public'],
    ['CRUCIBLE.TF.CKV_AZURE_104', 'Data Factory public'],
    ['CRUCIBLE.TF.CKV_AZURE_28', 'MySQL SSL'],
    ['CRUCIBLE.TF.CKV_AZURE_29', 'Postgres SSL'],
    ['CRUCIBLE.TF.CKV_AZURE_68', 'Postgres public'],
    ['CRUCIBLE.TF.CKV_AZURE_91', 'Redis non-SSL true'],
    ['CRUCIBLE.TF.CKV_AZURE_148', 'Redis TLS'],
    ['CRUCIBLE.TF.CKV_AZURE_89', 'Redis public'],
    ['CRUCIBLE.TF.CKV_AZURE_113', 'MSSQL public'],
    ['CRUCIBLE.TF.CKV_AZURE_52', 'MSSQL TLS'],
    ['CRUCIBLE.TF.CKV_AZURE_59', 'Storage public'],
    ['CRUCIBLE.TF.CKV_AZURE_190', 'Storage nested public'],
    ['CRUCIBLE.TF.CKV_AZURE_97', 'VMSS enc at host'],
    ['CRUCIBLE.TF.CKV_AZURE_151', 'Win VM enc at host'],
    ['CRUCIBLE.TF.CKV_AZURE_187', 'App Config purge'],
    ['CRUCIBLE.TF.CKV_AZURE_203', 'Service Bus local auth'],
    ['CRUCIBLE.TF.CKV_AZURE_204', 'Service Bus public'],
    ['CRUCIBLE.TF.CKV_AZURE_205', 'Service Bus TLS'],
    ['CRUCIBLE.TF.CKV_AZURE_48', 'Maria public'],
    ['CRUCIBLE.TF.CKV_AZURE_40', 'Key expiration'],
    ['CRUCIBLE.TF.CKV_AZURE_41', 'Secret expiration'],
    ['CRUCIBLE.TF.CKV_AZURE_109', 'KV firewall'],
    ['CRUCIBLE.TF.CKV_AZURE_111', 'KV soft delete false'],
    ['CRUCIBLE.TF.CKV_AZURE_16', 'App Service identity'],
    ['CRUCIBLE.TF.CKV_AZURE_56', 'Function auth'],
    ['CRUCIBLE.TF.CKV_AZURE_67', 'Function http2'],
    ['CRUCIBLE.TF.CKV_AZURE_145', 'Function min TLS present'],
    ['CRUCIBLE.TF.CKV_AZURE_145_LINUX', 'Linux Function min TLS'],
    ['CRUCIBLE.TF.CKV_AZURE_221', 'Function public'],
    ['CRUCIBLE.TF.CKV_AZURE_197', 'CDN HTTP'],
    ['CRUCIBLE.TF.CKV_AZURE_198', 'CDN HTTPS false'],
    ['CRUCIBLE.TF.CKV_AZURE_224', 'SQL ledger'],
    ['CRUCIBLE.TF.CKV_AZURE_19', 'Security Center Free'],
    ['CRUCIBLE.TF.CKV_AZURE_74', 'Kusto disk enc'],
    ['CRUCIBLE.TF.CKV_AZURE_96', 'MySQL infra enc'],
    ['CRUCIBLE.TF.CKV_AZURE_94', 'MySQL geo'],
    ['CRUCIBLE.TF.CKV_AZURE_54', 'MySQL TLS'],
    ['CRUCIBLE.TF.CKV_AZURE_130', 'Postgres infra enc'],
    ['CRUCIBLE.TF.CKV_AZURE_147', 'Postgres TLS'],
    ['CRUCIBLE.TF.CKV_AZURE_102', 'Postgres geo'],
    ['CRUCIBLE.TF.CKV_AZURE_129', 'Maria geo'],
    ['CRUCIBLE.TF.CKV_AZURE_189', 'KV public'],
    ['CRUCIBLE.TF.CKV_AZURE_50', 'VM extensions'],
    ['CRUCIBLE.TF.CKV_AZURE_49', 'VMSS password auth'],
    ['CRUCIBLE.TF.CKV_AZURE_178', 'Linux SSH key'],
    ['CRUCIBLE.TF.CKV_AZURE_177', 'Win auto updates false'],
    ['CRUCIBLE.TF.CKV_AZURE_179', 'VM agent false'],
    ['CRUCIBLE.TF.CKV_GCP_121', 'BQ deletion'],
    ['CRUCIBLE.TF.CKV_GCP_122', 'Bigtable deletion'],
    ['CRUCIBLE.TF.CKV_GCP_86', 'Cloud Build private'],
    ['CRUCIBLE.TF.CKV_GCP_124', 'Cloud Function ingress'],
    ['CRUCIBLE.TF.CKV_GCP_124_GEN2', 'Cloud Function gen2 ingress'],
    ['CRUCIBLE.TF.CKV_GCP_87', 'Data Fusion private'],
    ['CRUCIBLE.TF.CKV_GCP_104', 'Data Fusion logs'],
    ['CRUCIBLE.TF.CKV_GCP_105', 'Data Fusion mon'],
    ['CRUCIBLE.TF.CKV_GCP_103', 'Dataproc internal IP'],
    ['CRUCIBLE.TF.CKV_GCP_13', 'GKE client cert'],
    ['CRUCIBLE.TF.CKV_GCP_61', 'GKE flow logs'],
    ['CRUCIBLE.TF.CKV_GCP_9', 'node pool repair'],
    ['CRUCIBLE.TF.CKV_GCP_10', 'node pool upgrade'],
    ['CRUCIBLE.TF.CKV_GCP_70', 'GKE release channel'],
    ['CRUCIBLE.TF.CKV_GCP_33', 'project OS Login'],
    ['CRUCIBLE.TF.CKV_GCP_82', 'KMS prevent destroy'],
    ['CRUCIBLE.TF.CKV_GCP_27', 'project default network'],
    ['CRUCIBLE.TF.CKV_GCP_119', 'Spanner deletion false'],
    ['CRUCIBLE.TF.CKV_GCP_120', 'Spanner drop prot'],
    ['CRUCIBLE.TF.CKV_GCP_89', 'Vertex no public IP'],
    ['CRUCIBLE.TF.CKV_GCP_23', 'GKE alias IP'],
    ['CRUCIBLE.TF.CKV_GCP_65', 'GKE RBAC groups'],
  ] as const) {
    ok(`${label} (${id}) fires`, v1dCloud.findings.some((f) => f.ruleId === id), ids(v1dCloud.findings).join(','));
  }

  const v1dDk = await scanFile('v1d-docker.Dockerfile');
  for (const [id, label] of [
    ['CRUCIBLE.DOCKER.APT_NOT_GET', 'apt not apt-get'],
    ['CRUCIBLE.DOCKER.ZYPPER_DIST_UPGRADE', 'zypper dist-upgrade'],
    ['CRUCIBLE.DOCKER.PIP_CACHE', 'pip cache'],
    ['CRUCIBLE.DOCKER.ONBUILD_FROM', 'ONBUILD FROM'],
    ['CRUCIBLE.DOCKER.LN_BIN_SH', 'ln /bin/sh'],
    ['CRUCIBLE.DOCKER.CMD_SHELL_FORM', 'CMD shell form'],
    ['CRUCIBLE.DOCKER.WGET_AND_CURL', 'wget and curl'],
  ] as const) {
    ok(`${label} (${id}) fires`, v1dDk.findings.some((f) => f.ruleId === id), ids(v1dDk.findings).join(','));
  }

  const esOmit = evalTf(`
resource "aws_elasticsearch_domain" "def" {
  domain_name = "ok"
}
`);
  ok('CKV_AWS_83 silent when enforce_https omitted (Checkov missing=PASS)', !esOmit.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_83'), ids(esOmit).join(','));

  const smOmit = evalTf(`
resource "aws_sagemaker_notebook_instance" "def" {
  name          = "ok"
  instance_type = "ml.t3.medium"
  role_arn      = "arn:aws:iam::1:role/x"
  subnet_id     = "subnet-1"
  instance_metadata_service_configuration {
    minimum_instance_metadata_service_version = "2"
  }
}
`);
  ok('CKV_AWS_122 silent when direct_internet_access omitted (Checkov missing=PASS)', !smOmit.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AWS_122'), ids(smOmit).join(','));

  const debugOmit = evalTf(`
resource "azurerm_linux_web_app" "def" {
  name                = "ok"
  resource_group_name = "rg"
  location            = "eastus"
  service_plan_id     = "p"
  public_network_access_enabled = false
  identity { type = "SystemAssigned" }
  site_config {
    http2_enabled       = true
    ftps_state          = "Disabled"
    minimum_tls_version = "1.2"
  }
}
`);
  ok('CKV_AZURE_72 silent when remote_debugging omitted (Checkov missing=PASS)', !debugOmit.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AZURE_72'), ids(debugOmit).join(','));
  ok('CKV_AZURE_15_LINUX silent when minimum_tls_version=1.2', !debugOmit.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AZURE_15_LINUX'), ids(debugOmit).join(','));

  const redisOmit = evalTf(`
resource "azurerm_redis_cache" "def" {
  name                = "ok"
  resource_group_name = "rg"
  location            = "eastus"
  capacity            = 1
  family              = "C"
  sku_name            = "Basic"
  minimum_tls_version = "1.2"
  public_network_access_enabled = false
}
`);
  ok('CKV_AZURE_91 silent when enable_non_ssl_port omitted (Checkov missing=PASS)', !redisOmit.some((f) => f.ruleId === 'CRUCIBLE.TF.CKV_AZURE_91'), ids(redisOmit).join(','));

  const pipOk = evalDk('FROM alpine:3.19\\nUSER nobody\\nRUN pip install --no-cache-dir flask\\nHEALTHCHECK CMD true\\nCMD ["true"]\\n');
  ok('pip --no-cache-dir does not fire DL3042', !pipOk.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.PIP_CACHE'), ids(pipOk).join(','));

  const aptGet = evalDk('FROM alpine:3.19\\nUSER nobody\\nRUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\\nHEALTHCHECK CMD true\\nCMD ["true"]\\n');
  ok('apt-get does not fire DL3027', !aptGet.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.APT_NOT_GET'), ids(aptGet).join(','));

  const jsonCmd = evalDk('FROM alpine:3.19\\nUSER nobody\\nHEALTHCHECK CMD true\\nCMD ["true"]\\n');
  ok('JSON CMD does not fire DL3025', !jsonCmd.some((f) => f.ruleId === 'CRUCIBLE.DOCKER.CMD_SHELL_FORM'), ids(jsonCmd).join(','));


  // ── v1e remaining published attribute checks ──
  const v1eAws = await scanFile("v1e-aws.tf");
  for (const [id, label] of [
    ["CRUCIBLE.TF.CKV_AWS_106", "CKV_AWS_106"],
    ["CRUCIBLE.TF.CKV_AWS_129", "CKV_AWS_129"],
    ["CRUCIBLE.TF.CKV_AWS_142", "CKV_AWS_142"],
    ["CRUCIBLE.TF.CKV_AWS_152", "CKV_AWS_152"],
    ["CRUCIBLE.TF.CKV_AWS_154", "CKV_AWS_154"],
    ["CRUCIBLE.TF.CKV_AWS_177", "CKV_AWS_177"],
    ["CRUCIBLE.TF.CKV_AWS_178", "CKV_AWS_178"],
    ["CRUCIBLE.TF.CKV_AWS_179", "CKV_AWS_179"],
    ["CRUCIBLE.TF.CKV_AWS_180", "CKV_AWS_180"],
    ["CRUCIBLE.TF.CKV_AWS_181", "CKV_AWS_181"],
    ["CRUCIBLE.TF.CKV_AWS_183", "CKV_AWS_183"],
    ["CRUCIBLE.TF.CKV_AWS_184", "CKV_AWS_184"],
    ["CRUCIBLE.TF.CKV_AWS_185", "CKV_AWS_185"],
    ["CRUCIBLE.TF.CKV_AWS_186", "CKV_AWS_186"],
    ["CRUCIBLE.TF.CKV_AWS_187", "CKV_AWS_187"],
    ["CRUCIBLE.TF.CKV_AWS_189", "CKV_AWS_189"],
    ["CRUCIBLE.TF.CKV_AWS_190", "CKV_AWS_190"],
    ["CRUCIBLE.TF.CKV_AWS_191", "CKV_AWS_191"],
    ["CRUCIBLE.TF.CKV_AWS_197", "CKV_AWS_197"],
    ["CRUCIBLE.TF.CKV_AWS_199", "CKV_AWS_199"],
    ["CRUCIBLE.TF.CKV_AWS_201", "CKV_AWS_201"],
    ["CRUCIBLE.TF.CKV_AWS_203", "CKV_AWS_203"],
    ["CRUCIBLE.TF.CKV_AWS_209", "CKV_AWS_209"],
    ["CRUCIBLE.TF.CKV_AWS_211", "CKV_AWS_211"],
    ["CRUCIBLE.TF.CKV_AWS_212", "CKV_AWS_212"],
    ["CRUCIBLE.TF.CKV_AWS_217", "CKV_AWS_217"],
    ["CRUCIBLE.TF.CKV_AWS_219", "CKV_AWS_219"],
    ["CRUCIBLE.TF.CKV_AWS_221", "CKV_AWS_221"],
    ["CRUCIBLE.TF.CKV_AWS_233", "CKV_AWS_233"],
    ["CRUCIBLE.TF.CKV_AWS_234", "CKV_AWS_234"],
    ["CRUCIBLE.TF.CKV_AWS_236", "CKV_AWS_236"],
    ["CRUCIBLE.TF.CKV_AWS_237", "CKV_AWS_237"],
    ["CRUCIBLE.TF.CKV_AWS_245", "CKV_AWS_245"],
    ["CRUCIBLE.TF.CKV_AWS_246", "CKV_AWS_246"],
    ["CRUCIBLE.TF.CKV_AWS_247", "CKV_AWS_247"],
    ["CRUCIBLE.TF.CKV_AWS_248", "CKV_AWS_248"],
    ["CRUCIBLE.TF.CKV_AWS_262", "CKV_AWS_262"],
    ["CRUCIBLE.TF.CKV_AWS_263", "CKV_AWS_263"],
    ["CRUCIBLE.TF.CKV_AWS_264", "CKV_AWS_264"],
    ["CRUCIBLE.TF.CKV_AWS_266", "CKV_AWS_266"],
    ["CRUCIBLE.TF.CKV_AWS_267", "CKV_AWS_267"],
    ["CRUCIBLE.TF.CKV_AWS_268", "CKV_AWS_268"],
    ["CRUCIBLE.TF.CKV_AWS_269", "CKV_AWS_269"],
    ["CRUCIBLE.TF.CKV_AWS_270", "CKV_AWS_270"],
    ["CRUCIBLE.TF.CKV_AWS_271", "CKV_AWS_271"],
    ["CRUCIBLE.TF.CKV_AWS_278", "CKV_AWS_278"],
    ["CRUCIBLE.TF.CKV_AWS_280", "CKV_AWS_280"],
    ["CRUCIBLE.TF.CKV_AWS_281", "CKV_AWS_281"],
    ["CRUCIBLE.TF.CKV_AWS_282", "CKV_AWS_282"],
    ["CRUCIBLE.TF.CKV_AWS_294", "CKV_AWS_294"],
    ["CRUCIBLE.TF.CKV_AWS_297", "CKV_AWS_297"],
    ["CRUCIBLE.TF.CKV_AWS_298", "CKV_AWS_298"],
    ["CRUCIBLE.TF.CKV_AWS_308", "CKV_AWS_308"],
    ["CRUCIBLE.TF.CKV_AWS_320", "CKV_AWS_320"],
    ["CRUCIBLE.TF.CKV_AWS_322", "CKV_AWS_322"],
    ["CRUCIBLE.TF.CKV_AWS_327", "CKV_AWS_327"],
    ["CRUCIBLE.TF.CKV_AWS_330", "CKV_AWS_330"],
    ["CRUCIBLE.TF.CKV_AWS_337", "CKV_AWS_337"],
    ["CRUCIBLE.TF.CKV_AWS_339", "CKV_AWS_339"],
    ["CRUCIBLE.TF.CKV_AWS_345", "CKV_AWS_345"],
    ["CRUCIBLE.TF.CKV_AWS_346", "CKV_AWS_346"],
    ["CRUCIBLE.TF.CKV_AWS_347", "CKV_AWS_347"],
    ["CRUCIBLE.TF.CKV_AWS_354", "CKV_AWS_354"],
    ["CRUCIBLE.TF.CKV_AWS_367", "CKV_AWS_367"],
    ["CRUCIBLE.TF.CKV_AWS_368", "CKV_AWS_368"],
    ["CRUCIBLE.TF.CKV_AWS_369", "CKV_AWS_369"],
    ["CRUCIBLE.TF.CKV_AWS_372", "CKV_AWS_372"],
    ["CRUCIBLE.TF.CKV_AWS_84", "CKV_AWS_84"],
  ] as const) {
    ok(`${label} (${id}) fires`, v1eAws.findings.some((f) => f.ruleId === id), ids(v1eAws.findings).join(","));
  }

  const v1eCloud = await scanFile("v1e-azure-gcp.tf");
  for (const [id, label] of [
    ["CRUCIBLE.TF.CKV_AZURE_100", "CKV_AZURE_100"],
    ["CRUCIBLE.TF.CKV_AZURE_105", "CKV_AZURE_105"],
    ["CRUCIBLE.TF.CKV_AZURE_106", "CKV_AZURE_106"],
    ["CRUCIBLE.TF.CKV_AZURE_107", "CKV_AZURE_107"],
    ["CRUCIBLE.TF.CKV_AZURE_108", "CKV_AZURE_108"],
    ["CRUCIBLE.TF.CKV_AZURE_112", "CKV_AZURE_112"],
    ["CRUCIBLE.TF.CKV_AZURE_114", "CKV_AZURE_114"],
    ["CRUCIBLE.TF.CKV_AZURE_117", "CKV_AZURE_117"],
    ["CRUCIBLE.TF.CKV_AZURE_118", "CKV_AZURE_118"],
    ["CRUCIBLE.TF.CKV_AZURE_121", "CKV_AZURE_121"],
    ["CRUCIBLE.TF.CKV_AZURE_126", "CKV_AZURE_126"],
    ["CRUCIBLE.TF.CKV_AZURE_127", "CKV_AZURE_127"],
    ["CRUCIBLE.TF.CKV_AZURE_128", "CKV_AZURE_128"],
    ["CRUCIBLE.TF.CKV_AZURE_131", "CKV_AZURE_131"],
    ["CRUCIBLE.TF.CKV_AZURE_132", "CKV_AZURE_132"],
    ["CRUCIBLE.TF.CKV_AZURE_136", "CKV_AZURE_136"],
    ["CRUCIBLE.TF.CKV_AZURE_140", "CKV_AZURE_140"],
    ["CRUCIBLE.TF.CKV_AZURE_142", "CKV_AZURE_142"],
    ["CRUCIBLE.TF.CKV_AZURE_150", "CKV_AZURE_150"],
    ["CRUCIBLE.TF.CKV_AZURE_154", "CKV_AZURE_154"],
    ["CRUCIBLE.TF.CKV_AZURE_155", "CKV_AZURE_155"],
    ["CRUCIBLE.TF.CKV_AZURE_156", "CKV_AZURE_156"],
    ["CRUCIBLE.TF.CKV_AZURE_157", "CKV_AZURE_157"],
    ["CRUCIBLE.TF.CKV_AZURE_159", "CKV_AZURE_159"],
    ["CRUCIBLE.TF.CKV_AZURE_161", "CKV_AZURE_161"],
    ["CRUCIBLE.TF.CKV_AZURE_166", "CKV_AZURE_166"],
    ["CRUCIBLE.TF.CKV_AZURE_172", "CKV_AZURE_172"],
    ["CRUCIBLE.TF.CKV_AZURE_176", "CKV_AZURE_176"],
    ["CRUCIBLE.TF.CKV_AZURE_181", "CKV_AZURE_181"],
    ["CRUCIBLE.TF.CKV_AZURE_186", "CKV_AZURE_186"],
    ["CRUCIBLE.TF.CKV_AZURE_188", "CKV_AZURE_188"],
    ["CRUCIBLE.TF.CKV_AZURE_191", "CKV_AZURE_191"],
    ["CRUCIBLE.TF.CKV_AZURE_192", "CKV_AZURE_192"],
    ["CRUCIBLE.TF.CKV_AZURE_193", "CKV_AZURE_193"],
    ["CRUCIBLE.TF.CKV_AZURE_194", "CKV_AZURE_194"],
    ["CRUCIBLE.TF.CKV_AZURE_195", "CKV_AZURE_195"],
    ["CRUCIBLE.TF.CKV_AZURE_199", "CKV_AZURE_199"],
    ["CRUCIBLE.TF.CKV_AZURE_20", "CKV_AZURE_20"],
    ["CRUCIBLE.TF.CKV_AZURE_201", "CKV_AZURE_201"],
    ["CRUCIBLE.TF.CKV_AZURE_202", "CKV_AZURE_202"],
    ["CRUCIBLE.TF.CKV_AZURE_206", "CKV_AZURE_206"],
    ["CRUCIBLE.TF.CKV_AZURE_207", "CKV_AZURE_207"],
    ["CRUCIBLE.TF.CKV_AZURE_21", "CKV_AZURE_21"],
    ["CRUCIBLE.TF.CKV_AZURE_213", "CKV_AZURE_213"],
    ["CRUCIBLE.TF.CKV_AZURE_214", "CKV_AZURE_214"],
    ["CRUCIBLE.TF.CKV_AZURE_216", "CKV_AZURE_216"],
    ["CRUCIBLE.TF.CKV_AZURE_217", "CKV_AZURE_217"],
    ["CRUCIBLE.TF.CKV_AZURE_219", "CKV_AZURE_219"],
    ["CRUCIBLE.TF.CKV_AZURE_22", "CKV_AZURE_22"],
    ["CRUCIBLE.TF.CKV_AZURE_220", "CKV_AZURE_220"],
    ["CRUCIBLE.TF.CKV_AZURE_223", "CKV_AZURE_223"],
    ["CRUCIBLE.TF.CKV_AZURE_225", "CKV_AZURE_225"],
    ["CRUCIBLE.TF.CKV_AZURE_226", "CKV_AZURE_226"],
    ["CRUCIBLE.TF.CKV_AZURE_229", "CKV_AZURE_229"],
    ["CRUCIBLE.TF.CKV_AZURE_230", "CKV_AZURE_230"],
    ["CRUCIBLE.TF.CKV_AZURE_231", "CKV_AZURE_231"],
    ["CRUCIBLE.TF.CKV_AZURE_232", "CKV_AZURE_232"],
    ["CRUCIBLE.TF.CKV_AZURE_237", "CKV_AZURE_237"],
    ["CRUCIBLE.TF.CKV_AZURE_238", "CKV_AZURE_238"],
    ["CRUCIBLE.TF.CKV_AZURE_240", "CKV_AZURE_240"],
    ["CRUCIBLE.TF.CKV_AZURE_242", "CKV_AZURE_242"],
    ["CRUCIBLE.TF.CKV_AZURE_244", "CKV_AZURE_244"],
    ["CRUCIBLE.TF.CKV_AZURE_245", "CKV_AZURE_245"],
    ["CRUCIBLE.TF.CKV_AZURE_26", "CKV_AZURE_26"],
    ["CRUCIBLE.TF.CKV_AZURE_27", "CKV_AZURE_27"],
    ["CRUCIBLE.TF.CKV_AZURE_34", "CKV_AZURE_34"],
    ["CRUCIBLE.TF.CKV_AZURE_58", "CKV_AZURE_58"],
    ["CRUCIBLE.TF.CKV_AZURE_6", "CKV_AZURE_6"],
    ["CRUCIBLE.TF.CKV_AZURE_63", "CKV_AZURE_63"],
    ["CRUCIBLE.TF.CKV_AZURE_64", "CKV_AZURE_64"],
    ["CRUCIBLE.TF.CKV_AZURE_7", "CKV_AZURE_7"],
    ["CRUCIBLE.TF.CKV_AZURE_71", "CKV_AZURE_71"],
    ["CRUCIBLE.TF.CKV_AZURE_75", "CKV_AZURE_75"],
    ["CRUCIBLE.TF.CKV_AZURE_76", "CKV_AZURE_76"],
    ["CRUCIBLE.TF.CKV_AZURE_81", "CKV_AZURE_81"],
    ["CRUCIBLE.TF.CKV_AZURE_82", "CKV_AZURE_82"],
    ["CRUCIBLE.TF.CKV_AZURE_83", "CKV_AZURE_83"],
    ["CRUCIBLE.TF.CKV_AZURE_88", "CKV_AZURE_88"],
    ["CRUCIBLE.TF.CKV_AZURE_93", "CKV_AZURE_93"],
    ["CRUCIBLE.TF.CKV_AZURE_98", "CKV_AZURE_98"],
    ["CRUCIBLE.TF.CKV_AZURE_4", "CKV_AZURE_4"],
    ["CRUCIBLE.TF.CKV_AZURE_65", "CKV_AZURE_65"],
    ["CRUCIBLE.TF.CKV_AZURE_65_WEB", "CKV_AZURE_65_WEB"],
    ["CRUCIBLE.TF.CKV_AZURE_66", "CKV_AZURE_66"],
    ["CRUCIBLE.TF.CKV_AZURE_66_WEB", "CKV_AZURE_66_WEB"],
    ["CRUCIBLE.TF.CKV_GCP_118", "CKV_GCP_118"],
    ["CRUCIBLE.TF.CKV_GCP_12", "CKV_GCP_12"],
    ["CRUCIBLE.TF.CKV_GCP_14", "CKV_GCP_14"],
    ["CRUCIBLE.TF.CKV_GCP_16", "CKV_GCP_16"],
    ["CRUCIBLE.TF.CKV_GCP_26", "CKV_GCP_26"],
    ["CRUCIBLE.TF.CKV_GCP_68", "CKV_GCP_68"],
    ["CRUCIBLE.TF.CKV_GCP_76", "CKV_GCP_76"],
    ["CRUCIBLE.TF.CKV_GCP_79", "CKV_GCP_79"],
    ["CRUCIBLE.TF.CKV_GCP_80", "CKV_GCP_80"],
    ["CRUCIBLE.TF.CKV_GCP_81", "CKV_GCP_81"],
    ["CRUCIBLE.TF.CKV_GCP_83", "CKV_GCP_83"],
    ["CRUCIBLE.TF.CKV_GCP_84", "CKV_GCP_84"],
    ["CRUCIBLE.TF.CKV_GCP_85", "CKV_GCP_85"],
    ["CRUCIBLE.TF.CKV_GCP_90", "CKV_GCP_90"],
    ["CRUCIBLE.TF.CKV_GCP_91", "CKV_GCP_91"],
    ["CRUCIBLE.TF.CKV_GCP_92", "CKV_GCP_92"],
    ["CRUCIBLE.TF.CKV_GCP_93", "CKV_GCP_93"],
    ["CRUCIBLE.TF.CKV_GCP_94", "CKV_GCP_94"],
    ["CRUCIBLE.TF.CKV_GCP_96", "CKV_GCP_96"],
  ] as const) {
    ok(`${label} (${id}) fires`, v1eCloud.findings.some((f) => f.ruleId === id), ids(v1eCloud.findings).join(","));
  }

  const v1eDk = await scanFile("v1e-docker.Dockerfile");
  for (const [id, label] of [
    ["CRUCIBLE.DOCKER.USELESS_CMDS", "DL3001"],
    ["CRUCIBLE.DOCKER.WGET_PROGRESS", "DL3047"],
    ["CRUCIBLE.DOCKER.USERADD_NOL", "DL3046"],
  ] as const) {
    ok(`${label} (${id}) fires`, v1eDk.findings.some((f) => f.ruleId === id), ids(v1eDk.findings).join(","));
  }

  const acmOmit = evalTf(`
resource "aws_acm_certificate" "def" {
  domain_name = "example.com"
}
`);
  ok("CKV_AWS_234 silent when transparency preference omitted (Checkov missing=PASS)", !acmOmit.some((f) => f.ruleId === "CRUCIBLE.TF.CKV_AWS_234"), ids(acmOmit).join(","));

  const ebsDef = evalTf(`
resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}
`);
  ok("CKV_AWS_106 silent when enabled=true", !ebsDef.some((f) => f.ruleId === "CRUCIBLE.TF.CKV_AWS_106"), ids(ebsDef).join(","));


  // ── v1f remaining published attribute checks ──
  const v1fAws = await scanFile("v1f-aws.tf");
  for (const [id, label] of [
    ["CRUCIBLE.TF.CKV_AWS_311", "CKV_AWS_311"],
    ["CRUCIBLE.TF.CKV_AWS_328", "CKV_AWS_328"],
    ["CRUCIBLE.TF.CKV_AWS_276", "CKV_AWS_276"],
    ["CRUCIBLE.TF.CKV_AWS_389", "CKV_AWS_389"],
    ["CRUCIBLE.TF.CKV_AWS_374", "CKV_AWS_374"],
    ["CRUCIBLE.TF.CKV_AWS_319", "CKV_AWS_319"],
    ["CRUCIBLE.TF.CKV_AWS_316", "CKV_AWS_316"],
    ["CRUCIBLE.TF.CKV_AWS_302", "CKV_AWS_302"],
    ["CRUCIBLE.TF.CKV_AWS_295", "CKV_AWS_295"],
    ["CRUCIBLE.TF.CKV_AWS_363", "CKV_AWS_363"],
    ["CRUCIBLE.TF.CKV_AWS_223", "CKV_AWS_223"],
    ["CRUCIBLE.TF.CKV_AWS_333", "CKV_AWS_333"],
    ["CRUCIBLE.TF.CKV_AWS_329", "CKV_AWS_329"],
    ["CRUCIBLE.TF.CKV_AWS_331", "CKV_AWS_331"],
    ["CRUCIBLE.TF.CKV_AWS_134", "CKV_AWS_134"],
    ["CRUCIBLE.TF.CKV_AWS_348", "CKV_AWS_348"],
    ["CRUCIBLE.TF.CKV_AWS_301", "CKV_AWS_301"],
    ["CRUCIBLE.TF.CKV_AWS_115", "CKV_AWS_115"],
    ["CRUCIBLE.TF.CKV_AWS_258", "CKV_AWS_258"],
    ["CRUCIBLE.TF.CKV_AWS_69", "CKV_AWS_69"],
    ["CRUCIBLE.TF.CKV_AWS_291", "CKV_AWS_291"],
    ["CRUCIBLE.TF.CKV_AWS_202", "CKV_AWS_202"],
    ["CRUCIBLE.TF.CKV_AWS_102", "CKV_AWS_102"],
    ["CRUCIBLE.TF.CKV_AWS_326", "CKV_AWS_326"],
    ["CRUCIBLE.TF.CKV_AWS_343", "CKV_AWS_343"],
    ["CRUCIBLE.TF.CKV_AWS_377", "CKV_AWS_377"],
    ["CRUCIBLE.TF.CKV_AWS_303", "CKV_AWS_303"],
    ["CRUCIBLE.TF.CKV_AWS_130", "CKV_AWS_130"],
  ] as const) {
    ok(`${label} (${id}) fires`, v1fAws.findings.some((f) => f.ruleId === id), ids(v1fAws.findings).join(","));
  }

  const v1fAzure = await scanFile("v1f-azure.tf");
  for (const [id, label] of [
    ["CRUCIBLE.TF.CKV_AZURE_57", "CKV_AZURE_57"],
    ["CRUCIBLE.TF.CKV_AZURE_62", "CKV_AZURE_62"],
    ["CRUCIBLE.TF.CKV_AZURE_137", "CKV_AZURE_137"],
    ["CRUCIBLE.TF.CKV_AZURE_169", "CKV_AZURE_169"],
    ["CRUCIBLE.TF.CKV_AZURE_174", "CKV_AZURE_174"],
    ["CRUCIBLE.TF.CKV_AZURE_184", "CKV_AZURE_184"],
    ["CRUCIBLE.TF.CKV_AZURE_185", "CKV_AZURE_185"],
    ["CRUCIBLE.TF.CKV_AZURE_211", "CKV_AZURE_211"],
    ["CRUCIBLE.TF.CKV_AZURE_210", "CKV_AZURE_210"],
    ["CRUCIBLE.TF.CKV_AZURE_180", "CKV_AZURE_180"],
    ["CRUCIBLE.TF.CKV_AZURE_158", "CKV_AZURE_158"],
    ["CRUCIBLE.TF.CKV_AZURE_228", "CKV_AZURE_228"],
    ["CRUCIBLE.TF.CKV_AZURE_246", "CKV_AZURE_246"],
    ["CRUCIBLE.TF.CKV_AZURE_144", "CKV_AZURE_144"],
    ["CRUCIBLE.TF.CKV_AZURE_175", "CKV_AZURE_175"],
    ["CRUCIBLE.TF.CKV_AZURE_196", "CKV_AZURE_196"],
    ["CRUCIBLE.TF.CKV_AZURE_162", "CKV_AZURE_162"],
    ["CRUCIBLE.TF.CKV_AZURE_149", "CKV_AZURE_149"],
  ] as const) {
    ok(`${label} (${id}) fires`, v1fAzure.findings.some((f) => f.ruleId === id), ids(v1fAzure.findings).join(","));
  }

  const v1fGcp = await scanFile("v1f-gcp.tf");
  for (const [id, label] of [
    ["CRUCIBLE.TF.CKV_GCP_1", "CKV_GCP_1"],
    ["CRUCIBLE.TF.CKV_GCP_7", "CKV_GCP_7"],
    ["CRUCIBLE.TF.CKV_GCP_123", "CKV_GCP_123"],
    ["CRUCIBLE.TF.CKV_GCP_71", "CKV_GCP_71"],
    ["CRUCIBLE.TF.CKV_GCP_8", "CKV_GCP_8"],
    ["CRUCIBLE.TF.CKV_GCP_40", "CKV_GCP_40"],
    ["CRUCIBLE.TF.CKV_GCP_36", "CKV_GCP_36"],
    ["CRUCIBLE.TF.CKV_GCP_34", "CKV_GCP_34"],
    ["CRUCIBLE.TF.CKV_GCP_35", "CKV_GCP_35"],
    ["CRUCIBLE.TF.CKV_GCP_126", "CKV_GCP_126"],
    ["CRUCIBLE.TF.CKV_GCP_127", "CKV_GCP_127"],
  ] as const) {
    ok(`${label} (${id}) fires`, v1fGcp.findings.some((f) => f.ruleId === id), ids(v1fGcp.findings).join(","));
  }

  const v1fOther = await scanFile("v1f-other.tf");
  for (const [id, label] of [
    ["CRUCIBLE.TF.CKV_NCP_23", "CKV_NCP_23"],
    ["CRUCIBLE.TF.CKV_ALI_29", "CKV_ALI_29"],
    ["CRUCIBLE.TF.CKV_ALI_5", "CKV_ALI_5"],
    ["CRUCIBLE.TF.CKV_ALI_4", "CKV_ALI_4"],
    ["CRUCIBLE.TF.CKV_ALI_31", "CKV_ALI_31"],
    ["CRUCIBLE.TF.CKV_ALI_28", "CKV_ALI_28"],
    ["CRUCIBLE.TF.CKV_ALI_27", "CKV_ALI_27"],
    ["CRUCIBLE.TF.CKV_ALI_38", "CKV_ALI_38"],
    ["CRUCIBLE.TF.CKV_ALI_41", "CKV_ALI_41"],
    ["CRUCIBLE.TF.CKV_ALI_42", "CKV_ALI_42"],
    ["CRUCIBLE.TF.CKV_ALI_44", "CKV_ALI_44"],
    ["CRUCIBLE.TF.CKV_ALI_12", "CKV_ALI_12"],
    ["CRUCIBLE.TF.CKV_ALI_6", "CKV_ALI_6"],
    ["CRUCIBLE.TF.CKV_ALI_11", "CKV_ALI_11"],
    ["CRUCIBLE.TF.CKV_ALI_10", "CKV_ALI_10"],
    ["CRUCIBLE.TF.CKV_ALI_16", "CKV_ALI_16"],
    ["CRUCIBLE.TF.CKV_ALI_13", "CKV_ALI_13"],
    ["CRUCIBLE.TF.CKV_ALI_17", "CKV_ALI_17"],
    ["CRUCIBLE.TF.CKV_ALI_23", "CKV_ALI_23"],
    ["CRUCIBLE.TF.CKV_ALI_14", "CKV_ALI_14"],
    ["CRUCIBLE.TF.CKV_ALI_18", "CKV_ALI_18"],
    ["CRUCIBLE.TF.CKV_ALI_15", "CKV_ALI_15"],
    ["CRUCIBLE.TF.CKV_ALI_19", "CKV_ALI_19"],
    ["CRUCIBLE.TF.CKV_ALI_24", "CKV_ALI_24"],
    ["CRUCIBLE.TF.CKV_ALI_30", "CKV_ALI_30"],
    ["CRUCIBLE.TF.CKV_ALI_20", "CKV_ALI_20"],
    ["CRUCIBLE.TF.CKV_ALI_22", "CKV_ALI_22"],
    ["CRUCIBLE.TF.CKV_ALI_33", "CKV_ALI_33"],
    ["CRUCIBLE.TF.CKV_DIO_2", "CKV_DIO_2"],
    ["CRUCIBLE.TF.CKV_DIO_3", "CKV_DIO_3"],
    ["CRUCIBLE.TF.CKV_DIO_1", "CKV_DIO_1"],
    ["CRUCIBLE.TF.CKV_GIT_6", "CKV_GIT_6"],
    ["CRUCIBLE.TF.CKV_GIT_4", "CKV_GIT_4"],
    ["CRUCIBLE.TF.CKV_GIT_2", "CKV_GIT_2"],
    ["CRUCIBLE.TF.CKV_GLB_2", "CKV_GLB_2"],
    ["CRUCIBLE.TF.CKV_GLB_3", "CKV_GLB_3"],
    ["CRUCIBLE.TF.CKV_GLB_4", "CKV_GLB_4"],
    ["CRUCIBLE.TF.CKV_LIN_2", "CKV_LIN_2"],
    ["CRUCIBLE.TF.CKV_LIN_5", "CKV_LIN_5"],
    ["CRUCIBLE.TF.CKV_LIN_6", "CKV_LIN_6"],
    ["CRUCIBLE.TF.CKV_LIN_3", "CKV_LIN_3"],
    ["CRUCIBLE.TF.CKV_LIN_4", "CKV_LIN_4"],
    ["CRUCIBLE.TF.CKV_NCP_24", "CKV_NCP_24"],
    ["CRUCIBLE.TF.CKV_NCP_16", "CKV_NCP_16"],
    ["CRUCIBLE.TF.CKV_NCP_7", "CKV_NCP_7"],
    ["CRUCIBLE.TF.CKV_NCP_14", "CKV_NCP_14"],
    ["CRUCIBLE.TF.CKV_NCP_22", "CKV_NCP_22"],
    ["CRUCIBLE.TF.CKV_NCP_19", "CKV_NCP_19"],
    ["CRUCIBLE.TF.CKV_NCP_6", "CKV_NCP_6"],
    ["CRUCIBLE.TF.CKV_OCI_15", "CKV_OCI_15"],
    ["CRUCIBLE.TF.CKV_OCI_11", "CKV_OCI_11"],
    ["CRUCIBLE.TF.CKV_OCI_12", "CKV_OCI_12"],
    ["CRUCIBLE.TF.CKV_OCI_13", "CKV_OCI_13"],
    ["CRUCIBLE.TF.CKV_OCI_14", "CKV_OCI_14"],
    ["CRUCIBLE.TF.CKV_OCI_4", "CKV_OCI_4"],
    ["CRUCIBLE.TF.CKV_OCI_5", "CKV_OCI_5"],
    ["CRUCIBLE.TF.CKV_OCI_6", "CKV_OCI_6"],
    ["CRUCIBLE.TF.CKV_OCI_7", "CKV_OCI_7"],
    ["CRUCIBLE.TF.CKV_OCI_9", "CKV_OCI_9"],
    ["CRUCIBLE.TF.CKV_OCI_10", "CKV_OCI_10"],
    ["CRUCIBLE.TF.CKV_OCI_8", "CKV_OCI_8"],
    ["CRUCIBLE.TF.CKV_OCI_16", "CKV_OCI_16"],
    ["CRUCIBLE.TF.CKV_OCI_2", "CKV_OCI_2"],
    ["CRUCIBLE.TF.CKV_OCI_3", "CKV_OCI_3"],
    ["CRUCIBLE.TF.CKV_OPENSTACK_4", "CKV_OPENSTACK_4"],
    ["CRUCIBLE.TF.CKV_OPENSTACK_5", "CKV_OPENSTACK_5"],
    ["CRUCIBLE.TF.CKV_PAN_2", "CKV_PAN_2"],
    ["CRUCIBLE.TF.CKV_PAN_3", "CKV_PAN_3"],
    ["CRUCIBLE.TF.CKV_PAN_13", "CKV_PAN_13"],
    ["CRUCIBLE.TF.CKV_TC_1", "CKV_TC_1"],
    ["CRUCIBLE.TF.CKV_TC_9", "CKV_TC_9"],
    ["CRUCIBLE.TF.CKV_TC_10", "CKV_TC_10"],
    ["CRUCIBLE.TF.CKV_TC_12", "CKV_TC_12"],
    ["CRUCIBLE.TF.CKV_TC_2", "CKV_TC_2"],
    ["CRUCIBLE.TF.CKV_TC_3", "CKV_TC_3"],
    ["CRUCIBLE.TF.CKV_TC_6", "CKV_TC_6"],
    ["CRUCIBLE.TF.CKV_TC_14", "CKV_TC_14"],
    ["CRUCIBLE.TF.CKV_YC_18", "CKV_YC_18"],
    ["CRUCIBLE.TF.CKV_YC_22", "CKV_YC_22"],
    ["CRUCIBLE.TF.CKV_YC_2", "CKV_YC_2"],
    ["CRUCIBLE.TF.CKV_YC_11", "CKV_YC_11"],
    ["CRUCIBLE.TF.CKV_YC_4", "CKV_YC_4"],
    ["CRUCIBLE.TF.CKV_YC_13", "CKV_YC_13"],
    ["CRUCIBLE.TF.CKV_YC_23", "CKV_YC_23"],
    ["CRUCIBLE.TF.CKV_YC_21", "CKV_YC_21"],
    ["CRUCIBLE.TF.CKV_YC_7", "CKV_YC_7"],
    ["CRUCIBLE.TF.CKV_YC_10", "CKV_YC_10"],
    ["CRUCIBLE.TF.CKV_YC_16", "CKV_YC_16"],
    ["CRUCIBLE.TF.CKV_YC_8", "CKV_YC_8"],
    ["CRUCIBLE.TF.CKV_YC_6", "CKV_YC_6"],
    ["CRUCIBLE.TF.CKV_YC_15", "CKV_YC_15"],
    ["CRUCIBLE.TF.CKV_YC_5", "CKV_YC_5"],
    ["CRUCIBLE.TF.CKV_YC_14", "CKV_YC_14"],
    ["CRUCIBLE.TF.CKV_YC_9", "CKV_YC_9"],
    ["CRUCIBLE.TF.CKV_YC_12", "CKV_YC_12"],
    ["CRUCIBLE.TF.CKV_YC_1", "CKV_YC_1"],
    ["CRUCIBLE.TF.CKV_YC_3", "CKV_YC_3"],
  ] as const) {
    ok(`${label} (${id}) fires`, v1fOther.findings.some((f) => f.ruleId === id), ids(v1fOther.findings).join(","));
  }

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

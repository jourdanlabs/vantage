// CRUCIBLE — structural IaC / Docker rule engine
// Peer of METEOR/NOVA/ECLIPSE/PULSAR/NEBULA/AURORA.
// NOT a NEBULA taint frontend. Do not import nebula/frontend-*.
//
// Declared-dark (v1): Kubernetes manifests, cross-file / cross-module
// tracing, taint-flow. This module expresses a structural rule over a
// single parsed HCL or Dockerfile tree.

import * as fs from 'fs';
import * as path from 'path';
import { parseHcl, hclBlockToObject, HclBlock } from '../core/parsers/hcl';
import { parseDockerfile, DockerDocument } from '../core/parsers/dockerfile';
import { V1_RULEPACK } from './crucible-rules';

export const LINE_TOLERANCE = 5;

export type RuleCondition =
  | 'missing'
  | 'equals'
  | 'not-equals'
  | 'is-true'
  | 'is-false'
  | 'not-true'
  | 'contains'
  | 'matches'
  | 'not-matches'
  | 'matches-any'
  | 'in'
  | 'not-in'
  | 'lte'
  | 'gte'
  | 'equals-or-missing'
  | 'present'
  | 'consecutive'
  | 'duplicate';

export type RuleValue = string | number | boolean | Array<string | number>;

export interface RulePredicate {
  attributePath?: string;
  condition: RuleCondition;
  value?: RuleValue;
}

export interface StructuralRule {
  ruleId: string;
  resourceType: string;
  /** Alternate types; evaluated as OR with resourceType. */
  resourceTypes?: string[];
  /** Dotted path. Empty / omitted + condition `missing` = resource itself is absent. */
  attributePath?: string;
  condition: RuleCondition;
  value?: RuleValue;
  message: string;
  severity?: 'HIGH' | 'MED' | 'LOW';
  /** Published incumbent IDs this rule maps to. Quote only catalog IDs. */
  incumbentIds?: string[];
  /** All predicates must hold (AND), evaluated on the resource or anyElement item. */
  allOf?: RulePredicate[];
  /** OR of AND-groups. */
  anyOf?: RulePredicate[][];
  /** Evaluate allOf/anyOf against each list element of attributePath. */
  anyElement?: boolean;
  /** Skip this resource when a sibling type exists in the same file. */
  unlessSameFileResource?: string;
  /** Skip when this predicate holds on the resource. */
  unless?: RulePredicate;
  /** Resource-absent / consecutive: only files that already have this type. */
  requiresResourceType?: string;
}

export interface ConfigResource {
  resourceType: string;
  labels: string[];
  attributes: Record<string, unknown>;
  startLine: number;
  file: string;
}

export interface CrucibleFinding {
  ruleId: string;
  file: string;
  uri: string;
  startLine: number;
  message: string;
  severity: 'HIGH' | 'MED' | 'LOW';
  resourceType: string;
}

export interface CrucibleReport {
  findings: CrucibleFinding[];
  filesAnalyzed: number;
  resources: number;
  durationMs: number;
  notes: string[];
}

export const FIXTURE_RULES: StructuralRule[] = [
  {
    ruleId: 'CRUCIBLE.TF.S3_ENCRYPTION_MISSING',
    resourceType: 'aws_s3_bucket',
    attributePath: 'server_side_encryption_configuration',
    condition: 'missing',
    message: 'aws_s3_bucket is missing server_side_encryption_configuration',
    severity: 'HIGH',
    // Expressiveness fixture. Not mapped to CKV_AWS_19: that graph YAML
    // PASSES when the inline attribute is absent (AWS default SSE-S3).
  },
  {
    ruleId: 'CRUCIBLE.DOCKER.FROM_LATEST',
    resourceType: 'FROM',
    attributePath: 'tag',
    condition: 'equals',
    value: 'latest',
    message: 'FROM uses the floating :latest tag',
    severity: 'MED',
    incumbentIds: ['AVD-DS-0001', 'DL3007'],
  },
];

export const DEFAULT_RULES: StructuralRule[] = [...FIXTURE_RULES, ...V1_RULEPACK];

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '__pycache__',
  '.DS_Store', 'Pods', '.build', 'vendor', 'coverage', '.scannerwork',
  '.venv', 'venv', '.mypy_cache', '.pytest_cache', '.tox',
]);

const TF_EXT = new Set(['.tf', '.tfvars']);
const DOCKER_BASENAMES = new Set(['dockerfile', 'containerfile']);

function isDockerFilename(name: string): boolean {
  const lower = name.toLowerCase();
  return DOCKER_BASENAMES.has(lower) || lower.endsWith('.dockerfile');
}

function walkIacFiles(dir: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkIacFiles(full, out);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (TF_EXT.has(ext) || isDockerFilename(entry.name)) out.push(full);
    }
  }
}

export function discoverIacFiles(targetPath: string): string[] {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(targetPath);
  } catch {
    return [];
  }
  if (stat.isFile()) return [targetPath];
  const out: string[] = [];
  walkIacFiles(targetPath, out);
  return out;
}

export function resourcesFromHclBlocks(blocks: HclBlock[], file: string): ConfigResource[] {
  const out: ConfigResource[] = [];
  for (const b of blocks) {
    if (b.blockType === 'resource' && b.labels[0]) {
      out.push({
        resourceType: b.labels[0],
        labels: b.labels,
        attributes: hclBlockToObject(b),
        startLine: b.startLine,
        file,
      });
    }
    // Nested resource blocks do not exist in HCL; ignore other top-level kinds.
  }
  return out;
}

export function resourcesFromDocker(doc: DockerDocument): ConfigResource[] {
  const file = doc.file;
  const present: Record<string, unknown> = {};
  const out: ConfigResource[] = [];
  for (const inst of doc.instructions) {
    present[inst.instruction] = true;
    const attributes: Record<string, unknown> = {
      args: inst.args,
      values: inst.values,
      flags: inst.flags,
    };
    if (inst.image !== undefined) attributes.image = inst.image;
    if (inst.tag !== undefined) attributes.tag = inst.tag;
    if (inst.digest !== undefined) attributes.digest = inst.digest;
    if (inst.stage !== undefined) attributes.stage = inst.stage;
    if (inst.tagOmitted !== undefined) attributes.tagOmitted = inst.tagOmitted;
    if (inst.instruction === 'ENV' || inst.instruction === 'ARG') {
      const raw = inst.args || '';
      const eq = raw.indexOf('=');
      const name = (eq >= 0 ? raw.slice(0, eq) : raw).trim().split(/\s+/)[0] || '';
      attributes.name = name;
    }
    out.push({
      resourceType: inst.instruction,
      labels: inst.stage ? [inst.stage] : [],
      attributes,
      startLine: inst.startLine,
      file,
    });
  }
  out.push({
    resourceType: 'dockerfile',
    labels: [],
    attributes: present,
    startLine: 1,
    file,
  });
  return out;
}

function tryParseJson(v: unknown): unknown {
  if (typeof v !== 'string') return v;
  const t = v.trim();
  if (!t || (t[0] !== '{' && t[0] !== '[')) return v;
  try {
    return JSON.parse(t);
  } catch {
    return v;
  }
}

export function lookupAttribute(
  attrs: Record<string, unknown>,
  dotted?: string
): { found: boolean; value: unknown } {
  if (!dotted) return { found: true, value: attrs };
  const parts = dotted.split('.').filter(Boolean);
  let cur: unknown = attrs;
  for (const p of parts) {
    if (typeof cur === 'string') cur = tryParseJson(cur);
    if (cur == null || typeof cur !== 'object') return { found: false, value: undefined };
    if (Array.isArray(cur)) {
      if (cur.length === 0) return { found: false, value: undefined };
      cur = cur[0];
    }
    const obj = cur as Record<string, unknown>;
    if (!Object.prototype.hasOwnProperty.call(obj, p)) return { found: false, value: undefined };
    cur = obj[p];
  }
  if (typeof cur === 'string') {
    const parsed = tryParseJson(cur);
    if (parsed !== cur) return { found: true, value: parsed };
  }
  return { found: true, value: cur };
}

function asList(v: RuleValue | undefined): Array<string | number | boolean> {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

function valueIn(actual: unknown, candidates: RuleValue | undefined): boolean {
  const cand = asList(candidates).map(String);
  if (Array.isArray(actual)) return actual.some((a) => cand.includes(String(a)));
  return cand.includes(String(actual));
}

function toNumber(v: unknown): number | undefined {
  if (typeof v === 'number' && !Number.isNaN(v)) return v;
  if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
  return undefined;
}

function regexMatch(value: unknown, pattern: string): boolean {
  try {
    return new RegExp(pattern).test(String(value));
  } catch {
    return false;
  }
}

function conditionHolds(
  rule: { condition: RuleCondition; value?: RuleValue },
  looked: { found: boolean; value: unknown }
): boolean {
  const { found, value } = looked;
  switch (rule.condition) {
    case 'missing':
      return !found || value === undefined || value === null;
    case 'equals':
      if (!found) return false;
      return String(value) === String(rule.value);
    case 'not-equals':
      if (!found) return false;
      return String(value) !== String(rule.value);
    case 'equals-or-missing':
      if (!found || value === undefined || value === null) return true;
      return String(value) === String(rule.value);
    case 'is-true':
      return found && (value === true || value === 'true');
    case 'is-false':
      return found && (value === false || value === 'false');
    case 'not-true':
      if (!found || value === undefined || value === null) return true;
      return !(value === true || value === 'true');
    case 'contains':
      if (!found || value === undefined || value === null) return false;
      if (Array.isArray(value)) return value.map(String).includes(String(rule.value));
      return String(value).includes(String(rule.value));
    case 'matches':
      if (!found || value === undefined || value === null) return false;
      return regexMatch(value, String(rule.value ?? ''));
    case 'not-matches':
      if (!found || value === undefined || value === null) return true;
      return !regexMatch(value, String(rule.value ?? ''));
    case 'matches-any':
      if (!found || value === undefined || value === null) return false;
      return asList(rule.value).some((pat) => regexMatch(value, String(pat)));
    case 'in':
      if (!found) return false;
      return valueIn(value, rule.value);
    case 'not-in':
      if (!found) return false;
      return !valueIn(value, rule.value);
    case 'lte': {
      const n = toNumber(value);
      const t = toNumber(rule.value as string | number | boolean | undefined);
      return found && n !== undefined && t !== undefined && n <= t;
    }
    case 'gte': {
      const n = toNumber(value);
      const t = toNumber(rule.value as string | number | boolean | undefined);
      return found && n !== undefined && t !== undefined && n >= t;
    }
    case 'present':
      return found && value !== undefined && value !== null;
    default:
      return false;
  }
}

function predicateHolds(pred: RulePredicate, root: Record<string, unknown>): boolean {
  return conditionHolds(pred, lookupAttribute(root, pred.attributePath));
}

function asObjectList(value: unknown): Record<string, unknown>[] {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) {
    return value
      .filter((v) => v !== undefined && v !== null)
      .map((v) => (typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : { value: v }));
  }
  if (typeof value === 'object') return [value as Record<string, unknown>];
  return [{ value }];
}

function compoundHolds(rule: StructuralRule, root: Record<string, unknown>): boolean {
  const hasCompound = !!(rule.allOf || rule.anyOf);
  if (!hasCompound) {
    return conditionHolds(rule, lookupAttribute(root, rule.attributePath));
  }
  let ok = true;
  if (rule.allOf) ok = ok && rule.allOf.every((p) => predicateHolds(p, root));
  if (rule.anyOf) ok = ok && rule.anyOf.some((group) => group.every((p) => predicateHolds(p, root)));
  return ok;
}

function ruleTypes(rule: StructuralRule): string[] {
  const types = new Set<string>([rule.resourceType, ...(rule.resourceTypes || [])]);
  return [...types];
}

function duplicateHits(
  resources: ConfigResource[],
  rule: StructuralRule,
  scanRoot: string
): CrucibleFinding[] {
  const types = new Set(ruleTypes(rule));
  const byFile = new Map<string, ConfigResource[]>();
  for (const r of resources) {
    if (r.resourceType === 'dockerfile') continue;
    if (!types.has(r.resourceType)) continue;
    const list = byFile.get(r.file) || [];
    list.push(r);
    byFile.set(r.file, list);
  }
  const out: CrucibleFinding[] = [];
  for (const [file, list] of byFile) {
    const ordered = [...list].sort((a, b) => a.startLine - b.startLine);
    // Trivy DS016 / Hadolint DL4003: second and later CMD/ENTRYPOINT/HEALTHCHECK.
    // File-wide (not per-stage). Honest gap vs Trivy stage_cmd.
    for (let i = 1; i < ordered.length; i++) {
      const cur = ordered[i];
      out.push({
        ruleId: rule.ruleId,
        file,
        uri: toUri(scanRoot, file),
        startLine: cur.startLine,
        message: rule.message,
        severity: rule.severity || 'MED',
        resourceType: cur.resourceType,
      });
    }
  }
  return out;
}

function consecutiveHits(
  resources: ConfigResource[],
  rule: StructuralRule,
  scanRoot: string
): CrucibleFinding[] {
  const types = new Set(ruleTypes(rule));
  const byFile = new Map<string, ConfigResource[]>();
  for (const r of resources) {
    if (r.resourceType === 'dockerfile') continue;
    const list = byFile.get(r.file) || [];
    list.push(r);
    byFile.set(r.file, list);
  }
  const out: CrucibleFinding[] = [];
  for (const [file, list] of byFile) {
    const ordered = [...list].sort((a, b) => a.startLine - b.startLine);
    for (let i = 1; i < ordered.length; i++) {
      const prev = ordered[i - 1];
      const cur = ordered[i];
      if (!types.has(prev.resourceType) || !types.has(cur.resourceType)) continue;
      const prevArgs = String(prev.attributes.args || '');
      const curArgs = String(cur.attributes.args || '');
      const prevCmds = prevArgs.split(/&&|;/).map((s) => s.trim()).filter(Boolean).length;
      const curCmds = curArgs.split(/&&|;/).map((s) => s.trim()).filter(Boolean).length;
      // Hadolint DL3059 skips when either RUN has more than 2 present commands.
      if (prevCmds > 2 || curCmds > 2) continue;
      out.push({
        ruleId: rule.ruleId,
        file,
        uri: toUri(scanRoot, file),
        startLine: cur.startLine,
        message: rule.message,
        severity: rule.severity || 'MED',
        resourceType: cur.resourceType,
      });
    }
  }
  return out;
}

function toUri(scanRoot: string, file: string): string {
  const abs = path.isAbsolute(file) ? file : path.resolve(scanRoot, file);
  let rel = path.relative(path.resolve(scanRoot), abs);
  if (!rel || rel.startsWith('..')) rel = path.basename(abs);
  return rel.split(path.sep).join('/').replace(/^\.\//, '');
}

export function evaluateRules(
  resources: ConfigResource[],
  rules: StructuralRule[],
  scanRoot: string
): CrucibleFinding[] {
  const findings: CrucibleFinding[] = [];
  const byFile = new Map<string, ConfigResource[]>();
  for (const r of resources) {
    const list = byFile.get(r.file) || [];
    list.push(r);
    byFile.set(r.file, list);
  }

  for (const rule of rules) {
    if (rule.condition === 'consecutive') {
      findings.push(...consecutiveHits(resources, rule, scanRoot));
      continue;
    }
    if (rule.condition === 'duplicate') {
      findings.push(...duplicateHits(resources, rule, scanRoot));
      continue;
    }

    const types = new Set(ruleTypes(rule));
    const pathEmpty = !rule.attributePath;
    const noCompound = !rule.allOf && !rule.anyOf;
    if (rule.condition === 'missing' && pathEmpty && noCompound) {
      // Resource-absent: one finding per file that has no resource of this type.
      for (const [file, list] of byFile) {
        if (rule.requiresResourceType && !list.some((r) => r.resourceType === rule.requiresResourceType)) continue;
        const has = list.some((r) => types.has(r.resourceType));
        if (has) continue;
        findings.push({
          ruleId: rule.ruleId,
          file,
          uri: toUri(scanRoot, file),
          startLine: 1,
          message: rule.message,
          severity: rule.severity || 'MED',
          resourceType: rule.resourceType,
        });
      }
      continue;
    }

    for (const r of resources) {
      if (!types.has(r.resourceType)) continue;
      if (rule.unlessSameFileResource) {
        const sibs = byFile.get(r.file) || [];
        if (sibs.some((s) => s.resourceType === rule.unlessSameFileResource)) continue;
      }
      if (rule.unless && predicateHolds(rule.unless, r.attributes)) continue;

      let hit = false;
      if (rule.anyElement && rule.attributePath) {
        const looked = lookupAttribute(r.attributes, rule.attributePath);
        if (looked.found) {
          for (const item of asObjectList(looked.value)) {
            if (rule.unless && predicateHolds(rule.unless, item)) continue;
            if (compoundHolds(rule, item)) {
              hit = true;
              break;
            }
          }
        }
      } else {
        hit = compoundHolds(rule, r.attributes);
      }
      if (!hit) continue;
      findings.push({
        ruleId: rule.ruleId,
        file: r.file,
        uri: toUri(scanRoot, r.file),
        startLine: r.startLine,
        message: rule.message,
        severity: rule.severity || 'MED',
        resourceType: r.resourceType,
      });
    }
  }
  return findings;
}

export async function runCrucible(
  targetPath: string,
  rules: StructuralRule[] = DEFAULT_RULES
): Promise<CrucibleReport> {
  const start = Date.now();
  const notes: string[] = [];
  const files = discoverIacFiles(targetPath);
  const resources: ConfigResource[] = [];
  const scanRoot = (() => {
    try {
      return fs.statSync(targetPath).isFile() ? path.dirname(targetPath) : targetPath;
    } catch {
      return targetPath;
    }
  })();

  for (const file of files) {
    let src: string;
    try {
      src = fs.readFileSync(file, 'utf8');
    } catch (err) {
      notes.push(`${file}: read error — ${(err as Error).message}`);
      continue;
    }
    const base = path.basename(file);
    const ext = path.extname(file).toLowerCase();
    try {
      if (TF_EXT.has(ext)) {
        const doc = parseHcl(src, file);
        notes.push(...doc.notes);
        resources.push(...resourcesFromHclBlocks(doc.blocks, file));
      } else if (isDockerFilename(base)) {
        const doc = parseDockerfile(src, file);
        notes.push(...doc.notes);
        resources.push(...resourcesFromDocker(doc));
      }
    } catch (err) {
      notes.push(`${file}: parse error — ${(err as Error).message}`);
    }
  }

  const findings = evaluateRules(resources, rules, scanRoot);
  return {
    findings,
    filesAnalyzed: files.length,
    resources: resources.length,
    durationMs: Date.now() - start,
    notes,
  };
}

export interface CrucibleSarif {
  $schema: string;
  version: string;
  runs: Array<{
    tool: { driver: { name: string; rules: Array<{ id: string; name: string }> } };
    results: Array<{
      ruleId: string;
      level: 'error' | 'warning' | 'note';
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region: { startLine: number };
        };
      }>;
    }>;
  }>;
}

export function crucibleToSarif(findings: CrucibleFinding[]): CrucibleSarif {
  const ruleIds = [...new Set(findings.map((f) => f.ruleId))];
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'VANTAGE-CRUCIBLE',
            rules: ruleIds.map((id) => ({ id, name: id })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: f.severity === 'HIGH' ? 'error' : f.severity === 'LOW' ? 'note' : 'warning',
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.uri },
                region: { startLine: f.startLine },
              },
            },
          ],
        })),
      },
    ],
  };
}

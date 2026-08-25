// VANTAGE MCP tool — get_findings
// Returns a filtered subset of findings from a previous analyze call,
// keyed by stable IDs so they're safe to pass to verify_fix later.

import { getReportById } from '../cache';
import { GetFindingsInputType } from '../schemas';
import { AdversarialFinding, VantageReport } from '../../types';
import { computeFindingId, FindingSource } from '../finding-id';

export interface NormalizedFinding {
  id: string;
  source: FindingSource;
  severity: 'HIGH' | 'MED' | 'LOW';
  file: string;
  line?: number;
  type: string;
  description: string;
  fix?: string;
}

export interface FindingsResult {
  reportId: string;
  findings: NormalizedFinding[];
  total: number;
  filtered: number;
}

/**
 * Build the canonical, deduplicated list of findings from a VANTAGE report.
 * Exported so verify_fix can compute the same list for before/after diffing
 * without duplicating the normalization logic.
 */
export function collectFindings(report: VantageReport, targetPath?: string): NormalizedFinding[] {
  const out: NormalizedFinding[] = [];
  const seen = new Set<string>();

  const push = (f: NormalizedFinding) => {
    if (seen.has(f.id)) return;
    seen.add(f.id);
    out.push(f);
  };

  // PULSAR adversarial findings
  for (const f of report.pulsar.adversarialFindings ?? []) {
    push({
      id: computeFindingId({
        source: 'PULSAR',
        file: f.file,
        line: f.line,
        type: f.type,
        description: f.description,
      }, targetPath),
      source: 'PULSAR',
      severity: f.severity,
      file: f.file,
      line: f.line,
      type: f.type,
      description: f.description,
      fix: f.testCase ? `Test: ${f.testCase}` : undefined,
    });
  }

  // NOVA circular dependencies → HIGH findings
  for (const circ of report.nova.circularDeps ?? []) {
    const firstFile = circ.cycle?.[0] ?? '';
    push({
      id: computeFindingId({
        source: 'NOVA',
        file: firstFile,
        line: 0,
        type: 'circular-dep',
        description: circ.description,
      }, targetPath),
      source: 'NOVA',
      severity: 'HIGH',
      file: firstFile,
      type: 'circular-dep',
      description: circ.description,
    });
  }

  // AURORA top issues (ECLIPSE-risk and misc). Skip any issue whose
  // (file, line, description) matches an already-collected PULSAR or NOVA
  // finding — AURORA's top-issues list is a promotion layer, not a
  // distinct source. Without this check, every HIGH PULSAR finding that
  // gets promoted into AURORA appears twice in the normalized list (once
  // as PULSAR, once as a synthetic ECLIPSE entry).
  const locationKeys = new Set(
    out.map(f => `${f.file}:${f.line ?? 0}:${(f.description || '').trim()}`)
  );
  for (const issue of report.aurora.topIssues ?? []) {
    const locKey = `${issue.file}:${issue.line ?? 0}:${(issue.description || '').trim()}`;
    if (locationKeys.has(locKey)) continue;
    push({
      id: computeFindingId({
        source: 'ECLIPSE',
        file: issue.file,
        line: issue.line,
        type: 'risk',
        description: issue.description,
      }, targetPath),
      source: 'ECLIPSE',
      severity: issue.severity,
      file: issue.file,
      line: issue.line,
      type: 'risk',
      description: issue.description,
      fix: issue.fix,
    });
  }

  return out;
}

export async function toolGetFindings(input: GetFindingsInputType): Promise<FindingsResult> {
  const entry = getReportById(input.report_id);
  if (!entry) {
    throw new Error(`Report not found: ${input.report_id}. Run analyze first.`);
  }

  const allFindings = collectFindings(entry.report, entry.targetPath);
  const filters = input.filters ?? {};

  let filtered = allFindings;
  if (filters.severity) {
    filtered = filtered.filter(f => f.severity === filters.severity);
  }
  if (filters.engine) {
    filtered = filtered.filter(f => f.source === filters.engine);
  }
  if (filters.file) {
    const needle = filters.file.toLowerCase();
    filtered = filtered.filter(f => f.file.toLowerCase().includes(needle));
  }

  return {
    reportId: input.report_id,
    findings: filtered,
    total: allFindings.length,
    filtered: filtered.length,
  };
}

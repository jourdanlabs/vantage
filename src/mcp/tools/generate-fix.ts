// VANTAGE MCP tool — generate_fix
//
// Takes a finding ID from a prior analyze call, tries each fix template in
// turn, applies the produced patch to a temp working copy, verifies the
// patch via verify_fix (same gate the autonomous agent would use), and
// returns the result.
//
// The template path is deterministic and free. If no template matches,
// v1 returns a "no fix available" response; v2 will invoke the LLM
// fallback here.

import * as fs from 'fs';
import * as path from 'path';
import { getReportById } from '../cache';
import { GenerateFixInputType } from '../schemas';
import { collectFindings } from './get-findings';
import { toolVerifyFix, VerifyFixResult } from './verify-fix';
import { templatesForType, ALL_TEMPLATES } from '../fix-templates';
import { TemplateOutput } from '../fix-templates/types';

export interface GenerateFixResult {
  success: boolean;
  findingId: string;
  templateId?: string;
  rationale?: string;
  patch?: string;
  verification?: VerifyFixResult;
  attemptedTemplates: Array<{
    templateId: string;
    applied: boolean;
    verified?: boolean;
    skipReason?: string;
  }>;
  /** If success=false, why. Helps the caller decide whether to surface to the LLM path. */
  reason?: string;
}

export async function toolGenerateFix(input: GenerateFixInputType): Promise<GenerateFixResult> {
  const entry = getReportById(input.report_id);
  if (!entry) {
    throw new Error(
      `Baseline report not found: ${input.report_id}. Call analyze first and pass its reportId here.`
    );
  }

  const findings = collectFindings(entry.report, entry.targetPath);
  const finding = findings.find(f => f.id === input.finding_id);
  if (!finding) {
    return {
      success: false,
      findingId: input.finding_id,
      attemptedTemplates: [],
      reason: `Finding ${input.finding_id} not found in report ${input.report_id}. It may have been from a different analyze call.`,
    };
  }

  // Resolve the finding's file path to something we can read. The finding's
  // `file` may be corpus-relative (good) or absolute (from the original
  // analyze). Try both.
  const absPath = path.isAbsolute(finding.file)
    ? finding.file
    : path.join(input.target_path, finding.file);
  const altPath = path.join(input.target_path, finding.file);

  const resolvedPath = fs.existsSync(absPath)
    ? absPath
    : fs.existsSync(altPath)
      ? altPath
      : null;

  if (!resolvedPath) {
    return {
      success: false,
      findingId: input.finding_id,
      attemptedTemplates: [],
      reason: `Could not locate the finding's file. Tried ${absPath} and ${altPath}.`,
    };
  }

  const fileContents = fs.readFileSync(resolvedPath, 'utf8');
  const relPath = path.relative(input.target_path, resolvedPath)
    .split(path.sep).join('/');

  // Collect candidate templates. A template can claim a finding type directly
  // or via substring match (e.g., a template handles all "error-boundary"
  // findings but the normalized type is "error-boundary").
  const candidates = templatesForType(finding.type);
  if (candidates.length === 0) {
    return {
      success: false,
      findingId: input.finding_id,
      attemptedTemplates: ALL_TEMPLATES.map(t => ({
        templateId: t.id,
        applied: false,
        skipReason: `does not handle finding type "${finding.type}"`,
      })),
      reason: input.allow_llm_fallback
        ? `No template matches finding type "${finding.type}"; LLM fallback is stubbed in v1 and will ship in v2.`
        : `No template matches finding type "${finding.type}". Pass allow_llm_fallback=true to request an LLM path (stubbed in v1).`,
    };
  }

  const attempts: GenerateFixResult['attemptedTemplates'] = [];

  for (const template of candidates) {
    const out: TemplateOutput = template.attempt({
      filePath: relPath,
      fileContents,
      line: finding.line ?? 0,
      findingType: finding.type,
      description: finding.description,
    });

    if (!out.applied) {
      attempts.push({
        templateId: template.id,
        applied: false,
        skipReason: out.skipReason,
      });
      continue;
    }

    // Verify the candidate patch via the existing verify_fix tool.
    let verification: VerifyFixResult;
    try {
      verification = await toolVerifyFix({
        target_path: input.target_path,
        patch: out.patch,
        report_id: input.report_id,
        original_findings: [input.finding_id],
        threshold: input.threshold,
      });
    } catch (err: unknown) {
      attempts.push({
        templateId: template.id,
        applied: true,
        verified: false,
        skipReason: `verify_fix threw: ${(err as Error).message}`,
      });
      continue;
    }

    const resolved = verification.resolvedFindings.includes(input.finding_id);
    const noNewHigh = verification.newFindings.every(f =>
      f.severity !== 'HIGH' && f.severity !== 'CRITICAL'
    );

    if (resolved && noNewHigh && verification.patchApplied) {
      attempts.push({ templateId: template.id, applied: true, verified: true });
      return {
        success: true,
        findingId: input.finding_id,
        templateId: template.id,
        rationale: out.rationale,
        patch: out.patch,
        verification,
        attemptedTemplates: attempts,
      };
    }

    const reasons: string[] = [];
    if (!verification.patchApplied) reasons.push('patch failed to apply');
    if (!resolved) reasons.push('finding still present post-patch');
    if (!noNewHigh) reasons.push('patch introduced a HIGH/CRITICAL finding');

    attempts.push({
      templateId: template.id,
      applied: true,
      verified: false,
      skipReason: reasons.join('; '),
    });
  }

  return {
    success: false,
    findingId: input.finding_id,
    attemptedTemplates: attempts,
    reason: input.allow_llm_fallback
      ? 'All templates failed verification; LLM fallback is stubbed in v1 and will ship in v2.'
      : 'All templates failed verification. Pass allow_llm_fallback=true to request an LLM path (stubbed in v1).',
  };
}

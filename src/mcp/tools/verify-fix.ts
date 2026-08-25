// VANTAGE MCP tool — verify_fix
//
// Applies a patch to a temp working copy of the target, re-runs VANTAGE,
// and reports which of the original findings were resolved, which remain,
// and which new findings (if any) the patch introduced.
//
// Correctness depends on stable finding IDs (see ../finding-id.ts). The
// file-path component of every ID is normalized to a corpus-relative form,
// so the ID of a finding at `/Users/me/app/foo.js` is the same as that of
// the same finding at `/tmp/vantage-verify-abc/app/foo.js`.

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import { runPipeline } from '../../engines/index';
import { getReportById } from '../cache';
import { VerifyFixInputType } from '../schemas';
import { collectFindings } from './get-findings';

export interface VerifyFixResult {
  resolvedFindings: string[];   // IDs from original_findings that are gone post-patch
  remainingFindings: string[];  // IDs from original_findings that still exist
  newFindings: Array<{          // Findings introduced by the patch (not in baseline)
    id: string;
    severity: string;
    file: string;
    line?: number;
    description: string;
  }>;
  verdict: 'APPROVED' | 'REJECTED';
  score: number;
  scorePct: string;
  patchApplied: boolean;
  patchError?: string;
}

export async function toolVerifyFix(input: VerifyFixInputType): Promise<VerifyFixResult> {
  const targetPath = path.resolve(input.target_path);
  const threshold = input.threshold ?? 0.80;

  // Look up the baseline report by the explicit report_id, not by guessing
  // from finding ID substrings.
  const baseline = getReportById(input.report_id);
  if (!baseline) {
    throw new Error(
      `Baseline report not found: ${input.report_id}. ` +
      `Call analyze first and pass the returned reportId here.`
    );
  }

  const baselineFindings = collectFindings(baseline.report, baseline.targetPath);
  const baselineIds = new Set(baselineFindings.map(f => f.id));
  const originalIds = new Set(input.original_findings);

  // ── Build temp working copy ──────────────────────────────────────────────
  const tmpDir = path.join(os.tmpdir(), `vantage-verify-${crypto.randomUUID()}`);
  try {
    fs.mkdirSync(tmpDir, { recursive: true });
    execSync(`cp -R ${JSON.stringify(targetPath + '/.')} ${JSON.stringify(tmpDir + '/')}`, {
      stdio: 'pipe',
    });
  } catch (err: unknown) {
    throw new Error(`Failed to create working copy: ${(err as Error).message}`);
  }

  // ── Apply patch ──────────────────────────────────────────────────────────
  const patchFile = path.join(os.tmpdir(), `vantage-patch-${crypto.randomUUID()}.patch`);
  let patchApplied = false;
  let patchError: string | undefined;

  try {
    fs.writeFileSync(patchFile, input.patch, 'utf8');

    try {
      execSync(`git -C ${JSON.stringify(tmpDir)} apply ${JSON.stringify(patchFile)}`, {
        stdio: 'pipe',
      });
      patchApplied = true;
    } catch {
      try {
        execSync(`patch -p1 -d ${JSON.stringify(tmpDir)} < ${JSON.stringify(patchFile)}`, {
          stdio: 'pipe',
          shell: '/bin/sh',
        });
        patchApplied = true;
      } catch (err2: unknown) {
        patchError = (err2 as Error).message;
        patchApplied = false;
      }
    }
  } finally {
    try { fs.unlinkSync(patchFile); } catch { /* ignore */ }
  }

  // ── Re-analyze (patched copy if apply succeeded, otherwise original) ─────
  const analyzeTarget = patchApplied ? tmpDir : targetPath;
  const postReport = await runPipeline(analyzeTarget, null, undefined, threshold);
  const postFindings = collectFindings(postReport, analyzeTarget);

  // The IDs in postFindings are already anchored to `analyzeTarget` via
  // collectFindings, so they match the anchoring of the baseline set.  If
  // a finding survived the patch unchanged, the ID will be identical.
  const postIds = new Set(postFindings.map(f => f.id));

  const resolvedFindings: string[] = [];
  const remainingFindings: string[] = [];
  for (const origId of originalIds) {
    if (!baselineIds.has(origId)) {
      // Caller passed an ID that isn't in the baseline report — treat as
      // already-resolved rather than silently remaining.
      resolvedFindings.push(origId);
      continue;
    }
    if (postIds.has(origId)) {
      remainingFindings.push(origId);
    } else {
      resolvedFindings.push(origId);
    }
  }

  // New findings = post-patch findings whose IDs weren't in the baseline at all.
  const newFindings = postFindings
    .filter(f => !baselineIds.has(f.id))
    .slice(0, 20)
    .map(f => ({
      id: f.id,
      severity: f.severity,
      file: f.file,
      line: f.line,
      description: f.description,
    }));

  // ── Cleanup ──────────────────────────────────────────────────────────────
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }

  return {
    resolvedFindings,
    remainingFindings,
    newFindings,
    verdict: postReport.aurora.verdict,
    score: postReport.aurora.score,
    scorePct: `${(postReport.aurora.score * 100).toFixed(1)}%`,
    patchApplied,
    patchError,
  };
}

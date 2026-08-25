// VANTAGE Benchmark Harness — scoring engine
//
// Computes precision, recall, F1 against ground truth using a deliberately
// strict matching rule. The rule is documented on /methodology and any change
// to the rule must be reflected there to keep the leaderboard auditable.

import * as path from 'path';
import { Finding } from './runners/base';
import { CorpusGroundTruth, Vulnerability } from './ground-truth/schema';

/** Line tolerance for scope='file' matches. ±LINE_TOLERANCE around the GT line is a TP. */
export const LINE_TOLERANCE = 5;

export interface MatchResult {
  tp: Array<{ finding: Finding; gt: Vulnerability }>;
  fp: Finding[];
  fn: Vulnerability[];
  precision: number | null;
  recall: number | null;
  f1: number | null;
}

/**
 * Match tool findings against the ground truth catalog for a corpus.
 *
 * Matching rule (intentionally strict — credibility > generosity):
 *  - Path: normalized finding path must END WITH the GT path fragment.
 *    `endsWith` is required so a tool can't claim credit by reporting
 *    a finding in a different file with the same basename.
 *  - Type: normalized finding type must equal GT type (after type-alias map).
 *  - Line: depends on `gt.scope`:
 *      * 'file' (default) — |finding.line − gt.line| ≤ LINE_TOLERANCE
 *      * 'project'        — line ignored (used for whole-file vulns; document why in GT entry)
 *
 * Each GT entry can be claimed by exactly one finding (first match wins).
 * Each finding can claim exactly one GT entry (no double counting).
 *
 * Findings that don't match any unclaimed GT are FP. GT entries unclaimed
 * after all findings are processed are FN.
 *
 * Tools whose runners report file paths in different formats (absolute vs
 * relative, posix vs win) MUST normalize at the runner boundary before
 * returning. The scoring layer assumes paths are already corpus-relative
 * posix strings — this is enforced by `normalizeFinding` below as a safety
 * net, but runner-side normalization is required for correctness.
 */
export function scoreFindings(
  findings: Finding[],
  gt: CorpusGroundTruth,
  targetPath: string
): MatchResult {
  const claimedGT = new Set<string>();
  const tp: MatchResult['tp'] = [];
  const fp: Finding[] = [];

  for (const f of findings) {
    const normFile = normalizePath(f.file, targetPath);
    const normType = (f.type || '').toLowerCase();

    let matched = false;
    for (const gtEntry of gt.vulnerabilities) {
      if (claimedGT.has(gtEntry.id)) continue;

      const gtFile = normalizeGtPath(gtEntry.file);
      const gtType = (gtEntry.type || '').toLowerCase();

      // Strict suffix match: prevents a finding in `app/baz/bar.js` from
      // claiming a GT entry in `app/foo/bar.js`. The trailing path-segment
      // boundary check guards against `bar.js` matching `foobar.js`.
      const fileMatch = isFileMatch(normFile, gtFile);
      const typeMatch = normType === gtType;

      const scope = gtEntry.scope ?? 'file';
      const lineMatch = scope === 'project'
        ? true
        : Math.abs(f.line - gtEntry.line) <= LINE_TOLERANCE;

      if (fileMatch && typeMatch && lineMatch) {
        tp.push({ finding: f, gt: gtEntry });
        claimedGT.add(gtEntry.id);
        matched = true;
        break;
      }
    }

    if (!matched) {
      fp.push(f);
    }
  }

  const fn = gt.vulnerabilities.filter(e => !claimedGT.has(e.id));

  const tpCount = tp.length;
  const fpCount = fp.length;
  const fnCount = fn.length;

  // Standard precision/recall semantics:
  //   - precision = TP / (TP + FP); undefined if no findings produced
  //   - recall    = TP / (TP + FN); undefined if no GT entries (corpus empty)
  //   - f1        = 2·P·R / (P + R); 0 if both are 0; null if either is undefined
  const precision = (tpCount + fpCount) > 0 ? tpCount / (tpCount + fpCount) : null;
  const recall = (tpCount + fnCount) > 0 ? tpCount / (tpCount + fnCount) : null;
  let f1: number | null;
  if (precision === null || recall === null) {
    f1 = null;
  } else if (precision === 0 && recall === 0) {
    f1 = 0;
  } else {
    f1 = 2 * precision * recall / (precision + recall);
  }

  return { tp, fp, fn, precision, recall, f1 };
}

/**
 * Normalize a finding path to corpus-relative posix form. Runners are
 * expected to do this themselves; this is a defensive fallback so a
 * non-conforming runner doesn't silently distort the scoring.
 */
function normalizePath(filePath: string, targetPath: string): string {
  if (!filePath) return '';
  const abs = path.isAbsolute(filePath) ? filePath : path.resolve(targetPath, filePath);
  const rel = path.relative(targetPath, abs);
  // path.relative returns `../...` when filePath escapes targetPath; in that
  // case fall back to the original (caller bug, but better than misattributing).
  const useRel = rel && !rel.startsWith('..') ? rel : filePath;
  return useRel.split(path.sep).join('/').replace(/^\.\//, '');
}

/** Normalize a GT path fragment to posix and strip any leading slash. */
function normalizeGtPath(gtFile: string): string {
  return (gtFile || '').replace(/\\/g, '/').replace(/^\.?\//, '');
}

/**
 * Strict suffix match with a path-segment boundary so `foobar.js` does
 * not match a GT path of `bar.js`. The boundary is either the start of
 * the finding path or a `/` immediately preceding the GT fragment.
 */
function isFileMatch(findingPath: string, gtPath: string): boolean {
  if (!gtPath) return false;
  if (findingPath === gtPath) return true;
  if (!findingPath.endsWith(gtPath)) return false;
  const boundaryIndex = findingPath.length - gtPath.length;
  if (boundaryIndex === 0) return true;
  return findingPath.charAt(boundaryIndex - 1) === '/';
}

export interface ToolScore {
  tool: string;
  toolVersion: string;
  corpus: string;
  corpusLabel: string;
  tp: number;
  fp: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  durationMs: number;
  tpDetails: Array<{ file: string; line: number; type: string }>;
  fpDetails: Array<{ file: string; line: number; type: string; description: string }>;
  fnDetails: Array<{ id: string; file: string; line: number; type: string; description: string }>;
}

export interface BenchmarkResult {
  tool: string;
  toolVersion: string;
  runDate: string;
  commitSha: string;
  scores: ToolScore[];
  /**
   * Aggregate F1 across corpora (harmonic mean of per-corpus F1).
   * Null if any corpus reports null F1 (tool errored on that corpus).
   * Zero if any corpus reports F1 of 0 (tool found nothing on a non-empty corpus).
   */
  aggregateF1: number | null;
  medianDurationMs: number;
}

export function aggregateF1(scores: ToolScore[]): number | null {
  const f1s = scores.map(s => s.f1);
  // Null propagates: a tool that errored on a corpus shouldn't get a free
  // pass by having its bad corpus dropped from the average.
  if (f1s.some(f => f === null)) return null;
  if (f1s.length === 0) return null;
  // Any 0 → harmonic mean is 0 (or undefined; we choose 0 as the conservative
  // reading: "tool failed on at least one corpus, so its aggregate is 0").
  if (f1s.some(f => f === 0)) return 0;
  const sum = f1s.reduce<number>((a, b) => a + 1 / (b as number), 0);
  return f1s.length / sum;
}

export function medianDuration(scores: ToolScore[]): number {
  const durations = scores.map(s => s.durationMs).sort((a, b) => a - b);
  if (durations.length === 0) return 0;
  const mid = Math.floor(durations.length / 2);
  return durations.length % 2 === 0
    ? (durations[mid - 1] + durations[mid]) / 2
    : durations[mid];
}

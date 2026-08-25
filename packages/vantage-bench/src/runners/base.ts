// VANTAGE Benchmark Harness — abstract runner interface
// Implement this to add a new tool to the leaderboard.

import * as path from 'path';

export interface Finding {
  /**
   * Corpus-relative POSIX path (e.g. "app/routes/contributions.js").
   * Runners MUST normalize before returning. The scoring layer assumes this.
   * Use `toCorpusRelativePosix(targetPath, foundPath)` from this module.
   */
  file: string;
  line: number;
  type: string;      // normalized category: 'injection', 'hardcoded-secret', 'error-boundary', etc.
  severity: 'CRITICAL' | 'HIGH' | 'MED' | 'LOW';
  description: string;
  rawType?: string;  // original type string from the tool before normalization
}

/**
 * Normalize a tool-reported path to corpus-relative POSIX form.
 *
 * Why this lives in the runner contract: every static analyzer reports
 * paths differently. Semgrep returns paths relative to its working dir.
 * SonarQube returns `<projectKey>:<file>` strings. CodeQL emits
 * `file://...` URIs in SARIF. VANTAGE returns absolute paths.  Without
 * normalization at the runner boundary, scoring would have to second-guess
 * which tool's convention each finding came from — which both invites
 * bugs and creates per-tool bias in the leaderboard.
 */
export function toCorpusRelativePosix(targetPath: string, foundPath: string): string {
  if (!foundPath) return '';
  let p = foundPath;
  // Strip file:// URI prefix (SARIF, sometimes Semgrep)
  p = p.replace(/^file:\/\//, '');
  // URL-decoded percent-encoding (CodeQL emits these for spaces, etc.)
  try { p = decodeURIComponent(p); } catch { /* leave as-is on bad input */ }
  // Resolve against targetPath if it's already relative
  const abs = path.isAbsolute(p) ? p : path.resolve(targetPath, p);
  const rel = path.relative(targetPath, abs);
  // If the path is outside the target dir, return the original normalized to
  // posix so a misconfigured runner doesn't silently produce empty paths.
  const useRel = rel && !rel.startsWith('..') ? rel : p;
  return useRel.split(path.sep).join('/').replace(/^\.\//, '');
}

export interface RunResult {
  findings: Finding[];
  durationMs: number;
  toolVersion: string;
  error?: string;     // if the tool errored out, set this and return empty findings
}

export interface Runner {
  /** Tool name, e.g. "VANTAGE", "Semgrep", "SonarQube" */
  name: string;

  /**
   * Run the tool against a target directory and return normalized findings.
   * Must not throw — return RunResult.error instead.
   */
  run(targetPath: string): Promise<RunResult>;
}

/** Type normalization map for findings across tools */
export const TYPE_ALIASES: Record<string, string> = {
  // injection variants
  'eval-injection': 'injection',
  'nosql-injection': 'injection',
  'sql-injection': 'injection',
  'code-injection': 'injection',
  'command-injection': 'injection',
  'redos': 'injection',

  // secret variants
  'hardcoded-secret': 'hardcoded-secret',
  'hardcoded-password': 'hardcoded-secret',
  'hardcoded-credentials': 'hardcoded-secret',
  'private-key': 'hardcoded-secret',

  // error boundary variants
  'error-boundary': 'error-boundary',
  'missing-error-handling': 'error-boundary',

  // semgrep type → normalized
  'nodejs.express.security.audit.express-check-csurf-middleware-usage': 'csrf',
  'javascript.lang.security.audit.evaluate.eval-detected': 'injection',
  'javascript.express.security.audit.express-hardcoded-secret': 'hardcoded-secret',
  // semgrep 1.136.x resolves the OWASP pack's eval-via-string-concat pattern
  // to this id (1.159.x emitted eval-detected for the same lines). Same vuln
  // class — code injection. Without this alias, semgrep's correct findings
  // on NodeGoat contributions.js:32/33 score as FPs (type mismatch).
  'javascript.lang.security.audit.code-string-concat.code-string-concat': 'injection',
};

export function normalizeType(rawType: string): string {
  const lower = rawType.toLowerCase();
  // Check exact alias map
  if (TYPE_ALIASES[lower]) return TYPE_ALIASES[lower];
  // Fuzzy match by substring
  if (lower.includes('inject') || lower.includes('eval') || lower.includes('nosql') || lower.includes('redos')) return 'injection';
  if (lower.includes('secret') || lower.includes('password') || lower.includes('credential') || lower.includes('key')) return 'hardcoded-secret';
  if (lower.includes('error') || lower.includes('boundary') || lower.includes('parse')) return 'error-boundary';
  if (lower.includes('csrf')) return 'csrf';
  if (lower.includes('xss') || lower.includes('html')) return 'xss';
  if (lower.includes('traversal') || lower.includes('path')) return 'path-traversal';
  return lower;
}

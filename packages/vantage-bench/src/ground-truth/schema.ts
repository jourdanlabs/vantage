// VANTAGE Benchmark Harness — ground truth types (CC-BY-4.0)

export interface Vulnerability {
  id: string;
  file: string;      // path fragment relative to corpus root, e.g. "app/routes/contributions.js"
  line: number;      // canonical line number; matched against finding.line with ±5 tolerance when scope='file'
  type: string;      // maps to runner Finding.type after normalization
  category: string;
  cwe?: string;
  cve?: string;
  description: string;
  owasp?: string;
  /**
   * Scoring scope.
   * - 'file' (default): match requires file + type + line within ±LINE_TOLERANCE
   * - 'project': match requires file + type only — line is ignored.
   *   Use sparingly, only for vulnerabilities that are inherently file-wide
   *   (e.g. "missing CSRF middleware" applies to a whole router, not a line).
   *   Document the choice in the GT entry's `description`.
   */
  scope?: 'file' | 'project';
}

export interface OutOfScopeVuln {
  id: string;
  file: string;
  line?: number;
  category: string;
  cwe?: string;
  description: string;
  reason: string;    // why this is out of scope for benchmark tier-1
}

export interface CorpusGroundTruth {
  corpus: string;              // machine ID, e.g. "nodegoat"
  label: string;               // human label, e.g. "OWASP/NodeGoat"
  repo: string;
  sha: string;
  license: string;             // license of the corpus itself
  groundTruthLicense: string;  // license for the GT catalog (CC-BY-4.0)
  groundTruthVersion: string;  // YYYY-MM-DD of last catalog update
  vulnerabilities: Vulnerability[];
  knownOutOfScope?: OutOfScopeVuln[];
}

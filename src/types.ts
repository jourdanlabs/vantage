// VANTAGE — COSMIC Pipeline Types

export interface FileInfo {
  path: string;
  relativePath: string;
  language: string;  // registry-driven; e.g. 'typescript', 'python', 'go', 'other'
  lines: number;
  content: string;
}

export interface FunctionInfo {
  name: string;
  file: string;
  startLine: number;
  endLine: number;
  lines: number;
  complexity: number; // cyclomatic complexity approximation
  isAsync: boolean;
  hasErrorHandling: boolean;
  parameters: string[];
}

export interface ImportInfo {
  file: string;
  source: string; // what is imported from
  line: number;
  isRelative: boolean;
}

export interface ClassInfo {
  name: string;
  file: string;
  line: number;
  type: 'class' | 'struct' | 'enum' | 'interface' | 'protocol';
  exportCount: number;
}

export interface TodoItem {
  file: string;
  line: number;
  type: 'TODO' | 'FIXME' | 'HACK' | 'XXX';
  text: string;
}

// METEOR output
export interface MeteorOutput {
  files: FileInfo[];
  functions: FunctionInfo[];
  imports: ImportInfo[];
  classes: ClassInfo[];
  todos: TodoItem[];
  metrics: {
    linesOfCode: number;
    totalComplexity: number;
    todoCount: number;
    largeFunctions: FunctionInfo[]; // >100 lines
    highComplexityFunctions: FunctionInfo[]; // complexity >15
  };
  /** Files whose language is recognised but extraction is not yet reliable. */
  unsupportedFiles: {
    count: number;
    extensions: string[];   // deduplicated list of extensions seen
    filePaths: string[];     // full paths (capped at 100 for readability)
  };
}

// NOVA output
export interface CausalChain {
  root: string;
  chain: string[];
  impact: string;
  severity: 'HIGH' | 'MED' | 'LOW';
}

export interface CircularDep {
  cycle: string[];
  description: string;
}

export interface CouplingIssue {
  file: string;
  importedBy: string[];
  count: number;
  description: string;
}

export interface GodModule {
  file: string;
  lines: number;
  exportCount: number;
  description: string;
}

export interface NovaOutput {
  causalChains: CausalChain[];
  dependencyGraph: Record<string, string[]>; // file -> [files it imports]
  circularDeps: CircularDep[];
  couplingIssues: CouplingIssue[];
  godModules: GodModule[];
}

// ECLIPSE output
export interface RiskEntry {
  file: string;
  score: number; // 0.0 - 1.0
  factors: {
    complexity: number;
    coupling: number;
    testCoverage: number; // 1 = no tests, 0 = has tests
    todoDensity: number;
    functionSize: number;
  };
}

export interface EclipseOutput {
  riskScores: Record<string, number>; // file -> score
  highRisk: RiskEntry[]; // score >= 0.7
  medRisk: RiskEntry[]; // score >= 0.4
  estimatedBugProbability: number;
}

// PULSAR output
export interface AdversarialFinding {
  file: string;
  function?: string;
  line?: number;
  type: 'null-safety' | 'async-race' | 'error-boundary' | 'edge-case' | 'coupling-risk' | 'injection' | 'hardcoded-secret';
  severity: 'HIGH' | 'MED' | 'LOW';
  description: string;
  testCase: string; // the adversarial scenario
  /**
   * Product surface (Kaioken surface split 2026-08-05).
   * `security` — attacker-influenced / secrets / authz sinks.
   * `quality` — hygiene detectors (fallthrough, null-find, unchecked return, …).
   * Classified post-detect; never deleted — only filed.
   */
  surface?: 'security' | 'quality';
}

export interface PulsarOutput {
  adversarialFindings: AdversarialFinding[];
  missingGuards: string[];
  recommendations: string[];
}

// AURORA output
export interface AuroraIssue {
  severity: 'HIGH' | 'MED' | 'LOW';
  file: string;
  description: string;
  line?: number;
  fix?: string;
}

export interface AuroraOutput {
  score: number; // 0.0 - 1.0
  verdict: 'APPROVED' | 'REJECTED';
  topIssues: AuroraIssue[];
  fixes: string[];
  summary: string;
  breakdown: {
    complexityScore: number;
    dependencyScore: number;
    riskScore: number;
    adversarialScore: number;
  };
  /** Present when unsupported-language files were found in the corpus. */
  unsupportedFilesNote?: string;
  /** The threshold used to determine APPROVED vs REJECTED (default 0.80). */
  threshold: number;
}

// Full pipeline result
export interface VantageReport {
  target: string;
  timestamp: string;
  meteor: MeteorOutput;
  nova: NovaOutput;
  eclipse: EclipseOutput;
  pulsar: PulsarOutput;
  aurora: AuroraOutput;
}

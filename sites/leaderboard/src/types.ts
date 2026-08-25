export interface CorpusScore {
  corpus: string;
  corpusLabel: string;
  tp: number;
  fp: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  durationMs: number;
  tpDetails: Array<{ file: string; line: number; type: string; description?: string }>;
  fpDetails: Array<{ file: string; line: number; type: string; description: string }>;
  fnDetails: Array<{ id: string; file: string; line: number; type: string; description: string }>;
}

export interface LeaderboardEntry {
  rank: number;
  name: string;
  version: string;
  runDate: string;
  commitSha: string;
  aggregateF1: number | null;
  medianDurationMs: number;
  scores: CorpusScore[];
  /** True if the entry's numbers are from a previous scoring revision. */
  pendingRebench?: boolean;
  /** Human-readable explanation when pendingRebench is true. */
  stalenessNote?: string;
}

export interface LeaderboardData {
  generatedAt: string;
  /** Identifier for the scoring rule version that produced these numbers. Bump on every breaking change. */
  scoringVersion?: string;
  /** Short human-readable summary of what changed in this scoring version. */
  scoringChangeSummary?: string;
  tools: LeaderboardEntry[];
}

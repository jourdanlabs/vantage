// VANTAGE Benchmark Harness — report output (JSON + Markdown)

import { BenchmarkResult, ToolScore } from './scoring';

function pct(n: number | null, decimals = 1): string {
  if (n === null) return 'N/A';
  return `${(n * 100).toFixed(decimals)}%`;
}

function ms(n: number): string {
  if (n < 1000) return `${n.toFixed(0)} ms`;
  return `${(n / 1000).toFixed(1)} s`;
}

/** Render a single tool's result as a Markdown section */
function renderToolSection(result: BenchmarkResult): string {
  const lines: string[] = [];
  lines.push(`## ${result.tool} v${result.toolVersion}`);
  lines.push('');
  lines.push(`| Corpus | TP | FP | FN | Precision | Recall | F1 | Runtime |`);
  lines.push(`|--------|-----|-----|-----|-----------|--------|-----|---------|`);

  for (const s of result.scores) {
    lines.push(
      `| ${s.corpusLabel} | ${s.tp} | ${s.fp} | ${s.fn} | ` +
      `${pct(s.precision)} | ${pct(s.recall)} | ${pct(s.f1)} | ${ms(s.durationMs)} |`
    );
  }

  lines.push('');
  lines.push(`**Aggregate F1**: ${pct(result.aggregateF1)}`);
  lines.push(`**Commit SHA**: \`${result.commitSha}\``);
  lines.push(`**Run date**: ${result.runDate}`);
  lines.push('');

  return lines.join('\n');
}

/** Render full leaderboard Markdown */
export function renderMarkdownReport(results: BenchmarkResult[]): string {
  const sorted = [...results].sort((a, b) => {
    const af = a.aggregateF1 ?? -1;
    const bf = b.aggregateF1 ?? -1;
    return bf - af;
  });

  const lines: string[] = [];
  lines.push('# VANTAGE Benchmark — Leaderboard');
  lines.push('');
  lines.push(`_Last updated: ${new Date().toISOString().slice(0, 10)}_`);
  lines.push('');
  lines.push('| Rank | Tool | Version | NodeGoat F1 | Juice Shop F1 | Aggregate F1 | Runtime |');
  lines.push('|------|------|---------|------------|---------------|--------------|---------|');

  sorted.forEach((r, i) => {
    const ngScore = r.scores.find(s => s.corpus === 'nodegoat');
    const jsScore = r.scores.find(s => s.corpus === 'juice-shop');
    lines.push(
      `| ${i + 1} | **${r.tool}** | ${r.toolVersion} | ` +
      `${pct(ngScore?.f1 ?? null)} | ${pct(jsScore?.f1 ?? null)} | ` +
      `${pct(r.aggregateF1)} | ${ms(r.medianDurationMs)} |`
    );
  });

  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## Per-Tool Detail');
  lines.push('');

  for (const r of sorted) {
    lines.push(renderToolSection(r));
  }

  return lines.join('\n');
}

/** Render leaderboard as structured JSON for the static site */
export function renderJsonResults(results: BenchmarkResult[]): LeaderboardData {
  const sorted = [...results].sort((a, b) => {
    const af = a.aggregateF1 ?? -1;
    const bf = b.aggregateF1 ?? -1;
    return bf - af;
  });

  return {
    generatedAt: new Date().toISOString(),
    tools: sorted.map((r, i) => ({
      rank: i + 1,
      name: r.tool,
      version: r.toolVersion,
      runDate: r.runDate,
      commitSha: r.commitSha,
      aggregateF1: r.aggregateF1,
      medianDurationMs: r.medianDurationMs,
      scores: r.scores.map(s => ({
        corpus: s.corpus,
        corpusLabel: s.corpusLabel,
        tp: s.tp,
        fp: s.fp,
        fn: s.fn,
        precision: s.precision,
        recall: s.recall,
        f1: s.f1,
        durationMs: s.durationMs,
        tpDetails: s.tpDetails,
        fpDetails: s.fpDetails,
        fnDetails: s.fnDetails,
      })),
    })),
  };
}

export interface LeaderboardData {
  generatedAt: string;
  tools: LeaderboardEntry[];
}

export interface LeaderboardEntry {
  rank: number;
  name: string;
  version: string;
  runDate: string;
  commitSha: string;
  aggregateF1: number | null;
  medianDurationMs: number;
  scores: Array<{
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
  }>;
}

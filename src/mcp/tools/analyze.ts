// VANTAGE MCP tool — analyze
// Wraps the VANTAGE pipeline, caches results by content hash

import * as path from 'path';
import * as crypto from 'crypto';
import { runPipeline } from '../../engines/index';
import { VantageReport, AuroraIssue } from '../../types';
import {
  computeDirectoryHash,
  getCachedReport,
  setCachedReport,
  CacheEntry,
} from '../cache';
import { AnalyzeInputType } from '../schemas';

export interface AnalyzeResult {
  reportId: string;
  verdict: 'APPROVED' | 'REJECTED';
  score: number;
  scorePct: string;
  topIssues: AuroraIssue[];
  summary: string;
  breakdown: VantageReport['aurora']['breakdown'];
  metrics: {
    files: number;
    functions: number;
    linesOfCode: number;
    circularDeps: number;
    findings: number;
    todos: number;
  };
  cached: boolean;
  durationMs?: number;
}

export async function toolAnalyze(input: AnalyzeInputType): Promise<AnalyzeResult> {
  const targetPath = path.resolve(input.target_path);
  const options = input.options ?? {};
  const threshold = options.threshold ?? 0.80;
  const engineFilter = (options.engine ?? null) as Parameters<typeof runPipeline>[1];
  const semantic = options.semantic ?? false;
  const surface = options.surface ?? 'all';
  const includeTests = options.includeTests ?? false;

  // Cache key includes semantic/surface so mode variants don't collide.
  const cacheOptions = {
    engine: options.engine ?? null,
    threshold,
    semantic,
    surface,
    includeTests,
  };
  const hash = computeDirectoryHash(targetPath, cacheOptions);

  // Check cache
  const cached = getCachedReport(hash);
  if (cached) {
    return formatResult(cached.report, cached.reportId, true);
  }

  const start = Date.now();
  const report = await runPipeline(targetPath, engineFilter, undefined, threshold, {
    semantic,
    surface,
    includeTests,
  });
  const durationMs = Date.now() - start;

  const reportId = crypto.randomUUID();
  const entry: CacheEntry = {
    reportId,
    report,
    cachedAt: new Date().toISOString(),
    targetPath,
  };
  setCachedReport(hash, entry);

  return { ...formatResult(report, reportId, false), durationMs };
}

function formatResult(report: VantageReport, reportId: string, cached: boolean): AnalyzeResult {
  return {
    reportId,
    verdict: report.aurora.verdict,
    score: report.aurora.score,
    scorePct: `${(report.aurora.score * 100).toFixed(1)}%`,
    topIssues: report.aurora.topIssues,
    summary: report.aurora.summary,
    breakdown: report.aurora.breakdown,
    metrics: {
      files: report.meteor.files.length,
      functions: report.meteor.functions.length,
      linesOfCode: report.meteor.metrics.linesOfCode,
      circularDeps: report.nova.circularDeps.length,
      findings: report.pulsar.adversarialFindings.length,
      todos: report.meteor.todos.length,
    },
    cached,
  };
}

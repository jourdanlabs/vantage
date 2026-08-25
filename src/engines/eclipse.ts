// ECLIPSE — Risk Scoring Engine
// Scores each file on a 0.0-1.0 risk scale based on multiple factors

import * as path from 'path';
import * as fs from 'fs';
import { execSync } from 'child_process';
import { MeteorOutput, NovaOutput, EclipseOutput, RiskEntry } from '../types';
import { LANGUAGE_REGISTRY } from '../languages';

// Build test-file matchers from the registry (computed once at startup)
const ALL_TEST_SUFFIXES: string[] = LANGUAGE_REGISTRY.flatMap(l => l.testFileSuffixes);
const ALL_TEST_DIR_PATTERNS: string[] = [
  ...new Set(LANGUAGE_REGISTRY.flatMap(l => l.testDirPatterns))
];

function hasTestFile(filePath: string, allFiles: string[]): boolean {
  const base = path.basename(filePath, path.extname(filePath));

  // Build per-file candidate names from every language's suffixes
  const candidateNames = new Set(
    ALL_TEST_SUFFIXES.map(suffix => {
      // suffix may be a prefix pattern like 'test_*.py' — handle separately
      if (suffix.startsWith('test_')) return `test_${base}${path.extname(suffix.replace('test_', ''))}`;
      return `${base}${suffix}`;
    })
  );

  return allFiles.some(f => {
    const fname = path.basename(f);
    if (candidateNames.has(fname)) return true;
    // Check dir-pattern membership
    const normalized = f.replace(/\\/g, '/');
    return ALL_TEST_DIR_PATTERNS.some(dp => normalized.includes(`/${dp}`) || normalized.includes(dp));
  });
}

function getLastModifiedDays(filePath: string): number {
  try {
    const result = execSync(`git log --follow -1 --format="%ai" -- "${filePath}" 2>/dev/null`, {
      cwd: path.dirname(filePath),
      timeout: 3000,
      encoding: 'utf8'
    }).trim();

    if (!result) return 365; // no git history = treat as old

    const lastModified = new Date(result);
    const now = new Date();
    const diffMs = now.getTime() - lastModified.getTime();
    return Math.floor(diffMs / (1000 * 60 * 60 * 24));
  } catch {
    try {
      const stat = fs.statSync(filePath);
      const diffMs = Date.now() - stat.mtimeMs;
      return Math.floor(diffMs / (1000 * 60 * 60 * 24));
    } catch {
      return 180;
    }
  }
}

function scoreComplexity(avgComplexity: number): number {
  // 1-5 = low (0.0), 5-15 = med (0.3-0.6), 15+ = high (0.7-1.0)
  if (avgComplexity <= 5) return 0.0;
  if (avgComplexity <= 10) return 0.3;
  if (avgComplexity <= 20) return 0.6;
  if (avgComplexity <= 40) return 0.8;
  return 1.0;
}

function scoreCoupling(importedByCount: number): number {
  if (importedByCount === 0) return 0.0;
  if (importedByCount <= 2) return 0.1;
  if (importedByCount <= 5) return 0.4;
  if (importedByCount <= 8) return 0.6;
  return 1.0;
}

function scoreTodoDensity(todoCount: number, linesOfCode: number): number {
  if (linesOfCode === 0) return 0.0;
  const density = todoCount / linesOfCode;
  if (density === 0) return 0.0;
  if (density < 0.005) return 0.1;
  if (density < 0.01) return 0.3;
  if (density < 0.02) return 0.5;
  return 0.8;
}

function scoreFunctionSize(maxFuncLines: number): number {
  if (maxFuncLines <= 30) return 0.0;
  if (maxFuncLines <= 60) return 0.2;
  if (maxFuncLines <= 100) return 0.4;
  if (maxFuncLines <= 200) return 0.7;
  return 1.0;
}

export async function runECLIPSE(
  meteor: MeteorOutput,
  nova: NovaOutput,
  onProgress?: (msg: string) => void
): Promise<EclipseOutput> {
  onProgress?.('scoring files');

  const allFilePaths = meteor.files.map(f => f.path);
  const riskScores: Record<string, number> = {};
  const entries: RiskEntry[] = [];

  // Build reverse graph lookup from nova
  const reverseGraph: Record<string, string[]> = {};
  for (const [fromFile, toFiles] of Object.entries(nova.dependencyGraph)) {
    for (const toFile of toFiles) {
      if (!reverseGraph[toFile]) reverseGraph[toFile] = [];
      reverseGraph[toFile].push(fromFile);
    }
  }

  for (const file of meteor.files) {
    if (file.language === 'markdown') continue;

    const fileFunctions = meteor.functions.filter(f => f.file === file.path);
    const fileTodos = meteor.todos.filter(t => t.file === file.path);

    // Complexity factor
    const avgComplexity = fileFunctions.length > 0
      ? fileFunctions.reduce((sum, f) => sum + f.complexity, 0) / fileFunctions.length
      : 1;
    const complexityScore = scoreComplexity(avgComplexity);

    // Coupling factor (how many files import this one)
    const importedBy = reverseGraph[file.path] || [];
    const couplingScore = scoreCoupling(importedBy.length);

    // Test coverage proxy
    const hasCoverage = hasTestFile(file.path, allFilePaths);
    const testCoverageScore = hasCoverage ? 0.0 : 0.5; // no test = higher risk

    // TODO density
    const todoDensityScore = scoreTodoDensity(fileTodos.length, file.lines);

    // Function size
    const maxFuncLines = fileFunctions.length > 0
      ? Math.max(...fileFunctions.map(f => f.lines))
      : 0;
    const functionSizeScore = scoreFunctionSize(maxFuncLines);

    // Weighted composite score
    const score = (
      complexityScore * 0.3 +
      couplingScore * 0.25 +
      testCoverageScore * 0.2 +
      todoDensityScore * 0.1 +
      functionSizeScore * 0.15
    );

    const finalScore = Math.min(1.0, score);
    riskScores[file.path] = finalScore;

    entries.push({
      file: file.path,
      score: finalScore,
      factors: {
        complexity: complexityScore,
        coupling: couplingScore,
        testCoverage: testCoverageScore,
        todoDensity: todoDensityScore,
        functionSize: functionSizeScore
      }
    });
  }

  const sorted = [...entries].sort((a, b) => b.score - a.score);
  const highRisk = sorted.filter(e => e.score >= 0.65);
  const medRisk = sorted.filter(e => e.score >= 0.4 && e.score < 0.65);

  // Estimate overall bug probability
  const avgScore = entries.length > 0
    ? entries.reduce((sum, e) => sum + e.score, 0) / entries.length
    : 0;
  const estimatedBugProbability = Math.min(0.99, avgScore * 1.5);

  onProgress?.(`${highRisk.length} high-risk files, ${medRisk.length} medium-risk files`);

  return {
    riskScores,
    highRisk,
    medRisk,
    estimatedBugProbability
  };
}

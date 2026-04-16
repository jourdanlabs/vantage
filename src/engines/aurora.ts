// AURORA — Final Audit & Verdict Engine
// Synthesizes all COSMIC engine outputs into a final score and actionable report

import * as path from 'path';
import { MeteorOutput, NovaOutput, EclipseOutput, PulsarOutput, AuroraOutput, AuroraIssue } from '../types';

export async function runAURORA(
  meteor: MeteorOutput,
  nova: NovaOutput,
  eclipse: EclipseOutput,
  pulsar: PulsarOutput,
  onProgress?: (msg: string) => void,
  threshold = 0.80
): Promise<AuroraOutput> {
  onProgress?.('computing final audit score');

  // === Score components (each 0.0-1.0, inverted = lower is better risk = higher score) ===

  // Complexity score: how healthy is the codebase complexity?
  const avgComplexity = meteor.functions.length > 0
    ? meteor.metrics.totalComplexity / meteor.functions.length
    : 1;
  const complexityScore = Math.max(0, 1 - Math.min(1, (avgComplexity - 1) / 30));

  // Dependency score: circular deps and coupling hurt this
  const circDepPenalty = Math.min(1, nova.circularDeps.length * 0.15);
  const couplingPenalty = Math.min(0.3, nova.couplingIssues.length * 0.05);
  const godModulePenalty = Math.min(0.2, nova.godModules.length * 0.05);
  const dependencyScore = Math.max(0, 1 - circDepPenalty - couplingPenalty - godModulePenalty);

  // Risk score: from ECLIPSE
  const avgRisk = Object.values(eclipse.riskScores).length > 0
    ? Object.values(eclipse.riskScores).reduce((a, b) => a + b, 0) / Object.values(eclipse.riskScores).length
    : 0;
  const riskScore = Math.max(0, 1 - avgRisk);

  // Adversarial score: from PULSAR
  const highFindings = pulsar.adversarialFindings.filter(f => f.severity === 'HIGH').length;
  const medFindings = pulsar.adversarialFindings.filter(f => f.severity === 'MED').length;
  const adversarialPenalty = Math.min(1, highFindings * 0.1 + medFindings * 0.04);
  const adversarialScore = Math.max(0, 1 - adversarialPenalty);

  // Weighted AURORA score
  const score = (
    complexityScore * 0.25 +
    dependencyScore * 0.30 +
    riskScore * 0.25 +
    adversarialScore * 0.20
  );

  const verdict = score >= threshold ? 'APPROVED' : 'REJECTED';

  // === Build top issues list ===
  const issues: AuroraIssue[] = [];

  // Circular deps = HIGH priority
  for (const circ of nova.circularDeps.slice(0, 3)) {
    issues.push({
      severity: 'HIGH',
      file: circ.cycle[0],
      description: circ.description,
      fix: `Break the circular dependency by extracting shared types/utilities to a separate module`
    });
  }

  // High-risk files from ECLIPSE
  for (const risk of eclipse.highRisk.slice(0, 5)) {
    const relPath = path.relative(process.cwd(), risk.file);
    issues.push({
      severity: 'HIGH',
      file: risk.file,
      description: `High risk score ${(risk.score * 100).toFixed(0)}% — complexity: ${(risk.factors.complexity * 100).toFixed(0)}%, coupling: ${(risk.factors.coupling * 100).toFixed(0)}%, no tests: ${risk.factors.testCoverage > 0.3 ? 'YES' : 'no'}`,
      fix: `Add tests, reduce function complexity, and decouple from high-import modules`
    });
  }

  // High severity PULSAR findings
  for (const finding of pulsar.adversarialFindings.filter(f => f.severity === 'HIGH').slice(0, 5)) {
    issues.push({
      severity: 'HIGH',
      file: finding.file,
      line: finding.line,
      description: finding.description,
      fix: finding.testCase
    });
  }

  // God modules = MED
  for (const god of nova.godModules.slice(0, 3)) {
    issues.push({
      severity: 'MED',
      file: god.file,
      description: god.description,
      fix: `Split ${path.basename(god.file)} into smaller single-responsibility modules`
    });
  }

  // Coupling issues = MED
  for (const coupling of nova.couplingIssues.slice(0, 3)) {
    issues.push({
      severity: 'MED',
      file: coupling.file,
      description: coupling.description,
      fix: `Consider dependency injection or interface extraction to reduce coupling`
    });
  }

  // Large functions
  for (const func of meteor.metrics.largeFunctions.slice(0, 3)) {
    issues.push({
      severity: 'MED',
      file: func.file,
      line: func.startLine,
      description: `${func.name}() is ${func.lines} lines long (limit: 100) — complexity ${func.complexity}`,
      fix: `Decompose ${func.name}() into smaller focused functions`
    });
  }

  // Sort: HIGH first, then MED, then LOW
  const sortedIssues = issues.sort((a, b) => {
    const order = { HIGH: 0, MED: 1, LOW: 2 };
    return order[a.severity] - order[b.severity];
  });

  // Top 5 unique by file
  const topIssues: AuroraIssue[] = [];
  const seenFiles = new Set<string>();
  for (const issue of sortedIssues) {
    const key = `${issue.file}:${issue.severity}`;
    if (!seenFiles.has(key)) {
      seenFiles.add(key);
      topIssues.push(issue);
    }
    if (topIssues.length >= 10) break;
  }

  // Build fix list
  const fixes: string[] = [
    ...pulsar.recommendations,
    ...nova.circularDeps.map(c =>
      `Fix circular dep: ${c.cycle.map(p => path.basename(p)).join(' → ')}`
    ).slice(0, 3),
    ...nova.godModules.map(g =>
      `Refactor god module: ${path.basename(g.file)} (${g.lines} lines → split into 3-4 modules)`
    ).slice(0, 2),
  ].filter(Boolean).slice(0, 10);

  // Summary
  const summaryParts = [
    `Analyzed ${meteor.files.length} files, ${meteor.functions.length} functions, ${meteor.metrics.linesOfCode.toLocaleString()} lines of code.`,
    `Found ${nova.circularDeps.length} circular dependencies, ${nova.couplingIssues.length} coupling issues, ${nova.godModules.length} god modules.`,
    `${eclipse.highRisk.length} high-risk files identified. ${pulsar.adversarialFindings.filter(f => f.severity === 'HIGH').length} critical adversarial findings.`,
    verdict === 'APPROVED'
      ? `AURORA score ${(score * 100).toFixed(0)}% — codebase is ship-safe. Minor improvements recommended.`
      : `AURORA score ${(score * 100).toFixed(0)}% — codebase has ${topIssues.filter(i => i.severity === 'HIGH').length} HIGH severity issues blocking ship.`
  ];
  const summary = summaryParts.join(' ');

  // Unsupported files note
  let unsupportedFilesNote: string | undefined;
  if (meteor.unsupportedFiles.count > 0) {
    const pct = meteor.files.length > 0
      ? Math.round((meteor.unsupportedFiles.count / meteor.files.length) * 100)
      : 100;
    unsupportedFilesNote =
      `${meteor.unsupportedFiles.count} of ${meteor.files.length} files (${pct}%) are in language(s) without reliable extraction: ${meteor.unsupportedFiles.extensions.join(', ')}. ` +
      `LOC is counted; function/import/class analysis was skipped for these files. ` +
      `Score and findings reflect only the ${meteor.files.length - meteor.unsupportedFiles.count} supported-language files.`;
  }

  onProgress?.(`score ${score.toFixed(2)} → ${verdict}${threshold !== 0.80 ? ` (threshold ${threshold})` : ''}`);

  return {
    score,
    verdict,
    topIssues,
    fixes,
    summary,
    breakdown: {
      complexityScore,
      dependencyScore,
      riskScore,
      adversarialScore
    },
    unsupportedFilesNote,
    threshold,
  };
}

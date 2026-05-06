import { resolve } from "node:path";
import { hashCanonical, shortHash } from "../audit/hash.js";
import type { VantageBenchmarkCase, VantageBenchmarkReport, VantageBenchmarkResult, VantageFinding, VantageProject } from "../types.js";
import { runVantage } from "../products/vantage.js";

export const VANTAGE_BENCHMARK_CASES: VantageBenchmarkCase[] = [
  {
    case_id: "clean_node",
    project_name: "clean-node",
    description: "Healthy TypeScript package should avoid false alarms.",
    expected_findings: [],
    forbidden_findings: [
      "Missing build script",
      "Missing test script",
      "Missing lint script",
      "Missing license metadata",
      "Missing Node lockfile",
      "TypeScript strict mode disabled",
      "Dynamic code execution",
      "Child process usage"
    ]
  },
  {
    case_id: "package_hygiene",
    project_name: "package-hygiene",
    description: "Underspecified Node package should expose install, build, test, lint, and metadata gaps.",
    expected_findings: [
      { title: "Missing build script", severity: "medium" },
      { title: "Missing test script", severity: "medium" },
      { title: "Missing lint script", severity: "low" },
      { title: "Missing license metadata", severity: "low" },
      { title: "Missing Node lockfile", severity: "medium" },
      { title: "Missing README", severity: "low" }
    ],
    forbidden_findings: ["Dynamic code execution", "Child process usage", "Destructive fs call outside tests"]
  },
  {
    case_id: "dependency_hygiene",
    project_name: "dependency-hygiene",
    description: "Dependency drift and duplicated dependency sections should be caught.",
    expected_findings: [
      { title: "Broad dependency versions", severity: "medium" },
      { title: "Dependency duplicated in devDependencies", severity: "medium" }
    ],
    forbidden_findings: ["Missing Node lockfile", "Missing README", "Missing test script"]
  },
  {
    case_id: "runtime_danger",
    project_name: "runtime-danger",
    description: "Runtime dynamic execution, shelling out, env reads, and destructive filesystem calls should be escalated.",
    expected_findings: [
      { title: "Dynamic code execution", severity: "critical" },
      { title: "Child process usage", severity: "high" },
      { title: "Destructive fs call outside tests", severity: "high" },
      { title: "Direct process.env access", severity: "medium" }
    ],
    forbidden_findings: ["Missing build script", "Missing lint script", "Missing Node lockfile"]
  },
  {
    case_id: "test_harness_containment",
    project_name: "test-harness-containment",
    description: "Dangerous APIs inside tests should be contained as test risk, not runtime security panic.",
    expected_findings: [{ title: "Child process usage", severity: "low" }],
    forbidden_findings: ["Dynamic code execution", "Destructive fs call outside tests", "Direct process.env access"]
  },
  {
    case_id: "architecture_shape",
    project_name: "architecture-shape",
    description: "Import cycles and oversized functions should be caught as architecture findings.",
    expected_findings: [
      { title: "Circular dependency", severity: "high" },
      { title: "Long function", severity: "medium" }
    ],
    forbidden_findings: ["Dynamic code execution", "Destructive fs call outside tests"]
  },
  {
    case_id: "benchmark_intent_zone",
    project_name: "benchmark-intent-zone",
    description: "Benchmark comments can mention exploit strings without becoming runtime findings.",
    expected_findings: [],
    forbidden_findings: ["Dynamic code execution", "Child process usage", "Destructive fs call outside tests"]
  },
  {
    case_id: "duplicate_family_a",
    project_name: "same-app",
    description: "First member of a duplicate project family.",
    expected_findings: [],
    forbidden_findings: ["Dynamic code execution", "TypeScript strict mode disabled"]
  },
  {
    case_id: "duplicate_family_b",
    project_name: "@bench/same_app",
    description: "Second member of a duplicate project family with scoped punctuation variant.",
    expected_findings: [],
    forbidden_findings: ["Dynamic code execution", "TypeScript strict mode disabled"]
  }
];

export function runVantageBenchmark(fixturesRoot: string): VantageBenchmarkReport {
  const fixtures_root = resolve(fixturesRoot);
  const vantage = runVantage(fixtures_root, "report");
  const results = VANTAGE_BENCHMARK_CASES.map((benchmarkCase) => scoreCase(benchmarkCase, vantage.projects, vantage.duplicate_project_groups.length > 0));
  const summary = summarize(results);
  const withoutHash = {
    run_id: `vantage_benchmark_${shortHash({ fixtures_root, results, summary, vantage_audit_hash: vantage.audit_hash })}`,
    fixtures_root,
    results,
    summary,
    vantage_audit_hash: vantage.audit_hash
  };
  return {
    ...withoutHash,
    audit_hash: hashCanonical(withoutHash)
  };
}

function scoreCase(benchmarkCase: VantageBenchmarkCase, projects: VantageProject[], hasDuplicateGroup: boolean): VantageBenchmarkResult {
  const project = projects.find((candidate) => candidate.name === benchmarkCase.project_name);
  const findings = project?.findings ?? [];
  const titles = new Set(findings.map((finding) => finding.title));
  const missingExpected = benchmarkCase.expected_findings
    .filter((expected) => !titles.has(expected.title))
    .map((expected) => expected.title)
    .sort();
  const forbiddenHits = benchmarkCase.forbidden_findings.filter((title) => titles.has(title)).sort();
  const severityMismatches = benchmarkCase.expected_findings
    .filter((expected): expected is { title: string; severity: NonNullable<typeof expected.severity> } => Boolean(expected.severity) && titles.has(expected.title))
    .map((expected) => ({
      title: expected.title,
      expected: expected.severity,
      actual: severityFor(findings, expected.title)
    }))
    .filter((item) => item.actual !== item.expected)
    .sort((a, b) => a.title.localeCompare(b.title));
  const expectedTitles = new Set(benchmarkCase.expected_findings.map((expected) => expected.title));
  const unexpectedHighOrCritical = findings
    .filter((finding) => (finding.severity === "high" || finding.severity === "critical") && !expectedTitles.has(finding.title))
    .map((finding) => finding.title)
    .sort();
  const duplicateExpected = benchmarkCase.case_id.startsWith("duplicate_family");
  const duplicate_group_detected = duplicateExpected ? hasDuplicateGroup : false;
  const foundExpectedCount = benchmarkCase.expected_findings.length - missingExpected.length;
  const score = clamp(
    100
      - missingExpected.length * 18
      - forbiddenHits.length * 25
      - severityMismatches.length * 12
      - unexpectedHighOrCritical.length * 20
      + (duplicateExpected && duplicate_group_detected ? 10 : 0),
    0,
    100
  );
  return {
    case_id: benchmarkCase.case_id,
    project_name: benchmarkCase.project_name,
    expected_count: benchmarkCase.expected_findings.length,
    found_expected_count: foundExpectedCount,
    missing_expected_titles: missingExpected,
    forbidden_hit_titles: forbiddenHits,
    severity_mismatches: severityMismatches,
    unexpected_high_or_critical_titles: unexpectedHighOrCritical,
    duplicate_group_detected,
    score,
    outcome: score >= 95 ? "murked" : score >= 80 ? "passed" : "needs_work"
  };
}

function severityFor(findings: VantageFinding[], title: string): VantageFinding["severity"] {
  const finding = findings.find((item) => item.title === title);
  return finding?.severity ?? "info";
}

function summarize(results: VantageBenchmarkResult[]): VantageBenchmarkReport["summary"] {
  const expectedFindings = results.reduce((sum, result) => sum + result.expected_count, 0);
  const foundExpectedFindings = results.reduce((sum, result) => sum + result.found_expected_count, 0);
  return {
    total_cases: results.length,
    murked_count: results.filter((result) => result.outcome === "murked").length,
    passed_count: results.filter((result) => result.outcome === "passed").length,
    needs_work_count: results.filter((result) => result.outcome === "needs_work").length,
    expected_findings: expectedFindings,
    found_expected_findings: foundExpectedFindings,
    recall_percent: expectedFindings === 0 ? 100 : Math.round((foundExpectedFindings / expectedFindings) * 100),
    forbidden_hits: results.reduce((sum, result) => sum + result.forbidden_hit_titles.length, 0),
    severity_mismatches: results.reduce((sum, result) => sum + result.severity_mismatches.length, 0),
    unexpected_high_or_critical: results.reduce((sum, result) => sum + result.unexpected_high_or_critical_titles.length, 0),
    duplicate_groups_detected: results.filter((result) => result.duplicate_group_detected).length,
    average_score: Math.round(results.reduce((sum, result) => sum + result.score, 0) / Math.max(1, results.length))
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

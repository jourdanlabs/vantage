import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { runVantageBenchmark } from "../src/index.js";

describe("VANTAGE benchmark harness", () => {
  it("scores checked-in fixture projects for recall, severity, false positives, and duplicate detection", () => {
    const fixturesRoot = resolve("fixtures/vantage");
    const report = runVantageBenchmark(fixturesRoot);

    expect(report.summary.total_cases).toBe(9);
    expect(report.summary.recall_percent).toBe(100);
    expect(report.summary.forbidden_hits).toBe(0);
    expect(report.summary.severity_mismatches).toBe(0);
    expect(report.summary.needs_work_count).toBe(0);
    expect(report.summary.duplicate_groups_detected).toBe(2);
    expect(runVantageBenchmark(fixturesRoot).audit_hash).toBe(report.audit_hash);
  });
});

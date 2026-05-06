#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { canonicalJson } from "./audit/canonicalize.js";
import { applyVantageFixPlans, runVantage, runVantageBenchmark } from "./index.js";
import type { VantageMode } from "./types.js";

const [, , command, targetArg, modeArg, outputArg] = process.argv;

try {
  if (!command || command === "help" || command === "--help" || command === "-h") {
    usage();
  } else if (command === "audit" || command === "analyze" || command === "run") {
    const target = resolve(targetArg ?? ".");
    process.stdout.write(canonicalJson(runVantage(target, parseMode(modeArg))));
  } else if (command === "benchmark") {
    const fixtures = resolve(targetArg ?? "fixtures/vantage");
    process.stdout.write(canonicalJson(runVantageBenchmark(fixtures)));
  } else if (command === "apply") {
    const target = resolve(targetArg ?? ".");
    const dryRun = modeArg !== "--write";
    process.stdout.write(canonicalJson(applyVantageFixPlans(target, { dryRun })));
  } else if (command === "report") {
    const target = resolve(targetArg ?? ".");
    const outputPath = resolve(modeArg ?? outputArg ?? "vantage-report.json");
    const report = runVantage(target, "report");
    writeFileSync(outputPath, `${canonicalJson(report)}\n`, "utf8");
    process.stdout.write(canonicalJson({ output_file: outputPath, audit_hash: report.audit_hash }));
  } else {
    usage();
    process.exitCode = 1;
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`VANTAGE failed: ${message}\n`);
  process.exitCode = 1;
}

function parseMode(value: string | undefined): VantageMode {
  if (value === "fix" || value === "wrecking_crew" || value === "report") {
    return value;
  }
  return "report";
}

function usage(): void {
  process.stdout.write([
    "VANTAGE 2.0",
    "",
    "Usage:",
    "  vantage audit [directory] [report|fix|wrecking_crew]",
    "  vantage analyze [directory] [report|fix|wrecking_crew]",
    "  vantage benchmark [fixtures/vantage]",
    "  vantage apply [directory] [--write]",
    "  vantage report [directory] [output.json]",
    ""
  ].join("\n"));
}

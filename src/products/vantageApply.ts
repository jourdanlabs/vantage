import { readFileSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import type { VantageApplyReport, VantageFixPlan } from "../types.js";
import { hashCanonical, shortHash } from "../audit/hash.js";
import { runVantage } from "./vantage.js";

type JsonObject = Record<string, unknown>;

export function applyVantageFixPlans(rootPath: string, options: { dryRun?: boolean } = {}): VantageApplyReport {
  const target_root = resolve(rootPath);
  const dry_run = options.dryRun ?? true;
  const report = runVantage(target_root, "fix");
  const applied_plans: VantageApplyReport["applied_plans"] = [];
  const skipped_plans: VantageApplyReport["skipped_plans"] = [];
  const changed = new Map<string, { before: string; after: string }>();

  for (const plan of report.projects.flatMap((project) => project.fix_plans)) {
    const target = plan.target_file ? resolve(plan.target_file) : null;
    if (!canApplyPackagePlan(target_root, plan, target)) {
      skipped_plans.push({ plan_id: plan.plan_id, reason: skipReason(plan, target) });
      continue;
    }
    const before = readFileSync(target!, "utf8");
    const packageJson = JSON.parse(before) as JsonObject;
    const changes = applyPackagePreview(packageJson, plan.patch_preview);
    if (changes.length === 0) {
      skipped_plans.push({ plan_id: plan.plan_id, reason: "No supported package.json changes were present in patch preview." });
      continue;
    }
    const after = `${JSON.stringify(packageJson, null, 2)}\n`;
    if (after !== before) {
      changed.set(target!, { before, after });
      if (!dry_run) {
        writeFileSync(target!, after, "utf8");
      }
    }
    applied_plans.push({
      plan_id: plan.plan_id,
      target_file: target!,
      changes
    });
  }

  const changed_files = [...changed.entries()].map(([file_path, value]) => ({
    file_path,
    before_hash: hashCanonical(value.before),
    after_hash: hashCanonical(value.after)
  })).sort((a, b) => a.file_path.localeCompare(b.file_path));
  const summary = {
    applied_count: applied_plans.length,
    skipped_count: skipped_plans.length,
    changed_file_count: changed_files.length
  };
  const withoutHash = {
    run_id: `vantage_apply_${shortHash({ target_root, dry_run, applied_plans, skipped_plans, changed_files, summary })}`,
    target_root,
    dry_run,
    applied_plans: applied_plans.sort((a, b) => a.plan_id.localeCompare(b.plan_id)),
    skipped_plans: skipped_plans.sort((a, b) => a.plan_id.localeCompare(b.plan_id)),
    changed_files,
    summary
  };
  return {
    ...withoutHash,
    audit_hash: hashCanonical(withoutHash)
  };
}

function canApplyPackagePlan(rootPath: string, plan: VantageFixPlan, target: string | null): boolean {
  if (plan.action_type !== "package_json_patch" || !plan.deterministic || plan.risk === "high" || !target) {
    return false;
  }
  const relativeTarget = relative(rootPath, target);
  if (relativeTarget.startsWith("..") || relativeTarget.includes("node_modules")) {
    return false;
  }
  return target.endsWith("package.json");
}

function skipReason(plan: VantageFixPlan, target: string | null): string {
  if (!target) return "No target file.";
  if (plan.action_type !== "package_json_patch") return `Unsupported action type: ${plan.action_type}.`;
  if (!plan.deterministic) return "Plan is not deterministic.";
  if (plan.risk === "high") return "High-risk fixes require manual implementation.";
  if (!target.endsWith("package.json")) return "Only package.json patch plans are supported.";
  return "Target file is outside the supported package root.";
}

function applyPackagePreview(packageJson: JsonObject, previews: string[]): string[] {
  const changes: string[] = [];
  for (const preview of previews) {
    const scriptMatch = preview.match(/^scripts\.(test|build|lint) = (.+)$/);
    if (scriptMatch?.[1] && scriptMatch[2]) {
      const scripts = ensureObject(packageJson, "scripts");
      scripts[scriptMatch[1]] = scriptMatch[2];
      changes.push(preview);
      continue;
    }
    const licenseMatch = preview.match(/^license = (.+)$/);
    if (licenseMatch?.[1]) {
      packageJson.license = licenseMatch[1];
      changes.push(preview);
    }
  }
  return changes;
}

function ensureObject(target: JsonObject, key: string): JsonObject {
  const existing = target[key];
  if (existing && typeof existing === "object" && !Array.isArray(existing)) {
    return existing as JsonObject;
  }
  const created: JsonObject = {};
  target[key] = created;
  return created;
}

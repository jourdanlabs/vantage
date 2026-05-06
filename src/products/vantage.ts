import { existsSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import type { VantageFinding, VantageFixPlan, VantageMode, VantageProject, VantageReport } from "../types.js";
import { hashCanonical, shortHash } from "../audit/hash.js";
import { architectureFindings, sourceFindings } from "./vantageRules.js";
import {
  CODE_EXTENSIONS,
  TEXT_EXTENSIONS,
  TEST_FILE_PATTERN,
  TEST_NAME_PATTERN,
  compareFindings,
  countLanguages,
  dependencyMap,
  extension,
  finding,
  firstRelativeMatches,
  identityTerms,
  inferProjectType,
  isTestPath,
  listFiles,
  modeAwareFindings,
  normalizedTextIncludes,
  packageLockfiles,
  readFileIfExists,
  readJsonIfExists,
  readmeIdentityTerms,
  scriptMap,
  walkDirs
} from "./vantageSupport.js";

const BROAD_DEPENDENCY_VERSION_PATTERN = /^(\*|latest|next)$/i;

export function runVantage(rootPath: string, mode: VantageMode = "report"): VantageReport {
  const scanned_root = resolve(rootPath);
  const projects = discoverProjects(scanned_root).map((projectRoot) => auditProject(projectRoot, mode));
  const duplicate_project_groups = detectDuplicateProjects(projects);
  const summary = summarize(projects);
  const withoutHash = {
    run_id: `vantage_${shortHash({ scanned_root, mode, projects, duplicate_project_groups, summary })}`,
    mode,
    scanned_root,
    projects,
    duplicate_project_groups,
    summary
  };
  return {
    ...withoutHash,
    audit_hash: hashCanonical(withoutHash)
  };
}

function discoverProjects(rootPath: string): string[] {
  const roots = new Set<string>();
  walkDirs(rootPath, (dir) => {
    if (existsSync(join(dir, "package.json")) || existsSync(join(dir, "pyproject.toml")) || existsSync(join(dir, "Cargo.toml")) || existsSync(join(dir, "go.mod"))) {
      roots.add(dir);
      return false;
    }
    return true;
  });
  if (roots.size === 0) {
    roots.add(rootPath);
  }
  return [...roots].sort();
}

function auditProject(rootPath: string, mode: VantageMode): VantageProject {
  const files = listFiles(rootPath);
  const textFiles = files.filter((file) => TEXT_EXTENSIONS.has(extension(file)));
  const codeFiles = files.filter((file) => CODE_EXTENSIONS.has(extension(file)));
  const language_counts = countLanguages(files);
  const packageJson = readJsonIfExists(join(rootPath, "package.json"));
  const project_type = inferProjectType(rootPath);
  const name = typeof packageJson?.name === "string" ? packageJson.name : basename(rootPath);
  const findings = modeAwareFindings([
    ...packageFindings(rootPath, packageJson),
    ...typescriptFindings(rootPath),
    ...readinessFindings(rootPath, packageJson, files),
    ...documentationFindings(rootPath, packageJson),
    ...architectureFindings(rootPath, codeFiles),
    ...sourceFindings(rootPath, codeFiles, textFiles)
  ], mode).sort(compareFindings);
  const fix_plans = fixPlansForFindings(rootPath, packageJson, files, findings, mode);
  const signals = projectSignals(rootPath, packageJson, files, findings);
  const stage = inferStage(files, packageJson, findings);
  const quality = inferQuality(findings, signals);

  return {
    project_id: `project_${shortHash({ rootPath, name, project_type })}`,
    root_path: rootPath,
    project_type,
    name,
    stage,
    quality,
    file_count: files.length,
    language_counts,
    signals,
    findings,
    fix_plans
  };
}

function packageFindings(rootPath: string, packageJson: Record<string, unknown> | null): VantageFinding[] {
  if (!packageJson) {
    return [];
  }
  const scripts = scriptMap(packageJson);
  const findings: VantageFinding[] = [];
  if (!scripts.test) {
    findings.push(finding("medium", "test_risk", "Missing test script", "package.json does not define a test script.", join(rootPath, "package.json"), ["scripts.test absent"], "Add a deterministic test script.", true));
  }
  if (!scripts.build) {
    findings.push(finding("medium", "package_health", "Missing build script", "package.json does not define a build script.", join(rootPath, "package.json"), ["scripts.build absent"], "Add a build script that validates production artifacts.", true));
  }
  if (!scripts.lint) {
    findings.push(finding("low", "maintainability", "Missing lint script", "package.json does not define a lint script.", join(rootPath, "package.json"), ["scripts.lint absent"], "Add linting or a static check script.", true));
  }
  if (!packageJson.license) {
    findings.push(finding("low", "package_health", "Missing license metadata", "package.json does not declare a license.", join(rootPath, "package.json"), ["license absent"], "Declare license metadata or mark the package private.", true));
  }
  findings.push(...dependencyFindings(rootPath, packageJson));
  return findings;
}

function dependencyFindings(rootPath: string, packageJson: Record<string, unknown>): VantageFinding[] {
  const findings: VantageFinding[] = [];
  const dependencies = dependencyMap(packageJson.dependencies);
  const devDependencies = dependencyMap(packageJson.devDependencies);
  const optionalDependencies = dependencyMap(packageJson.optionalDependencies);
  const peerDependencies = dependencyMap(packageJson.peerDependencies);
  const dependencyEntries = [
    ...Object.entries(dependencies).map(([name, version]) => ({ section: "dependencies", name, version })),
    ...Object.entries(devDependencies).map(([name, version]) => ({ section: "devDependencies", name, version })),
    ...Object.entries(optionalDependencies).map(([name, version]) => ({ section: "optionalDependencies", name, version })),
    ...Object.entries(peerDependencies).map(([name, version]) => ({ section: "peerDependencies", name, version }))
  ].sort((a, b) => a.section.localeCompare(b.section) || a.name.localeCompare(b.name));

  const broadVersions = dependencyEntries.filter(({ version }) => BROAD_DEPENDENCY_VERSION_PATTERN.test(version));
  if (broadVersions.length > 0) {
    findings.push(finding(
      "medium",
      "package_health",
      "Broad dependency versions",
      "package.json pins one or more dependencies to non-deterministic broad versions.",
      join(rootPath, "package.json"),
      broadVersions.map(({ section, name, version }) => `${section}.${name}: ${version}`),
      "Pin broad dependency versions to explicit compatible ranges.",
      true
    ));
  }

  const duplicated = Object.keys(dependencies)
    .filter((name) => Object.hasOwn(devDependencies, name))
    .sort();
  if (duplicated.length > 0) {
    findings.push(finding(
      "medium",
      "package_health",
      "Dependency duplicated in devDependencies",
      "The same package appears in both dependencies and devDependencies.",
      join(rootPath, "package.json"),
      duplicated.map((name) => `${name}: dependencies=${dependencies[name]}, devDependencies=${devDependencies[name]}`),
      "Keep each package in the dependency section that matches its runtime role.",
      true
    ));
  }
  return findings;
}

function readinessFindings(rootPath: string, packageJson: Record<string, unknown> | null, files: string[]): VantageFinding[] {
  if (!packageJson) {
    return [];
  }
  const scripts = scriptMap(packageJson);
  const hasTests = files.some((file) => isTestPath(rootPath, file));
  const hasLockfile = packageLockfiles(rootPath).length > 0;
  const findings: VantageFinding[] = [];

  if (!hasLockfile) {
    findings.push(finding(
      "medium",
      "package_health",
      "Missing Node lockfile",
      "Node package does not include a package manager lockfile, so installs may drift across machines.",
      join(rootPath, "package.json"),
      ["no package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, or bun.lockb"],
      "Commit the package manager lockfile used for deterministic installs.",
      true
    ));
  }
  if (hasTests && !scripts.test) {
    findings.push(finding(
      "medium",
      "test_risk",
      "Tests present but no test script",
      "Test files exist, but package.json has no script entry that runs them.",
      join(rootPath, "package.json"),
      firstRelativeMatches(rootPath, files, (file) => isTestPath(rootPath, file)),
      "Add a deterministic test script that exercises the checked-in tests.",
      true
    ));
  }
  if (!hasTests && scripts.test) {
    findings.push(finding(
      "medium",
      "test_risk",
      "Test script without checked-in tests",
      "package.json defines a test script, but VANTAGE did not find test files in the project.",
      join(rootPath, "package.json"),
      [`scripts.test: ${String(scripts.test)}`],
      "Add test files or replace the script with the actual validation command.",
      false
    ));
  }
  if (scripts.build && !existsSync(join(rootPath, "tsconfig.json")) && !files.some((file) => basename(file).startsWith("vite.config") || basename(file).startsWith("rollup.config"))) {
    findings.push(finding(
      "low",
      "package_health",
      "Build script lacks obvious build config",
      "package.json defines a build script, but common build configuration files were not found.",
      join(rootPath, "package.json"),
      [`scripts.build: ${String(scripts.build)}`],
      "Confirm the build script is self-contained or check in its configuration.",
      false
    ));
  }
  return findings;
}

function typescriptFindings(rootPath: string): VantageFinding[] {
  const tsconfig = readJsonIfExists(join(rootPath, "tsconfig.json"));
  if (!tsconfig) {
    return [];
  }
  const compilerOptions = typeof tsconfig.compilerOptions === "object" && tsconfig.compilerOptions !== null ? (tsconfig.compilerOptions as Record<string, unknown>) : {};
  if (compilerOptions.strict !== true) {
    return [finding("high", "correctness", "TypeScript strict mode disabled", "tsconfig.json does not enable strict mode.", join(rootPath, "tsconfig.json"), ["compilerOptions.strict is not true"], "Enable strict TypeScript checking.", true)];
  }
  return [];
}

function documentationFindings(rootPath: string, packageJson: Record<string, unknown> | null): VantageFinding[] {
  const findings: VantageFinding[] = [];
  const readmePath = join(rootPath, "README.md");
  const readme = readFileIfExists(readmePath);
  if (!readme) {
    findings.push(finding(
      "low",
      "documentation",
      "Missing README",
      "Project root does not include a readable README.md.",
      null,
      ["README.md absent"],
      "Add a short README with project identity, install, test, and build instructions.",
      true
    ));
    return findings;
  }
  const packageName = typeof packageJson?.name === "string" ? packageJson.name : "";
  if (packageName) {
    const readmeNames = readmeIdentityTerms(readme);
    const packageTerms = identityTerms(packageName);
    const packageMentioned = packageTerms.some((term) => normalizedTextIncludes(readme, term));
    if (readmeNames.length > 0 && !packageMentioned) {
      findings.push(finding(
        "info",
        "documentation",
        "README identity differs from package name",
        "README presents a project identity that does not mention the package.json name.",
        readmePath,
        [`package name: ${packageName}`, ...readmeNames.map((name) => `README identity: ${name}`)],
        "Align README identity and package metadata or document why they intentionally differ.",
        false
      ));
    }
  }
  return findings;
}

function fixPlansForFindings(
  rootPath: string,
  packageJson: Record<string, unknown> | null,
  files: string[],
  findings: VantageFinding[],
  mode: VantageMode
): VantageFixPlan[] {
  if (mode === "report") {
    return [];
  }
  const candidates = mode === "fix" ? findings.filter((item) => item.fixable) : findings;
  return candidates
    .map((item) => fixPlanForFinding(rootPath, packageJson, files, item, mode))
    .sort((a, b) => a.risk.localeCompare(b.risk) || a.action_type.localeCompare(b.action_type) || a.finding_id.localeCompare(b.finding_id));
}

function fixPlanForFinding(
  rootPath: string,
  packageJson: Record<string, unknown> | null,
  files: string[],
  findingItem: VantageFinding,
  mode: Extract<VantageMode, "fix" | "wrecking_crew">
): VantageFixPlan {
  const packagePath = join(rootPath, "package.json");
  const base = {
    finding_id: findingItem.finding_id,
    mode,
    target_file: findingItem.file_path,
    risk: riskForFinding(findingItem),
    patch_preview: [] as string[]
  };
  const specific = mode === "fix"
    ? fixModePlan(rootPath, packagePath, packageJson, files, findingItem)
    : wreckingCrewPlan(findingItem);
  const withoutId = { ...base, ...specific };
  return {
    plan_id: `fixplan_${shortHash(withoutId)}`,
    ...withoutId
  };
}

function fixModePlan(
  rootPath: string,
  packagePath: string,
  packageJson: Record<string, unknown> | null,
  files: string[],
  findingItem: VantageFinding
): Omit<VantageFixPlan, "plan_id" | "finding_id" | "mode" | "risk"> {
  const hasTsconfig = existsSync(join(rootPath, "tsconfig.json"));
  const hasTests = files.some((file) => isTestPath(rootPath, file));
  if (findingItem.title === "Missing test script" || findingItem.title === "Tests present but no test script") {
    return packagePatch(packagePath, "Add a deterministic test script.", [`scripts.test = ${hasTests ? "vitest run" : "node --test"}`]);
  }
  if (findingItem.title === "Missing build script") {
    return packagePatch(packagePath, "Add a deterministic build script.", [`scripts.build = ${hasTsconfig ? "tsc -p tsconfig.json" : "npm run lint"}`]);
  }
  if (findingItem.title === "Missing lint script") {
    return packagePatch(packagePath, "Add a static validation script.", [`scripts.lint = ${hasTsconfig ? "tsc -p tsconfig.json --noEmit" : "npm test"}`]);
  }
  if (findingItem.title === "Missing license metadata") {
    return packagePatch(packagePath, "Declare explicit package license metadata.", ["license = UNLICENSED"]);
  }
  if (findingItem.title === "Missing Node lockfile") {
    return {
      action_type: "command_required",
      target_file: packagePath,
      deterministic: true,
      summary: "Create the package-manager lockfile with the local package manager.",
      patch_preview: ["npm install --package-lock-only"]
    };
  }
  if (findingItem.title === "Broad dependency versions" || findingItem.title === "Dependency duplicated in devDependencies") {
    return {
      action_type: "manual_review",
      target_file: packagePath,
      deterministic: false,
      summary: "Dependency intent needs a human choice before VANTAGE should rewrite it.",
      patch_preview: packageJson ? [`package: ${String(packageJson.name ?? "unknown")}`] : []
    };
  }
  return {
    action_type: "manual_review",
    target_file: findingItem.file_path,
    deterministic: false,
    summary: findingItem.suggested_action,
    patch_preview: findingItem.evidence
  };
}

function packagePatch(targetFile: string, summary: string, patchPreview: string[]): Omit<VantageFixPlan, "plan_id" | "finding_id" | "mode" | "risk"> {
  return {
    action_type: "package_json_patch",
    target_file: targetFile,
    deterministic: true,
    summary,
    patch_preview: patchPreview
  };
}

function wreckingCrewPlan(findingItem: VantageFinding): Omit<VantageFixPlan, "plan_id" | "finding_id" | "mode" | "risk"> {
  return {
    action_type: "challenge",
    target_file: findingItem.file_path,
    deterministic: true,
    summary: `Prove this finding cannot ship, or prove it is an intentional boundary: ${findingItem.title}.`,
    patch_preview: findingItem.evidence
  };
}

function riskForFinding(findingItem: VantageFinding): VantageFixPlan["risk"] {
  if (findingItem.severity === "critical" || findingItem.severity === "high") return "high";
  if (findingItem.severity === "medium") return "medium";
  return "low";
}

function detectDuplicateProjects(projects: VantageProject[]): VantageReport["duplicate_project_groups"] {
  const byName = new Map<string, VantageProject[]>();
  for (const project of projects) {
    const familyName = normalizeProjectFamilyName(project.name);
    byName.set(familyName, [...(byName.get(familyName) ?? []), project]);
  }
  return [...byName.entries()]
    .filter(([, group]) => group.length > 1)
    .map(([name, group]) => ({
      group_id: `duplicate_${shortHash({ name, project_ids: group.map((project) => project.project_id).sort() })}`,
      project_ids: group.map((project) => project.project_id).sort(),
      reason: `Projects share normalized name ${name}`
    }))
    .sort((a, b) => a.group_id.localeCompare(b.group_id));
}

function normalizeProjectFamilyName(name: string): string {
  return name.replace(/^@[^/]+\//, "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function projectSignals(rootPath: string, packageJson: Record<string, unknown> | null, files: string[], findings: VantageFinding[]): string[] {
  const signals = new Set<string>();
  const scripts = packageJson ? scriptMap(packageJson) : {};
  const hasTests = files.some((file) => isTestPath(rootPath, file));
  if (packageJson) signals.add("node_package");
  if (packageLockfiles(rootPath).length > 0) signals.add("lockfile_present");
  if (existsSync(join(rootPath, "tsconfig.json"))) signals.add("typescript");
  if (existsSync(join(rootPath, "README.md"))) signals.add("readme");
  if (scripts.test) signals.add("test_script");
  if (scripts.build) signals.add("build_script");
  if (scripts.lint) signals.add("lint_script");
  if (hasTests) signals.add("tests_present");
  if (files.some((file) => relative(rootPath, file).startsWith("fixtures/"))) signals.add("fixtures_present");
  if (findings.some((item) => item.category === "security")) signals.add("source_risk_findings");
  if (findings.some((item) => item.severity === "high" || item.severity === "critical")) signals.add("high_risk_findings");
  return [...signals].sort();
}

function inferStage(files: string[], packageJson: Record<string, unknown> | null, findings: VantageFinding[]): VantageProject["stage"] {
  const hasTests = files.some((file) => TEST_FILE_PATTERN.test(file) || TEST_NAME_PATTERN.test(file));
  const hasBuild = Boolean(packageJson ? scriptMap(packageJson).build : false);
  const hasHigh = findings.some((item) => item.severity === "high" || item.severity === "critical");
  if (hasTests && hasBuild && !hasHigh) return "hardened";
  if (hasTests && hasBuild) return "working";
  if (files.length > 10) return "prototype";
  return "seed";
}

function inferQuality(findings: VantageFinding[], signals: string[]): VantageProject["quality"] {
  if (findings.some((item) => item.severity === "critical" || item.severity === "high")) return "risky";
  if (findings.filter((item) => item.severity === "medium").length > 2) return "rough";
  if (signals.includes("tests_present") && signals.includes("typescript")) return "promising";
  return "clean";
}

function summarize(projects: VantageProject[]): VantageReport["summary"] {
  const findings = projects.flatMap((project) => project.findings);
  const fixPlans = projects.flatMap((project) => project.fix_plans);
  return {
    project_count: projects.length,
    finding_count: findings.length,
    critical_count: findings.filter((findingItem) => findingItem.severity === "critical").length,
    high_count: findings.filter((findingItem) => findingItem.severity === "high").length,
    medium_count: findings.filter((findingItem) => findingItem.severity === "medium").length,
    fixable_count: findings.filter((findingItem) => findingItem.fixable).length,
    fix_plan_count: fixPlans.length
  };
}

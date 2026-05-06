import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runVantage } from "../src/index.js";
import { listFiles } from "../src/products/vantageSupport.js";

describe("VANTAGE 2.0", () => {
  it("discovers a Node project and reports package health findings", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "rough-app", version: "0.0.1", scripts: { build: "tsc" } }, null, 2)
      );
      writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { strict: false } }, null, 2));
      mkdirSync(join(dir, "src"));
      writeFileSync(join(dir, "src", "index.ts"), "const value: unknown = 1;\nconsole.log(value);\n");

      const report = runVantage(dir);
      expect(report.projects).toHaveLength(1);
      expect(report.projects[0]?.project_type).toBe("node");
      expect(report.summary.finding_count).toBeGreaterThanOrEqual(4);
      expect(report.projects[0]?.findings.some((finding) => finding.title === "TypeScript strict mode disabled")).toBe(true);
      expect(report.audit_hash).toMatch(/^[a-f0-9]{64}$/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("detects duplicate project families by normalized package name", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-dupes-"));
    try {
      for (const [child, name] of [["one", "same-app"], ["two", "@scope/same_app"]]) {
        mkdirSync(join(dir, child));
        writeFileSync(join(dir, child, "package.json"), JSON.stringify({ name, version: "0.0.1" }, null, 2));
      }
      const report = runVantage(dir);
      expect(report.projects).toHaveLength(2);
      expect(report.duplicate_project_groups).toHaveLength(1);
      expect(report.duplicate_project_groups[0]?.project_ids).toEqual([...report.duplicate_project_groups[0]!.project_ids].sort());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports dependency hygiene and test readiness signals", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-deps-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify(
          {
            name: "dependency-risk",
            version: "0.0.1",
            scripts: { test: "vitest run", build: "tsc" },
            dependencies: { leftpad: "*", shared: "^1.0.0" },
            devDependencies: { shared: "^1.0.0", vitest: "latest" }
          },
          null,
          2
        )
      );

      const report = runVantage(dir);
      const titles = report.projects[0]?.findings.map((finding) => finding.title) ?? [];
      expect(titles).toContain("Missing Node lockfile");
      expect(titles).toContain("Broad dependency versions");
      expect(titles).toContain("Dependency duplicated in devDependencies");
      expect(titles).toContain("Test script without checked-in tests");
      expect(report.projects[0]?.signals).toContain("test_script");
      expect(runVantage(dir).audit_hash).toBe(report.audit_hash);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("emits deterministic fix plans in fix mode", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-fix-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "fix-me", version: "0.0.1", scripts: {} }, null, 2)
      );
      writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { strict: true } }, null, 2));

      const report = runVantage(dir, "fix");
      const plans = report.projects[0]?.fix_plans ?? [];
      expect(report.mode).toBe("fix");
      expect(plans.length).toBeGreaterThan(0);
      expect(plans.every((plan) => plan.plan_id.match(/^fixplan_[a-f0-9]+$/))).toBe(true);
      expect(plans.map((plan) => plan.action_type)).toContain("package_json_patch");
      expect(plans.some((plan) => plan.patch_preview.includes("scripts.test = node --test"))).toBe(true);
      expect(runVantage(dir, "fix").projects[0]?.fix_plans).toEqual(plans);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports dangerous source calls outside tests", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-source-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "danger-zone", version: "0.0.1", scripts: { test: "vitest run" } }, null, 2)
      );
      mkdirSync(join(dir, "src"));
      writeFileSync(
        join(dir, "src", "index.ts"),
        [
          "import { rmSync } from 'node:fs';",
          "import { execSync } from 'node:child_process';",
          "const home = process.env.HOME;",
          "const fn = new Function('return 1');",
          "execSync(String(home));",
          "rmSync('/tmp/example', { recursive: true, force: true });",
          "export { fn };"
        ].join("\n")
      );

      const report = runVantage(dir, "wrecking_crew");
      const findings = report.projects[0]?.findings ?? [];
      expect(report.mode).toBe("wrecking_crew");
      expect(findings.map((finding) => finding.title)).toEqual(
        expect.arrayContaining([
          "Child process usage",
          "Destructive fs call outside tests",
          "Direct process.env access",
          "Dynamic code execution"
        ])
      );
      expect(findings.find((finding) => finding.title === "Dynamic code execution")?.severity).toBe("critical");
      expect(findings.every((finding) => finding.suggested_action.startsWith("Wrecking crew challenge:"))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("downgrades the constrained LUNA LaunchAgent bridge without hiding it", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-luna-bridge-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "luna-bridge", version: "0.0.1", license: "MIT", scripts: { build: "tsc", lint: "tsc --noEmit", test: "vitest run" } }, null, 2)
      );
      writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "luna-bridge", lockfileVersion: 3 }, null, 2));
      writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { strict: true } }, null, 2));
      writeFileSync(join(dir, "README.md"), "# luna-bridge\n");
      mkdirSync(join(dir, "src"));
      mkdirSync(join(dir, "src", "luna"));
      mkdirSync(join(dir, "tests"));
      writeFileSync(join(dir, "tests", "launchAgent.test.ts"), "import '../src/luna/launchAgent';\n");
      writeFileSync(
        join(dir, "src", "luna", "launchAgent.ts"),
        [
          "import { existsSync, unlinkSync } from 'node:fs';",
          "import { execFileSync } from 'node:child_process';",
          "import { lunaLaunchAgentPath } from './paths';",
          "export function unload(homeDir?: string) {",
          "  const plist_path = lunaLaunchAgentPath(homeDir);",
          "  execFileSync('launchctl', ['unload', plist_path], { stdio: 'ignore' });",
          "  if (existsSync(plist_path)) unlinkSync(plist_path);",
          "}"
        ].join("\n")
      );

      const findings = runVantage(dir).projects[0]?.findings ?? [];
      expect(findings.find((finding) => finding.title === "Constrained system command bridge")?.severity).toBe("medium");
      expect(findings.find((finding) => finding.title === "Constrained LaunchAgent cleanup")?.severity).toBe("medium");
      expect(findings.some((finding) => finding.severity === "high" || finding.severity === "critical")).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("detects benchmark-owned JavaScript security patterns", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-owned-patterns-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "owned-patterns", version: "0.0.1", license: "UNLICENSED", scripts: { build: "tsc", lint: "tsc --noEmit", test: "vitest run" } }, null, 2)
      );
      writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "owned-patterns", lockfileVersion: 3 }, null, 2));
      writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { strict: true } }, null, 2));
      writeFileSync(join(dir, "README.md"), "# owned-patterns\n");
      mkdirSync(join(dir, "routes"));
      mkdirSync(join(dir, "tests"));
      writeFileSync(join(dir, "tests", "index.test.ts"), "import '../routes/index';\n");
      writeFileSync(
        join(dir, "routes", "index.ts"),
        [
          "import crypto from 'node:crypto';",
          "export const key = '-----BEGIN RSA PRIVATE KEY-----';",
          "export const hmac = crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj');",
          "export const query = { $where: `this.userId == ${'${userId}'}` };",
          "export const parsed = JSON.parse('{\"ok\":true}');",
          "export const matcher = new RegExp(`prefix-${'${name}'}`);"
        ].join("\n")
      );

      const titles = runVantage(dir).projects[0]?.findings.map((finding) => finding.title) ?? [];
      expect(titles).toEqual(expect.arrayContaining([
        "Dynamic regular expression",
        "Hardcoded secret material",
        "JSON.parse without local boundary",
        "NoSQL $where injection"
      ]));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports circular dependencies and long functions", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-architecture-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "architecture-risk", version: "0.0.1", license: "UNLICENSED", scripts: { build: "tsc", lint: "tsc --noEmit", test: "vitest run" } }, null, 2)
      );
      writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "architecture-risk", lockfileVersion: 3 }, null, 2));
      writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { strict: true } }, null, 2));
      writeFileSync(join(dir, "README.md"), "# architecture-risk\n");
      mkdirSync(join(dir, "src"));
      mkdirSync(join(dir, "tests"));
      writeFileSync(join(dir, "tests", "index.test.ts"), "import '../src/a';\n");
      writeFileSync(join(dir, "src", "a.ts"), "import { b } from './b';\nexport const a = b;\n");
      writeFileSync(join(dir, "src", "b.ts"), "import { a } from './a';\nexport const b = a;\n");
      writeFileSync(
        join(dir, "src", "long.ts"),
        [
          "export function longFunction() {",
          ...Array.from({ length: 105 }, (_, index) => `  const value${index} = ${index};`),
          "  return value104;",
          "}"
        ].join("\n")
      );

      const report = runVantage(dir);
      const findings = report.projects[0]?.findings ?? [];
      expect(findings.map((finding) => finding.title)).toEqual(expect.arrayContaining(["Circular dependency", "Long function"]));
      expect(findings.find((finding) => finding.title === "Circular dependency")?.severity).toBe("high");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not treat benchmark comments as runtime dynamic execution", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-benchmark-zone-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "benchmark-zone", version: "0.0.1", license: "UNLICENSED", scripts: { build: "tsc", lint: "tsc --noEmit", test: "vitest run" } }, null, 2)
      );
      writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "benchmark-zone", lockfileVersion: 3 }, null, 2));
      writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { strict: true } }, null, 2));
      writeFileSync(join(dir, "README.md"), "# benchmark-zone\n");
      mkdirSync(join(dir, "benchmarks"));
      mkdirSync(join(dir, "tests"));
      writeFileSync(join(dir, "tests", "index.test.ts"), "import '../benchmarks/stage';\n");
      writeFileSync(join(dir, "benchmarks", "stage.ts"), "// eval(req.body) is an intentional benchmark phrase.\nexport const ok = true;\n");

      const report = runVantage(dir);
      const dynamicFindings = report.projects[0]?.findings.filter((finding) => finding.title === "Dynamic code execution") ?? [];
      expect(dynamicFindings).toHaveLength(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("bounds ambient scans and skips heavyweight generated directories", () => {
    const dir = mkdtempSync(join(tmpdir(), "vantage-bounds-"));
    try {
      mkdirSync(join(dir, "src"));
      mkdirSync(join(dir, ".venv"));
      mkdirSync(join(dir, "vendor"));
      writeFileSync(join(dir, "src", "a.ts"), "export const a = 1;\n");
      writeFileSync(join(dir, "src", "b.ts"), "export const b = 2;\n");
      writeFileSync(join(dir, ".venv", "ignored.py"), "print('skip')\n");
      writeFileSync(join(dir, "vendor", "ignored.js"), "module.exports = 1;\n");

      const files = listFiles(dir, 1).map((file) => file.replaceAll("\\", "/"));
      const allFiles = listFiles(dir).map((file) => file.replaceAll("\\", "/"));

      expect(files).toHaveLength(1);
      expect(allFiles.some((file) => file.includes("/.venv/"))).toBe(false);
      expect(allFiles.some((file) => file.includes("/vendor/"))).toBe(false);
      expect(allFiles.filter((file) => file.includes("/src/"))).toHaveLength(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

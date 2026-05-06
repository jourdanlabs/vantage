import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { VantageFinding, VantageMode, VantageProject } from "../types.js";
import { shortHash } from "../audit/hash.js";

const SKIP_DIRS = new Set([
  ".cache",
  ".git",
  ".mypy_cache",
  ".next",
  ".pytest_cache",
  ".ruff_cache",
  ".tox",
  ".turbo",
  ".venv",
  "__pycache__",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "Pods",
  "target",
  "venv",
  "vendor"
]);

const DEFAULT_FILE_SCAN_LIMIT = 8_000;
const DEFAULT_DIR_SCAN_LIMIT = 2_000;

export const CODE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rs", ".go"]);
export const TEXT_EXTENSIONS = new Set([...CODE_EXTENSIONS, ".json", ".md", ".yml", ".yaml", ".toml"]);
export const TEST_FILE_PATTERN = /(^|\/)(__tests__|tests?|spec)\//;
export const TEST_NAME_PATTERN = /\.(test|spec)\.[cm]?[jt]sx?$/;

export function listFiles(rootPath: string, maxFiles = DEFAULT_FILE_SCAN_LIMIT): string[] {
  const files: string[] = [];
  walkDirs(rootPath, (dir) => {
    for (const entry of safeReadDir(dir)) {
      if (files.length >= maxFiles) {
        break;
      }
      const full = join(dir, entry);
      const stat = safeStat(full);
      if (stat?.isFile()) {
        files.push(full);
      }
    }
    return files.length < maxFiles;
  });
  return files.sort();
}

export function walkDirs(rootPath: string, visit: (dir: string) => boolean, maxDirs = DEFAULT_DIR_SCAN_LIMIT): void {
  const state = { dirCount: 0, stopped: false };
  walkDirsInternal(rootPath, visit, maxDirs, state);
}

function walkDirsInternal(rootPath: string, visit: (dir: string) => boolean, maxDirs: number, state: { dirCount: number; stopped: boolean }): void {
  if (state.stopped) {
    return;
  }
  if (!safeStat(rootPath)?.isDirectory()) {
    return;
  }
  state.dirCount += 1;
  if (state.dirCount > maxDirs) {
    state.stopped = true;
    return;
  }
  const shouldDescend = visit(rootPath);
  if (!shouldDescend) {
    return;
  }
  for (const entry of safeReadDir(rootPath)) {
    if (state.stopped) {
      return;
    }
    const full = join(rootPath, entry);
    if (!safeStat(full)?.isDirectory() || SKIP_DIRS.has(entry)) {
      continue;
    }
    walkDirsInternal(full, visit, maxDirs, state);
  }
}

export function safeReadDir(dir: string): string[] {
  try {
    return readdirSync(dir).sort();
  } catch {
    return [];
  }
}

export function safeStat(path: string): ReturnType<typeof statSync> | null {
  try {
    return existsSync(path) ? statSync(path) : null;
  } catch {
    return null;
  }
}

export function countLanguages(files: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const file of files) {
    const language = languageFor(extension(file));
    if (language) {
      counts[language] = (counts[language] ?? 0) + 1;
    }
  }
  return Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)));
}

export function inferProjectType(rootPath: string): VantageProject["project_type"] {
  if (existsSync(join(rootPath, "package.json"))) return "node";
  if (existsSync(join(rootPath, "pyproject.toml"))) return "python";
  if (existsSync(join(rootPath, "Cargo.toml"))) return "rust";
  if (existsSync(join(rootPath, "go.mod"))) return "go";
  return "unknown";
}

export function extension(file: string): string {
  const match = file.match(/(\.[^.]+)$/);
  return match?.[1]?.toLowerCase() ?? "";
}

function languageFor(ext: string): string | null {
  const map: Record<string, string> = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".rs": "rust",
    ".go": "go",
    ".json": "json",
    ".md": "markdown",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".toml": "toml"
  };
  return map[ext] ?? null;
}

export function readJsonIfExists(file: string): Record<string, unknown> | null {
  const content = readFileIfExists(file);
  if (!content) return null;
  try {
    return JSON.parse(content) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function readFileIfExists(file: string): string | null {
  const stat = safeStat(file);
  if (!stat?.isFile()) return null;
  if (stat.size > 512_000) return null;
  try {
    return readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

export function scriptMap(packageJson: Record<string, unknown>): Record<string, unknown> {
  return typeof packageJson.scripts === "object" && packageJson.scripts !== null ? (packageJson.scripts as Record<string, unknown>) : {};
}

export function dependencyMap(value: unknown): Record<string, string> {
  if (typeof value !== "object" || value === null) {
    return {};
  }
  const entries: Array<[string, string]> = [];
  for (const [name, version] of Object.entries(value as Record<string, unknown>)) {
    if (typeof version === "string") {
      entries.push([name, version]);
    }
  }
  return Object.fromEntries(entries.sort(([a], [b]) => a.localeCompare(b)));
}

export function packageLockfiles(rootPath: string): string[] {
  return ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"]
    .map((name) => join(rootPath, name))
    .filter((file) => existsSync(file));
}

export function isTestPath(rootPath: string, file: string): boolean {
  const rel = relative(rootPath, file).replaceAll("\\", "/");
  return TEST_FILE_PATTERN.test(rel) || TEST_NAME_PATTERN.test(rel);
}

export function firstRelativeMatches(rootPath: string, files: string[], predicate: (file: string) => boolean): string[] {
  return files
    .filter(predicate)
    .map((file) => relative(rootPath, file).replaceAll("\\", "/"))
    .sort()
    .slice(0, 5);
}

export function readmeIdentityTerms(readme: string): string[] {
  return readme
    .split(/\r?\n/)
    .filter((line) => /^#\s+/.test(line))
    .map((line) => line.replace(/^#\s+/, "").trim())
    .filter(Boolean)
    .slice(0, 3)
    .sort();
}

export function identityTerms(name: string): string[] {
  const withoutScope = name.replace(/^@[^/]+\//, "");
  return [...new Set([name, withoutScope, withoutScope.replace(/[-_]/g, " ")].map(normalizeIdentity).filter(Boolean))].sort();
}

function normalizeIdentity(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

export function normalizedTextIncludes(text: string, term: string): boolean {
  return normalizeIdentity(text).includes(term);
}

export function matchingLines(content: string, pattern: RegExp): string[] {
  return content
    .split(/\r?\n/)
    .map((line, index) => ({ line, number: index + 1 }))
    .filter(({ line }) => pattern.test(line))
    .slice(0, 5)
    .map(({ line, number }) => `${number}: ${line.trim()}`);
}

export function commentMatchingLines(content: string, pattern: RegExp): string[] {
  return content
    .split(/\r?\n/)
    .map((line, index) => ({ line, number: index + 1 }))
    .filter(({ line }) => /^\s*(\/\/|#|\/\*|\*|<!--)/.test(line) && pattern.test(line))
    .slice(0, 5)
    .map(({ line, number }) => `${number}: ${line.trim()}`);
}

export function finding(
  severity: VantageFinding["severity"],
  category: VantageFinding["category"],
  title: string,
  detail: string,
  file_path: string | null,
  evidence: string[],
  suggested_action: string,
  fixable: boolean
): VantageFinding {
  return {
    finding_id: `finding_${shortHash({ severity, category, title, detail, file_path, evidence })}`,
    severity,
    category,
    title,
    detail,
    file_path,
    evidence: [...evidence].sort(),
    suggested_action,
    fixable
  };
}

export function severityRank(severity: VantageFinding["severity"]): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
}

export function modeAwareFindings(findings: VantageFinding[], mode: VantageMode): VantageFinding[] {
  if (mode === "report") {
    return findings;
  }
  return findings.map((item) => {
    const prefix = mode === "fix" ? "Dry-run fix candidate:" : "Wrecking crew challenge:";
    return {
      ...item,
      suggested_action: `${prefix} ${item.suggested_action}`
    };
  });
}

export function compareFindings(a: VantageFinding, b: VantageFinding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    a.category.localeCompare(b.category) ||
    a.title.localeCompare(b.title) ||
    (a.file_path ?? "").localeCompare(b.file_path ?? "") ||
    a.finding_id.localeCompare(b.finding_id)
  );
}

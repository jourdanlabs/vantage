import { dirname, join, relative, resolve } from "node:path";
import type { VantageFinding } from "../types.js";
import {
  commentMatchingLines,
  compareFindings,
  extension,
  finding,
  isTestPath,
  matchingLines,
  readFileIfExists,
  safeStat
} from "./vantageSupport.js";

const LARGE_FILE_LINE_THRESHOLD = 500;
const LARGE_FILE_BYTE_THRESHOLD = 80_000;
const TODO_DEBT_THRESHOLD = 8;
const COMMENT_DEBT_THRESHOLD = 120;
const LONG_FUNCTION_LINE_THRESHOLD = 100;
const HIGH_FAN_IN_THRESHOLD = 10;

type IntentZone = "runtime" | "test" | "benchmark" | "catalog" | "generated" | "tooling";

export function architectureFindings(rootPath: string, codeFiles: string[]): VantageFinding[] {
  const graph = buildDependencyGraph(rootPath, codeFiles);
  return [
    ...circularDependencyFindings(rootPath, graph),
    ...highCouplingFindings(rootPath, graph),
    ...longFunctionFindings(rootPath, codeFiles)
  ];
}

function buildDependencyGraph(rootPath: string, codeFiles: string[]): Map<string, string[]> {
  const moduleFiles = codeFiles.filter((file) => isModuleCodeFile(file));
  const knownModules = new Set(moduleFiles);
  const graph = new Map<string, string[]>();
  for (const file of moduleFiles) {
    const content = readFileIfExists(file);
    if (!content) {
      graph.set(file, []);
      continue;
    }
    const dependencies = extractImportSpecifiers(stripComments(content))
      .filter((specifier) => specifier.startsWith("."))
      .map((specifier) => resolveImport(file, specifier, knownModules))
      .filter((resolved): resolved is string => Boolean(resolved))
      .filter((resolved) => resolved.startsWith(rootPath))
      .sort();
    graph.set(file, [...new Set(dependencies)]);
  }
  return graph;
}

function circularDependencyFindings(rootPath: string, graph: Map<string, string[]>): VantageFinding[] {
  return detectCycles(graph)
    .slice(0, 12)
    .map((cycle) => {
      const relCycle = cycle.map((file) => moduleLabel(rootPath, file));
      const contained = cycle.some((file) => isContainedIntent(rootPath, file));
      return finding(
        contained ? "low" : "high",
        contained ? "test_risk" : "maintainability",
        contained ? "Contained circular dependency fixture" : "Circular dependency",
        contained ? `Intentional fixture cycle detected: ${relCycle.join(" -> ")}` : `Circular dependency detected: ${relCycle.join(" -> ")}`,
        cycle[0] ?? null,
        [relCycle.join(" -> ")],
        contained ? "Keep fixture defects isolated from runtime imports and benchmark their expected detection." : "Break the cycle by extracting shared contracts or moving orchestration out of leaf modules.",
        false
      );
    });
}

function highCouplingFindings(rootPath: string, graph: Map<string, string[]>): VantageFinding[] {
  const inbound = new Map<string, string[]>();
  for (const [from, deps] of graph.entries()) {
    for (const dep of deps) {
      inbound.set(dep, [...(inbound.get(dep) ?? []), from]);
    }
  }
  return [...inbound.entries()]
    .filter(([, importers]) => importers.length >= HIGH_FAN_IN_THRESHOLD)
    .sort(([a, aImporters], [b, bImporters]) => bImporters.length - aImporters.length || a.localeCompare(b))
    .slice(0, 10)
    .map(([file, importers]) => {
      const label = moduleLabel(rootPath, file);
      const stableBoundary = isStableBoundaryModule(label);
      return finding(
        stableBoundary ? "low" : "medium",
        "maintainability",
        stableBoundary ? "Stable boundary fan-in" : "High fan-in coupling",
        `${label} is imported by ${importers.length} modules.`,
        file,
        importers.map((importer) => moduleLabel(rootPath, importer)).sort().slice(0, 8),
        stableBoundary ? "Keep this boundary small, dependency-light, and covered by package-level tests." : "Confirm this is a deliberate stable boundary, or split shared contracts from implementation.",
        false
      );
    });
}

function isStableBoundaryModule(label: string): boolean {
  return /^(src\/index|src\/types|src\/audit\/hash|tests\/helpers)$/.test(label);
}

function longFunctionFindings(rootPath: string, codeFiles: string[]): VantageFinding[] {
  const findings: VantageFinding[] = [];
  for (const file of codeFiles.filter(isModuleCodeFile)) {
    const content = readFileIfExists(file);
    if (!content) {
      continue;
    }
    for (const functionSpan of findFunctionSpans(content)) {
      if (functionSpan.line_count <= LONG_FUNCTION_LINE_THRESHOLD) {
        continue;
      }
      const contained = isContainedIntent(rootPath, file);
      findings.push(finding(
        contained ? "low" : "medium",
        contained ? "test_risk" : "maintainability",
        contained ? "Contained long-function fixture" : "Long function",
        contained ? `${functionSpan.name}() in ${relative(rootPath, file)} is a contained fixture spanning ${functionSpan.line_count} lines.` : `${functionSpan.name}() in ${relative(rootPath, file)} spans ${functionSpan.line_count} lines.`,
        file,
        [`${functionSpan.name}(): lines ${functionSpan.start_line}-${functionSpan.end_line}`, `${functionSpan.line_count} lines`],
        contained ? "Keep fixture defects explicit and covered by benchmark expectations." : "Split the function into smaller deterministic validators or extraction helpers.",
        false
      ));
    }
  }
  return findings.sort(compareFindings).slice(0, 12);
}

export function sourceFindings(rootPath: string, codeFiles: string[], textFiles: string[]): VantageFinding[] {
  return [
    ...textSourceFindings(rootPath, textFiles),
    ...codeSourceFindings(rootPath, codeFiles)
  ];
}

function textSourceFindings(rootPath: string, textFiles: string[]): VantageFinding[] {
  const findings: VantageFinding[] = [];
  for (const file of textFiles) {
    const content = readFileIfExists(file);
    if (!content) {
      continue;
    }
    const rel = relative(rootPath, file);
    const todoLines = commentMatchingLines(content, /\bTODO\b|\bFIXME\b/);
    if (todoLines.length > 0) {
      findings.push(finding("low", "maintainability", "TODO/FIXME left in source", `${rel} contains TODO/FIXME markers.`, file, todoLines, "Resolve or track the TODO with an issue reference.", false));
    }
    if (/\bconsole\.log\s*\(/.test(content) && !rel.startsWith("tests/")) {
      findings.push(finding("low", "maintainability", "Console logging in runtime source", `${rel} contains console.log calls.`, file, matchingLines(content, /\bconsole\.log\s*\(/), "Use structured logging or remove debug output.", true));
    }
    if (/execFileSync\([^)]*dist\/src\/cli\.js/.test(content)) {
      findings.push(finding("high", "test_risk", "Test depends on prebuilt dist artifact", `${rel} invokes dist/src/cli.js, so a clean npm test can depend on build order.`, file, matchingLines(content, /dist\/src\/cli\.js/), "Invoke the TypeScript CLI through tsx or make the test build its fixture explicitly.", true));
    }
  }
  return findings;
}

function codeSourceFindings(rootPath: string, codeFiles: string[]): VantageFinding[] {
  const findings: VantageFinding[] = [];
  for (const file of codeFiles) {
    const content = readFileIfExists(file);
    if (!content) {
      continue;
    }
    findings.push(...codeFileSizeAndDebtFindings(rootPath, file, content));
    findings.push(...codeFileTypeFindings(rootPath, file, content));
    findings.push(...codeFileExecutionFindings(rootPath, file, content));
  }
  return findings;
}

function codeFileSizeAndDebtFindings(rootPath: string, file: string, content: string): VantageFinding[] {
  const findings: VantageFinding[] = [];
  const rel = relative(rootPath, file);
  const lines = content.split(/\r?\n/);
  const stat = safeStat(file);
  const todoLines = commentMatchingLines(content, /\bTODO\b|\bFIXME\b/);
  const commentLines = lines.filter((line) => /^\s*(\/\/|#|\/\*|\*|<!--)/.test(line)).length;

  if (stat && (lines.length > LARGE_FILE_LINE_THRESHOLD || stat.size > LARGE_FILE_BYTE_THRESHOLD)) {
    const stableBoundary = isStableBoundaryModule(moduleLabel(rootPath, file));
    findings.push(finding(
      stableBoundary ? "low" : "medium",
      "maintainability",
      stableBoundary ? "Large stable contract file" : "Large source file",
      `${rel} is large enough to make review and deterministic auditing harder.`,
      file,
      [`${lines.length} lines`, `${stat.size} bytes`],
      stableBoundary ? "Keep the contract organized by domain and protect it with package-level type checks." : "Split the file by responsibility or add stronger local tests around it.",
      false
    ));
  }
  if (todoLines.length >= TODO_DEBT_THRESHOLD) {
    findings.push(finding("medium", "maintainability", "High TODO/FIXME debt", `${rel} contains many unresolved TODO/FIXME comments.`, file, todoLines, "Resolve, ticket, or remove stale TODO/FIXME markers.", false));
  }
  if (commentLines >= COMMENT_DEBT_THRESHOLD) {
    findings.push(finding("low", "maintainability", "High comment debt", `${rel} contains a high volume of comments relative to source review expectations.`, file, [`${commentLines} comment lines`, `${lines.length} total lines`], "Audit comments for stale explanations and move long-lived rationale into docs where appropriate.", false));
  }
  return findings;
}

function codeFileTypeFindings(rootPath: string, file: string, content: string): VantageFinding[] {
  const rel = relative(rootPath, file);
  const findings: VantageFinding[] = [];
  if (/as\s+any\b|:\s*any\b/.test(content)) {
    findings.push(finding("medium", "correctness", "Explicit any type", `${rel} contains explicit any usage.`, file, matchingLines(content, /as\s+any\b|:\s*any\b/), "Replace any with a narrow type or unknown plus validation.", true));
  }
  if (/\/\/\s*@ts-ignore/.test(content)) {
    findings.push(finding("medium", "correctness", "TypeScript ignore directive", `${rel} suppresses TypeScript checking.`, file, matchingLines(content, /\/\/\s*@ts-ignore/), "Remove the suppression or replace it with a justified @ts-expect-error.", true));
  }
  return findings;
}

function codeFileExecutionFindings(rootPath: string, file: string, content: string): VantageFinding[] {
  const executableContent = stripNonExecutableText(content);
  const rel = relative(rootPath, file);
  const zone = intentZone(rootPath, file);
  return [
    ...processEnvFindings(file, rel, zone, executableContent),
    ...childProcessFindings(file, rel, zone, executableContent),
    ...dynamicExecutionFindings(file, rel, zone, executableContent),
    ...nosqlWhereFindings(file, rel, zone, content),
    ...hardcodedSecretFindings(file, rel, zone, content),
    ...jsonParseBoundaryFindings(file, rel, zone, content),
    ...dynamicRegexFindings(file, rel, zone, content),
    ...destructiveFsFindings(file, rel, zone, executableContent)
  ];
}

function processEnvFindings(file: string, rel: string, zone: IntentZone, executableContent: string): VantageFinding[] {
  if (!/\bprocess\.env\b/.test(executableContent)) return [];
  const inTest = zone !== "runtime";
  return [finding(inTest ? "low" : "medium", inTest ? "test_risk" : "security", "Direct process.env access", inTest ? `${rel} reads process.env inside a test harness.` : `${rel} reads process.env directly, which can hide configuration contracts.`, file, matchingLines(executableContent, /\bprocess\.env\b/), inTest ? "Keep test environment dependencies explicit and deterministic." : "Centralize environment parsing and validation behind a typed config boundary.", false)];
}

function childProcessFindings(file: string, rel: string, zone: IntentZone, executableContent: string): VantageFinding[] {
  const pattern = /\b(child_process|execSync|execFileSync|spawnSync|exec\s*\(|execFile\s*\(|spawn\s*\()/m;
  if (!pattern.test(executableContent)) return [];
  const inTest = zone !== "runtime";
  const constrainedSystemBridge = rel === "src/luna/launchAgent.ts";
  return [finding(
    inTest ? "low" : constrainedSystemBridge ? "medium" : "high",
    inTest ? "test_risk" : "security",
    constrainedSystemBridge ? "Constrained system command bridge" : "Child process usage",
    inTest ? `${rel} invokes child process APIs from a test harness.` : constrainedSystemBridge ? `${rel} invokes launchctl through a narrow LaunchAgent boundary.` : `${rel} invokes child process APIs that need strict input boundaries.`,
    file,
    matchingLines(executableContent, pattern),
    inTest ? "Keep command arguments deterministic and avoid relying on prebuilt artifacts." : constrainedSystemBridge ? "Keep the command allowlisted, argument-shaped, and covered by install/uninstall tests." : "Validate all command inputs and prefer narrow execFile-style calls.",
    false
  )];
}

function dynamicExecutionFindings(file: string, rel: string, zone: IntentZone, executableContent: string): VantageFinding[] {
  const pattern = /\beval\s*\(|\bnew\s+Function\s*\(/;
  if (!pattern.test(executableContent)) return [];
  const inTest = zone !== "runtime";
  const severity = zone === "benchmark" ? "low" : inTest ? "medium" : "critical";
  return [finding(severity, inTest ? "test_risk" : "security", "Dynamic code execution", inTest ? `${rel} exercises dynamic code execution in a test path.` : `${rel} uses eval or new Function.`, file, findingCluster(matchingLines(executableContent, pattern), 2), inTest ? "Keep dynamic execution isolated to fixtures and assert it cannot ship in runtime paths." : "Replace dynamic execution with a parser, interpreter, or explicit dispatch table.", false)];
}

function nosqlWhereFindings(file: string, rel: string, zone: IntentZone, content: string): VantageFinding[] {
  if (isSecurityNoisePath(rel)) return [];
  const lines = matchingLines(content, /\$where\s*:\s*(?:`|'[^']*'\s*\+|"[^"]*"\s*\+)/);
  if (lines.length === 0) return [];
  const inTest = zone !== "runtime";
  return [finding(inTest ? "low" : "high", inTest ? "test_risk" : "security", "NoSQL $where injection", `${rel} builds a MongoDB $where predicate from executable string content.`, file, lines, inTest ? "Keep intentionally vulnerable fixtures isolated from runtime paths." : "Replace $where string execution with structured Mongo query operators and validated inputs.", false)];
}

function hardcodedSecretFindings(file: string, rel: string, zone: IntentZone, content: string): VantageFinding[] {
  if (isSecurityNoisePath(rel)) return [];
  const secretLines = [
    ...matchingLines(content, /BEGIN [A-Z ]*PRIVATE KEY/),
    ...matchingLines(content, /createHmac\s*\(\s*['"][^'"]+['"]\s*,\s*['"][^'"]{8,}['"]\s*\)/)
  ];
  if (secretLines.length === 0) return [];
  const inTest = zone !== "runtime";
  return [finding(inTest ? "low" : "high", inTest ? "test_risk" : "security", "Hardcoded secret material", `${rel} embeds key material or cryptographic secret literals.`, file, [...new Set(secretLines)], inTest ? "Keep benchmark or fixture secrets synthetic and isolated." : "Move secrets to a validated runtime secret provider and rotate exposed material.", false)];
}

function jsonParseBoundaryFindings(file: string, rel: string, zone: IntentZone, content: string): VantageFinding[] {
  if (zone !== "runtime" || isSecurityNoisePath(rel)) return [];
  if (!isRouteBoundaryPath(rel)) return [];
  const lines = findingCluster(matchingLines(content, /\bJSON\.parse\s*\(/), 1);
  if (lines.length === 0) return [];
  const inTest = zone !== "runtime";
  return [finding(inTest ? "low" : "medium", inTest ? "test_risk" : "correctness", "JSON.parse without local boundary", `${rel} parses JSON without a locally verified error boundary.`, file, lines, inTest ? "Keep parser-crash fixtures covered by explicit benchmark expectations." : "Wrap JSON parsing in a narrow try/catch or validation boundary that returns a controlled error.", true)];
}

function dynamicRegexFindings(file: string, rel: string, zone: IntentZone, content: string): VantageFinding[] {
  if (zone !== "runtime" || isSecurityNoisePath(rel)) return [];
  const lines = findingCluster(matchingLines(content, /\bnew\s+RegExp\s*\(\s*(?!['"][^'"]+['"]\s*\))/), 1);
  if (lines.length === 0) return [];
  const inTest = zone !== "runtime";
  return [finding(inTest ? "low" : "medium", inTest ? "test_risk" : "security", "Dynamic regular expression", `${rel} constructs a RegExp from non-literal input.`, file, lines, inTest ? "Keep ReDoS fixtures isolated from runtime paths." : "Constrain dynamic regex input or replace it with explicit string matching.", false)];
}

function destructiveFsFindings(file: string, rel: string, zone: IntentZone, executableContent: string): VantageFinding[] {
  const pattern = /\b(?:rmSync|rmdirSync|unlinkSync)\s*\(/;
  if (zone !== "runtime" || !pattern.test(executableContent)) return [];
  const constrainedLaunchAgentCleanup = rel === "src/luna/launchAgent.ts";
  return [finding(
    constrainedLaunchAgentCleanup ? "medium" : "high",
    "security",
    constrainedLaunchAgentCleanup ? "Constrained LaunchAgent cleanup" : "Destructive fs call outside tests",
    constrainedLaunchAgentCleanup ? `${rel} removes only the computed LUNA LaunchAgent plist.` : `${rel} uses synchronous destructive filesystem APIs outside a test path.`,
    file,
    matchingLines(executableContent, pattern),
    constrainedLaunchAgentCleanup ? "Keep the target path derived from lunaLaunchAgentPath and covered by uninstall tests." : "Guard destructive file operations behind explicit path validation and dry-run tests.",
    false
  )];
}

function findingCluster(lines: string[], maxPerFile: number): string[] {
  return lines.slice(0, maxPerFile);
}

function isSecurityNoisePath(rel: string): boolean {
  return /(^|\/)(vendor|vendors|third[_-]?party|node_modules)(\/|$)/.test(rel) ||
    /\.min\.[cm]?js$/i.test(rel) ||
    rel.startsWith("frontend/") ||
    rel.startsWith("test/") ||
    rel.startsWith("tests/");
}

function isRouteBoundaryPath(rel: string): boolean {
  return /(^|\/)(routes?|controllers?|handlers?|api)(\/|$)/.test(rel);
}

function stripNonExecutableText(content: string): string {
  return content
    .replace(/`(?:\\.|[^`\\])*`/gs, " ")
    .replace(/"(?:\\.|[^"\\])*"/g, " ")
    .replace(/'(?:\\.|[^'\\])*'/g, " ")
    .replace(/`(?:\\.|[^`\\])*`/gs, " ")
    .replace(/"(?:\\.|[^"\\])*"/g, " ")
    .replace(/'(?:\\.|[^'\\])*'/g, " ")
    .replace(/\/(?:\\.|[^/\\\r\n])+\/[dgimsuvy]*/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/.*$/gm, "$1 ");
}

function stripComments(content: string): string {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/.*$/gm, "$1 ");
}

function isModuleCodeFile(file: string): boolean {
  return [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].includes(extension(file)) && !file.endsWith(".d.ts");
}

function extractImportSpecifiers(content: string): string[] {
  const specifiers: string[] = [];
  const importExportPattern = /\b(?:import|export)\s+(?:type\s+)?(?:[^'"]*?\s+from\s+)?["']([^"']+)["']/g;
  const requirePattern = /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g;
  const dynamicImportPattern = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
  for (const pattern of [importExportPattern, requirePattern, dynamicImportPattern]) {
    for (const match of content.matchAll(pattern)) {
      if (match[1]) {
        specifiers.push(match[1]);
      }
    }
  }
  return specifiers.sort();
}

function resolveImport(fromFile: string, specifier: string, knownModules: Set<string>): string | null {
  const base = resolve(dirname(fromFile), specifier);
  const baseWithoutModuleExtension = base.replace(/\.[cm]?[jt]sx?$/, "");
  const candidates = [
    base,
    baseWithoutModuleExtension,
    ...[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].map((ext) => `${baseWithoutModuleExtension}${ext}`),
    ...[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].map((ext) => `${base}${ext}`),
    ...[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].map((ext) => join(base, `index${ext}`)),
    ...[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].map((ext) => join(baseWithoutModuleExtension, `index${ext}`))
  ];
  return candidates.find((candidate) => knownModules.has(candidate)) ?? null;
}

function detectCycles(graph: Map<string, string[]>): string[][] {
  const cycles = new Map<string, string[]>();
  const nodes = [...graph.keys()].sort();
  for (const node of nodes) {
    visitCycleNode(graph, node, [], new Set(), cycles);
  }
  return [...cycles.values()].sort((a, b) => a.join("\0").localeCompare(b.join("\0")));
}

function visitCycleNode(graph: Map<string, string[]>, node: string, stack: string[], pathSet: Set<string>, cycles: Map<string, string[]>): void {
  const existingIndex = stack.indexOf(node);
  if (existingIndex >= 0) {
    const cycle = stack.slice(existingIndex);
    cycles.set(canonicalCycleKey(cycle), [...cycle, cycle[0]!]);
    return;
  }
  if (pathSet.has(node) || stack.length > 40) {
    return;
  }
  const nextPathSet = new Set(pathSet);
  nextPathSet.add(node);
  const nextStack = [...stack, node];
  for (const dep of graph.get(node) ?? []) {
    visitCycleNode(graph, dep, nextStack, nextPathSet, cycles);
  }
}

function canonicalCycleKey(cycle: string[]): string {
  if (cycle.length === 0) {
    return "";
  }
  const rotations = cycle.map((_, index) => [...cycle.slice(index), ...cycle.slice(0, index)].join("\0"));
  return rotations.sort()[0]!;
}

function moduleLabel(rootPath: string, file: string): string {
  return relative(rootPath, file).replaceAll("\\", "/").replace(/\.[cm]?[jt]sx?$/, "");
}

function findFunctionSpans(content: string): Array<{ name: string; start_line: number; end_line: number; line_count: number }> {
  const rawLines = content.split(/\r?\n/);
  const declarations = rawLines
    .map((line, index) => ({ name: functionNameFromLine(line), line: index + 1 }))
    .filter((item): item is { name: string; line: number } => Boolean(item.name));
  const spans: Array<{ name: string; start_line: number; end_line: number; line_count: number }> = [];
  for (const [index, declaration] of declarations.entries()) {
    const nextDeclaration = declarations[index + 1];
    const startLine = declaration.line;
    const endLine = nextDeclaration ? nextDeclaration.line - 1 : rawLines.length;
    spans.push({
      name: declaration.name,
      start_line: startLine,
      end_line: endLine,
      line_count: endLine - startLine + 1
    });
  }
  return spans;
}

function functionNameFromLine(line: string): string | null {
  return (
    line.match(/^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/)?.[1] ??
    line.match(/^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{/)?.[1] ??
    null
  );
}

function intentZone(rootPath: string, file: string): IntentZone {
  const rel = relative(rootPath, file).replaceAll("\\", "/");
  if (isTestPath(rootPath, file)) return "test";
  if (/(^|\/)(benchmarks?|corpus|fixtures?|test-target|samples?|vantage-bench)(\/|$)/.test(rel)) return "benchmark";
  if (/(^|\/)(catalog|rules?|patterns?)(\/|$)/.test(rel)) return "catalog";
  if (/(^|\/)(dist|build|generated|coverage)(\/|$)/.test(rel) || /\.generated\./.test(rel)) return "generated";
  if (/(^|\/)(scripts?|bin|hooks?|\.github)(\/|$)/.test(rel)) return "tooling";
  return "runtime";
}

function isContainedIntent(rootPath: string, file: string): boolean {
  return ["benchmark", "catalog", "generated", "test"].includes(intentZone(rootPath, file));
}

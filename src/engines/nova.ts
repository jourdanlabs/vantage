// NOVA — Causal Analysis & Dependency Graph Engine
// Builds the dependency graph, finds circular deps, tight coupling, god modules

import * as path from 'path';
import { MeteorOutput, NovaOutput, CausalChain, CircularDep, CouplingIssue, GodModule } from '../types';
import { LANGUAGE_REGISTRY } from '../languages';

// Build normalisation regex and import extensions from the registry (once at startup)
const ALL_EXTENSIONS: string[] = LANGUAGE_REGISTRY.flatMap(l => l.extensions);
// Escape dots, join as alternation for the strip regex
const EXT_PATTERN = ALL_EXTENSIONS.map(e => e.replace('.', '\\.')).join('|');
const STRIP_EXT_RE = new RegExp(`(${EXT_PATTERN})$`);

// All extensions to probe when resolving bare import paths
const IMPORT_PROBE_EXTS: string[] = [
  '',
  ...new Set(LANGUAGE_REGISTRY.flatMap(l => l.importExtensions)),
  '/index.ts',
  '/index.js',
];

function resolveImportPath(fromFile: string, importSource: string): string | null {
  if (!importSource.startsWith('.')) return null; // external dep

  const dir = path.dirname(fromFile);
  const resolved = path.resolve(dir, importSource);

  // Return first probe candidate (we can't stat without fs here)
  for (const ext of IMPORT_PROBE_EXTS) {
    const candidate = resolved + ext;
    return normalizeFilePath(candidate);
  }
  return normalizeFilePath(resolved);
}

function normalizeFilePath(filePath: string): string {
  return filePath.replace(STRIP_EXT_RE, '');
}

function detectCircularDeps(graph: Record<string, string[]>): CircularDep[] {
  const cycles: CircularDep[] = [];
  const visited = new Set<string>();
  const inStack = new Set<string>();

  function dfs(node: string, stack: string[]): boolean {
    visited.add(node);
    inStack.add(node);

    const neighbors = graph[node] || [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        if (dfs(neighbor, [...stack, neighbor])) return true;
      } else if (inStack.has(neighbor)) {
        // Found cycle
        const cycleStart = stack.indexOf(neighbor);
        const cycle = cycleStart >= 0
          ? [...stack.slice(cycleStart), neighbor]
          : [...stack, neighbor];
        cycles.push({
          cycle,
          description: `Circular dependency: ${cycle.map(c => path.basename(c)).join(' → ')}`
        });
        return false; // don't propagate, just record
      }
    }

    inStack.delete(node);
    return false;
  }

  for (const node of Object.keys(graph)) {
    if (!visited.has(node)) {
      dfs(node, [node]);
    }
  }

  return cycles;
}

function buildCausalChains(
  circularDeps: CircularDep[],
  couplingIssues: CouplingIssue[],
  godModules: GodModule[]
): CausalChain[] {
  const chains: CausalChain[] = [];

  for (const circ of circularDeps) {
    const fileNames = circ.cycle.map(c => path.basename(c));
    chains.push({
      root: circ.cycle[0],
      chain: [
        `${fileNames[0]} imports ${fileNames[1] || fileNames[0]}`,
        `${fileNames[fileNames.length - 1]} imports back to ${fileNames[0]}`,
        'Creates initialization deadlock risk and unpredictable load order'
      ],
      impact: `Circular dependency across ${circ.cycle.length} modules — may cause runtime errors or stale state`,
      severity: 'HIGH'
    });
  }

  for (const coupling of couplingIssues) {
    const baseName = path.basename(coupling.file);
    chains.push({
      root: coupling.file,
      chain: [
        `${baseName} is imported by ${coupling.count} other modules`,
        `Any change to ${baseName} cascades to ${coupling.count} dependents`,
        'High risk of regression on modification'
      ],
      impact: `Tight coupling: ${baseName} is a shared dependency hub — changes are high-blast-radius`,
      severity: coupling.count > 8 ? 'HIGH' : 'MED'
    });
  }

  for (const god of godModules) {
    const baseName = path.basename(god.file);
    chains.push({
      root: god.file,
      chain: [
        `${baseName} has ${god.lines} lines and ${god.exportCount} exports`,
        'God modules accumulate responsibilities over time',
        'Single responsibility violation — testing, change isolation both suffer'
      ],
      impact: `God module: ${baseName} violates single responsibility and is hard to test or refactor`,
      severity: 'MED'
    });
  }

  return chains;
}

export async function runNOVA(meteor: MeteorOutput, onProgress?: (msg: string) => void): Promise<NovaOutput> {
  onProgress?.('building dependency graph');

  // Build dependency graph: normalized file -> [normalized files it imports]
  const depGraph: Record<string, string[]> = {};

  // Initialize all known files
  for (const file of meteor.files) {
    const normKey = normalizeFilePath(file.path);
    depGraph[normKey] = [];
  }

  // Populate edges from imports
  for (const imp of meteor.imports) {
    if (!imp.isRelative) continue;

    const fromNorm = normalizeFilePath(imp.file);
    const resolved = resolveImportPath(imp.file, imp.source);
    if (!resolved) continue;

    const toNorm = normalizeFilePath(resolved);

    // Only track edges to known files (in our codebase)
    const knownFiles = Object.keys(depGraph);
    const matchedFile = knownFiles.find(k => k === toNorm || k.endsWith(toNorm) || toNorm.endsWith(k));

    if (matchedFile) {
      if (!depGraph[fromNorm]) depGraph[fromNorm] = [];
      if (!depGraph[fromNorm].includes(matchedFile)) {
        depGraph[fromNorm].push(matchedFile);
      }
    }
  }

  onProgress?.('detecting circular dependencies');
  const circularDeps = detectCircularDeps(depGraph);

  onProgress?.('finding coupling issues');
  // Build reverse graph: who imports each file
  const reverseGraph: Record<string, string[]> = {};
  for (const [fromFile, toFiles] of Object.entries(depGraph)) {
    for (const toFile of toFiles) {
      if (!reverseGraph[toFile]) reverseGraph[toFile] = [];
      reverseGraph[toFile].push(fromFile);
    }
  }

  const couplingIssues: CouplingIssue[] = [];
  for (const [file, importedBy] of Object.entries(reverseGraph)) {
    if (importedBy.length > 4) { // imported by 5+ others
      couplingIssues.push({
        file,
        importedBy,
        count: importedBy.length,
        description: `${path.basename(file)} is imported by ${importedBy.length} modules — high coupling`
      });
    }
  }

  onProgress?.('identifying god modules');
  const godModules: GodModule[] = [];
  for (const file of meteor.files) {
    if (file.lines > 500) {
      // Count exports in this file
      const exportMatches = file.content.match(/\bexport\b/g) || [];
      if (exportMatches.length > 8) {
        godModules.push({
          file: file.path,
          lines: file.lines,
          exportCount: exportMatches.length,
          description: `${file.relativePath} — ${file.lines} lines, ${exportMatches.length} exports (god module)`
        });
      }
    }
  }

  onProgress?.(`${circularDeps.length} circular deps, ${couplingIssues.length} coupling issues, ${godModules.length} god modules`);

  const causalChains = buildCausalChains(circularDeps, couplingIssues, godModules);

  return {
    causalChains,
    dependencyGraph: depGraph,
    circularDeps,
    couplingIssues,
    godModules
  };
}

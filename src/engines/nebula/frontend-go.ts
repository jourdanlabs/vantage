// NEBULA Go frontend — dispatches to the Python-side subset lowerer.
// Go adds a catalog + frontend. Do not add a fourth analyzer guard.
// DEV: go-quicktest. Sealed hold-out: go-normal/gin — do not score.

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ModuleIR } from './ir';
import { analyzeModule, AnalyzerCatalog, TaintFinding } from './analyzer';
import {
  GO_SOURCES,
  GO_SINKS,
  GO_SANITIZERS,
  matchGoSinkExtra,
  matchGoSanitizerExtra,
  matchGoCallSourceExtra,
  GO_CATALOG_EXTRAS,
} from './catalog/go';

export const GO_CATALOG: AnalyzerCatalog = {
  sources: GO_SOURCES,
  sinks: GO_SINKS,
  sanitizers: GO_SANITIZERS,
  matchSinkExtra: matchGoSinkExtra,
  matchSanitizerExtra: matchGoSanitizerExtra,
  matchCallSourceExtra: matchGoCallSourceExtra,
  extras: GO_CATALOG_EXTRAS,
};

export function analyzeGoModules(modules: ModuleIR[]): TaintFinding[] {
  const findings: TaintFinding[] = [];
  for (const module of modules) {
    findings.push(...analyzeModule(module, GO_CATALOG));
  }
  return findings;
}

export interface GoFrontendResult {
  modules: ModuleIR[];
  errors: string[];
}

function devSrc(): string {
  return path.join(__dirname, '..', '..', '..', 'src');
}

export function goFrontendAvailable(): boolean {
  try {
    const r = spawnSync(
      'python3',
      ['-c', 'import vantage.nebula_frontend_go'],
      {
        env: { ...process.env, PYTHONPATH: devSrc() + ':' + (process.env.PYTHONPATH || '') },
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 4000,
      }
    );
    return r.status === 0;
  } catch {
    return false;
  }
}

const GO_BATCH = 2000;

export function lowerGoFiles(files: string[]): GoFrontendResult {
  if (!files.length) return { modules: [], errors: [] };
  const modules: ModuleIR[] = [];
  const errors: string[] = [];
  for (let i = 0; i < files.length; i += GO_BATCH) {
    const chunk = files.slice(i, i + GO_BATCH);
    const result = spawnSync(
      'python3',
      ['-m', 'vantage.nebula_frontend_go', '--batch'],
      {
        input: chunk.join('\n') + '\n',
        encoding: 'utf8',
        maxBuffer: 256 * 1024 * 1024,
        env: { ...process.env, PYTHONPATH: devSrc() + ':' + (process.env.PYTHONPATH || '') },
        timeout: 300_000,
      }
    );
    if (result.error) {
      errors.push(`go frontend spawn error: ${result.error.message}`);
      continue;
    }
    if (result.status !== 0) {
      errors.push(
        `go frontend exited ${result.status} on batch ${i}: ${(result.stderr || '').slice(0, 500)}`
      );
      continue;
    }
    errors.push(...(result.stderr || '').split('\n').filter(Boolean).map(l => `go: ${l}`));
    try {
      modules.push(...(JSON.parse(result.stdout) as ModuleIR[]));
    } catch (err: unknown) {
      errors.push('go frontend malformed JSON on batch ' + i + ': ' + (err as Error).message);
    }
  }
  return { modules, errors };
}

export function findGoFiles(dir: string): string[] {
  const SKIP = new Set([
    'node_modules', '.git', 'dist', 'build', 'vendor', '__pycache__', '.venv',
  ]);
  const SKIP_BASE = new Set(['shared.go', 'routes.go', 'routes_unix.go']);
  const out: string[] = [];
  function walk(d: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (SKIP.has(e.name)) continue;
        walk(full);
      } else if (e.isFile() && e.name.endsWith('.go')) {
        if (SKIP_BASE.has(e.name)) continue;
        out.push(full);
      }
    }
  }
  walk(dir);
  return out;
}

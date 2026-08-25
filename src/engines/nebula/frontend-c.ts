// NEBULA C frontend — dispatches to the Python-side raw-source lowerer.
// C adds a catalog + frontend. Do not add a fourth analyzer guard.

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ModuleIR } from './ir';
import { analyzeModule, AnalyzerCatalog, TaintFinding } from './analyzer';
import {
  C_SOURCES,
  C_SINKS,
  C_SANITIZERS,
  matchCSinkExtra,
  matchCSanitizerExtra,
  matchCCallSourceExtra,
  C_CATALOG_EXTRAS,
} from './catalog/c';

export const C_CATALOG: AnalyzerCatalog = {
  sources: C_SOURCES,
  sinks: C_SINKS,
  sanitizers: C_SANITIZERS,
  matchSinkExtra: matchCSinkExtra,
  matchSanitizerExtra: matchCSanitizerExtra,
  matchCallSourceExtra: matchCCallSourceExtra,
  extras: C_CATALOG_EXTRAS,
};

export function analyzeCModules(modules: ModuleIR[]): TaintFinding[] {
  const findings: TaintFinding[] = [];
  for (const module of modules) {
    findings.push(...analyzeModule(module, C_CATALOG));
  }
  return findings;
}

export interface CFrontendResult {
  modules: ModuleIR[];
  errors: string[];
}

function devSrc(): string {
  return path.join(__dirname, '..', '..', '..', 'src');
}

export function cFrontendAvailable(): boolean {
  try {
    const r = spawnSync(
      'python3',
      ['-c', 'import vantage.nebula_frontend_c'],
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

const C_BATCH = 2000;

export function lowerCFiles(files: string[]): CFrontendResult {
  if (!files.length) return { modules: [], errors: [] };
  const modules: ModuleIR[] = [];
  const errors: string[] = [];
  for (let i = 0; i < files.length; i += C_BATCH) {
    const chunk = files.slice(i, i + C_BATCH);
    const result = spawnSync(
      'python3',
      ['-m', 'vantage.nebula_frontend_c', '--batch'],
      {
        input: chunk.join('\n') + '\n',
        encoding: 'utf8',
        maxBuffer: 256 * 1024 * 1024,
        env: { ...process.env, PYTHONPATH: devSrc() + ':' + (process.env.PYTHONPATH || '') },
        timeout: 300_000,
      }
    );
    if (result.status !== 0) {
      errors.push(
        `c frontend exited ${result.status} on batch ${i}: ${(result.stderr || '').slice(0, 500)}`
      );
      continue;
    }
    errors.push(...(result.stderr || '').split('\n').filter(Boolean).map(l => `c: ${l}`));
    try {
      modules.push(...(JSON.parse(result.stdout) as ModuleIR[]));
    } catch (err: unknown) {
      errors.push('c frontend malformed JSON on batch ' + i + ': ' + (err as Error).message);
    }
  }
  return { modules, errors };
}

export function findCFiles(dir: string): string[] {
  const SKIP = new Set([
    'node_modules', '.git', 'dist', 'build', 'target', '__pycache__', '.venv',
  ]);
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
      } else if (e.isFile() && e.name.endsWith('.c')) {
        out.push(full);
      }
    }
  }
  walk(dir);
  return out;
}

// NEBULA PHP frontend — dispatches to the Python-side subset lowerer.
// PHP adds a catalog + frontend. Do not add a fourth analyzer guard.

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ModuleIR } from './ir';
import { analyzeModule, AnalyzerCatalog, TaintFinding } from './analyzer';
import {
  PHP_SOURCES,
  PHP_SINKS,
  PHP_SANITIZERS,
  matchPhpSinkExtra,
  matchPhpSanitizerExtra,
  matchPhpCallSourceExtra,
  PHP_CATALOG_EXTRAS,
} from './catalog/php';

export const PHP_CATALOG: AnalyzerCatalog = {
  sources: PHP_SOURCES,
  sinks: PHP_SINKS,
  sanitizers: PHP_SANITIZERS,
  matchSinkExtra: matchPhpSinkExtra,
  matchSanitizerExtra: matchPhpSanitizerExtra,
  matchCallSourceExtra: matchPhpCallSourceExtra,
  extras: PHP_CATALOG_EXTRAS,
};

export function analyzePhpModules(modules: ModuleIR[]): TaintFinding[] {
  const findings: TaintFinding[] = [];
  for (const module of modules) {
    findings.push(...analyzeModule(module, PHP_CATALOG));
  }
  return findings;
}

export interface PhpFrontendResult {
  modules: ModuleIR[];
  errors: string[];
}

function devSrc(): string {
  return path.join(__dirname, '..', '..', '..', 'src');
}

export function phpFrontendAvailable(): boolean {
  try {
    const r = spawnSync(
      'python3',
      ['-c', 'import vantage.nebula_frontend_php'],
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

const PHP_BATCH = 2000;

export function lowerPhpFiles(files: string[]): PhpFrontendResult {
  if (!files.length) return { modules: [], errors: [] };
  const modules: ModuleIR[] = [];
  const errors: string[] = [];
  for (let i = 0; i < files.length; i += PHP_BATCH) {
    const chunk = files.slice(i, i + PHP_BATCH);
    const result = spawnSync(
      'python3',
      ['-m', 'vantage.nebula_frontend_php', '--batch'],
      {
        input: chunk.join('\n') + '\n',
        encoding: 'utf8',
        maxBuffer: 256 * 1024 * 1024,
        env: { ...process.env, PYTHONPATH: devSrc() + ':' + (process.env.PYTHONPATH || '') },
        timeout: 300_000,
      }
    );
    if (result.error) {
      errors.push(`php frontend spawn error: ${result.error.message}`);
      continue;
    }
    if (result.status !== 0) {
      errors.push(
        `php frontend exited ${result.status} on batch ${i}: ${(result.stderr || '').slice(0, 500)}`
      );
      continue;
    }
    errors.push(...(result.stderr || '').split('\n').filter(Boolean).map(l => `php: ${l}`));
    try {
      modules.push(...(JSON.parse(result.stdout) as ModuleIR[]));
    } catch (err: unknown) {
      errors.push('php frontend malformed JSON on batch ' + i + ': ' + (err as Error).message);
    }
  }
  return { modules, errors };
}

export function findPhpFiles(dir: string): string[] {
  const SKIP = new Set([
    'node_modules', '.git', 'dist', 'build', 'vendor', '__pycache__', '.venv',
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
      } else if (e.isFile() && e.name.endsWith('.php')) {
        out.push(full);
      }
    }
  }
  walk(dir);
  return out;
}

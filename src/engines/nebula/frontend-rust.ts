// NEBULA Rust frontend — dispatches to the Python-side raw-source lowerer.
// Rust adds a catalog + frontend. Do not add a fourth analyzer guard.
// Parser decision: receipts/sealed-holdout/rust-v1-normal-actix-web-2026-08-20/RECEIPT.md §2a.

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ModuleIR } from './ir';
import { analyzeModule, AnalyzerCatalog, TaintFinding } from './analyzer';
import {
  RUST_SOURCES,
  RUST_SINKS,
  RUST_SANITIZERS,
  matchRustSinkExtra,
  matchRustSanitizerExtra,
  matchRustCallSourceExtra,
  RUST_CATALOG_EXTRAS,
} from './catalog/rust';

export const RUST_CATALOG: AnalyzerCatalog = {
  sources: RUST_SOURCES,
  sinks: RUST_SINKS,
  sanitizers: RUST_SANITIZERS,
  matchSinkExtra: matchRustSinkExtra,
  matchSanitizerExtra: matchRustSanitizerExtra,
  matchCallSourceExtra: matchRustCallSourceExtra,
  extras: RUST_CATALOG_EXTRAS,
};

export function analyzeRustModules(modules: ModuleIR[]): TaintFinding[] {
  const findings: TaintFinding[] = [];
  for (const module of modules) {
    findings.push(...analyzeModule(module, RUST_CATALOG));
  }
  return findings;
}

export interface RustFrontendResult {
  modules: ModuleIR[];
  errors: string[];
}

function devSrc(): string {
  return path.join(__dirname, '..', '..', '..', 'src');
}

export function rustFrontendAvailable(): boolean {
  try {
    const r = spawnSync(
      'python3',
      ['-c', 'import vantage.nebula_frontend_rust'],
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

const RUST_BATCH = 2000;

export function lowerRustFiles(files: string[]): RustFrontendResult {
  if (!files.length) return { modules: [], errors: [] };
  const modules: ModuleIR[] = [];
  const errors: string[] = [];
  for (let i = 0; i < files.length; i += RUST_BATCH) {
    const chunk = files.slice(i, i + RUST_BATCH);
    const result = spawnSync(
      'python3',
      ['-m', 'vantage.nebula_frontend_rust', '--batch'],
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
        `rust frontend exited ${result.status} on batch ${i}: ${(result.stderr || '').slice(0, 500)}`
      );
      continue;
    }
    errors.push(...(result.stderr || '').split('\n').filter(Boolean).map(l => `rust: ${l}`));
    try {
      modules.push(...(JSON.parse(result.stdout) as ModuleIR[]));
    } catch (err: unknown) {
      errors.push('rust frontend malformed JSON on batch ' + i + ': ' + (err as Error).message);
    }
  }
  return { modules, errors };
}

export function findRustFiles(dir: string): string[] {
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
      } else if (e.isFile() && e.name.endsWith('.rs')) {
        if (e.name === 'lib.rs' || e.name === 'shared.rs') continue;
        out.push(full);
      }
    }
  }
  walk(dir);
  return out;
}

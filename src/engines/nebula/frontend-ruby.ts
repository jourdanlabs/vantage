// NEBULA Ruby frontend — dispatches to the Python-side subset lowerer.
// Ruby adds a catalog + frontend. Do not add a fourth analyzer guard.
// Parser decision: receipts/sealed-holdout/ruby-v1-normal-rails-2026-08-20/RECEIPT.md §2a.

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ModuleIR } from './ir';
import { analyzeModule, AnalyzerCatalog, TaintFinding } from './analyzer';
import {
  RUBY_SOURCES,
  RUBY_SINKS,
  RUBY_SANITIZERS,
  matchRubySinkExtra,
  matchRubySanitizerExtra,
  matchRubyCallSourceExtra,
  RUBY_CATALOG_EXTRAS,
} from './catalog/ruby';

export const RUBY_CATALOG: AnalyzerCatalog = {
  sources: RUBY_SOURCES,
  sinks: RUBY_SINKS,
  sanitizers: RUBY_SANITIZERS,
  matchSinkExtra: matchRubySinkExtra,
  matchSanitizerExtra: matchRubySanitizerExtra,
  matchCallSourceExtra: matchRubyCallSourceExtra,
  extras: RUBY_CATALOG_EXTRAS,
};

export function analyzeRubyModules(modules: ModuleIR[]): TaintFinding[] {
  const findings: TaintFinding[] = [];
  for (const module of modules) {
    findings.push(...analyzeModule(module, RUBY_CATALOG));
  }
  return findings;
}

export interface RubyFrontendResult {
  modules: ModuleIR[];
  errors: string[];
}

function devSrc(): string {
  return path.join(__dirname, '..', '..', '..', 'src');
}

export function rubyFrontendAvailable(): boolean {
  try {
    const r = spawnSync(
      'python3',
      ['-c', 'import vantage.nebula_frontend_ruby'],
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

const RUBY_BATCH = 2000;

export function lowerRubyFiles(files: string[]): RubyFrontendResult {
  if (!files.length) return { modules: [], errors: [] };
  const modules: ModuleIR[] = [];
  const errors: string[] = [];
  for (let i = 0; i < files.length; i += RUBY_BATCH) {
    const chunk = files.slice(i, i + RUBY_BATCH);
    const result = spawnSync(
      'python3',
      ['-m', 'vantage.nebula_frontend_ruby', '--batch'],
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
        `ruby frontend exited ${result.status} on batch ${i}: ${(result.stderr || '').slice(0, 500)}`
      );
      continue;
    }
    errors.push(...(result.stderr || '').split('\n').filter(Boolean).map(l => `ruby: ${l}`));
    try {
      modules.push(...(JSON.parse(result.stdout) as ModuleIR[]));
    } catch (err: unknown) {
      errors.push('ruby frontend malformed JSON on batch ' + i + ': ' + (err as Error).message);
    }
  }
  return { modules, errors };
}

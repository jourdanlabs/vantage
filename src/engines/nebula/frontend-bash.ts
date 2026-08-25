// NEBULA Bash frontend — dispatches to the Python-side raw-source lowerer.
// Bash adds a catalog + frontend. Do not add a fourth analyzer guard.
// Sealed hold-out: bash-normal — do not score.

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ModuleIR } from './ir';
import { analyzeModule, AnalyzerCatalog, TaintFinding } from './analyzer';
import {
  BASH_SOURCES,
  BASH_SINKS,
  BASH_SANITIZERS,
  matchBashSinkExtra,
  matchBashSanitizerExtra,
  matchBashCallSourceExtra,
  BASH_CATALOG_EXTRAS,
} from './catalog/bash';

export const BASH_CATALOG: AnalyzerCatalog = {
  sources: BASH_SOURCES,
  sinks: BASH_SINKS,
  sanitizers: BASH_SANITIZERS,
  matchSinkExtra: matchBashSinkExtra,
  matchSanitizerExtra: matchBashSanitizerExtra,
  matchCallSourceExtra: matchBashCallSourceExtra,
  extras: BASH_CATALOG_EXTRAS,
};

export function analyzeBashModules(modules: ModuleIR[]): TaintFinding[] {
  const findings: TaintFinding[] = [];
  for (const module of modules) {
    findings.push(...analyzeModule(module, BASH_CATALOG));
  }
  return findings;
}

export interface BashFrontendResult {
  modules: ModuleIR[];
  errors: string[];
}

function devSrc(): string {
  return path.join(__dirname, '..', '..', '..', 'src');
}

export function bashFrontendAvailable(): boolean {
  try {
    const r = spawnSync(
      'python3',
      ['-c', 'import vantage.nebula_frontend_bash'],
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

const BASH_BATCH = 2000;

export function lowerBashFiles(files: string[]): BashFrontendResult {
  if (!files.length) return { modules: [], errors: [] };
  const modules: ModuleIR[] = [];
  const errors: string[] = [];
  for (let i = 0; i < files.length; i += BASH_BATCH) {
    const chunk = files.slice(i, i + BASH_BATCH);
    const result = spawnSync(
      'python3',
      ['-m', 'vantage.nebula_frontend_bash', '--batch'],
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
        `bash frontend exited ${result.status} on batch ${i}: ${(result.stderr || '').slice(0, 500)}`
      );
      continue;
    }
    errors.push(...(result.stderr || '').split('\n').filter(Boolean).map(l => `bash: ${l}`));
    try {
      modules.push(...(JSON.parse(result.stdout) as ModuleIR[]));
    } catch (err: unknown) {
      errors.push('bash frontend malformed JSON on batch ' + i + ': ' + (err as Error).message);
    }
  }
  return { modules, errors };
}

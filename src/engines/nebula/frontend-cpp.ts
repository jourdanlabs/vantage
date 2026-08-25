// NEBULA C++ frontend. Catalog + frontend only. Same raw-source lowerer as C
// (std:: stripped at callee names). cpp-normal/standalone is sealed.

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ModuleIR } from './ir';
import { analyzeModule, AnalyzerCatalog, TaintFinding } from './analyzer';
import {
  CPP_SOURCES,
  CPP_SINKS,
  CPP_SANITIZERS,
  matchCppSinkExtra,
  matchCppSanitizerExtra,
  matchCppCallSourceExtra,
  CPP_CATALOG_EXTRAS,
} from './catalog/cpp';

export const CPP_CATALOG: AnalyzerCatalog = {
  sources: CPP_SOURCES,
  sinks: CPP_SINKS,
  sanitizers: CPP_SANITIZERS,
  matchSinkExtra: matchCppSinkExtra,
  matchSanitizerExtra: matchCppSanitizerExtra,
  matchCallSourceExtra: matchCppCallSourceExtra,
  extras: CPP_CATALOG_EXTRAS,
};

export function analyzeCppModules(modules: ModuleIR[]): TaintFinding[] {
  const findings: TaintFinding[] = [];
  for (const module of modules) {
    findings.push(...analyzeModule(module, CPP_CATALOG));
  }
  return findings;
}

export interface CppFrontendResult {
  modules: ModuleIR[];
  errors: string[];
}

function devSrc(): string {
  return path.join(__dirname, '..', '..', '..', 'src');
}

export function cppFrontendAvailable(): boolean {
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

const CPP_BATCH = 2000;

export function lowerCppFiles(files: string[]): CppFrontendResult {
  if (!files.length) return { modules: [], errors: [] };
  const modules: ModuleIR[] = [];
  const errors: string[] = [];
  for (let i = 0; i < files.length; i += CPP_BATCH) {
    const chunk = files.slice(i, i + CPP_BATCH);
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
        `cpp frontend exited ${result.status} on batch ${i}: ${(result.stderr || '').slice(0, 500)}`
      );
      continue;
    }
    errors.push(
      ...(result.stderr || '').split('\n').filter(Boolean).map(l => `cpp: ${l}`)
    );
    try {
      modules.push(...(JSON.parse(result.stdout) as ModuleIR[]));
    } catch (err: unknown) {
      errors.push('cpp frontend malformed JSON on batch ' + i + ': ' + (err as Error).message);
    }
  }
  return { modules, errors };
}

export function findCppFiles(dir: string): string[] {
  const SKIP = new Set(['node_modules', '.git', 'dist', 'build', 'target', '__pycache__', '.venv']);
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
      } else if (e.isFile() && /\.(cpp|cc|cxx)$/i.test(e.name)) {
        out.push(full);
      }
    }
  }
  walk(dir);
  return out;
}

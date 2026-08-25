// NEBULA Java frontend — dispatches to the Python-side javalang lowerer.
// Same IR as TS/Python. Java adds a catalog, not a third analyzer guard.

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ModuleIR } from './ir';
import { analyzeModule, AnalyzerCatalog, TaintFinding } from './analyzer';
import {
  JAVA_SOURCES,
  JAVA_SINKS,
  JAVA_SANITIZERS,
  matchJavaSinkExtra,
  matchJavaSanitizerExtra,
  JAVA_CATALOG_EXTRAS,
} from './catalog/java';

export const JAVA_CATALOG: AnalyzerCatalog = {
  sources: JAVA_SOURCES,
  sinks: JAVA_SINKS,
  sanitizers: JAVA_SANITIZERS,
  matchSinkExtra: matchJavaSinkExtra,
  matchSanitizerExtra: matchJavaSanitizerExtra,
  extras: JAVA_CATALOG_EXTRAS,
};

export function analyzeJavaModules(modules: ModuleIR[]): TaintFinding[] {
  const findings: TaintFinding[] = [];
  for (const module of modules) {
    findings.push(...analyzeModule(module, JAVA_CATALOG));
  }
  return findings;
}

export interface JavaFrontendResult {
  modules: ModuleIR[];
  errors: string[];
}

function devSrc(): string {
  return path.join(__dirname, '..', '..', '..', 'src');
}

export function javaFrontendAvailable(): boolean {
  try {
    const r = spawnSync(
      'python3',
      ['-c', 'import vantage.nebula_frontend_java, javalang'],
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

export function lowerJavaFiles(files: string[]): JavaFrontendResult {
  if (!files.length) return { modules: [], errors: [] };
  const result = spawnSync(
    'python3',
    ['-m', 'vantage.nebula_frontend_java', '--batch'],
    {
      input: files.join('\n') + '\n',
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
      env: { ...process.env, PYTHONPATH: devSrc() + ':' + (process.env.PYTHONPATH || '') },
      timeout: 300_000,
    }
  );
  if (result.error) {
    return {
      modules: [],
      errors: [
        `java frontend spawn error: ${result.error.message}`,
      ],
    };
  }
  if (result.status !== 0) {
    return {
      modules: [],
      errors: [
        `java frontend exited ${result.status}: ${(result.stderr || '').slice(0, 500)}`,
      ],
    };
  }
  const stderrNotes = (result.stderr || '')
    .split('\n')
    .filter(Boolean)
    .map(l => `java: ${l}`);
  try {
    const modules = JSON.parse(result.stdout) as ModuleIR[];
    return { modules, errors: stderrNotes };
  } catch (err: unknown) {
    return {
      modules: [],
      errors: [
        'java frontend produced malformed JSON: ' + (err as Error).message,
        ...stderrNotes,
      ],
    };
  }
}

export function findJavaFiles(dir: string): string[] {
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
      } else if (e.isFile() && e.name.endsWith('.java')) {
        out.push(full);
      }
    }
  }
  walk(dir);
  return out;
}

// NEBULA Python frontend — dispatches to the Python-side lowering script.
//
// We deliberately do NOT port the Python AST parser to JavaScript. Python's
// native `ast` module is the only parser guaranteed to match the language
// semantics exactly, and keeping the parser in Python means the rules ship
// alongside the `vantage-x` PyPI package — one source of truth for Python
// parsing, regardless of which end of the pipeline is invoked.
//
// Transport: we spawn `python3 -m vantage.nebula_frontend <files...>` and
// read a JSON array of ModuleIR dicts from stdout. The Python side writes
// the exact same IR shape the TypeScript frontend produces; the analyzer
// doesn't know or care which frontend generated the IR.
//
// If python3 or the vantage_x package isn't available, we gracefully skip
// Python files with a frontend note — the Node-side TS/JS analysis still
// runs on whatever else is in the tree.

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ModuleIR } from './ir';
import { analyzeModule, AnalyzerCatalog, TaintFinding } from './analyzer';
import {
  PYTHON_SOURCES,
  PYTHON_SINKS,
  PYTHON_SANITIZERS,
  matchPythonSinkExtra,
  matchPythonCallSourceExtra,
  PYTHON_CATALOG_EXTRAS,
} from './catalog/python';

/** Python-only catalog. Never pass this to JS/TS analyzeModule calls. */
export const PYTHON_CATALOG: AnalyzerCatalog = {
  sources: PYTHON_SOURCES,
  sinks: PYTHON_SINKS,
  sanitizers: PYTHON_SANITIZERS,
  matchSinkExtra: matchPythonSinkExtra,
  matchCallSourceExtra: matchPythonCallSourceExtra,
  extras: PYTHON_CATALOG_EXTRAS,
};

/** Analyze already-lowered Python IR against the Python catalog (not javascript.ts). */
export function analyzePythonModules(modules: ModuleIR[]): TaintFinding[] {
  const findings: TaintFinding[] = [];
  for (const module of modules) {
    findings.push(...analyzeModule(module, PYTHON_CATALOG));
  }
  return findings;
}

export interface PythonFrontendResult {
  modules: ModuleIR[];
  errors: string[];
}

export function pythonAvailable(): boolean {
  // Quick check — can we at least invoke `python3 -c "import vantage.nebula_frontend"`?
  // A bit more than just `which python3` because the Python user might have
  // Python installed but no vantage-x package, in which case we'd rather
  // gracefully degrade than fail with a confusing import error.
  try {
    const r = spawnSync('python3', ['-c', 'import vantage.nebula_frontend'], {
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 3000,
    });
    if (r.status === 0) return true;
  } catch {
    /* fall through */
  }
  // Try to auto-inject the repo's src/ onto PYTHONPATH as a dev-time fallback.
  // This is how the frontend works inside a monorepo checkout where
  // vantage-x hasn't been pip-installed yet.
  try {
    const devSrc = path.join(__dirname, '..', '..', '..', 'src');
    const r = spawnSync('python3', ['-c', 'import vantage.nebula_frontend'], {
      env: { ...process.env, PYTHONPATH: devSrc + ':' + (process.env.PYTHONPATH || '') },
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 3000,
    });
    return r.status === 0;
  } catch {
    return false;
  }
}

/**
 * Lower a batch of Python files to NEBULA IR.  Returns an array of
 * ModuleIR objects (one per file) plus any error messages from the
 * Python side that we want to surface as frontend notes.
 */
export function lowerPythonFiles(files: string[]): PythonFrontendResult {
  if (files.length === 0) return { modules: [], errors: [] };

  // Pipe the file list via stdin to avoid OS argv-length limits on big
  // projects.  `--batch` mode reads one file per line from stdin.
  const devSrc = path.join(__dirname, '..', '..', '..', 'src');
  const result = spawnSync(
    'python3',
    ['-m', 'vantage.nebula_frontend', '--batch'],
    {
      input: files.join('\n'),
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024, // 256 MB — big corpora can produce big IR
      env: { ...process.env, PYTHONPATH: devSrc + ':' + (process.env.PYTHONPATH || '') },
      timeout: 300_000,
    }
  );

  if (result.error) {
    return {
      modules: [],
      errors: [
        `python frontend spawn error: ${result.error.message} (code=${(result.error as NodeJS.ErrnoException).code})`,
      ],
    };
  }
  if (result.status !== 0) {
    return {
      modules: [],
      errors: [
        `python frontend exited ${result.status}: ${(result.stderr || '').slice(0, 500)}`,
      ],
    };
  }

  const stderrNotes = (result.stderr || '')
    .split('\n')
    .filter(Boolean)
    .map(l => `python: ${l}`);

  try {
    const modules = JSON.parse(result.stdout) as ModuleIR[];
    return { modules, errors: stderrNotes };
  } catch (err: unknown) {
    return {
      modules: [],
      errors: [
        'python frontend produced malformed JSON: ' + (err as Error).message,
        ...stderrNotes,
      ],
    };
  }
}

/** Walk a directory for .py source files. */
export function findPythonFiles(dir: string): string[] {
  const SKIP = new Set(['__pycache__', '.venv', 'venv', 'node_modules', '.git', 'dist', '.mypy_cache', '.pytest_cache', '.tox']);
  const out: string[] = [];
  function walk(d: string) {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (SKIP.has(e.name)) continue;
        walk(full);
      } else if (e.isFile() && e.name.endsWith('.py')) {
        out.push(full);
      }
    }
  }
  walk(dir);
  return out;
}

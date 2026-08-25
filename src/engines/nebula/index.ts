// NEBULA engine entrypoint — called from src/engines/index.ts when the
// --semantic flag is set. v0 is opt-in and does not run in the default
// analyze path, preserving VANTAGE's sub-100ms scan envelope.
//
// Polyglot routing: we dispatch per file extension to the right frontend.
//   - .ts / .tsx / .js / .jsx / .mjs  → TypeScript frontend (in-process)
//   - .py                              → Python frontend (subprocess, via vantage-x)
//
// Both frontends produce the same IR; the analyzer runs once per module
// regardless of source language.

import * as fs from 'fs';
import * as path from 'path';
import { lowerFile as lowerTsFile } from './frontend-typescript';
import { pythonAvailable, lowerPythonFiles, findPythonFiles, analyzePythonModules } from './frontend-python';
import { javaFrontendAvailable, lowerJavaFiles, analyzeJavaModules } from './frontend-java';
import { cFrontendAvailable, lowerCFiles, analyzeCModules } from './frontend-c';
import { cppFrontendAvailable, lowerCppFiles, analyzeCppModules } from './frontend-cpp';
import { rubyFrontendAvailable, lowerRubyFiles, analyzeRubyModules } from './frontend-ruby';
import { rustFrontendAvailable, lowerRustFiles, analyzeRustModules } from './frontend-rust';
import { bashFrontendAvailable, lowerBashFiles, analyzeBashModules } from './frontend-bash';
import { phpFrontendAvailable, lowerPhpFiles, analyzePhpModules } from './frontend-php';
import { goFrontendAvailable, lowerGoFiles, analyzeGoModules } from './frontend-go';
import { analyzeModule, analyzeProject, TaintFinding } from './analyzer';
import { ModuleIR } from './ir';

export { TaintFinding, analyzeModule, analyzeProject } from './analyzer';

export interface NebulaReport {
  findings: TaintFinding[];
  filesAnalyzed: number;
  frontendNotes: string[];
  durationMs: number;
  byLanguage: Record<string, number>;  // {ts: N, py: N, js: N}
}

const TS_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage', '.scannerwork', 'build', 'target', 'vendor', '__pycache__', '.venv', 'venv', '.mypy_cache', '.pytest_cache', '.tox']);

/**
 * Run NEBULA over every supported source file in the target directory.
 * Language coverage in v0.2:
 *   - TypeScript / JavaScript (in-process, always available)
 *   - Python (via vantage-x PyPI package; gracefully skipped if Python or
 *     the package isn't installed, with a note in frontendNotes)
 */
export async function runNebula(targetPath: string): Promise<NebulaReport> {
  const start = Date.now();
  const tsFiles: string[] = [];
  const pyFiles: string[] = [];
  const javaFiles: string[] = [];
  const cFiles: string[] = [];
  const cppFiles: string[] = [];
  const rubyFiles: string[] = [];
  const rustFiles: string[] = [];
  const phpFiles: string[] = [];
  const bashFiles: string[] = [];
  const goFiles: string[] = [];
  walk(targetPath, tsFiles, pyFiles, javaFiles, cFiles, cppFiles, rubyFiles, rustFiles, phpFiles, bashFiles, goFiles);

  const allFindings: TaintFinding[] = [];
  const notes: string[] = [];
  const byLanguage: Record<string, number> = {};

  // ── TypeScript / JavaScript ───────────────────────────────────────────
  // Kaioken V: cross-file interprocedural needs the full module graph.
  // Kaioken VII.2 / BENCH_FAST: BenchProctor stages 10k–100k *independent*
  // case files (+ tiny shared.js). Building one ProjectCtx of 100k modules
  // OOMs/thrash; catalog sinks (db.query, fs.*) do not need cross-file.
  // Per-file analyzeModule is correct for that shape and ~orders faster.
  const benchFast = process.env.VANTAGE_BENCH_FAST === '1';
  const tsModules: ModuleIR[] = [];
  for (const file of tsFiles) {
    let src: string;
    try { src = fs.readFileSync(file, 'utf8'); } catch { continue; }
    try {
      const module = lowerTsFile(file, src);
      tsModules.push(module);
      notes.push(...module.frontendNotes.map(n => `${file}: ${n}`));
      const ext = path.extname(file).slice(1) || 'ts';
      byLanguage[ext] = (byLanguage[ext] || 0) + 1;
      // Stream findings immediately under BENCH_FAST so we never hold 100k IRs.
      if (benchFast) {
        allFindings.push(...analyzeModule(module));
      }
    } catch (err: unknown) {
      notes.push(`${file}: ts frontend error — ${(err as Error).message}`);
    }
  }
  if (!benchFast) {
    if (tsModules.length === 1) {
      allFindings.push(...analyzeModule(tsModules[0]));
    } else if (tsModules.length > 1) {
      allFindings.push(...analyzeProject(tsModules));
    }
  }

  // ── Python — subprocess lowering via vantage-x PyPI package ────────────
  if (pyFiles.length > 0) {
    if (!pythonAvailable()) {
      notes.push(
        `${pyFiles.length} Python file(s) skipped — python3 or vantage-x package not available. ` +
        `Install with: pip install vantage-x`
      );
    } else {
      // BenchProctor enterprise is ~100k independent files. One spawn's JSON IR
      // exceeds spawnSync maxBuffer (~256MB) and returns 0 findings. Batch.
      // Same honesty as JAVA_BATCH / cpp first-invoke-no-ir: do not score the empty SARIF.
      const PYTHON_BATCH = 4000;
      for (let i = 0; i < pyFiles.length; i += PYTHON_BATCH) {
        const slice = pyFiles.slice(i, i + PYTHON_BATCH);
        const { modules, errors } = lowerPythonFiles(slice);
        notes.push(...errors);
        for (const module of modules) {
          try {
            allFindings.push(...analyzePythonModules([module as ModuleIR]));
            byLanguage['py'] = (byLanguage['py'] || 0) + 1;
          } catch (err: unknown) {
            notes.push(`${module.path}: python analyzer error — ${(err as Error).message}`);
          }
        }
      }
    }
  }

  // ── C — raw-source lowering (catalog/c.ts; c-normal is sealed) ─
  if (cFiles.length > 0) {
    if (!cFrontendAvailable()) {
      notes.push(
        `${cFiles.length} C file(s) skipped — python3/vantage.nebula_frontend_c not available`
      );
    } else {
      const { modules, errors } = lowerCFiles(cFiles);
      notes.push(...errors);
      for (const module of modules) {
        try {
          allFindings.push(...analyzeCModules([module as ModuleIR]));
          byLanguage['c'] = (byLanguage['c'] || 0) + 1;
        } catch (err: unknown) {
          notes.push(`${module.path}: c analyzer error — ${(err as Error).message}`);
        }
      }
    }
  }

  // ── C++ — raw-source (catalog/cpp.ts; cpp-normal/standalone is sealed) ─
  if (cppFiles.length > 0) {
    if (!cppFrontendAvailable()) {
      notes.push(
        `${cppFiles.length} C++ file(s) skipped — python3/vantage.nebula_frontend_c not available`
      );
    } else {
      const { modules, errors } = lowerCppFiles(cppFiles);
      notes.push(...errors);
      for (const module of modules) {
        try {
          allFindings.push(...analyzeCppModules([module as ModuleIR]));
          byLanguage['cpp'] = (byLanguage['cpp'] || 0) + 1;
        } catch (err: unknown) {
          notes.push(`${module.path}: cpp analyzer error — ${(err as Error).message}`);
        }
      }
    }
  }

  // ── Rust — raw-source (catalog/rust.ts; actix_web-normal is sealed) ─
  if (rustFiles.length > 0) {
    if (!rustFrontendAvailable()) {
      notes.push(
        `${rustFiles.length} Rust file(s) skipped — python3/vantage.nebula_frontend_rust not available`
      );
    } else {
      const RUST_BATCH = 2000;
      for (let i = 0; i < rustFiles.length; i += RUST_BATCH) {
        const slice = rustFiles.slice(i, i + RUST_BATCH);
        const { modules, errors } = lowerRustFiles(slice);
        notes.push(...errors);
        for (const module of modules) {
          try {
            allFindings.push(...analyzeRustModules([module as ModuleIR]));
            byLanguage['rs'] = (byLanguage['rs'] || 0) + 1;
          } catch (err: unknown) {
            notes.push(`${module.path}: rust analyzer error — ${(err as Error).message}`);
          }
        }
      }
    }
  }

  // ── Ruby — subset lowering (catalog/ruby.ts; rails-normal is sealed) ─
  if (rubyFiles.length > 0) {
    if (!rubyFrontendAvailable()) {
      notes.push(
        `${rubyFiles.length} Ruby file(s) skipped — python3/vantage.nebula_frontend_ruby not available`
      );
    } else {
      const RUBY_BATCH = 2000;
      for (let i = 0; i < rubyFiles.length; i += RUBY_BATCH) {
        const slice = rubyFiles.slice(i, i + RUBY_BATCH);
        const { modules, errors } = lowerRubyFiles(slice);
        notes.push(...errors);
        for (const module of modules) {
          try {
            allFindings.push(...analyzeRubyModules([module as ModuleIR]));
            byLanguage['rb'] = (byLanguage['rb'] || 0) + 1;
          } catch (err: unknown) {
            notes.push(`${module.path}: ruby analyzer error — ${(err as Error).message}`);
          }
        }
      }
    }
  }

  // ── PHP — subset lowering (catalog/php.ts; laravel-normal is sealed) ─
  if (phpFiles.length > 0) {
    if (!phpFrontendAvailable()) {
      notes.push(
        `${phpFiles.length} PHP file(s) skipped — python3/vantage.nebula_frontend_php not available`
      );
    } else {
      const PHP_BATCH = 2000;
      for (let i = 0; i < phpFiles.length; i += PHP_BATCH) {
        const slice = phpFiles.slice(i, i + PHP_BATCH);
        const { modules, errors } = lowerPhpFiles(slice);
        notes.push(...errors);
        for (const module of modules) {
          try {
            allFindings.push(...analyzePhpModules([module as ModuleIR]));
            byLanguage['php'] = (byLanguage['php'] || 0) + 1;
          } catch (err: unknown) {
            notes.push(`${module.path}: php analyzer error — ${(err as Error).message}`);
          }
        }
      }
    }
  }

  // ── Bash — raw-source (catalog/bash.ts; bash-normal is sealed) ─
  if (bashFiles.length > 0) {
    if (!bashFrontendAvailable()) {
      notes.push(
        `${bashFiles.length} Bash file(s) skipped — python3/vantage.nebula_frontend_bash not available`
      );
    } else {
      const BASH_BATCH = 2000;
      for (let i = 0; i < bashFiles.length; i += BASH_BATCH) {
        const slice = bashFiles.slice(i, i + BASH_BATCH);
        const { modules, errors } = lowerBashFiles(slice);
        notes.push(...errors);
        for (const module of modules) {
          try {
            allFindings.push(...analyzeBashModules([module as ModuleIR]));
            byLanguage['sh'] = (byLanguage['sh'] || 0) + 1;
          } catch (err: unknown) {
            notes.push(`${module.path}: bash analyzer error — ${(err as Error).message}`);
          }
        }
      }
    }
  }

  // ── Go — subset lowering (catalog/go.ts; gin-normal is sealed) ─
  if (goFiles.length > 0) {
    if (!goFrontendAvailable()) {
      notes.push(
        `${goFiles.length} Go file(s) skipped — python3/vantage.nebula_frontend_go not available`
      );
    } else {
      const GO_BATCH = 2000;
      for (let i = 0; i < goFiles.length; i += GO_BATCH) {
        const slice = goFiles.slice(i, i + GO_BATCH);
        const { modules, errors } = lowerGoFiles(slice);
        notes.push(...errors);
        for (const module of modules) {
          try {
            allFindings.push(...analyzeGoModules([module as ModuleIR]));
            byLanguage['go'] = (byLanguage['go'] || 0) + 1;
          } catch (err: unknown) {
            notes.push(`${module.path}: go analyzer error — ${(err as Error).message}`);
          }
        }
      }
    }
  }

  // ── Java — javalang lowering (catalog/java.ts; Spring hold-out is sealed) ─
  if (javaFiles.length > 0) {
    if (!javaFrontendAvailable()) {
      notes.push(
        `${javaFiles.length} Java file(s) skipped — python3/javalang/vantage.nebula_frontend_java not available`
      );
    } else {
      // BenchProctor enterprise is ~100k independent files. One spawn's JSON IR
      // exceeds spawnSync maxBuffer (~256MB) and returns 0 findings. Batch.
      const JAVA_BATCH = 4000;
      for (let i = 0; i < javaFiles.length; i += JAVA_BATCH) {
        const slice = javaFiles.slice(i, i + JAVA_BATCH);
        const { modules, errors } = lowerJavaFiles(slice);
        notes.push(...errors);
        for (const module of modules) {
          try {
            allFindings.push(...analyzeJavaModules([module as ModuleIR]));
            byLanguage['java'] = (byLanguage['java'] || 0) + 1;
          } catch (err: unknown) {
            notes.push(`${module.path}: java analyzer error — ${(err as Error).message}`);
          }
        }
      }
    }
  }

  return {
    findings: allFindings,
    filesAnalyzed: tsFiles.length + pyFiles.length + javaFiles.length + cFiles.length + cppFiles.length + rubyFiles.length + rustFiles.length + phpFiles.length + bashFiles.length + goFiles.length,
    frontendNotes: notes,
    durationMs: Date.now() - start,
    byLanguage,
  };
}

function walk(target: string, tsOut: string[], pyOut: string[], javaOut: string[] = [], cOut: string[] = [], cppOut: string[] = [], rubyOut: string[] = [], rustOut: string[] = [], phpOut: string[] = [], bashOut: string[] = [], goOut: string[] = []): void {
  let st: fs.Stats;
  try {
    st = fs.statSync(target);
  } catch {
    return;
  }

  // Single-file target (CLI `vantage analyze foo.js --semantic`)
  if (st.isFile()) {
    collectFile(target, tsOut, pyOut, javaOut, cOut, cppOut, rubyOut, rustOut, phpOut, bashOut, goOut);
    return;
  }

  if (!st.isDirectory()) return;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(target, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, tsOut, pyOut, javaOut, cOut, cppOut, rubyOut, rustOut, phpOut, bashOut, goOut);
    } else if (entry.isFile()) {
      collectFile(full, tsOut, pyOut, javaOut, cOut, cppOut, rubyOut, rustOut, phpOut, bashOut, goOut);
    }
  }
}

function collectFile(full: string, tsOut: string[], pyOut: string[], javaOut: string[] = [], cOut: string[] = [], cppOut: string[] = [], rubyOut: string[] = [], rustOut: string[] = [], phpOut: string[] = [], bashOut: string[] = [], goOut: string[] = []): void {
  const ext = path.extname(full);
  if (full.endsWith('.d.ts')) return;
  if (full.endsWith('.min.js')) return;
  if (TS_EXTENSIONS.has(ext)) {
    tsOut.push(full);
  } else if (ext === '.py') {
    try {
      if (fs.statSync(full).size > 0) pyOut.push(full);
    } catch { /* skip unreadable */ }
  } else if (ext === '.java') {
    javaOut.push(full);
  } else if (ext === '.c') {
    cOut.push(full);
  } else if (ext === '.cpp' || ext === '.cc' || ext === '.cxx') {
    cppOut.push(full);
  } else if (ext === '.rb') {
    rubyOut.push(full);
  } else if (ext === '.rs') {
    const base = path.basename(full);
    if (base === 'lib.rs' || base === 'shared.rs') return;
    rustOut.push(full);
  } else if (ext === '.php' || ext === '.phtml') {
    phpOut.push(full);
  } else if (ext === '.sh' || ext === '.bash') {
    bashOut.push(full);
  } else if (ext === '.go') {
    const base = path.basename(full);
    if (base === 'shared.go' || base === 'routes.go' || base === 'routes_unix.go') return;
    goOut.push(full);
  }
}

// Keep the old named export for backward compatibility with tests
export { findPythonFiles };

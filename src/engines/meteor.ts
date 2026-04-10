// METEOR — File Scanner & Code Intelligence Engine
// Walks directories, parses files, extracts real code structure

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import {
  FileInfo, FunctionInfo, ImportInfo, ClassInfo, TodoItem, MeteorOutput
} from '../types';

const SUPPORTED_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.swift', '.py', '.md']);

function getLanguage(ext: string): FileInfo['language'] {
  switch (ext) {
    case '.ts': case '.tsx': return 'typescript';
    case '.js': case '.jsx': return 'javascript';
    case '.swift': return 'swift';
    case '.py': return 'python';
    case '.md': return 'markdown';
    default: return 'other';
  }
}

function loadGitignorePatterns(dir: string): string[] {
  const patterns: string[] = [];
  const gitignorePath = path.join(dir, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    const lines = fs.readFileSync(gitignorePath, 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        patterns.push(trimmed);
      }
    }
  }
  return patterns;
}

function isIgnored(filePath: string, rootDir: string, patterns: string[]): boolean {
  const rel = path.relative(rootDir, filePath);
  const parts = rel.split(path.sep);

  // Always ignore these
  const alwaysIgnore = ['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', '.DS_Store', 'Pods', '.build'];
  if (parts.some(p => alwaysIgnore.includes(p))) return true;

  for (const pattern of patterns) {
    const cleaned = pattern.replace(/^\//, '').replace(/\/$/, '');
    if (rel.startsWith(cleaned) || parts.includes(cleaned)) return true;
    if (rel === cleaned) return true;
  }
  return false;
}

function walkDir(dir: string, rootDir: string, ignorePatterns: string[]): string[] {
  const results: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (isIgnored(fullPath, rootDir, ignorePatterns)) continue;

    if (entry.isDirectory()) {
      results.push(...walkDir(fullPath, rootDir, ignorePatterns));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SUPPORTED_EXTENSIONS.has(ext)) {
        results.push(fullPath);
      }
    }
  }
  return results;
}

// Estimate cyclomatic complexity by counting branch points
function calculateComplexity(content: string): number {
  let complexity = 1; // base
  const branchKeywords = [
    /\bif\b/g, /\belse\b/g, /\bfor\b/g, /\bwhile\b/g, /\bswitch\b/g,
    /\bcase\b/g, /\bcatch\b/g, /\b\?\s*:/g, /\?\?/g, /&&/g, /\|\|/g,
    /\bguard\b/g, /\bforeach\b/gi, /\bfor\s+in\b/gi
  ];
  for (const pattern of branchKeywords) {
    const matches = content.match(pattern);
    if (matches) complexity += matches.length;
  }
  return complexity;
}

function extractFunctionsTS(content: string, filePath: string): FunctionInfo[] {
  const functions: FunctionInfo[] = [];
  const lines = content.split('\n');

  // Named functions
  const namedFuncRe = /(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/;
  // Arrow functions
  const arrowFuncRe = /(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(async\s+)?\(?([^)]*)\)?\s*=>/;
  // Class methods (TS/JS)
  const methodRe = /^\s+(?:async\s+)?(?:public\s+|private\s+|protected\s+|static\s+)*(\w+)\s*\(([^)]*)\)\s*(?::\s*\S+)?\s*\{/;
  // Swift functions
  const swiftFuncRe = /func\s+(\w+)\s*\(([^)]*)\)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let funcName: string | null = null;
    let params: string = '';
    let isAsync = false;

    const named = line.match(namedFuncRe);
    if (named) {
      funcName = named[1];
      params = named[2];
      isAsync = line.includes('async');
    } else {
      const arrow = line.match(arrowFuncRe);
      if (arrow) {
        funcName = arrow[1];
        params = arrow[3] || '';
        isAsync = !!arrow[2];
      } else {
        const method = line.match(methodRe);
        if (method && !['if', 'else', 'for', 'while', 'switch', 'catch', 'constructor'].includes(method[1])) {
          funcName = method[1];
          params = method[2];
          isAsync = line.includes('async');
        } else {
          const swift = line.match(swiftFuncRe);
          if (swift) {
            funcName = swift[1];
            params = swift[2];
            isAsync = line.includes('async');
          }
        }
      }
    }

    if (!funcName) continue;

    // Find function end by counting braces
    let braceDepth = 0;
    let endLine = i;
    let started = false;
    for (let j = i; j < lines.length && j < i + 500; j++) {
      const l = lines[j];
      for (const ch of l) {
        if (ch === '{') { braceDepth++; started = true; }
        if (ch === '}') braceDepth--;
      }
      if (started && braceDepth <= 0) {
        endLine = j;
        break;
      }
    }

    const funcLines = lines.slice(i, endLine + 1);
    const funcContent = funcLines.join('\n');
    const complexity = calculateComplexity(funcContent);

    // Check error handling
    const hasErrorHandling = funcContent.includes('try') || funcContent.includes('catch') ||
      funcContent.includes('.catch(') || funcContent.includes('Result<') ||
      funcContent.includes('throws') || funcContent.includes('guard ');

    functions.push({
      name: funcName,
      file: filePath,
      startLine: i + 1,
      endLine: endLine + 1,
      lines: endLine - i + 1,
      complexity,
      isAsync,
      hasErrorHandling,
      parameters: params.split(',').map(p => p.trim()).filter(Boolean)
    });
  }

  return functions;
}

function extractImports(content: string, filePath: string): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const lines = content.split('\n');

  // TS/JS: import ... from '...'
  const tsImportRe = /import\s+.*?from\s+['"]([^'"]+)['"]/;
  // TS/JS: require(...)
  const requireRe = /require\(['"]([^'"]+)['"]\)/;
  // Swift: import Module
  const swiftImportRe = /^import\s+(\w+)/;
  // Python: import X / from X import Y
  const pyImportRe = /^(?:from\s+(\S+)\s+import|import\s+(\S+))/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    const ts = line.match(tsImportRe);
    if (ts) {
      imports.push({
        file: filePath,
        source: ts[1],
        line: i + 1,
        isRelative: ts[1].startsWith('.')
      });
      continue;
    }

    const req = line.match(requireRe);
    if (req) {
      imports.push({
        file: filePath,
        source: req[1],
        line: i + 1,
        isRelative: req[1].startsWith('.')
      });
      continue;
    }

    const swift = line.match(swiftImportRe);
    if (swift) {
      imports.push({
        file: filePath,
        source: swift[1],
        line: i + 1,
        isRelative: false
      });
      continue;
    }

    const py = line.match(pyImportRe);
    if (py) {
      imports.push({
        file: filePath,
        source: py[1] || py[2],
        line: i + 1,
        isRelative: (py[1] || py[2] || '').startsWith('.')
      });
    }
  }

  return imports;
}

function extractClasses(content: string, filePath: string): ClassInfo[] {
  const classes: ClassInfo[] = [];
  const lines = content.split('\n');

  const patterns: Array<[RegExp, ClassInfo['type']]> = [
    [/(?:export\s+)?(?:abstract\s+)?class\s+(\w+)/, 'class'],
    [/(?:export\s+)?interface\s+(\w+)/, 'interface'],
    [/^struct\s+(\w+)/, 'struct'],
    [/^enum\s+(\w+)/, 'enum'],
    [/^protocol\s+(\w+)/, 'protocol'],
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const [re, type] of patterns) {
      const match = line.match(re);
      if (match) {
        // Count exports from this entity (rough: count 'export' keywords in vicinity)
        const exportCount = (content.match(/\bexport\b/g) || []).length;
        classes.push({
          name: match[1],
          file: filePath,
          line: i + 1,
          type,
          exportCount
        });
      }
    }
  }

  return classes;
}

function extractTodos(content: string, filePath: string): TodoItem[] {
  const todos: TodoItem[] = [];
  const lines = content.split('\n');
  const todoRe = /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i;

  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(todoRe);
    if (match) {
      todos.push({
        file: filePath,
        line: i + 1,
        type: match[1].toUpperCase() as TodoItem['type'],
        text: match[2].trim()
      });
    }
  }

  return todos;
}

export async function runMETEOR(targetPath: string, onProgress?: (msg: string) => void): Promise<MeteorOutput> {
  const stat = fs.statSync(targetPath);
  const isFile = stat.isFile();

  let filePaths: string[];
  let rootDir: string;

  if (isFile) {
    filePaths = [targetPath];
    rootDir = path.dirname(targetPath);
  } else {
    rootDir = targetPath;
    const ignorePatterns = loadGitignorePatterns(rootDir);
    filePaths = walkDir(rootDir, rootDir, ignorePatterns);
  }

  onProgress?.(`scanning ${filePaths.length} files`);

  const files: FileInfo[] = [];
  const allFunctions: FunctionInfo[] = [];
  const allImports: ImportInfo[] = [];
  const allClasses: ClassInfo[] = [];
  const allTodos: TodoItem[] = [];

  for (const filePath of filePaths) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const ext = path.extname(filePath).toLowerCase();
    const language = getLanguage(ext);
    const lines = content.split('\n').length;

    files.push({
      path: filePath,
      relativePath: path.relative(rootDir, filePath),
      language,
      lines,
      content
    });

    if (language !== 'markdown' && language !== 'other') {
      const funcs = extractFunctionsTS(content, filePath);
      allFunctions.push(...funcs);

      const imports = extractImports(content, filePath);
      allImports.push(...imports);

      const classes = extractClasses(content, filePath);
      allClasses.push(...classes);
    }

    const todos = extractTodos(content, filePath);
    allTodos.push(...todos);
  }

  const totalLOC = files.reduce((sum, f) => sum + f.lines, 0);
  const totalComplexity = allFunctions.reduce((sum, f) => sum + f.complexity, 0);
  const largeFunctions = allFunctions.filter(f => f.lines > 100);
  const highComplexityFunctions = allFunctions.filter(f => f.complexity > 15);

  onProgress?.(`${files.length} files scanned, ${allFunctions.length} functions found, ${allTodos.length} TODO/FIXME items`);

  return {
    files,
    functions: allFunctions,
    imports: allImports,
    classes: allClasses,
    todos: allTodos,
    metrics: {
      linesOfCode: totalLOC,
      totalComplexity,
      todoCount: allTodos.length,
      largeFunctions,
      highComplexityFunctions
    }
  };
}

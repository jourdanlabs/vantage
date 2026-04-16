// METEOR — File Scanner & Code Intelligence Engine
// Walks directories, parses files, extracts real code structure

import * as fs from 'fs';
import * as path from 'path';
import {
  FileInfo, FunctionInfo, ImportInfo, ClassInfo, TodoItem, MeteorOutput
} from '../types';
import {
  SUPPORTED_EXTENSIONS, getLanguageName, getLanguageDef, isLanguageFullySupported
} from '../languages';

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
  const alwaysIgnore = ['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', '.DS_Store', 'Pods', '.build', 'vendor'];
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
        // Skip minified files — they produce phantom complexity and are not application code
        const base = entry.name.toLowerCase();
        if (base.endsWith('.min.js') || base.endsWith('.min.ts') || base.includes('-min.js')) continue;
        results.push(fullPath);
      }
    }
  }
  return results;
}

// Estimate cyclomatic complexity using the language's keywords, or a generic fallback
function calculateComplexity(content: string, langName: string): number {
  const def = getLanguageDef(
    // map name back to first extension for lookup
    (() => {
      const { LANGUAGE_REGISTRY } = require('../languages');
      return LANGUAGE_REGISTRY.find((l: { name: string; extensions: string[] }) => l.name === langName)?.extensions[0] ?? '.ts';
    })()
  );

  let complexity = 1; // base
  if (def) {
    // Reset lastIndex before use (global flag)
    def.complexityKeywords.lastIndex = 0;
    const matches = content.match(def.complexityKeywords);
    if (matches) complexity += matches.length;
  } else {
    // Fallback generic keywords
    const fallback = [
      /\bif\b/g, /\belse\b/g, /\bfor\b/g, /\bwhile\b/g, /\bswitch\b/g,
      /\bcase\b/g, /\bcatch\b/g, /&&/g, /\|\|/g
    ];
    for (const re of fallback) {
      const m = content.match(re);
      if (m) complexity += m.length;
    }
  }
  return complexity;
}

function extractFunctions(content: string, filePath: string, langName: string): FunctionInfo[] {
  const functions: FunctionInfo[] = [];
  const def = (() => {
    const { LANGUAGE_REGISTRY } = require('../languages');
    return LANGUAGE_REGISTRY.find((l: { name: string }) => l.name === langName);
  })();

  if (!def || def.functionPatterns.length === 0) return functions;

  const lines = content.split('\n');
  const skipKeywords = new Set(['if', 'else', 'for', 'while', 'switch', 'catch', 'constructor', 'do', 'try']);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let funcName: string | null = null;
    let isAsync = line.includes('async');

    for (const pattern of def.functionPatterns) {
      const match = line.match(pattern);
      if (match) {
        // The first capture group with a valid identifier wins
        const candidate = match[1] || match[2] || null;
        if (candidate && !skipKeywords.has(candidate)) {
          funcName = candidate;
          break;
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

    // Extract parameters from the line (text between first ( and ))
    const paramMatch = line.match(/\(([^)]*)\)/);
    const params = paramMatch ? paramMatch[1] : '';

    const funcLines = lines.slice(i, endLine + 1);
    const funcContent = funcLines.join('\n');
    const complexity = calculateComplexity(funcContent, langName);

    const hasErrorHandling = funcContent.includes('try') || funcContent.includes('catch') ||
      funcContent.includes('.catch(') || funcContent.includes('Result<') ||
      funcContent.includes('throws') || funcContent.includes('guard ') ||
      funcContent.includes('except') || funcContent.includes('rescue') ||
      funcContent.includes('Err(') || funcContent.includes('unwrap_or');

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

function extractImports(content: string, filePath: string, langName: string): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const def = (() => {
    const { LANGUAGE_REGISTRY } = require('../languages');
    return LANGUAGE_REGISTRY.find((l: { name: string }) => l.name === langName);
  })();

  if (!def || def.importPatterns.length === 0) return imports;

  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    for (const pattern of def.importPatterns) {
      const match = line.match(pattern);
      if (match) {
        const source = match[1] || match[2] || '';
        if (source) {
          imports.push({
            file: filePath,
            source,
            line: i + 1,
            isRelative: source.startsWith('.')
          });
        }
        break; // only one pattern per line
      }
    }
  }

  return imports;
}

function extractClasses(content: string, filePath: string, langName: string): ClassInfo[] {
  const classes: ClassInfo[] = [];
  const def = (() => {
    const { LANGUAGE_REGISTRY } = require('../languages');
    return LANGUAGE_REGISTRY.find((l: { name: string }) => l.name === langName);
  })();

  if (!def || def.classPatterns.length === 0) return classes;

  const lines = content.split('\n');

  // Map pattern index to a ClassInfo type label
  const typeLabels: ClassInfo['type'][] = ['class', 'interface', 'struct', 'enum', 'protocol'];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (let pi = 0; pi < def.classPatterns.length; pi++) {
      const match = line.match(def.classPatterns[pi]);
      if (match) {
        const name = match[1] || match[2] || '';
        if (!name) continue;

        // Determine type from pattern index (best effort)
        let type: ClassInfo['type'] = 'class';
        const lowerLine = line.toLowerCase();
        if (lowerLine.includes('interface')) type = 'interface';
        else if (lowerLine.includes('struct')) type = 'struct';
        else if (lowerLine.includes('enum')) type = 'enum';
        else if (lowerLine.includes('protocol')) type = 'protocol';

        const exportCount = (content.match(/\bexport\b/g) || []).length;
        classes.push({
          name,
          file: filePath,
          line: i + 1,
          type,
          exportCount
        });
        break; // one match per line
      }
    }
  }

  return classes;
}

function extractTodos(content: string, filePath: string, langName: string): TodoItem[] {
  const todos: TodoItem[] = [];
  const def = (() => {
    const { LANGUAGE_REGISTRY } = require('../languages');
    return LANGUAGE_REGISTRY.find((l: { name: string }) => l.name === langName);
  })();

  const todoRe = def?.todoPattern ?? /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i;
  const lines = content.split('\n');

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

  // Track files in languages where extraction is not yet reliable
  const unsupportedFilePaths: string[] = [];
  const unsupportedExtsSeen = new Set<string>();

  for (const filePath of filePaths) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const ext = path.extname(filePath).toLowerCase();
    const language = getLanguageName(ext);
    // Subtract trailing empty element produced by files ending with \n
    const rawLines = content.split('\n');
    const lines = rawLines.length > 0 && rawLines[rawLines.length - 1] === '' ? rawLines.length - 1 : rawLines.length;

    files.push({
      path: filePath,
      relativePath: path.relative(rootDir, filePath),
      language,
      lines,
      content
    });

    // If the language registry marks this extension as not fully supported,
    // count it for LOC but skip function/import/class extraction entirely.
    if (!isLanguageFullySupported(ext)) {
      unsupportedFilePaths.push(filePath);
      unsupportedExtsSeen.add(ext);
      // Still extract TODOs — those are comment-based and language-agnostic
      const todos = extractTodos(content, filePath, language);
      allTodos.push(...todos);
      continue;
    }

    if (language !== 'markdown' && language !== 'other') {
      const funcs = extractFunctions(content, filePath, language);
      allFunctions.push(...funcs);

      const imports = extractImports(content, filePath, language);
      allImports.push(...imports);

      const classes = extractClasses(content, filePath, language);
      allClasses.push(...classes);
    }

    const todos = extractTodos(content, filePath, language);
    allTodos.push(...todos);
  }

  const totalLOC = files.reduce((sum, f) => sum + f.lines, 0);
  const totalComplexity = allFunctions.reduce((sum, f) => sum + f.complexity, 0);
  const largeFunctions = allFunctions.filter(f => f.lines > 100);
  const highComplexityFunctions = allFunctions.filter(f => f.complexity > 15);

  if (unsupportedFilePaths.length > 0) {
    onProgress?.(
      `WARNING: skipped extraction for ${unsupportedFilePaths.length} files in unsupported language(s): ${[...unsupportedExtsSeen].join(', ')} — LOC counted, no function/import/class data`
    );
  }

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
    },
    unsupportedFiles: {
      count: unsupportedFilePaths.length,
      extensions: [...unsupportedExtsSeen].sort(),
      filePaths: unsupportedFilePaths.slice(0, 100), // cap for readability
    },
  };
}

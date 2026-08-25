// VANTAGE — Central Language Registry
// Adding a new language requires touching ONLY this file.

export interface LanguageDef {
  extensions: string[];         // e.g. ['.go']
  name: string;                 // language label
  /**
   * Whether VANTAGE has reliable extraction for this language.
   * false = LOC is counted but function/import/class extraction is skipped and
   * files are reported in MeteorOutput.unsupportedFiles.
   * Defaults to true when omitted.
   */
  fullySupported?: boolean;
  // Regex patterns for METEOR extraction
  functionPatterns: RegExp[];   // matches function/method declarations
  importPatterns: RegExp[];     // matches import/require/use/include statements
  classPatterns: RegExp[];      // matches class/struct/interface/trait/enum declarations
  complexityKeywords: RegExp;   // single regex matching branching keywords
  todoPattern: RegExp;          // matches TODO/FIXME/HACK/NOTE comments
  // Test file detection for ECLIPSE
  testFileSuffixes: string[];   // e.g. ['_test.go']
  testDirPatterns: string[];    // e.g. ['__tests__', 'test/', 'tests/']
  // Import resolution for NOVA
  importExtensions: string[];   // extensions to try when resolving bare imports
  /** Exact basenames (Dockerfile) — METEOR/CRUCIBLE discovery when there is no extension. */
  filenames?: string[];
}

export const LANGUAGE_REGISTRY: LanguageDef[] = [
  // ── TypeScript / TSX ────────────────────────────────────────────────────────
  {
    extensions: ['.ts', '.tsx'],
    name: 'typescript',
    functionPatterns: [
      /(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(/,
      /(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?[^)]*\)?\s*=>/,
      /^\s+(?:async\s+)?(?:public\s+|private\s+|protected\s+|static\s+)*(\w+)\s*\([^)]*\)\s*(?::\s*\S+)?\s*\{/,
    ],
    importPatterns: [
      /import\s+.*?from\s+['"]([^'"]+)['"]/,
      /require\(['"]([^'"]+)['"]\)/,
    ],
    classPatterns: [
      /(?:export\s+)?(?:abstract\s+)?class\s+(\w+)/,
      /(?:export\s+)?interface\s+(\w+)/,
      /(?:export\s+)?enum\s+(\w+)/,
      /(?:export\s+)?type\s+(\w+)\s*=/,
    ],
    complexityKeywords: /\bif\b|\belse if\b|\bfor\b|\bwhile\b|\bswitch\b|\bcase\b|\bcatch\b|\?|&&|\|\|/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['.test.ts', '.spec.ts', '.test.tsx', '.spec.tsx'],
    testDirPatterns: ['__tests__', 'test/', 'tests/'],
    importExtensions: ['.ts', '.tsx', '/index.ts'],
  },

  // ── JavaScript / JSX ────────────────────────────────────────────────────────
  {
    extensions: ['.js', '.jsx', '.mjs', '.cjs'],
    name: 'javascript',
    functionPatterns: [
      /(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(/,
      /(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?[^)]*\)?\s*=>/,
      /^\s+(?:async\s+)?(?:public\s+|private\s+|protected\s+|static\s+)*(\w+)\s*\([^)]*\)\s*\{/,
    ],
    importPatterns: [
      /import\s+.*?from\s+['"]([^'"]+)['"]/,
      /require\(['"]([^'"]+)['"]\)/,
    ],
    classPatterns: [
      /(?:export\s+)?(?:abstract\s+)?class\s+(\w+)/,
      /(?:export\s+)?enum\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belse if\b|\bfor\b|\bwhile\b|\bswitch\b|\bcase\b|\bcatch\b|\?|&&|\|\|/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['.test.js', '.spec.js', '.test.jsx', '.spec.jsx'],
    testDirPatterns: ['__tests__', 'test/', 'tests/'],
    importExtensions: ['.js', '.jsx', '/index.js'],
  },

  // ── Python ──────────────────────────────────────────────────────────────────
  {
    extensions: ['.py', '.pyw'],
    name: 'python',
    functionPatterns: [
      /^\s*(?:async\s+)?def\s+(\w+)\s*\(/,
    ],
    importPatterns: [
      /^import\s+(\S+)/,
      /^from\s+(\S+)\s+import/,
    ],
    classPatterns: [
      /^class\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belif\b|\belse\b|\bfor\b|\bwhile\b|\btry\b|\bexcept\b|\bwith\b|\band\b|\bor\b/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['_test.py', 'test_.py'],
    testDirPatterns: ['tests/', 'test/'],
    importExtensions: ['.py'],
  },

  // ── Swift ────────────────────────────────────────────────────────────────────
  {
    extensions: ['.swift'],
    name: 'swift',
    functionPatterns: [
      /\bfunc\s+(\w+)\s*\(/,
      /\binit\s*\(/,
      /\bdeinit\b/,
    ],
    importPatterns: [
      /^import\s+(\w+)/,
    ],
    classPatterns: [
      /\bclass\s+(\w+)/,
      /\bstruct\s+(\w+)/,
      /\benum\s+(\w+)/,
      /\bprotocol\s+(\w+)/,
      /\bextension\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belse if\b|\bguard\b|\bfor\b|\bwhile\b|\bswitch\b|\bcase\b|\bcatch\b|&&|\|\||\?/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['Tests.swift', 'Spec.swift'],
    testDirPatterns: ['Tests/', 'test/'],
    importExtensions: ['.swift'],
  },

  // ── Go ───────────────────────────────────────────────────────────────────────
  {
    extensions: ['.go'],
    name: 'go',
    functionPatterns: [
      /^func\s+(\w+)\s*\(/,
      /^func\s+\(\s*\w+\s+\*?\w+\s*\)\s+(\w+)\s*\(/,
    ],
    importPatterns: [
      /import\s+"([^"]+)"/,
      /import\s+\(/,
    ],
    classPatterns: [
      /type\s+(\w+)\s+struct/,
      /type\s+(\w+)\s+interface/,
    ],
    complexityKeywords: /\bif\b|\belse\b|\bfor\b|\bswitch\b|\bcase\b|\bselect\b|\bfallthrough\b|&&|\|\|/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['_test.go'],
    testDirPatterns: ['testdata/'],
    importExtensions: ['.go'],
  },

  // ── Rust ─────────────────────────────────────────────────────────────────────
  {
    extensions: ['.rs'],
    name: 'rust',
    functionPatterns: [
      /(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(/,
    ],
    importPatterns: [
      /^use\s+(\S+)/,
      /^extern\s+crate\s+(\w+)/,
    ],
    classPatterns: [
      /\bstruct\s+(\w+)/,
      /\benum\s+(\w+)/,
      /\btrait\s+(\w+)/,
      /\bimpl\s+(?:\w+\s+for\s+)?(\w+)/,
      /\btype\s+(\w+)\s*=/,
    ],
    complexityKeywords: /\bif\b|\belse\b|\bmatch\b|\bfor\b|\bwhile\b|\bloop\b|&&|\|\||\?/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: [],
    testDirPatterns: ['tests/'],
    importExtensions: ['.rs'],
  },

  // ── C ────────────────────────────────────────────────────────────────────────
  {
    extensions: ['.c', '.h'],
    name: 'c',
    functionPatterns: [
      /(?:static\s+|extern\s+|inline\s+)?[\w\s\*]+\b(\w+)\s*\([^;]*\)\s*\{/,
    ],
    importPatterns: [
      /^#\s*include\s+[<"]([^>"]+)[>"]/,
    ],
    classPatterns: [
      /\bstruct\s+(\w+)/,
      /\benum\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belse\b|\bfor\b|\bwhile\b|\bswitch\b|\bcase\b|&&|\|\||\?/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: [],
    testDirPatterns: ['test/', 'tests/'],
    importExtensions: ['.c', '.h'],
  },

  // ── Java ─────────────────────────────────────────────────────────────────────
  {
    extensions: ['.java'],
    name: 'java',
    functionPatterns: [
      /(?:public|private|protected|static|final|abstract|synchronized)[\w\s<>\[\]]*\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+(?:,\s*\w+)*)?\s*\{/,
    ],
    importPatterns: [
      /^import\s+([\w.]+(?:\.\*)?)/,
    ],
    classPatterns: [
      /\bclass\s+(\w+)/,
      /\binterface\s+(\w+)/,
      /\benum\s+(\w+)/,
      /\b@interface\s+(\w+)/,
      /\brecord\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belse if\b|\bfor\b|\bwhile\b|\bswitch\b|\bcase\b|\bcatch\b|&&|\|\||\?/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['Test.java', 'Tests.java', 'Spec.java', 'IT.java'],
    testDirPatterns: ['src/test/'],
    importExtensions: ['.java'],
  },

  // ── Kotlin ───────────────────────────────────────────────────────────────────
  {
    extensions: ['.kt', '.kts'],
    name: 'kotlin',
    functionPatterns: [
      /(?:suspend\s+)?fun\s+(\w+)\s*\(/,
    ],
    importPatterns: [
      /^import\s+([\w.]+(?:\.\*)?)/,
    ],
    classPatterns: [
      /\bclass\s+(\w+)/,
      /\binterface\s+(\w+)/,
      /\bobject\s+(\w+)/,
      /\bdata\s+class\s+(\w+)/,
      /\bsealed\s+class\s+(\w+)/,
      /\benum\s+class\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belse\b|\bwhen\b|\bfor\b|\bwhile\b|\bcatch\b|&&|\|\||\?/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['Test.kt', 'Tests.kt', 'Spec.kt'],
    testDirPatterns: ['test/', 'tests/'],
    importExtensions: ['.kt'],
  },

  // ── Ruby ─────────────────────────────────────────────────────────────────────
  {
    extensions: ['.rb'],
    name: 'ruby',
    functionPatterns: [
      /^\s*def\s+(self\.)?(\w+)/,
    ],
    importPatterns: [
      /^require\s+['"]([^'"]+)['"]/,
      /^require_relative\s+['"]([^'"]+)['"]/,
      /^\s*include\s+(\w+)/,
      /^\s*extend\s+(\w+)/,
    ],
    classPatterns: [
      /\bclass\s+(\w+)/,
      /\bmodule\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belsif\b|\bunless\b|\bwhile\b|\buntil\b|\bfor\b|\bcase\b|\bwhen\b|\brescue\b|&&|\|\|/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['_test.rb', '_spec.rb'],
    testDirPatterns: ['spec/', 'test/'],
    importExtensions: ['.rb'],
  },

  // ── C / C++ ──────────────────────────────────────────────────────────────────
  // fullySupported: false — regex patterns require '{' on same line as signature,
  // which fails for Allman-style C (the dominant kernel/systems style). LOC is
  // still counted but function/import/class extraction is skipped. Tracked under
  // MeteorOutput.unsupportedFiles. Real fix: tree-sitter-c (future work).
  {
    extensions: ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'],
    name: 'cpp',
    fullySupported: false,
    functionPatterns: [
      /\w+\s+\w+\s*\([^)]*\)\s*(?:const\s*)?\{/,
      /\w+::\w+\s*\([^)]*\)\s*(?:const\s*)?\{/,
    ],
    importPatterns: [
      /^#include\s+[<"]([^>"]+)[>"]/,
    ],
    classPatterns: [
      /\bclass\s+(\w+)/,
      /\bstruct\s+(\w+)/,
      /\bunion\s+(\w+)/,
      /\benum\s+(?:class\s+)?(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belse if\b|\bfor\b|\bwhile\b|\bswitch\b|\bcase\b|\bcatch\b|&&|\|\||\?/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['_test.cpp', '_test.cc', 'Test.cpp', '_unittest.cc'],
    testDirPatterns: ['test/', 'tests/'],
    importExtensions: ['.h', '.hpp', '.cpp', '.cc'],
  },

  // ── C# ───────────────────────────────────────────────────────────────────────
  {
    extensions: ['.cs'],
    name: 'csharp',
    functionPatterns: [
      /(?:public|private|protected|internal|static|async|override|virtual)[\w\s<>\[\]]*\s+(\w+)\s*\([^)]*\)\s*\{/,
      /\w+\s+(\w+)\s*\([^)]*\)\s*\{/,
    ],
    importPatterns: [
      /^using\s+([\w.]+)/,
    ],
    classPatterns: [
      /\bclass\s+(\w+)/,
      /\binterface\s+(\w+)/,
      /\bstruct\s+(\w+)/,
      /\benum\s+(\w+)/,
      /\brecord\s+(\w+)/,
      /\bdelegate\s+\w+\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belse if\b|\bfor\b|\bforeach\b|\bwhile\b|\bswitch\b|\bcase\b|\bcatch\b|&&|\|\||\?/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['Test.cs', 'Tests.cs', 'Spec.cs'],
    testDirPatterns: ['Tests/', 'test/'],
    importExtensions: ['.cs'],
  },

  // ── PHP ──────────────────────────────────────────────────────────────────────
  {
    extensions: ['.php', '.phtml'],
    name: 'php',
    functionPatterns: [
      /(?:public|private|protected|static\s+)?function\s+(\w+)\s*\(/,
    ],
    importPatterns: [
      /\brequire_once\s+['"]([^'"]+)['"]/,
      /\brequire\s+['"]([^'"]+)['"]/,
      /\binclude_once\s+['"]([^'"]+)['"]/,
      /\binclude\s+['"]([^'"]+)['"]/,
      /^use\s+([\w\\]+)/,
    ],
    classPatterns: [
      /\bclass\s+(\w+)/,
      /\binterface\s+(\w+)/,
      /\btrait\s+(\w+)/,
      /\babstract\s+class\s+(\w+)/,
      /\benum\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belseif\b|\belse\b|\bforeach\b|\bfor\b|\bwhile\b|\bswitch\b|\bcase\b|\bcatch\b|&&|\|\|/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['Test.php', 'Tests.php'],
    testDirPatterns: ['test/', 'tests/'],
    importExtensions: ['.php'],
  },

  // ── Scala ────────────────────────────────────────────────────────────────────
  {
    extensions: ['.scala', '.sc'],
    name: 'scala',
    functionPatterns: [
      /\bdef\s+(\w+)\s*\(/,
      /\bval\s+(\w+)\s*=\s*.*=>/,
      /\bvar\s+(\w+)\s*=\s*.*=>/,
    ],
    importPatterns: [
      /^import\s+([\w.]+(?:\._)?)/,
    ],
    classPatterns: [
      /\bclass\s+(\w+)/,
      /\bobject\s+(\w+)/,
      /\btrait\s+(\w+)/,
      /\bcase\s+class\s+(\w+)/,
      /\bsealed\s+trait\s+(\w+)/,
      /\benum\s+(\w+)/,
    ],
    complexityKeywords: /\bif\b|\belse\b|\bmatch\b|\bcase\b|\bfor\b|\bwhile\b|\bcatch\b|&&|\|\|/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['Test.scala', 'Tests.scala', 'Spec.scala', 'Suite.scala'],
    testDirPatterns: ['test/', 'tests/'],
    importExtensions: ['.scala'],
  },

  // ── Shell / Bash ─────────────────────────────────────────────────────────────
  {
    extensions: ['.sh', '.bash', '.zsh', '.fish'],
    name: 'shell',
    functionPatterns: [
      /\bfunction\s+(\w+)\s*\{/,
      /^(\w+)\s*\(\s*\)\s*\{/,
    ],
    importPatterns: [
      /^\s*source\s+['"]?([^\s'"]+)['"]?/,
      /^\s*\.\s+['"]?([^\s'"]+)['"]?/,
    ],
    classPatterns: [],
    complexityKeywords: /\bif\b|\belif\b|\belse\b|\bfor\b|\bwhile\b|\buntil\b|\bcase\b|\[\[|&&|\|\|/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: ['_test.sh', '.bats'],
    testDirPatterns: ['test/', 'tests/'],
    importExtensions: ['.sh', '.bash'],
  },

  // ── Terraform / HCL ──────────────────────────────────────────────────────────
  // fullySupported: false — METEOR function extraction is N/A.
  // CRUCIBLE owns the structural config tree. No module expansion.
  {
    extensions: ['.tf', '.tfvars'],
    name: 'terraform',
    fullySupported: false,
    functionPatterns: [],
    importPatterns: [
      /module\s+"([^"]+)"/,
    ],
    classPatterns: [
      /resource\s+"([^"]+)"/,
      /data\s+"([^"]+)"/,
    ],
    complexityKeywords: /(?:)/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: [],
    testDirPatterns: ['test/', 'tests/'],
    importExtensions: ['.tf'],
  },

  // ── Dockerfile ───────────────────────────────────────────────────────────────
  // No extension. Discovery is via `filenames`. Kubernetes YAML is declared-dark.
  {
    extensions: [],
    name: 'dockerfile',
    fullySupported: false,
    filenames: ['Dockerfile', 'dockerfile', 'Containerfile'],
    functionPatterns: [],
    importPatterns: [],
    classPatterns: [],
    complexityKeywords: /(?:)/g,
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: [],
    testDirPatterns: [],
    importExtensions: [],
  },

  // ── Markdown ─────────────────────────────────────────────────────────────────
  {
    extensions: ['.md', '.mdx', '.markdown'],
    name: 'markdown',
    functionPatterns: [],
    importPatterns: [],
    classPatterns: [],
    complexityKeywords: /(?:)/g,  // never matches
    todoPattern: /\b(TODO|FIXME|HACK|XXX)\b[:\s]*(.*)/i,
    testFileSuffixes: [],
    testDirPatterns: [],
    importExtensions: [],
  },
];

// ── Lookup helpers ────────────────────────────────────────────────────────────

/** All extensions known to VANTAGE, derived from the registry. */
export const SUPPORTED_EXTENSIONS: Set<string> = new Set(
  LANGUAGE_REGISTRY.flatMap(l => l.extensions)
);

/** Return the LanguageDef for a given file extension, or undefined. */
export function getLanguageDef(ext: string): LanguageDef | undefined {
  return LANGUAGE_REGISTRY.find(l => l.extensions.includes(ext.toLowerCase()));
}

/** Return the language name for a given extension (falls back to 'other'). */
export function getLanguageName(ext: string): string {
  return getLanguageDef(ext)?.name ?? 'other';
}

/** All import-resolution extensions, deduplicated. */
export const ALL_IMPORT_EXTENSIONS: string[] = [
  ...new Set(LANGUAGE_REGISTRY.flatMap(l => l.importExtensions))
];

/**
 * Returns true if VANTAGE has reliable function/import/class extraction for
 * the given file extension. Returns false for languages where extraction is
 * known to be unreliable (e.g. C/C++ Allman-style). Defaults to true for
 * unrecognised extensions (they won't be walked anyway).
 */
export function isLanguageFullySupported(ext: string): boolean {
  const def = getLanguageDef(ext);
  if (!def) return true; // unknown ext — won't be walked, irrelevant
  return def.fullySupported !== false;
}

/** Exact-basename match for extensionless files (Dockerfile). */
export function isKnownBasename(name: string): boolean {
  const lower = name.toLowerCase();
  return LANGUAGE_REGISTRY.some(l => (l.filenames || []).some(f => f.toLowerCase() === lower));
}

/** Language def for a path: basename first (Dockerfile), then extension. */
export function getLanguageForPath(filePath: string): LanguageDef | undefined {
  const base = filePath.split(/[/\\]/).pop() || '';
  const byName = LANGUAGE_REGISTRY.find(l =>
    (l.filenames || []).some(f => f.toLowerCase() === base.toLowerCase())
  );
  if (byName) return byName;
  const dot = base.lastIndexOf('.');
  if (dot < 0) return undefined;
  return getLanguageDef(base.slice(dot));
}


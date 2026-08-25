// Template correctness checks. Run with:
//   npx ts-node src/mcp/fix-templates/templates.test.ts
//
// Each case constructs a synthetic finding for a small source snippet,
// runs the template, and asserts the patch matches expectation. The
// patches are checked by applying them in-memory (the same way `git apply`
// would) and comparing the post-patch source to the expected file.

import { NullSafetyTemplate } from './null-safety';
import { ErrorBoundaryTemplate } from './error-boundary';
import { HardcodedSecretTemplate } from './hardcoded-secret';

interface Case {
  name: string;
  template: typeof NullSafetyTemplate | typeof ErrorBoundaryTemplate | typeof HardcodedSecretTemplate;
  filePath: string;
  before: string;
  line: number;
  findingType: string;
  description: string;
  expectApplied: boolean;
  expectAfter?: string;     // only required if expectApplied
  expectSkipReasonIncludes?: string;
}

const cases: Case[] = [
  // ── null-safety ──────────────────────────────────────────────────────────
  {
    name: 'null-safety: deep chain in const declaration',
    template: NullSafetyTemplate,
    filePath: 'a.ts',
    before: [
      'function f(req) {',
      '  const x = req.body.user.name;',
      '  return x;',
      '}',
    ].join('\n'),
    line: 2,
    findingType: 'null-safety',
    description: 'Deep property access without null check',
    expectApplied: true,
    expectAfter: [
      'function f(req) {',
      '  const x = req?.body?.user?.name;',
      '  return x;',
      '}',
    ].join('\n'),
  },
  {
    name: 'null-safety: chain in return',
    template: NullSafetyTemplate,
    filePath: 'a.ts',
    before: [
      'function g(obj) {',
      '  return obj.nested.field.value;',
      '}',
    ].join('\n'),
    line: 2,
    findingType: 'null-safety',
    description: 'Deep property access without null check',
    expectApplied: true,
    expectAfter: [
      'function g(obj) {',
      '  return obj?.nested?.field?.value;',
      '}',
    ].join('\n'),
  },
  {
    name: 'null-safety: skip when chain is on assignment LHS',
    template: NullSafetyTemplate,
    filePath: 'a.ts',
    before: [
      'function h(obj, val) {',
      '  obj.a.b.c = val;',
      '}',
    ].join('\n'),
    line: 2,
    findingType: 'null-safety',
    description: 'Deep property access without null check',
    expectApplied: false,
    // The per-chain LHS check skips this chain individually, leaving no
    // chains to rewrite, so the final reason is "no chains found".
    expectSkipReasonIncludes: 'no deep access chain found',
  },
  {
    name: 'null-safety: skip when already optional-chained',
    template: NullSafetyTemplate,
    filePath: 'a.ts',
    before: [
      'function k(obj) {',
      '  return obj?.a?.b?.c;',
      '}',
    ].join('\n'),
    line: 2,
    findingType: 'null-safety',
    description: 'Deep property access without null check',
    expectApplied: false,
    expectSkipReasonIncludes: 'already uses optional chaining',
  },
  {
    name: 'null-safety: refuse to handle wrong finding type',
    template: NullSafetyTemplate,
    filePath: 'a.ts',
    before: 'const x = a.b.c;\n',
    line: 1,
    findingType: 'error-boundary',
    description: 'irrelevant',
    expectApplied: false,
    expectSkipReasonIncludes: 'does not handle',
  },

  // ── error-boundary (JSON.parse) ──────────────────────────────────────────
  {
    name: 'error-boundary: const-bound JSON.parse',
    template: ErrorBoundaryTemplate,
    filePath: 'r.ts',
    before: [
      'function handler(req) {',
      '  const data = JSON.parse(req.body);',
      '  return data;',
      '}',
    ].join('\n'),
    line: 2,
    findingType: 'error-boundary',
    description: 'JSON.parse() without try/catch',
    expectApplied: true,
    // We don't lock in the EXACT text — too brittle. Just check that the
    // transform produced try/catch + the original assignment lives inside.
  },
  {
    name: 'error-boundary: return JSON.parse',
    template: ErrorBoundaryTemplate,
    filePath: 'r.ts',
    before: [
      'function pluck(s) {',
      '  return JSON.parse(s);',
      '}',
    ].join('\n'),
    line: 2,
    findingType: 'error-boundary',
    description: 'JSON.parse() without try/catch',
    expectApplied: true,
  },
  {
    name: 'error-boundary: skip when already in try',
    template: ErrorBoundaryTemplate,
    filePath: 'r.ts',
    before: [
      'function safeHandler(req) {',
      '  try {',
      '    const data = JSON.parse(req.body);',
      '    return data;',
      '  } catch (err) {',
      '    return null;',
      '  }',
      '}',
    ].join('\n'),
    line: 3,
    findingType: 'error-boundary',
    description: 'JSON.parse() without try/catch',
    expectApplied: false,
    expectSkipReasonIncludes: 'already be inside a try',
  },
  {
    name: 'error-boundary: skip when description is non-JSON.parse',
    template: ErrorBoundaryTemplate,
    filePath: 'r.ts',
    before: 'fetch(url);\n',
    line: 1,
    findingType: 'error-boundary',
    description: 'fetch without error handling',
    expectApplied: false,
    expectSkipReasonIncludes: 'does not mention JSON.parse',
  },
  {
    name: 'error-boundary: .js file must use plain err.message, not (err as Error)',
    template: ErrorBoundaryTemplate,
    filePath: 'loader.js',
    before: 'const conf = JSON.parse(configFile);\n',
    line: 1,
    findingType: 'error-boundary',
    description: 'JSON.parse() without try/catch',
    expectApplied: true,
    // Don't lock in exact text; just ensure the output compiles as JS.
    // We verify separately that the patched source doesn't contain `as Error`.
  },
  {
    name: 'error-boundary: .ts file should use (err as Error).message',
    template: ErrorBoundaryTemplate,
    filePath: 'r.ts',
    before: 'const conf = JSON.parse(configFile);\n',
    line: 1,
    findingType: 'error-boundary',
    description: 'JSON.parse() without try/catch',
    expectApplied: true,
  },

  // ── hardcoded-secret ────────────────────────────────────────────────────
  {
    name: 'hardcoded-secret: API key const declaration',
    template: HardcodedSecretTemplate,
    filePath: 'c.ts',
    before: [
      'const API_KEY = "sk-proj-abc123456789def";',
      'export { API_KEY };',
    ].join('\n'),
    line: 1,
    findingType: 'hardcoded-secret',
    description: 'Hardcoded API key in source file',
    expectApplied: true,
    expectAfter: [
      'const API_KEY = process.env.API_KEY ?? \'\';',
      'export { API_KEY };',
    ].join('\n'),
  },
  {
    name: 'hardcoded-secret: JWT secret with obvious var name',
    template: HardcodedSecretTemplate,
    filePath: 'c.ts',
    before: `  const jwtSecret = "my-super-secret-signing-key";\n`,
    line: 1,
    findingType: 'hardcoded-secret',
    description: 'JWT secret hardcoded',
    expectApplied: true,
  },
  {
    name: 'hardcoded-secret: skip short literal',
    template: HardcodedSecretTemplate,
    filePath: 'c.ts',
    before: 'const mode = "dev";\n',
    line: 1,
    findingType: 'hardcoded-secret',
    description: 'possibly a secret',
    expectApplied: false,
    expectSkipReasonIncludes: 'does not look like a secret',
  },
  {
    name: 'hardcoded-secret: skip URL values',
    template: HardcodedSecretTemplate,
    filePath: 'c.ts',
    before: 'const API_URL = "https://api.example.com/v1/users";\n',
    line: 1,
    findingType: 'hardcoded-secret',
    description: 'possibly a secret',
    expectApplied: false,
    expectSkipReasonIncludes: 'does not look like a secret',
  },
  {
    name: 'hardcoded-secret: skip already-using-env',
    template: HardcodedSecretTemplate,
    filePath: 'c.ts',
    before: 'const API_KEY = process.env.API_KEY;\n',
    line: 1,
    findingType: 'hardcoded-secret',
    description: 'placeholder',
    expectApplied: false,
    expectSkipReasonIncludes: 'already reads from process.env',
  },
  {
    name: 'hardcoded-secret: this.token assignment',
    template: HardcodedSecretTemplate,
    filePath: 'c.ts',
    before: '    this.token = "xoxb-1234567890-abcdefghij";\n',
    line: 1,
    findingType: 'hardcoded-secret',
    description: 'Slack bot token hardcoded',
    expectApplied: true,
  },
];

function applyPatch(beforeText: string, patch: string): string {
  // Minimal apply: parse our own diff format (we wrote it, we know its shape)
  const lines = beforeText.split('\n');
  const hunks = patch.split(/^@@/m).slice(1);
  const out = [...lines];
  for (let h = hunks.length - 1; h >= 0; h--) {
    const hunkText = '@@' + hunks[h];
    const headerMatch = hunkText.match(/^@@ -(\d+),(\d+) \+\d+,\d+ @@/);
    if (!headerMatch) continue;
    const oldStart = parseInt(headerMatch[1], 10);
    const oldCount = parseInt(headerMatch[2], 10);
    const body = hunkText.split('\n').slice(1);
    const newSeg: string[] = [];
    for (const l of body) {
      if (l.startsWith(' ') || l.startsWith('+')) newSeg.push(l.slice(1));
      // skip removals
    }
    out.splice(oldStart - 1, oldCount, ...newSeg);
  }
  return out.join('\n');
}

let pass = 0;
let fail = 0;

for (const c of cases) {
  const result = c.template.attempt({
    filePath: c.filePath,
    fileContents: c.before,
    line: c.line,
    findingType: c.findingType,
    description: c.description,
  });

  const ok = (() => {
    if (result.applied !== c.expectApplied) return false;
    if (!c.expectApplied) {
      if (c.expectSkipReasonIncludes && !(result.skipReason ?? '').includes(c.expectSkipReasonIncludes)) {
        return false;
      }
      return true;
    }
    if (c.expectAfter !== undefined) {
      const after = applyPatch(c.before, result.patch);
      if (after.trimEnd() !== c.expectAfter.trimEnd()) {
        console.log('    expected:\n' + c.expectAfter);
        console.log('    got:\n' + after);
        return false;
      }
    } else {
      // No exact expectation — just ensure the patch is non-empty and
      // produces something that contains "try" and "catch" for the
      // error-boundary cases.
      const after = applyPatch(c.before, result.patch);
      if (c.template === ErrorBoundaryTemplate && !(after.includes('try {') && after.includes('catch ('))) {
        console.log('    error-boundary patch did not produce try/catch:\n' + after);
        return false;
      }
      // JS files must not contain TS cast syntax
      if (c.template === ErrorBoundaryTemplate && c.filePath.endsWith('.js') && after.includes('as Error')) {
        console.log('    .js file incorrectly emitted TS cast syntax:\n' + after);
        return false;
      }
      // TS files must use the TS cast for consistency
      if (c.template === ErrorBoundaryTemplate && c.filePath.endsWith('.ts') && !after.includes('as Error')) {
        console.log('    .ts file missing TS cast syntax:\n' + after);
        return false;
      }
    }
    return true;
  })();

  if (ok) {
    console.log(`  ✓ ${c.name}`);
    pass++;
  } else {
    console.log(`  ✗ ${c.name}`);
    if (result.skipReason) console.log(`    skip reason: ${result.skipReason}`);
    fail++;
  }
}

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);

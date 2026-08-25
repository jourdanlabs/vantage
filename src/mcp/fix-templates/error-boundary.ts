// Error-boundary template — wraps JSON.parse calls in try/catch.
//
// Target pattern:
//   const data = JSON.parse(req.body);
// →
//   let data;
//   try {
//     data = JSON.parse(req.body);
//   } catch (err) {
//     // VANTAGE auto-fix: malformed JSON would otherwise crash this handler.
//     // Replace this stub with appropriate error handling for your context.
//     throw new Error(`Invalid JSON: ${(err as Error).message}`);
//   }
//
// Other supported shapes:
//   return JSON.parse(x);   →  same wrap, returning from the catch
//   foo(JSON.parse(x));     →  hoist JSON.parse to a let, wrap, then call foo
//
// NOT handled (skip → LLM fallback):
//   - JSON.parse already inside a try block
//   - JSON.parse used as an expression deeply nested in a larger statement
//   - Any pattern PULSAR is right about but the template can't safely express
//
// The "throw new Error" stub is deliberate: silently swallowing the error is
// usually worse than the original bug. A throw at least surfaces the malformed
// input. Users can replace the catch body with whatever their app needs.

import { FixTemplate, TemplateInput, TemplateOutput } from './types';
import { makeUnifiedDiff, indentOf } from './diff';

const TEMPLATE_ID = 'error-boundary-jsonparse-trycatch';

const JSON_PARSE_RE = /\bJSON\.parse\b/;

// Recognize the common variable-binding shapes so we can rewrite them
// into try/catch with a hoisted declaration.
const ASSIGN_RE = /^(\s*)(const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(JSON\.parse\(.+?\)\s*);?\s*$/;
const RETURN_RE = /^(\s*)return\s+(JSON\.parse\(.+?\)\s*);?\s*$/;
const STMT_RE   = /^(\s*)([A-Za-z_$][\w$.]*\s*=\s*)?(JSON\.parse\(.+?\))\s*;?\s*$/;

export const ErrorBoundaryTemplate: FixTemplate = {
  id: TEMPLATE_ID,
  supportedFindingTypes: ['error-boundary', 'missing-error-handling'],

  attempt(input: TemplateInput): TemplateOutput {
    const skip = (reason: string): TemplateOutput => ({
      applied: false,
      patch: '',
      rationale: '',
      templateId: TEMPLATE_ID,
      skipReason: reason,
    });

    if (!this.supportedFindingTypes.includes(input.findingType)) {
      return skip(`template does not handle finding type "${input.findingType}"`);
    }

    // Only handle JSON.parse-flavored error-boundary findings; other
    // error-boundary patterns (network, FS) need their own templates.
    if (!/JSON\.parse/i.test(input.description)) {
      return skip('description does not mention JSON.parse — out of template scope');
    }

    const lines = input.fileContents.split('\n');
    if (input.line < 1 || input.line > lines.length) {
      return skip(`finding line ${input.line} is outside file (${lines.length} lines)`);
    }

    const original = lines[input.line - 1];

    if (!JSON_PARSE_RE.test(original)) {
      return skip(`no JSON.parse on line ${input.line}`);
    }

    // Skip if already inside a try block — look backwards for an unmatched `try {`
    // before any `catch`/`finally`. A real AST would handle this correctly;
    // text-based check is approximate. The verify_fix gate will catch the
    // case where we missed an existing try and rewrote it anyway, since
    // the patch would either fail to apply or the finding would persist.
    if (isAlreadyInTry(lines, input.line)) {
      return skip('JSON.parse appears to already be inside a try block');
    }

    const indent = indentOf(original);
    const innerIndent = indent + '  ';

    // Emit TS-style `(err as Error).message` for .ts files; plain `err.message`
    // for .js. Getting this right is non-optional — TS cast syntax breaks the
    // file as JS, and verify_fix's parser is permissive enough to miss that.
    const isTs = /\.tsx?$/i.test(input.filePath);
    const errExpr = isTs ? '(err as Error).message' : 'err.message';

    // Pattern 1: `const x = JSON.parse(...)` (or let/var)
    const assignM = original.match(ASSIGN_RE);
    if (assignM) {
      const [, , kw, name, expr] = assignM;
      // Use `let` so the declaration is mutable inside the try; if user wrote
      // const, surfacing that constraint to them via a comment is cleaner than
      // silently weakening it.
      const constNote = kw === 'const' ? ` // (was: const)` : '';
      const newLines = [
        `${indent}let ${name};${constNote}`,
        `${indent}try {`,
        `${innerIndent}${name} = ${expr.trim().replace(/;\s*$/, '')};`,
        `${indent}} catch (err) {`,
        `${innerIndent}// VANTAGE auto-fix: malformed JSON would crash the caller.`,
        `${innerIndent}throw new Error(\`Invalid JSON in ${name}: \${${errExpr}}\`);`,
        `${indent}}`,
      ];
      return success(input, lines, newLines, `Hoisted \`${name}\` declaration and wrapped \`JSON.parse\` in a try/catch that re-throws with context.`);
    }

    // Pattern 2: `return JSON.parse(...)`
    const returnM = original.match(RETURN_RE);
    if (returnM) {
      const [, , expr] = returnM;
      const newLines = [
        `${indent}try {`,
        `${innerIndent}return ${expr.trim().replace(/;\s*$/, '')};`,
        `${indent}} catch (err) {`,
        `${innerIndent}// VANTAGE auto-fix: malformed JSON would crash the caller.`,
        `${innerIndent}throw new Error(\`Invalid JSON: \${${errExpr}}\`);`,
        `${indent}}`,
      ];
      return success(input, lines, newLines, `Wrapped the \`return JSON.parse(...)\` in a try/catch that re-throws with context.`);
    }

    // Pattern 3: bare expression statement (rare — usually side-effect of throwing on bad input)
    const stmtM = original.match(STMT_RE);
    if (stmtM) {
      const [, , lhs = '', expr] = stmtM;
      const inner = lhs ? `${lhs}${expr};` : `${expr};`;
      const newLines = [
        `${indent}try {`,
        `${innerIndent}${inner}`,
        `${indent}} catch (err) {`,
        `${innerIndent}// VANTAGE auto-fix: malformed JSON would crash the caller.`,
        `${innerIndent}throw new Error(\`Invalid JSON: \${${errExpr}}\`);`,
        `${indent}}`,
      ];
      return success(input, lines, newLines, `Wrapped the \`JSON.parse\` statement in a try/catch.`);
    }

    return skip('JSON.parse appears in a non-statement context (nested expression, callback arg) that the template cannot rewrite safely');
  },
};

function success(
  input: TemplateInput,
  lines: string[],
  newLines: string[],
  rationale: string
): TemplateOutput {
  const patch = makeUnifiedDiff({
    filePath: input.filePath,
    originalLines: lines,
    changes: [{ oldStart: input.line, oldCount: 1, newLines }],
  });
  return {
    applied: true,
    patch,
    rationale,
    templateId: TEMPLATE_ID,
  };
}

/**
 * Cheap heuristic: scan backwards from the finding line for an unmatched
 * `try {` that hasn't been closed by a `catch`/`finally`. Approximate but
 * good enough to catch the obvious case. A real AST is the correct tool;
 * the verify_fix gate is the safety net.
 */
function isAlreadyInTry(lines: string[], lineNo: number): boolean {
  let depth = 0;
  for (let i = lineNo - 1; i >= 0; i--) {
    const l = lines[i];
    if (/\bcatch\s*\(/.test(l) || /\bfinally\s*\{/.test(l)) {
      // Encountered a closer first — not in an open try
      return false;
    }
    if (/\btry\s*\{/.test(l)) {
      // Found an unmatched try
      return depth === 0;
    }
    // Track braces to handle nested blocks crudely
    for (const ch of l) {
      if (ch === '{') depth--;
      else if (ch === '}') depth++;
    }
    if (depth < 0) return false; // walked out of scope
  }
  return false;
}

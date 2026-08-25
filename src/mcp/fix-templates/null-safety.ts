// Null-safety template — converts deep property access to optional chaining.
//
// Target pattern (what PULSAR flags):
//   const x = a.b.c.d;           →  const x = a?.b?.c?.d;
//   return foo.bar.baz;          →  return foo?.bar?.baz;
//   obj.nested.field.method();   →  obj?.nested?.field?.method();
//
// Explicitly NOT handled by this template (falls through to "did not apply",
// eventually the LLM path):
//   - Assignment LHS:              a.b.c = x   — optional chaining is invalid here
//   - Single-level access:         a.b         — not a "deep" chain, PULSAR shouldn't
//                                                 flag this anyway
//   - Destructuring:               const { x } = a.b.c
//                                                — optional chaining has no destructuring
//                                                 form; leave for LLM fallback
//   - Multi-line chains            — the text match operates on one line; templates that
//                                     span lines need AST.
//
// This template is deliberately conservative. The verify_fix gate will catch
// bad rewrites (finding persists, new HIGH findings appear). Preferring to
// skip over a marginal case than to ship a wrong patch is the contract.

import { FixTemplate, TemplateInput, TemplateOutput } from './types';
import { makeUnifiedDiff } from './diff';

const TEMPLATE_ID = 'null-safety-optional-chaining';

// Matches a property access chain: `ident.ident.ident...` with at least 3 parts
// (the "deep" threshold PULSAR uses). Allows method calls at the tail.
const DEEP_CHAIN_RE = /\b([A-Za-z_$][\w$]*)(\.[A-Za-z_$][\w$]*){2,}(\?\s*\(|\()?/g;

// Patterns that disqualify the line. If any match, skip.
//
// We deliberately do NOT include a generic `=` disqualifier — that would
// reject `const x = req.body.user.name` even though the chain is on the
// RHS of the assignment, not the LHS. The per-chain LHS check happens
// inside the replace callback below: a chain followed by `=` (not `==`,
// `===`, or `=>`) is on the LHS and is skipped individually.
const DISQUALIFIERS: Array<{ re: RegExp; reason: string }> = [
  { re: /\?\./, reason: 'line already uses optional chaining' },
  { re: /^\s*(const|let|var)\s*\{/, reason: 'destructuring — no optional-chaining form' },
  { re: /^\s*\{/, reason: 'object literal or destructuring on its own line' },
];

export const NullSafetyTemplate: FixTemplate = {
  id: TEMPLATE_ID,
  supportedFindingTypes: ['null-safety'],

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

    const lines = input.fileContents.split('\n');
    if (input.line < 1 || input.line > lines.length) {
      return skip(`finding line ${input.line} is outside file (${lines.length} lines)`);
    }

    // Consider the finding line plus the two neighbors in case the access
    // wraps onto an adjacent line. We still rewrite a single line; the
    // multi-line case is intentionally out-of-scope for v0.
    const original = lines[input.line - 1];

    // Check disqualifiers
    for (const d of DISQUALIFIERS) {
      if (d.re.test(original)) {
        return skip(`disqualifier: ${d.reason}`);
      }
    }

    // Find chains on the line and rewrite them
    let rewritten = original;
    let chainsFixed = 0;

    rewritten = rewritten.replace(DEEP_CHAIN_RE, (match, _p1, _p2, _p3, offset: number, full: string) => {
      // Don't touch chains that already contain `?.` (belt-and-braces)
      if (match.includes('?.')) return match;

      // LHS check: if the chain is immediately followed by a single `=`
      // (not `==`, `===`, `=>`, `!=`, `<=`, `>=`), then it's the LHS of
      // an assignment and optional chaining is a syntax error there.
      // Member assignments look like `obj.a.b = x`.
      const afterIdx = offset + match.length;
      const afterContext = full.slice(afterIdx);
      const lhsRe = /^\s*=(?!=|>)/;
      if (lhsRe.test(afterContext)) {
        return match; // skip this particular chain
      }

      chainsFixed++;
      // Split into segments. First segment stays as-is; rest get `?.`.
      // Handle tail: if match ends with `(` or `?(`, preserve that suffix.
      let suffix = '';
      let core = match;
      const callMatch = core.match(/(\?\s*\(|\()$/);
      if (callMatch) {
        suffix = callMatch[0];
        core = core.slice(0, core.length - suffix.length);
      }
      const segments = core.split('.');
      const rewrittenCore = segments[0] + segments.slice(1).map(s => '?.' + s).join('');
      return rewrittenCore + suffix;
    });

    if (chainsFixed === 0 || rewritten === original) {
      return skip('no deep access chain found on finding line, or line already safe');
    }

    const patch = makeUnifiedDiff({
      filePath: input.filePath,
      originalLines: lines,
      changes: [{ oldStart: input.line, oldCount: 1, newLines: [rewritten] }],
    });

    return {
      applied: true,
      patch,
      rationale: `Rewrote ${chainsFixed} deep property-access chain${chainsFixed === 1 ? '' : 's'} on line ${input.line} to use optional chaining (\`?.\`), so a null or undefined intermediate value short-circuits to \`undefined\` instead of throwing a TypeError.`,
      templateId: TEMPLATE_ID,
    };
  },
};

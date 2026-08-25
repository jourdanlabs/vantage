// Hardcoded-secret template — moves a literal secret into an env var.
//
// Target patterns:
//   const API_KEY = "sk-abc123...";           → const API_KEY = process.env.API_KEY;
//   let jwtSecret = 'my-super-secret';         → let jwtSecret = process.env.JWT_SECRET;
//   this.token = "xoxb-...";                   → this.token = process.env.TOKEN;
//   crypto.createHmac('sha256', 'secret');     → crypto.createHmac('sha256', process.env.HMAC_SECRET);
//
// The transform also emits the variable name + suggested env var into the
// patch's rationale, so generate_fix output includes an actionable checklist
// for the deploy side ("remember to add SECRET_NAME=... to your .env and
// your production config"). The patch itself is conservative: one-line edit,
// no files created, no imports added.
//
// Skip (falls through to LLM or "no fix available"):
//   - Test fixtures with obviously-fake values (we detect this heuristically)
//   - Values that are short enough to plausibly not be secrets (< 12 chars)
//   - Lines where the "secret" is already process.env.*
//   - Values that look like file paths or URLs (likely not actual secrets)
//   - Multi-line string literals

import { FixTemplate, TemplateInput, TemplateOutput } from './types';
import { makeUnifiedDiff } from './diff';

const TEMPLATE_ID = 'hardcoded-secret-to-env';

// Common variable-name roots that signal a secret. Case-insensitive match.
const SECRET_NAME_HINTS = [
  'secret', 'password', 'passwd', 'pwd', 'token', 'api_key', 'apikey',
  'auth', 'credential', 'private_key', 'privatekey', 'access_key', 'accesskey',
  'session_secret', 'jwt', 'hmac', 'signing_key', 'signingkey',
];

// Patterns that look like real secrets in the *value*
const LOOKS_SECRET_RE = /^(sk-|pk_|xox[aboprs]-|ghp_|ghu_|ghs_|gho_|github_pat_|AKIA|AIza|-----BEGIN [A-Z]+ ?KEY-----)/;

// Patterns that look like file paths, URLs, or config strings — skip
const NOT_SECRET_RE = /^(https?:\/\/|\/[a-z]|\.\/|\.\.\/|[A-Za-z]:\\|localhost|\d+\.\d+\.\d+|(?:true|false|null)$)/i;

// Matches variable declarations with a string literal value.
// Groups: 1=indent, 2=kw (const|let|var), 3=name, 4=quote, 5=value
const DECL_RE = /^(\s*)(const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?\s*=\s*(['"`])((?:(?!\4).)+)\4\s*;?\s*$/;

// Matches property assignment with a string literal value.
// Groups: 1=indent, 2=lhs (e.g., this.token), 3=quote, 4=value
const PROP_ASSIGN_RE = /^(\s*)((?:this\.)?[A-Za-z_$][\w$.]*)\s*=\s*(['"`])((?:(?!\3).)+)\3\s*;?\s*$/;

// Matches a function call where one argument is a string literal that looks like a secret.
// e.g., createHmac('sha256', 'literal-secret')
// Groups: 1=indent, 2=call+args-prefix, 3=quote, 4=value, 5=call+args-suffix
// This is intentionally conservative: only touches calls where the literal
// passes the secret heuristics.
const CALL_ARG_RE = /^(\s*)(.*?\()(['"])([^'"`]{12,})\3(.*\).*)$/;

export const HardcodedSecretTemplate: FixTemplate = {
  id: TEMPLATE_ID,
  supportedFindingTypes: ['hardcoded-secret'],

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

    const original = lines[input.line - 1];

    // Already using env var
    if (/process\.env\./.test(original)) {
      return skip('line already reads from process.env');
    }

    // Try declaration shape first
    const declMatch = original.match(DECL_RE);
    if (declMatch) {
      const [, indent, kw, name, , value] = declMatch;
      if (!looksLikeSecret(name, value)) {
        return skip(`value does not look like a secret (name="${name}", value len=${value.length})`);
      }
      const envName = toEnvName(name);
      const rewritten = `${indent}${kw} ${name} = process.env.${envName} ?? '';`;
      return makeResult(input, lines, rewritten, name, envName, value);
    }

    // Try property assignment shape
    const propMatch = original.match(PROP_ASSIGN_RE);
    if (propMatch) {
      const [, indent, lhs, , value] = propMatch;
      const nameForEnv = lhs.split('.').pop() ?? lhs;
      if (!looksLikeSecret(nameForEnv, value)) {
        return skip(`value does not look like a secret (lhs="${lhs}", value len=${value.length})`);
      }
      const envName = toEnvName(nameForEnv);
      const rewritten = `${indent}${lhs} = process.env.${envName} ?? '';`;
      return makeResult(input, lines, rewritten, nameForEnv, envName, value);
    }

    // Try call-argument shape (e.g., createHmac('sha256', 'literal'))
    const callMatch = original.match(CALL_ARG_RE);
    if (callMatch) {
      const [, indent, prefix, , value, suffix] = callMatch;
      // Need a reasonable env name from context — use a nearby variable if there's one,
      // otherwise the function name.
      const callContext = prefix.match(/([A-Za-z_$][\w$]*)\s*\(/);
      const contextName = callContext ? callContext[1] : 'secret';
      if (!looksLikeSecret(contextName, value) && !LOOKS_SECRET_RE.test(value)) {
        return skip(`literal does not match a known secret pattern (context="${contextName}")`);
      }
      const envName = toEnvName(contextName) + '_SECRET';
      const rewritten = `${indent}${prefix}process.env.${envName} ?? ''${suffix}`;
      return makeResult(input, lines, rewritten, contextName, envName, value);
    }

    return skip('no matched declaration/assignment/call pattern with a string-literal secret');
  },
};

function looksLikeSecret(name: string, value: string): boolean {
  // Value-level heuristics
  if (value.length < 12) return false;
  if (NOT_SECRET_RE.test(value)) return false;
  if (LOOKS_SECRET_RE.test(value)) return true;

  // Name-level heuristic: any hint substring matches (case-insensitive)
  const lower = name.toLowerCase();
  for (const hint of SECRET_NAME_HINTS) {
    if (lower.includes(hint)) {
      // Additional filter: bail on values that are clearly enum-like or test fixtures
      if (value.length > 200) return false; // likely a whole config blob
      return true;
    }
  }
  return false;
}

function toEnvName(varName: string): string {
  // myApiKey → MY_API_KEY
  // this.jwtSecret → JWT_SECRET (we get just "jwtSecret" in)
  const snake = varName
    .replace(/([a-z\d])([A-Z])/g, '$1_$2')
    .replace(/[-\s]+/g, '_')
    .toUpperCase();
  return snake.replace(/_+/g, '_').replace(/^_|_$/g, '');
}

function makeResult(
  input: TemplateInput,
  lines: string[],
  rewritten: string,
  varName: string,
  envName: string,
  originalValue: string
): TemplateOutput {
  const patch = makeUnifiedDiff({
    filePath: input.filePath,
    originalLines: lines,
    changes: [{ oldStart: input.line, oldCount: 1, newLines: [rewritten] }],
  });

  const valuePreview = originalValue.length > 40
    ? originalValue.slice(0, 20) + '…' + originalValue.slice(-8)
    : originalValue;

  return {
    applied: true,
    patch,
    rationale:
      `Replaced hardcoded secret value (${valuePreview}) in \`${varName}\` with ` +
      `\`process.env.${envName}\`. Remember to: (1) add \`${envName}=${valuePreview}\` to ` +
      `your production secrets manager, (2) add \`${envName}=\` (without the value) to ` +
      `\`.env.example\` if the project has one, (3) rotate the previously-exposed secret ` +
      `since it's been in version control.`,
    templateId: TEMPLATE_ID,
  };
}

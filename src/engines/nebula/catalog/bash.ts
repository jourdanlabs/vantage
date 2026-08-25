// Bash-only source / sink / sanitizer catalog for NEBULA.
// Language-selected at the Bash frontend. Do not merge into javascript.ts.
// Built against BenchProctor bash quicktest enumeration (45 categories).
// Development set: bash-quicktest/standalone. Sealed hold-out: bash-normal — do not score.

import { TaintSource, TaintSink, Sanitizer } from './javascript';
import { ModuleImport } from '../ir';

export const BASH_SOURCES: TaintSource[] = [
  { id: 'bash.user_input', fieldPath: ['user_input'], kind: 'user-input', description: 'user_input — BenchProctor attacker stand-in' },
  { id: 'bash.env', fieldPath: ['env'], kind: 'user-input', description: 'HTTP_* / QUERY_STRING / APP_INPUT' },
];

export const BASH_SINKS: TaintSink[] = [
  { id: 'eval', calleePath: ['eval'], dangerousArgs: [0], danger: 'command-injection', description: 'eval — command injection' },
  { id: 'bash', calleePath: ['bash'], dangerousArgs: [1], danger: 'command-injection', description: 'bash -c' },
  { id: 'curl', calleePath: ['curl'], dangerousArgs: [0, 1, 2], danger: 'ssrf', description: 'curl URL — SSRF' },
  { id: 'mysql', calleePath: ['mysql'], dangerousArgs: [1, 2], danger: 'sql-injection', description: 'mysql -e concat SQL' },
  { id: 'mongosh', calleePath: ['mongosh'], dangerousArgs: [1], danger: 'sql-injection', description: 'mongosh --eval' },
  { id: 'ldapsearch', calleePath: ['ldapsearch'], dangerousArgs: [4], danger: 'sql-injection', description: 'ldapsearch filter' },
  { id: 'tar', calleePath: ['tar'], dangerousArgs: [2, 3], danger: 'command-injection', description: 'tar unquoted args' },
  { id: 'logger', calleePath: ['logger'], dangerousArgs: [0], danger: 'template-injection', description: 'logger — log injection' },
];

export const BASH_SANITIZERS: Sanitizer[] = [
  { id: 'bash.basename', calleePath: ['basename'], sanitizesArgs: [0], against: ['ssrf'], description: 'basename strips directories' },
];

export function matchBashSinkExtra(path: string[], _imports: ModuleImport[]): TaintSink | null {
  const tail = path[path.length - 1];
  if (tail === 'eval') {
    return { id: 'eval.any', calleePath: path, dangerousArgs: [0], danger: 'command-injection', description: 'eval' };
  }
  if (tail === 'curl') {
    return { id: 'curl.any', calleePath: path, dangerousArgs: [0, 1], danger: 'ssrf', description: 'curl' };
  }
  return null;
}

export function matchBashSanitizerExtra(_path: string[], _imports: ModuleImport[]): Sanitizer | null {
  return null;
}

export function matchBashCallSourceExtra(path: string[], _imports: ModuleImport[]): TaintSource | null {
  const tail = path[path.length - 1];
  if (tail === 'cat' || tail === 'read') {
    return { id: 'bash.stdin', fieldPath: ['stdin'], kind: 'user-input', description: 'stdin' };
  }
  return null;
}

export const BASH_CATALOG_EXTRAS = {
  numericSizeSinkIds: [] as string[],
};

// C-only source / sink / sanitizer catalog for NEBULA.
// Language-selected at the C frontend. Do not merge into javascript.ts.
// Built against BenchProctor C quicktest enumeration (34 categories).
// Development set: c-quicktest/standalone. Sealed hold-out: c-normal — do not score.

import { TaintSource, TaintSink, Sanitizer } from './javascript';
import { ModuleImport } from '../ir';

export const C_SOURCES: TaintSource[] = [
  { id: 'c.argv', fieldPath: ['argv'], kind: 'user-input', description: 'argv — command-line args (BenchProctor attacker stand-in)' },
  { id: 'c.getenv', fieldPath: ['getenv'], kind: 'user-input', description: 'getenv — USER_INPUT / QUERY_STRING / CONTENT_LENGTH are attacker-controlled in BP' },
  { id: 'c.stdin', fieldPath: ['stdin'], kind: 'user-input', description: 'stdin / fread / fgets — request body stand-in' },
];

export const C_SINKS: TaintSink[] = [
  { id: 'c.system', calleePath: ['system'], dangerousArgs: [0], danger: 'command-injection', description: 'system() — command injection' },
  { id: 'c.execl', calleePath: ['execl'], dangerousArgs: [0, 1, 2, 3], danger: 'command-injection', description: 'execl — command injection' },
  { id: 'c.execv', calleePath: ['execv'], dangerousArgs: [0], danger: 'command-injection', description: 'execv(program) — command injection (argv is argument injection)' },
  { id: 'c.execvp', calleePath: ['execvp'], dangerousArgs: [0, 1], danger: 'command-injection', description: 'execvp — command injection' },
  { id: 'c.popen', calleePath: ['popen'], dangerousArgs: [0], danger: 'command-injection', description: 'popen — command injection' },
  { id: 'c.fopen', calleePath: ['fopen'], dangerousArgs: [0], danger: 'ssrf', description: 'fopen with user path — path traversal' },
  { id: 'c.open', calleePath: ['open'], dangerousArgs: [0], danger: 'ssrf', description: 'open() with user path' },
  { id: 'c.remove', calleePath: ['remove'], dangerousArgs: [0], danger: 'ssrf', description: 'remove() with user path' },
  { id: 'c.unlink', calleePath: ['unlink'], dangerousArgs: [0], danger: 'ssrf', description: 'unlink() with user path' },
  { id: 'c.sqlite3_exec', calleePath: ['sqlite3_exec'], dangerousArgs: [1], danger: 'sql-injection', description: 'sqlite3_exec concatenated SQL' },
  { id: 'c.ldap_search_ext_s', calleePath: ['ldap_search_ext_s'], dangerousArgs: [1, 3], danger: 'sql-injection', description: 'ldap_search_ext_s filter — LDAP injection' },
  { id: 'c.xmlReadMemory', calleePath: ['xmlReadMemory'], dangerousArgs: [0], danger: 'code-execution', description: 'xmlReadMemory of user XML — XXE' },
  { id: 'c.xmlXPathEvalExpression', calleePath: ['xmlXPathEvalExpression'], dangerousArgs: [0], danger: 'sql-injection', description: 'xpath of user expression' },
  { id: 'c.getaddrinfo', calleePath: ['getaddrinfo'], dangerousArgs: [0], danger: 'ssrf', description: 'getaddrinfo with user host — SSRF' },
  { id: 'c.connect', calleePath: ['connect'], dangerousArgs: [0], danger: 'ssrf', description: 'connect — SSRF' },
  { id: 'c.curl_easy_setopt', calleePath: ['curl_easy_setopt'], dangerousArgs: [2], danger: 'ssrf', description: 'curl_easy_setopt URL — SSRF' },
  { id: 'c.printf', calleePath: ['printf'], dangerousArgs: [0], danger: 'template-injection', description: 'printf with user data — log / format' },
  { id: 'c.fprintf', calleePath: ['fprintf'], dangerousArgs: [1], danger: 'template-injection', description: 'fprintf with user data — log injection' },
  { id: 'c.syslog', calleePath: ['syslog'], dangerousArgs: [1], danger: 'template-injection', description: 'syslog with user data' },
  { id: 'c.setuid', calleePath: ['setuid'], dangerousArgs: [0], danger: 'ssrf', description: 'setuid(tainted uid) — privilege escalation' },
  { id: 'c.setgid', calleePath: ['setgid'], dangerousArgs: [0], danger: 'ssrf', description: 'setgid(tainted gid)' },
  { id: 'c.malloc', calleePath: ['malloc'], dangerousArgs: [0], danger: 'ssrf', description: 'malloc(tainted size) — resource exhaustion' },
  { id: 'c.calloc', calleePath: ['calloc'], dangerousArgs: [0, 1], danger: 'ssrf', description: 'calloc(tainted size)' },
  { id: 'c.realloc', calleePath: ['realloc'], dangerousArgs: [1], danger: 'ssrf', description: 'realloc(tainted size)' },
];

export const C_SANITIZERS: Sanitizer[] = [
  { id: 'c.basename', calleePath: ['basename'], sanitizesArgs: [0], against: ['ssrf'], description: 'basename strips directories' },
  { id: 'c.atoi', calleePath: ['atoi'], sanitizesArgs: [0], against: ['command-injection', 'sql-injection', 'code-execution', 'template-injection', 'redirect'], description: 'atoi — numeric coerce (not a size sanitizer)' },
  { id: 'c.strtol', calleePath: ['strtol'], sanitizesArgs: [0], against: ['command-injection', 'sql-injection', 'code-execution', 'template-injection', 'redirect'], description: 'strtol — numeric coerce' },
  { id: 'c.sqlite3_bind_text', calleePath: ['sqlite3_bind_text'], sanitizesArgs: [2], against: ['sql-injection'], description: 'sqlite3_bind_text parameterized' },
  { id: 'c.strncmp', calleePath: ['strncmp'], sanitizesArgs: [0], against: ['ssrf'], description: 'strncmp prefix allowlist — SSRF host check' },
];

export function matchCSinkExtra(path: string[], _imports: ModuleImport[]): TaintSink | null {
  const tail = path[path.length - 1];
  if (!tail) return null;
  if (/^exec[lv]p?e?$/.test(tail) || tail === 'system' || tail === 'popen') {
    return {
      id: `c.${tail}.any`,
      calleePath: path,
      dangerousArgs: tail === 'execl' ? [0, 1, 2, 3] : [0],
      danger: 'command-injection',
      description: `${tail} — command injection`,
    };
  }
  if (tail === 'sqlite3_exec') {
    return {
      id: 'c.sqlite3_exec.any',
      calleePath: path,
      dangerousArgs: [1],
      danger: 'sql-injection',
      description: 'sqlite3_exec concatenated SQL',
    };
  }
  if (tail === 'ldap_search_ext_s' || tail === 'ldap_search_s') {
    return {
      id: 'c.ldap.any',
      calleePath: path,
      dangerousArgs: [1, 3],
      danger: 'sql-injection',
      description: 'LDAP search filter injection',
    };
  }
  if (tail === 'xmlReadMemory' || tail === 'xmlReadFile' || tail === 'xmlParseMemory') {
    return {
      id: 'c.xml.read.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'code-execution',
      description: 'libxml read of user XML — XXE',
    };
  }
  if (tail === 'xmlXPathEvalExpression' || tail === 'xmlXPathEval') {
    return {
      id: 'c.xpath.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'XPath of user expression',
    };
  }
  if (tail === 'getaddrinfo' || tail === 'curl_easy_perform') {
    return {
      id: `c.${tail}.any`,
      calleePath: path,
      dangerousArgs: [0],
      danger: 'ssrf',
      description: `${tail} — SSRF`,
    };
  }
  return null;
}

export function matchCSanitizerExtra(path: string[], _imports: ModuleImport[]): Sanitizer | null {
  const tail = path[path.length - 1];
  if (tail === 'basename' || tail === 'dirname') {
    return {
      id: `c.${tail}.any`,
      calleePath: path,
      sanitizesArgs: [0],
      against: ['ssrf'],
      description: `${tail} strips path components`,
    };
  }
  if (tail === 'strncmp' || tail === 'strncasecmp') {
    return {
      id: `c.${tail}.any`,
      calleePath: path,
      sanitizesArgs: [0],
      against: ['ssrf'],
      description: `${tail} prefix allowlist — SSRF host check`,
    };
  }
  return null;
}

export function matchCCallSourceExtra(path: string[], _imports: ModuleImport[]): TaintSource | null {
  const tail = path[path.length - 1];
  if (tail === 'fgets' || tail === 'fread' || tail === 'fgetc' || tail === 'gets') {
    return {
      id: 'c.stdin',
      fieldPath: ['stdin'],
      kind: 'user-input',
      description: 'fgets/fread — attacker-controlled input',
    };
  }
  if (tail === 'getenv') {
    return {
      id: 'c.getenv',
      fieldPath: ['getenv'],
      kind: 'user-input',
      description: 'getenv — attacker-controlled in BP',
    };
  }
  return null;
}

export const C_CATALOG_EXTRAS = {
  numericSizeSinkIds: ['c.malloc', 'c.calloc', 'c.realloc', 'c.setuid', 'c.setgid'],
};

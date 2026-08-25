// PHP-only source / sink / sanitizer catalog for NEBULA.
// Language-selected at the PHP frontend. Do not merge into javascript.ts.
// Built against receipts/sealed-holdout/php-v1-normal-laravel-2026-08-20/CWE-ENUMERATION.md (CSV only).
// Development set: php-quicktest laravel + symfony. Sealed hold-out: php-normal/laravel — do not score.

import { TaintSource, TaintSink, Sanitizer } from './javascript';
import { ModuleImport } from '../ir';

export const PHP_SOURCES: TaintSource[] = [
  { id: 'php.request', fieldPath: ['request'], kind: 'user-input', description: 'Laravel/Symfony Request' },
  { id: 'php.request.header', fieldPath: ['request', 'header'], kind: 'user-input', description: 'Request::header' },
  { id: 'php.request.query', fieldPath: ['request', 'query'], kind: 'user-input', description: 'Request::query / query->get' },
  { id: 'php.request.input', fieldPath: ['request', 'input'], kind: 'user-input', description: 'Request::input' },
  { id: 'php.request.cookie', fieldPath: ['request', 'cookie'], kind: 'user-input', description: 'Request::cookie' },
  { id: 'php.request.json', fieldPath: ['request', 'json'], kind: 'user-input', description: 'Request::json' },
  { id: 'php.request.file', fieldPath: ['request', 'file'], kind: 'user-input', description: 'Request::file' },
  { id: 'php.request.headers', fieldPath: ['request', 'headers'], kind: 'user-input', description: 'Symfony headers bag' },
  { id: 'php.request.cookies', fieldPath: ['request', 'cookies'], kind: 'user-input', description: 'Symfony cookies bag' },
  { id: 'php.GET', fieldPath: ['_GET'], kind: 'user-input', description: '$_GET' },
  { id: 'php.POST', fieldPath: ['_POST'], kind: 'user-input', description: '$_POST' },
  { id: 'php.REQUEST', fieldPath: ['_REQUEST'], kind: 'user-input', description: '$_REQUEST' },
  { id: 'php.COOKIE', fieldPath: ['_COOKIE'], kind: 'user-input', description: '$_COOKIE' },
  { id: 'php.SERVER', fieldPath: ['_SERVER'], kind: 'user-input', description: '$_SERVER' },
];

export const PHP_SINKS: TaintSink[] = [
  { id: 'php.eval', calleePath: ['eval'], dangerousArgs: [0], danger: 'code-execution', description: 'eval() — code/eval injection' },
  { id: 'php.assert', calleePath: ['assert'], dangerousArgs: [0], danger: 'code-execution', description: 'assert() of user string' },
  { id: 'php.exec', calleePath: ['exec'], dangerousArgs: [0], danger: 'command-injection', description: 'exec()' },
  { id: 'php.system', calleePath: ['system'], dangerousArgs: [0], danger: 'command-injection', description: 'system()' },
  { id: 'php.passthru', calleePath: ['passthru'], dangerousArgs: [0], danger: 'command-injection', description: 'passthru()' },
  { id: 'php.shell_exec', calleePath: ['shell_exec'], dangerousArgs: [0], danger: 'command-injection', description: 'shell_exec()' },
  { id: 'php.proc_open', calleePath: ['proc_open'], dangerousArgs: [0], danger: 'command-injection', description: 'proc_open()' },
  { id: 'php.popen', calleePath: ['popen'], dangerousArgs: [0], danger: 'command-injection', description: 'popen()' },
  { id: 'php.unserialize', calleePath: ['unserialize'], dangerousArgs: [0], danger: 'code-execution', description: 'unserialize() — unsafe deserial' },
  { id: 'php.file_get_contents', calleePath: ['file_get_contents'], dangerousArgs: [0], danger: 'ssrf', description: 'file_get_contents of user URL — ssrf (CWE-918)' },
  { id: 'php.file_put_contents', calleePath: ['file_put_contents'], dangerousArgs: [0], danger: 'ssrf', description: 'file_put_contents of user URL — ssrf (CWE-918)' },
  { id: 'php.fopen', calleePath: ['fopen'], dangerousArgs: [0], danger: 'ssrf', description: 'fopen of user path' },
  { id: 'php.include', calleePath: ['include'], dangerousArgs: [0], danger: 'code-execution', description: 'include of user path' },
  { id: 'php.require', calleePath: ['require'], dangerousArgs: [0], danger: 'code-execution', description: 'require of user path' },
  { id: 'php.redirect', calleePath: ['redirect'], dangerousArgs: [0], danger: 'redirect', description: 'redirect($url)' },
  { id: 'php.response', calleePath: ['response'], dangerousArgs: [0], danger: 'template-injection', description: 'response(HTML) — XSS' },
  { id: 'php.Blade.render', calleePath: ['Blade', 'render'], dangerousArgs: [0], danger: 'template-injection', description: 'Blade::render of user template — SSTI' },
  { id: 'php.evaluate', calleePath: ['evaluate'], dangerousArgs: [0], danger: 'template-injection', description: 'ExpressionLanguage::evaluate — EL injection' },
  { id: 'php.simplexml_load_string', calleePath: ['simplexml_load_string'], dangerousArgs: [0], danger: 'code-execution', description: 'simplexml_load_string — XXE' },
  { id: 'php.loadXML', calleePath: ['loadXML'], dangerousArgs: [0], danger: 'code-execution', description: 'DOMDocument::loadXML — XXE' },
  { id: 'php.error_log', calleePath: ['error_log'], dangerousArgs: [0], danger: 'template-injection', description: 'error_log of user data' },
  { id: 'php.header', calleePath: ['header'], dangerousArgs: [0], danger: 'template-injection', description: 'header() of user data — CRLF' },
  { id: 'php.ldap_search', calleePath: ['ldap_search'], dangerousArgs: [2], danger: 'sql-injection', description: 'ldap_search filter' },
  { id: 'php.abort', calleePath: ['abort'], dangerousArgs: [1], danger: 'template-injection', description: 'abort(500, user message) — errormessage (CWE-209)' },
  { id: 'php.session', calleePath: ['session'], dangerousArgs: [0], danger: 'template-injection', description: 'session([...]) of user data — session fixation (CWE-384)' },
  { id: 'php.xpath', calleePath: ['xpath'], dangerousArgs: [0], danger: 'sql-injection', description: 'xpath of user expression — xpathi (CWE-643)' },
];

export const PHP_SANITIZERS: Sanitizer[] = [
  { id: 'php.int', calleePath: ['int'], sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection', 'template-injection', 'redirect'], description: '(int) cast' },
  { id: 'php.intval', calleePath: ['intval'], sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection', 'template-injection', 'redirect'], description: 'intval()' },
  { id: 'php.htmlspecialchars', calleePath: ['htmlspecialchars'], sanitizesArgs: [0], against: ['template-injection'], description: 'htmlspecialchars' },
  { id: 'php.htmlentities', calleePath: ['htmlentities'], sanitizesArgs: [0], against: ['template-injection'], description: 'htmlentities' },
  { id: 'php.escapeshellarg', calleePath: ['escapeshellarg'], sanitizesArgs: [0], against: ['command-injection'], description: 'escapeshellarg' },
  { id: 'php.basename', calleePath: ['basename'], sanitizesArgs: [0], against: ['ssrf'], description: 'basename strips directories' },
  { id: 'php.realpath', calleePath: ['realpath'], sanitizesArgs: [0], against: ['ssrf'], description: 'realpath resolved path (prefix-checked by caller)' },
  { id: 'php.json_decode', calleePath: ['json_decode'], sanitizesArgs: [0], against: ['code-execution'], description: 'json_decode is not unserialize' },
  { id: 'php.filter_var', calleePath: ['filter_var'], sanitizesArgs: [0], against: ['ssrf', 'redirect'], description: 'filter_var IP/URL pin (FILTER_FLAG_NO_PRIV_RANGE)' },
  { id: 'php.password_hash', calleePath: ['password_hash'], sanitizesArgs: [0], against: ['code-execution', 'template-injection'], description: 'password_hash' },
];

export function matchPhpSinkExtra(path: string[], _imports: ModuleImport[]): TaintSink | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  const joined = path.join('.');

  if (tail === 'select' || tail === 'statement' || tail === 'insert' || tail === 'update' || tail === 'delete' || tail === 'unprepared') {
    if (path.some(p => /^(DB|db|pdo|PDO|mysqli|connection|conn)$/i.test(p)) || path.length <= 2) {
      return {
        id: `php.db.${tail}`,
        calleePath: path,
        dangerousArgs: [0],
        danger: 'sql-injection',
        description: `DB::${tail} of concatenated SQL — SQL injection`,
      };
    }
  }
  if (tail === 'query' && path.some(p => /xpath|XPath|DOMXPath/i.test(p))) {
    return {
      id: 'php.xpath.query',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'DOMXPath::query of user expression — xpathi (CWE-643)',
    };
  }
  if (['exec', 'system', 'passthru', 'shell_exec', 'proc_open', 'popen'].includes(tail)) {
    return {
      id: `php.cmd.${tail}`,
      calleePath: path,
      dangerousArgs: [0],
      danger: 'command-injection',
      description: `${tail}() of user string — command injection`,
    };
  }
  if (tail === 'eval' || tail === 'assert' || tail === 'create_function') {
    return {
      id: `php.eval.${tail}`,
      calleePath: path,
      dangerousArgs: [0],
      danger: 'code-execution',
      description: `${tail}() of user string — code injection`,
    };
  }
  if (tail === 'render' && path.some(p => /Blade|Twig|Engine/i.test(p))) {
    return {
      id: 'php.tpl.render',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'template-injection',
      description: 'template render of user source — SSTI',
    };
  }
  if (tail === 'evaluate' || tail === 'compile') {
    return {
      id: 'php.el.evaluate.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'template-injection',
      description: 'EL evaluate of user string',
    };
  }
  if (tail === 'findOne' || tail === 'find' || tail === 'find_one') {
    return {
      id: 'php.mongo.find',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'Mongo find of user filter — NoSQL injection',
    };
  }
  if (tail === 'info' || tail === 'warning' || tail === 'error' || tail === 'debug') {
    if (path.some(p => /Log|logger/i.test(p))) {
      return {
        id: 'php.log.any',
        calleePath: path,
        dangerousArgs: [0],
        danger: 'template-injection',
        description: 'Log of user data — log injection',
      };
    }
  }
  if (tail === 'header' && /header/i.test(joined)) {
    return {
      id: 'php.header.any',
      calleePath: path,
      dangerousArgs: [1],
      danger: 'template-injection',
      description: '->header of user value — CRLF / CORS',
    };
  }
  if (tail === 'cookie') {
    return {
      id: 'php.cookie.set',
      calleePath: path,
      dangerousArgs: [1],
      danger: 'template-injection',
      description: '->cookie of user value',
    };
  }
  return null;
}

export function matchPhpSanitizerExtra(path: string[], _imports: ModuleImport[]): Sanitizer | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  if (tail === 'htmlspecialchars' || tail === 'htmlentities' || tail === 'e') {
    return {
      id: 'php.html.escape.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'HTML escape',
    };
  }
  if (tail === 'escapeshellarg' || tail === 'escapeshellcmd') {
    return {
      id: 'php.shell.escape.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['command-injection'],
      description: 'escapeshellarg/cmd',
    };
  }
  if (tail === 'text' && path.some(p => /Parsedown/i.test(p))) {
    return {
      id: 'php.Parsedown.text',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'Parsedown setSafeMode()->text',
    };
  }
  return null;
}

export function matchPhpCallSourceExtra(path: string[], _imports: ModuleImport[]): TaintSource | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  const head = path[0];
  if (
    ['header', 'query', 'input', 'cookie', 'json', 'getContent', 'get', 'all', 'post', 'file', 'getClientOriginalName'].includes(tail) &&
    (head === 'request' || head === 'Request' || path.includes('headers') || path.includes('cookies'))
  ) {
    return {
      id: `php.request.${tail}`,
      fieldPath: path,
      kind: 'user-input',
      description: `Request::${tail} — user-controlled`,
    };
  }
  if (tail === 'getenv' || tail === 'env') {
    return {
      id: 'php.getenv',
      fieldPath: ['getenv'],
      kind: 'user-input',
      description: 'getenv/env — USER_INPUT is attacker-controlled in BP',
    };
  }
  if (tail === 'fgets') {
    return {
      id: 'php.fgets',
      fieldPath: ['fgets'],
      kind: 'user-input',
      description: 'fgets(STDIN) — attacker-controlled in BP',
    };
  }
  if (tail === 'selectOne') {
    return {
      id: 'php.db.result',
      fieldPath: ['DB', 'result'],
      kind: 'user-input',
      description: 'DB::selectOne result — stored data treated as untrusted (second-order taint)',
    };
  }
  return null;
}

export const PHP_CATALOG_EXTRAS = {
  htmlReturnSink: true,
  bindParamHardensSql: true,
};

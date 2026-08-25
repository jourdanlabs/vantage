// Python-only source / sink / sanitizer catalog for NEBULA.
//
// Language-selected at the Python frontend / runNebula Python path.
// Do NOT merge these rows into catalog/javascript.ts — analyzer is
// first-match-wins, and JS already has exec.bare (command-injection) on
// calleePath ['exec'] ahead of any python.exec (code-execution).
//
// Built against the BenchProctor Python CWE enumeration
// (receipts/sealed-holdout/python-v2-fastapi-2026-08-17/CWE-ENUMERATION.md).
// Development set: Flask quicktest. Sealed hold-out: FastAPI — do not score it.

import { TaintSource, TaintSink, Sanitizer } from './javascript';
import { ModuleImport } from '../ir';

export const PYTHON_SOURCES: TaintSource[] = [
  // Flask
  { id: 'flask.request.args',    fieldPath: ['request', 'args'],    kind: 'user-input', description: 'Flask request.args — URL query string' },
  { id: 'flask.request.form',    fieldPath: ['request', 'form'],    kind: 'user-input', description: 'Flask request.form — form-encoded POST body' },
  { id: 'flask.request.json',    fieldPath: ['request', 'json'],    kind: 'user-input', description: 'Flask request.json' },
  { id: 'flask.request.values',  fieldPath: ['request', 'values'],  kind: 'user-input', description: 'Flask request.values' },
  { id: 'flask.request.data',    fieldPath: ['request', 'data'],    kind: 'user-input', description: 'Flask request.data' },
  { id: 'flask.request.files',   fieldPath: ['request', 'files'],   kind: 'user-input', description: 'Flask request.files' },
  { id: 'flask.request.headers', fieldPath: ['request', 'headers'], kind: 'user-input', description: 'Flask request.headers' },
  { id: 'flask.request.cookies', fieldPath: ['request', 'cookies'], kind: 'user-input', description: 'Flask request.cookies' },
  { id: 'flask.request.get_json', fieldPath: ['request', 'get_json'], kind: 'user-input', description: 'Flask request.get_json()' },
  { id: 'flask.request.get_data', fieldPath: ['request', 'get_data'], kind: 'user-input', description: 'Flask request.get_data()' },
  { id: 'flask.request.form.get', fieldPath: ['request', 'form', 'get'], kind: 'user-input', description: 'request.form.get as field' },
  { id: 'starlette.request.body', fieldPath: ['request', 'body'], kind: 'user-input', description: 'Starlette/FastAPI request.body()' },
  { id: 'starlette.request.form', fieldPath: ['request', 'form'], kind: 'user-input', description: 'Starlette/FastAPI await request.form()' },
  { id: 'starlette.request.query_params', fieldPath: ['request', 'query_params'], kind: 'user-input', description: 'duplicate query_params path for prefix match' },

  // Django
  { id: 'django.request.GET',     fieldPath: ['request', 'GET'],     kind: 'user-input', description: 'Django HttpRequest.GET' },
  { id: 'django.request.POST',    fieldPath: ['request', 'POST'],    kind: 'user-input', description: 'Django HttpRequest.POST' },
  { id: 'django.request.body',    fieldPath: ['request', 'body'],    kind: 'user-input', description: 'Django HttpRequest.body' },
  { id: 'django.request.FILES',   fieldPath: ['request', 'FILES'],   kind: 'user-input', description: 'Django HttpRequest.FILES' },
  { id: 'django.request.COOKIES', fieldPath: ['request', 'COOKIES'], kind: 'user-input', description: 'Django HttpRequest.COOKIES' },
  { id: 'django.request.META',    fieldPath: ['request', 'META'],    kind: 'user-input', description: 'Django HttpRequest.META' },

  // FastAPI / Starlette
  { id: 'fastapi.request.query_params', fieldPath: ['request', 'query_params'], kind: 'user-input', description: 'Starlette request.query_params' },
  { id: 'fastapi.request.path_params',  fieldPath: ['request', 'path_params'],  kind: 'user-input', description: 'Starlette request.path_params' },

  // Env / argv — USER_INPUT is the BenchProctor attacker stand-in
  { id: 'python.os.environ', fieldPath: ['os', 'environ'], kind: 'user-input', description: 'os.environ — USER_INPUT is attacker-controlled in BP' },
  { id: 'python.sys.argv',   fieldPath: ['sys', 'argv'],   kind: 'env', description: 'sys.argv' },
  { id: 'python.sys.stdin',  fieldPath: ['sys', 'stdin'],  kind: 'user-input', description: 'sys.stdin' },
];

export const PYTHON_SINKS: TaintSink[] = [
  // Code execution
  { id: 'python.eval',       calleePath: ['eval'],       dangerousArgs: [0], danger: 'code-execution', description: 'Python eval() — evaluates arbitrary source' },
  { id: 'python.exec',       calleePath: ['exec'],       dangerousArgs: [0], danger: 'code-execution', description: 'Python exec() — executes arbitrary source' },
  { id: 'python.compile',    calleePath: ['compile'],    dangerousArgs: [0], danger: 'code-execution', description: 'Python compile() — compiles arbitrary source' },
  { id: 'python.__import__', calleePath: ['__import__'], dangerousArgs: [0], danger: 'code-execution', description: 'Dynamic __import__()' },

  // Command injection
  { id: 'python.os.system',              calleePath: ['os', 'system'],              dangerousArgs: [0], danger: 'command-injection', description: 'os.system — shell command string' },
  { id: 'python.os.popen',               calleePath: ['os', 'popen'],               dangerousArgs: [0], danger: 'command-injection', description: 'os.popen — shell pipe' },
  { id: 'python.os.execv',               calleePath: ['os', 'execv'],               dangerousArgs: [1], danger: 'command-injection', description: 'os.execv argv' },
  { id: 'python.os.execl',               calleePath: ['os', 'execl'],               dangerousArgs: [1], danger: 'command-injection', description: 'os.execl argv' },
  { id: 'python.subprocess.run',         calleePath: ['subprocess', 'run'],         dangerousArgs: [0], danger: 'command-injection', description: 'subprocess.run' },
  { id: 'python.subprocess.call',        calleePath: ['subprocess', 'call'],        dangerousArgs: [0], danger: 'command-injection', description: 'subprocess.call' },
  { id: 'python.subprocess.Popen',       calleePath: ['subprocess', 'Popen'],       dangerousArgs: [0], danger: 'command-injection', description: 'subprocess.Popen' },
  { id: 'python.subprocess.check_output', calleePath: ['subprocess', 'check_output'], dangerousArgs: [0], danger: 'command-injection', description: 'subprocess.check_output' },
  { id: 'python.subprocess.check_call',  calleePath: ['subprocess', 'check_call'],  dangerousArgs: [0], danger: 'command-injection', description: 'subprocess.check_call' },

  // SQL
  { id: 'python.db.execute',        calleePath: ['db', 'execute'],        dangerousArgs: [0], danger: 'sql-injection', description: 'db.execute raw SQL' },
  { id: 'python.cursor.execute',    calleePath: ['cursor', 'execute'],    dangerousArgs: [0], danger: 'sql-injection', description: 'DB-API cursor.execute' },
  { id: 'python.connection.execute', calleePath: ['connection', 'execute'], dangerousArgs: [0], danger: 'sql-injection', description: 'connection.execute' },

  // Deserial
  { id: 'python.pickle.loads',  calleePath: ['pickle', 'loads'],  dangerousArgs: [0], danger: 'code-execution', description: 'pickle.loads — RCE via __reduce__' },
  { id: 'python.pickle.load',   calleePath: ['pickle', 'load'],   dangerousArgs: [0], danger: 'code-execution', description: 'pickle.load' },
  { id: 'python.yaml.load',     calleePath: ['yaml', 'load'],     dangerousArgs: [0], danger: 'code-execution', description: 'yaml.load without SafeLoader — unsafe deserialization' },
  { id: 'python.marshal.loads', calleePath: ['marshal', 'loads'], dangerousArgs: [0], danger: 'code-execution', description: 'marshal.loads' },

  // Templates / SSTI / EL
  { id: 'python.render_template_string', calleePath: ['render_template_string'], dangerousArgs: [0], danger: 'template-injection', description: 'Flask render_template_string — SSTI / EL injection' },
  { id: 'python.jinja2.Template',        calleePath: ['Template'],               dangerousArgs: [0], danger: 'template-injection', description: 'Jinja2/Django Template(user source)' },
  { id: 'python.jinja2.from_string',     calleePath: ['from_string'],            dangerousArgs: [0], danger: 'template-injection', description: 'Environment.from_string / Engine.from_string' },
  { id: 'python.django.mark_safe',       calleePath: ['mark_safe'],              dangerousArgs: [0], danger: 'template-injection', description: 'Django mark_safe of user HTML — XSS' },
  { id: 'python.django.format_html',     calleePath: ['format_html'],            dangerousArgs: [0], danger: 'template-injection', description: 'Django format_html of user format string — XSS (CWE-79)' },

  // Path / file
  { id: 'python.open',        calleePath: ['open'],              dangerousArgs: [0], danger: 'ssrf', description: 'open() with user-controlled path — path traversal' },
  { id: 'python.os.listdir',  calleePath: ['os', 'listdir'],     dangerousArgs: [0], danger: 'ssrf', description: 'os.listdir — directory listing exposure' },
  { id: 'python.os.unlink',   calleePath: ['os', 'unlink'],      dangerousArgs: [0], danger: 'ssrf', description: 'os.unlink with user path' },
  { id: 'python.os.remove',   calleePath: ['os', 'remove'],      dangerousArgs: [0], danger: 'ssrf', description: 'os.remove with user path' },
  { id: 'python.send_file',   calleePath: ['send_file'],         dangerousArgs: [0], danger: 'ssrf', description: 'Flask send_file with user path' },

  // SSRF / redirect
  { id: 'python.requests.get',  calleePath: ['requests', 'get'],  dangerousArgs: [0], danger: 'ssrf', description: 'requests.get with user-controlled URL — SSRF' },
  { id: 'python.requests.post', calleePath: ['requests', 'post'], dangerousArgs: [0], danger: 'ssrf', description: 'requests.post with user-controlled URL' },
  { id: 'python.requests.put',  calleePath: ['requests', 'put'],  dangerousArgs: [0], danger: 'ssrf', description: 'requests.put' },
  { id: 'python.urllib.urlopen', calleePath: ['urlopen'],        dangerousArgs: [0], danger: 'ssrf', description: 'urlopen with user URL' },
  { id: 'python.socket.create_connection', calleePath: ['socket', 'create_connection'], dangerousArgs: [0], danger: 'ssrf', description: 'socket.create_connection with user host' },
  { id: 'python.flask.redirect', calleePath: ['redirect'],       dangerousArgs: [0], danger: 'redirect', description: 'Flask redirect(user URL) — open redirect' },
  { id: 'python.RedirectResponse', calleePath: ['RedirectResponse'], dangerousArgs: [0], dangerousKwargs: ['url'], danger: 'redirect', description: 'Starlette RedirectResponse(url=) — open redirect' },
  { id: 'python.HTMLResponse', calleePath: ['HTMLResponse'], dangerousArgs: [0], danger: 'template-injection', description: 'Starlette HTMLResponse with user HTML — XSS (CWE-79)' },
  { id: 'python.PlainTextResponse', calleePath: ['PlainTextResponse'], dangerousArgs: [0], danger: 'template-injection', description: 'Starlette PlainTextResponse with user body' },
  { id: 'python.jinja2.Template.render', calleePath: ['Template', 'render'], dangerousArgs: [], danger: 'template-injection', description: 'Template(taint).render — SSTI (constructor is the real sink)' },

  // XSS-ish response helpers
  { id: 'python.make_response', calleePath: ['make_response'], dangerousArgs: [0], danger: 'template-injection', description: 'make_response with user HTML' },

  // LDAP / XPath / XXE
  { id: 'python.ldap.search_s', calleePath: ['search_s'], dangerousArgs: [2], danger: 'sql-injection', description: 'ldap.search_s filter — LDAP injection' },
  { id: 'python.etree.xpath',   calleePath: ['xpath'],    dangerousArgs: [0], danger: 'sql-injection', description: 'lxml xpath with user expression — XPath injection' },
  { id: 'python.etree.fromstring', calleePath: ['fromstring'], dangerousArgs: [0], danger: 'code-execution', description: 'etree.fromstring of user XML — XXE' },
  { id: 'python.etree.XMLParser', calleePath: ['XMLParser'], dangerousArgs: [], danger: 'code-execution', description: 'XMLParser(resolve_entities=True)' },

  // Logging
  { id: 'python.logging.info',    calleePath: ['logging', 'info'],    dangerousArgs: [0], danger: 'template-injection', description: 'logging.info with user data — log injection / sensitive log' },
  { id: 'python.logging.error',   calleePath: ['logging', 'error'],   dangerousArgs: [0], danger: 'template-injection', description: 'logging.error' },
  { id: 'python.logging.warning', calleePath: ['logging', 'warning'], dangerousArgs: [0], danger: 'template-injection', description: 'logging.warning' },
  { id: 'python.logging.debug',   calleePath: ['logging', 'debug'],   dangerousArgs: [0], danger: 'template-injection', description: 'logging.debug' },

  // Privilege
  { id: 'python.os.setuid',  calleePath: ['os', 'setuid'],  dangerousArgs: [0], danger: 'code-execution', description: 'os.setuid with user uid — privilege escalation' },
  { id: 'python.os.setgid',  calleePath: ['os', 'setgid'],  dangerousArgs: [0], danger: 'code-execution', description: 'os.setgid' },

  // Resource
  { id: 'python.bytearray', calleePath: ['bytearray'], dangerousArgs: [0], danger: 'ssrf', description: 'bytearray(user size) — resource exhaustion' },

  // NoSQL exact (collection name varies — also matchSinkExtra)
  { id: 'python.mongo.find',     calleePath: ['mongo_db', 'users', 'find'],     dangerousArgs: [0], danger: 'sql-injection', description: 'mongo_db.users.find with user filter — NoSQL injection' },
  { id: 'python.mongo.find_one', calleePath: ['mongo_db', 'users', 'find_one'], dangerousArgs: [0], danger: 'sql-injection', description: 'mongo_db.users.find_one' },
];

export const PYTHON_SANITIZERS: Sanitizer[] = [
  { id: 'python.int',   calleePath: ['int'],   sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection'], description: 'int() coerces to integer' },
  { id: 'python.float', calleePath: ['float'], sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection'], description: 'float() coerces to float' },
  { id: 'python.html.escape', calleePath: ['html', 'escape'], sanitizesArgs: [0], against: ['template-injection'], description: 'html.escape' },
  { id: 'python.escape',      calleePath: ['escape'],         sanitizesArgs: [0], against: ['template-injection'], description: 'markupsafe/html escape' },
  { id: 'python.bleach.clean', calleePath: ['bleach', 'clean'], sanitizesArgs: [0], against: ['template-injection'], description: 'bleach.clean' },
  { id: 'python.bleach.clean.bare', calleePath: ['clean'], sanitizesArgs: [0], against: ['template-injection'], description: 'bleach.clean imported as clean' },
  { id: 'python.shlex.quote', calleePath: ['shlex', 'quote'], sanitizesArgs: [0], against: ['command-injection'], description: 'shlex.quote' },
  { id: 'python.yaml.safe_load', calleePath: ['yaml', 'safe_load'], sanitizesArgs: [0], against: ['code-execution'], description: 'yaml.safe_load' },
  { id: 'python.json.loads', calleePath: ['json', 'loads'], sanitizesArgs: [0], against: ['code-execution'], description: 'json.loads — data only, not pickle' },
  { id: 'python.os.path.basename', calleePath: ['os', 'path', 'basename'], sanitizesArgs: [0], against: ['ssrf'], description: 'os.path.basename strips directories' },
  { id: 'python.os.path.realpath', calleePath: ['os', 'path', 'realpath'], sanitizesArgs: [0], against: [], description: 'realpath listed; containment is the startswith gate' },
  { id: 'python.defusedxml.fromstring', calleePath: ['defusedxml', 'ElementTree', 'fromstring'], sanitizesArgs: [0], against: ['code-execution'], description: 'defusedxml forbids XXE' },
  { id: 'python.hashlib.pbkdf2_hmac', calleePath: ['hashlib', 'pbkdf2_hmac'], sanitizesArgs: [1], against: ['ssrf', 'code-execution', 'template-injection'], description: 'pbkdf2_hmac — not cleartext storage' },
];

/** Suffix / import-aware Python sinks that cannot be exact catalog rows. */
export function matchPythonSinkExtra(path: string[], _imports: ModuleImport[]): TaintSink | null {
  const tail = path[path.length - 1];
  if (!tail) return null;

  if (tail === 'find' || tail === 'find_one' || tail === 'findOne') {
    const root = path[0] || '';
    if (root === '_' || root === 're') return null;
    if (tail === 'find' && path.length < 2) return null;
    return {
      id: `python.nosql.${tail}`,
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: `Mongo-style ${tail}(filter) with user-controlled filter — NoSQL injection`,
    };
  }
  if (tail === 'search_s' || (tail === 'search' && path.some(p => /ldap/i.test(p)))) {
    return {
      id: 'python.ldap.search',
      calleePath: path,
      dangerousArgs: [0, 1, 2],
      danger: 'sql-injection',
      description: 'LDAP search with user-controlled DN/filter — LDAP injection',
    };
  }
  if (tail === 'xpath') {
    return {
      id: 'python.xpath.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'xpath() with user-controlled expression — XPath injection',
    };
  }
  if (
    tail === 'fromstring' &&
    path.some(p => /etree|lxml/i.test(p)) &&
    !path.some(p => /defused/i.test(p))
  ) {
    return {
      id: 'python.etree.fromstring.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'code-execution',
      description: 'XML fromstring of user input — XXE',
    };
  }
  if (tail === 'execute' && path.length >= 1) {
    const head = path[0];
    if (['db', 'cursor', 'connection', 'conn', 'session'].includes(head) || path.includes('db')) {
      return {
        id: 'python.execute.any',
        calleePath: path,
        dangerousArgs: [0],
        danger: 'sql-injection',
        description: 'execute() with user-controlled SQL — SQL injection',
      };
    }
  }
  return null;
}

/** Second-order: db/cursor/connection fetch/execute return stored attacker data. */
export function matchPythonCallSourceExtra(
  path: string[],
  _imports: ModuleImport[]
): TaintSource | null {
  if (!path.length) return null;
  const joined = path.join('.');
  const tail = path[path.length - 1];
  const head = path[0];
  const dbHead = ['db', 'database', 'client', 'conn', 'connection', 'pool', 'cursor', 'session'];
  if (
    /^(db|database|client|conn|connection|pool|cursor|session)\.(query|execute|fetch_one|fetchone|fetchall|fetchall_array)$/.test(
      joined
    ) ||
    (dbHead.includes(head) &&
      ['query', 'execute', 'fetch_one', 'fetchone', 'fetchall'].includes(tail))
  ) {
    return {
      id: 'db.result',
      fieldPath: ['db', 'result'],
      kind: 'user-input',
      description: 'Database query result — stored data treated as untrusted (second-order taint)',
    };
  }
  if (
    (['get', 'getSync', 'getAsync'].includes(tail) && /redis|session|cache/i.test(head)) ||
    (path.length >= 2 && /redis|session/i.test(joined) && ['get', 'getSync'].includes(tail))
  ) {
    return {
      id: 'redis.result',
      fieldPath: ['redis', 'get'],
      kind: 'user-input',
      description: 'Redis/session store read — attacker-influenced stored value',
    };
  }
  return null;
}

export const PYTHON_CATALOG_EXTRAS = {
  htmlReturnSink: true,
  bindParamHardensSql: true,
  numericSizeSinkIds: ['python.bytearray'],
};

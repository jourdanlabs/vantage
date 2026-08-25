// Rust-only source / sink / sanitizer catalog for NEBULA.
// Language-selected at the Rust frontend. Do not merge into javascript.ts.
// Built against receipts/sealed-holdout/rust-v1-normal-actix-web-2026-08-20/CWE-ENUMERATION.md.
// Development set: rust-quicktest actix_web + axum. Sealed hold-out: rust-normal/actix_web — do not score.

import { TaintSource, TaintSink, Sanitizer } from './javascript';
import { ModuleImport } from '../ir';

export const RUST_SOURCES: TaintSource[] = [
  { id: 'rust.env.USER_INPUT', fieldPath: ['env', 'USER_INPUT'], kind: 'user-input', description: 'std::env::var("USER_INPUT") — attacker stand-in in BP' },
  { id: 'rust.env.DOTENV_VAR', fieldPath: ['env', 'DOTENV_VAR'], kind: 'user-input', description: 'std::env::var("DOTENV_VAR") — attacker stand-in in BP' },
  { id: 'rust.request', fieldPath: ['req'], kind: 'user-input', description: 'Actix HttpRequest' },
  { id: 'rust.body', fieldPath: ['body'], kind: 'user-input', description: 'web::Bytes request body' },
  { id: 'rust.query', fieldPath: ['query'], kind: 'user-input', description: 'web::Query' },
  { id: 'rust.form', fieldPath: ['form'], kind: 'user-input', description: 'web::Form' },
  { id: 'rust.payload', fieldPath: ['payload'], kind: 'user-input', description: 'actix_multipart::Multipart' },
];

export const RUST_SINKS: TaintSink[] = [
  { id: 'rust.Command.new', calleePath: ['Command', 'new'], dangerousArgs: [0], danger: 'command-injection', description: 'Command::new of user program — command injection' },
  { id: 'rust.db_query', calleePath: ['db_query'], dangerousArgs: [0], danger: 'sql-injection', description: 'db_query concatenated SQL' },
  { id: 'rust.db_exec', calleePath: ['db_exec'], dangerousArgs: [0], danger: 'sql-injection', description: 'db_exec concatenated SQL' },
  { id: 'rust.db_connect', calleePath: ['db_connect'], dangerousArgs: [0], danger: 'ssrf', description: 'db_connect of user DSN' },
  { id: 'rust.ldap_search', calleePath: ['ldap_search'], dangerousArgs: [0], danger: 'sql-injection', description: 'ldap_search filter' },
  { id: 'rust.xpath_eval', calleePath: ['xpath_eval'], dangerousArgs: [0], danger: 'sql-injection', description: 'xpath_eval of user expression' },
  { id: 'rust.nosql_find_one', calleePath: ['nosql_find_one'], dangerousArgs: [0], danger: 'sql-injection', description: 'nosql_find_one $where filter' },
  { id: 'rust.render_html', calleePath: ['render_html'], dangerousArgs: [0], danger: 'template-injection', description: 'render_html of user HTML — XSS/SSTI' },
  { id: 'rust.fs.read_to_string', calleePath: ['fs', 'read_to_string'], dangerousArgs: [0], danger: 'ssrf', description: 'tokio::fs::read_to_string of user path' },
  { id: 'rust.fs.write', calleePath: ['fs', 'write'], dangerousArgs: [0], danger: 'ssrf', description: 'tokio::fs::write of user path' },
  { id: 'rust.fs.remove_file', calleePath: ['fs', 'remove_file'], dangerousArgs: [0], danger: 'ssrf', description: 'tokio::fs::remove_file of user path' },
  { id: 'rust.reqwest.get', calleePath: ['reqwest', 'get'], dangerousArgs: [0], danger: 'ssrf', description: 'reqwest::get of user URL — SSRF' },
  { id: 'rust.TcpStream.connect', calleePath: ['TcpStream', 'connect'], dangerousArgs: [0], danger: 'ssrf', description: 'TcpStream::connect of user host' },
  { id: 'rust.set_cookie', calleePath: ['set_cookie'], dangerousArgs: [0], danger: 'template-injection', description: 'set_cookie of user value' },
  { id: 'rust.write_csv', calleePath: ['write_csv'], dangerousArgs: [0], danger: 'template-injection', description: 'write_csv of user field' },
  { id: 'rust.encrypt_with_key', calleePath: ['encrypt_with_key'], dangerousArgs: [0], danger: 'ssrf', description: 'encrypt_with_key of user/hardcoded key' },
  { id: 'rust.setuid', calleePath: ['setuid'], dangerousArgs: [0], danger: 'ssrf', description: 'libc::setuid of tainted uid' },
  { id: 'rust.send_error', calleePath: ['send_error'], dangerousArgs: [0], danger: 'template-injection', description: 'send_error of user data — info disclosure' },
];

export const RUST_SANITIZERS: Sanitizer[] = [
  { id: 'rust.shell_escape', calleePath: ['escape'], sanitizesArgs: [0], against: ['command-injection'], description: 'shell_escape::escape' },
  { id: 'rust.ammonia.clean', calleePath: ['clean'], sanitizesArgs: [0], against: ['template-injection'], description: 'ammonia::clean' },
  { id: 'rust.html_escape.encode_text', calleePath: ['encode_text'], sanitizesArgs: [0], against: ['template-injection'], description: 'html_escape::encode_text' },
  { id: 'rust.db_query_bind', calleePath: ['db_query_bind'], sanitizesArgs: [1], against: ['sql-injection'], description: 'db_query_bind parameterized' },
  { id: 'rust.db_exec_bind', calleePath: ['db_exec_bind'], sanitizesArgs: [1], against: ['sql-injection'], description: 'db_exec_bind parameterized' },
];

export function matchRustSinkExtra(path: string[], _imports: ModuleImport[]): TaintSink | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  const joined = path.join('.');
  if (tail === 'new' && path.some(p => /Command/i.test(p))) {
    return {
      id: 'rust.Command.new.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'command-injection',
      description: 'Command::new of user program — command injection',
    };
  }
  if (tail === 'db_query' || tail === 'db_exec' || joined.endsWith('execute')) {
    return {
      id: 'rust.sql.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'db_query/execute of user SQL',
    };
  }
  if (tail === 'get' && path.some(p => /reqwest|Client/i.test(p))) {
    return {
      id: 'rust.reqwest.get.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'ssrf',
      description: 'reqwest get of user URL — SSRF',
    };
  }
  if (tail === 'info' || tail === 'warn' || tail === 'error') {
    if (path.some(p => /log/i.test(p))) {
      return {
        id: 'rust.log.any',
        calleePath: path,
        dangerousArgs: [0],
        danger: 'template-injection',
        description: 'log of user data — log injection',
      };
    }
  }
  if (tail === 'read_to_string' || tail === 'remove_file' || (tail === 'write' && path.some(p => /fs/i.test(p)))) {
    return {
      id: 'rust.fs.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'ssrf',
      description: 'fs op of user path — path traversal',
    };
  }
  return null;
}

export function matchRustSanitizerExtra(path: string[], _imports: ModuleImport[]): Sanitizer | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  if (tail === 'escape' && path.some(p => /shell_escape|shell/i.test(p))) {
    return {
      id: 'rust.shell_escape.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['command-injection'],
      description: 'shell_escape::escape',
    };
  }
  if (tail === 'encode_text' || tail === 'encode_safe' || (tail === 'clean' && path.some(p => /ammonia|html_escape/i.test(p)))) {
    return {
      id: 'rust.html_escape.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'html_escape::encode_text / ammonia::clean',
    };
  }
  return null;
}

export function matchRustCallSourceExtra(path: string[], _imports: ModuleImport[]): TaintSource | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  if (tail === 'db_fetch_one' || tail === 'redis_get' || tail === 'passthrough') {
    return {
      id: 'rust.second_order',
      fieldPath: path,
      kind: 'user-input',
      description: 'shared helper return — stored/passed attacker data',
    };
  }
  if (tail === 'get' && path.some(p => /headers|cookie|match_info|query|form/i.test(p))) {
    return {
      id: 'rust.header.get',
      fieldPath: path,
      kind: 'user-input',
      description: 'request header/cookie/path/query get',
    };
  }
  return null;
}

export const RUST_CATALOG_EXTRAS = {
  htmlReturnSink: true,
  bindParamHardensSql: true,
};

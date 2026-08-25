// Ruby-only source / sink / sanitizer catalog for NEBULA.
// Language-selected at the Ruby frontend. Do not merge into javascript.ts.
// Built against receipts/sealed-holdout/ruby-v1-normal-rails-2026-08-20/CWE-ENUMERATION.md.
// Development set: ruby-quicktest rails + sinatra. Sealed hold-out: ruby-normal/rails — do not score.

import { TaintSource, TaintSink, Sanitizer } from './javascript';
import { ModuleImport } from '../ir';

export const RUBY_SOURCES: TaintSource[] = [
  { id: 'ruby.ENV', fieldPath: ['ENV'], kind: 'user-input', description: 'ENV — USER_INPUT is attacker-controlled in BP' },
  { id: 'ruby.params', fieldPath: ['params'], kind: 'user-input', description: 'Rails/Sinatra params' },
  { id: 'ruby.cookies', fieldPath: ['cookies'], kind: 'user-input', description: 'Request cookies (read)' },
  { id: 'ruby.request', fieldPath: ['request'], kind: 'user-input', description: 'request.headers/body/query/host/referer/cookies' },
  { id: 'ruby.session', fieldPath: ['session'], kind: 'user-input', description: 'session store — attacker-influenced in some cases' },
];

export const RUBY_SINKS: TaintSink[] = [
  { id: 'ruby.eval', calleePath: ['eval'], dangerousArgs: [0], danger: 'code-execution', description: 'Kernel.eval — code injection' },
  { id: 'ruby.instance_eval', calleePath: ['instance_eval'], dangerousArgs: [0], danger: 'code-execution', description: 'instance_eval' },
  { id: 'ruby.class_eval', calleePath: ['class_eval'], dangerousArgs: [0], danger: 'code-execution', description: 'class_eval' },
  { id: 'ruby.send', calleePath: ['send'], dangerousArgs: [0], danger: 'code-execution', description: 'Object#send of user method name' },
  { id: 'ruby.system', calleePath: ['system'], dangerousArgs: [0], danger: 'command-injection', description: 'system(string) — shell command injection' },
  { id: 'ruby.exec', calleePath: ['exec'], dangerousArgs: [0], danger: 'command-injection', description: 'exec' },
  { id: 'ruby.spawn', calleePath: ['spawn'], dangerousArgs: [0], danger: 'command-injection', description: 'spawn' },
  { id: 'ruby.backtick', calleePath: ['backtick'], dangerousArgs: [0], danger: 'command-injection', description: 'Kernel backticks' },
  { id: 'ruby.execute', calleePath: ['execute'], dangerousArgs: [0], danger: 'sql-injection', description: 'connection.execute concatenated SQL' },
  { id: 'ruby.exec_query', calleePath: ['exec_query'], dangerousArgs: [0], danger: 'sql-injection', description: 'exec_query' },
  { id: 'ruby.where', calleePath: ['where'], dangerousArgs: [0], danger: 'sql-injection', description: 'ActiveRecord.where string' },
  { id: 'ruby.File.delete', calleePath: ['File', 'delete'], dangerousArgs: [0], danger: 'ssrf', description: 'File.delete of user path — path traversal' },
  { id: 'ruby.File.open', calleePath: ['File', 'open'], dangerousArgs: [0], danger: 'ssrf', description: 'File.open of user path' },
  { id: 'ruby.File.read', calleePath: ['File', 'read'], dangerousArgs: [0], danger: 'ssrf', description: 'File.read of user path' },
  { id: 'ruby.File.write', calleePath: ['File', 'write'], dangerousArgs: [0], danger: 'ssrf', description: 'File.write of user path' },
  { id: 'ruby.IO.read', calleePath: ['IO', 'read'], dangerousArgs: [0], danger: 'ssrf', description: 'IO.read' },
  { id: 'ruby.URI.open', calleePath: ['URI', 'open'], dangerousArgs: [0], danger: 'ssrf', description: 'URI.open of user URL — SSRF' },
  { id: 'ruby.open', calleePath: ['open'], dangerousArgs: [0], danger: 'ssrf', description: 'Kernel.open / URI.open' },
  { id: 'ruby.Net.HTTP.get', calleePath: ['Net', 'HTTP', 'get'], dangerousArgs: [0], danger: 'ssrf', description: 'Net::HTTP.get' },
  { id: 'ruby.redirect_to', calleePath: ['redirect_to'], dangerousArgs: [0], danger: 'redirect', description: 'redirect_to user URL' },
  { id: 'ruby.redirect', calleePath: ['redirect'], dangerousArgs: [0], danger: 'redirect', description: 'Sinatra redirect' },
  { id: 'ruby.Marshal.load', calleePath: ['Marshal', 'load'], dangerousArgs: [0], danger: 'code-execution', description: 'Marshal.load — unsafe deserialization' },
  { id: 'ruby.YAML.load', calleePath: ['YAML', 'load'], dangerousArgs: [0], danger: 'code-execution', description: 'YAML.load' },
  { id: 'ruby.ERB.new', calleePath: ['ERB', 'new'], dangerousArgs: [0], danger: 'template-injection', description: 'ERB.new of user template — SSTI' },
  { id: 'ruby.html_safe', calleePath: ['html_safe'], dangerousArgs: [0], danger: 'template-injection', description: 'html_safe of concatenated HTML — XSS' },
  { id: 'ruby.logger.info', calleePath: ['logger', 'info'], dangerousArgs: [0], danger: 'template-injection', description: 'logger.info of user data — log injection' },
  { id: 'ruby.Rails.logger.info', calleePath: ['Rails', 'logger', 'info'], dangerousArgs: [0], danger: 'template-injection', description: 'Rails.logger.info' },
  { id: 'ruby.Nokogiri.XML', calleePath: ['Nokogiri', 'XML'], dangerousArgs: [0], danger: 'code-execution', description: 'Nokogiri::XML of user input — XXE' },
  { id: 'ruby.xpath', calleePath: ['xpath'], dangerousArgs: [0], danger: 'sql-injection', description: 'xpath of user expression' },
  { id: 'ruby.CSV', calleePath: ['CSV', 'generate_line'], dangerousArgs: [0], danger: 'template-injection', description: 'CSV of user field' },
  { id: 'ruby.setuid', calleePath: ['Process', 'uid='], dangerousArgs: [0], danger: 'ssrf', description: 'Process.uid= tainted' },
];

export const RUBY_SANITIZERS: Sanitizer[] = [
  { id: 'ruby.CGI.escapeHTML', calleePath: ['CGI', 'escapeHTML'], sanitizesArgs: [0], against: ['template-injection'], description: 'CGI.escapeHTML' },
  { id: 'ruby.Sanitize.fragment', calleePath: ['Sanitize', 'fragment'], sanitizesArgs: [0], against: ['template-injection'], description: 'Sanitize.fragment' },
  { id: 'ruby.ERB.Util.h', calleePath: ['h'], sanitizesArgs: [0], against: ['template-injection'], description: 'ERB::Util.h' },
  { id: 'ruby.Shellwords.escape', calleePath: ['Shellwords', 'escape'], sanitizesArgs: [0], against: ['command-injection'], description: 'Shellwords.escape' },
  { id: 'ruby.File.realpath', calleePath: ['File', 'realpath'], sanitizesArgs: [0], against: ['ssrf'], description: 'File.realpath — still needs prefix check' },
  { id: 'ruby.Integer', calleePath: ['Integer'], sanitizesArgs: [0], against: ['sql-injection'], description: 'Integer() coercion — SQL id' },
  { id: 'ruby.str.delete', calleePath: ['delete'], sanitizesArgs: [0], against: ['template-injection'], description: 'String#delete CRLF strip' },
];

export function matchRubySinkExtra(path: string[], _imports: ModuleImport[]): TaintSink | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  const joined = path.join('.');
  if (tail === 'execute' || tail === 'exec_query' || tail === 'exec_insert' || tail === 'exec_update') {
    return {
      id: 'ruby.execute.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'execute/exec_query with user-controlled SQL — SQL injection',
    };
  }
  if (tail === 'system' || tail === 'exec' || tail === 'spawn' || tail === 'popen') {
    return {
      id: 'ruby.system.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'command-injection',
      description: 'system/exec of user string — command injection',
    };
  }
  if (tail === 'eval' || tail === 'instance_eval' || tail === 'class_eval' || tail === 'module_eval') {
    return {
      id: 'ruby.eval.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'code-execution',
      description: 'eval of user string — code injection',
    };
  }
  if ((tail === 'open' && path.some(p => /URI|Kernel|IO/i.test(p))) || joined === 'URI.open') {
    return {
      id: 'ruby.open.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'ssrf',
      description: 'open of user URL/path — SSRF / path',
    };
  }
  if (tail === 'info' || tail === 'warn' || tail === 'error' || tail === 'debug') {
    if (path.some(p => /logger/i.test(p))) {
      return {
        id: 'ruby.logger.any',
        calleePath: path,
        dangerousArgs: [0],
        danger: 'template-injection',
        description: 'logger of user data — log injection',
      };
    }
  }
  if (tail === 'find' || tail === 'find_one' || tail === 'findOne') {
    if (path.some(p => /mongo|Mongo/i.test(p))) {
      return {
        id: 'ruby.mongo.find',
        calleePath: path,
        dangerousArgs: [0],
        danger: 'sql-injection',
        description: 'Mongo find of user filter — NoSQL injection',
      };
    }
  }
  if (tail === 'search' || tail === 'search_s') {
    return {
      id: 'ruby.ldap.search',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'LDAP search of user filter',
    };
  }
  return null;
}

export function matchRubySanitizerExtra(path: string[], _imports: ModuleImport[]): Sanitizer | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  if (tail === 'escapeHTML' || tail === 'html_escape' || tail === 'h') {
    return {
      id: 'ruby.escapeHTML.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'HTML escape',
    };
  }
  if (tail === 'fragment' && path.some(p => /Sanitize/i.test(p))) {
    return {
      id: 'ruby.Sanitize.fragment.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'Sanitize.fragment',
    };
  }
  if (tail === 'render' && path.some(p => /Redcarpet|SafeHTML/i.test(p))) {
    return {
      id: 'ruby.Redcarpet.SafeHTML',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'Redcarpet SafeHTML render',
    };
  }
  if (tail === 'html_escape') {
    return {
      id: 'ruby.ERB.Util.html_escape',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'ERB::Util.html_escape',
    };
  }
  if (tail === 'escape' && path.some(p => /Shellwords|shellwords/i.test(p))) {
    return {
      id: 'ruby.Shellwords.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['command-injection'],
      description: 'Shellwords.escape',
    };
  }
  return null;
}

export function matchRubyCallSourceExtra(path: string[], _imports: ModuleImport[]): TaintSource | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  const head = path[0];
  if (
    ['first', 'find', 'find_by', 'last', 'take'].includes(tail) &&
    /^[A-Z]/.test(head || '')
  ) {
    return {
      id: 'ruby.model.first',
      fieldPath: path,
      kind: 'user-input',
      description: 'ActiveRecord/model read — stored data treated as untrusted (second-order taint)',
    };
  }
  if (tail === 'read' && path.some(p => /body|request/i.test(p))) {
    return {
      id: 'ruby.request.body.read',
      fieldPath: ['request', 'body'],
      kind: 'user-input',
      description: 'request.body.read',
    };
  }
  return null;
}

export const RUBY_CATALOG_EXTRAS = {
  htmlReturnSink: true,
  bindParamHardensSql: true,
};

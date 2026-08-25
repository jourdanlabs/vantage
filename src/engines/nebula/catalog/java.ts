// Java-only source / sink / sanitizer catalog for NEBULA.
// Language-selected at the Java frontend. Do not merge into javascript.ts.
// Built against BenchProctor Java CWE enumeration (61 categories, same as Python).
// Development set: Jakarta. Sealed hold-out: Spring — do not score it.

import { TaintSource, TaintSink, Sanitizer } from './javascript';
import { ModuleImport } from '../ir';

export const JAVA_SOURCES: TaintSource[] = [
  { id: 'java.request.getParameter', fieldPath: ['request', 'getParameter'], kind: 'user-input', description: 'HttpServletRequest.getParameter' },
  { id: 'java.request.getHeader', fieldPath: ['request', 'getHeader'], kind: 'user-input', description: 'HttpServletRequest.getHeader' },
  { id: 'java.request.getQueryString', fieldPath: ['request', 'getQueryString'], kind: 'user-input', description: 'HttpServletRequest.getQueryString' },
  { id: 'java.request.getCookies', fieldPath: ['request', 'getCookies'], kind: 'user-input', description: 'HttpServletRequest.getCookies' },
  { id: 'java.System.getenv', fieldPath: ['System', 'getenv'], kind: 'user-input', description: 'System.getenv — USER_INPUT is attacker-controlled in BP' },
];

export const JAVA_SINKS: TaintSink[] = [
  { id: 'java.Runtime.exec', calleePath: ['Runtime', 'getRuntime', 'exec'], dangerousArgs: [0], danger: 'command-injection', description: 'Runtime.getRuntime().exec — command injection' },
  { id: 'java.ProcessBuilder.start', calleePath: ['ProcessBuilder', 'start'], dangerousArgs: [], danger: 'command-injection', description: 'ProcessBuilder.start' },
  { id: 'java.ScriptEngine.eval', calleePath: ['ScriptEngine', 'eval'], dangerousArgs: [0], danger: 'code-execution', description: 'ScriptEngine.eval — code injection (not ELProcessor)' },
  { id: 'java.Statement.executeQuery', calleePath: ['executeQuery'], dangerousArgs: [0], danger: 'sql-injection', description: 'Statement.executeQuery with concatenated SQL' },
  { id: 'java.Statement.execute', calleePath: ['execute'], dangerousArgs: [0], danger: 'sql-injection', description: 'Statement.execute with concatenated SQL' },
  { id: 'java.EntityManager.createQuery', calleePath: ['createQuery'], dangerousArgs: [0], danger: 'sql-injection', description: 'EntityManager.createQuery concatenated JPQL — hibernate_sqli CWE-564' },
  { id: 'java.EntityManager.createNativeQuery', calleePath: ['createNativeQuery'], dangerousArgs: [0], danger: 'sql-injection', description: 'EntityManager.createNativeQuery concatenated SQL — hibernate_sqli CWE-564' },
  { id: 'java.sendRedirect', calleePath: ['sendRedirect'], dangerousArgs: [0], danger: 'redirect', description: 'HttpServletResponse.sendRedirect — open redirect' },
  { id: 'java.URL.openConnection', calleePath: ['openConnection'], dangerousArgs: [], danger: 'ssrf', description: 'URL.openConnection — SSRF (URI.create is parse, not the sink)' },
  { id: 'java.Socket', calleePath: ['Socket'], dangerousArgs: [0], danger: 'ssrf', description: 'new Socket(host) — SSRF' },
  { id: 'java.Files.delete', calleePath: ['Files', 'delete'], dangerousArgs: [0], danger: 'ssrf', description: 'Files.delete with user path — path traversal' },
  { id: 'java.Files.readAllBytes', calleePath: ['Files', 'readAllBytes'], dangerousArgs: [0], danger: 'ssrf', description: 'Files.readAllBytes with user path' },
  { id: 'java.Paths.get', calleePath: ['Paths', 'get'], dangerousArgs: [0], danger: 'ssrf', description: 'Paths.get with user path' },
  { id: 'java.ObjectInputStream.readObject', calleePath: ['readObject'], dangerousArgs: [], danger: 'code-execution', description: 'ObjectInputStream.readObject — unsafe deserialization' },
  { id: 'java.Response.ok', calleePath: ['Response', 'ok'], dangerousArgs: [0], danger: 'template-injection', description: 'Response.ok body — XSS (CWE-79)' },
  { id: 'java.PrintWriter.print', calleePath: ['print'], dangerousArgs: [0], danger: 'template-injection', description: 'PrintWriter.print HTML — XSS' },
  { id: 'java.PrintWriter.println', calleePath: ['println'], dangerousArgs: [0], danger: 'template-injection', description: 'PrintWriter.println HTML — XSS' },
  { id: 'java.PrintWriter.write', calleePath: ['write'], dangerousArgs: [0], danger: 'template-injection', description: 'PrintWriter.write HTML — XSS' },
  { id: 'java.Spel.parseExpression', calleePath: ['parseExpression'], dangerousArgs: [0], danger: 'template-injection', description: 'SpelExpressionParser.parseExpression — SSTI / EL injection' },
  { id: 'java.Expression.getValue', calleePath: ['Expression', 'getValue'], dangerousArgs: [], danger: 'template-injection', description: 'SpEL Expression.getValue of attacker template' },
  { id: 'java.ELProcessor.eval', calleePath: ['ELProcessor', 'eval'], dangerousArgs: [0], danger: 'template-injection', description: 'ELProcessor.eval — expression-language injection (CWE-917)' },
  { id: 'java.ValueExpression.getValue', calleePath: ['ValueExpression', 'getValue'], dangerousArgs: [], danger: 'template-injection', description: 'EL ValueExpression.getValue' },
];

export const JAVA_SANITIZERS: Sanitizer[] = [
  { id: 'java.Integer.parseInt', calleePath: ['Integer', 'parseInt'], sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection', 'template-injection', 'redirect'], description: 'Integer.parseInt' },
  { id: 'java.URLEncoder.encode', calleePath: ['URLEncoder', 'encode'], sanitizesArgs: [0], against: ['redirect'], description: 'URLEncoder.encode — not an SSRF sanitizer' },
  { id: 'java.Paths.getFileName', calleePath: ['getFileName'], sanitizesArgs: [0], against: ['ssrf'], description: 'Path.getFileName strips directories' },
  { id: 'java.Encode.forHtml', calleePath: ['Encode', 'forHtml'], sanitizesArgs: [0], against: ['template-injection'], description: 'OWASP Encode.forHtml' },
  { id: 'java.Encode.forHtml.bare', calleePath: ['forHtml'], sanitizesArgs: [0], against: ['template-injection'], description: 'Encode.forHtml imported' },
  { id: 'java.policy.sanitize', calleePath: ['sanitize'], sanitizesArgs: [0], against: ['template-injection'], description: 'OWASP HTML sanitizer / PolicyFactory.sanitize' },
  { id: 'java.String.matches', calleePath: ['matches'], sanitizesArgs: [0], against: ['code-execution', 'template-injection'], description: 'String.matches allowlist — EL/eval' },
  { id: 'java.Enum.valueOf', calleePath: ['valueOf'], sanitizesArgs: [0], against: ['code-execution', 'template-injection'], description: 'Enum.valueOf allowlist — EL/eval' },
  { id: 'java.Validator.validate', calleePath: ['validate'], sanitizesArgs: [0], against: ['code-execution', 'template-injection'], description: 'Bean Validation validate — EL/eval' },
];

export function matchJavaSinkExtra(path: string[], _imports: ModuleImport[]): TaintSink | null {
  const tail = path[path.length - 1];
  if (!tail) return null;
  if (tail === 'exec' && path.includes('Runtime')) {
    return {
      id: 'java.exec.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'command-injection',
      description: 'Runtime.exec — command injection',
    };
  }
  if (tail === 'eval' && path.some(p => /ScriptEngine/i.test(p))) {
    return {
      id: 'java.ScriptEngine.eval.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'code-execution',
      description: 'ScriptEngine.eval — code injection',
    };
  }
  if (tail === 'executeQuery') {
    return {
      id: 'java.executeQuery.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'executeQuery concatenated SQL — SQL injection',
    };
  }
  if (tail === 'createQuery') {
    return {
      id: 'java.createQuery.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'createQuery concatenated JPQL — hibernate_sqli CWE-564',
    };
  }
  if (tail === 'createNativeQuery') {
    return {
      id: 'java.createNativeQuery.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'createNativeQuery concatenated SQL — hibernate_sqli CWE-564',
    };
  }
  if (tail === 'sendRedirect') {
    return {
      id: 'java.sendRedirect.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'redirect',
      description: 'sendRedirect — open redirect',
    };
  }
  if (tail === 'parseExpression') {
    return {
      id: 'java.parseExpression.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'template-injection',
      description: 'parseExpression of user template — SSTI / EL',
    };
  }
  if (
    (tail === 'print' || tail === 'println') &&
    path.some(p => /getWriter|PrintWriter|writer/i.test(p))
  ) {
    return {
      id: `java.writer.${tail}`,
      calleePath: path,
      dangerousArgs: [0],
      danger: 'template-injection',
      description: `response.getWriter().${tail} HTML — XSS`,
    };
  }
  if (tail === 'search' && path.some(p => /DirContext|LdapContext|ldapContext|InitialDirContext/i.test(p))) {
    return {
      id: 'java.ldap.search',
      calleePath: path,
      dangerousArgs: [1],
      danger: 'sql-injection',
      description: 'DirContext.search filter — LDAP injection (CWE-90)',
    };
  }
  if (tail === 'compile' && path.some(p => /XPath|xpath/i.test(p))) {
    return {
      id: 'java.xpath.compile',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'XPath.compile of user expression — XPath injection',
    };
  }
  if (tail === 'evaluate' && path.some(p => /XPath|xpath/i.test(p))) {
    return {
      id: 'java.xpath.evaluate',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: 'XPath.evaluate of user expression',
    };
  }
  if (
    (tail === 'parse' || tail === 'parseString' || tail === 'newDocumentBuilder') &&
    path.some(p => /DocumentBuilder|SAXParser|XMLReader|DocumentBuilderFactory/i.test(p))
  ) {
    return {
      id: 'java.xml.parse',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'code-execution',
      description: 'XML parse of user input — XXE',
    };
  }
  if (tail === 'send' && path.some(p => /HttpClient|httpClient/i.test(p))) {
    return {
      id: 'java.HttpClient.send',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'ssrf',
      description: 'HttpClient.send — SSRF',
    };
  }
  return null;
}

export function matchJavaSanitizerExtra(
  path: string[],
  _imports: ModuleImport[]
): Sanitizer | null {
  const tail = path[path.length - 1];
  if (tail === 'forHtml' || tail === 'forHtmlContent' || tail === 'forHtmlAttribute') {
    return {
      id: 'java.Encode.forHtml.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'OWASP Encode.forHtml*',
    };
  }
  if (tail === 'sanitize') {
    return {
      id: 'java.sanitize.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'HTML PolicyFactory.sanitize',
    };
  }
  if (tail === 'matches') {
    return {
      id: 'java.matches.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['code-execution', 'template-injection'],
      description: 'String.matches allowlist — EL/eval',
    };
  }
  if (tail === 'valueOf' && path.some(p => /AllowedValue|Enum/i.test(p))) {
    return {
      id: 'java.valueOf.enum',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['code-execution', 'template-injection'],
      description: 'Enum.valueOf allowlist — EL/eval',
    };
  }
  return null;
}

export const JAVA_CATALOG_EXTRAS = {
  htmlReturnSink: true,
};

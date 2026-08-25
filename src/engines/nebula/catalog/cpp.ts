// C++-only catalog. Language-selected at the C++ frontend.
// Do not merge into javascript.ts. Do not add analyzer guards.
// DEV: cpp-quicktest/standalone. SEALED: cpp-normal/standalone — do not score.

import { TaintSource, TaintSink, Sanitizer } from './javascript';
import { ModuleImport } from '../ir';
import {
  C_SOURCES,
  C_SINKS,
  C_SANITIZERS,
  matchCSinkExtra,
  matchCSanitizerExtra,
  matchCCallSourceExtra,
  C_CATALOG_EXTRAS,
} from './c';

export const CPP_SOURCES: TaintSource[] = [
  ...C_SOURCES,
  { id: 'cpp.cin', fieldPath: ['cin'], kind: 'user-input', description: 'std::cin / getline — attacker input' },
  { id: 'cpp.req.param', fieldPath: ['req', 'get_param_value'], kind: 'user-input', description: 'httplib Request.get_param_value' },
  { id: 'cpp.req.header', fieldPath: ['req', 'get_header_value'], kind: 'user-input', description: 'httplib Request.get_header_value' },
  { id: 'cpp.req.body', fieldPath: ['req', 'body'], kind: 'user-input', description: 'httplib Request.body' },
  { id: 'cpp.req.path_params', fieldPath: ['req', 'path_params'], kind: 'user-input', description: 'httplib path_params' },
];

export const CPP_SINKS: TaintSink[] = [
  ...C_SINKS,
  { id: 'cpp.system', calleePath: ['system'], dangerousArgs: [0], danger: 'command-injection', description: 'std::system — command injection' },
  { id: 'cpp.set_redirect', calleePath: ['set_redirect'], dangerousArgs: [0], danger: 'redirect', description: 'httplib Response.set_redirect' },
  { id: 'cpp.set_content', calleePath: ['set_content'], dangerousArgs: [0], danger: 'template-injection', description: 'httplib Response.set_content — XSS / reflected' },
  { id: 'cpp.set_header', calleePath: ['set_header'], dangerousArgs: [1], danger: 'template-injection', description: 'httplib set_header — CRLF / header injection' },
  { id: 'cpp.ofstream', calleePath: ['ofstream'], dangerousArgs: [0], danger: 'ssrf', description: 'std::ofstream user path' },
  { id: 'cpp.operator_ltlt', calleePath: ['operator<<'], dangerousArgs: [0], danger: 'template-injection', description: 'stream << taint — log / XSS' },
];

export const CPP_SANITIZERS: Sanitizer[] = [
  ...C_SANITIZERS,
  { id: 'cpp.stoi', calleePath: ['stoi'], sanitizesArgs: [0], against: ['command-injection', 'sql-injection', 'code-execution', 'template-injection', 'redirect'], description: 'std::stoi numeric coerce' },
  { id: 'cpp.stol', calleePath: ['stol'], sanitizesArgs: [0], against: ['command-injection', 'sql-injection', 'code-execution', 'template-injection', 'redirect'], description: 'std::stol' },
];

export function matchCppSinkExtra(path: string[], imports: ModuleImport[]): TaintSink | null {
  const c = matchCSinkExtra(path, imports);
  if (c) return c;
  const tail = path[path.length - 1];
  if (!tail) return null;
  if (tail === 'set_redirect') {
    return {
      id: 'cpp.set_redirect.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'redirect',
      description: 'set_redirect — open redirect',
    };
  }
  if (tail === 'set_content') {
    return {
      id: 'cpp.set_content.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'template-injection',
      description: 'set_content — reflected body',
    };
  }
  if (tail === 'system' || tail === 'popen') {
    return {
      id: `cpp.${tail}.any`,
      calleePath: path,
      dangerousArgs: [0],
      danger: 'command-injection',
      description: `std::${tail}`,
    };
  }
  return null;
}

export function matchCppSanitizerExtra(path: string[], imports: ModuleImport[]): Sanitizer | null {
  return matchCSanitizerExtra(path, imports);
}

export function matchCppCallSourceExtra(path: string[], imports: ModuleImport[]): TaintSource | null {
  const c = matchCCallSourceExtra(path, imports);
  if (c) return c;
  const tail = path[path.length - 1];
  if (tail === 'getline' || tail === 'cin') {
    return {
      id: 'cpp.cin',
      fieldPath: ['cin'],
      kind: 'user-input',
      description: 'std::getline / cin — attacker input',
    };
  }
  if (tail === 'get_param_value' || tail === 'get_header_value') {
    return {
      id: `cpp.req.${tail}`,
      fieldPath: ['req', tail],
      kind: 'user-input',
      description: `httplib Request.${tail}`,
    };
  }
  return null;
}

export const CPP_CATALOG_EXTRAS = {
  ...C_CATALOG_EXTRAS,
  numericSizeSinkIds: [
    ...(C_CATALOG_EXTRAS.numericSizeSinkIds || []),
    'cpp.new',
  ],
};

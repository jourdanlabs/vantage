// Go-only source / sink / sanitizer catalog for NEBULA.
// Language-selected at the Go frontend. Do not merge into javascript.ts.
// Built against receipts/sealed-holdout/go-v1-normal-gin-2026-08-20/CWE-ENUMERATION-QT.md
// (CSV names only). DEV: go-quicktest gin + net_http. Sealed: go-normal/gin — do not score.

import { TaintSource, TaintSink, Sanitizer } from './javascript';
import { ModuleImport } from '../ir';

export const GO_SOURCES: TaintSource[] = [
  { id: 'go.gin.GetHeader', fieldPath: ['c', 'GetHeader'], kind: 'user-input', description: 'gin.Context.GetHeader' },
  { id: 'go.gin.Query', fieldPath: ['c', 'Query'], kind: 'user-input', description: 'gin.Context.Query' },
  { id: 'go.gin.Param', fieldPath: ['c', 'Param'], kind: 'user-input', description: 'gin.Context.Param' },
  { id: 'go.gin.PostForm', fieldPath: ['c', 'PostForm'], kind: 'user-input', description: 'gin.Context.PostForm' },
  { id: 'go.gin.Cookie', fieldPath: ['c', 'Cookie'], kind: 'user-input', description: 'gin.Context.Cookie' },
  { id: 'go.gin.DefaultQuery', fieldPath: ['c', 'DefaultQuery'], kind: 'user-input', description: 'gin.Context.DefaultQuery' },
  { id: 'go.gin.FormFile', fieldPath: ['c', 'FormFile'], kind: 'user-input', description: 'gin.Context.FormFile' },
  { id: 'go.gin.Request', fieldPath: ['c', 'Request'], kind: 'user-input', description: 'gin.Context.Request (Host/Body/Header)' },
  { id: 'go.http.Header.Get', fieldPath: ['r', 'Header', 'Get'], kind: 'user-input', description: 'http.Request.Header.Get' },
  { id: 'go.http.FormValue', fieldPath: ['r', 'FormValue'], kind: 'user-input', description: 'http.Request.FormValue' },
  { id: 'go.http.Cookie', fieldPath: ['r', 'Cookie'], kind: 'user-input', description: 'http.Request.Cookie' },
  { id: 'go.http.URL', fieldPath: ['r', 'URL'], kind: 'user-input', description: 'http.Request.URL' },
  { id: 'go.http.Host', fieldPath: ['r', 'Host'], kind: 'user-input', description: 'http.Request.Host' },
  { id: 'go.http.Body', fieldPath: ['r', 'Body'], kind: 'user-input', description: 'http.Request.Body' },
  { id: 'go.os.Getenv', fieldPath: ['os', 'Getenv'], kind: 'user-input', description: 'os.Getenv — USER_INPUT is attacker-controlled in BP' },
];

// Structural owns injection cats. Taint Query/Exec FPs on allowlisted
// ORDER BY / regex-gated Sprintf. Empty is legal.
export const GO_SINKS: TaintSink[] = [];

export const GO_SANITIZERS: Sanitizer[] = [
  { id: 'go.html.EscapeString', calleePath: ['html', 'EscapeString'], sanitizesArgs: [0], against: ['template-injection'], description: 'html.EscapeString' },
  { id: 'go.bluemonday.Sanitize', calleePath: ['Sanitize'], sanitizesArgs: [0], against: ['template-injection'], description: 'bluemonday.Sanitize' },
  { id: 'go.filepath.Base', calleePath: ['filepath', 'Base'], sanitizesArgs: [0], against: ['ssrf'], description: 'filepath.Base strips directories' },
  { id: 'go.strconv.Atoi', calleePath: ['strconv', 'Atoi'], sanitizesArgs: [0], against: ['command-injection', 'sql-injection', 'code-execution', 'template-injection', 'redirect'], description: 'strconv.Atoi numeric coerce' },
];

export function matchGoSinkExtra(_path: string[], _imports: ModuleImport[]): TaintSink | null {
  return null;
}

export function matchGoSanitizerExtra(path: string[], _imports: ModuleImport[]): Sanitizer | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  if (tail === 'EscapeString' || tail === 'Sanitize') {
    return {
      id: 'go.html.escape.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'HTML escape / bluemonday',
    };
  }
  if (tail === 'Atoi' || tail === 'ParseInt' || tail === 'Atoi') {
    return {
      id: 'go.strconv.num.any',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['command-injection', 'sql-injection', 'code-execution', 'template-injection', 'redirect'],
      description: 'strconv numeric coerce',
    };
  }
  return null;
}

export function matchGoCallSourceExtra(path: string[], _imports: ModuleImport[]): TaintSource | null {
  if (!path.length) return null;
  const tail = path[path.length - 1];
  const ginSrc = ['GetHeader', 'Query', 'Param', 'PostForm', 'Cookie', 'DefaultQuery', 'FormFile', 'GetQuery', 'GetPostForm'];
  if (ginSrc.includes(tail)) {
    return {
      id: `go.gin.${tail}`,
      fieldPath: path,
      kind: 'user-input',
      description: `gin/net-http ${tail} — user-controlled`,
    };
  }
  if (tail === 'Get' && (path.includes('Header') || path.includes('header'))) {
    return {
      id: 'go.Header.Get',
      fieldPath: path,
      kind: 'user-input',
      description: 'Header.Get — user-controlled',
    };
  }
  if (tail === 'FormValue' || tail === 'PostFormValue' || tail === 'Cookie') {
    return {
      id: `go.http.${tail}`,
      fieldPath: path,
      kind: 'user-input',
      description: `http.Request.${tail}`,
    };
  }
  if (tail === 'Getenv' || tail === 'LookupEnv') {
    return {
      id: 'go.os.Getenv',
      fieldPath: ['Getenv'],
      kind: 'user-input',
      description: 'os.Getenv — attacker-controlled in BP',
    };
  }
  if (tail === 'ReadAll' || tail === 'Decode') {
    return {
      id: 'go.body.Decode',
      fieldPath: path,
      kind: 'user-input',
      description: 'Request body read/decode — user-controlled',
    };
  }
  if (tail === 'QueryRow' || tail === 'Scan') {
    return {
      id: 'go.db.result',
      fieldPath: ['DB', 'result'],
      kind: 'user-input',
      description: 'DB.QueryRow/Scan — stored data treated as untrusted (second-order taint)',
    };
  }
  if (tail === 'Load') {
    return {
      id: 'go.atomic.Load',
      fieldPath: path,
      kind: 'user-input',
      description: 'atomic.Value.Load of previously stored request data',
    };
  }
  return null;
}

export const GO_CATALOG_EXTRAS = {
  htmlReturnSink: true,
  bindParamHardensSql: true,
  numericSizeSinkIds: ['go.os.Setuid', 'go.os.Setgid', 'go.Setuid.any'],
};

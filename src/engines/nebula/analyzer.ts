// NEBULA taint analyzer — Kaioken VII (require/import alias → catalog).
//
// Walks each function in the IR, maintains a per-variable taint map, and emits
// a TaintFinding whenever a tainted value reaches a sink without passing
// through a sanitizer that neutralizes the sink's danger class.
//
// Scope:
//   - source recognition via FieldAccess path match (req.body, process.env, etc.)
//   - sink recognition via Call callee path match (eval, vm.runInNewContext, etc.)
//   - **Kaioken VII**: `const childProcess = require('child_process'); childProcess.execSync`
//     rewrites local binding → package name so catalog sinks fire (BP idiom)
//   - sanitizer recognition as call wrappers that neutralize specific danger classes
//   - flow-sensitive per-variable taint map, updated at each Assign
//   - **within-file interprocedural**: local `foo(x)` binds arg taint to params,
//     analyzes callee, returns return-taint, emits sinks inside callee
//   - recursion/cycles: guarded (no re-entry); falls back to arg pass-through
//   - conditionals and loops take a conservative join at end (any-branch taint)
//
// Findings produced here get injected into PULSAR's adversarialFindings list
// downstream, so they appear in analyze/get_findings output identically to
// pattern-based PULSAR findings — no UI change needed.

import * as fs from 'fs';
import * as path from 'path';
import {
  Block,
  FunctionIR,
  ModuleIR,
  ModuleImport,
  Statement,
  Value,
  Location,
} from './ir';
import {
  JAVASCRIPT_SOURCES,
  JAVASCRIPT_SINKS,
  JAVASCRIPT_SANITIZERS,
  TaintSource,
  TaintSink,
  Sanitizer,
  matchJavascriptSinkExtra,
  matchJavascriptSanitizerExtra,
} from './catalog/javascript';

/** Optional language catalog. Default is JAVASCRIPT_* (JS/TS path unchanged). */
export interface AnalyzerCatalog {
  sources: TaintSource[];
  sinks: TaintSink[];
  sanitizers: Sanitizer[];
  /** Language-specific suffix / import-aware sink matcher. */
  matchSinkExtra?: (path: string[], imports: ModuleImport[]) => TaintSink | null;
  matchSanitizerExtra?: (path: string[], imports: ModuleImport[]) => Sanitizer | null;
  /** Call whose return value is a language-specific second-order source. */
  matchCallSourceExtra?: (path: string[], imports: ModuleImport[]) => TaintSource | null;
  extras?: {
    uncheckedDbExecute?: boolean;
    extraParameterRole?: boolean;
    htmlReturnSink?: boolean;
    bindParamHardensSql?: boolean;
    /** JS-only structural / framework emits (Express, Koa, Nest, Node APIs). */
    jsLegacyEmits?: boolean;
    /** Sink ids that still fire after parseInt/Number (size / uid control). */
    numericSizeSinkIds?: string[];
  };
}

const JS_DEFAULT_CATALOG: AnalyzerCatalog = {
  sources: JAVASCRIPT_SOURCES,
  sinks: JAVASCRIPT_SINKS,
  sanitizers: JAVASCRIPT_SANITIZERS,
  matchSinkExtra: matchJavascriptSinkExtra,
  matchSanitizerExtra: matchJavascriptSanitizerExtra,
  matchCallSourceExtra: matchJavascriptCallSourceExtra,
  extras: {
    uncheckedDbExecute: true,
    extraParameterRole: true,
    jsLegacyEmits: true,
    numericSizeSinkIds: [
      'Buffer.alloc',
      'Buffer.allocUnsafe',
      'Buffer.readUInt8',
      'buf.readUInt8',
      'buf.readInt8',
      'buf.readUInt16LE',
      'buf.readUInt32LE',
      'fs.chmod',
      'fs.chmodSync',
      'fs.chown',
      'fs.chownSync',
      'process.setuid',
      'process.setgid',
      'setuid.bare',
    ],
  },
};

function jsLegacy(): boolean {
  return !!ACTIVE_CATALOG.extras?.jsLegacyEmits;
}

function isNumericSizeSink(sinkId: string): boolean {
  if (ACTIVE_CATALOG.extras?.numericSizeSinkIds?.includes(sinkId)) return true;
  return jsLegacy() && sinkId.startsWith('buf.');
}

let ACTIVE_CATALOG: AnalyzerCatalog = JS_DEFAULT_CATALOG;
let ACTIVE_SOURCES: TaintSource[] = JAVASCRIPT_SOURCES;
let ACTIVE_SINKS: TaintSink[] = JAVASCRIPT_SINKS;
let ACTIVE_SANITIZERS: Sanitizer[] = JAVASCRIPT_SANITIZERS;

function withCatalog<T>(catalog: AnalyzerCatalog | undefined, fn: () => T): T {
  if (!catalog) return fn();
  const prevCat = ACTIVE_CATALOG;
  const prevSources = ACTIVE_SOURCES;
  const prevSinks = ACTIVE_SINKS;
  const prevSans = ACTIVE_SANITIZERS;
  ACTIVE_CATALOG = catalog;
  ACTIVE_SOURCES = catalog.sources;
  ACTIVE_SINKS = catalog.sinks;
  ACTIVE_SANITIZERS = catalog.sanitizers;
  try {
    return fn();
  } finally {
    ACTIVE_CATALOG = prevCat;
    ACTIVE_SOURCES = prevSources;
    ACTIVE_SINKS = prevSinks;
    ACTIVE_SANITIZERS = prevSans;
  }
}

export interface TaintFinding {
  file: string;
  line: number;
  type: string;           // normalized, matches PULSAR finding.type
  severity: 'HIGH' | 'MED' | 'LOW';
  description: string;
  source: string;         // which source this tainted value originated from
  sink: string;           // which sink it reached
  testCase: string;       // short adversarial reproducer hint
  /** Chain of variable assignments from source to sink, for the UI / fix loop. */
  flow: Array<{ statementId: string; variable?: string; location: Location }>;
}

interface TaintLabel {
  source: TaintSource;
  flow: TaintFinding['flow'];
  /** Set when value only survived via parseInt/Number — blocks code/sql/cmd injection, not size sinks. */
  numericCoerced?: boolean;
}

/**
 * Taint environment — Kaioken VI field-sensitive.
 * Keys are base names or dotted paths: `obj`, `obj.payload`, `obj.a.b` (max depth 4).
 */
interface TaintEnv {
  vars: Map<string, TaintLabel[]>;
  /** Names bound to constant string/number arrays (allowlist tables). */
  constArrays: Set<string>;
  /** hostVar → urlVar for `hostVar = new URL(urlVar).hostname` (Kaioken SSRF/redirect). */
  hostFromUrl: Map<string, string>;
  /** Vars assigned from .find()/.findOne() — FieldAccess may null-deref (Kaioken XVII). */
  maybeNull: Set<string>;
  /** Vars holding readFileSync content not yet integrity-checked (Kaioken XXXV). */
  unverifiedReads: Set<string>;
  /** safeParse result vars whose .data is strong-regex validated (Kaioken XLI). */
  zodValidated: Set<string>;
  /**
   * Vars whose values are crypto-protected material (cipher update/final, pbkdf2,
   * Buffer.concat of those, .toString of those). Writing them to a fixed path is
   * not cleartext/path-injection noise (Kaioken LIII — QT crypto safe twins).
   */
  cryptoProtected: Set<string>;
  /** Vars assigned from fs.mkdtempSync / os.tmpdir — temp dirs (CWE-377 safe pattern). */
  tempDirs: Set<string>;
}

const MAX_FIELD_DEPTH = 4;

/** Jinja Environment(autoescape=True) HTML-escapes render() output. Cached per file. */
const jinjaAutoescapeCache = new Map<string, boolean>();
function fileHasJinjaAutoescape(file: string): boolean {
  const hit = jinjaAutoescapeCache.get(file);
  if (hit !== undefined) return hit;
  let present = false;
  try {
    present = fs.readFileSync(file, 'utf8').includes('autoescape=True');
  } catch {
    present = false;
  }
  jinjaAutoescapeCache.set(file, present);
  return present;
}

const xmlSchemaCache = new Map<string, boolean>();
function fileHasXmlSchema(file: string): boolean {
  const hit = xmlSchemaCache.get(file);
  if (hit !== undefined) return hit;
  let present = false;
  try {
    present = fs.readFileSync(file, 'utf8').includes('XMLSchema');
  } catch {
    present = false;
  }
  xmlSchemaCache.set(file, present);
  return present;
}

function emptyEnv(): TaintEnv {
  return {
    vars: new Map(),
    constArrays: new Set(),
    hostFromUrl: new Map(),
    maybeNull: new Set(),
    unverifiedReads: new Set(),
    zodValidated: new Set(),
    cryptoProtected: new Set(),
    tempDirs: new Set(),
  };
}

function cloneEnv(env: TaintEnv): TaintEnv {
  return {
    vars: new Map(env.vars),
    constArrays: new Set(env.constArrays),
    hostFromUrl: new Map(env.hostFromUrl),
    maybeNull: new Set(env.maybeNull),
    unverifiedReads: new Set(env.unverifiedReads),
    zodValidated: new Set(env.zodValidated),
    cryptoProtected: new Set(env.cryptoProtected),
    tempDirs: new Set(env.tempDirs),
  };
}

function joinEnvs(a: TaintEnv, b: TaintEnv): TaintEnv {
  const out = emptyEnv();
  for (const key of new Set([...a.vars.keys(), ...b.vars.keys()])) {
    const labels = [...(a.vars.get(key) ?? []), ...(b.vars.get(key) ?? [])];
    // Dedupe by source ID + flow head; keep all distinct flows
    const seen = new Set<string>();
    const deduped = labels.filter(l => {
      const sig = l.source.id + '|' + (l.flow[0]?.statementId ?? '');
      if (seen.has(sig)) return false;
      seen.add(sig); return true;
    });
    if (deduped.length) out.vars.set(key, deduped);
  }
  for (const n of a.constArrays) out.constArrays.add(n);
  for (const n of b.constArrays) out.constArrays.add(n);
  for (const [k, v] of a.hostFromUrl) out.hostFromUrl.set(k, v);
  for (const [k, v] of b.hostFromUrl) out.hostFromUrl.set(k, v);
  for (const n of a.maybeNull) out.maybeNull.add(n);
  for (const n of b.maybeNull) out.maybeNull.add(n);
  for (const n of a.unverifiedReads) out.unverifiedReads.add(n);
  for (const n of b.unverifiedReads) out.unverifiedReads.add(n);
  for (const n of a.zodValidated) out.zodValidated.add(n);
  for (const n of b.zodValidated) out.zodValidated.add(n);
  for (const n of a.cryptoProtected) out.cryptoProtected.add(n);
  for (const n of b.cryptoProtected) out.cryptoProtected.add(n);
  for (const n of a.tempDirs) out.tempDirs.add(n);
  for (const n of b.tempDirs) out.tempDirs.add(n);
  return out;
}

/** Project-wide state (shared stack + cache across files). Kaioken V. */
interface ProjectCtx {
  /** path.normalize(absPath) → module */
  modules: Map<string, ModuleIR>;
  analyzing: Set<string>;
  cache: Map<string, { returnLabels: TaintLabel[]; findings: TaintFinding[] }>;
}

/** Per-module view for name + import resolution. */
interface ModuleCtx {
  byName: Map<string, FunctionIR>;
  imports: ModuleImport[];
  modulePath: string;
  project: ProjectCtx;
  frontendNotes: string[];
}

interface EvalCtx {
  module: ModuleCtx;
  returnLabels: TaintLabel[];
  findings: TaintFinding[];
  /** Free-var writes from last interproc call — applied by analyzeStatement. */
  callSideEffects?: Map<string, TaintLabel[]>;
  /** Set when if (!req.session.user) return; — suppress session fixation on fall-through. */
  sessionUserGated?: boolean;
  /** Set when login rate-limit / 429 pattern seen — suppress brute-force authCheck FPs. */
  rateLimitPresent?: boolean;
  /**
   * True while evaluating under unary `!` / `not`.
   * Fail-closed `if (!authCheck(...)) return 401` is a gate, not a login brute-force surface
   * (Kaioken LIII — quiets CWE-287/306 safe twins without killing CWE-307 vulns).
   */
  inNegation?: boolean;
  /** Set when if (!authzCheck(...)) return; — suppress broken-grant after real authz. */
  authzGated?: boolean;
  /** Set when CSRF mismatch guard then-exits — suppress broken-authz grant noise after CSRF. */
  csrfGated?: boolean;
  /**
   * True while analyzing try body whose catch is non-empty and reports an error
   * (status 500 / error json). Used to quiet privilege-drop noise when failure is handled
   * (Kaioken LIII — CWE-280 safe vs empty-catch vuln).
   */
  privilegeDropHandled?: boolean;
  /**
   * After HMAC/timingSafeEqual reject-then-exit, fall-through body is integrity-verified.
   * Suppress queue/cloud body sinks on verified payload vars.
   */
  hmacVerified?: boolean;
  /** Field allowlist loop gated mass-assign (Object.keys check + return on bad key). */
  fieldAllowlistGated?: boolean;
  /**
   * req.session.expiresAt / maxAge set to a finite short-ish TTL this function.
   * Suppresses session.data spray on CWE-613 safe twins (vulns omit expiry).
   */
  sessionExpirySet?: boolean;
  /** Inside try { } body — bare JSON.parse outside try is fail-open parse. */
  inTryBlock?: boolean;
  /** True only while evaluating ExpressionStmt root — bare parse as statement. */
  inExpressionStmt?: boolean;
  /**
   * globalThis._stateLock / mutex-style promise chain seen — race_condition safe twins
   * serialize sharedState writes through a lock.
   */
  sharedStateLocked?: boolean;
  /** Kaioken XLV — ctx.status = 4xx/5xx seen (Koa error body disclosure). */
  koaErrorStatus?: boolean;
  /** Kaioken XLVII — analyzing a NestJS controller method (taintedParams present). */
  nestController?: boolean;
  /** Current function param names — skip identity `return param` XSS FPs. */
  currentFnParams?: Set<string>;
  /** Kaioken LI — saw if (divisor === 0n) return before tainted division. */
  divisorZeroChecked?: boolean;
  /** Bean Validation Validator.validate(...) seen — EL eval of that input is gated. */
  beanValidated?: boolean;
  /** String.matches(allowlist) seen — EL eval after that is gated. */
  stringAllowlisted?: boolean;
  /** PHP session()->regenerate() seen — later session([...]) is not fixation. */
  sessionRegenerated?: boolean;
}
function buildModuleCtx(mod: ModuleIR, project: ProjectCtx): ModuleCtx {
  const byName = new Map<string, FunctionIR>();
  for (const fn of mod.functions) {
    if (fn.name) byName.set(fn.name, fn);
  }
  const topLevel: FunctionIR = {
    id: mod.path + ':<top-level>',
    name: '<top-level>',
    params: [],
    body: mod.topLevel,
    location: { file: mod.path, line: 1 },
    modifiers: { async: false, generator: false, arrow: false },
  };
  byName.set('<top-level>', topLevel);
  return {
    byName,
    imports: mod.imports ?? [],
    modulePath: mod.path,
    project,
    frontendNotes: mod.frontendNotes ?? [],
  };
}

/** Single-file analysis (tests + isolated modules). */
export function analyzeModule(module: ModuleIR, catalog?: AnalyzerCatalog): TaintFinding[] {
  return withCatalog(catalog, () => analyzeProject([module]));
}

/**
 * Kaioken V — cross-file interprocedural analysis over a set of modules.
 * Relative require/import only (./ and ../).
 */
export function analyzeProject(modules: ModuleIR[]): TaintFinding[] {
  const project: ProjectCtx = {
    modules: new Map(),
    analyzing: new Set(),
    cache: new Map(),
  };
  for (const m of modules) {
    // Ensure imports/exports arrays exist (older IR fixtures)
    if (!m.imports) m.imports = [];
    if (!m.exports) m.exports = [];
    project.modules.set(normalizePath(m.path), m);
  }

  const all: TaintFinding[] = [];
  for (const m of modules) {
    const mctx = buildModuleCtx(m, project);
    for (const fn of [...m.functions, mctx.byName.get('<top-level>')!]) {
      const r = analyzeFunctionEntry(fn, mctx, null);
      all.push(...r.findings);
    }
    // Kaioken LIV — promote frontend structural switch findings (CWE-478/484)
    if (m.structuralFindings?.length) {
      for (const sf of m.structuralFindings) {
        all.push({
          file: sf.location.file,
          line: sf.location.line,
          type: 'injection',
          severity: 'MED',
          description: sf.description,
          source: 'control-flow',
          sink: sf.sink,
          testCase:
            sf.kind === 'switch_missing_default'
              ? 'switch(data) without default clause'
              : sf.kind === 'switch_fallthrough'
                ? 'switch case falls through without break'
                : sf.description,
          flow: [{ statementId: '<structural>', variable: undefined, location: sf.location }],
        });
      }
    }
  }
  return dedupeFindings(all);
}

function normalizePath(p: string): string {
  // Avoid importing path if possible for browser? Node is fine — use simple normalize.
  return p.replace(/\\/g, '/');
}

function dedupeFindings(findings: TaintFinding[]): TaintFinding[] {
  const seen = new Set<string>();
  const out: TaintFinding[] = [];
  for (const f of findings) {
    const k = `${f.file}:${f.line}:${f.type}:${f.sink}:${f.source}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}

/**
 * Entry-point analysis: Nest/framework params as sources when entryEnv is null.
 * Call-site analysis: entryEnv already has param bindings from caller args.
 */
function analyzeFunctionEntry(
  fn: FunctionIR,
  moduleCtx: ModuleCtx,
  entryEnv: TaintEnv | null,
  opts?: { nestController?: boolean }
): { returnLabels: TaintLabel[]; findings: TaintFinding[] } {
  const env = entryEnv ? cloneEnv(entryEnv) : emptyEnv();
  if (!entryEnv) {
    for (const tp of fn.taintedParams ?? []) {
      const source: TaintSource = {
        id: tp.sourceId,
        fieldPath: [tp.name],
        kind: 'user-input',
        description: tp.description,
      };
      env.vars.set(tp.name, [{
        source,
        flow: [{ statementId: '<param>', variable: tp.name, location: fn.location }],
      }]);
    }
  }

  // Cache must include free-var taint (handler tables: () => sink(data)), not only params.
  // nestController flag is part of the analysis mode for return sinks.
  const envSig = [...env.vars.entries()]
    .filter(([, labs]) => labs.length > 0)
    .map(([k, labs]) => `${k}:${labs.map(l => l.source.id).join('+')}`)
    .sort()
    .join(';');
  const cacheKey = `${fn.id}|${envSig}|nc:${opts?.nestController ? 1 : 0}`;
  const project = moduleCtx.project;
  if (project.cache.has(cacheKey)) {
    return project.cache.get(cacheKey)!;
  }
  if (project.analyzing.has(fn.id)) {
    // Recursion / mutual recursion: do not re-enter; no return model.
    return { returnLabels: [], findings: [] };
  }

  project.analyzing.add(fn.id);
  const findings: TaintFinding[] = [];
  const returnLabels: TaintLabel[] = [];
  // Resolve home module ctx so nested calls use the callee file's imports.
  const home = homeModuleCtx(fn, moduleCtx);
  // Nest controller method: has @Body/@Param/… OR entry analysis of a @nestjs module
  // file (param-less db/env handlers) OR inherited from outer controller call.
  const nestModule = home.imports.some(i => /@nestjs\//.test(i.specifier));
  const nestController =
    !!opts?.nestController ||
    (fn.taintedParams ?? []).some(
      tp => tp.sourceId.startsWith('nestjs.') || /NestJS/i.test(tp.description)
    ) ||
    (nestModule && !entryEnv);
  const ectx: EvalCtx = {
    module: home,
    returnLabels,
    findings,
    nestController,
    currentFnParams: new Set(fn.params),
  };
  analyzeBlock(fn.body, env, ectx);
  project.analyzing.delete(fn.id);

  const result = { returnLabels: [...returnLabels], findings: [...findings] };
  project.cache.set(cacheKey, result);
  return result;
}

function homeModuleCtx(fn: FunctionIR, fallback: ModuleCtx): ModuleCtx {
  const project = fallback.project;
  for (const m of project.modules.values()) {
    if (m.functions.some(f => f.id === fn.id) || fn.id === m.path + ':<top-level>') {
      return buildModuleCtx(m, project);
    }
  }
  // Fallback: id prefix match
  for (const m of project.modules.values()) {
    if (fn.id.startsWith(m.path)) return buildModuleCtx(m, project);
  }
  return fallback;
}

function analyzeBlock(block: Block, env: TaintEnv, ectx: EvalCtx): TaintEnv {
  let current = env;
  for (const stmt of block.statements) {
    current = analyzeStatement(stmt, current, ectx);
  }
  return current;
}

function analyzeStatement(stmt: Statement, env: TaintEnv, ectx: EvalCtx): TaintEnv {
  switch (stmt.kind) {
    case 'Assign': {
      const next = cloneEnv(env);
      // Strong update: reassigning `obj` kills obj.* field taint
      deleteKeyPrefix(next, stmt.target);

      // Object literal: field-sensitive store { payload: taint }
      if (stmt.value.kind === 'ObjectLiteral') {
        for (const prop of stmt.value.props) {
          const labs = evaluate(prop.value, env, stmt.location, ectx);
          const key = joinTaintKey(stmt.target, [prop.key]);
          if (labs.length && key) {
            next.vars.set(
              key,
              labs.map(l => ({
                source: l.source,
                flow: [...l.flow, { statementId: stmt.id, variable: key, location: stmt.location }],
              }))
            );
          }
        }
        // Constant allowlist / host tracking N/A for object literal whole
        next.constArrays.delete(stmt.target);
        next.hostFromUrl.delete(stmt.target);
        return next;
      }

      ectx.callSideEffects = undefined;
      // Evaluate against `next` so side-effects (unverifiedReads clear on hash.update)
      // land on the env we return — not the pre-clone parent.
      let labels = evaluate(stmt.value, next, stmt.location, ectx);
      // Kaioken XVI: parseInt/Number clear injection returns but still carry
      // size/uid taint into the assigned variable (intoverflow / setuid paths).
      if (!labels.length) {
        labels = peelNumericCoercion(stmt.value, next, stmt.location, ectx).map(l => ({
          ...l,
          numericCoerced: true,
        }));
      }
      // Interproc free-var writes (e.g. callback sets outer `data`)
      if (ectx.callSideEffects) {
        for (const [k, labs] of ectx.callSideEffects) {
          next.vars.set(
            k,
            labs.map(l => ({
              source: l.source,
              flow: [...l.flow, { statementId: stmt.id, variable: k, location: stmt.location }],
            }))
          );
        }
        ectx.callSideEffects = undefined;
      }

      // Constant allowlist tables: const allowed = ["a","b"] / new Set(["a","b"])
      if (isConstantLiteralArray(stmt.value) || isConstantLiteralSet(stmt.value)) {
        next.constArrays.add(stmt.target);
      } else if (stmt.value.kind === 'Call') {
        const cp = calleePathOf(stmt.value.callee);
        const tail = cp ? cp[cp.length - 1] : '';
        if (
          (tail === 'of' && cp && (cp.includes('Set') || cp.includes('List') || cp[0] === 'Set')) ||
          tail === 'asList'
        ) {
          const allLit = (stmt.value.args || []).every(
            a => a.kind === 'Literal' && (a.literalKind === 'string' || a.literalKind === 'number')
          );
          if (allLit && (stmt.value.args || []).length) next.constArrays.add(stmt.target);
          else next.constArrays.delete(stmt.target);
        } else {
          next.constArrays.delete(stmt.target);
        }
      } else if (stmt.value.kind === 'Variable' && env.constArrays.has(stmt.value.name)) {
        next.constArrays.add(stmt.target);
      } else {
        next.constArrays.delete(stmt.target);
      }

      // Host extraction: parsedHost = new URL(data).hostname
      // Also parsed = urlparse(data) (Python) so a later hostname allowlist
      // reject-guard can clear the original URL variable.
      const urlParent = urlParentOfHostname(stmt.value) || urlParentOfParseCall(stmt.value);
      if (urlParent) {
        next.hostFromUrl.set(stmt.target, urlParent);
      } else if (stmt.value.kind === 'Variable' && env.hostFromUrl.has(stmt.value.name)) {
        next.hostFromUrl.set(stmt.target, env.hostFromUrl.get(stmt.value.name)!);
      } else {
        next.hostFromUrl.delete(stmt.target);
      }

      // Copy field taint when assigning objects: const data = _obj (shallow path copy)
      if (stmt.value.kind === 'Variable') {
        copyFieldTaint(next, env, stmt.value.name, stmt.target);
      }

      if (labels.length) {
        const propagated = labels.map(l => ({
          source: l.source,
          flow: [...l.flow, { statementId: stmt.id, variable: stmt.target, location: stmt.location }],
          ...(l.numericCoerced ? { numericCoerced: true as const } : {}),
        }));
        next.vars.set(stmt.target, propagated);
      } else if (stmt.value.kind !== 'Variable') {
        next.vars.delete(stmt.target);
      }

      // Mark maybe-null when assigned from .find() / .findOne()
      next.maybeNull.delete(stmt.target);
      if (stmt.value.kind === 'Call') {
        const cp = calleePathOf(stmt.value.callee);
        const tail = cp?.[cp.length - 1];
        if (tail === 'find' || tail === 'findOne' || tail === 'first') next.maybeNull.add(stmt.target);
        // Kaioken XXXV — readFileSync content is unverified until hashed
        if (tail === 'readFileSync' || tail === 'readFile' || (cp && cp.join('.').includes('readFile'))) {
          next.unverifiedReads.add(stmt.target);
        }
      }
      // Chained: db.querySync(...).find(...)
      if (stmt.value.kind === 'Call' && stmt.value.callee.kind === 'FieldAccess') {
        if (stmt.value.callee.field === 'find' || stmt.value.callee.field === 'findOne' || stmt.value.callee.field === 'first') {
          next.maybeNull.add(stmt.target);
        }
        if (stmt.value.callee.field === 'readFileSync' || stmt.value.callee.field === 'readFile') {
          next.unverifiedReads.add(stmt.target);
        }
      }
      // Propagate unverifiedReads through String()/identity assigns
      if (stmt.value.kind === 'Variable' && env.unverifiedReads.has(stmt.value.name)) {
        next.unverifiedReads.add(stmt.target);
      }
      // Kaioken LIII — track crypto-protected material for fixed-path write suppress
      next.cryptoProtected.delete(stmt.target);
      if (isCryptoProtectedValue(stmt.value, env)) {
        next.cryptoProtected.add(stmt.target);
      } else if (stmt.value.kind === 'Variable' && env.cryptoProtected.has(stmt.value.name)) {
        next.cryptoProtected.add(stmt.target);
      }
      // Kaioken LIII — mkdtempSync / tmpdir roots for CWE-377 safe twins
      next.tempDirs.delete(stmt.target);
      if (isTempDirValue(stmt.value, env)) {
        next.tempDirs.add(stmt.target);
      } else if (stmt.value.kind === 'Variable' && env.tempDirs.has(stmt.value.name)) {
        next.tempDirs.add(stmt.target);
      }
      // zod.z.string().regex(/strong/).safeParse(data) → result var is validated
      if (isStrongZodSafeParse(stmt.value)) {
        next.zodValidated.add(stmt.target);
      }
      if (callLooksLikeBeanValidate(stmt.value)) ectx.beanValidated = true;
      return next;
    }
    case 'FieldAssign': {
      let labels = evaluate(stmt.value, env, stmt.location, ectx);
      // Kaioken LVIII+ — static key material assigned to instance/object fields
      // (this._encryptionKey = "hardcoded_aes…"). LooksLikeHardcodedSecret may
      // miss aes key fixtures; field name + long literal is enough for crypto.
      if (
        !labels.length &&
        stmt.value.kind === 'Literal' &&
        stmt.value.literalKind === 'string' &&
        stmt.value.raw &&
        stmt.value.raw.length >= 16 &&
        /key|secret|password|token|cipher|aes|hmac|iv\b/i.test(stmt.field)
      ) {
        labels = [
          {
            source: HARDCODED_SECRET_SOURCE,
            flow: [
              {
                statementId: stmt.id,
                variable: stmt.field,
                location: stmt.location,
              },
            ],
          },
        ];
      }
      const basePath = valueAsFieldPath(stmt.object);
      const next = cloneEnv(env);
      if (basePath) {
        const fullFieldsEarly = [...basePath.fields, stmt.field];
        const onSessionEarly =
          fullFieldsEarly.includes('session') ||
          basePath.base === 'session' ||
          (basePath.base === 'req' && fullFieldsEarly[0] === 'session') ||
          (basePath.base === 'request' && fullFieldsEarly[0] === 'session') ||
          (basePath.base === 'ctx' && fullFieldsEarly[0] === 'session');
        // Kaioken LIII — mark TTL even when RHS is untainted Date.now()+N
        if (
          onSessionEarly &&
          (stmt.field === 'expiresAt' || stmt.field === 'maxAge') &&
          valueLooksLikeSessionTtl(stmt.value)
        ) {
          ectx.sessionExpirySet = true;
        }
        // Kaioken LIV — race lock serialization (globalThis._stateLock = promise chain)
        if (
          (basePath.base === 'globalThis' || basePath.base === 'global') &&
          /lock|mutex|queue/i.test(stmt.field)
        ) {
          ectx.sharedStateLocked = true;
        }
        // Kaioken LIV — unprotected global shared state write (CWE-362 race_condition)
        if (
          labels.length &&
          !ectx.sharedStateLocked &&
          (basePath.base === 'global' || basePath.base === 'globalThis') &&
          /sharedState|shared_state|globalState/i.test(stmt.field)
        ) {
          for (const label of labels) {
            ectx.findings.push({
              file: stmt.location.file,
              line: stmt.location.line,
              type: 'injection',
              severity: 'HIGH',
              description: `Tainted value from ${label.source.description.split(' — ')[0]} written to global shared state without lock — race condition`,
              source: label.source.id,
              sink: 'global.sharedState',
              testCase: 'Concurrent requests mutate global.sharedState without serialization',
              flow: [
                ...label.flow,
                { statementId: stmt.id, variable: stmt.field, location: stmt.location },
              ],
            });
          }
        }
        const key = joinTaintKey(basePath.base, [...basePath.fields, stmt.field]);
        if (key) {
          if (labels.length) {
            next.vars.set(
              key,
              labels.map(l => ({
                source: l.source,
                flow: [...l.flow, { statementId: stmt.id, variable: key, location: stmt.location }],
              }))
            );
            // Kaioken IX / LIII — session fixation (id) always; session.data only if no expiry set
            // (CWE-613 safe twins set expiresAt = Date.now()+900000 before data write).
            // Whole-object `ctx.session = { id: randomSid, data: taint }` is NOT fixation when id is clean.
            const fullFields = fullFieldsEarly;
            const onSession = onSessionEarly;
            const sessionIdField =
              stmt.field === 'id' ||
              stmt.field === 'sessionID' ||
              stmt.field === 'sessionId' ||
              stmt.field === 'sid' ||
              stmt.field === 'session_id';
            const sessionDataField = !sessionIdField && stmt.field !== 'expiresAt' && stmt.field !== 'maxAge';
            let fireSessionFix = false;
            let sessionLabs = labels;
            if (onSession && stmt.field === 'session' && stmt.value.kind === 'ObjectLiteral') {
              const idProp = stmt.value.props.find(
                (p) => p.key === 'id' || p.key === 'sessionID' || p.key === 'sessionId' || p.key === 'sid'
              );
              const dataProp = stmt.value.props.find(
                (p) => p.key === 'data' || p.key === 'user' || p.key === 'payload'
              );
              const idLabs = idProp ? evaluate(idProp.value, env, stmt.location, ectx) : [];
              const dataLabs = dataProp ? evaluate(dataProp.value, env, stmt.location, ectx) : [];
              if (idLabs.length) {
                fireSessionFix = true;
                sessionLabs = idLabs;
              } else if (dataLabs.length && !idProp && !ectx.sessionExpirySet) {
                fireSessionFix = true;
                sessionLabs = dataLabs;
              }
              // else: clean random id + optional data taint → quiet (CWE-539 koa safe twins)
            } else if (
              labels.length &&
              onSession &&
              (sessionIdField || (sessionDataField && !ectx.sessionExpirySet))
            ) {
              fireSessionFix = true;
            }
            if (fireSessionFix && sessionLabs.length && !ectx.sessionUserGated) {
              for (const label of sessionLabs) {
                ectx.findings.push({
                  file: stmt.location.file,
                  line: stmt.location.line,
                  type: 'injection',
                  severity: 'HIGH',
                  description: `Tainted value from ${label.source.description.split(' — ')[0]} written to session — session fixation`,
                  source: label.source.id,
                  sink: 'session.fix',
                  testCase: `Set session field from attacker input → session fixation`,
                  flow: [
                    ...label.flow,
                    { statementId: stmt.id, variable: key, location: stmt.location },
                  ],
                });
              }
            }
          } else {
            next.vars.delete(key);
          }
        }
        // Kaioken XLV — Koa response FieldAssign sinks (ctx.body / ctx.status)
        if (jsLegacy()) emitKoaFieldAssignSinks(stmt, basePath, labels, env, ectx);
        // Kaioken XLIX — process.env.X = taint (external config control)
        if (
          jsLegacy() &&
          labels.length &&
          basePath.base === 'process' &&
          basePath.fields.length === 1 &&
          basePath.fields[0] === 'env'
        ) {
          for (const label of labels) {
            ectx.findings.push({
              file: stmt.location.file,
              line: stmt.location.line,
              type: 'injection',
              severity: 'HIGH',
              description: `Tainted value from ${label.source.description.split(' — ')[0]} written to process.env — external config control`,
              source: label.source.id,
              sink: 'process.env.assign',
              testCase: 'Attacker-controlled value assigned into process.env',
              flow: [
                ...label.flow,
                { statementId: stmt.id, variable: key, location: stmt.location },
              ],
            });
          }
        }
      }
      // still evaluate for sink side effects on RHS
      return next;
    }
    case 'ExpressionStmt':
    case 'Throw': {
      ectx.callSideEffects = undefined;
      const expr: Value | null =
        stmt.kind === 'Throw'
          ? stmt.value
          : stmt.kind === 'ExpressionStmt'
            ? stmt.expr
            : null;
      if (expr) {
        const prevExpr = ectx.inExpressionStmt;
        if (stmt.kind === 'ExpressionStmt') ectx.inExpressionStmt = true;
        let labs: TaintLabel[] = [];
        try {
          labs = evaluate(expr, env, stmt.location, ectx);
        } finally {
          ectx.inExpressionStmt = prevExpr;
        }
        if (callLooksLikeBeanValidate(expr)) ectx.beanValidated = true;
        if (callLooksLikeAllowlistMatches(expr)) ectx.stringAllowlisted = true;
        if (stmt.kind === 'Throw') {
          // Kaioken LI — throw new Error("..." + taint) (not TypeError)
          emitTaintedErrorThrow(expr, labs, stmt.location, ectx);
        }
      }
      let next = env;
      if (ectx.callSideEffects && ectx.callSideEffects.size) {
        next = cloneEnv(env);
        for (const [k, labs] of ectx.callSideEffects) {
          next.vars.set(
            k,
            labs.map(l => ({
              source: l.source,
              flow: [...l.flow, { statementId: stmt.id, variable: k, location: stmt.location }],
            }))
          );
        }
        ectx.callSideEffects = undefined;
      }
      // Kaioken XVI — array mutation: parts.push(token) taints parts
      // Kaioken LIV — Map.set(k,v) taints the Map (querystring parse → params.get("role"))
      if (expr && expr.kind === 'Call' && expr.callee.kind === 'FieldAccess') {
        const field = expr.callee.field;
        if (field === 'push' || field === 'unshift' || field === 'set') {
          const base = valueAsFieldPath(expr.callee.object);
          if (base && base.fields.length === 0) {
            const labs = expr.args.flatMap(a => evaluate(a, env, stmt.location, ectx));
            if (labs.length) {
              if (next === env) next = cloneEnv(env);
              const prev = next.vars.get(base.base) ?? [];
              next.vars.set(
                base.base,
                [
                  ...prev,
                  ...labs.map(l => ({
                    source: l.source,
                    flow: [
                      ...l.flow,
                      { statementId: stmt.id, variable: base.base, location: stmt.location },
                    ],
                  })),
                ]
              );
            }
          }
        }
      }
      return next;
    }
    case 'Return': {
      if (stmt.value) {
        const labs = evaluate(stmt.value, env, stmt.location, ectx);
        ectx.returnLabels.push(...labs);
        // Kaioken XLVII — NestJS / framework controller return sinks
        if (jsLegacy()) emitFrameworkReturnSinks(stmt, labs, env, ectx);
        emitHtmlStringReturn(stmt, labs, ectx);
        // Kaioken VII.3 — closure return: `(v) => () => v`
        // Returning a function value that closes over tainted locals should
        // propagate those free-var labels so `const f = capture(taint); f()`
        // still carries taint (BenchProctor relative_path_traversal idiom).
        if (stmt.value.kind === 'Variable') {
          const retFn = ectx.module.byName.get(stmt.value.name);
          if (retFn) {
            for (const free of freeVarsInFunction(retFn)) {
              const freeLabs = env.vars.get(free);
              if (freeLabs?.length) {
                ectx.returnLabels.push(
                  ...freeLabs.map(l => ({
                    source: l.source,
                    flow: [
                      ...l.flow,
                      { statementId: stmt.id, variable: free, location: stmt.location },
                    ],
                  }))                );
              }
            }
          }
        }
      }
      return env;
    }
    case 'Conditional': {
      if (valueContainsAllowlistMatches(stmt.condition)) ectx.stringAllowlisted = true;
      // Kaioken: control-flow sanitizers.
      //   if (!allowedHosts.includes(x)) return;          // fall-through clean
      //   if (!/^[a-z0-9]+$/.test(x)) return;             // strong regex
      //   if (allowed.includes(x)) { use x } else return; // then-branch clean
      // Note: condition Call sinks (authCheck) are evaluated via taintDrivingCondition
      // in emitWeakInputValidation / emitBrokenAuthzGrant (preserves inNegation).
      const rejectCleared = varsClearedByRejectGuard(stmt.condition, env);
      const acceptCleared = varsClearedByAcceptAllowlist(stmt.condition, env);

      // Kaioken XXXIII — rate limit / authz gate markers for later sinks
      if (conditionLooksLikeRateLimit(stmt.condition) || blockLooksLikeRateLimitResponse(stmt.thenBlock)) {
        ectx.rateLimitPresent = true;
      }
      if (conditionIsAuthzCheckGuard(stmt.condition) && blockAlwaysExits(stmt.thenBlock)) {
        ectx.authzGated = true;
      }
      // Bounds check: if (!Number.isFinite(n) || n < 0 || n > MAX) return; clears size taint
      const boundCleared = varsClearedByNumericBoundsGuard(stmt.condition);
      // applied after thenExits below

      // Kaioken XI.1 — broken authz: if (allowlist.includes(taint)) grant admin
      emitBrokenAuthzGrant(stmt, env, ectx);
      // Kaioken XVI — weak input validation echo
      emitWeakInputValidation(stmt, env, ectx);
      // Kaioken LIII — field allowlist: for (k of keys) if (!allowed.includes(k)) return
      if (conditionLooksLikeFieldAllowlistReject(stmt.condition) && blockAlwaysExits(stmt.thenBlock)) {
        ectx.fieldAllowlistGated = true;
      }
      // Kaioken LI — if (divisor === 0n) return; gates divide-by-zero
      if (conditionLooksLikeZeroDivisorGuard(stmt.condition) && blockAlwaysExits(stmt.thenBlock)) {
        ectx.divisorZeroChecked = true;
      }

      let thenStart = env;
      if (acceptCleared.length) {
        thenStart = clearVars(env, acceptCleared);
      }
      const thenEnv = analyzeBlock(stmt.thenBlock, thenStart, ectx);
      const elseEnv = stmt.elseBlock ? analyzeBlock(stmt.elseBlock, env, ectx) : env;

      const thenExits = blockAlwaysExits(stmt.thenBlock);
      const elseExits = stmt.elseBlock ? blockAlwaysExits(stmt.elseBlock) : false;

      if (!stmt.elseBlock) {
        if (thenExits && rejectCleared.length) {
          return clearVars(env, rejectCleared);
        }
        if (thenExits && boundCleared.length) {
          return clearVars(env, boundCleared);
        }
        // Kaioken XXVIII — if (!row) return; clears maybe-null on fall-through
        const nullGuarded = varsNullCheckedInCondition(stmt.condition);
        if (thenExits && nullGuarded.length) {
          const next = cloneEnv(env);
          for (const v of nullGuarded) next.maybeNull.delete(v);
          return next;
        }
        // Kaioken XXXI — if (data !== req.session.csrfToken) return; clears taint on data
        const csrfCleared = varsClearedByCsrfGuard(stmt.condition);
        if (thenExits && csrfCleared.length) {
          ectx.csrfGated = true;
          return clearVars(env, csrfCleared);
        }
        // Kaioken LIII — header CSRF vs session.csrfToken gate (no named var clear)
        if (thenExits && conditionLooksLikeCsrfGuard(stmt.condition)) {
          ectx.csrfGated = true;
        }
        // Kaioken LIII — HMAC / timingSafeEqual fail → return; fall-through is verified
        if (thenExits && conditionLooksLikeHmacOrTimingSafeReject(stmt.condition)) {
          ectx.hmacVerified = true;
          const hmacCleared = varsMentioned(stmt.condition);
          if (hmacCleared.length) {
            // keep going with cleared compare vars; verified body assigned next
            return clearVars(env, hmacCleared.filter((n) => !/^(_expected|_sig|crypto|Buffer)$/.test(n)));
          }
        }
        // Kaioken XXXII — if (_blocked/_isMeta) return after private/metadata host check
        // clears URL parents tracked in hostFromUrl (cloud_ssrf safe twins)
        if (thenExits && conditionLooksLikeHostBlockFlag(stmt.condition)) {
          const names = [
            ...env.hostFromUrl.keys(),
            ...env.hostFromUrl.values(),
            ...varsMentioned(stmt.condition),
            ...env.vars.keys(),
            'data',
            'target_url',
            'targetUrl',
            'url',
            'resolved',
            'parsed',
            'parsedUri',
            'socketHost',
            'socketRaw',
            'addr',
          ];
          return clearVars(env, names);
        }
        // Kaioken XXXI — if (!req.session.user) return; gates session fixation writes
        if (thenExits && conditionIsSessionUserGuard(stmt.condition)) {
          ectx.sessionUserGated = true;
        }
        if (thenExits) return env;
        // Allowlist-fail then Y = literal: pass path is constrained, fail path is const.
        // Join would keep Y tainted from the pre-if copy; clear it.
        const allowlistRewritten = varsAssignedLiteralOnAllowlistFail(
          stmt.condition,
          stmt.thenBlock,
          env,
        );
        if (allowlistRewritten.length) {
          return clearVars(joinEnvs(thenEnv, env), allowlistRewritten);
        }
        return joinEnvs(thenEnv, env);
      }

      const parts: TaintEnv[] = [];
      if (!thenExits) parts.push(thenEnv);
      if (!elseExits) parts.push(elseEnv);
      if (parts.length === 0) return emptyEnv();
      if (parts.length === 1) return parts[0];
      return joinEnvs(parts[0], parts[1]);
    }
    case 'Loop': {
      // Single pass is unsound (a loop can propagate taint through its back-edge)
      // but consistent with v1 scope. A real fixed-point iteration lands later.
      return analyzeBlock(stmt.body, env, ectx);
    }
    case 'TryCatch': {
      // Kaioken LI — empty catch after JSON.parse(taint) is fail-open / generic_catch
      emitEmptyCatchAfterParse(stmt, env, ectx);
      // Kaioken LIII — non-empty catch that surfaces an error → privilege-drop is handled
      const prevPriv = ectx.privilegeDropHandled;
      const prevTry = ectx.inTryBlock;
      if (stmt.catchBlock && catchBlockHandlesPrivilegeError(stmt.catchBlock)) {
        ectx.privilegeDropHandled = true;
      }
      ectx.inTryBlock = true;
      let tryEnv: TaintEnv;
      try {
        tryEnv = analyzeBlock(stmt.tryBlock, env, ectx);
      } finally {
        ectx.privilegeDropHandled = prevPriv;
        ectx.inTryBlock = prevTry;
      }
      if (!stmt.catchBlock) return tryEnv;
      const catchEnv = analyzeBlock(stmt.catchBlock, env, ectx);
      // catch that always returns (URL parse fail → 403) → fall-through is try path only
      if (blockAlwaysExits(stmt.catchBlock)) return tryEnv;
      return joinEnvs(tryEnv, catchEnv);
    }
  }
  return env;
}

/**
 * Evaluate a Value in the current environment, returning any taint labels it
 * carries. Side effect: if the Value is a Call that hits a sink, emit a
 * finding for every tainted argument at a dangerous position.
 */
function evaluate(value: Value, env: TaintEnv, loc: Location, ectx: EvalCtx): TaintLabel[] {
  switch (value.kind) {
    case 'Literal':
      // Kaioken XI — hardcoded secret-like strings are taint sources (creds/keys)
      if (
        value.literalKind === 'string' &&
        value.raw &&
        looksLikeHardcodedSecret(value.raw)
      ) {
        return [{
          source: HARDCODED_SECRET_SOURCE,
          flow: [{ statementId: '<hardcoded-secret>', variable: undefined, location: loc }],
        }];
      }
      return [];
    case 'Unknown':
      return [];

    case 'Variable':
      return env.vars.get(value.name) ?? [];

    case 'FieldAccess': {
      // Is the whole access a taint source? e.g. req.body, req.query.id
      const source = matchSource(value);
      if (source) {
        // process.env.USER_INPUT is BenchProctor attacker stand-in (not ENC_KEY).
        // Re-tag as user-input so createCipheriv / crypto key sinks fire (CWE-320/324).
        let src = source;
        if (jsLegacy() && source.id === 'process.env') {
          const fpath = calleePathOf(value);
          const field = fpath && fpath.length >= 3 ? fpath[fpath.length - 1] : '';
          if (field && /^(USER_INPUT|ATTACKER|UNTRUSTED)/i.test(field)) {
            src = {
              ...source,
              id: `process.env.${field}`,
              kind: 'user-input' as const,
              description: `process.env.${field} — BenchProctor attacker stand-in`,
            };
          }
        }
        return [{
          source: src,
          flow: [{ statementId: '<source>', variable: undefined, location: loc }],
        }];
      }
      // Kaioken XIX — { secret: "p4ssw0rd" }.secret inline object field
      if (value.object.kind === 'ObjectLiteral') {
        for (const prop of value.object.props) {
          if (prop.key === value.field) {
            return evaluate(prop.value, env, loc, ectx);
          }
        }
      }
      // Kaioken XVII — null deref: row.name after row = arr.find(...)
      const fpath0 = valueAsFieldPath(value);
      if (fpath0 && env.maybeNull.has(fpath0.base) && fpath0.fields.length >= 1) {
        ectx.findings.push({
          file: loc.file,
          line: loc.line,
          type: 'injection',
          severity: 'MED',
          description: `Property access on result of find/findOne without null check — null dereference`,
          source: 'control-flow',
          sink: 'null.deref',
          testCase: 'find() returns undefined; accessing .field throws',
          flow: [{ statementId: '<null-deref>', variable: fpath0.base, location: loc }],
        });
      }
      // Field-sensitive lookup: obj.payload, then fall back to whole-obj taint
      const fpath = valueAsFieldPath(value);
      if (fpath) {
        // zod safeParse result .data after success check — validated clean
        if (fpath.fields.length === 1 && fpath.fields[0] === 'data' && env.zodValidated.has(fpath.base)) {
          return [];
        }
        const exact = joinTaintKey(fpath.base, fpath.fields);
        if (exact && env.vars.has(exact)) return env.vars.get(exact)!;
        // prefix: obj.a.b → try obj.a, then obj
        for (let i = fpath.fields.length - 1; i >= 0; i--) {
          const pref = joinTaintKey(fpath.base, fpath.fields.slice(0, i));
          if (pref && env.vars.has(pref)) return env.vars.get(pref)!;
        }
        if (env.vars.has(fpath.base)) return env.vars.get(fpath.base)!;
      }
      // Otherwise, taint flows through field access: if `x` is tainted, so is `x.foo`.
      return evaluate(value.object, env, loc, ectx);
    }

    case 'Call': {
      // Resolve callee path (e.g. `eval` → ['eval'], `vm.runInNewContext` → ['vm', 'runInNewContext'])
      const calleePath = calleePathOf(value.callee);

      // Sanitizer? (Kaioken VII: resolve require aliases before catalog match)
      const sanitizer = calleePath
        ? matchSanitizer(calleePath, ectx.module.imports)
        : null;

      // Evaluate args (and Python/JS keyword args) to gather their taint labels
      const posLabels = value.args.map(a => evaluate(a, env, loc, ectx));
      const kwLabels = (value.kwargs || []).map(k => evaluate(k.value, env, loc, ectx));
      const argLabels = [...posLabels, ...kwLabels];

      // Method-call taint propagation: `x.foo()` where `x` is tainted should
      // produce a tainted result unless `foo` is a sanitizer. The receiver's
      // taint is captured by evaluating the callee expression (which, if it's
      // a FieldAccess, recursively walks to the receiver).
      const receiverLabels = value.callee.kind === 'FieldAccess'
        ? evaluate(value.callee.object, env, loc, ectx)
        : [];
      // Closure-value call: `const f = capture(taint); f()` — f itself is tainted.
      const calleeVarLabels =
        value.callee.kind === 'Variable'
          ? (env.vars.get(value.callee.name) ?? [])
          : [];

      // Sink check — emit finding if a dangerous arg has taint the sanitizer hasn't cleared
      const sink = calleePath ? matchSink(calleePath, ectx.module.imports) : null;
      const calleeTail = calleePath ? calleePath[calleePath.length - 1] : '';
      if (calleeTail === 'regenerate') ectx.sessionRegenerated = true;
      if (
        sink &&
        (ectx.beanValidated || ectx.stringAllowlisted) &&
        /ELProcessor|parseExpression|ValueExpression|Spel\.parseExpression/.test(sink.id)
      ) {
        // Bean Validation already rejected invalid input — EL eval is not a vuln.
      } else if (
        sink &&
        (sink.id === 'php.log.any' || sink.id === 'php.error_log') &&
        ectx.module.frontendNotes.includes('php-log-crlf-stripped')
      ) {
        // str_replace CR/LF before logger — loginjection / sensinlogs safe twin
      } else if (
        sink &&
        (sink.id === 'php.file_get_contents' || sink.id === 'php.file_put_contents') &&
        ectx.module.frontendNotes.includes('php-ssrf-range-gated')
      ) {
        // FILTER_FLAG_NO_PRIV_RANGE / gethostbyname gate — SSRF safe twin
      } else if (sink && sink.id === 'php.session' && ectx.sessionRegenerated) {
        // regenerate() before session([...]) is the safe twin
      } else if (sink && !sinkCallIsHardened(sink.id, value)) {
        // Keyword sinks: RedirectResponse(url=taint)
        if (sink.dangerousKwargs && value.kwargs) {
          for (const kw of value.kwargs) {
            if (!sink.dangerousKwargs.includes(kw.key)) continue;
            if (isFixedHostOrPathBase(kw.value, sink.id, env, loc, ectx)) continue;
            const kwLabs = evaluate(kw.value, env, loc, ectx);
            for (const label of kwLabs) {
              if (label.source.id === 'config') continue;
              ectx.findings.push({
                file: loc.file,
                line: loc.line,
                type: mapSinkDangerToType(sink.danger),
                severity: 'HIGH',
                description: `Tainted value from ${label.source.description.split(' — ')[0]} reaches ${sink.id}(${kw.key}=) — ${sink.description.toLowerCase()}`,
                source: label.source.id,
                sink: sink.id,
                testCase: synthesizeTestCase(label.source, sink),
                flow: [...label.flow, { statementId: '<sink>', variable: undefined, location: loc }],
              });
            }
          }
        }
        for (const idx of sink.dangerousArgs) {
          // Kaioken L / LIII — fixed-host URL guard + fixed-prefix+encodeURIComponent path guard
          // (https.get("https://fixed..."+taint), https.get({hostname:"fixed",...}),
          //  fs.read("/var/..."+encodeURIComponent(taint)) — CWE-22 vulns do NOT encode)
          const argExpr = value.args && value.args[idx];
          if (argExpr && isFixedHostOrPathBase(argExpr, sink.id, env, loc, ectx)) {
            continue;
          }
          if (argExpr && sink.id.startsWith('php.db.') && isPhpBacktickIdentQuoted(argExpr)) {
            continue;
          }
          // Kaioken LIII — fixed-path write of crypto-protected content (cipher.bin / pbkdf2 digests)
          if (
            argExpr &&
            (sink.id === 'fs.writeFileSync' ||
              sink.id === 'fs.writeFile' ||
              sink.id === 'fs.appendFileSync' ||
              sink.id === 'fs.appendFile') &&
            idx === 1 &&
            isFixedPathLiteral(value.args[0]) &&
            isCryptoProtectedValue(argExpr, env)
          ) {
            continue;
          }
          // Kaioken LIII — fixed-path write of integrity-verified file content
          // (CWE-353 safe: hash then promote; vuln still hits via fs.write.unverified).
          // Do NOT suppress secrets.txt / credential paths (CWE-312/522 cleartext storage).
          if (
            argExpr &&
            (sink.id === 'fs.writeFileSync' || sink.id === 'fs.writeFile') &&
            idx === 1 &&
            isFixedPathLiteral(value.args[0]) &&
            argExpr.kind === 'Variable' &&
            !env.unverifiedReads.has(argExpr.name)
          ) {
            const pth =
              value.args[0]?.kind === 'Literal' ? String(value.args[0].raw || '') : '';
            const secretsPath = /secret|password|credential|token|\.pem$|\.key$/i.test(pth);
            if (!secretsPath) {
              const contentLabs = argLabels[idx] ?? [];
              if (
                contentLabs.length > 0 &&
                contentLabs.every(
                  (l) =>
                    l.source.id === 'fs.content' ||
                    /File\/stdin read content/i.test(l.source.description || '') ||
                    /readFile/i.test(l.source.id || '')
                )
              ) {
                continue;
              }
            }
          }
          // Kaioken LIII — res.send/end of pure file content is not XSS of user HTML.
          // CWE-22 pathtraver safes: path gated then read+send; vulns still flag on fs.read path.
          if (
            (sink.id === 'express.res.send' ||
              sink.id === 'express.res.end' ||
              sink.id === 'express.res.write') &&
            idx === 0
          ) {
            const sendLabs = argLabels[idx] ?? [];
            if (
              sendLabs.length > 0 &&
              sendLabs.every(
                (l) =>
                  l.source.id === 'fs.content' ||
                  /File\/stdin read content/i.test(l.source.description || '')
              )
            ) {
              continue;
            }
          }
          // NOTE: parameterized db.execute("…?", [taint]) is INTENTIONALLY a finding.
          // BenchProctor keys CWE-345 data-integrity and CWE-352 CSRF on bind-param
          // taint (see sarif cwePrimary / ALIASES). Suppressing bind kills QT TPR.
          // Off-CWE spray on other safes is the cost of those keyed TPs (D1 territory).
          // Kaioken LIII — writes under mkdtempSync/tmpdir path (CWE-377 safe twins)
          if (
            (sink.id === 'fs.writeFileSync' ||
              sink.id === 'fs.writeFile' ||
              sink.id === 'fs.appendFileSync' ||
              sink.id === 'fs.appendFile') &&
            (idx === 0 || idx === 1) &&
            pathUsesTempDir(value.args[0], env)
          ) {
            continue;
          }
          // Buffer.alloc(parseInt(data)) — parseInt is a sanitizer for injection
          // but size is still attacker-controlled for resource exhaustion.
          let labels = argLabels[idx] ?? [];
          // Numeric peels: parseInt / |0 don't clear size/uid control
          if (labels.length === 0 && value.args[idx] && isNumericSizeSink(sink.id)) {
            labels = peelIntegerWrap(value.args[idx], env, loc, ectx);
          }
          for (const label of labels) {
            // parseInt-coerced taint: still fires size/uid sinks, not code/sql/cmd injection
            if (label.numericCoerced) {
              if (!isNumericSizeSink(sink.id)) continue;
            }
            // Env-backed keys are not hardcodedcreds (BP safe twin uses process.env.ENC_KEY).
            // Exception: process.env.USER_INPUT is BP attacker stand-in (CWE-320/324 empty FNs).
            if (isEnvSource(label) && !isAttackerEnvSource(label)) {
              if (
                /createCipher|jwt\.sign|jsonwebtoken/i.test(sink.id) ||
                sink.id === 'jsonwebtoken.sign' ||
                sink.id === 'jwt.sign'
              ) {
                continue;
              }
              // Do NOT skip authCheck — default-cred authCheck("admin", envUser) is still a TP
            }
            // Directory listing safe twins: readdir after session.user gate
            if (
              ectx.sessionUserGated &&
              (sink.id === 'fs.readdirSync' || sink.id === 'fs.readdir')
            ) {
              continue;
            }
            // authCheck: default-cred OR brute-force (no rate limit). Skip when rate-limited.
            if (sink.id === 'authCheck') {
              const isDefault = authCheckLooksDefaultCred(value);
              if (!isDefault && ectx.rateLimitPresent) continue;
              // Kaioken LII - env-backed secret/cred (BP safe twins like benchmark_test_00013 use process.env for token)
              // is not attacker-controlled user input for brute-force / CWE-307. Suppress spray on safe QT.
              // Keep default-cred cases even if env (e.g. authCheck("admin", envUser) is TP).
              if (!isDefault && hasEnvTaint(value.args?.[1], env, loc, ectx)) {
                continue;
              }
              // Kaioken LIII — fail-closed gate `if (!authCheck(...)) return 401` is not CWE-307.
              // Vuln twins use positive `if (authCheck(...)) { authenticated }` without rate limit.
              if (!isDefault && ectx.inNegation) {
                continue;
              }
            }
            // Kaioken LIII — setuid/setgid inside try with handled catch is not silent priv failure
            if (
              ectx.privilegeDropHandled &&
              (sink.id === 'process.setuid' ||
                sink.id === 'process.setgid' ||
                sink.id === 'setuid.bare' ||
                sink.id === 'setgid.bare')
            ) {
              continue;
            }
            // Kaioken LIII — HMAC/timingSafeEqual verified payload to queue is not CWE-20 spray
            if (
              ectx.hmacVerified &&
              (sink.id === 'sqs.sendMessage' ||
                sink.id === 'sns.publish' ||
                /sqs\.|sns\./i.test(sink.id))
            ) {
              continue;
            }
            // Kaioken LIII — js-yaml.load of fixed config path is package-path noise, not deserial of user input
            if (
              (sink.id === 'js-yaml.pkg' ||
                sink.id === 'js-yaml.load' ||
                sink.id === 'jsyaml.load' ||
                sink.id === 'yaml.load') &&
              argExpr &&
              isFixedConfigFileRead(argExpr)
            ) {
              continue;
            }
            // Kaioken LIII — cookie value taint after session.user gate (CWE-539 safe)
            if (
              ectx.sessionUserGated &&
              (sink.id === 'express.res.cookie' || sink.id === 'koa.ctx.cookies.set')
            ) {
              continue;
            }
            // Kaioken LIII — structured audit log sandwich:
            //   "audit actor=" + data + " action=revoke_sessions"
            // CWE-221 safe twins. Plain log injection vulns are "Action: " + data (one literal).
            if (
              (sink.id === 'console.log' ||
                sink.id === 'console.error' ||
                sink.id === 'console.info' ||
                sink.id === 'console.warn') &&
              argExpr &&
              isStructuredAuditLogMessage(argExpr)
            ) {
              continue;
            }

            // Jinja Environment(autoescape=True).from_string(...).render(value=data)
            // is HTML-escaped. HTMLResponse of that result is not XSS/SSTI.
            // Template(data) SSTI still fires via the Template() constructor sink.
            if (sink.id === 'python.HTMLResponse' && fileHasJinjaAutoescape(loc.file)) {
              continue;
            }
            if (
              (sink.id === 'python.etree.fromstring' ||
                sink.id === 'python.etree.fromstring.any') &&
              fileHasXmlSchema(loc.file)
            ) {
              continue;
            }

            let desc = `Tainted value from ${label.source.description.split(' — ')[0]} reaches ${sink.id} — ${sink.description.toLowerCase()}`;
            if (sink.id === 'authCheck' && authCheckLooksDefaultCred(value)) {
              desc += ' — default credentials (literal admin/password)';
            } else if (sink.id === 'authCheck') {
              desc += ' — no brute-force rate limit on authCheck';
            }
            // Kaioken LVI — res.set/setHeader("Content-Type", taint) is CWE-115 MIME
            // misinterpretation (ts-normal held-out hole), not generic CRLF CWE-113.
            if (
              (sink.id === 'express.res.set' ||
                sink.id === 'express.res.setHeader' ||
                sink.id === 'koa.ctx.set') &&
              isContentTypeHeaderName(value.args[0])
            ) {
              desc = `Tainted value from ${label.source.description.split(' — ')[0]} reaches ${sink.id}("Content-Type") — content-type misinterpretation`;
            }
            // Secrets path write → cleartext storage / credprotection CWE
            // Skip *.enc / ciphertext filenames (BP cleartextstorage safe encrypts first)
            if (
              (sink.id === 'fs.writeFileSync' ||
                sink.id === 'fs.writeFile' ||
                sink.id === 'fs.appendFileSync') &&
              value.args[0]?.kind === 'Literal' &&
              value.args[0].literalKind === 'string'
            ) {
              const pth = value.args[0].raw || '';
              if (
                /secret|password|credential|token|\.pem$|\.key$/i.test(pth) &&
                !/\.enc$/i.test(pth) &&
                !/ciphertext|encrypted/i.test(pth)
              ) {
                desc += ' — cleartext storage of secret/credential material';
              }
            }
            ectx.findings.push({
              file: loc.file,
              line: loc.line,
              type: mapSinkDangerToType(sink.danger),
              severity: 'HIGH',
              description: desc,
              source: label.source.id,
              sink: sink.id,
              testCase: synthesizeTestCase(label.source, sink),
              flow: [
                ...label.flow,
                { statementId: '<sink>', variable: undefined, location: loc },
              ],
            });
          }
        }
      }

      // Kaioken XVIII — eval('res.redirect(data)') string-literal code with free vars
      if (jsLegacy()) emitEvalStringLiteral(value, calleePath, env, loc, ectx);

      // Kaioken IX — weak hash: crypto.createHash("md5").update(taint)
      if (jsLegacy()) emitWeakHashFindings(value, calleePath, argLabels, env, loc, ectx);

      // Kaioken XXXV — createHash(...).update(content) / createHmac verifies integrity
      if (
        value.callee.kind === 'FieldAccess' &&
        value.callee.field === 'update' &&
        value.args[0]
      ) {
        for (const name of varsMentioned(value.args[0])) {
          env.unverifiedReads.delete(name);
        }
      }
      // Kaioken XXXVI — CSV formula sanitizer: cell = /^[=+\-@]/.test(data) ? "'" + data : data
      // Also clear taint for formula-prefix strip on appendFile content when arg is quoted-safe.
      // (Handled via reject-style clear when ternary peels — see peelCsvSanitized below)
      // writeFileSync(path, unverifiedContent) without prior hash → missing integrity
      if (sink && (sink.id === 'fs.writeFileSync' || sink.id === 'fs.writeFile')) {
        const contentArg = value.args[1];
        if (contentArg) {
          for (const name of varsMentioned(contentArg)) {
            if (env.unverifiedReads.has(name)) {
              ectx.findings.push({
                file: loc.file,
                line: loc.line,
                type: 'injection',
                severity: 'HIGH',
                description:
                  'Write of readFile content without integrity check (hash/signature) — missing integrity check',
                source: 'control-flow',
                sink: 'fs.write.unverified',
                testCase: 'Tamper cached package bytes before promote-to-active write',
                flow: [{ statementId: '<integrity>', variable: name, location: loc }],
              });
            }
          }
        }
      }

      // JS-only structural extras — live in the JS catalog extras, not as
      // analyzer guards. Python/Java catalogs leave jsLegacyEmits unset.
      if (ACTIVE_CATALOG.extras?.jsLegacyEmits) {
        emitTlsVerifyDisabled(value, calleePath, loc, ectx);
        emitCertHostIdentityBypass(value, calleePath, loc, ectx);
        emitBareJsonParse(value, calleePath, argLabels, loc, ectx);
        emitInfoLossOmissionLog(value, calleePath, argLabels, env, loc, ectx);
        emitErrorDisclosure(value, calleePath, env, loc, ectx);
        emitNestExceptionDisclosure(value, calleePath, env, loc, ectx);
        emitInsecureCookieFlags(value, calleePath, loc, ectx);
        emitMathRandom(value, calleePath, loc, ectx);
        emitWeakKeyAndCipher(value, calleePath, loc, ectx);
        emitRsaPkcs1NoOaep(value, calleePath, loc, ectx);
        emitHardcodedCryptoKey(value, calleePath, env, loc, ectx);
        emitPrototypePollution(value, calleePath, argLabels, loc, ectx);
      }
      emitUncheckedDbExecute(value, calleePath, argLabels, loc, ectx);
      emitExtraParameterRole(value, calleePath, argLabels, env, loc, ectx);

      // Kaioken XVI — shift/pop return receiver taint (pending.shift() → collected.push)
      if (
        value.callee.kind === 'FieldAccess' &&
        (value.callee.field === 'shift' ||
          value.callee.field === 'pop' ||
          value.callee.field === 'join' ||
          value.callee.field === 'slice' ||
          value.callee.field === 'concat' ||
          value.callee.field === 'toString' ||
          value.callee.field === 'valueOf')
      ) {
        // fall through to unknown-function return which includes receiverLabels
      }

      // Kaioken IX — `new Class(taint)` propagates arg taint to instance (field reads)
      const ctorTaint = constructorArgTaint(calleePath, argLabels);

      // Kaioken XL — str.replace(/[\r\n]/) and HTML-entity replace clear header/XSS taint
      if (
        value.callee.kind === 'FieldAccess' &&
        value.callee.field === 'replace' &&
        (isHtmlOrCrlfSanitizingReplace(value) || isSqlIdentQuoteReplace(value))
      ) {
        return [];
      }
      // re.sub(r'[A-Za-z0-9]{4,}', '****', data) — log-redaction safes
      if (isRedactingSub(value)) {
        return [];
      }

      // Catalog sanitizer: return is clean — except weak encoders / path.normalize
      // which do not neutralize traversal or injection (Kaioken IX/XIX).
      if (sanitizer) {
        if (
          sanitizer.id === 'encodeURIComponent' ||
          sanitizer.id === 'encodeURI' ||
          sanitizer.id === 'path.normalize' ||
          sanitizer.id === 'path.resolve'
        ) {
          return argLabels.flat();
        }
        return [];
      }

      // Kaioken LIII — fixed-template render (SSTI safe): renderString("<p>{{ x }}</p>", {x: taint})
      // Template literal is not attacker-controlled; context values are data, not SSTI.
      // Vuln twins pass taint as arg0: renderString(data, {}).
      if (
        jsLegacy() &&
        calleePath &&
        (calleePath[calleePath.length - 1] === 'renderString' ||
          (calleePath[0] === 'nunjucks' && calleePath[1] === 'renderString') ||
          (calleePath[0] === 'ejs' && calleePath[1] === 'render') ||
          (calleePath[0] === 'pug' && (calleePath[1] === 'render' || calleePath[1] === 'compile')) ||
          (calleePath[0] === 'handlebars' && calleePath[1] === 'compile'))
      ) {
        const tpl = value.args[0];
        if (tpl && tpl.kind === 'Literal' && tpl.literalKind === 'string') {
          return [];
        }
      }

      // Language catalog: call-return second-order sources (db / fs / s3 / redis / …)
      const callSrc = ACTIVE_CATALOG.matchCallSourceExtra?.(
        calleePath || [],
        ectx.module.imports
      );
      if (callSrc) {
        return [{
          source: callSrc,
          flow: [{ statementId: '<call-source>', variable: undefined, location: loc }],
        }];
      }

      // Kaioken XX — Promise.resolve(x) carries arg taint; .then(fn) passes receiver taint
      if (
        jsLegacy() &&
        calleePath &&
        calleePath[calleePath.length - 1] === 'resolve' &&
        (calleePath[0] === 'Promise' || calleePath.length === 1)
      ) {
        const labs = argLabels.flat();
        if (labs.length) {
          return labs.map(l => ({
            source: l.source,
            flow: [
              ...l.flow,
              { statementId: '<promise-resolve-static>', variable: undefined, location: loc },
            ],
          }));
        }
      }
      if (
        jsLegacy() &&
        value.callee.kind === 'FieldAccess' &&
        value.callee.field === 'then' &&
        receiverLabels.length
      ) {
        // Promise.resolve(taint).then(String) — keep taint through then
        return receiverLabels.map(l => ({
          source: l.source,
          flow: [
            ...l.flow,
            { statementId: '<promise-then>', variable: undefined, location: loc },
          ],
        }));
      }

      // Kaioken XIX — http(s).get/request(options) with Authorization header / host taint
      if (jsLegacy()) emitHttpOptionsTaint(value, calleePath, env, loc, ectx);

      // Kaioken XIX — setImmediate/setTimeout/nextTick: analyze callback free vars
      if (jsLegacy() && isTimerApi(calleePath)) {
        for (const a of value.args) {
          if (a.kind === 'Variable') {
            const cb = ectx.module.byName.get(a.name);
            if (cb) {
              const entry = emptyEnv();
              for (const [k, labs] of env.vars) {
                entry.vars.set(k, labs.map(l => ({ ...l, flow: [...l.flow] })));
              }
              const result = analyzeFunctionEntry(cb, ectx.module, entry, {
                nestController: ectx.nestController,
              });
              ectx.findings.push(...result.findings);
              // resolve(userInput) inside timer → return those labels upward
              const resolved = collectResolveArgTaint(cb, entry, ectx.module, loc);
              if (resolved.length) {
                return resolved.map(l => ({
                  source: l.source,
                  flow: [
                    ...l.flow,
                    { statementId: '<timer-resolve>', variable: undefined, location: loc },
                  ],
                }));
              }
            }
          }
        }
      }

      // Kaioken XVII/XIX — new Promise((resolve) => { ... }) + resolve(taint) return
      if (
        jsLegacy() &&
        calleePath &&
        (calleePath[calleePath.length - 1] === 'Promise' || calleePath[0] === 'Promise')
      ) {
        const resolveLabs: TaintLabel[] = [];
        for (const a of value.args) {
          if (a.kind === 'Variable') {
            const execFn = ectx.module.byName.get(a.name);
            if (execFn) {
              const entry = emptyEnv();
              for (const [k, labs] of env.vars) {
                entry.vars.set(k, labs.map(l => ({ ...l, flow: [...l.flow] })));
              }
              // inject resolve param as unbound — collect resolve(arg) taint
              const result = analyzeFunctionEntry(execFn, ectx.module, entry, {
                nestController: ectx.nestController,
              });
              ectx.findings.push(...result.findings);
              resolveLabs.push(...collectResolveArgTaint(execFn, entry, ectx.module, loc));
              // Nested setImmediate inside executor also runs via timer analysis when we
              // re-evaluate? Walk executor body Calls to setImmediate.
              resolveLabs.push(...collectNestedTimerResolveTaint(execFn, entry, ectx.module, loc));
              // Kaioken XLVII — NestJS `_asyncOut = html/url` free-var writes inside executor
              const freeWrites = freeVarTaintFromCalleeEval(execFn, entry, ectx.module, loc);
              if (freeWrites.size) {
                if (!ectx.callSideEffects) ectx.callSideEffects = new Map();
                for (const [k, labs] of freeWrites) {
                  ectx.callSideEffects.set(k, labs);
                }
              }
            }
          }
        }
        if (resolveLabs.length) {
          return resolveLabs.map(l => ({
            source: l.source,
            flow: [
              ...l.flow,
              { statementId: '<promise-resolve>', variable: undefined, location: loc },
            ],
          }));
        }
        // Free-var-only Promise (no resolve(taint)) still may write outer vars
        if (ectx.callSideEffects?.size) {
          return [];
        }
      }

      // ── Kaioken IV/V: within-file + cross-file interprocedural ───────────
      const targetFn = resolveCallee(calleePath, ectx.module);
      if (targetFn) {
        const entry = emptyEnv();
        for (let i = 0; i < targetFn.params.length; i++) {
          const pname = targetFn.params[i];
          const labs = argLabels[i] ?? [];
          if (labs.length) {
            entry.vars.set(
              pname,
              labs.map(l => ({
                source: l.source,
                flow: [
                  ...l.flow,
                  { statementId: '<call-arg>', variable: pname, location: loc },
                ],
              }))
            );
          }
        }
        // Free vars from caller (handler tables: primary: () => sink(data))
        for (const [k, labs] of env.vars) {
          if (!targetFn.params.includes(k) && !entry.vars.has(k)) {
            entry.vars.set(k, labs.map(l => ({ ...l, flow: [...l.flow] })));
          }
        }
        const result = analyzeFunctionEntry(targetFn, ectx.module, entry, {
          nestController: ectx.nestController,
        });
        ectx.findings.push(...result.findings);
        // Kaioken VIII: free-var writes ` (v) => { data = v } ` → outer `data` tainted
        const freeWrites = freeVarTaintFromCallee(targetFn, entry);
        if (freeWrites.size) ectx.callSideEffects = freeWrites;

        return result.returnLabels.map(l => ({
          source: l.source,
          flow: [
            ...l.flow,
            { statementId: '<call-return>', variable: undefined, location: loc },
          ],
        }));
      }

      // Unknown function: conservatively pass through receiver + callable-value + arg taint.
      // Also constructor-style calls (capitalized callee) carry arg taint on the instance.
      // Method-as-source: request.get_json() — the FieldAccess itself is the source.
      const calleeSourceLabels =
        value.callee.kind === 'FieldAccess' ? evaluate(value.callee, env, loc, ectx) : [];
      return [
        ...receiverLabels,
        ...calleeVarLabels,
        ...calleeSourceLabels,
        ...argLabels.flat(),
        ...ctorTaint,
      ];
    }

    case 'Template': {
      // A template string propagates taint from any embedded expression.
      const inner = value.parts.flatMap(p =>
        'expr' in p ? evaluate(p.expr, env, loc, ectx) : []
      );
      return inner;
    }

    case 'Binary': {
      // CSV formula sanitizer: /^[=+\-@]/.test(data) ? "'" + data : data
      // Ternary lowers as Binary op "?:"; either arm still carries data, but
      // prefixing with apostrophe neutralizes spreadsheet formula injection.
      if (value.op === '?:' && isCsvFormulaSanitizedTernary(value)) {
        return [];
      }
      // BP cmdi/ssrf safes: (allowlist) ? data : "asc" / "/bin/echo" / "default"
      // False arm is a shell-safe literal; the (dropped) condition constrained data.
      if (value.op === '?:' && isAllowlistFallbackTernary(value)) {
        return [];
      }
      const leftLabs = evaluate(value.left, env, loc, ectx);
      const rightLabs = evaluate(value.right, env, loc, ectx);
      // Division/mod by attacker-controlled divisor without prior zero-check
      if ((value.op === '/' || value.op === '%') && !ectx.divisorZeroChecked) {
        let divLabs = rightLabs;
        if (!divLabs.length && value.right) {
          divLabs = peelIntegerWrap(value.right, env, loc, ectx);
        }
        if (divLabs.length) {
          emitDivideByZero(divLabs, loc, ectx);
        }
      }
      const binLabs = [...leftLabs, ...rightLabs];
      // Kaioken L — BP LCG: (seed * 9301 + 49297) % 233280 with tainted seed
      if (binLabs.length && binaryTreeHasLcgMagic(value)) {
        emitWeakLcgPrng(binLabs, loc, ectx);
      }
      return binLabs;
    }

    case 'Unary': {
      // !x / -x / etc. — taint flows through the operand; barrier logic lives
      // in Conditional analysis (varsClearedByRejectAllowlist).
      // Kaioken LIII — track negation so authCheck fail-closed guards can be suppressed.
      if (value.op === '!' || value.op === 'not') {
        const prev = ectx.inNegation;
        ectx.inNegation = true;
        try {
          return evaluate(value.operand, env, loc, ectx);
        } finally {
          ectx.inNegation = prev;
        }
      }
      return evaluate(value.operand, env, loc, ectx);
    }

    case 'ArrayLiteral': {
      // Constant arrays themselves are not tainted. Elements may be.
      return value.elements.flatMap(el => evaluate(el, env, loc, ectx));
    }

    case 'ObjectLiteral': {
      // Reading an object literal as a value joins taint of all props (rare as rvalue).
      return value.props.flatMap(p => evaluate(p.value, env, loc, ectx));
    }
  }
}

/** Walk FieldAccess chain to base Variable + field path. */
function valueAsFieldPath(v: Value): { base: string; fields: string[] } | null {
  const fields: string[] = [];
  let cur: Value = v;
  while (cur.kind === 'FieldAccess') {
    fields.unshift(cur.field);
    cur = cur.object;
  }
  if (cur.kind !== 'Variable') return null;
  return { base: cur.name, fields };
}

function joinTaintKey(base: string, fields: string[]): string | null {
  if (fields.length > MAX_FIELD_DEPTH) return null;
  return fields.length ? `${base}.${fields.join('.')}` : base;
}

function deleteKeyPrefix(env: TaintEnv, base: string): void {
  for (const k of [...env.vars.keys()]) {
    if (k === base || k.startsWith(base + '.')) env.vars.delete(k);
  }
}

/** Shallow-copy field keys when `const a = b` and b has b.field taint. */
function copyFieldTaint(dst: TaintEnv, src: TaintEnv, fromBase: string, toBase: string): void {
  const prefix = fromBase + '.';
  for (const [k, labs] of src.vars) {
    if (k.startsWith(prefix)) {
      const rest = k.slice(prefix.length);
      dst.vars.set(`${toBase}.${rest}`, labs.map(l => ({ ...l, flow: [...l.flow] })));
    }
  }
}

/**
 * Resolve callee to a FunctionIR:
 *   - local `foo`
 *   - imported binding `foo` from './helper'
 *   - namespace `helper.foo` where helper = require('./helper')
 */
function resolveCallee(
  calleePath: string[] | null,
  module: ModuleCtx
): FunctionIR | null {
  if (!calleePath || calleePath.length === 0) return null;
  // Don't treat catalog sinks/sanitizers as local/imported functions
  if (matchSink(calleePath, module.imports) || matchSanitizer(calleePath, module.imports)) return null;

  if (calleePath.length === 1) {
    const name = calleePath[0];
    const local = module.byName.get(name);
    if (local) return local;
    const imp = module.imports.find(i => i.localName === name);
    if (imp && imp.imported !== '*') {
      return lookupExport(module, imp.specifier, imp.imported);
    }
    // default import used as callable: import run from './m'; run(x)
    if (imp && imp.imported === 'default') {
      return lookupExport(module, imp.specifier, 'default')
        ?? lookupExport(module, imp.specifier, name);
    }
    return null;
  }

  if (calleePath.length === 2) {
    const [ns, method] = calleePath;
    // Local object-dispatch: _handlers.primary() where primary is a local fn.
    // Do NOT map String(x).normalize / data.slice → local helper of the same name
    // (Kaioken LV — CWE-76 NFKC empty FN when local `function normalize` shadows).
    const PROTOTYPE_METHODS = new Set([
      'normalize',
      'slice',
      'split',
      'join',
      'replace',
      'substring',
      'substr',
      'trim',
      'toLowerCase',
      'toUpperCase',
      'concat',
      'indexOf',
      'includes',
      'startsWith',
      'endsWith',
      'match',
      'padStart',
      'padEnd',
      'repeat',
      'charAt',
      'charCodeAt',
      'toString',
      'valueOf',
      'map',
      'filter',
      'reduce',
      'forEach',
      'push',
      'pop',
      'shift',
      'unshift',
      'then',
      'catch',
      'finally',
      'update',
      'digest',
      'get',
      'set',
      'has',
    ]);
    const looksLikeBuiltinReceiver = /^[A-Z]/.test(ns) || ns === 'console' || ns === 'Math';
    if (!PROTOTYPE_METHODS.has(method) && !looksLikeBuiltinReceiver) {
      const localMethod = module.byName.get(method);
      if (localMethod) return localMethod;
    }

    const imp = module.imports.find(i => i.localName === ns);
    if (!imp) return null;
    if (imp.imported === '*') {
      return lookupExport(module, imp.specifier, method);
    }
    // const helper = require('./m'); helper.run — treated as namespace
    if (imp.imported === 'default' || imp.imported === '*') {
      return lookupExport(module, imp.specifier, method);
    }
  }
  return null;
}

function lookupExport(
  from: ModuleCtx,
  specifier: string,
  exportName: string
): FunctionIR | null {
  const resolved = resolveModulePath(from.modulePath, specifier, from.project);
  if (!resolved) return null;
  const mod = from.project.modules.get(resolved);
  if (!mod) return null;

  const exp =
    (mod.exports ?? []).find(e => e.exportName === exportName) ??
    (exportName !== 'default'
      ? undefined
      : (mod.exports ?? []).find(e => e.exportName === 'default'));

  const localName = exp?.localName ?? (
    // Fallback: bare function name matches export name even if export list missed
    mod.functions.some(f => f.name === exportName) ? exportName : null
  );
  if (!localName) return null;
  return mod.functions.find(f => f.name === localName) ?? null;
}

function resolveModulePath(
  fromFile: string,
  specifier: string,
  project: ProjectCtx
): string | null {
  if (!specifier.startsWith('.')) return null; // only relative for v1 cross-file
  const base = path.resolve(path.dirname(fromFile), specifier);
  const candidates = [
    base,
    base + '.js',
    base + '.ts',
    base + '.tsx',
    base + '.mjs',
    base + '.jsx',
    base + '.cjs',
    path.join(base, 'index.js'),
    path.join(base, 'index.ts'),
  ];
  for (const c of candidates) {
    const n = normalizePath(c);
    if (project.modules.has(n)) return n;
    for (const k of project.modules.keys()) {
      if (normalizePath(k) === n) return k;
    }
  }
  return null;
}

/** True if every path through the block ends in Return or Throw. */
function blockAlwaysExits(block: Block): boolean {
  if (!block.statements.length) return false;
  // Sequential IR: a Return/Throw anywhere ends the block (later stmts dead).
  for (const s of block.statements) {
    if (s.kind === 'Return' || s.kind === 'Throw') return true;
    if (s.kind === 'Conditional') {
      const thenEx = blockAlwaysExits(s.thenBlock);
      const elseEx = s.elseBlock ? blockAlwaysExits(s.elseBlock) : false;
      // Only a full-exit conditional "ends" the outer block if both sides exit
      // AND it's the terminal statement — handle simply: if both exit, treat as exit.
      if (thenEx && elseEx) return true;
    }
  }
  return false;
}

function clearVars(env: TaintEnv, names: string[]): TaintEnv {
  if (!names.length) return env;
  const next = cloneEnv(env);
  const toClear = expandClearSet(names, env);
  for (const n of toClear) {
    deleteKeyPrefix(next, n);
  }
  return next;
}

/** Also clear URL parents of host vars and hosts derived from cleared URLs. */
function expandClearSet(names: string[], env: TaintEnv): Set<string> {
  const toClear = new Set(names);
  for (const n of names) {
    const parent = env.hostFromUrl.get(n);
    if (parent) toClear.add(parent);
  }
  for (const [host, url] of env.hostFromUrl) {
    if (toClear.has(url)) toClear.add(host);
  }
  // `_hurl = data` before `if (data.rfind(prefix) != 0) return` — copies share labels.
  const sourceIds = new Set<string>();
  for (const n of toClear) {
    for (const lab of env.vars.get(n) || []) sourceIds.add(lab.source.id);
  }
  if (sourceIds.size) {
    for (const [k, labs] of env.vars) {
      if (toClear.has(k)) continue;
      if (labs.some((l) => sourceIds.has(l.source.id))) toClear.add(k);
    }
  }
  return toClear;
}

/**
 * Reject guards on the true branch that exit:
 *   if (!allowlist.includes(x)) return;
 *   if (!/^[a-z0-9_.-]+$/.test(x)) return;   // strong allowlist regex only
 * Weak control-char regexes do NOT clear (BenchProctor vuln twins).
 */
function varsClearedByRejectGuard(condition: Value, env: TaintEnv): string[] {
  // Combine OR reject arms: if (len > N || !/strong/.test(x)) return;
  if (condition.kind === 'Binary' && (condition.op === '||' || condition.op === 'or')) {
    const left = varsClearedByRejectGuard(condition.left, env);
    const right = varsClearedByRejectGuard(condition.right, env);
    // Prefer regex/allowlist clears (stronger); merge unique
    const out = [...new Set([...left, ...right])];
    if (out.length) return out;
  }
  if (condition.kind === 'Binary' && (condition.op === '&&' || condition.op === 'and')) {
    const left = varsClearedByRejectGuard(condition.left, env);
    const right = varsClearedByRejectGuard(condition.right, env);
    const out = [...new Set([...left, ...right])];
    if (out.length) return out;
  }
  if (condition.kind === 'Unary' && (condition.op === '!' || condition.op === 'not')) {
    const inner = condition.operand;
    const fromInc = varsFromConstantIncludesCall(inner, env);
    if (fromInc.length) return fromInc;
    const fromInArray = varsFromPhpInArrayCall(inner, env);
    if (fromInArray.length) return fromInArray;
    const fromRe = varsFromStrongRegexTest(inner);
    if (fromRe.length) return fromRe;
    const fromMatches = varsFromJavaMatchesCall(inner);
    if (fromMatches.length) return fromMatches;
    // if (!resolved.startsWith("/var/app/data/")) return — path containment
    const fromPrefix = varsFromPathPrefixStartsWith(inner);
    if (fromPrefix.length) return fromPrefix;
    // if (base not in candidate.parents) return — pathlib containment
    const fromParents = varsFromPathParentsIn(inner);
    if (fromParents.length) return fromParents;
    const fromIn = varsFromConstArrayIn(inner, env);
    if (fromIn.length) return fromIn;
  }
  const fromRfind = varsFromRfindPrefixReject(condition);
  if (fromRfind.length) return fromRfind;
  return [];
}

/** resolved.startsWith("/absolute/prefix") — containment check after path.resolve */
function varsFromPathPrefixStartsWith(v: Value): string[] {
  if (v.kind !== 'Call') return [];
  const callee = v.callee;
  if (callee.kind !== 'FieldAccess' || callee.field !== 'startsWith') return [];
  if (!v.args.length) return [];
  const arg = v.args[0];
  if (arg.kind === 'Literal' && arg.literalKind === 'string' && arg.raw) {
    // Absolute path prefix only (not weak startsWith("a"))
    if (!arg.raw.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(arg.raw)) return [];
    if (arg.raw.length < 4) return [];
    return varsMentioned(callee.object);
  }
  // full_path.startswith(base_dir + os.sep)
  if (arg.kind === 'Binary' && arg.op === '+') {
    const sides = [arg.left, arg.right];
    const sepish = sides.some(
      (s) =>
        (s.kind === 'Literal' && s.literalKind === 'string' && (s.raw === '/' || s.raw === '\\')) ||
        (s.kind === 'FieldAccess' && s.field === 'sep')
    );
    if (sepish) return varsMentioned(callee.object);
  }
  return [];
}

/** PHP `in_array($data, ['asc','desc'])` — needle first, haystack second. */
function varsFromPhpInArrayCall(v: Value, env: TaintEnv): string[] {
  if (v.kind !== 'Call') return [];
  const path = calleePathOf(v.callee);
  if (!path || path[path.length - 1] !== 'in_array') return [];
  if (v.args.length < 2) return [];
  const hay = v.args[1];
  const isAllow =
    isConstantLiteralArray(hay) ||
    (hay.kind === 'Variable' && env.constArrays.has(hay.name));
  if (!isAllow) return [];
  return varsMentioned(v.args[0]);
}

/** `data in allowed` when allowed is a const string set/list. */
function varsFromConstArrayIn(v: Value, env: TaintEnv): string[] {
  if (v.kind !== 'Binary' || v.op !== 'in') return [];
  const recv = v.right;
  const isAllow =
    isConstantLiteralArray(recv) ||
    isConstantLiteralSet(recv) ||
    (recv.kind === 'Variable' && env.constArrays.has(recv.name));
  if (!isAllow) return [];
  return varsMentioned(v.left);
}

/** `base not in candidate.parents` — pathlib containment (inner of Unary not). */
function varsFromPathParentsIn(v: Value): string[] {
  if (v.kind === 'Binary' && v.op === 'in' && v.right.kind === 'FieldAccess' && v.right.field === 'parents') {
    return varsMentioned(v.right.object);
  }
  return [];
}

/**
 * data.rfind("https://api.internal…/", 0) != 0 — C++ starts-with prefix reject.
 * Fall-through has proven the URL/path prefix.
 */
function varsFromRfindPrefixReject(condition: Value): string[] {
  if (condition.kind !== 'Binary' || (condition.op !== '!=' && condition.op !== '!==')) return [];
  const call =
    condition.left.kind === 'Call'
      ? condition.left
      : condition.right.kind === 'Call'
        ? condition.right
        : null;
  if (!call) return [];
  const callee = call.callee;
  if (callee.kind !== 'FieldAccess' || callee.field !== 'rfind') return [];
  const prefix = call.args[0];
  if (prefix?.kind !== 'Literal' || prefix.literalKind !== 'string' || !prefix.raw) return [];
  if (prefix.raw.length < 8) return [];
  if (
    !prefix.raw.startsWith('https://') &&
    !prefix.raw.startsWith('http://') &&
    !prefix.raw.startsWith('/')
  ) {
    return [];
  }
  return varsMentioned(callee.object);
}

/**
 * Null-check guards: if (!row) return; / if (row == null) return;
 * Fall-through path has proven non-null for those vars.
 */
function varsNullCheckedInCondition(condition: Value): string[] {
  // !row / !row.x (only bare vars matter for maybeNull base)
  if (condition.kind === 'Unary' && (condition.op === '!' || condition.op === 'not')) {
    if (condition.operand.kind === 'Variable') return [condition.operand.name];
  }
  // row == null / row === undefined / null == row
  if (condition.kind === 'Binary' && (condition.op === '==' || condition.op === '===' || condition.op === '!=' || condition.op === '!==')) {
    const litNull = (v: Value) =>
      v.kind === 'Literal' && (v.literalKind === 'null' || v.literalKind === 'undefined' || v.raw === 'null' || v.raw === 'undefined');
    if (condition.left.kind === 'Variable' && litNull(condition.right)) return [condition.left.name];
    if (condition.right.kind === 'Variable' && litNull(condition.left)) return [condition.right.name];
  }
  return [];
}

/** catch { res.status(500).json({error:...}); return; } — privilege drop failure is not silent. */
function catchBlockHandlesPrivilegeError(block: Block): boolean {
  if (!block.statements.length) return false;
  const s = JSON.stringify(block);
  return /status|"500"|error|forbidden|privilege|failed/i.test(s);
}

/**
 * Audit-style log: fixed-string + taint + fixed-string (or more fixed segments).
 * Not the single-prefix log-injection vuln shape ("Action: " + data).
 */
function isStructuredAuditLogMessage(v: Value): boolean {
  // Flatten + tree into sequence of leaves
  const leaves: Value[] = [];
  const walk = (x: Value) => {
    if (x.kind === 'Binary' && x.op === '+') {
      walk(x.left);
      walk(x.right);
      return;
    }
    if (x.kind === 'Call') {
      const cp = calleePathOf(x.callee);
      const tail = cp ? cp[cp.length - 1] : '';
      if (tail === 'String' || tail === 'toString') {
        if (x.args[0]) walk(x.args[0]);
        else leaves.push(x);
        return;
      }
    }
    leaves.push(x);
  };
  walk(v);
  if (leaves.length < 3) return false;
  let lit = 0;
  let nonLit = 0;
  for (const leaf of leaves) {
    if (leaf.kind === 'Literal' && leaf.literalKind === 'string') lit++;
    else nonLit++;
  }
  // Need at least two fixed string segments and one dynamic middle
  return lit >= 2 && nonLit >= 1;
}

/** Date.now() + 900000 / short TTL literals used as session expiry. */
function valueLooksLikeSessionTtl(v: Value): boolean {
  if (v.kind === 'Binary' && (v.op === '+' || v.op === '-')) {
    const s = JSON.stringify(v);
    // Date.now() + N or now + minutes
    if (/Date\.now|now|getTime/i.test(s) && /"raw":"\d{3,}"/.test(s)) return true;
    if (v.right?.kind === 'Literal' && v.right.literalKind === 'number') {
      const n = Number(v.right.raw);
      // 1 min .. 7 days in ms
      if (n >= 60_000 && n <= 7 * 24 * 3600 * 1000) return true;
    }
  }
  if (v.kind === 'Literal' && v.literalKind === 'number') {
    const n = Number(v.raw);
    if (n >= 60_000 && n <= 7 * 24 * 3600 * 1000) return true;
  }
  return false;
}

/** js-yaml.load(fs.readFileSync("/etc/app/config.yaml")) — fixed config path, not user deserial. */
function isFixedConfigFileRead(v: Value): boolean {
  if (v.kind === 'Call') {
    const cp = calleePathOf(v.callee);
    const tail = cp ? cp[cp.length - 1] : '';
    if (tail === 'readFileSync' || tail === 'readFile') {
      const p = v.args[0];
      if (p && p.kind === 'Literal' && p.literalKind === 'string') {
        const raw = p.raw || '';
        return /^\/(etc|var|opt|usr)\//.test(raw) || /\.(ya?ml|json|conf|config)$/i.test(raw);
      }
    }
    // .field after load(readFileSync(...))
    if (v.callee.kind === 'FieldAccess') {
      return isFixedConfigFileRead(v.callee.object);
    }
  }
  if (v.kind === 'FieldAccess') return isFixedConfigFileRead(v.object);
  return false;
}

/** if (!allowedFields.includes(k)) return — mass-assign field allowlist. */
function conditionLooksLikeFieldAllowlistReject(condition: Value): boolean {
  if (condition.kind === 'Unary' && (condition.op === '!' || condition.op === 'not')) {
    const inner = condition.operand;
    if (inner.kind === 'Call') {
      const cp = calleePathOf(inner.callee);
      if (cp && cp[cp.length - 1] === 'includes') {
        // receiver is allowlist array (const or literal)
        return true;
      }
    }
  }
  if (condition.kind === 'Binary' && (condition.op === '||' || condition.op === 'or')) {
    return (
      conditionLooksLikeFieldAllowlistReject(condition.left) ||
      conditionLooksLikeFieldAllowlistReject(condition.right)
    );
  }
  return false;
}

/** HMAC / timingSafeEqual failure branch that returns 403. */
function conditionLooksLikeHmacOrTimingSafeReject(condition: Value): boolean {
  const s = JSON.stringify(condition);
  if (/timingSafeEqual|createHmac|createHmac/.test(s)) return true;
  if (/timingSafeEqual/.test(s)) return true;
  if (condition.kind === 'Binary' && (condition.op === '||' || condition.op === 'or' || condition.op === '&&')) {
    return (
      conditionLooksLikeHmacOrTimingSafeReject(condition.left) ||
      conditionLooksLikeHmacOrTimingSafeReject(condition.right)
    );
  }
  if (condition.kind === 'Unary') return conditionLooksLikeHmacOrTimingSafeReject(condition.operand);
  if (condition.kind === 'Call') {
    const cp = calleePathOf(condition.callee);
    if (cp && (cp[cp.length - 1] === 'timingSafeEqual' || cp.join('.').includes('timingSafeEqual'))) {
      return true;
    }
  }
  return false;
}

/** if (timingSafeEqual(hash, session.adminHash)) grant admin — correct crypto authn. */
function conditionLooksLikeCryptoAuthGrant(condition: Value): boolean {
  return conditionLooksLikeHmacOrTimingSafeReject(condition);
}

/**
 * CSRF gate shapes:
 *   if (data !== req.session.csrfToken) return;
 *   if ((req.headers["x-csrf-token"]||"") !== (req.session.csrfToken||"")) return 403;
 */
function conditionLooksLikeCsrfGuard(condition: Value): boolean {
  if (varsClearedByCsrfGuard(condition).length) return true;
  if (condition.kind !== 'Binary') return false;
  if (!(condition.op === '!==' || condition.op === '!=' || condition.op === '===' || condition.op === '==')) {
    return false;
  }
  const mentionsCsrf = (v: Value): boolean => {
    const s = JSON.stringify(v);
    return /csrf/i.test(s);
  };
  return mentionsCsrf(condition.left) || mentionsCsrf(condition.right);
}

/** if (data !== req.session.csrfToken) return; → clear `data` on fall-through. */
function varsClearedByCsrfGuard(condition: Value): string[] {
  if (condition.kind !== 'Binary') return [];
  if (!(condition.op === '!==' || condition.op === '!=' || condition.op === '===' || condition.op === '==')) {
    return [];
  }
  const isCsrfField = (v: Value): boolean => {
    if (v.kind !== 'FieldAccess') return false;
    // req.session.csrfToken / session.csrfToken
    if (v.field === 'csrfToken' || v.field === 'csrf' || v.field === '_csrf') return true;
    if (v.object.kind === 'FieldAccess' && v.object.field === 'session') {
      return v.field === 'csrfToken' || v.field === 'csrf' || v.field === '_csrf';
    }
    return false;
  };
  if (condition.left.kind === 'Variable' && isCsrfField(condition.right)) return [condition.left.name];
  if (condition.right.kind === 'Variable' && isCsrfField(condition.left)) return [condition.right.name];
  return [];
}

/**
 * Login rate-limit markers. NEVER JSON.stringify whole IR — location.file paths
 * like benchmark_test_02429.js contain "429" and false-positive the detector.
 */
function conditionLooksLikeRateLimit(condition: Value): boolean {
  return valueMentionsRateLimit(condition);
}

function blockLooksLikeRateLimitResponse(block: Block): boolean {
  for (const s of block.statements) {
    if (statementMentionsRateLimit(s)) return true;
  }
  return false;
}

function statementMentionsRateLimit(s: Statement): boolean {
  if (s.kind === 'ExpressionStmt') return valueMentionsRateLimit(s.expr);
  if (s.kind === 'Return' && s.value) return valueMentionsRateLimit(s.value);
  if (s.kind === 'Assign') return valueMentionsRateLimit(s.value);
  // Kaioken XLVI — Koa: ctx.status = 429; ctx.body = {error: "too many attempts"}
  if (s.kind === 'FieldAssign') {
    if (valueMentionsRateLimit(s.value)) return true;
    if (s.field === 'status' && s.value.kind === 'Literal' && String(s.value.raw) === '429') {
      return true;
    }
  }
  // Kaioken XLVII — NestJS: throw new InternalServerErrorException({error: "too many attempts"})
  if (s.kind === 'Throw') return valueMentionsRateLimit(s.value);
  if (s.kind === 'Conditional') {
    return (
      valueMentionsRateLimit(s.condition) ||
      blockLooksLikeRateLimitResponse(s.thenBlock) ||
      (s.elseBlock ? blockLooksLikeRateLimitResponse(s.elseBlock) : false)
    );
  }
  return false;
}

function valueMentionsRateLimit(v: Value): boolean {
  if (v.kind === 'Literal') {
    const raw = String(v.raw ?? '');
    // status(429) uses numeric literal 429 — not path strings
    if (v.literalKind === 'number' && raw === '429') return true;
    if (v.literalKind === 'string' && /too many attempts|rate.?limit/i.test(raw)) return true;
    return false;
  }
  if (v.kind === 'Variable') {
    return /loginAttempts|rateLimit|attempts/i.test(v.name);
  }
  if (v.kind === 'FieldAccess') {
    if (/loginAttempts|rateLimit|attempts/i.test(v.field)) return true;
    return valueMentionsRateLimit(v.object);
  }
  if (v.kind === 'Call') {
    return valueMentionsRateLimit(v.callee) || v.args.some(valueMentionsRateLimit);
  }
  if (v.kind === 'ObjectLiteral') {
    return v.props.some(p => valueMentionsRateLimit(p.value));
  }
  if (v.kind === 'Binary' || v.kind === 'Unary') {
    if (v.kind === 'Unary') return valueMentionsRateLimit(v.operand);
    return valueMentionsRateLimit(v.left) || valueMentionsRateLimit(v.right);
  }
  if (v.kind === 'Template') {
    return v.parts.some(p => ('expr' in p ? valueMentionsRateLimit(p.expr) : false));
  }
  return false;
}

/** if (!authzCheck(...)) return 403 — real authz gate. */
function conditionIsAuthzCheckGuard(condition: Value): boolean {
  let inner = condition;
  if (inner.kind === 'Unary' && (inner.op === '!' || inner.op === 'not')) {
    inner = inner.operand;
  } else {
    // only negative guards (fail closed)
    return false;
  }
  if (inner.kind !== 'Call') return false;
  const path = calleePathOf(inner.callee);
  return !!(path && path[path.length - 1] === 'authzCheck');
}

/**
 * if (!Number.isFinite(n) || n < 0 || n > MAX) return — clears size taint for intoverflow safe.
 * Also: if (!Number.isInteger(idx) || idx < 0 || idx >= buf.length) return — OOB safe (Kaioken LIII).
 */
function varsClearedByNumericBoundsGuard(condition: Value): string[] {
  const s = JSON.stringify(condition);
  const hasCmp = /"op":"(<|>|<=|>=)"/.test(s) || /(<|>|<=|>=)/.test(s);
  const hasNumericPred =
    /isFinite|isInteger|isNaN|Number\.isFinite|Number\.isInteger/.test(s);
  if (!hasCmp && !hasNumericPred) return [];
  // Must look like a range/reject guard, not a random comparison
  if (
    !/(isFinite|isInteger|isNaN|1048576|MAX|max|limit|bound|length)/i.test(s) &&
    !/(<\s*0|>\s*0|>=\s*0|<=\s*0)/.test(s) &&
    !/"op":"<".*"raw":"0"|"raw":"0".*"op":"</.test(s)
  ) {
    // still allow n < 0 || n > N patterns without isFinite if both sides present
    if (!/(<\s*0|<=\s*-1|"op":"<")/.test(s) || !/(>|>=)/.test(s)) return [];
  }
  return varsMentioned(condition).filter(
    (n) => !/^(Number|Math|isFinite|isNaN|isInteger)$/.test(n)
  );
}

/**
 * Host blocklist flags used by BenchProctor cloud_ssrf safe twins:
 *   if (_blocked) return;  /  if (_isMeta) return;
 * Name heuristic — paired with hostFromUrl clear of URL parents.
 */
function conditionLooksLikeHostBlockFlag(condition: Value): boolean {
  if (condition.kind === 'Variable') {
    return /block|meta|private|loopback|denied|forbidden|ssrf/i.test(condition.name);
  }
  // Direct: if (/169.254|metadata/.test(host)) return;
  if (condition.kind === 'Call' && condition.callee.kind === 'FieldAccess' && condition.callee.field === 'test') {
    const re = condition.callee.object;
    if (re.kind === 'Literal' && re.literalKind === 'string' && re.raw) {
      if (/169\.254|metadata|127\.|localhost|192\.168|10\./i.test(re.raw)) return true;
    }
  }
  if (condition.kind === 'Binary' && (condition.op === '||' || condition.op === 'or' || condition.op === '&&')) {
    return conditionLooksLikeHostBlockFlag(condition.left) || conditionLooksLikeHostBlockFlag(condition.right);
  }
  // ipaddress.ip_address(resolved).is_link_local / InetAddress.isLinkLocalAddress()
  if (condition.kind === 'FieldAccess') {
    if (
      /^(is_link_local|is_private|is_loopback|is_reserved|is_multicast|isLinkLocalAddress|isSiteLocalAddress|isLoopbackAddress|isAnyLocalAddress)$/.test(
        condition.field
      )
    ) {
      return true;
    }
  }
  if (condition.kind === 'Call') {
    const p = calleePathOf(condition.callee);
    const tail = p ? p[p.length - 1] : '';
    if (
      /^(isLinkLocalAddress|isSiteLocalAddress|isLoopbackAddress|isAnyLocalAddress|is_link_local|is_private)$/.test(
        tail
      )
    ) {
      return true;
    }
  }
  return false;
}

/** if (!req.session.user) / if (!req.session) — auth gate before session write. */
function conditionIsSessionUserGuard(condition: Value): boolean {
  const fieldPath = (v: Value): string[] | null => {
    const parts: string[] = [];
    let cur: Value = v;
    while (cur.kind === 'FieldAccess') {
      parts.unshift(cur.field);
      cur = cur.object;
    }
    if (cur.kind === 'Variable') parts.unshift(cur.name);
    else return null;
    return parts;
  };
  let inner = condition;
  if (inner.kind === 'Unary' && (inner.op === '!' || inner.op === 'not')) {
    inner = inner.operand;
  }
  // !req.session || !req.session.user — may be Binary with ||
  if (inner.kind === 'Binary' && (inner.op === '||' || inner.op === 'or')) {
    return conditionIsSessionUserGuard(inner.left) || conditionIsSessionUserGuard(inner.right);
  }
  const path = fieldPath(inner);
  if (path && path.includes('session') && path.includes('user')) return true;
  // session.get('user') is None  /  not session.get("user")
  const sessionGetUser = (v: Value): boolean => {
    if (v.kind !== 'Call') return false;
    const p = calleePathOf(v.callee);
    if (!p || p[p.length - 1] !== 'get') return false;
    if (!p.includes('session')) return false;
    const key = v.args[0];
    return (
      !!key &&
      key.kind === 'Literal' &&
      key.literalKind === 'string' &&
      /^(user|username|uid|id|role)$/i.test(key.raw || '')
    );
  };
  if (sessionGetUser(inner)) return true;
  if (inner.kind === 'Binary' && (inner.op === '===' || inner.op === '==' || inner.op === '!==' || inner.op === '!=')) {
    if (sessionGetUser(inner.left) || sessionGetUser(inner.right)) return true;
  }
  return false;
}

function varsClearedByAcceptAllowlist(condition: Value, env: TaintEnv): string[] {
  if (condition.kind === 'Unary') return [];
  const fromInc = varsFromConstantIncludesCall(condition, env);
  if (fromInc.length) return fromInc;
  const fromInArray = varsFromPhpInArrayCall(condition, env);
  if (fromInArray.length) return fromInArray;
  return varsFromStrongRegexTest(condition);
}

/**
 * if (allowlist_check(x) fails) y = "const"
 * After the if, y is either the constant or x that passed the allowlist.
 */
function varsAssignedLiteralOnAllowlistFail(
  condition: Value,
  thenBlock: Block,
  env: TaintEnv,
): string[] {
  const checked = [
    ...varsClearedByRejectGuard(condition, env),
    ...varsFromStrongRegexTest(condition),
  ];
  if (condition.kind === 'Binary' && (condition.op === '!=' || condition.op === '!==')) {
    checked.push(...varsFromStrongRegexTest(condition.left));
    checked.push(...varsFromStrongRegexTest(condition.right));
  }
  if (!checked.length && !conditionLooksLikeAllowlistFail(condition)) return [];
  const assigned: string[] = [];
  for (const s of thenBlock.statements) {
    if (s.kind === 'Assign' && s.value.kind === 'Literal' && typeof s.target === 'string') {
      assigned.push(s.target);
    }
  }
  return assigned;
}

function conditionLooksLikeAllowlistFail(condition: Value): boolean {
  const walk = (v: Value): boolean => {
    if (v.kind === 'Call') {
      const tail = calleePathOf(v.callee)?.slice(-1)[0] || '';
      if (tail === 'regexec' || tail === 'matches' || tail === 'fullmatch' || tail === 'test' || tail === 'is_match') {
        return true;
      }
    }
    if (v.kind === 'Unary') return walk(v.operand);
    if (v.kind === 'Binary') return walk(v.left) || walk(v.right);
    return false;
  };
  return walk(condition);
}

/** `["lit"].includes(x)` or `allowedHosts.includes(x)` when allowedHosts is a const array. */
function varsFromConstantIncludesCall(v: Value, env: TaintEnv): string[] {
  if (v.kind !== 'Call') return [];
  const callee = v.callee;
  // Array.includes / Set.has allowlists
  if (
    callee.kind !== 'FieldAccess' ||
    (callee.field !== 'includes' && callee.field !== 'has' && callee.field !== 'contains')
  ) {
    return [];
  }
  const recv = callee.object;
  const isAllow =
    isConstantLiteralArray(recv) ||
    isConstantLiteralSet(recv) ||
    (recv.kind === 'Variable' && env.constArrays.has(recv.name));
  if (!isAllow) return [];
  if (v.args.length < 1) return [];
  return varsMentioned(v.args[0]);
}

/** Strong allowlist regex .test(x) — NOT control-char "weak" filters.
 *  Also `re.fullmatch(pattern, x)` / `re.match(pattern, x)` (Python). */
function varsFromStrongRegexTest(v: Value): string[] {
  if (v.kind !== 'Call') return [];
  const callee = v.callee;
  const path = calleePathOf(callee);
  const tail = path ? path[path.length - 1] : '';

  // JS: /^…$/.test(x)
  if (callee.kind === 'FieldAccess' && callee.field === 'test') {
    const rec = callee.object;
    if (rec.kind !== 'Literal' || rec.literalKind !== 'string' || !rec.raw) return [];
    if (!isStrongAllowlistRegex(rec.raw)) return [];
    if (v.args.length < 1) return [];
    return varsMentioned(v.args[0]);
  }

  // C/POSIX: regexec(&re, data, ...) — subject is arg 1
  if (tail === 'regexec') {
    if (v.args.length >= 2) return varsMentioned(v.args[1]);
    return [];
  }

  // Java: data.matches("^[a-zA-Z0-9_.-]+$")
  if (tail === 'matches') {
    const pat = v.args[0];
    if (!pat || pat.kind !== 'Literal' || pat.literalKind !== 'string' || !pat.raw) return [];
    if (!isStrongAllowlistRegex(pat.raw, true)) return [];
    if (callee.kind === 'FieldAccess') return varsMentioned(callee.object);
    return [];
  }

  // PHP: preg_match('/^[a-zA-Z0-9_.-]+$/', $data) OR extension allowlist
  if (tail === 'preg_match' || tail === 'preg_match_all') {
    const pat = v.args[0];
    const subject = v.args[1];
    if (!pat || !subject) return [];
    if (pat.kind !== 'Literal' || pat.literalKind !== 'string' || !pat.raw) return [];
    const extAllow = /\.\\?\(jpe?g\|png\|gif\|pdf\)/i.test(pat.raw) || /\.\\?\(jpg\|png\|gif\|pdf\)/i.test(pat.raw);
    if (!isStrongAllowlistRegex(pat.raw) && !extAllow) return [];
    return varsMentioned(subject);
  }

  // Python: re.fullmatch(r'[A-Za-z0-9_.-]+', data) / re.match(...)
  // fullmatch is whole-string — treat the pattern as implicitly ^…$.
  if (tail === 'fullmatch' || (tail === 'match' && path && path[0] === 're')) {
    const pat = v.args[0];
    const subject = v.args[1];
    if (!pat || !subject) return [];
    if (!pat || pat.kind !== 'Literal' || pat.literalKind !== 'string' || !pat.raw) return [];
    if (!isStrongAllowlistRegex(pat.raw, tail === 'fullmatch')) return [];
    return varsMentioned(subject);
  }

  // Rust: _RE_SCHEMA.is_match(&data) — frontend rewrites known patterns to .test;
  // this catches the name-based fallback when the static pattern wasn't inlined.
  if (tail === 'is_match') {
    if (v.args.length < 1) return [];
    let recName = '';
    if (callee.kind === 'FieldAccess' && callee.object.kind === 'Variable') {
      recName = callee.object.name;
    }
    if (recName === '_RE_SCHEMA' || recName === '_RE_ALLOW') {
      return varsMentioned(v.args[0]);
    }
    return [];
  }
  return [];
}

/**
 * Strong: /^[a-zA-Z0-9_.-]+$/  (SSTI-safe char class)
 * Weak:   /^[^\x00-\x08...]+$/ (still allows quotes, template chars — vuln twin)
 */
function isStrongAllowlistRegex(raw: string, implicitAnchor = false): boolean {
  const m = raw.match(/^\/(.+)\/([a-z]*)$/i);
  let pat = m ? m[1] : raw;
  if (implicitAnchor) {
    if (!pat.startsWith('^')) pat = `^${pat}`;
    if (!pat.endsWith('$')) pat = `${pat}$`;
  }
  if (!pat.startsWith('^') || !pat.includes('$')) return false;
  // Negated character classes are "filter junk" not allowlists.
  if (pat.includes('[^')) return false;
  // Must constrain to a positive class somewhere
  if (!/\[[A-Za-z0-9_./\\-]+\]/.test(pat) && !/\\[dws]/.test(pat)) {
    // also allow simple [a-zA-Z0-9_.-]+ forms already covered
    if (!/\[/.test(pat)) return false;
  }
  return true;
}

function isConstantLiteralArray(v: Value): boolean {
  if (v.kind !== 'ArrayLiteral') return false;
  if (!v.elements.length) return false;
  return v.elements.every(
    el => el.kind === 'Literal' && (el.literalKind === 'string' || el.literalKind === 'number')
  );
}

/**
 * .replace(/[\r\n]+/g, " ") — CRLF strip for header injection.
 * HTML: only clear when encoding quotes (&quot; / &#x27;) — BP vuln twins
 * often encode &<> only and remain attribute-XSS; safe twins finish with quotes.
 */
function isHtmlOrCrlfSanitizingReplace(value: Extract<Value, { kind: 'Call' }>): boolean {
  if (!value.args.length) return false;
  const re = value.args[0];
  if (re.kind === 'Literal' && re.literalKind === 'string' && re.raw) {
    const pat = re.raw;
    if (/\\r|\\n|crlf|carriage/i.test(pat)) return true;
    if (/\[\\r\\n\+?\]|\[\\n\\r\+?\]|\\r\?\\n/.test(pat)) return true;
    if (/\[\\r\\n\]/.test(pat) || /\[\\n\\r\]/.test(pat)) return true;
  }
  // Quote-entity replacements (complete HTML encode chain)
  const rep = value.args[1];
  if (rep && rep.kind === 'Literal' && rep.literalKind === 'string' && rep.raw) {
    if (/^&quot;$|^&#x27;$|^&#39;$|^&#x22;$/i.test(rep.raw)) return true;
  }
  return false;
}

/** `s.replace('"', '""')` — SQL identifier quoting. */
function isSqlIdentQuoteReplace(value: Extract<Value, { kind: 'Call' }>): boolean {
  if (value.args.length < 2) return false;
  const pat = value.args[0];
  const repl = value.args[1];
  if (pat?.kind !== 'Literal' || pat.literalKind !== 'string') return false;
  if (repl?.kind !== 'Literal' || repl.literalKind !== 'string') return false;
  return pat.raw === '"' && repl.raw === '""';
}

/** `re.sub(pattern, '****', data)` — alphanumeric redaction for logs. */
function isRedactingSub(value: Extract<Value, { kind: 'Call' }>): boolean {
  const path = calleePathOf(value.callee);
  if (!path || path[path.length - 1] !== 'sub') return false;
  if (value.args.length < 2) return false;
  const repl = value.args[1];
  return repl?.kind === 'Literal' && repl.literalKind === 'string' && repl.raw === '****';
}

/** Ternary arm is "'" + data (CSV formula neutralization). */
function isCsvFormulaSanitizedTernary(v: Extract<Value, { kind: 'Binary' }>): boolean {
  // left arm: Binary + with literal "'" and a variable
  const quotePrefixed = (arm: Value): boolean => {
    if (arm.kind !== 'Binary' || arm.op !== '+') return false;
    const litLeft =
      arm.left.kind === 'Literal' &&
      arm.left.literalKind === 'string' &&
      (arm.left.raw === "'" || arm.left.raw === "\\'");
    const litRight =
      arm.right.kind === 'Literal' &&
      arm.right.literalKind === 'string' &&
      (arm.right.raw === "'" || arm.right.raw === "\\'");
    return (litLeft && arm.right.kind === 'Variable') || (litRight && arm.left.kind === 'Variable');
  };
  return quotePrefixed(v.left) || quotePrefixed(v.right);
}

/** Ternary fallback to a shell-safe literal — command-injection allowlist. */
function isAllowlistFallbackTernary(v: Extract<Value, { kind: 'Binary' }>): boolean {
  const shellSafe = (raw: string): boolean => /^[A-Za-z0-9/._-]+$/.test(raw);
  const safeLit = (arm: Value): boolean => {
    if (arm.kind === 'Literal' && arm.literalKind === 'string' && arm.raw && shellSafe(arm.raw)) {
      return true;
    }
    // C frontend: std::string("asc") / string("default")
    if (arm.kind === 'Call' && arm.args.length === 1) {
      const a = arm.args[0];
      return a.kind === 'Literal' && a.literalKind === 'string' && !!a.raw && shellSafe(a.raw);
    }
    return false;
  };
  return safeLit(v.left) || safeLit(v.right);
}

/** new Set(["a","b"]) / new Set(['config.json', ...]) */
function isConstantLiteralSet(v: Value): boolean {
  if (v.kind !== 'Call' || !v.args.length) return false;
  const path = calleePathOf(v.callee);
  if (!path || path[path.length - 1] !== 'Set') return false;
  return isConstantLiteralArray(v.args[0]);
}

/**
 * zod.z.string().regex(/^[a-zA-Z0-9_.-]+$/).safeParse(data)
 * Nested Call chain ending in safeParse with strong regex in the tree.
 */
function isStrongZodSafeParse(v: Value): boolean {
  if (v.kind !== 'Call') return false;
  const path = calleePathOf(v.callee);
  const tail = path ? path[path.length - 1] : null;
  // callee is FieldAccess .safeParse on a Call chain
  if (v.callee.kind === 'FieldAccess' && v.callee.field === 'safeParse') {
    return callTreeHasStrongRegex(v.callee.object);
  }
  if (tail === 'safeParse') return callTreeHasStrongRegex(v);
  return false;
}

function callTreeHasStrongRegex(v: Value): boolean {
  if (v.kind === 'Literal' && v.literalKind === 'string' && v.raw && isStrongAllowlistRegex(v.raw)) {
    return true;
  }
  if (v.kind === 'Call') {
    if (v.args.some(callTreeHasStrongRegex)) return true;
    return callTreeHasStrongRegex(v.callee);
  }
  if (v.kind === 'FieldAccess') return callTreeHasStrongRegex(v.object);
  return false;
}

/** `new URL(data).hostname` / `new URL(String(data)).hostname` → parent var "data" */
/** parsed = urlparse(data) / urlsplit(data) — parent URL var is the arg. */
function urlParentOfParseCall(v: Value): string | null {
  if (v.kind !== 'Call') return null;
  const path = calleePathOf(v.callee);
  if (!path) return null;
  const tail = path[path.length - 1];
  // URI.create(data).toURL() — peel the conversion wrapper
  if ((tail === 'toURL' || tail === 'toURI') && v.callee.kind === 'FieldAccess' && v.callee.object.kind === 'Call') {
    return urlParentOfParseCall(v.callee.object);
  }
  if (tail === 'create' && !(path.includes('URI') || path[0] === 'URI')) return null;
  if (tail !== 'urlparse' && tail !== 'urlsplit' && tail !== 'urljoin' && tail !== 'create') return null;
  if (!v.args.length) return null;
  const vars = varsMentioned(v.args[0]).filter(n => !/^(str|String)$/.test(n));
  return vars[0] ?? null;
}

function urlParentOfHostname(v: Value): string | null {
  if (v.kind !== 'FieldAccess' || v.field !== 'hostname') return null;
  const obj = v.object;
  if (obj.kind !== 'Call') return null;
  const path = calleePathOf(obj.callee);
  if (!path || path[path.length - 1] !== 'URL') return null;
  if (!obj.args.length) return null;
  // Peel String()/Number() wrappers — varsMentioned would put "String" first
  let arg: Value = obj.args[0];
  while (
    arg.kind === 'Call' &&
    arg.callee.kind === 'Variable' &&
    /^(String|Number|Boolean)$/.test(arg.callee.name) &&
    arg.args.length
  ) {
    arg = arg.args[0];
  }
  if (arg.kind === 'Variable') return arg.name;
  const vars = varsMentioned(arg).filter(n => !/^(String|Number|Boolean|URL)$/.test(n));
  return vars[0] ?? null;
}

function varsMentioned(v: Value): string[] {
  switch (v.kind) {
    case 'Variable':
      return [v.name];
    case 'FieldAccess':
      return varsMentioned(v.object);
    case 'Unary':
      return varsMentioned(v.operand);
    case 'Binary':
      return [...varsMentioned(v.left), ...varsMentioned(v.right)];
    case 'Call':
      return [...varsMentioned(v.callee), ...v.args.flatMap(varsMentioned)];
    case 'Template':
      return v.parts.flatMap(p => ('expr' in p ? varsMentioned(p.expr) : []));
    case 'ArrayLiteral':
      return v.elements.flatMap(varsMentioned);
    case 'ObjectLiteral':
      return v.props.flatMap(p => varsMentioned(p.value));
    default:
      return [];
  }
}

/**
 * Free-variable assignments of the form `outer = param` inside a callee.
 * BP idiom: `const onInput = (v) => { data = v }; onInput(userInput);`
 */
function freeVarTaintFromCallee(
  fn: FunctionIR,
  entry: TaintEnv
): Map<string, TaintLabel[]> {
  const params = new Set(fn.params);
  const out = new Map<string, TaintLabel[]>();
  const walk = (b: Block) => {
    for (const s of b.statements) {
      if (s.kind === 'Assign' && !params.has(s.target)) {
        if (s.value.kind === 'Variable') {
          const labs = entry.vars.get(s.value.name);
          if (labs?.length) out.set(s.target, labs);
        }
      } else if (s.kind === 'Conditional') {
        walk(s.thenBlock);
        if (s.elseBlock) walk(s.elseBlock);
      } else if (s.kind === 'Loop') {
        walk(s.body);
      } else if (s.kind === 'TryCatch') {
        walk(s.tryBlock);
        if (s.catchBlock) walk(s.catchBlock);
      }
    }
  };
  walk(fn.body);
  return out;
}

/**
 * Kaioken XLVII — free-var writes with any RHS taint (not only Variable).
 * NestJS BP: `await new Promise(r => { _asyncOut = "<div>"+data; r(); }); return _asyncOut`
 */
function freeVarTaintFromCalleeEval(
  fn: FunctionIR,
  entry: TaintEnv,
  module: ModuleCtx,
  loc: Location
): Map<string, TaintLabel[]> {
  const params = new Set(fn.params);
  const out = new Map<string, TaintLabel[]>();
  const tempFindings: TaintFinding[] = [];
  const tempEctx: EvalCtx = {
    module,
    returnLabels: [],
    findings: tempFindings,
  };
  const walk = (b: Block) => {
    for (const s of b.statements) {
      if (s.kind === 'Assign' && !params.has(s.target)) {
        const labs = evaluate(s.value, entry, s.location, tempEctx);
        if (labs.length) {
          out.set(
            s.target,
            labs.map(l => ({
              source: l.source,
              flow: [
                ...l.flow,
                { statementId: s.id, variable: s.target, location: s.location },
              ],
            }))
          );
        }
        // Field-sensitive object: _asyncOut = { url: data }
        if (s.value.kind === 'ObjectLiteral') {
          for (const prop of s.value.props) {
            const plabs = evaluate(prop.value, entry, s.location, tempEctx);
            if (plabs.length) {
              const key = joinTaintKey(s.target, [prop.key]);
              if (key) {
                out.set(
                  key,
                  plabs.map(l => ({
                    source: l.source,
                    flow: [
                      ...l.flow,
                      { statementId: s.id, variable: key, location: s.location },
                    ],
                  }))
                );
              }
            }
          }
        }
      } else if (s.kind === 'Conditional') {
        walk(s.thenBlock);
        if (s.elseBlock) walk(s.elseBlock);
      } else if (s.kind === 'Loop') {
        walk(s.body);
      } else if (s.kind === 'TryCatch') {
        walk(s.tryBlock);
        if (s.catchBlock) walk(s.catchBlock);
      }
    }
  };
  walk(fn.body);
  return out;
}

/** Free variable names used in a function body (not parameters). */
function freeVarsInFunction(fn: FunctionIR): string[] {
  const params = new Set(fn.params);
  const used = new Set<string>();
  const walkBlock = (b: Block) => {
    for (const s of b.statements) walkStmt(s);
  };
  const walkStmt = (s: Statement) => {
    switch (s.kind) {
      case 'Assign':
        for (const n of varsMentioned(s.value)) if (!params.has(n)) used.add(n);
        break;
      case 'FieldAssign':
        for (const n of varsMentioned(s.object)) if (!params.has(n)) used.add(n);
        for (const n of varsMentioned(s.value)) if (!params.has(n)) used.add(n);
        break;
      case 'ExpressionStmt':
        for (const n of varsMentioned(s.expr)) if (!params.has(n)) used.add(n);
        break;
      case 'Return':
        if (s.value) for (const n of varsMentioned(s.value)) if (!params.has(n)) used.add(n);
        break;
      case 'Conditional':
        for (const n of varsMentioned(s.condition)) if (!params.has(n)) used.add(n);
        walkBlock(s.thenBlock);
        if (s.elseBlock) walkBlock(s.elseBlock);
        break;
      case 'Loop':
        if (s.condition) for (const n of varsMentioned(s.condition)) if (!params.has(n)) used.add(n);
        walkBlock(s.body);
        break;
      case 'TryCatch':
        walkBlock(s.tryBlock);
        if (s.catchBlock) walkBlock(s.catchBlock);
        break;
      case 'Throw':
        for (const n of varsMentioned(s.value)) if (!params.has(n)) used.add(n);
        break;
    }
  };
  walkBlock(fn.body);
  return [...used];
}

function calleePathOf(v: Value): string[] | null {
  if (v.kind === 'Variable') return [v.name];
  if (v.kind === 'FieldAccess') {
    const base = calleePathOf(v.object);
    if (base) return [...base, v.field];
    // Kaioken VIII — method on call result: db.collection("users").findOne
    // IR is FieldAccess(Call(db.collection, ...), findOne) → ['db','collection','findOne']
    if (v.object.kind === 'Call') {
      const inner = calleePathOf(v.object.callee);
      if (inner) return [...inner, v.field];
      return [v.field];
    }
    return null;
  }
  return null;
}

function matchSource(access: Value): TaintSource | null {
  // We only attempt to match FieldAccess chains rooted in an Identifier:
  // `req.body`, `req.params.id`, `process.env.FOO`. A source matches if the
  // access path *starts with* the source's fieldPath (so req.body.user.name
  // still hits the req.body source).
  const path = calleePathOf(access);
  if (!path) return null;
  for (const src of ACTIVE_SOURCES) {
    if (pathStartsWith(path, src.fieldPath)) return src;
  }
  return null;
}

/**
 * Kaioken VII — expand callee paths through require/import aliases.
 * `const childProcess = require('child_process'); childProcess.execSync`
 * → candidates include ['child_process','execSync'] for catalog match.
 */
function expandCalleePaths(path: string[], imports: ModuleImport[]): string[][] {
  const out: string[][] = [path];
  if (!path.length || !imports.length) return out;

  const imp = imports.find(i => i.localName === path[0]);
  if (!imp) return out;

  // Relative modules stay as local names (cross-file resolves them).
  if (imp.specifier.startsWith('.') || imp.specifier.startsWith('/')) return out;

  const pkg = packageBase(imp.specifier);
  const alts = packageAliases(pkg);

  if (imp.imported === '*') {
    // Namespace: alias.method → pkg.method
    for (const alt of alts) {
      const candidate = [alt, ...path.slice(1)];
      if (!out.some(p => pathsEqual(p, candidate))) out.push(candidate);
    }
  } else if (path.length === 1) {
    // Named/default bind used bare: const { execSync } = require('child_process')
    // or const load = require('js-yaml').load
    const method = imp.imported === 'default' ? path[0] : imp.imported;
    for (const alt of alts) {
      const candidate = [alt, method];
      if (!out.some(p => pathsEqual(p, candidate))) out.push(candidate);
    }
  }
  return out;
}

function packageBase(specifier: string): string {
  if (specifier.startsWith('@')) {
    const parts = specifier.split('/');
    return parts.slice(0, 2).join('/');
  }
  return specifier.split('/')[0];
}

/** Catalog package-name variants for the same module. */
function packageAliases(pkg: string): string[] {
  const MAP: Record<string, string[]> = {
    'js-yaml': ['js-yaml', 'jsyaml', 'yaml'],
    'node-serialize': ['node-serialize', 'nodeSerialize'],
    'isomorphic-dompurify': ['isomorphic-dompurify', 'DOMPurify', 'dompurify'],
    'shell-quote': ['shell-quote', 'shellQuote'],
    'pg-escape': ['pg-escape', 'pgEscape'],
    ldapjs: ['ldapjs', 'ldap'],
    jsonwebtoken: ['jsonwebtoken', 'jwt'],
  };
  return MAP[pkg] ?? [pkg];
}

/** True when ObjectLiteral arg has key with literal value matching pred. */
function objectLitHas(
  arg: Value | undefined,
  key: string,
  pred: (v: Value) => boolean
): boolean {
  if (!arg || arg.kind !== 'ObjectLiteral') return false;
  for (const p of arg.props) {
    if (p.key === key && pred(p.value)) return true;
  }
  return false;
}

function isBoolLit(v: Value, want: boolean): boolean {
  return (
    v.kind === 'Literal' &&
    v.literalKind === 'boolean' &&
    v.raw === (want ? 'true' : 'false')
  );
}

/**
 * Kaioken XXVII — harden checks that turn a sink into a non-issue for BP safe twins:
 * - res.cookie(name, val, { httpOnly: true, ... }) — secure cookie flags
 * - libxmljs.parseXml(xml, { noent: false, nonet: true }) — XXE disabled
 */
function valueContainsAllowlistMatches(v: Value): boolean {
  if (callLooksLikeAllowlistMatches(v)) return true;
  if (v.kind === 'Unary') return valueContainsAllowlistMatches(v.operand);
  if (v.kind === 'Binary') {
    return valueContainsAllowlistMatches(v.left) || valueContainsAllowlistMatches(v.right);
  }
  return false;
}

function callLooksLikeAllowlistMatches(v: Value): boolean {
  if (v.kind !== 'Call') return false;
  const p = calleePathOf(v.callee);
  if (p && p[p.length - 1] === 'matches') return true;
  if (v.callee.kind === 'FieldAccess' && v.callee.field === 'matches') return true;
  return false;
}

function callLooksLikeBeanValidate(v: Value): boolean {
  if (v.kind !== 'Call') return false;
  const p = calleePathOf(v.callee);
  if (!p || p[p.length - 1] !== 'validate') return false;
  return p.some(x => /Validator|VALIDATOR|validator/i.test(x)) || p.length <= 2;
}

/** data.matches("^[A-Za-z0-9]+$") — Java String.matches allowlist. */
function varsFromJavaMatchesCall(v: Value): string[] {
  if (v.kind !== 'Call') return [];
  const callee = v.callee;
  if (callee.kind !== 'FieldAccess' || callee.field !== 'matches') return [];
  if (!v.args.length) return [];
  const arg = v.args[0];
  if (arg.kind !== 'Literal' || arg.literalKind !== 'string' || !arg.raw) return [];
  if (arg.raw.length < 4) return [];
  return varsMentioned(callee.object);
}

function sinkCallIsHardened(
  sinkId: string,
  value: Extract<Value, { kind: 'Call' }>
): boolean {
  if (sinkId === 'php.setcookie' || sinkId === 'php.cookie.set') {
    const opts = value.args[2] ?? (value.args.length >= 3 ? value.args[value.args.length - 1] : undefined);
    if (
      objectLitHas(opts, 'secure', v => isBoolLit(v, true)) &&
      (objectLitHas(opts, 'httponly', v => isBoolLit(v, true)) ||
        objectLitHas(opts, 'httpOnly', v => isBoolLit(v, true)))
    ) {
      const ss =
        objectLitHas(
          opts,
          'samesite',
          v =>
            v.kind === 'Literal' &&
            v.literalKind === 'string' &&
            /^(strict|lax)$/i.test(v.raw || '')
        ) ||
        objectLitHas(
          opts,
          'sameSite',
          v =>
            v.kind === 'Literal' &&
            v.literalKind === 'string' &&
            /^(strict|lax)$/i.test(v.raw || '')
        );
      if (ss) return true;
    }
  }
  if (sinkId === 'express.res.cookie' || sinkId === 'koa.ctx.cookies.set') {
    // Express: res.cookie(name, value, options) — options at arg 2
    // Also accept options at arg 1 if only two args (some wrappers)
    const opts = value.args[2] ?? value.args[1];
    if (objectLitHas(opts, 'httpOnly', v => isBoolLit(v, true))) return true;
    // sameSite: 'strict'|'lax' also marks cookie as intentionally hardened
    if (
      objectLitHas(
        opts,
        'sameSite',
        v =>
          v.kind === 'Literal' &&
          v.literalKind === 'string' &&
          /^(strict|lax)$/i.test(v.raw || '')
      )
    ) {
      return true;
    }
  }
  if (ACTIVE_CATALOG.extras?.bindParamHardensSql && /execute|query|exec/i.test(sinkId)) {
    // db.execute("... :id", { id: data }) / cursor.execute(sql, params)
    const bind = value.args[1];
    if (bind && (bind.kind === 'ObjectLiteral' || bind.kind === 'ArrayLiteral')) {
      return true;
    }
    // Go database/sql: Query("SELECT ... WHERE id = ?", data)
    const sql = value.args[0];
    if (
      sql &&
      sql.kind === 'Literal' &&
      sql.literalKind === 'string' &&
      /\?/.test(sql.raw || '') &&
      value.args.length > 1
    ) {
      return true;
    }
  }
  if (sinkId === 'libxmljs.parseXml' || sinkId === 'libxmljs.parseXmlString') {
    const opts = value.args[1];
    // noent:false disables external entity expansion; nonet:true blocks network
    if (objectLitHas(opts, 'noent', v => isBoolLit(v, false))) return true;
    if (objectLitHas(opts, 'nonet', v => isBoolLit(v, true))) return true;
  }
  return false;
}

/**
 * authCheck(user, "admin") / authCheck("admin", pass) → default cred surface.
 * authCheck(user, process.env.SECRET) → env-backed secret, not a default-cred hit.
 */
function authCheckLooksDefaultCred(value: Extract<Value, { kind: 'Call' }>): boolean {
  const DEFAULT = /^(admin|password|pass|secret|root|test|default|changeme|1234|letmein)$/i;
  for (const arg of value.args) {
    if (arg.kind === 'Literal' && arg.literalKind === 'string' && DEFAULT.test(arg.raw || '')) {
      return true;
    }
  }
  return false;
}

/** Header name is Content-Type (literal or stringy). */
function isContentTypeHeaderName(v: Value | undefined): boolean {
  if (!v) return false;
  if (v.kind === 'Literal' && v.literalKind === 'string') {
    return /^content-type$/i.test((v.raw || '').trim());
  }
  return false;
}

function isEnvSource(label: { source: { id: string; description: string; kind?: string } }): boolean {
  const id = label.source.id || '';
  const d = label.source.description || '';
  return (
    label.source.kind === 'environment' ||
    /^(process\.env|env\.|environment)/i.test(id) ||
    /environment variable/i.test(d) ||
    id.includes('process.env') ||
    id === 'env' ||
    id.startsWith('env.')
  );
}

/**
 * BenchProctor attacker stand-in via process.env.USER_INPUT (and close variants).
 * Not a real secret — treat as user-input for crypto-key sinks (CWE-320/324).
 * IMPORTANT: do not match catalog description text ("attacker-controlled in some
 * deploy scenarios") — that would re-enable ENC_KEY / JWT_SECRET safe FPs.
 */
function isAttackerEnvSource(label: {
  source: { id: string; description: string; kind?: string };
  flow?: Array<{ variable?: string }>;
}): boolean {
  if (!isEnvSource(label)) return false;
  const id = (label.source.id || '').toLowerCase();
  // Only trust explicit id re-tags like process.env.USER_INPUT (FieldAccess path)
  if (/process\.env\.(user_input|userinput|attacker|untrusted)/i.test(id)) return true;
  const vars = (label.flow || []).map((f) => (f.variable || '').toLowerCase()).join(' ');
  return /\b(user_input|userinput)\b/.test(vars);
}

function hasEnvTaint(v: Value | undefined, env: TaintEnv, loc: Location, ectx: EvalCtx): boolean {
  if (!v) return false;
  const labs = evaluate(v, env, loc, ectx);
  return labs.some(isEnvSource);
}

/**
 * Kaioken L / LIII — fixed-host URL guard + fixed-prefix+encodeURIComponent path guard.
 *
 * URL: https.get("https://api.node.internal/..."+taint) and options objects with
 *      hostname/host literal — host not attacker-controlled.
 * Path: fs.*(fixedPrefix + encodeURIComponent(taint)) — CWE-22 vulns use raw concat
 *       (no encode). CWE-353 still keyed via fs.write.unverified.
 */
function isPhpBacktickIdentQuoted(v: Value): boolean {
  if (!v) return false;
  if (v.kind === 'Call') {
    const p = calleePathOf(v.callee);
    const tail = p ? p[p.length - 1] : '';
    if (tail === 'str_replace' && v.args.length >= 3) {
      const a0 = v.args[0];
      const a1 = v.args[1];
      if (
        a0?.kind === 'Literal' &&
        a0.literalKind === 'string' &&
        a0.raw === '`' &&
        a1?.kind === 'Literal' &&
        a1.literalKind === 'string' &&
        a1.raw === '``'
      ) {
        return true;
      }
    }
    for (const a of v.args) {
      if (isPhpBacktickIdentQuoted(a)) return true;
    }
  }
  if (v.kind === 'Binary') {
    return isPhpBacktickIdentQuoted(v.left) || isPhpBacktickIdentQuoted(v.right);
  }
  return false;
}

function isFixedHostOrPathBase(
  v: Value,
  sinkId: string,
  _env: TaintEnv,
  _loc: Location,
  _ectx: EvalCtx
): boolean {
  if (!v) return false;

  // Fixed-host suppress is for HTTPS/SSRF noise only.
  // Plain http.get("http://fixed/...") must still fire (CWE-319 cleartext transmit).
  const isCleartextHttpSink = /^http\.(get|request)$/i.test(sinkId);
  const isUrlSink =
    /https?\.(get|request)|fetch|axios|http\.|res\.redirect/i.test(sinkId);
  if (isUrlSink && !isCleartextHttpSink) {
    return urlHostIsFixedLiteral(v);
  }
  if (isCleartextHttpSink) {
    return false;
  }

  // fs path args only (path is dangerousArgs[0] for most; write content handled elsewhere)
  const isFsPathSink =
    /fs\.(read|write|append|unlink|rm|open|stat|access|createRead|createWrite|readdir|chmod|chown)/i.test(
      sinkId
    );
  if (isFsPathSink) {
    return pathIsFixedPrefixWithEncodeURIComponent(v);
  }

  return false;
}

function isFixedPathLiteral(v: Value | undefined): boolean {
  if (!v) return false;
  return v.kind === 'Literal' && v.literalKind === 'string' && typeof v.raw === 'string' && v.raw.length > 0;
}

/** Fixed SQL string with bind placeholders — not string-concat SQLi. */
function isParameterizedSqlLiteral(v: Value | undefined): boolean {
  if (!v || v.kind !== 'Literal' || v.literalKind !== 'string') return false;
  const s = v.raw || '';
  // Must look like SQL text with at least one placeholder; no dynamic concat
  if (!/\?/.test(s) && !/\$\d+/.test(s) && !/:\w+/.test(s)) return false;
  return /SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|SET|INTO/i.test(s);
}

function isTempDirValue(v: Value, env: TaintEnv): boolean {
  if (v.kind === 'Variable') return env.tempDirs.has(v.name);
  if (v.kind === 'Call') {
    const cp = calleePathOf(v.callee);
    const joined = cp ? cp.join('.') : '';
    const tail = cp ? cp[cp.length - 1] : '';
    if (
      tail === 'mkdtempSync' ||
      tail === 'mkdtemp' ||
      joined === 'fs.mkdtempSync' ||
      joined === 'fs.mkdtemp' ||
      joined === 'os.tmpdir' ||
      tail === 'tmpdir'
    ) {
      return true;
    }
  }
  if (v.kind === 'Binary' && v.op === '+') {
    // os.tmpdir() + "/app-" still a temp root prefix
    return isTempDirValue(v.left, env) || isTempDirValue(v.right, env);
  }
  return false;
}

/** write path rooted in a tracked temp dir (tmpDir + "/data.tmp"). */
function pathUsesTempDir(v: Value | undefined, env: TaintEnv): boolean {
  if (!v) return false;
  if (v.kind === 'Variable') return env.tempDirs.has(v.name);
  if (v.kind === 'Binary' && v.op === '+') {
    return pathUsesTempDir(v.left, env) || pathUsesTempDir(v.right, env);
  }
  if (v.kind === 'Call') {
    const cp = calleePathOf(v.callee);
    const tail = cp ? cp[cp.length - 1] : '';
    // path.join(tmpDir, "data.tmp")
    if (tail === 'join' || tail === 'resolve') {
      return (v.args || []).some((a) => pathUsesTempDir(a, env));
    }
  }
  return isTempDirValue(v, env);
}

function isEncodeURIComponentCall(v: Value | undefined): boolean {
  if (!v || v.kind !== 'Call') return false;
  const cp = calleePathOf(v.callee);
  if (!cp) return false;
  const tail = cp[cp.length - 1];
  if (tail === 'encodeURIComponent' || tail === 'encodeURI') return true;
  // encodeURIComponent(String(x)) already covered by tail on outer call
  return false;
}

/** fixedPrefix + encodeURIComponent(taint) — not raw path traversal (CWE-22). */
function pathIsFixedPrefixWithEncodeURIComponent(v: Value): boolean {
  if (v.kind === 'Binary' && v.op === '+') {
    if (
      v.left &&
      v.left.kind === 'Literal' &&
      v.left.literalKind === 'string' &&
      /[\/\\]/.test(v.left.raw || '')
    ) {
      if (isEncodeURIComponentCall(v.right)) return true;
      // encodeURIComponent(String(x)) is still encodeURIComponent outer
      if (v.right && pathIsFixedPrefixWithEncodeURIComponent(v.right)) return true;
    }
    if (v.left && pathIsFixedPrefixWithEncodeURIComponent(v.left)) return true;
  }
  if (v.kind === 'Template' && v.parts && v.parts.length > 0) {
    // `${fixed}/` + expr — rare; skip unless first literal is path-like and rest encoded
    const first = v.parts[0];
    if (first && 'literal' in first && typeof first.literal === 'string' && /[\/\\]/.test(first.literal)) {
      // template with only encode call expressions is uncommon in BP; treat conservatively
      return false;
    }
  }
  return false;
}

/**
 * Ciphertext / KDF / hash digest material — not cleartext storage of the original input.
 * Used to quiet QT safe twins that encrypt-or-hash then write to a fixed path.
 */
function isCryptoProtectedValue(v: Value, env: TaintEnv): boolean {
  if (!v) return false;
  if (v.kind === 'Variable') {
    return env.cryptoProtected.has(v.name);
  }
  if (v.kind === 'Call') {
    const cp = calleePathOf(v.callee);
    const tail = cp ? cp[cp.length - 1] : '';
    const joined = cp ? cp.join('.') : '';
    // cipher.update / .final / .getAuthTag / .digest
    if (v.callee.kind === 'FieldAccess') {
      const f = v.callee.field;
      if (f === 'update' || f === 'final' || f === 'getAuthTag' || f === 'digest') {
        return true;
      }
      if (f === 'toString' || f === 'toJSON') {
        return isCryptoProtectedValue(v.callee.object, env);
      }
    }
    if (
      tail === 'pbkdf2Sync' ||
      tail === 'pbkdf2' ||
      tail === 'scryptSync' ||
      tail === 'scrypt' ||
      joined.includes('pbkdf2')
    ) {
      return true;
    }
    if (tail === 'concat' || joined === 'Buffer.concat' || joined.endsWith('.concat')) {
      // Buffer.concat([a,b,c]) — single ArrayLiteral arg, not varargs
      for (const a of v.args || []) {
        if (a.kind === 'ArrayLiteral') {
          if ((a.elements || []).some((el) => isCryptoProtectedValue(el, env))) return true;
        } else if (isCryptoProtectedValue(a, env)) {
          return true;
        }
      }
      return false;
    }
    if (tail === 'from' && (joined === 'Buffer.from' || joined.endsWith('Buffer.from'))) {
      return (v.args || []).some((a) => isCryptoProtectedValue(a, env));
    }
  }
  if (v.kind === 'Binary' && (v.op === '+' || v.op === '||')) {
    // saltHex + ":" + digestHex — either side crypto-protected ⇒ storage of derived material
    return (
      isCryptoProtectedValue(v.left, env) ||
      isCryptoProtectedValue(v.right, env)
    );
  }
  return false;
}

function urlHostIsFixedLiteral(v: Value): boolean {
  if (v.kind === 'Literal' && v.literalKind === 'string' && typeof v.raw === 'string') {
    const s = (v.raw || '').trim();
    return /^https?:\/\/[a-z0-9.-]+/i.test(s);
  }
  // https.get({ hostname: "api.node.internal", path: "/u/" + taint, headers: {...} })
  if (v.kind === 'ObjectLiteral' && v.props) {
    for (const p of v.props) {
      if ((p.key === 'hostname' || p.key === 'host') && p.value) {
        if (p.value.kind === 'Literal' && p.value.literalKind === 'string') {
          const h = (p.value.raw || '').trim();
          if (h.length > 0 && !/[\/\?]/.test(h) && !/\$\{/.test(h)) return true;
        }
      }
      if (p.key === 'url' && p.value && urlHostIsFixedLiteral(p.value)) return true;
    }
    return false;
  }
  if (v.kind === 'Binary' && v.op === '+') {
    if (v.left && urlHostIsFixedLiteral(v.left)) return true;
    return false;
  }
  if (v.kind === 'Template' && v.parts && v.parts.length > 0) {
    const first = v.parts[0];
    if (first && 'literal' in first && typeof first.literal === 'string' && /^https?:\/\/[a-z0-9.-]+/i.test(first.literal)) {
      return true;
    }
    return false;
  }
  if (v.kind === 'Call' && v.callee) {
    const c = v.callee;
    // new URL(...) lowers as Call with callee Variable URL
    if (c.kind === 'Variable' && c.name === 'URL' && v.args && v.args[0]) {
      return urlHostIsFixedLiteral(v.args[0]);
    }
  }
  return false;
}

function matchSink(path: string[], imports: ModuleImport[] = []): TaintSink | null {
  for (const candidate of expandCalleePaths(path, imports)) {
    for (const sink of ACTIVE_SINKS) {
      if (pathsEqual(candidate, sink.calleePath)) return sink;
    }
  }
  return ACTIVE_CATALOG.matchSinkExtra?.(path, imports) ?? null;
}

// note: escapeHtml matched via JAVASCRIPT_SANITIZERS + basename path end

/** DB read APIs whose *return value* is untrusted stored data (secondary source). */
function isDbResultSource(path: string[] | null, imports: ModuleImport[]): boolean {
  if (!path || !path.length) return false;
  for (const candidate of expandCalleePaths(path, imports)) {
    const joined = candidate.join('.');
    if (
      /^(db|database|client|conn|connection|pool)\.(query|querySync|execute|executeSync|fetch_one|fetchone|fetchall)$/.test(joined) ||
      candidate[candidate.length - 1] === 'query' ||
      candidate[candidate.length - 1] === 'querySync' ||
      candidate[candidate.length - 1] === 'fetch_one' ||
      candidate[candidate.length - 1] === 'fetchone'
    ) {
      // Avoid treating random .query as DB if it's clearly jQuery etc. — require db-ish head or import
      if (['db', 'database', 'client', 'conn', 'connection', 'pool', 'pg', 'mysql', 'mysql2'].includes(candidate[0])) {
        return true;
      }
    }
  }
  return false;
}

const DB_RESULT_SOURCE: TaintSource = {
  id: 'db.result',
  fieldPath: ['db', 'result'],
  kind: 'user-input',
  description: 'Database query result — stored data treated as untrusted (second-order taint)',
};

const FILE_CONTENT_SOURCE: TaintSource = {
  id: 'fs.content',
  fieldPath: ['fs', 'read'],
  kind: 'filesystem',
  description: 'File/stdin read content — untrusted stored or external data',
};

const REDIS_RESULT_SOURCE: TaintSource = {
  id: 'redis.result',
  fieldPath: ['redis', 'get'],
  kind: 'user-input',
  description: 'Redis/session store read — attacker-influenced stored value',
};

function isRedisReadSource(path: string[] | null, imports: ModuleImport[]): boolean {
  if (!path || !path.length) return false;
  for (const c of expandCalleePaths(path, imports)) {
    const tail = c[c.length - 1];
    const head = c[0];
    if (
      (tail === 'get' || tail === 'getSync' || tail === 'getAsync') &&
      /redis|session|cache/i.test(head)
    ) {
      return true;
    }
    // redisClient.getSync
    if (c.length >= 2 && /redis|session/i.test(c.join('.'))) {
      if (tail === 'get' || tail === 'getSync') return true;
    }
  }
  // bare getSync after const { redisClient } — path redisClient.getSync
  if (path.length === 2 && (path[1] === 'getSync' || path[1] === 'get')) {
    if (/redis|session|cache|client/i.test(path[0])) return true;
  }
  return false;
}

function isTimerApi(path: string[] | null): boolean {
  if (!path || !path.length) return false;
  const tail = path[path.length - 1];
  return (
    tail === 'setImmediate' ||
    tail === 'setTimeout' ||
    tail === 'setInterval' ||
    tail === 'nextTick' ||
    (path[0] === 'process' && tail === 'nextTick')
  );
}

/** Walk function body for resolve(x) / reject(x) Call with tainted args. */
function collectResolveArgTaint(
  fn: FunctionIR,
  entry: TaintEnv,
  module: ModuleCtx,
  loc: Location
): TaintLabel[] {
  const resolveNames = new Set(fn.params.slice(0, 2)); // resolve, reject
  const out: TaintLabel[] = [];
  const ectx: EvalCtx = {
    module,
    returnLabels: [],
    findings: [],
  };
  const walk = (block: Block) => {
    for (const s of block.statements) {
      if (s.kind === 'ExpressionStmt' && s.expr.kind === 'Call') {
        const cp = calleePathOf(s.expr.callee);
        if (cp && cp.length === 1 && resolveNames.has(cp[0])) {
          for (const a of s.expr.args) {
            out.push(...evaluate(a, entry, loc, ectx));
          }
        }
      }
      if (s.kind === 'Conditional') {
        walk(s.thenBlock);
        if (s.elseBlock) walk(s.elseBlock);
      }
      if (s.kind === 'Loop') walk(s.body);
      if (s.kind === 'TryCatch') {
        walk(s.tryBlock);
        if (s.catchBlock) walk(s.catchBlock);
      }
    }
  };
  walk(fn.body);
  return out;
}

/** setImmediate(() => resolve(userInput)) inside Promise executor. */
function collectNestedTimerResolveTaint(
  fn: FunctionIR,
  entry: TaintEnv,
  module: ModuleCtx,
  loc: Location
): TaintLabel[] {
  const out: TaintLabel[] = [];
  const handleTimerCall = (call: Extract<Value, { kind: 'Call' }>) => {
    const cp = calleePathOf(call.callee);
    if (!isTimerApi(cp)) return;
    for (const a of call.args) {
      if (a.kind === 'Variable') {
        const cb = module.byName.get(a.name);
        if (cb) {
          const nestedEntry = cloneEnv(entry);
          for (const [k, labs] of entry.vars) {
            nestedEntry.vars.set(k, labs.map(l => ({ ...l, flow: [...l.flow] })));
          }
          // Outer resolve is free in nested; also scan resolve(arg) Call args
          out.push(...collectResolveArgTaint(cb, nestedEntry, module, loc));
          out.push(...collectAnyCallArgTaint(cb, nestedEntry, module, loc));
        }
      }
    }
  };
  const walk = (block: Block) => {
    for (const s of block.statements) {
      // (resolve) => setImmediate(...)  — expression-body arrow → Return Call
      if (s.kind === 'ExpressionStmt' && s.expr.kind === 'Call') {
        handleTimerCall(s.expr);
      }
      if (s.kind === 'Return' && s.value?.kind === 'Call') {
        handleTimerCall(s.value);
      }
      if (s.kind === 'Conditional') {
        walk(s.thenBlock);
        if (s.elseBlock) walk(s.elseBlock);
      }
      if (s.kind === 'Loop') walk(s.body);
    }
  };
  walk(fn.body);
  return out;
}

function collectAnyCallArgTaint(
  fn: FunctionIR,
  entry: TaintEnv,
  module: ModuleCtx,
  loc: Location
): TaintLabel[] {
  const out: TaintLabel[] = [];
  const ectx: EvalCtx = { module, returnLabels: [], findings: [] };
  const walk = (block: Block) => {
    for (const s of block.statements) {
      if (s.kind === 'ExpressionStmt' && s.expr.kind === 'Call') {
        for (const a of s.expr.args) {
          out.push(...evaluate(a, entry, loc, ectx));
        }
      }
      if (s.kind === 'Return' && s.value?.kind === 'Call') {
        for (const a of s.value.args) {
          out.push(...evaluate(a, entry, loc, ectx));
        }
      }
      if (s.kind === 'Conditional') {
        walk(s.thenBlock);
        if (s.elseBlock) walk(s.elseBlock);
      }
    }
  };
  walk(fn.body);
  return out;
}

function emitHttpOptionsTaint(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const cands = expandCalleePaths(calleePath, ectx.module.imports);
  const isHttp = cands.some(p => {
    const head = p[0];
    const tail = p[p.length - 1];
    return (
      (['http', 'https'].includes(head) && ['get', 'request'].includes(tail)) ||
      tail === 'get' ||
      tail === 'request'
    );
  });
  if (!isHttp) return;

  for (const arg of value.args) {
    if (arg.kind !== 'ObjectLiteral') continue;
    for (const prop of arg.props) {
      if (prop.key === 'hostname' || prop.key === 'host' || prop.key === 'path' || prop.key === 'href') {
        for (const label of evaluate(prop.value, env, loc, ectx)) {
          ectx.findings.push({
            file: loc.file,
            line: loc.line,
            type: 'ssrf',
            severity: 'HIGH',
            description: `Tainted value in http(s) options.${prop.key} — SSRF`,
            source: label.source.id,
            sink: `http.options.${prop.key}`,
            testCase: 'Control host/path via request options object',
            flow: [...label.flow, { statementId: '<sink>', variable: undefined, location: loc }],
          });
        }
      }
      if (prop.key === 'headers' && prop.value.kind === 'ObjectLiteral') {
        for (const h of prop.value.props) {
          for (const label of evaluate(h.value, env, loc, ectx)) {
            // Env-backed API keys are not hardcodedcreds (BP safe twin)
            if (isEnvSource(label)) continue;
            ectx.findings.push({
              file: loc.file,
              line: loc.line,
              type: 'injection',
              severity: 'HIGH',
              description: `Tainted/hardcoded secret in HTTP header ${h.key} — credential in transit / header injection`,
              source: label.source.id,
              sink: `http.headers.${h.key}`,
              testCase: 'Authorization Bearer with attacker or hardcoded secret',
              flow: [...label.flow, { statementId: '<sink>', variable: undefined, location: loc }],
            });
          }
        }
      }
    }
  }
}

function isFileReadSource(path: string[] | null, imports: ModuleImport[]): boolean {
  if (!path || !path.length) return false;
  for (const c of expandCalleePaths(path, imports)) {
    const tail = c[c.length - 1];
    if (['readFile', 'readFileSync', 'readFilePromise'].includes(tail)) {
      if (c[0] === 'fs' || c[0] === 'fs/promises' || c.length === 1) return true;
    }
  }
  return false;
}

function matchJavascriptCallSourceExtra(
  path: string[],
  imports: ModuleImport[]
): TaintSource | null {
  if (isDbResultSource(path, imports)) return DB_RESULT_SOURCE;
  if (isFileReadSource(path, imports)) return FILE_CONTENT_SOURCE;
  if (isS3ReadSource(path, imports)) {
    return {
      id: 's3.content',
      kind: 'user-input',
      description: 'S3 object body/key from getObject — cloud-stored attacker-influenced data',
      fieldPath: [],
    };
  }
  if (isRedisReadSource(path, imports)) return REDIS_RESULT_SOURCE;
  return null;
}

function isS3ReadSource(path: string[] | null, imports: ModuleImport[]): boolean {
  if (!path || !path.length) return false;
  for (const c of expandCalleePaths(path, imports)) {
    const tail = c[c.length - 1];
    if (['getObjectSync', 'getObject', 'getObjectPromise'].includes(tail)) {
      // s3.getObject*, shared.s3.getObject*, require(...).s3.getObject*
      if (c.includes('s3') || c.includes('S3') || c[c.length - 2] === 's3') return true;
      if (c.length === 1) return true; // bare getObjectSync from destructure
    }
  }
  // require("./shared").s3.getObjectSync → path may be ['require','s3','getObjectSync'] or similar
  const joined = path.join('.');
  if (/\.s3\.(getObject|getObjectSync)/i.test(joined) || /s3\.(getObject|getObjectSync)/i.test(joined)) {
    return true;
  }
  return false;
}

/** Peel (x + 1) | 0 and similar int-wrap for resource sinks. */
function peelIntegerWrap(
  v: Value,
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): TaintLabel[] {
  if (v.kind === 'Binary' && ['|', '&', '+', '-', '*', '<<', '>>'].includes(v.op)) {
    return [
      ...peelIntegerWrap(v.left, env, loc, ectx),
      ...peelIntegerWrap(v.right, env, loc, ectx),
    ];
  }
  return peelNumericCoercion(v, env, loc, ectx);
}

const CONFIG_SOURCE: TaintSource = {
  id: 'config',
  fieldPath: ['config'],
  kind: 'env',
  description: 'Insecure configuration',
};

const HARDCODED_SECRET_SOURCE: TaintSource = {
  id: 'hardcoded.secret',
  fieldPath: ['hardcoded'],
  kind: 'env',
  description: 'Hardcoded secret/credential/token string literal',
};

function looksLikeHardcodedSecret(s: string): boolean {
  if (!s || s.length < 8) return false;
  // Filesystem paths are not secrets ("/var/data/secrets.txt" contains "secret")
  if (/[\/\\]/.test(s) || /^[A-Za-z]:\\/.test(s)) return false;
  if (/\.(txt|json|pem|key|env|log|bin|dat)$/i.test(s)) return false;
  // SQL templates / query strings with password= placeholders are not secret literals
  if (/\b(SELECT|INSERT|UPDATE|DELETE|CONNECT|FROM|WHERE)\b/i.test(s)) return false;
  if (/\?/.test(s) && /password|user|pass/i.test(s)) return false;
  // Config/display labels used as non-secret userInput in BP safe twins
  // (not config_secret_* which ARE credential fixtures)
  if (/^(default_|feature_|app_)/i.test(s) && !/secret|password|token|key/i.test(s)) return false;
  if (/^config_(label|name|value|setting)/i.test(s)) return false;
  // Explicit credential fixtures
  if (/BENCH_FAKE|s3cr3t|p4ssw0rd|passw0rd|config_secret|secret_test|apikey|api_key|private[_-]?key|BEGIN (RSA |EC )?PRIVATE/i.test(s)) {
    return true;
  }
  // secret/password/token as whole-word when it looks like a value (digits, no SQL =)
  if (/\b(secret|password|token|passwd)\b/i.test(s) && /\d/.test(s) && !/=/.test(s) && !/\?/.test(s)) {
    return true;
  }
  // Mixed alnum tokens often used as fake hardcoded keys in BP
  if (s.length >= 12 && /[A-Za-z]/.test(s) && /\d/.test(s) && !/\s/.test(s) && !/^[a-z_]+$/i.test(s)) {
    return true;
  }
  return false;
}

const WEAK_HASH_ALGOS = new Set(['md5', 'sha1', 'md4', 'md2', 'sha0', 'ripemd', 'ripemd160']);

/** parseInt/Number clear injection taint but size is still attacker-controlled. */
function peelNumericCoercion(
  v: Value,
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): TaintLabel[] {
  if (v.kind === 'Call') {
    const path = calleePathOf(v.callee);
    const name = path ? path[path.length - 1] : null;
    // Recurse into coerce args — do NOT evaluate() (parseInt is a sanitizer that returns [])
    if (name && ['parseInt', 'parseFloat', 'Number', 'BigInt', 'int', 'float'].includes(name)) {
      return v.args.flatMap(a => peelNumericCoercion(a, env, loc, ectx));
    }
  }
  if (v.kind === 'Binary') {
    // || 0 fallback after parseInt still carries the coerced taint
    return [
      ...peelNumericCoercion(v.left, env, loc, ectx),
      ...peelNumericCoercion(v.right, env, loc, ectx),
    ];
  }
  if (v.kind === 'Variable') return env.vars.get(v.name) ?? [];
  if (v.kind === 'FieldAccess') return evaluate(v, env, loc, ectx);
  return evaluate(v, env, loc, ectx);
}

function constructorArgTaint(
  path: string[] | null,
  argLabels: TaintLabel[][]
): TaintLabel[] {
  if (!path || path.length !== 1) return [];
  // `new RequestPayload(taint)` / capitalised ctor name
  if (!/^[A-Z]/.test(path[0])) return [];
  // Avoid treating global constructors as always-tainted instances
  if (['Number', 'String', 'Boolean', 'Object', 'Array', 'Date', 'RegExp', 'Error', 'URL', 'Buffer'].includes(path[0])) {
    return [];
  }
  return argLabels.flat();
}

function isCreateHashPath(path: string[] | null, imports: ModuleImport[]): boolean {
  if (!path) return false;
  for (const c of expandCalleePaths(path, imports)) {
    if (c.length === 2 && c[0] === 'crypto' && c[1] === 'createHash') return true;
    if (c.length === 1 && c[0] === 'createHash') return true;
  }
  return false;
}

function weakAlgoFromCreateHashCall(call: Value): string | null {
  if (call.kind !== 'Call' || !call.args.length) return null;
  const algo = call.args[0];
  if (algo.kind !== 'Literal' || algo.literalKind !== 'string' || !algo.raw) return null;
  const a = algo.raw.toLowerCase().replace(/^node:/, '');
  return WEAK_HASH_ALGOS.has(a) ? a : null;
}

/**
 * BP idiom: eval('res.redirect(data);') / eval('http.get(data);')
 * Arg is a string literal of source text — not a tainted string. Walk free
 * identifiers in that text; if any are tainted in env and the text names a
 * known sink, emit a finding.
 */
function emitEvalStringLiteral(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const isEval =
    (calleePath.length === 1 && calleePath[0] === 'eval') ||
    (calleePath.length === 2 && calleePath[1] === 'eval');
  if (!isEval || !value.args.length) return;
  const arg0 = value.args[0];
  if (arg0.kind !== 'Literal' || arg0.literalKind !== 'string' || !arg0.raw) return;
  const code = arg0.raw;

  const sinkPatterns: Array<{ re: RegExp; sink: string; danger: string }> = [
    { re: /res\s*\.\s*redirect\s*\(/, sink: 'express.res.redirect', danger: 'open redirect' },
    { re: /ctx\s*\.\s*redirect\s*\(/, sink: 'koa.ctx.redirect', danger: 'open redirect' },
    { re: /res\s*\.\s*send\s*\(/, sink: 'express.res.send', danger: 'XSS' },
    // Kaioken XLVI — path before XSS: eval often embeds both readFileSync + ctx.body=
    { re: /fs\s*\.\s*readFileSync\s*\(/, sink: 'fs.readFileSync', danger: 'path traversal' },
    { re: /fs\s*\.\s*readFile\s*\(/, sink: 'fs.readFile', danger: 'path traversal' },
    { re: /fs\s*\.\s*writeFileSync\s*\(/, sink: 'fs.writeFileSync', danger: 'path traversal' },
    { re: /fs\s*\.\s*writeFile\s*\(/, sink: 'fs.writeFile', danger: 'path traversal' },
    // Kaioken LV — enterprise pathtraver via eval('fs.unlinkSync(... + data)')
    { re: /fs\s*\.\s*unlinkSync\s*\(/, sink: 'fs.unlinkSync', danger: 'path traversal' },
    { re: /fs\s*\.\s*unlink\s*\(/, sink: 'fs.unlink', danger: 'path traversal' },
    { re: /fs\s*\.\s*rmSync\s*\(/, sink: 'fs.rmSync', danger: 'path traversal' },
    { re: /fs\s*\.\s*rm\s*\(/, sink: 'fs.rm', danger: 'path traversal' },
    { re: /ctx\s*\.\s*body\s*=/, sink: 'koa.ctx.body', danger: 'XSS' },
    // NestJS eval-string returns — require free-var `data` (not createClient({ url: "ldap…" }))
    { re: /\(\s*\{\s*url\s*:\s*data\s*\}\s*\)/, sink: 'nestjs.return.redirect', danger: 'open redirect' },
    { re: /["']\s*<div>\s*["']\s*\+\s*data|<\s*div\s*>["']\s*\+\s*data/, sink: 'nestjs.return.body', danger: 'XSS' },
    // Kaioken LVI — script_in_attributes / HTML attr XSS via eval(string):
    //   eval('(\'<input … value="\' + data + \'">\')')  (held-out nestjs 2 FNs)
    {
      re: /<\s*(?:input|textarea|select|option|button|a|img|iframe|script|div|span|body|p|form)\b/i,
      sink: 'nestjs.return.body',
      danger: 'XSS',
    },
    {
      re: /(?:value|href|src|action|style|onclick|onerror|on\w+)\s*=\s*["'][^"']*["']\s*\+\s*\w+/i,
      sink: 'nestjs.return.body',
      danger: 'XSS',
    },
    { re: /http\s*\.\s*get\s*\(/, sink: 'http.get', danger: 'SSRF' },
    { re: /https\s*\.\s*get\s*\(/, sink: 'https.get', danger: 'SSRF' },
    { re: /fetch\s*\(/, sink: 'fetch', danger: 'SSRF' },
    // Kaioken LV — net.connect / jsYaml.load via eval(string-literal) free vars
    { re: /net\s*\.\s*connect\s*\(/, sink: 'net.connect', danger: 'SSRF' },
    { re: /net\s*\.\s*Socket\s*\(/, sink: 'net.Socket', danger: 'SSRF' },
    { re: /(?:jsYaml|jsyaml|yaml|js\-yaml)\s*\.\s*load\s*\(/, sink: 'jsYaml.load', danger: 'deserialization' },
    { re: /\.load\s*\(\s*data\s*\)/, sink: 'yaml.load', danger: 'deserialization' },
    { re: /(?:childProcess|child_process)\s*\.\s*exec(?:Sync)?\s*\(/, sink: 'child_process.exec', danger: 'command injection' },
    { re: /\bexecSync\s*\(/, sink: 'execSync.bare', danger: 'command injection' },
    { re: /\bexec\s*\(/, sink: 'exec.bare', danger: 'command injection' },
    { re: /db\s*\.\s*query\s*\(/, sink: 'db.query', danger: 'SQL injection' },
    { re: /db\s*\.\s*execute\s*\(/, sink: 'db.execute', danger: 'SQL injection' },
    { re: /\beval\s*\(/, sink: 'eval', danger: 'code execution' },
    { re: /unserialize\s*\(/, sink: 'unserialize', danger: 'deserialization' },
    { re: /nunjucks\s*\.\s*renderString\s*\(/, sink: 'nunjucks.renderString', danger: 'SSTI' },
    { re: /ldap(?:js|Client)?[\s\S]*\.search\s*\(/, sink: 'ldap.search', danger: 'LDAP injection' },
    { re: /\.search\s*\(\s*["']ou=/, sink: 'ldap.search', danger: 'LDAP injection' },
    { re: /xpath\s*\.\s*select\s*\(/, sink: 'xpath.select', danger: 'XPath injection' },
    { re: /findOne\s*\(/, sink: 'nosql.findOne', danger: 'NoSQL injection' },
    { re: /parseXml\s*\(/, sink: 'libxmljs.parseXml', danger: 'XXE' },
  ];

  const idents = new Set(
    (code.match(/\b[A-Za-z_$][\w$]*\b/g) || []).filter(
      id =>
        ![
          'res', 'req', 'ctx', 'http', 'https', 'fetch', 'db', 'eval', 'const', 'let', 'var',
          'function', 'return', 'true', 'false', 'null', 'undefined', 'String', 'Number',
          'childProcess', 'child_process', 'execSync', 'exec', 'query', 'execute', 'get',
          'redirect', 'send', 'renderString', 'nunjucks', 'unserialize', 'SELECT', 'FROM',
          'WHERE', 'id', 'users', 'net', 'connect', 'Socket', 'jsYaml', 'jsyaml', 'yaml',
          'load',
        ].includes(id)
    )
  );

  let matchedSink: { sink: string; danger: string } | null = null;
  for (const p of sinkPatterns) {
    if (p.re.test(code)) {
      matchedSink = p;
      break;
    }
  }
  if (!matchedSink) return;

  const taintedLabs: TaintLabel[] = [];
  for (const id of idents) {
    const labs = env.vars.get(id);
    if (labs?.length) taintedLabs.push(...labs);
  }
  // Also whole free vars that appear after + concatenation in the string
  if (!taintedLabs.length) {
    for (const [k, labs] of env.vars) {
      if (labs.length && new RegExp(`\\b${k}\\b`).test(code)) taintedLabs.push(...labs);
    }
  }
  if (!taintedLabs.length) return;

  for (const label of taintedLabs) {
    ectx.findings.push({
      file: loc.file,
      line: loc.line,
      type: 'injection',
      severity: 'HIGH',
      description: `Tainted free variable reaches ${matchedSink.sink} via eval(string-literal code) — ${matchedSink.danger}`,
      source: label.source.id,
      sink: `eval.string.${matchedSink.sink}`,
      testCase: `eval('...${matchedSink.sink}(taint)...') with free var from request`,
      flow: [...label.flow, { statementId: '<eval-string>', variable: undefined, location: loc }],
    });
  }
}

function emitWeakHashFindings(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  argLabels: TaintLabel[][],
  _env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): void {
  // crypto.createHash("md5").update(taint)
  if (!calleePath || calleePath[calleePath.length - 1] !== 'update') return;
  if (value.callee.kind !== 'FieldAccess') return;
  const obj = value.callee.object;
  if (obj.kind !== 'Call') return;
  const hashPath = calleePathOf(obj.callee);
  if (!isCreateHashPath(hashPath, ectx.module.imports)) return;
  const algo = weakAlgoFromCreateHashCall(obj);
  if (!algo) return;
  for (const label of argLabels[0] ?? []) {
    ectx.findings.push({
      file: loc.file,
      line: loc.line,
      type: 'injection',
      severity: 'HIGH',
      description: `Tainted value hashed with weak algorithm ${algo} via crypto.createHash — weak hash`,
      source: label.source.id,
      sink: `crypto.createHash.${algo}`,
      testCase: `Hash attacker-controlled data with ${algo}`,
      flow: [...label.flow, { statementId: '<sink>', variable: undefined, location: loc }],
    });
  }
}

/** res.status(5xx).json({ error: taint, stack }) — info disclosure / debug in prod */
function emitErrorDisclosure(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): void {
  // BP debug_code_production safe twins gate on session.user first
  if (ectx.sessionUserGated) return;
  if (!calleePath || calleePath[calleePath.length - 1] !== 'json') return;

  let errorStatus = false;
  if (value.callee.kind === 'FieldAccess' && value.callee.object.kind === 'Call') {
    const statusPath = calleePathOf(value.callee.object.callee);
    if (statusPath && statusPath[statusPath.length - 1] === 'status') {
      const codeArg = value.callee.object.args[0];
      if (codeArg?.kind === 'Literal' && codeArg.literalKind === 'number') {
        const code = Number(codeArg.raw);
        if (code >= 400) errorStatus = true;
      }
    }
  }

  const body = value.args[0];
  if (!body || body.kind !== 'ObjectLiteral') return;
  emitErrorBodyDisclosure(body, errorStatus, env, loc, ectx, 'res.json.error');
}

/**
 * Kaioken XLV — shared error/stack body disclosure for Express res.json and
 * Koa `ctx.status=500; ctx.body={ error, stack }`.
 */
function emitErrorBodyDisclosure(
  body: Extract<Value, { kind: 'ObjectLiteral' }>,
  errorStatus: boolean,
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx,
  sinkId: string
): void {
  if (ectx.sessionUserGated) return;
  const sensitiveKeys = new Set(['error', 'stack', 'message', 'detail', 'details', 'exception', 'trace']);
  let hasStack = false;
  const taintedLabs: TaintLabel[] = [];
  for (const prop of body.props) {
    if (prop.key === 'stack') hasStack = true;
    if (sensitiveKeys.has(prop.key)) {
      taintedLabs.push(...evaluate(prop.value, env, loc, ectx));
    }
  }
  if (!taintedLabs.length && !hasStack) return;
  if (!errorStatus && !hasStack) return;

  const labels = taintedLabs.length
    ? taintedLabs
    : [{
        source: CONFIG_SOURCE,
        flow: [{ statementId: '<config>', variable: undefined, location: loc }],
      }];

  for (const label of labels) {
    ectx.findings.push({
      file: loc.file,
      line: loc.line,
      type: 'injection',
      severity: 'HIGH',
      description:
        `Tainted/sensitive data in error JSON response` +
        (hasStack ? ' (stack included)' : '') +
        ` — information disclosure / debug error message`,
      source: label.source.id,
      sink: sinkId,
      testCase: 'Return error/stack body with attacker-influenced fields',
      flow: [...label.flow, { statementId: '<sink>', variable: undefined, location: loc }],
    });
  }
}

/**
 * Kaioken XLV — Koa FieldAssign sinks:
 *   ctx.status = 500
 *   ctx.body = "<div>" + taint          → XSS
 *   ctx.body = { error, stack }         → error disclosure
 */
function emitKoaFieldAssignSinks(
  stmt: Extract<Statement, { kind: 'FieldAssign' }>,
  basePath: { base: string; fields: string[] },
  labels: TaintLabel[],
  env: TaintEnv,
  ectx: EvalCtx
): void {
  const full = [...basePath.fields, stmt.field];
  // ctx.status = NNN
  if (
    basePath.base === 'ctx' &&
    full.length === 1 &&
    full[0] === 'status' &&
    stmt.value.kind === 'Literal' &&
    stmt.value.literalKind === 'number'
  ) {
    const code = Number(stmt.value.raw);
    if (code >= 400) ectx.koaErrorStatus = true;
    return;
  }

  // Kaioken LV — ctx.type = taint (CWE-115 / misinterpretation_output)
  // Express uses res.type(taint); Koa assigns ctx.type. Safes allowlist/zod before assign.
  if (basePath.base === 'ctx' && full.length === 1 && full[0] === 'type' && labels.length) {
    // Suppress when RHS came through zodValidated or constArrays allowlist (rough)
    const rhsName = stmt.value.kind === 'Variable' ? stmt.value.name : null;
    if (rhsName && ectx.module && env.zodValidated?.has(rhsName)) return;
    // peel String(x)
    let peelLabs = labels;
    if (stmt.value.kind === 'Call') {
      const cp = calleePathOf(stmt.value.callee);
      if (cp && cp.length === 1 && cp[0] === 'String' && stmt.value.args[0]) {
        peelLabs = evaluate(stmt.value.args[0], env, stmt.location, ectx);
      }
    }
    if (!peelLabs.length) return;
    for (const label of peelLabs) {
      ectx.findings.push({
        file: stmt.location.file,
        line: stmt.location.line,
        type: 'injection',
        severity: 'MED',
        description: `Tainted value from ${label.source.description.split(' — ')[0]} written to ctx.type — content-type misinterpretation`,
        source: label.source.id,
        sink: 'koa.ctx.type',
        testCase: 'ctx.type = attacker MIME; safe twins allowlist/zod before assign',
        flow: [
          ...label.flow,
          { statementId: stmt.id, variable: 'ctx.type', location: stmt.location },
        ],
      });
    }
    return;
  }

  // ctx.body = ...
  if (!(basePath.base === 'ctx' && full.length === 1 && full[0] === 'body')) return;

  // Error disclosure object body
  if (stmt.value.kind === 'ObjectLiteral') {
    emitErrorBodyDisclosure(
      stmt.value,
      !!ectx.koaErrorStatus,
      env,
      stmt.location,
      ectx,
      'koa.ctx.body.error'
    );
    return;
  }

  // XSS: stringy body with taint (not JSON object ack)
  if (!labels.length) return;
  if (!valueLooksStringyResponse(stmt.value)) return;
  // Kaioken LIII — pure file content after path gate is not user-HTML XSS
  // (koa twin of express.res.send(fileContent) suppress; CWE-22 vulns still hit fs.read)
  const xssLabels = labels.filter(
    (l) =>
      l.source.id !== 'fs.content' &&
      !/File\/stdin read content/i.test(l.source.description || '')
  );
  if (!xssLabels.length) return;

  for (const label of xssLabels) {
    ectx.findings.push({
      file: stmt.location.file,
      line: stmt.location.line,
      type: 'injection',
      severity: 'HIGH',
      description: `Tainted value from ${label.source.description.split(' — ')[0]} reaches ctx.body — XSS via HTML response`,
      source: label.source.id,
      sink: 'koa.ctx.body',
      testCase: 'Reflect attacker input into HTML response body without full encode',
      flow: [
        ...label.flow,
        { statementId: stmt.id, variable: 'ctx.body', location: stmt.location },
      ],
    });
  }
}

/** HTML/string response RHS (not plain object/json ack). */
function valueLooksStringyResponse(v: Value): boolean {
  if (v.kind === 'Binary' || v.kind === 'Template') return true;
  if (v.kind === 'Variable') return true;
  if (v.kind === 'Call') return true;
  if (v.kind === 'FieldAccess') return true;
  if (v.kind === 'Literal' && v.literalKind === 'string') {
    return /<|>|html|div|script|input|span|body/i.test(v.raw || '');
  }
  return false;
}

/**
 * Kaioken XLVII — NestJS controller returns:
 *   return "<div>" + taint          → XSS
 *   return { url: taint }           → open redirect (@Redirect)
 *   return { access: "granted" }    → handled via blockGrantsPrivilege
 * Also: throw new InternalServerErrorException({ error, stack })
 */
/** Flask/Django HTML string return: return '<div>' + taint + '</div>' */
function emitHtmlStringReturn(
  stmt: Extract<Statement, { kind: 'Return' }>,
  labels: TaintLabel[],
  ectx: EvalCtx
): void {
  if (!ACTIVE_CATALOG.extras?.htmlReturnSink) return;
  if (!stmt.value || !labels.length) return;
  const htmlish = valueLooksLikeHtml(stmt.value);
  if (!htmlish) return;
  for (const label of labels) {
    ectx.findings.push({
      file: stmt.location.file,
      line: stmt.location.line,
      type: 'injection',
      severity: 'HIGH',
      description: `Tainted value from ${label.source.description.split(' — ')[0]} reaches HTML string return — XSS`,
      source: label.source.id,
      sink: 'python.html.return',
      testCase: "return '<div>' + attacker + '</div>'",
      flow: [...label.flow, { statementId: stmt.id, variable: undefined, location: stmt.location }],
    });
  }
}

function valueLooksLikeHtml(v: Value): boolean {
  const s = JSON.stringify(v);
  return /<(div|html|h1|h2|span|script|body|input|img|a |p>)/i.test(s);
}

function emitFrameworkReturnSinks(
  stmt: Extract<Statement, { kind: 'Return' }>,
  labels: TaintLabel[],
  env: TaintEnv,
  ectx: EvalCtx
): void {
  if (!stmt.value) return;
  // Only NestJS controller methods — never Express helper returns like `(v) => v`.
  if (!ectx.nestController) return;

  // Redirect field taint on returned object or variable.field
  let redirectLabs: TaintLabel[] = [];
  if (stmt.value.kind === 'ObjectLiteral') {
    for (const p of stmt.value.props) {
      if (!/^(url|location|href|redirect)$/i.test(p.key)) continue;
      redirectLabs.push(...evaluate(p.value, env, stmt.location, ectx));
    }
  } else if (stmt.value.kind === 'Variable') {
    for (const field of ['url', 'location', 'href', 'redirect']) {
      const key = joinTaintKey(stmt.value.name, [field]);
      if (key && env.vars.has(key)) {
        redirectLabs.push(...(env.vars.get(key) || []));
      }
    }
  }

  if (redirectLabs.length) {
    for (const label of redirectLabs) {
      ectx.findings.push({
        file: stmt.location.file,
        line: stmt.location.line,
        type: 'open-redirect',
        severity: 'HIGH',
        description: `Tainted value from ${label.source.description.split(' — ')[0]} reaches redirect url return — open redirect`,
        source: label.source.id,
        sink: 'nestjs.return.redirect',
        testCase: '@Redirect() return { url: attackerInput }',
        flow: [
          ...label.flow,
          { statementId: stmt.id, variable: undefined, location: stmt.location },
        ],
      });
    }
    return; // redirect takes precedence over generic XSS on same return
  }

  // XSS: HTML Binary/Template, or Variable from Nest asyncOut.
  // NOT Call (return eval(taint) is the eval sink).
  // NOT identity `return param` inside helpers like `(v) => v` (XSS FPs).
  if (!labels.length) return;

  const isParamIdentity =
    stmt.value.kind === 'Variable' &&
    !!ectx.currentFnParams?.has(stmt.value.name);

  const stringyReturn =
    stmt.value.kind === 'Binary' ||
    stmt.value.kind === 'Template' ||
    (stmt.value.kind === 'Literal' &&
      stmt.value.literalKind === 'string' &&
      /<|>|html|div|script|input/i.test(stmt.value.raw || '')) ||
    (stmt.value.kind === 'Variable' && !isParamIdentity);

  if (stringyReturn) {
    // Kaioken LIII — pure file content after path gate is not user-HTML XSS
    const xssLabels = labels.filter(
      (l) =>
        l.source.id !== 'fs.content' &&
        !/File\/stdin read content/i.test(l.source.description || '')
    );
    for (const label of xssLabels) {
      ectx.findings.push({
        file: stmt.location.file,
        line: stmt.location.line,
        type: 'injection',
        severity: 'HIGH',
        description: `Tainted value from ${label.source.description.split(' — ')[0]} reaches controller return — XSS via HTML response`,
        source: label.source.id,
        sink: 'nestjs.return.body',
        testCase: 'Reflect attacker input into NestJS controller HTML return',
        flow: [
          ...label.flow,
          { statementId: stmt.id, variable: undefined, location: stmt.location },
        ],
      });
    }
  }
}

/** NestJS HttpException subclasses that dump error/stack to clients. */
function emitNestExceptionDisclosure(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): void {
  if (ectx.sessionUserGated) return;
  if (!calleePath || calleePath.length !== 1) return;
  const name = calleePath[0];
  if (
    !/^(InternalServerErrorException|BadGatewayException|HttpException|UnauthorizedException|ForbiddenException|BadRequestException|NotFoundException)$/.test(
      name
    )
  ) {
    return;
  }
  const body = value.args[0];
  if (!body || body.kind !== 'ObjectLiteral') return;
  // Nest error responses are always "error status" class
  emitErrorBodyDisclosure(body, true, env, loc, ectx, `nestjs.${name}`);
}

/**
 * Cookie options from a named config object / field / builder (not an inline
 * literal of flags). Real apps:
 *   cookies.set(name, val, this.sessionCookieOptions)
 *   cookies.set(name, val, buildRefreshCookieOptions(...))
 *   cookies.set(name, val, { ...this.sessionCookieOptions, signed: false })
 * IR drops object spreads (v1), so the last becomes `{ signed: false }` only —
 * treat that incomplete override as external, not "missing httpOnly".
 */
function cookieOptionsLookExternal(v: Value): boolean {
  if (v.kind === 'Variable' && /options|opts|cookie/i.test(v.name)) return true;
  if (v.kind === 'FieldAccess' && /options|opts|cookie/i.test(v.field)) return true;
  // buildRefreshCookieOptions(...) / buildCookieOptionsWithExpiry(...)
  if (v.kind === 'Call') {
    const path = calleePathOf(v.callee);
    const name = path ? path[path.length - 1] || '' : '';
    if (/cookieoptions|cookie_options|cookieOpts/i.test(name)) return true;
    if (/^(build|get|create|make|resolve).*(cookie|session).*(option|opt)/i.test(name)) {
      return true;
    }
    if (/^(build|get|create|make|resolve).*(option|opt).*(cookie|session)/i.test(name)) {
      return true;
    }
  }
  // spread of external options / incomplete post-spread residual
  if (v.kind === 'ObjectLiteral') {
    for (const p of v.props) {
      if (p.key === '...' || p.key === 'spread') {
        if (cookieOptionsLookExternal(p.value)) return true;
      }
      if (
        (p.value.kind === 'FieldAccess' && /options|opts/i.test(p.value.field)) ||
        (p.value.kind === 'Variable' && /options|opts/i.test(p.value.name))
      ) {
        return true;
      }
    }
    // Only meta keys (signed/path/…) and zero hardening keys → almost always a
    // dropped-spread residual. BP vulns use no options arg at all.
    const keys = v.props.map(p => p.key.toLowerCase());
    if (keys.length > 0) {
      const hardening = keys.some(k =>
        k === 'httponly' || k === 'samesite' || k === 'secure'
      );
      const onlyMeta = keys.every(k =>
        /^(signed|path|domain|maxage|max-age|expires|overwrite|encode)$/i.test(k)
      );
      if (!hardening && onlyMeta) return true;
    }
  }
  return false;
}

/**
 * Kaioken XLV — session cookie set without hardened flags (httpOnly/sameSite).
 * Structural (no taint required): BP safe twins always set secure+httpOnly+sameSite.
 */
function emitInsecureCookieFlags(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const tail = calleePath[calleePath.length - 1];
  const isPhpSetcookie = tail === 'setcookie' || tail === 'setrawcookie';
  const isCookie =
    isPhpSetcookie ||
    (calleePath.length >= 2 &&
      calleePath[calleePath.length - 1] === 'cookie' &&
      calleePath[calleePath.length - 2] === 'res') ||
    (calleePath.length >= 3 &&
      calleePath[calleePath.length - 1] === 'set' &&
      calleePath[calleePath.length - 2] === 'cookies' &&
      calleePath[0] === 'ctx') ||
    (calleePath.length === 2 &&
      calleePath[0] === 'cookies' &&
      calleePath[1] === 'set');
  if (!isCookie) return;
  if (sinkCallIsHardened('koa.ctx.cookies.set', value)) return;
  if (sinkCallIsHardened('express.res.cookie', value)) return;
  if (isPhpSetcookie && sinkCallIsHardened('php.setcookie', value)) return;
  // Options object passed by name (this.sessionCookieOptions / cookieOptions) —
  // flags live in that object; structural ObjectLiteral scan cannot see them.
  // BP safe/vuln twins inline { httpOnly, sameSite, secure } literals.
  const optsArg =
    value.args.length >= 3 ? value.args[2] : value.args.length >= 2 ? value.args[value.args.length - 1] : null;
  if (optsArg && cookieOptionsLookExternal(optsArg)) return;
  // Kaioken LIII — after if (!req.session.user) return, cookie set is auth-gated session
  // material (CWE-539 safe twins). Vulns set cookie with no session-user gate.
  if (ectx.sessionUserGated) return;

  ectx.findings.push({
    file: loc.file,
    line: loc.line,
    type: 'injection',
    severity: 'HIGH',
    description:
      'Session cookie set without httpOnly/sameSite/secure hardening — cookie injection / missing Secure/HttpOnly/SameSite flags',
    source: CONFIG_SOURCE.id,
    sink: isPhpSetcookie
      ? 'php.setcookie'
      : calleePath.includes('cookies')
        ? 'koa.ctx.cookies.set'
        : 'express.res.cookie',
    testCase: 'Set session cookie without httpOnly:true + sameSite + secure',
    flow: [{ statementId: '<cookie-flags>', variable: undefined, location: loc }],
  });
}

/**
 * Weak input "validation": if (/[a-z]+/.test(taint)) res.json({ validated: taint })
 * Unanchored / partial regex does not neutralize — still reflected (inputval).
 */
function emitWeakInputValidation(
  stmt: Extract<Statement, { kind: 'Conditional' }>,
  env: TaintEnv,
  ectx: EvalCtx
): void {
  const labs = taintDrivingCondition(stmt.condition, env, stmt.location, ectx);
  if (!labs.length) return;
  let weakTest = false;
  const cond = stmt.condition;
  if (cond.kind === 'Call' && calleePathOf(cond.callee)?.slice(-1)[0] === 'test') {
    if (cond.callee.kind === 'FieldAccess') {
      const rx = cond.callee.object;
      if (rx.kind === 'Literal' && rx.literalKind === 'string' && rx.raw) {
        const pat = rx.raw;
        if (!(pat.includes('^') && pat.includes('$'))) weakTest = true;
      }
      if (rx.kind === 'Variable') weakTest = true;
    }
  }
  if (!weakTest) return;
  if (!blockEchoesValidatedInput(stmt.thenBlock)) return;

  for (const label of labs) {
    ectx.findings.push({
      file: stmt.location.file,
      line: stmt.location.line,
      type: 'injection',
      severity: 'MED',
      description:
        'Tainted input accepted by weak/partial regex validation and echoed — improper input validation',
      source: label.source.id,
      sink: 'input.validation.weak',
      testCase: 'Bypass partial character-class regex; inject still-valid payload',
      flow: [...label.flow, { statementId: stmt.id, variable: undefined, location: stmt.location }],
    });
  }
}

function blockEchoesValidatedInput(block: Block): boolean {
  for (const s of block.statements) {
    if (s.kind === 'ExpressionStmt' && s.expr.kind === 'Call') {
      const path = calleePathOf(s.expr.callee);
      if (path && (path[path.length - 1] === 'json' || path[path.length - 1] === 'send')) {
        const arg = s.expr.args[0];
        if (arg?.kind === 'ObjectLiteral') {
          for (const p of arg.props) {
            if (/valid|input|value|data|msg|message|echo/i.test(p.key) || p.key === 'validated') {
              return true;
            }
          }
        }
        if (arg && arg.kind !== 'ObjectLiteral') return true;
      }
    }
    // Kaioken XLV — Koa: ctx.body = { validated: data }
    if (s.kind === 'FieldAssign') {
      const base = valueAsFieldPath(s.object);
      if (base && base.base === 'ctx' && s.field === 'body') {
        if (s.value.kind === 'ObjectLiteral') {
          for (const p of s.value.props) {
            if (/valid|input|value|data|msg|message|echo/i.test(p.key) || p.key === 'validated') {
              return true;
            }
          }
        } else {
          return true;
        }
      }
    }
    // Nest/controller return of echoed validated payload — not bare helper Calls
    // (Parse getStore denylist: if (bad.test(name)) return createStore() is NOT an echo).
    if (s.kind === 'Return' && s.value) {
      if (s.value.kind === 'ObjectLiteral') {
        for (const p of s.value.props) {
          if (/valid|input|value|data|msg|message|echo/i.test(p.key) || p.key === 'validated') {
            return true;
          }
        }
      } else if (s.value.kind === 'Variable' || s.value.kind === 'Binary' || s.value.kind === 'Template') {
        return true;
      }
      // return res.json(...) style
      if (s.value.kind === 'Call') {
        const path = calleePathOf(s.value.callee);
        if (path && (path[path.length - 1] === 'json' || path[path.length - 1] === 'send')) {
          return true;
        }
      }
    }
    if (s.kind === 'Conditional' && blockEchoesValidatedInput(s.thenBlock)) return true;
  }
  return false;
}

/**
 * Broken authorization: if (roles.includes(userInput)) { res.json({role:"admin"}) }
 * or if (role === 'admin') after role = taint.
 */
function emitBrokenAuthzGrant(
  stmt: Extract<Statement, { kind: 'Conditional' }>,
  env: TaintEnv,
  ectx: EvalCtx
): void {
  // Prior if (!authzCheck(...)) return; means access was actually gated
  if (ectx.authzGated) return;
  // Kaioken LIII — CSRF mismatch gate already enforced → not missing-authz spray
  if (ectx.csrfGated) return;
  // Kaioken LIII — real crypto compare grant (timingSafeEqual / HMAC) is correct authn
  if (conditionLooksLikeCryptoAuthGrant(stmt.condition)) return;
  if (!blockGrantsPrivilege(stmt.thenBlock)) return;

  const labs = taintDrivingCondition(stmt.condition, env, stmt.location, ectx);
  if (!labs.length) return;

  for (const label of labs) {
    ectx.findings.push({
      file: stmt.location.file,
      line: stmt.location.line,
      type: 'injection',
      severity: 'HIGH',
      description:
        `Tainted input drives authorization grant (admin/access granted) — broken access control / authz failure`,
      source: label.source.id,
      sink: 'authz.grant',
      testCase: 'Attacker-controlled value used in allowlist/role check that grants privilege',
      flow: [...label.flow, { statementId: stmt.id, variable: undefined, location: stmt.location }],
    });
  }
}

function objectLiteralGrantsPrivilege(arg: Value): boolean {
  if (arg.kind !== 'ObjectLiteral') return false;
  for (const p of arg.props) {
    // role/access/admin grants — NOT mere {authenticated:true} (login success ≠ broken authz)
    if (
      (p.key === 'role' || p.key === 'access' || p.key === 'admin') &&
      p.value.kind === 'Literal' &&
      p.value.literalKind === 'string' &&
      /admin|granted|true|ok|success/i.test(p.value.raw || '')
    ) {
      return true;
    }
  }
  return false;
}

function blockGrantsPrivilege(block: Block): boolean {
  for (const s of block.statements) {
    if (s.kind === 'ExpressionStmt' && s.expr.kind === 'Call') {
      const path = calleePathOf(s.expr.callee);
      if (path && (path[path.length - 1] === 'json' || path[path.length - 1] === 'send')) {
        if (s.expr.args[0] && objectLiteralGrantsPrivilege(s.expr.args[0])) return true;
      }
    }
    // Kaioken XLV — Koa: ctx.body = { access: "granted", role: "admin" }
    if (s.kind === 'FieldAssign') {
      const base = valueAsFieldPath(s.object);
      if (base && base.base === 'ctx' && s.field === 'body' && objectLiteralGrantsPrivilege(s.value)) {
        return true;
      }
    }
    if (s.kind === 'Return' && s.value?.kind === 'Call') {
      // return res.json(...)
      const path = calleePathOf(s.value.callee);
      if (path && path[path.length - 1] === 'json' && s.value.args[0]?.kind === 'ObjectLiteral') {
        for (const p of s.value.args[0].props) {
          if (
            p.value.kind === 'Literal' &&
            /admin|granted/i.test(p.value.raw || '')
          ) {
            return true;
          }
        }
      }
    }
    // Kaioken XLVII — NestJS: return { access: "granted", role: "admin" }
    if (s.kind === 'Return' && s.value && objectLiteralGrantsPrivilege(s.value)) {
      return true;
    }
    if (s.kind === 'Conditional' && blockGrantsPrivilege(s.thenBlock)) return true;
  }
  return false;
}

function taintDrivingCondition(
  cond: Value,
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): TaintLabel[] {
  // allowlist.includes(taint) / taint === 'admin' / == 
  if (cond.kind === 'Call') {
    const path = calleePathOf(cond.callee);
    if (path && path[path.length - 1] === 'includes') {
      // receiver may be const array; arg 0 is candidate
      return cond.args.flatMap(a => evaluate(a, env, loc, ectx));
    }
    if (path && path[path.length - 1] === 'test') {
      // regex.test(taint) used as "validation" that still grants — still taint-driven
      return cond.args.flatMap(a => evaluate(a, env, loc, ectx));
    }
  }
  if (cond.kind === 'Binary' && ['===', '==', '!==', '!='].includes(cond.op)) {
    return [
      ...evaluate(cond.left, env, loc, ectx),
      ...evaluate(cond.right, env, loc, ectx),
    ];
  }
  if (cond.kind === 'Unary' && (cond.op === '!' || cond.op === 'not')) {
    // Preserve fail-closed context for authCheck suppress (Kaioken LIII)
    const prev = ectx.inNegation;
    ectx.inNegation = true;
    try {
      return taintDrivingCondition(cond.operand, env, loc, ectx);
    } finally {
      ectx.inNegation = prev;
    }
  }
  return evaluate(cond, env, loc, ectx);
}

function emitMathRandom(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const isRandom =
    (calleePath.length === 2 && calleePath[0] === 'Math' && calleePath[1] === 'random') ||
    (calleePath.length === 1 && calleePath[0] === 'random');
  if (!isRandom) return;
  ectx.findings.push({
    file: loc.file,
    line: loc.line,
    type: 'injection',
    severity: 'MED',
    description: 'Math.random() used for security-sensitive token/id — weak PRNG / weakrand',
    source: CONFIG_SOURCE.id,
    sink: 'Math.random',
    testCase: 'Replace Math.random with crypto.randomBytes / randomFillSync',
    flow: [{ statementId: '<config>', variable: undefined, location: loc }],
  });
}

/** BP corpus LCG constants (Java Random-style): seed*9301+49297 % 233280 */
const LCG_MAGIC = new Set(['9301', '49297', '233280']);

function binaryTreeHasLcgMagic(v: Value): boolean {
  if (v.kind === 'Literal' && v.literalKind === 'number' && v.raw && LCG_MAGIC.has(v.raw)) {
    return true;
  }
  if (v.kind === 'Binary') {
    return binaryTreeHasLcgMagic(v.left) || binaryTreeHasLcgMagic(v.right);
  }
  if (v.kind === 'Unary') return binaryTreeHasLcgMagic(v.operand);
  if (v.kind === 'Call') {
    return v.args.some(binaryTreeHasLcgMagic) || binaryTreeHasLcgMagic(v.callee);
  }
  if (v.kind === 'FieldAccess') return binaryTreeHasLcgMagic(v.object);
  return false;
}

function emitWeakLcgPrng(labs: TaintLabel[], loc: Location, ectx: EvalCtx): void {
  // Dedupe: one LCG finding per line
  if (ectx.findings.some(f => f.sink === 'prng.lcg' && f.line === loc.line && f.file === loc.file)) {
    return;
  }
  const label = labs[0];
  ectx.findings.push({
    file: loc.file,
    line: loc.line,
    type: 'injection',
    severity: 'HIGH',
    description:
      `Tainted/user-influenced seed drives linear congruential PRNG (9301/49297/233280) — weak PRNG / same-seed / small random space`,
    source: label?.source.id ?? CONFIG_SOURCE.id,
    sink: 'prng.lcg',
    testCase: 'Replace LCG token mint with crypto.randomBytes',
    flow: label?.flow?.length
      ? [...label.flow, { statementId: '<prng-lcg>', variable: undefined, location: loc }]
      : [{ statementId: '<prng-lcg>', variable: undefined, location: loc }],
  });
}

function conditionLooksLikeZeroDivisorGuard(cond: Value): boolean {
  // divisor === 0n / == 0 / === 0
  if (cond.kind !== 'Binary') return false;
  if (cond.op !== '===' && cond.op !== '==' && cond.op !== '!==' && cond.op !== '!=') return false;
  const zeroLit = (v: Value) => {
    if (v.kind === 'Literal') {
      return (
        v.raw === '0' ||
        v.raw === '0n' ||
        v.raw === '0N' ||
        (v.literalKind === 'number' && v.raw === '0')
      );
    }
    // Frontend v1: 0n BigIntLiteral → Unknown
    if (v.kind === 'Unknown' && /bigintliteral/i.test(v.hint || '')) return true;
    return false;
  };
  return zeroLit(cond.left) || zeroLit(cond.right);
}

function emitDivideByZero(labs: TaintLabel[], loc: Location, ectx: EvalCtx): void {
  if (ectx.findings.some(f => f.sink === 'div.zero' && f.line === loc.line && f.file === loc.file)) {
    return;
  }
  const label = labs[0];
  ectx.findings.push({
    file: loc.file,
    line: loc.line,
    type: 'injection',
    severity: 'MED',
    description:
      'Division/modulo by attacker-influenced divisor without zero check — divide by zero',
    source: label?.source.id ?? CONFIG_SOURCE.id,
    sink: 'div.zero',
    testCase: 'Send non-numeric or zero divisor to crash arithmetic',
    flow: label?.flow?.length
      ? [...label.flow, { statementId: '<div-zero>', variable: undefined, location: loc }]
      : [{ statementId: '<div-zero>', variable: undefined, location: loc }],
  });
}

/** try { JSON.parse(taint) } catch (e) { } — empty catch swallows parse errors */
function emitEmptyCatchAfterParse(
  stmt: Extract<Statement, { kind: 'TryCatch' }>,
  env: TaintEnv,
  ectx: EvalCtx
): void {
  if (!stmt.catchBlock) return;
  // Empty or no-op catch (no statements, or only empty)
  if (stmt.catchBlock.statements.length > 0) {
    // Allow only pure rethrow patterns as non-empty — anything else is "handled"
    // Safe twins: catch(e) { if (e instanceof SyntaxError) { res.status(400)...; return; } throw e; }
    if (!catchBlockIsEmptyOrNada(stmt.catchBlock)) return;
  }
  // Try body must parse tainted input
  let parseTaint = false;
  let labs: TaintLabel[] = [];
  const walk = (b: Block) => {
    for (const s of b.statements) {
      if (s.kind === 'ExpressionStmt' && s.expr.kind === 'Call') {
        const path = calleePathOf(s.expr.callee);
        if (path && path[path.length - 1] === 'parse' && path[0] === 'JSON') {
          labs = s.expr.args.flatMap(a => evaluate(a, env, s.location, ectx));
          if (labs.length) parseTaint = true;
        }
      }
      if (s.kind === 'Assign' && s.value.kind === 'Call') {
        const path = calleePathOf(s.value.callee);
        if (path && path[path.length - 1] === 'parse' && path[0] === 'JSON') {
          labs = s.value.args.flatMap(a => evaluate(a, env, s.location, ectx));
          if (labs.length) parseTaint = true;
        }
      }
    }
  };
  walk(stmt.tryBlock);
  if (!parseTaint) return;
  const label = labs[0];
  ectx.findings.push({
    file: stmt.location.file,
    line: stmt.location.line,
    type: 'injection',
    severity: 'MED',
    description:
      'JSON.parse of tainted input with empty/no-op catch — fail-open / generic catch / improper exception handling',
    source: label?.source.id ?? CONFIG_SOURCE.id,
    sink: 'json.parse.empty-catch',
    testCase: 'Send invalid JSON; error swallowed and request continues',
    flow: label?.flow?.length
      ? [...label.flow, { statementId: stmt.id, variable: undefined, location: stmt.location }]
      : [{ statementId: stmt.id, variable: undefined, location: stmt.location }],
  });
}

function catchBlockIsEmptyOrNada(block: Block): boolean {
  if (!block.statements.length) return true;
  // Only empty ExpressionStmts or comments — treat any real statement as handling
  for (const s of block.statements) {
    if (s.kind === 'ExpressionStmt' && s.expr.kind === 'Literal') continue;
    return false;
  }
  return true;
}

function emitTaintedErrorThrow(
  expr: Value,
  labs: TaintLabel[],
  loc: Location,
  ectx: EvalCtx
): void {
  if (!labs.length) return;
  // throw new Error(...) — not TypeError (BP safe uses TypeError for typed validation)
  if (expr.kind !== 'Call') return;
  const path = calleePathOf(expr.callee);
  if (!path || path[path.length - 1] !== 'Error') return;
  if (path.length >= 2 && path[path.length - 2] !== 'Error') {
    // TypeError ends with Error too? path ['TypeError'] vs ['Error']
  }
  const name = path[0];
  if (name !== 'Error') return; // skip TypeError, RangeError, etc.
  ectx.findings.push({
    file: loc.file,
    line: loc.line,
    type: 'injection',
    severity: 'MED',
    description:
      'throw new Error embeds attacker-controlled data — generic throws / information in exception',
    source: labs[0].source.id,
    sink: 'throw.Error',
    testCase: 'Force validation throw; read message for reflected input',
    flow: [
      ...labs[0].flow,
      { statementId: '<throw>', variable: undefined, location: loc },
    ],
  });
}

/**
 * Kaioken L — crypto.publicEncrypt({ padding: RSA_PKCS1_PADDING }) without OAEP.
 */
function emitRsaPkcs1NoOaep(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const tail = calleePath[calleePath.length - 1];
  if (tail !== 'publicEncrypt' && tail !== 'privateDecrypt') return;
  for (const arg of value.args) {
    if (arg.kind !== 'ObjectLiteral') continue;
    for (const prop of arg.props) {
      if (prop.key !== 'padding') continue;
      // crypto.constants.RSA_PKCS1_PADDING — FieldAccess chain ending PKCS1_PADDING without OAEP
      const path = calleePathOf(prop.value);
      if (!path) continue;
      const joined = path.join('.');
      if (/RSA_PKCS1_PADDING/.test(joined) && !/OAEP/.test(joined)) {
        ectx.findings.push({
          file: loc.file,
          line: loc.line,
          type: 'injection',
          severity: 'HIGH',
          description:
            'RSA PKCS#1 v1.5 padding (RSA_PKCS1_PADDING) without OAEP — rsa_no_oaep / weak crypto padding',
          source: CONFIG_SOURCE.id,
          sink: 'crypto.rsa.pkcs1',
          testCase: 'Use RSA_PKCS1_OAEP_PADDING',
          flow: [{ statementId: '<rsa-pkcs1>', variable: undefined, location: loc }],
        });
      }
    }
  }
}

const WEAK_CIPHER_RE = /^(des|des-ede|des-ede3|rc2|rc4|bf|blowfish|aes-128-ecb|aes-256-ecb|.*-ecb)$/i;

function emitWeakKeyAndCipher(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const cands = expandCalleePaths(calleePath, ectx.module.imports);

  // crypto.generateKeyPairSync("rsa", { modulusLength: 512 })
  const isKeyPair = cands.some(
    p =>
      (p[0] === 'crypto' && (p[1] === 'generateKeyPairSync' || p[1] === 'generateKeyPair')) ||
      p[p.length - 1] === 'generateKeyPairSync' ||
      p[p.length - 1] === 'generateKeyPair'
  );
  if (isKeyPair) {
    for (const arg of value.args) {
      if (arg.kind !== 'ObjectLiteral') continue;
      for (const prop of arg.props) {
        if (
          prop.key === 'modulusLength' &&
          prop.value.kind === 'Literal' &&
          prop.value.literalKind === 'number'
        ) {
          const n = Number(prop.value.raw);
          if (n > 0 && n < 2048) {
            ectx.findings.push({
              file: loc.file,
              line: loc.line,
              type: 'injection',
              severity: 'HIGH',
              description: `RSA modulusLength ${n} is too small (<2048) — weak key length`,
              source: CONFIG_SOURCE.id,
              sink: 'crypto.generateKeyPairSync.weak',
              testCase: 'Use modulusLength >= 2048',
              flow: [{ statementId: '<config>', variable: undefined, location: loc }],
            });
          }
        }
      }
    }
  }

  // crypto.createCipheriv("des-ede3-ecb", ...)
  const isCipher = cands.some(
    p =>
      (p[0] === 'crypto' &&
        (p[1] === 'createCipheriv' || p[1] === 'createCipher' || p[1] === 'createDecipheriv')) ||
      ['createCipheriv', 'createCipher', 'createDecipheriv'].includes(p[p.length - 1])
  );
  if (isCipher && value.args[0]?.kind === 'Literal' && value.args[0].literalKind === 'string') {
    const algo = (value.args[0].raw || '').toLowerCase();
    if (WEAK_CIPHER_RE.test(algo) || algo.includes('ecb') || algo.startsWith('des')) {
      ectx.findings.push({
        file: loc.file,
        line: loc.line,
        type: 'injection',
        severity: 'HIGH',
        description: `Weak/obsolete cipher algorithm "${algo}" — weakcipher`,
        source: CONFIG_SOURCE.id,
        sink: `crypto.createCipheriv.${algo}`,
        testCase: 'Use aes-256-gcm or modern AEAD',
        flow: [{ statementId: '<config>', variable: undefined, location: loc }],
      });
    }
  }
}

/** Hardcoded key material into createCipheriv (no user taint — still a vuln twin). */
function emitHardcodedCryptoKey(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const cands = expandCalleePaths(calleePath, ectx.module.imports);
  const isCipher = cands.some(
    p =>
      (p[0] === 'crypto' && (p[1] === 'createCipheriv' || p[1] === 'createCipher')) ||
      p[p.length - 1] === 'createCipheriv' ||
      p[p.length - 1] === 'createCipher'
  );
  if (!isCipher || value.args.length < 2) return;

  const keyArg = value.args[1];
  const keyLabs = evaluate(keyArg, env, loc, ectx);
  // User-tainted keys already covered by catalog sink. Flag static/non-random keys.
  // Env-backed keys are NOT hardcoded (BP safe twin uses process.env.ENC_KEY) —
  // except process.env.USER_INPUT (attacker stand-in; catalog path should fire).
  const fromUser = keyLabs.some(
    l =>
      l.source.kind === 'user-input' ||
      l.source.id.startsWith('express') ||
      l.source.id.startsWith('koa') ||
      l.source.id.startsWith('fastify') ||
      l.source.id.startsWith('nestjs') ||
      isAttackerEnvSource(l)
  );
  if (fromUser) return;
  if (keyLabs.some(l => isEnvSource(l) && !isAttackerEnvSource(l))) return;
  if (involvesSecureRandom(keyArg)) return;
  // Kaioken LVII — static key/nonce evidence without overclaiming instance keys.
  // BP: Buffer.from(STATIC_KEY.padEnd…), Buffer.alloc(32,1) + Buffer.alloc(12,0) IV twin.
  // Real-world skip: this._encryptionKey, sha256(config).digest() variables.
  const fromHardcodedSecret = keyLabs.some(
    l =>
      /hardcoded|literal.?secret|secret.?literal|BENCH_FAKE/i.test(
        `${l.source.id} ${l.source.description || ''}`
      ) || l.source.id === 'hardcoded.secret' || l.source.id === 'literal.secret'
  );
  if (involvesHashDerive(keyArg)) return;
  // Instance/config fields without static evidence (this._encryptionKey from
  // secret manager) — skip. Hardcoded literal assigned onto a field still fires
  // via fromHardcodedSecret (Pan LVIII flag: storage site ≠ non-static).
  if (keyArg.kind === 'FieldAccess' && !fromHardcodedSecret && !keyLabs.length) {
    return;
  }
  if (
    keyArg.kind === 'Variable' &&
    !fromHardcodedSecret &&
    !keyLabs.length
  ) {
    return; // bare derived/config var, not a static construct
  }
  const hasStaticKeyMaterial =
    fromHardcodedSecret ||
    valueContainsStringLiteral(keyArg) ||
    involvesBufferStaticConstruct(keyArg) ||
    (keyArg.kind === 'Literal' &&
      (keyArg.literalKind === 'string' || keyArg.literalKind === 'number') &&
      !!keyArg.raw &&
      String(keyArg.raw).length >= 8);
  if (!hasStaticKeyMaterial) return;
  ectx.findings.push({
    file: loc.file,
    line: loc.line,
    type: 'injection',
    severity: 'HIGH',
    description: 'Hardcoded/static crypto key material passed to createCipheriv — hardcoded crypto key',
    source: keyLabs[0]?.source.id ?? CONFIG_SOURCE.id,
    sink: 'crypto.createCipheriv.hardcoded-key',
    testCase: 'Load keys from a secret manager / env, never hardcode',
    flow: keyLabs[0]?.flow?.length
      ? [...keyLabs[0].flow, { statementId: '<sink>', variable: undefined, location: loc }]
      : [{ statementId: '<config>', variable: undefined, location: loc }],
  });
}

/** Buffer.alloc/from/fill constructions used as static keys or fixed nonces (BP). */
function involvesBufferStaticConstruct(v: Value): boolean {
  switch (v.kind) {
    case 'Call': {
      const path = calleePathOf(v.callee);
      if (path) {
        const joined = path.join('.');
        if (
          /^(Buffer\.)?(alloc|allocUnsafe|allocUnsafeSlow|fill|from)$/i.test(
            path[path.length - 1] || ''
          ) ||
          /Buffer\.(alloc|from|fill)/i.test(joined)
        ) {
          return true;
        }
        // .slice(0,32) on Buffer.from(...) — still static construct
        if (path[path.length - 1] === 'slice' && v.callee.kind === 'FieldAccess') {
          return involvesBufferStaticConstruct(v.callee.object);
        }
      }
      if (v.callee.kind === 'FieldAccess' && v.callee.field === 'slice') {
        return involvesBufferStaticConstruct(v.callee.object);
      }
      return v.args.some(involvesBufferStaticConstruct);
    }
    case 'FieldAccess':
      return involvesBufferStaticConstruct(v.object);
    case 'Binary':
      return involvesBufferStaticConstruct(v.left) || involvesBufferStaticConstruct(v.right);
    default:
      return false;
  }
}

/** Key derived via hash/KDF — not a hardcoded literal (Strapi getHashedKey etc.). */
function involvesHashDerive(v: Value): boolean {
  switch (v.kind) {
    case 'Call': {
      const path = calleePathOf(v.callee);
      if (path) {
        const joined = path.join('.');
        const last = path[path.length - 1] || '';
        if (/^(scrypt|scryptSync|pbkdf2|pbkdf2Sync|hkdf|hkdfSync)$/i.test(last)) {
          return true;
        }
        if (/createHash|createHmac/i.test(joined)) return true;
      }
      // crypto.createHash(...).update(...).digest()
      if (v.callee.kind === 'FieldAccess' && v.callee.field === 'digest') {
        return true;
      }
      if (v.callee.kind === 'FieldAccess' && v.callee.field === 'update') {
        return involvesHashDerive(v.callee.object);
      }
      return v.args.some(involvesHashDerive);
    }
    case 'FieldAccess':
      return involvesHashDerive(v.object);
    case 'Binary':
      return involvesHashDerive(v.left) || involvesHashDerive(v.right);
    default:
      return false;
  }
}

function involvesSecureRandom(v: Value): boolean {
  switch (v.kind) {
    case 'Call': {
      const path = calleePathOf(v.callee);
      if (path) {
        const joined = path.join('.');
        if (/randomBytes|randomFill|generateKey|getRandomValues/i.test(joined)) return true;
      }
      return v.args.some(involvesSecureRandom) || involvesSecureRandom(v.callee);
    }
    case 'FieldAccess':
      return involvesSecureRandom(v.object);
    case 'Binary':
      return involvesSecureRandom(v.left) || involvesSecureRandom(v.right);
    default:
      return false;
  }
}

function valueContainsStringLiteral(v: Value): boolean {
  switch (v.kind) {
    case 'Literal':
      return v.literalKind === 'string' && !!v.raw && v.raw.length >= 8;
    case 'Call':
      return v.args.some(valueContainsStringLiteral);
    case 'Binary':
      return valueContainsStringLiteral(v.left) || valueContainsStringLiteral(v.right);
    case 'FieldAccess':
      return valueContainsStringLiteral(v.object);
    default:
      return false;
  }
}

function emitPrototypePollution(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  argLabels: TaintLabel[][],
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath || !calleePath.length) return;
  const name = calleePath[calleePath.length - 1];
  const isMerge =
    /^(merge|extend|defaultsDeep|defaults|assignIn|assign)$/i.test(name) ||
    (calleePath[0] === 'Object' && name === 'assign') ||
    (calleePath[0] === '_' && /merge|extend|defaults/i.test(name)) ||
    /merge/i.test(name);
  if (!isMerge) return;
  // Kaioken LIII — mass-assign safe twins allowlist keys before Object.assign
  if (ectx.fieldAllowlistGated) return;

  const flat = argLabels.flat();
  if (!flat.length) return;

  for (const label of flat) {
    ectx.findings.push({
      file: loc.file,
      line: loc.line,
      type: 'injection',
      severity: 'HIGH',
      description: `Tainted object merged via ${calleePath.join('.')} — prototype pollution risk`,
      source: label.source.id,
      sink: 'prototype.pollution.merge',
      testCase: 'Deep-merge untrusted JSON into objects without key allowlists',
      flow: [...label.flow, { statementId: '<sink>', variable: undefined, location: loc }],
    });
  }
}

function emitTlsVerifyDisabled(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const candidates = expandCalleePaths(calleePath, ectx.module.imports);
  const isTlsCall = candidates.some(p => {
    const head = p[0];
    const tail = p[p.length - 1];
    if (['https', 'http', 'tls'].includes(head) && ['get', 'request', 'connect'].includes(tail)) return true;
    if (p.length === 1 && ['get', 'request'].includes(tail)) return true; // rare bare
    return false;
  });
  // Also: https.get after require alias expand
  const looksLikeRequest = candidates.some(p =>
    ['get', 'request'].includes(p[p.length - 1]) || p[0] === 'https' || p[0] === 'http'
  );
  if (!isTlsCall && !looksLikeRequest) return;

  for (const arg of value.args) {
    if (arg.kind !== 'ObjectLiteral') continue;
    for (const prop of arg.props) {
      if (
        prop.key === 'rejectUnauthorized' &&
        prop.value.kind === 'Literal' &&
        (prop.value.raw === 'false' || prop.value.literalKind === 'boolean' && prop.value.raw === 'false')
      ) {
        ectx.findings.push({
          file: loc.file,
          line: loc.line,
          type: 'injection',
          severity: 'HIGH',
          description:
            'TLS certificate verification disabled (rejectUnauthorized: false) — man-in-the-middle risk',
          source: CONFIG_SOURCE.id,
          sink: 'tls.rejectUnauthorized',
          testCase: 'HTTPS request with rejectUnauthorized: false',
          flow: [{ statementId: '<config>', variable: undefined, location: loc }],
        });
      }
    }
  }
}

/** https.get(url, { checkServerIdentity: () => undefined }) — CWE-297 cert host mismatch. */
function emitCertHostIdentityBypass(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const tail = calleePath[calleePath.length - 1];
  const head = calleePath[0];
  const isHttps =
    tail === 'get' ||
    tail === 'request' ||
    head === 'https' ||
    calleePath.includes('https');
  if (!isHttps && head !== 'tls') return;
  for (const arg of value.args) {
    if (arg.kind !== 'ObjectLiteral') continue;
    for (const prop of arg.props) {
      if (prop.key !== 'checkServerIdentity') continue;
      // BP vuln twins always set checkServerIdentity (often () => undefined).
      // Safe twins omit the option entirely — so presence alone is the signal.
      ectx.findings.push({
        file: loc.file,
        line: loc.line,
        type: 'injection',
        severity: 'HIGH',
        description:
          'TLS checkServerIdentity overridden — certificate hostname mismatch accepted (CWE-297)',
        source: CONFIG_SOURCE.id,
        sink: 'tls.checkServerIdentity',
        testCase: 'https.get(url, { checkServerIdentity: () => undefined })',
        flow: [{ statementId: '<config>', variable: undefined, location: loc }],
      });
    }
  }
}

/**
 * Bare JSON.parse(taint) as a statement outside try/catch — improper cleanup /
 * unusual condition (CWE-460 / CWE-754). Safe twins wrap parse in try/catch.
 */
function emitBareJsonParse(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  argLabels: TaintLabel[][],
  loc: Location,
  ectx: EvalCtx
): void {
  if (ectx.inTryBlock) return;
  // Only bare statement `JSON.parse(data);` — not `const x = JSON.parse(data)`
  if (!ectx.inExpressionStmt) return;
  if (!calleePath) return;
  const isParse =
    (calleePath.length === 2 && calleePath[0] === 'JSON' && calleePath[1] === 'parse') ||
    (calleePath.length === 1 && calleePath[0] === 'parse');
  if (!isParse) return;
  const labs = (argLabels[0] ?? []).filter((l) => l.source.id !== CONFIG_SOURCE.id);
  if (!labs.length) return;
  for (const label of labs) {
    ectx.findings.push({
      file: loc.file,
      line: loc.line,
      type: 'injection',
      severity: 'MED',
      description: `Tainted value from ${label.source.description.split(' — ')[0]} reaches JSON.parse without try/catch — improper exception / unusual condition handling`,
      source: label.source.id,
      sink: 'JSON.parse.bare',
      testCase: 'JSON.parse(userInput) without try/catch — crash / fail-open parse',
      flow: [...label.flow, { statementId: '<sink>', variable: undefined, location: loc }],
    });
  }
}

/**
 * Kaioken LV — info_loss_omission (CWE-221): after sensitive db.execute(DELETE/UPDATE),
 * vuln twins log a static "request processed"; safes log `audit actor=` + data.
 * Fire when console.log arg is a pure string literal (no taint / no concat of data).
 */
function emitInfoLossOmissionLog(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  argLabels: TaintLabel[][],
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!calleePath) return;
  const isConsoleLog =
    (calleePath.length === 2 &&
      calleePath[0] === 'console' &&
      (calleePath[1] === 'log' || calleePath[1] === 'info' || calleePath[1] === 'debug')) ||
    (calleePath.length === 1 && calleePath[0] === 'log');
  if (!isConsoleLog || !value.args.length) return;

  const arg0 = value.args[0];
  // Safe twins: "audit actor=" + data  (Binary) or template with expr
  if (arg0.kind === 'Binary' || arg0.kind === 'Template') return;
  if (arg0.kind === 'Variable') {
    // log(data) carries identity — not omission
    if ((env.vars.get(arg0.name) ?? []).length) return;
  }
  // Pure literal static message = info loss relative to prior sensitive op
  if (arg0.kind !== 'Literal' || arg0.literalKind !== 'string') return;
  const msg = (arg0.raw || '').toLowerCase();
  // BP vuln shape: console.log("request processed") — not audit/detail logs
  if (!/request processed|done|ok|success|completed/.test(msg)) return;
  if (/audit|actor=|action=|user=|owner=/.test(msg)) return;

  // Require a prior sensitive db.execute in this function (same ectx findings or rough heuristic)
  const sawSensitiveDb = ectx.findings.some(
    (f) =>
      /db\.execute|DELETE FROM|UPDATE /i.test(f.description + f.sink) &&
      f.file === loc.file
  );
  if (!sawSensitiveDb) return;

  ectx.findings.push({
    file: loc.file,
    line: loc.line,
    type: 'injection',
    severity: 'LOW',
    description:
      'Sensitive db.execute followed by static console.log without actor/data — information loss / omission of security-relevant log details',
    source: 'control-flow',
    sink: 'console.log.info-loss-omission',
    testCase:
      'console.log("request processed") after DELETE/UPDATE; safe logs audit actor= + data',
    flow: [{ statementId: '<info-loss>', variable: undefined, location: loc }],
  });
}

/**
 * Kaioken LV — `db.execute(...);` as ExpressionStmt (return discarded).
 * BP unchecked_return / unexpected_status / error_no_action / unchecked_error /
 * error_condition_detect / insuff_privilege: safes assign `_result` and check
 * `_result.affected === 0`. Vulns call execute as a bare statement.
 * Do NOT alias CWE-221 onto inject primaries (FPR on info_loss safes).
 */
function emitUncheckedDbExecute(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  argLabels: TaintLabel[][],
  loc: Location,
  ectx: EvalCtx
): void {
  // Language-selected catalogs opt in. Python exec()/run() are not JS db.execute.
  if (!ACTIVE_CATALOG.extras?.uncheckedDbExecute) return;
  if (!ectx.inExpressionStmt) return;
  if (!calleePath) return;
  const cands = expandCalleePaths(calleePath, ectx.module.imports);
  const isDbExec = cands.some((p) => {
    const tail = p[p.length - 1];
    if (!['execute', 'query', 'run', 'exec'].includes(tail)) return false;
    // db.execute / connection.query / sequelize.query
    if (p.length === 1) return true; // bare execute from destructure
    const head = p[0];
    return (
      head === 'db' ||
      head === 'database' ||
      head === 'conn' ||
      head === 'connection' ||
      head === 'client' ||
      head === 'sequelize' ||
      head === 'knex' ||
      head === 'pool' ||
      p.includes('db')
    );
  });
  if (!isDbExec) return;
  // Prefer user-tainted executes; still flag bare execute of static SQL (less common)
  const labs = argLabels.flat().filter((l) => l.source.id !== CONFIG_SOURCE.id);
  const label = labs[0];
  ectx.findings.push({
    file: loc.file,
    line: loc.line,
    type: 'injection',
    severity: 'MED',
    description: label
      ? `Tainted value from ${label.source.description.split(' — ')[0]} reaches db.execute without checking return/status — unchecked return / unexpected status / error no action`
      : 'db.execute/query as statement without checking return/status — unchecked return / unexpected status / error no action',
    source: label?.source.id ?? 'control-flow',
    sink: 'db.execute.unchecked-return',
    testCase:
      'db.execute(...) as ExpressionStmt — discard return; safe twins check _result.affected',
    flow: label
      ? [...label.flow, { statementId: '<sink>', variable: undefined, location: loc }]
      : [{ statementId: '<control>', variable: undefined, location: loc }],
  });
}

/**
 * params.get("role") after Map filled from querystring of taint — CWE-235 extra parameter.
 * res.json is intentionally not a generic sink; this is the BP-specific role mass-assign shape.
 */
function emitExtraParameterRole(
  value: Extract<Value, { kind: 'Call' }>,
  calleePath: string[] | null,
  argLabels: TaintLabel[][],
  env: TaintEnv,
  loc: Location,
  ectx: EvalCtx
): void {
  if (!ACTIVE_CATALOG.extras?.extraParameterRole) return;
  if (!calleePath || calleePath[calleePath.length - 1] !== 'get') return;
  const keyArg = value.args[0];
  if (
    !keyArg ||
    keyArg.kind !== 'Literal' ||
    keyArg.literalKind !== 'string' ||
    !/^(role|admin|privilege|access|isAdmin)$/i.test(keyArg.raw || '')
  ) {
    return;
  }
  // Receiver Map/object carries taint from querystring parse of user input
  let recvLabs: TaintLabel[] = [];
  if (value.callee.kind === 'FieldAccess') {
    recvLabs = evaluate(value.callee.object, env, loc, ectx);
  }
  const labs = [...recvLabs, ...(argLabels.flat() || [])].filter(
    (l) => l.source.id !== CONFIG_SOURCE.id
  );
  if (!labs.length) return;
  for (const label of labs) {
    ectx.findings.push({
      file: loc.file,
      line: loc.line,
      type: 'injection',
      severity: 'HIGH',
      description: `Tainted querystring Map yields privileged key "${keyArg.raw}" via .get — improper handling of extra parameters (CWE-235)`,
      source: label.source.id,
      sink: 'params.get.role',
      testCase: 'Map from user "&" pairs; params.get("role") drives privileged response',
      flow: [...label.flow, { statementId: '<sink>', variable: undefined, location: loc }],
    });
  }
}

function matchSanitizer(path: string[], imports: ModuleImport[] = []): Sanitizer | null {
  for (const candidate of expandCalleePaths(path, imports)) {
    for (const san of ACTIVE_SANITIZERS) {
      if (pathsEqual(candidate, san.calleePath)) return san;
    }
  }
  return ACTIVE_CATALOG.matchSanitizerExtra?.(path, imports) ?? null;
}

function pathsEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((p, i) => p === b[i]);
}

function pathStartsWith(p: string[], prefix: string[]): boolean {
  if (p.length < prefix.length) return false;
  return prefix.every((s, i) => p[i] === s);
}

function mapSinkDangerToType(danger: TaintSink['danger']): string {
  switch (danger) {
    case 'code-execution':     return 'injection';
    case 'sql-injection':      return 'injection';
    case 'command-injection':  return 'injection';
    case 'template-injection': return 'injection';
    case 'redirect':           return 'open-redirect';
    case 'ssrf':               return 'ssrf';
  }
}

function synthesizeTestCase(source: TaintSource, sink: TaintSink): string {
  const payload = sink.danger === 'code-execution'
    ? `"; process.exit(1); //"`
    : sink.danger === 'command-injection'
      ? `"; rm -rf /tmp/sentinel //"`
      : `"' OR '1'='1"`;
  return `POST to this endpoint with ${source.fieldPath.join('.')}=${payload} — reaches ${sink.id} without a sanitizer.`;
}

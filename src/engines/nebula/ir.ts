// NEBULA IR — the intermediate representation VANTAGE's semantic engine analyzes.
//
// Per ADR-0002: a deliberately minimal IR, hand-rolled rather than borrowed
// from a compiler framework, because polyglot support is a near-term target
// and every major toolchain (TS, Python's ast, SwiftSyntax) has its own
// idioms. One analyzer against one IR that multiple frontends lower into
// beats one analyzer per language.
//
// The IR is designed for intraprocedural taint analysis v1. Things it
// deliberately does NOT represent:
//   - control-flow graph structure beyond basic blocks (no dominance, no SSA)
//   - types beyond "is this a string / function / unknown"
//   - object structure beyond "field access on a named variable"
//   - exceptions (try/catch is a block structure; tainted values re-emerge
//     from catch as-is for v1)
//
// Interprocedural extension (v1.1) adds `CallGraph` on the side; no IR change
// required. Field-sensitivity (v2) adds a `FieldPath` to `Variable`; IR change
// required but backward-compatible (variables without field paths still work).

export type StatementId = string;
export type FunctionId = string;

export interface Location {
  file: string;    // corpus-relative POSIX path
  line: number;
  column?: number;
}

// ─── Values ─────────────────────────────────────────────────────────────────

export type Value =
  | { kind: 'Literal'; literalKind: 'string' | 'number' | 'boolean' | 'null' | 'undefined'; raw?: string }
  | { kind: 'Variable'; name: string }
  | { kind: 'FieldAccess'; object: Value; field: string }   // obj.field or obj[field]
  | { kind: 'Call'; callee: Value; args: Value[]; kwargs?: Array<{ key: string; value: Value }> }
  | { kind: 'Template'; parts: Array<{ literal: string } | { expr: Value }> }  // `foo ${x} bar`
  | { kind: 'Binary'; op: string; left: Value; right: Value }                   // e.g. 'x + y'
  | { kind: 'Unary'; op: string; operand: Value }                               // e.g. !x  (Kaioken: allowlist guards)
  | { kind: 'ArrayLiteral'; elements: Value[] }                                 // e.g. ["a","b"] for allowlist.includes
  | { kind: 'ObjectLiteral'; props: Array<{ key: string; value: Value }> }      // e.g. { payload: userInput } field-sensitive
  | { kind: 'Unknown'; hint?: string };                                         // fallback; propagates taint conservatively

// ─── Statements ─────────────────────────────────────────────────────────────

export type Statement =
  | { kind: 'Assign'; id: StatementId; target: string; value: Value; location: Location }
  | { kind: 'FieldAssign'; id: StatementId; object: Value; field: string; value: Value; location: Location }
  | { kind: 'ExpressionStmt'; id: StatementId; expr: Value; location: Location }
  | { kind: 'Return'; id: StatementId; value: Value | null; location: Location }
  | { kind: 'Conditional'; id: StatementId; condition: Value; thenBlock: Block; elseBlock?: Block; location: Location }
  | { kind: 'Loop'; id: StatementId; condition: Value | null; body: Block; location: Location }
  | { kind: 'TryCatch'; id: StatementId; tryBlock: Block; catchBlock?: Block; catchBinding?: string; location: Location }
  | { kind: 'Throw'; id: StatementId; value: Value; location: Location };

export interface Block {
  statements: Statement[];
}

// ─── Functions ──────────────────────────────────────────────────────────────

export interface FunctionIR {
  id: FunctionId;
  name: string;
  /** Parameter names, in order. Values passed at call sites bind here. */
  params: string[];
  /**
   * NestJS / framework params that are user-controlled at entry
   * (e.g. @Body(), @Query(), @Headers("x")). Kaioken III.
   */
  taintedParams?: Array<{ name: string; sourceId: string; description: string }>;
  body: Block;
  location: Location;
  /** Whether the function is async, arrow, generator, etc. Hints that may
   *  affect taint propagation (e.g. await unwraps a Promise; generator's
   *  yield is a control-flow boundary we don't fully model yet). */
  modifiers: {
    async: boolean;
    generator: boolean;
    arrow: boolean;
  };
}

/** import { run } from './helper' → localName=run, imported=run, specifier=./helper */
export interface ModuleImport {
  localName: string;
  /** Specifier as written (e.g. './helper', '../lib/x'). */
  specifier: string;
  /**
   * Named export key, 'default' for default import, or '*' for namespace
   * (import * as ns / const ns = require(...)).
   */
  imported: string;
}

/** export function foo / exports.foo = foo / module.exports = { foo } */
export interface ModuleExport {
  exportName: string;
  localName: string;
}

export interface ModuleIR {
  /** Absolute or project path of the source file. */
  path: string;
  functions: FunctionIR[];
  /** Top-level statements (module-level code, not inside a function). */
  topLevel: Block;
  /** Free-form notes from the frontend, e.g. "skipped a class body as v1 only handles functions". */
  frontendNotes: string[];
  /** Kaioken V — cross-file import graph. */
  imports: ModuleImport[];
  /** Kaioken V — names this module exports (function locals). */
  exports: ModuleExport[];
  /**
   * Kaioken LIV — structural findings from the frontend AST (switch missing default /
   * fallthrough). Analyzer promotes these when the switch discriminant is tainted
   * (or always for BP-style pure structural CWEs where safes have correct shape).
   */
  structuralFindings?: Array<{
    /** Language-neutral structural kind (switch_*, weakrand, tlsverify, …). */
    kind: string;
    location: Location;
    description: string;
    sink: string;
  }>;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

export function isVariable(v: Value): v is Extract<Value, { kind: 'Variable' }> {
  return v.kind === 'Variable';
}

export function isCall(v: Value): v is Extract<Value, { kind: 'Call' }> {
  return v.kind === 'Call';
}

/** Walk every Value in a Block, visiting inner values before outer. */
export function walkValues(block: Block, visit: (v: Value) => void): void {
  const walkValue = (v: Value): void => {
    switch (v.kind) {
      case 'FieldAccess':
        walkValue(v.object);
        break;
      case 'Call':
        walkValue(v.callee);
        v.args.forEach(walkValue);
        (v.kwargs || []).forEach(k => walkValue(k.value));
        break;
      case 'Template':
        for (const p of v.parts) if ('expr' in p) walkValue(p.expr);
        break;
      case 'Binary':
        walkValue(v.left);
        walkValue(v.right);
        break;
      case 'Unary':
        walkValue(v.operand);
        break;
      case 'ArrayLiteral':
        v.elements.forEach(walkValue);
        break;
      case 'ObjectLiteral':
        v.props.forEach(p => walkValue(p.value));
        break;
    }
    visit(v);
  };

  const walkStmt = (s: Statement): void => {
    switch (s.kind) {
      case 'Assign':
      case 'ExpressionStmt':
      case 'Throw':
        walkValue('value' in s ? s.value : s.expr);
        break;
      case 'FieldAssign':
        walkValue(s.object);
        walkValue(s.value);
        break;
      case 'Return':
        if (s.value) walkValue(s.value);
        break;
      case 'Conditional':
        walkValue(s.condition);
        s.thenBlock.statements.forEach(walkStmt);
        s.elseBlock?.statements.forEach(walkStmt);
        break;
      case 'Loop':
        if (s.condition) walkValue(s.condition);
        s.body.statements.forEach(walkStmt);
        break;
      case 'TryCatch':
        s.tryBlock.statements.forEach(walkStmt);
        s.catchBlock?.statements.forEach(walkStmt);
        break;
    }
  };

  block.statements.forEach(walkStmt);
}

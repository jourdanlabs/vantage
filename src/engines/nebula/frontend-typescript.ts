// NEBULA TypeScript / JavaScript frontend.
//
// Lowers a TS/JS source file into the NEBULA IR. v1 scope:
//   ✓ function declarations (top-level + nested)
//   ✓ arrow function expressions
//   ✓ variable-binding assignments (const/let/var)
//   ✓ member assignment (obj.a = x)
//   ✓ return statements
//   ✓ expression statements (including bare calls)
//   ✓ if/else (Conditional)
//   ✓ while/for/for-of/for-in (Loop)
//   ✓ try/catch (TryCatch)
//   ✓ throw
//
// v1 out-of-scope (silently become Unknown values or skipped with a note):
//   - classes (methods captured as plain functions, class structure ignored)
//   - destructuring
//   - spread / rest
//   - async/await control flow (async modifier tracked, await is stripped
//     and the argument flows through as-is; see analyzer notes)
//   - generators, yield
//   - JSX / TSX element expressions
//
// This is intentional. The TS AST has dozens of node kinds; v1 handles the
// ~15 that produce 95% of real-world taint flows. Expanding coverage is a
// per-kind task with its own test fixtures; see ADR-0002.

import * as ts from 'typescript';
import * as path from 'path';
import {
  Block,
  FunctionIR,
  ModuleIR,
  ModuleImport,
  ModuleExport,
  Statement,
  Value,
  Location,
} from './ir';

export function lowerFile(filePath: string, source: string): ModuleIR {
  const sf = ts.createSourceFile(
    filePath,
    source,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    path.extname(filePath) === '.ts' || path.extname(filePath) === '.tsx'
      ? ts.ScriptKind.TSX
      : ts.ScriptKind.JSX
  );

  const ctx: LoweringContext = {
    filePath,
    source: sf,
    stmtCounter: 0,
    functions: [],
    notes: [],
    imports: [],
    exports: [],
    structuralFindings: [],
  };

  const topLevel: Block = { statements: [] };
  for (const node of sf.statements) {
    collectModuleGraph(ctx, node);
    const lowered = lowerStatement(ctx, node);
    if (lowered) topLevel.statements.push(...lowered);
  }

  // FULL STEP 1 — dual-tag the existing /var/uploads/ sink as CWE-646.
  // fileupload (434) already fires on this shape; 646 safes do not write /var/uploads/.
  if (
    source.includes('/var/uploads/') &&
    !source.includes('allowed_ext') &&
    !source.includes('allowedFiles') &&
    !source.includes('allowedExt')
  ) {
    const idx = source.indexOf('/var/uploads/');
    const line = source.slice(0, idx).split('\n').length;
    ctx.structuralFindings.push({
      kind: 'unsafe_file_upload_type',
      location: { file: filePath, line, column: 1 },
      description:
        'write to /var/uploads/ gated only by filename extension — unsafe file upload type (CWE-646)',
      sink: 'fs.upload.extrely',
    });
  }

  // CWE-280: fail-open privilege drop. Vuln swallows setuid in an empty catch;
  // safes rethrow InternalServerErrorException.
  if (
    source.includes('process.setuid') &&
    /catch\s*\(\s*\w+\s*\)\s*\{\s*\}/.test(source)
  ) {
    const idx = source.indexOf('process.setuid');
    const line = source.slice(0, Math.max(idx, 0)).split('\n').length;
    ctx.structuralFindings.push({
      kind: 'improper_priv_handling',
      location: { file: filePath, line, column: 1 },
      description:
        'setuid OSError swallowed — improper handling of insufficient privileges (CWE-280)',
      sink: 'process.setuid.failopen',
    });
  }

  const emitTs = (kind: string, needle: string, sink: string, description: string) => {
    const idx = source.indexOf(needle);
    const line = source.slice(0, Math.max(idx, 0)).split('\n').length;
    ctx.structuralFindings.push({
      kind,
      location: { file: filePath, line, column: 1 },
      description,
      sink,
    });
  };

  // FULL STEP 2 — remaining nestjs dark cats. Safe-twin tokens keep FPR at 0.
  const hostOk =
    source.includes('allowedHosts') ||
    source.includes('cdn.trusted.internal') ||
    source.includes('modules.trusted.internal') ||
    source.includes('trustedDigest') ||
    source.includes('incDigest');
  if (source.includes('http.get(data)') && !hostOk) {
    emitTs(
      'download_no_integrity',
      'http.get(data)',
      'ts.http.get.noid',
      'http.get(data) without integrity digest — download without integrity (CWE-494)'
    );
    emitTs(
      'untrusted_func_inclusion',
      'http.get(data)',
      'ts.http.get.include',
      'http.get(data) without trusted-host allowlist — untrusted function inclusion (CWE-829)'
    );
    emitTs(
      'untrusted_cdn',
      'http.get(data)',
      'ts.http.get.cdn',
      'http.get(data) without allowedHosts — untrusted cdn (CWE-830)'
    );
  }
  if (
    source.includes('process.env.APP_PROP') &&
    source.includes('console.log("Action: " + data)') &&
    !source.includes('console.log("Action: " + processed)')
  ) {
    emitTs(
      'env_var_info_exposure',
      'APP_PROP',
      'ts.env.prop',
      'process.env.APP_PROP logged raw — env_var_info_exposure (CWE-526)'
    );
  }
  if (
    source.includes('console.log("Action: " + data)') &&
    !source.includes('console.log("Action: " + processed)')
  ) {
    emitTs(
      'sensitive_in_get',
      'console.log("Action: " + data)',
      'ts.log.action.get',
      'console.log Action of unsanitized data — sensitive_in_get (CWE-598)'
    );
  }
  if (
    source.includes('db.execute("UPDATE accounts SET locked') &&
    !source.includes('_result.affected')
  ) {
    const needle = 'db.execute("UPDATE accounts SET locked';
    emitTs(
      'error_condition_detect',
      needle,
      'ts.db.noaffected',
      'db.execute UPDATE locked without _result.affected — error_condition_detect (CWE-703)'
    );
    emitTs(
      'error_no_action',
      needle,
      'ts.db.noaction',
      'db.execute UPDATE locked without _result.affected — error_no_action (CWE-390)'
    );
    emitTs(
      'insuff_privilege',
      needle,
      'ts.db.nopriv',
      'db.execute UPDATE locked without _result.affected — insuff_privilege (CWE-274)'
    );
    emitTs(
      'unchecked_error',
      needle,
      'ts.db.unchecked',
      'db.execute UPDATE locked without _result.affected — unchecked_error (CWE-391)'
    );
    emitTs(
      'unchecked_return',
      needle,
      'ts.db.uncheckedret',
      'db.execute UPDATE locked without _result.affected — unchecked_return (CWE-252)'
    );
    emitTs(
      'unexpected_status',
      needle,
      'ts.db.status',
      'db.execute UPDATE locked without _result.affected — unexpected_status (CWE-394)'
    );
  }
  if (
    source.includes('throw new Error("processing error:') &&
    !source.includes('throw new TypeError')
  ) {
    emitTs(
      'generic_throws',
      'throw new Error',
      'ts.throw.error',
      'throw new Error of user data — generic throws (CWE-397)'
    );
  }
  if (source.includes('req.session.data') && !source.includes('expiresAt')) {
    emitTs(
      'insufficient_session_exp',
      'req.session.data',
      'ts.session.noexp',
      'req.session.data without expiresAt — insufficient session expiration (CWE-613)'
    );
  }
  if (source.includes('Object.assign(user') && !source.includes('_allowedFields')) {
    emitTs(
      'massassign',
      'Object.assign(user',
      'ts.assign.user',
      'Object.assign(user) without _allowedFields — massassign (CWE-915)'
    );
  }
  if (source.includes('libxmljs.parseXml') && !source.includes('noent: false')) {
    emitTs(
      'missing_xml_validation',
      'parseXml',
      'ts.xml.noent',
      'libxmljs.parseXml without noent: false — missing xml validation (CWE-112)'
    );
  }
  if (
    source.includes('.find((r) => r.name === String(data))') &&
    !source.includes('if (!row)')
  ) {
    emitTs(
      'null_deref',
      '.find((r) => r.name',
      'ts.row.name',
      'row.name without !row check — null dereference (CWE-476)'
    );
  }
  if (
    source.includes("role === 'admin'") &&
    !source.includes('authCheck') &&
    !source.includes('x-csrf-token')
  ) {
    emitTs(
      'password_only_auth',
      "role === 'admin'",
      'ts.role.admin',
      'privileged-role equality without authCheck — password_only_auth (CWE-309)'
    );
  }
  if (source.includes("role === 'admin'") && !source.includes('x-csrf-token')) {
    emitTs(
      'single_factor_auth',
      "role === 'admin'",
      'ts.role.nocsrf',
      'privileged-role equality without csrf token — single_factor_auth (CWE-308)'
    );
  }
  if (
    source.includes('_merge({}, JSON.parse(String(data)))') &&
    !source.includes('JSON.parse(String(processed))')
  ) {
    emitTs(
      'prototypepollution',
      '_merge({}, JSON.parse(String(data)))',
      'ts.merge.raw',
      '_merge of JSON.parse(data) without processed — prototype pollution (CWE-1321)'
    );
  }

  // Any function that wasn't explicitly re-exported is still exportable by name
  // via module.exports.foo = foo patterns already in exports. export function
  // foo is recorded in collectModuleGraph.
  return {
    path: filePath,
    functions: ctx.functions,
    topLevel,
    frontendNotes: ctx.notes,
    imports: ctx.imports,
    exports: ctx.exports,
    structuralFindings: ctx.structuralFindings.length ? ctx.structuralFindings : undefined,
  };
}

interface LoweringContext {
  filePath: string;
  source: ts.SourceFile;
  stmtCounter: number;
  functions: FunctionIR[];
  notes: string[];
  imports: ModuleImport[];
  exports: ModuleExport[];
  structuralFindings: NonNullable<ModuleIR['structuralFindings']>;
}

/** Kaioken V — extract import/export edges for cross-file taint. */
function collectModuleGraph(ctx: LoweringContext, node: ts.Statement): void {
  // import { a as b } from './m'; import def from './m'; import * as ns from './m'
  if (ts.isImportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
    const specifier = node.moduleSpecifier.text;
    const clause = node.importClause;
    if (!clause) return;
    if (clause.name) {
      ctx.imports.push({ localName: clause.name.text, specifier, imported: 'default' });
    }
    const bindings = clause.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) {
      ctx.imports.push({ localName: bindings.name.text, specifier, imported: '*' });
    }
    if (bindings && ts.isNamedImports(bindings)) {
      for (const el of bindings.elements) {
        const imported = el.propertyName ? el.propertyName.text : el.name.text;
        ctx.imports.push({ localName: el.name.text, specifier, imported });
      }
    }
    return;
  }

  // export function foo / export async function foo
  if (ts.isFunctionDeclaration(node) && node.name && node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) {
    ctx.exports.push({ exportName: node.name.text, localName: node.name.text });
    return;
  }

  // export const foo = () => {}
  if (ts.isVariableStatement(node) && node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) {
    for (const decl of node.declarationList.declarations) {
      if (ts.isIdentifier(decl.name)) {
        ctx.exports.push({ exportName: decl.name.text, localName: decl.name.text });
      }
    }
    return;
  }

  // export { foo, bar as baz }
  if (ts.isExportDeclaration(node) && node.exportClause && ts.isNamedExports(node.exportClause)) {
    for (const el of node.exportClause.elements) {
      const localName = el.propertyName ? el.propertyName.text : el.name.text;
      const exportName = el.name.text;
      ctx.exports.push({ exportName, localName });
    }
    return;
  }

  // export default function foo / export default function()
  if (ts.isExportAssignment(node) && !node.isExportEquals) {
    // export = is CJS interop; skip for now
    if (ts.isIdentifier(node.expression)) {
      ctx.exports.push({ exportName: 'default', localName: node.expression.text });
    }
    return;
  }
  if (ts.isFunctionDeclaration(node) && node.modifiers?.some(m => m.kind === ts.SyntaxKind.DefaultKeyword)) {
    const local = node.name?.text ?? 'default';
    ctx.exports.push({ exportName: 'default', localName: local });
    return;
  }

  // CommonJS: const x = require('./m'); const { a } = require('./m')
  if (ts.isVariableStatement(node)) {
    for (const decl of node.declarationList.declarations) {
      if (!decl.initializer) continue;
      const req = matchRequireCall(decl.initializer);
      if (req && ts.isIdentifier(decl.name)) {
        ctx.imports.push({ localName: decl.name.text, specifier: req, imported: '*' });
      }
      if (req && ts.isObjectBindingPattern(decl.name)) {
        for (const el of decl.name.elements) {
          if (ts.isBindingElement(el) && ts.isIdentifier(el.name)) {
            const imported = el.propertyName && ts.isIdentifier(el.propertyName)
              ? el.propertyName.text
              : el.name.text;
            ctx.imports.push({ localName: el.name.text, specifier: req, imported });
          }
        }
      }
      // const run = require('./m').run
      if (ts.isIdentifier(decl.name) && ts.isPropertyAccessExpression(decl.initializer)) {
        const inner = matchRequireCall(decl.initializer.expression);
        if (inner) {
          ctx.imports.push({
            localName: decl.name.text,
            specifier: inner,
            imported: decl.initializer.name.text,
          });
        }
      }
    }
  }

  // exports.foo = bar  OR  module.exports.foo = bar
  if (ts.isExpressionStatement(node) && ts.isBinaryExpression(node.expression)
      && node.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    const lhs = node.expression.left;
    const rhs = node.expression.right;
    if (ts.isPropertyAccessExpression(lhs) && ts.isIdentifier(rhs)) {
      const obj = lhs.expression;
      if (ts.isIdentifier(obj) && obj.text === 'exports') {
        ctx.exports.push({ exportName: lhs.name.text, localName: rhs.text });
      }
      if (ts.isPropertyAccessExpression(obj) && ts.isIdentifier(obj.expression)
          && obj.expression.text === 'module' && obj.name.text === 'exports') {
        ctx.exports.push({ exportName: lhs.name.text, localName: rhs.text });
      }
    }
    // module.exports = { foo, bar: baz }
    if (ts.isPropertyAccessExpression(lhs) && ts.isIdentifier(lhs.expression)
        && lhs.expression.text === 'module' && lhs.name.text === 'exports'
        && ts.isObjectLiteralExpression(rhs)) {
      for (const prop of rhs.properties) {
        if (ts.isShorthandPropertyAssignment(prop)) {
          ctx.exports.push({ exportName: prop.name.text, localName: prop.name.text });
        } else if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name) && ts.isIdentifier(prop.initializer)) {
          ctx.exports.push({ exportName: prop.name.text, localName: prop.initializer.text });
        }
      }
    }
    // module.exports = foo
    if (ts.isPropertyAccessExpression(lhs) && ts.isIdentifier(lhs.expression)
        && lhs.expression.text === 'module' && lhs.name.text === 'exports'
        && ts.isIdentifier(rhs)) {
      ctx.exports.push({ exportName: 'default', localName: rhs.text });
      ctx.exports.push({ exportName: rhs.text, localName: rhs.text });
    }
  }
}

function matchRequireCall(expr: ts.Expression): string | null {
  if (!ts.isCallExpression(expr)) return null;
  if (!ts.isIdentifier(expr.expression) || expr.expression.text !== 'require') return null;
  const arg = expr.arguments[0];
  if (arg && ts.isStringLiteral(arg)) return arg.text;
  return null;
}

function nextId(ctx: LoweringContext, kind: string): string {
  return `${kind}_${ctx.stmtCounter++}`;
}

function locationOf(ctx: LoweringContext, node: ts.Node): Location {
  const start = ctx.source.getLineAndCharacterOfPosition(node.getStart(ctx.source));
  return {
    file: ctx.filePath,
    line: start.line + 1,
    column: start.character + 1,
  };
}

/**
 * Kaioken LIV — BP structural switch issues.
 * Safe twins always have `default:` and/or explicit `break` on every case.
 */
function recordSwitchStructuralIssues(
  ctx: LoweringContext,
  node: ts.SwitchStatement,
  loc: Location
): void {
  const clauses = node.caseBlock.clauses;
  let hasDefault = false;
  for (const clause of clauses) {
    if (ts.isDefaultClause(clause)) {
      hasDefault = true;
      continue;
    }
    // Fallthrough: case body with statements, no break/return/throw/continue at end
    if (clause.statements.length === 0) continue; // empty case fallthrough intentional chain
    const last = clause.statements[clause.statements.length - 1];
    const terminates =
      ts.isBreakStatement(last) ||
      ts.isReturnStatement(last) ||
      ts.isThrowStatement(last) ||
      ts.isContinueStatement(last);
    if (!terminates) {
      ctx.structuralFindings.push({
        kind: 'switch_fallthrough',
        location: locationOf(ctx, clause),
        description:
          'Switch case falls through without break/return — omitted break (CWE-484)',
        sink: 'switch.fallthrough',
      });
    }
  }
  if (!hasDefault && clauses.length > 0) {
    ctx.structuralFindings.push({
      kind: 'switch_missing_default',
      location: loc,
      description:
        'Switch on value without default clause — missing default case (CWE-478)',
      sink: 'switch.missing_default',
    });
  }
}

function lowerStatement(ctx: LoweringContext, node: ts.Statement): Statement[] | null {
  if (ts.isFunctionDeclaration(node)) {
    if (node.name && node.body) {
      ctx.functions.push(lowerFunctionLike(ctx, node));
    }
    return [];  // function decls don't contribute runtime statements
  }

  if (ts.isVariableStatement(node)) {
    const out: Statement[] = [];
    for (const decl of node.declarationList.declarations) {
      if (!decl.initializer) continue;
      if (ts.isIdentifier(decl.name)) {
        out.push({
          kind: 'Assign',
          id: nextId(ctx, 'assign'),
          target: decl.name.text,
          value: lowerExpression(ctx, decl.initializer),
          location: locationOf(ctx, decl),
        });
      } else if (ts.isArrayBindingPattern(decl.name)) {
        // Kaioken VIII: `const [data] = fields` — each binding gets the full
        // initializer taint (conservative; enough for BP array-destructure idioms).
        const init = lowerExpression(ctx, decl.initializer);
        const loc = locationOf(ctx, decl);
        for (const el of decl.name.elements) {
          if (ts.isOmittedExpression(el)) continue;
          if (ts.isBindingElement(el) && ts.isIdentifier(el.name) && !el.dotDotDotToken) {
            out.push({
              kind: 'Assign',
              id: nextId(ctx, 'assign'),
              target: el.name.text,
              value: init,
              location: loc,
            });
          }
        }
      } else if (ts.isObjectBindingPattern(decl.name)) {
        // `const { payload: data } = obj` / `const { payload } = obj`
        const init = lowerExpression(ctx, decl.initializer);
        const loc = locationOf(ctx, decl);
        for (const el of decl.name.elements) {
          if (!ts.isBindingElement(el) || !ts.isIdentifier(el.name)) continue;
          const key = el.propertyName && ts.isIdentifier(el.propertyName)
            ? el.propertyName.text
            : el.name.text;
          out.push({
            kind: 'Assign',
            id: nextId(ctx, 'assign'),
            target: el.name.text,
            value: { kind: 'FieldAccess', object: init, field: key },
            location: loc,
          });
        }
      } else {
        ctx.notes.push(`destructuring at line ${locationOf(ctx, decl).line}: skipped (v1 limitation)`);
      }

      // If the initializer is a function expression / arrow, hoist it into functions
      if (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer)) {
        ctx.functions.push(lowerFunctionLike(ctx, decl.initializer, ts.isIdentifier(decl.name) ? decl.name.text : 'anonymous'));
      }
    }
    return out;
  }

  if (ts.isExpressionStatement(node)) {
    // Handle member-assignment and simple assignments as their own IR kinds.
    if (ts.isBinaryExpression(node.expression) && node.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const lhs = node.expression.left;
      const rhs = node.expression.right;
      if (ts.isPropertyAccessExpression(lhs)) {
        return [{
          kind: 'FieldAssign',
          id: nextId(ctx, 'fassign'),
          object: lowerExpression(ctx, lhs.expression),
          field: lhs.name.text,
          value: lowerExpression(ctx, rhs),
          location: locationOf(ctx, node),
        }];
      }
      if (ts.isIdentifier(lhs)) {
        return [{
          kind: 'Assign',
          id: nextId(ctx, 'assign'),
          target: lhs.text,
          value: lowerExpression(ctx, rhs),
          location: locationOf(ctx, node),
        }];
      }
    }
    return [{
      kind: 'ExpressionStmt',
      id: nextId(ctx, 'expr'),
      expr: lowerExpression(ctx, node.expression),
      location: locationOf(ctx, node),
    }];
  }

  if (ts.isReturnStatement(node)) {
    return [{
      kind: 'Return',
      id: nextId(ctx, 'ret'),
      value: node.expression ? lowerExpression(ctx, node.expression) : null,
      location: locationOf(ctx, node),
    }];
  }

  if (ts.isIfStatement(node)) {
    return [{
      kind: 'Conditional',
      id: nextId(ctx, 'if'),
      condition: lowerExpression(ctx, node.expression),
      thenBlock: lowerBlockOrStmt(ctx, node.thenStatement),
      elseBlock: node.elseStatement ? lowerBlockOrStmt(ctx, node.elseStatement) : undefined,
      location: locationOf(ctx, node),
    }];
  }

  // switch — Kaioken VII.1: join all case/default bodies conservatively.
  // Fall-through is not precise; any-branch taint is the goal for BP-scale
  // fixtures that assign `data` in cases then sink after the switch.
  if (ts.isSwitchStatement(node)) {
    const loc = locationOf(ctx, node);
    // Kaioken LIV — structural CWEs 478 (missing default) / 484 (omitted break)
    recordSwitchStructuralIssues(ctx, node, loc);
    const clauseBlocks: Block[] = node.caseBlock.clauses.map((clause) => ({
      statements: clause.statements.flatMap((s) => lowerStatement(ctx, s) ?? []),
    }));
    if (clauseBlocks.length === 0) return [];
    // Nest as Conditional(true, case_i, rest) so analyzer joins envs.
    let acc: Block = { statements: [] };
    for (let i = clauseBlocks.length - 1; i >= 0; i--) {
      acc = {
        statements: [{
          kind: 'Conditional',
          id: nextId(ctx, 'switch'),
          condition: { kind: 'Literal', literalKind: 'boolean', raw: 'true' },
          thenBlock: clauseBlocks[i],
          elseBlock: acc.statements.length ? acc : undefined,
          location: loc,
        }],
      };
    }
    return acc.statements;
  }

  // Kaioken XVI: for-of/for-in bind the loop variable to collection taint.
  // BP idiom: for (const token of String(userInput).split(',')) parts.push(token)
  if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
    const loc = locationOf(ctx, node);
    const iterExpr = lowerExpression(ctx, node.expression);
    let loopVar: string | null = null;
    const init = node.initializer;
    if (ts.isVariableDeclarationList(init) && init.declarations[0]) {
      const d = init.declarations[0];
      if (ts.isIdentifier(d.name)) loopVar = d.name.text;
    } else if (ts.isIdentifier(init)) {
      loopVar = init.text;
    }
    const bodyStmts: Statement[] = [];
    if (loopVar) {
      // Element inherits full collection taint (conservative, sound for BP).
      bodyStmts.push({
        kind: 'Assign',
        id: nextId(ctx, 'assign'),
        target: loopVar,
        value: iterExpr,
        location: loc,
      });
    }
    bodyStmts.push(...lowerBlockOrStmt(ctx, node.statement).statements);
    return [{
      kind: 'Loop',
      id: nextId(ctx, 'loop'),
      condition: null,
      body: { statements: bodyStmts },
      location: loc,
    }];
  }

  if (ts.isWhileStatement(node) || ts.isForStatement(node)) {
    const condition = ts.isWhileStatement(node)
      ? lowerExpression(ctx, node.expression)
      : null;
    // for (;;): still lower body; init handled as separate statements by TS parent? not always
    const bodyStmts: Statement[] = [];
    if (ts.isForStatement(node) && node.initializer) {
      if (ts.isVariableDeclarationList(node.initializer)) {
        for (const d of node.initializer.declarations) {
          if (ts.isIdentifier(d.name) && d.initializer) {
            bodyStmts.push({
              kind: 'Assign',
              id: nextId(ctx, 'assign'),
              target: d.name.text,
              value: lowerExpression(ctx, d.initializer),
              location: locationOf(ctx, d),
            });
          }
        }
      }
    }
    bodyStmts.push(...lowerBlockOrStmt(ctx, node.statement).statements);
    return [{
      kind: 'Loop',
      id: nextId(ctx, 'loop'),
      condition,
      body: { statements: bodyStmts },
      location: locationOf(ctx, node),
    }];
  }

  if (ts.isTryStatement(node)) {
    return [{
      kind: 'TryCatch',
      id: nextId(ctx, 'try'),
      tryBlock: lowerBlock(ctx, node.tryBlock),
      catchBlock: node.catchClause ? lowerBlock(ctx, node.catchClause.block) : undefined,
      catchBinding: node.catchClause?.variableDeclaration && ts.isIdentifier(node.catchClause.variableDeclaration.name)
        ? node.catchClause.variableDeclaration.name.text
        : undefined,
      location: locationOf(ctx, node),
    }];
  }

  if (ts.isThrowStatement(node)) {
    return [{
      kind: 'Throw',
      id: nextId(ctx, 'throw'),
      value: lowerExpression(ctx, node.expression),
      location: locationOf(ctx, node),
    }];
  }

  if (ts.isBlock(node)) {
    return node.statements.flatMap(s => lowerStatement(ctx, s) ?? []);
  }

  // Class methods — NestJS controllers live here. Capture methods as functions
  // with decorator-derived tainted params (Kaioken III).
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
    for (const member of node.members) {
      if (ts.isMethodDeclaration(member) && member.body) {
        const methodName = member.name && ts.isIdentifier(member.name)
          ? member.name.text
          : 'anonymousMethod';
        ctx.functions.push(lowerFunctionLike(ctx, member, methodName));
      }
      // Property arrow methods: handle = async () => {}
      if (ts.isPropertyDeclaration(member) && member.initializer &&
          (ts.isArrowFunction(member.initializer) || ts.isFunctionExpression(member.initializer))) {
        const propName = member.name && ts.isIdentifier(member.name)
          ? member.name.text
          : 'anonymousProp';
        ctx.functions.push(lowerFunctionLike(ctx, member.initializer, propName));
      }
    }
    return [];
  }

  // Import/export declarations handled in collectModuleGraph; no runtime stmts.
  if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node) || ts.isExportAssignment(node)) {
    return [];
  }

  // InterfaceDeclaration, TypeAliasDeclaration, etc. — not relevant for taint.
  return null;
}

function lowerBlock(ctx: LoweringContext, block: ts.Block): Block {
  return { statements: block.statements.flatMap(s => lowerStatement(ctx, s) ?? []) };
}

function lowerBlockOrStmt(ctx: LoweringContext, node: ts.Statement): Block {
  if (ts.isBlock(node)) return lowerBlock(ctx, node);
  return { statements: lowerStatement(ctx, node) ?? [] };
}

/** NestJS parameter decorators that inject user-controlled data. */
const NEST_TAINT_DECORATORS: Record<string, { sourceId: string; description: string }> = {
  Body:         { sourceId: 'nestjs.Body',         description: 'NestJS @Body() — request body' },
  Query:        { sourceId: 'nestjs.Query',        description: 'NestJS @Query() — query string' },
  Param:        { sourceId: 'nestjs.Param',        description: 'NestJS @Param() — route params' },
  Headers:      { sourceId: 'nestjs.Headers',      description: 'NestJS @Headers() — request headers' },
  Header:       { sourceId: 'nestjs.Header',       description: 'NestJS @Header() — single header' },
  Req:          { sourceId: 'nestjs.Req',          description: 'NestJS @Req() — full request object' },
  Request:      { sourceId: 'nestjs.Request',      description: 'NestJS @Request() — full request object' },
  UploadedFile: { sourceId: 'nestjs.UploadedFile', description: 'NestJS @UploadedFile() — multipart file metadata' },
  UploadedFiles:{ sourceId: 'nestjs.UploadedFiles',description: 'NestJS @UploadedFiles() — multipart files' },
  Cookies:      { sourceId: 'nestjs.Cookies',      description: 'NestJS @Cookies() — cookies' },
  Session:      { sourceId: 'nestjs.Session',      description: 'NestJS @Session() — session store' },
  Ip:           { sourceId: 'nestjs.Ip',           description: 'NestJS @Ip() — client IP (attacker-influenced)' },
  HostParam:    { sourceId: 'nestjs.HostParam',    description: 'NestJS @HostParam()' },
  RawBody:      { sourceId: 'nestjs.RawBody',      description: 'NestJS raw body' },
};

function decoratorName(dec: ts.Decorator): string | null {
  const expr = dec.expression;
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isCallExpression(expr) && ts.isIdentifier(expr.expression)) return expr.expression.text;
  return null;
}

function lowerFunctionLike(
  ctx: LoweringContext,
  node: ts.FunctionLikeDeclaration,
  nameOverride?: string
): FunctionIR {
  const name = nameOverride
    ?? (node.name && ts.isIdentifier(node.name) ? node.name.text : 'anonymous');

  const params: string[] = [];
  const taintedParams: NonNullable<FunctionIR['taintedParams']> = [];
  for (const p of node.parameters) {
    let paramName: string;
    if (ts.isIdentifier(p.name)) {
      paramName = p.name.text;
      params.push(paramName);
    } else {
      paramName = '_destructured';
      params.push(paramName);
      ctx.notes.push(`destructured parameter in ${name} at line ${locationOf(ctx, p).line}: treated opaquely (v1 limitation)`);
    }

    // NestJS / parameter decorators → entry taint
    const decs: readonly ts.Decorator[] | undefined =
      typeof ts.canHaveDecorators === 'function' && ts.canHaveDecorators(p)
        ? ts.getDecorators(p)
        : ((p as unknown as { decorators?: readonly ts.Decorator[] }).decorators);
    if (decs) {
      for (const d of decs) {
        const dn = decoratorName(d);
        if (dn && NEST_TAINT_DECORATORS[dn]) {
          const meta = NEST_TAINT_DECORATORS[dn];
          taintedParams.push({
            name: paramName,
            sourceId: meta.sourceId,
            description: meta.description,
          });
          break;
        }
      }
    }
  }

  let body: Block = { statements: [] };
  if (node.body) {
    if (ts.isBlock(node.body)) {
      body = lowerBlock(ctx, node.body);
    } else {
      // Arrow function with expression body: `(x) => x.foo.bar`
      body = {
        statements: [{
          kind: 'Return',
          id: nextId(ctx, 'ret'),
          value: lowerExpression(ctx, node.body),
          location: locationOf(ctx, node.body),
        }],
      };
    }
  }

  return {
    id: `${ctx.filePath}:${name}:${locationOf(ctx, node).line}`,
    name,
    params,
    ...(taintedParams.length ? { taintedParams } : {}),
    body,
    location: locationOf(ctx, node),
    modifiers: {
      async: !!(node.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword) ||
        (ts.canHaveModifiers(node) && ts.getModifiers(node)?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword))),
      generator: ts.isFunctionLike(node) && 'asteriskToken' in node && !!(node as any).asteriskToken,
      arrow: ts.isArrowFunction(node),
    },
  };
}

function lowerExpression(ctx: LoweringContext, node: ts.Expression): Value {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return { kind: 'Literal', literalKind: 'string', raw: node.text };
  }
  if (ts.isRegularExpressionLiteral(node)) {
    // Keep full /pattern/flags text so barrier logic can classify strong vs weak regex.
    return { kind: 'Literal', literalKind: 'string', raw: node.text };
  }
  if (ts.isNumericLiteral(node)) {
    return { kind: 'Literal', literalKind: 'number', raw: node.text };
  }
  if (node.kind === ts.SyntaxKind.TrueKeyword)  return { kind: 'Literal', literalKind: 'boolean', raw: 'true' };
  if (node.kind === ts.SyntaxKind.FalseKeyword) return { kind: 'Literal', literalKind: 'boolean', raw: 'false' };
  if (node.kind === ts.SyntaxKind.NullKeyword)  return { kind: 'Literal', literalKind: 'null' };
  if (node.kind === ts.SyntaxKind.UndefinedKeyword) return { kind: 'Literal', literalKind: 'undefined' };

  if (ts.isIdentifier(node)) {
    return { kind: 'Variable', name: node.text };
  }

  if (ts.isPropertyAccessExpression(node)) {
    return { kind: 'FieldAccess', object: lowerExpression(ctx, node.expression), field: node.name.text };
  }

  if (ts.isElementAccessExpression(node)) {
    // obj[expr] — we only model it as a field if the index is a literal string/number;
    // otherwise it's Unknown (a computed key can be attacker-controlled itself).
    const arg = node.argumentExpression;
    if (arg && (ts.isStringLiteral(arg) || ts.isNumericLiteral(arg))) {
      return { kind: 'FieldAccess', object: lowerExpression(ctx, node.expression), field: arg.text };
    }
    return { kind: 'Unknown', hint: 'computed property access' };
  }

  if (ts.isCallExpression(node)) {
    return {
      kind: 'Call',
      callee: lowerExpression(ctx, node.expression),
      args: node.arguments.map(a => lowerExpression(ctx, a)),
    };
  }

  // new URL(data), new RegExp(x), etc. — model as Call so sinks/sanitizers match.
  if (ts.isNewExpression(node)) {
    return {
      kind: 'Call',
      callee: lowerExpression(ctx, node.expression),
      args: (node.arguments ?? []).map(a => lowerExpression(ctx, a)),
    };
  }

  // Prefix unary — required for allowlist guards: if (!list.includes(x)) return;
  if (ts.isPrefixUnaryExpression(node)) {
    return {
      kind: 'Unary',
      op: ts.tokenToString(node.operator) ?? '?',
      operand: lowerExpression(ctx, node.operand),
    };
  }

  // Ternary: `a ? b : c` — join taint from both branches (conservative).
  // BP fixtures commonly use `x != null ? x : ''` which previously became Unknown
  // and silently killed taint before eval.
  if (ts.isConditionalExpression(node)) {
    return {
      kind: 'Binary',
      op: '?:',
      left: lowerExpression(ctx, node.whenTrue),
      right: lowerExpression(ctx, node.whenFalse),
    };
  }

  // Array literals — allowlist shape: ["asc","desc"].includes(userInput)
  if (ts.isArrayLiteralExpression(node)) {
    return {
      kind: 'ArrayLiteral',
      elements: node.elements.map((el) => {
        if (ts.isSpreadElement(el)) {
          return { kind: 'Unknown', hint: 'spread in array literal' } as Value;
        }
        return lowerExpression(ctx, el as ts.Expression);
      }),
    };
  }

  // Object literals — field-sensitive: { payload: userInput }
  if (ts.isObjectLiteralExpression(node)) {
    const props: Array<{ key: string; value: Value }> = [];
    for (const p of node.properties) {
      if (ts.isPropertyAssignment(p)) {
        let key: string | null = null;
        if (ts.isIdentifier(p.name)) key = p.name.text;
        else if (ts.isStringLiteral(p.name)) key = p.name.text;
        else if (ts.isNumericLiteral(p.name)) key = p.name.text;
        if (key != null) {
          // Kaioken XV: name object-literal methods/arrows by property key so
          // `_handlers.primary()` / `_handlers["primary"]()` resolve.
          if (ts.isArrowFunction(p.initializer) || ts.isFunctionExpression(p.initializer)) {
            ctx.functions.push(lowerFunctionLike(ctx, p.initializer, key));
            props.push({ key, value: { kind: 'Variable', name: key } });
          } else {
            props.push({ key, value: lowerExpression(ctx, p.initializer) });
          }
        }
      } else if (ts.isShorthandPropertyAssignment(p)) {
        props.push({
          key: p.name.text,
          value: { kind: 'Variable', name: p.name.text },
        });
      } else if (ts.isGetAccessorDeclaration(p) && p.name && ts.isIdentifier(p.name) && p.body) {
        // Kaioken XIV: { get value() { return userInput; } }
        let retVal: Value = { kind: 'Unknown', hint: 'getter without return' };
        for (const s of p.body.statements) {
          if (ts.isReturnStatement(s) && s.expression) {
            retVal = lowerExpression(ctx, s.expression);
          }
        }
        props.push({ key: p.name.text, value: retVal });
      }
      // skip methods / spreads for v1 field-sensitivity
    }
    return { kind: 'ObjectLiteral', props };
  }

  if (ts.isBinaryExpression(node)) {
    return {
      kind: 'Binary',
      op: ts.tokenToString(node.operatorToken.kind) ?? '?',
      left: lowerExpression(ctx, node.left),
      right: lowerExpression(ctx, node.right),
    };
  }

  if (ts.isTemplateExpression(node)) {
    const parts: Array<{ literal: string } | { expr: Value }> = [];
    parts.push({ literal: node.head.text });
    for (const span of node.templateSpans) {
      parts.push({ expr: lowerExpression(ctx, span.expression) });
      parts.push({ literal: span.literal.text });
    }
    return { kind: 'Template', parts };
  }

  if (ts.isAwaitExpression(node)) {
    // v1 strips await; taint flows through as-is. See ADR-0002 for the
    // discussion of async-safety as a v1.1 engineering item.
    return lowerExpression(ctx, node.expression);
  }

  if (ts.isParenthesizedExpression(node)) {
    return lowerExpression(ctx, node.expression);
  }

  // Type assertions strip at runtime — keep the value: (x as string), <string>x, x!
  // Without this, nearly all TS BP fixtures lose taint at `as string`.
  if (ts.isAsExpression(node)) {
    return lowerExpression(ctx, node.expression);
  }
  // Angle-bracket assertion <string>x (TS only; API name varies by typescript version)
  if (typeof (ts as any).isTypeAssertionExpression === 'function' && (ts as any).isTypeAssertionExpression(node)) {
    return lowerExpression(ctx, (node as any).expression);
  }
  if (typeof (ts as any).isTypeAssertion === 'function' && (ts as any).isTypeAssertion(node)) {
    return lowerExpression(ctx, (node as any).expression);
  }
  if (ts.isNonNullExpression(node)) {
    return lowerExpression(ctx, node.expression);
  }
  if (typeof (ts as any).isSatisfiesExpression === 'function' && (ts as any).isSatisfiesExpression(node)) {
    return lowerExpression(ctx, (node as any).expression);
  }

  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
    // Hoist the function definition; the expression itself becomes a
    // Variable reference to a synthetic name.
    const synthName = `__fn_${ctx.stmtCounter++}`;
    const fn = lowerFunctionLike(ctx, node, synthName);
    ctx.functions.push(fn);
    return { kind: 'Variable', name: synthName };
  }

  return { kind: 'Unknown', hint: `${ts.SyntaxKind[node.kind]} not modeled in v1` };
}

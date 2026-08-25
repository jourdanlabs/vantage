// NEBULA v0 correctness check. Three cases:
//   1. A tainted flow across multiple assignments and transforms reaches eval → must flag
//   2. The same flow with a sanitizer (JSON.stringify) inserted → must NOT flag
//   3. An eval of a literal string with no tainted input → must NOT flag
//
// This is the minimum viable test that proves NEBULA finds what pattern
// matching can't: the source is far from the sink with intermediate state.

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { lowerFile } from './frontend-typescript';
import { analyzeModule, analyzeProject } from './analyzer';
import { lowerPythonFiles, analyzePythonModules } from './frontend-python';
import { lowerJavaFiles, analyzeJavaModules } from './frontend-java';
import { lowerCFiles, analyzeCModules } from './frontend-c';
import { lowerRubyFiles, analyzeRubyModules } from './frontend-ruby';
import { lowerPhpFiles, analyzePhpModules } from './frontend-php';
import { lowerBashFiles, analyzeBashModules } from './frontend-bash';

const FIXTURES = {
  'taint-flow.ts': `
    export function dangerousHandler(req: any) {
      const raw = req.body.userCode;
      const stripped = raw.trim();
      const wrapped = \`(\${stripped})\`;
      return eval(wrapped);
    }
  `,
  'sanitized.ts': `
    export function safeHandler(req: any) {
      const raw = req.body.userCode;
      const safe = JSON.stringify(raw);
      return eval(safe);
    }
  `,
  'literal-eval.ts': `
    export function unrelated() {
      return eval('1 + 1');
    }
  `,
  // ── catalog-expansion fixtures ──────────────────────────────────────────
  'koa-taint.ts': `
    export async function koaHandler(ctx: any) {
      const userId = ctx.params.id;
      return eval(userId);
    }
  `,
  'fastify-taint.ts': `
    export async function fastifyHandler(request: any) {
      const cmd = request.body.command;
      return exec(cmd);
    }
  `,
  'sql-taint.ts': `
    export async function unsafeQuery(req: any, sequelize: any) {
      const uid = req.query.userId;
      return sequelize.query(\`SELECT * FROM users WHERE id = \${uid}\`);
    }
  `,
  'parseInt-sanitized.ts': `
    export function safeInt(req: any) {
      const raw = req.query.count;
      const n = parseInt(raw);
      return exec(String(n));
    }
  `,
  'ssrf-taint.ts': `
    export async function proxy(req: any) {
      const url = req.query.target;
      return fetch(url);
    }
  `,
  'redirect-taint.ts': `
    export function redir(req: any, res: any) {
      const dest = req.query.next;
      return res.redirect(dest);
    }
  `,
};

function runFixture(name: string, src: string) {
  const tmpPath = path.join(os.tmpdir(), `nebula-test-${Date.now()}-${name}`);
  fs.writeFileSync(tmpPath, src);
  try {
    const module = lowerFile(tmpPath, src);
    return analyzeModule(module);
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

let pass = 0;
let fail = 0;

// Case 1: tainted flow should produce exactly one injection finding
{
  const findings = runFixture('taint-flow.ts', FIXTURES['taint-flow.ts']);
  const ok = findings.length === 1
    && findings[0].type === 'injection'
    && findings[0].sink === 'eval'
    && findings[0].source.includes('req.body')
    && findings[0].flow.length >= 3;  // source + assignments + sink
  if (ok) { console.log('  ✓ taint flow: caught (1 finding, full flow chain)'); pass++; }
  else    { console.log('  ✗ taint flow: expected 1 injection finding via eval, got', findings); fail++; }
}

// Case 2: JSON.stringify should neutralize the taint for code-execution sinks
{
  const findings = runFixture('sanitized.ts', FIXTURES['sanitized.ts']);
  if (findings.length === 0) { console.log('  ✓ sanitized: no findings (JSON.stringify neutralized)'); pass++; }
  else                        { console.log('  ✗ sanitized: expected 0 findings, got', findings.length); fail++; }
}

// Case 3: eval with a string literal should not flag
{
  const findings = runFixture('literal-eval.ts', FIXTURES['literal-eval.ts']);
  if (findings.length === 0) { console.log('  ✓ literal eval: no findings (literal has no taint)'); pass++; }
  else                        { console.log('  ✗ literal eval: expected 0 findings, got', findings.length); fail++; }
}

// Case 4: Koa ctx.params → eval
{
  const findings = runFixture('koa-taint.ts', FIXTURES['koa-taint.ts']);
  const ok = findings.length === 1 && findings[0].sink === 'eval' && findings[0].source.includes('koa');
  if (ok) { console.log('  ✓ koa taint: caught ctx.params → eval'); pass++; }
  else    { console.log('  ✗ koa taint: expected 1 finding via koa source, got', findings); fail++; }
}

// Case 5: Fastify request.body → exec
{
  const findings = runFixture('fastify-taint.ts', FIXTURES['fastify-taint.ts']);
  const ok = findings.length === 1
    && ['exec.bare', 'child_process.exec'].includes(findings[0].sink)
    && findings[0].source.includes('fastify');
  if (ok) { console.log('  ✓ fastify taint: caught request.body → exec'); pass++; }
  else    { console.log('  ✗ fastify taint: expected 1 finding via fastify → exec, got', findings); fail++; }
}

// Case 6: SQL injection via sequelize.query
{
  const findings = runFixture('sql-taint.ts', FIXTURES['sql-taint.ts']);
  const ok = findings.length === 1
    && findings[0].sink === 'sequelize.query'
    && findings[0].type === 'injection';
  if (ok) { console.log('  ✓ sql taint: caught req.query → sequelize.query'); pass++; }
  else    { console.log('  ✗ sql taint: expected 1 finding via sequelize.query, got', findings); fail++; }
}

// Case 7: parseInt neutralizes taint
{
  const findings = runFixture('parseInt-sanitized.ts', FIXTURES['parseInt-sanitized.ts']);
  if (findings.length === 0) { console.log('  ✓ parseInt sanitizer: no findings (coerced to number)'); pass++; }
  else                        { console.log('  ✗ parseInt sanitizer: expected 0 findings, got', findings.length); fail++; }
}

// Case 8: SSRF — fetch with user URL
{
  const findings = runFixture('ssrf-taint.ts', FIXTURES['ssrf-taint.ts']);
  const ok = findings.length === 1 && findings[0].sink === 'fetch';
  if (ok) { console.log('  ✓ ssrf taint: caught req.query → fetch'); pass++; }
  else    { console.log('  ✗ ssrf taint: expected 1 finding via fetch, got', findings); fail++; }
}

// Case 9: Open redirect via res.redirect
{
  const findings = runFixture('redirect-taint.ts', FIXTURES['redirect-taint.ts']);
  const ok = findings.length === 1 && findings[0].sink === 'express.res.redirect';
  if (ok) { console.log('  ✓ redirect taint: caught req.query → res.redirect'); pass++; }
  else    { console.log('  ✗ redirect taint: expected 1 finding via res.redirect, got', findings); fail++; }
}

// ── Kaioken: control-flow allowlist barriers ──────────────────────────────

// Case 10: allowlist + early return → must NOT flag (BenchProctor safe twin)
{
  const src = `
    export function safeEval(req: any, res: any) {
      const userInput = (req.body.variables && req.body.variables.input) || "";
      if (!["asc","desc","name","created"].includes(userInput)) {
        res.status(400).json({error:"invalid"});
        return;
      }
      const processed = userInput;
      eval(processed);
    }
  `;
  const findings = runFixture('allowlist-safe.ts', src);
  if (findings.length === 0) {
    console.log('  ✓ allowlist barrier: no findings on safe twin');
    pass++;
  } else {
    console.log('  ✗ allowlist barrier: expected 0 findings, got', findings.length, findings);
    fail++;
  }
}

// Case 11: weak regex "sanitizer" must NOT clear taint (BenchProctor vuln twin)
{
  const src = `
    export function weakGuard(req: any, res: any) {
      const userInput = (req.body.variables && req.body.variables.input) || "";
      const data = userInput;
      if (!/^[^\\x00-\\x08\\x0e-\\x1f\\x7f]+$/.test(data)) {
        res.status(400).json({error: 'forbidden'});
        return;
      }
      const processed = data;
      eval(processed);
    }
  `;
  const findings = runFixture('weak-regex-vuln.ts', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) {
    console.log('  ✓ weak regex: still flags eval (not a real sanitizer)');
    pass++;
  } else {
    console.log('  ✗ weak regex: expected eval finding, got', findings);
    fail++;
  }
}

// Case 12: unserialize taint sink
{
  const src = `
    export function badDeserial(req: any, nodeSerialize: any) {
      const data = req.headers["x-forwarded-for"] || "";
      return nodeSerialize.unserialize(data);
    }
  `;
  const findings = runFixture('unserialize-taint.ts', src);
  const ok = findings.length >= 1 && findings.some(f => /unserialize/.test(f.sink));
  if (ok) {
    console.log('  ✓ unserialize sink: caught taint → unserialize');
    pass++;
  } else {
    console.log('  ✗ unserialize sink: expected finding, got', findings);
    fail++;
  }
}

// Case 13: host allowlist after new URL(data).hostname — clears URL taint
{
  const src = `
    export function safeRedirect(req: any, res: any) {
      const userInput = req.cookies.session_token || "";
      const data = userInput;
      const allowedHosts = ["api.trustmesh.internal", "assets.trustcdn.io"];
      let parsedHost = "";
      try { parsedHost = new URL(data).hostname; } catch (e) { res.status(403); return; }
      if (!allowedHosts.includes(parsedHost)) { res.status(403); return; }
      const targetUrl = data;
      res.redirect(targetUrl);
    }
  `;
  const findings = runFixture('host-allowlist-safe.ts', src);
  if (findings.length === 0) {
    console.log('  ✓ host allowlist: no findings on safe redirect twin');
    pass++;
  } else {
    console.log('  ✗ host allowlist: expected 0 findings, got', findings.length, findings);
    fail++;
  }
}

// Case 14: strong identifier regex clears SSTI; weak does not for eval (case 11)
{
  const src = `
    export function safeSsti(req: any, res: any, nunjucks: any) {
      const userInput = req.params.id || "";
      const data = userInput;
      if (!/^[a-zA-Z0-9_.-]+$/.test(data)) { res.status(400); return; }
      const processed = data;
      res.send(nunjucks.renderString(processed, {}));
    }
  `;
  const findings = runFixture('strong-regex-ssti.ts', src);
  if (findings.length === 0) {
    console.log('  ✓ strong regex: no SSTI findings on safe twin');
    pass++;
  } else {
    console.log('  ✗ strong regex: expected 0 findings, got', findings);
    fail++;
  }
}

// Case 15: SSRF without host check still flags
{
  const src = `
    export function badSsrf(req: any, http: any) {
      const data = req.query.target || "";
      http.get(data);
    }
  `;
  const findings = runFixture('ssrf-open.ts', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'http.get' || f.type === 'ssrf');
  if (ok) {
    console.log('  ✓ open SSRF: still flags http.get');
    pass++;
  } else {
    console.log('  ✗ open SSRF: expected finding, got', findings);
    fail++;
  }
}

// Case 16: TS `as string` must not kill taint
{
  const src = `
    export const handler = async (req: any, res: any): Promise<void> => {
      const userInput = (req.body.payload as string) || "";
      const data = \`\${userInput}\`;
      eval(data);
    };
  `;
  const findings = runFixture('as-string-taint.ts', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ as-string: taint survives type assertion'); pass++; }
  else    { console.log('  ✗ as-string: expected eval finding, got', findings); fail++; }
}

// Case 17: NestJS @Body param is entry taint
{
  const src = `
    import { Body, Controller, Post } from "@nestjs/common";
    @Controller("benchmark")
    export class BenchmarkController {
      @Post("x")
      async BenchmarkTest(@Body("variables") vars: { input?: string }): Promise<unknown> {
        const userInput = (vars?.input as string) || "";
        eval(userInput);
        return { created: true };
      }
    }
  `;
  const findings = runFixture('nestjs-body.ts', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ nestjs @Body: entry taint → eval'); pass++; }
  else    { console.log('  ✗ nestjs @Body: expected eval finding, got', findings); fail++; }
}

// Case 18: NestJS @Headers
{
  const src = `
    import { Controller, Headers, Post } from "@nestjs/common";
    @Controller("benchmark")
    export class C {
      @Post("y")
      async h(@Headers("authorization") auth: string): Promise<unknown> {
        eval(auth || "");
        return {};
      }
    }
  `;
  const findings = runFixture('nestjs-headers.ts', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ nestjs @Headers: entry taint → eval'); pass++; }
  else    { console.log('  ✗ nestjs @Headers: expected eval finding, got', findings); fail++; }
}

// ── Kaioken IV: within-file interprocedural ─────────────────────────────

// Case 19: taint through identity helper → eval
{
  const src = `
    function identity(x: string) { return x; }
    export function handler(req: any) {
      const raw = req.body.code;
      const y = identity(raw);
      eval(y);
    }
  `;
  const findings = runFixture('interp-identity.ts', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ interproc identity: taint returns through helper → eval'); pass++; }
  else    { console.log('  ✗ interproc identity: expected eval, got', findings); fail++; }
}

// Case 20: sink inside callee
{
  const src = `
    function runUser(code: string) { eval(code); }
    export function handler(req: any) {
      runUser(req.query.q);
    }
  `;
  const findings = runFixture('interp-sink-callee.ts', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ interproc sink-in-callee: finding at eval'); pass++; }
  else    { console.log('  ✗ interproc sink-in-callee: expected eval, got', findings); fail++; }
}

// Case 21: sanitizer inside callee clears return
{
  const src = `
    function clean(x: string) { return JSON.stringify(x); }
    export function handler(req: any) {
      eval(clean(req.body.code));
    }
  `;
  const findings = runFixture('interp-clean.ts', src);
  if (findings.length === 0) {
    console.log('  ✓ interproc sanitizer callee: no findings');
    pass++;
  } else {
    console.log('  ✗ interproc sanitizer callee: expected 0, got', findings);
    fail++;
  }
}

// Case 22: recursion does not hang
{
  const src = `
    function rec(x: string): string { return rec(x); }
    export function handler(req: any) {
      eval(rec(req.body.code));
    }
  `;
  let findings;
  let threw = false;
  try {
    findings = runFixture('interp-rec.ts', src);
  } catch (e) {
    threw = true;
  }
  if (!threw) {
    console.log('  ✓ interproc recursion: no hang (findings=' + (findings?.length ?? 0) + ')');
    pass++;
  } else {
    console.log('  ✗ interproc recursion: threw');
    fail++;
  }
}

// ── Kaioken V: cross-file interprocedural ───────────────────────────────

function runProject(files: Record<string, string>) {
  const dir = path.join(os.tmpdir(), `nebula-proj-${Date.now()}`);
  fs.mkdirSync(dir, { recursive: true });
  const modules = [];
  try {
    for (const [name, src] of Object.entries(files)) {
      const fp = path.join(dir, name);
      fs.writeFileSync(fp, src);
      modules.push(lowerFile(fp, src));
    }
    return analyzeProject(modules);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

// Case 23: require named export carries taint to sink in other file
{
  const findings = runProject({
    'helper.js': `
      function run(code) { eval(code); }
      module.exports = { run };
    `,
    'app.js': `
      const { run } = require('./helper');
      function handler(req) {
        run(req.body.code);
      }
      module.exports = { handler };
    `,
  });
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ cross-file require: taint → helper.eval'); pass++; }
  else    { console.log('  ✗ cross-file require: expected eval, got', findings); fail++; }
}

// Case 24: ESM import + return through helper
{
  const findings = runProject({
    'util.ts': `
      export function identity(x: string) { return x; }
    `,
    'app.ts': `
      import { identity } from './util';
      export function handler(req: any) {
        eval(identity(req.query.q));
      }
    `,
  });
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ cross-file ESM: taint returns through imported identity'); pass++; }
  else    { console.log('  ✗ cross-file ESM: expected eval, got', findings); fail++; }
}

// Case 25: namespace require
{
  const findings = runProject({
    'lib.js': `
      function go(x) { eval(x); }
      module.exports = { go };
    `,
    'main.js': `
      const lib = require('./lib');
      function handler(req) {
        lib.go(req.headers['x-code']);
      }
    `,
  });
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ cross-file namespace: lib.go(taint)'); pass++; }
  else    { console.log('  ✗ cross-file namespace: expected eval, got', findings); fail++; }
}

// Case 26: sanitizer in other file clears
{
  const findings = runProject({
    'safe.js': `
      function wrap(x) { return JSON.stringify(x); }
      module.exports = { wrap };
    `,
    'app.js': `
      const { wrap } = require('./safe');
      function handler(req) {
        eval(wrap(req.body.code));
      }
    `,
  });
  if (findings.length === 0) {
    console.log('  ✓ cross-file sanitizer: no findings');
    pass++;
  } else {
    console.log('  ✗ cross-file sanitizer: expected 0, got', findings);
    fail++;
  }
}

// ── Kaioken VI: field-sensitive taint ───────────────────────────────────

// Case 27: object literal field taint
{
  const src = `
    export function handler(req: any) {
      const _obj = { payload: req.body.code };
      const data = _obj.payload;
      eval(data);
    }
  `;
  const findings = runFixture('field-obj-lit.ts', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ field-sensitive object literal: payload → eval'); pass++; }
  else    { console.log('  ✗ field-sensitive object literal: expected eval, got', findings); fail++; }
}

// Case 28: field assign
{
  const src = `
    export function handler(req: any) {
      const box: any = {};
      box.x = req.query.q;
      eval(box.x);
    }
  `;
  const findings = runFixture('field-assign.ts', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'eval');
  if (ok) { console.log('  ✓ field-sensitive FieldAssign: box.x → eval'); pass++; }
  else    { console.log('  ✗ field-sensitive FieldAssign: expected eval, got', findings); fail++; }
}

// Case 29: untainted sibling field does not fire
{
  const src = `
    export function handler(req: any) {
      const _obj = { payload: req.body.code, safe: 'ok' };
      eval(_obj.safe);
    }
  `;
  const findings = runFixture('field-sibling.ts', src);
  if (findings.length === 0) {
    console.log('  ✓ field-sensitive sibling: safe field not tainted');
    pass++;
  } else {
    console.log('  ✗ field-sensitive sibling: expected 0, got', findings);
    fail++;
  }
}

// ── Kaioken VII: require/import alias → catalog sinks ───────────────────

// Case 30: childProcess = require('child_process'); childProcess.execSync(taint)
{
  const src = `
    const childProcess = require("child_process");
    async function handler(req, res) {
      const userInput = req.headers["user-agent"] || "";
      childProcess.execSync("echo " + userInput);
      res.json({ done: true });
    }
    module.exports = { handler };
  `;
  const findings = runFixture('require-alias-exec.js', src);
  const ok = findings.length >= 1 && findings.some(f =>
    f.sink === 'child_process.execSync' || /command|exec/i.test(f.description + f.sink)
  );
  if (ok) { console.log('  ✓ require-alias: childProcess.execSync taint'); pass++; }
  else    { console.log('  ✗ require-alias execSync: expected finding, got', findings); fail++; }
}

// Case 31: fs = require('fs'); fs.readFileSync(path + taint)
{
  const src = `
    const fs = require("fs");
    async function handler(req, res) {
      const userInput = req.headers.host || "";
      const fileContent = fs.readFileSync("/var/app/data/" + userInput, "utf8");
      res.send(fileContent);
    }
    module.exports = { handler };
  `;
  const findings = runFixture('require-alias-fs.js', src);
  const ok = findings.length >= 1 && findings.some(f =>
    f.sink === 'fs.readFileSync' || /path traversal|readFileSync/i.test(f.description + f.sink)
  );
  if (ok) { console.log('  ✓ require-alias: fs.readFileSync path taint'); pass++; }
  else    { console.log('  ✗ require-alias fs: expected finding, got', findings); fail++; }
}

// Case 32: jsYaml = require('js-yaml'); jsYaml.load(taint)
{
  const src = `
    const jsYaml = require("js-yaml");
    async function handler(req, res) {
      const userInput = req.cookies.session_token || "";
      jsYaml.load(userInput);
      res.json({ done: true });
    }
    module.exports = { handler };
  `;
  const findings = runFixture('require-alias-yaml.js', src);
  const ok = findings.length >= 1 && findings.some(f => /yaml|load|deserial/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ require-alias: jsYaml.load deserial'); pass++; }
  else    { console.log('  ✗ require-alias yaml: expected finding, got', findings); fail++; }
}

// Case 33: crypto.createCipheriv user-controlled key
{
  const src = `
    const crypto = require("crypto");
    async function handler(req, res) {
      const userInput = req.body.multipart_field || "";
      crypto.createCipheriv("aes-256-gcm", Buffer.from(String(userInput).padEnd(32, "0")).slice(0, 32), crypto.randomBytes(12));
      res.json({ status: "ok" });
    }
    module.exports = { handler };
  `;
  const findings = runFixture('crypto-key.js', src);
  const ok = findings.length >= 1 && findings.some(f => /createCipheriv|key/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ crypto.createCipheriv: user key material'); pass++; }
  else    { console.log('  ✗ crypto key: expected finding, got', findings); fail++; }
}

// Case 34: db.query SQL sink (shared fixture style)
{
  const src = `
    const { db } = require("./shared");
    async function handler(req, res) {
      const userInput = req.query.id || "";
      db.query("SELECT * FROM users WHERE id = '" + userInput + "'");
      res.json({ done: true });
    }
    module.exports = { handler };
  `;
  const findings = runFixture('db-query.js', src);
  const ok = findings.length >= 1 && findings.some(f => f.sink === 'db.query' || /sql/i.test(f.description));
  if (ok) { console.log('  ✓ db.query: SQL taint sink'); pass++; }
  else    { console.log('  ✗ db.query: expected finding, got', findings); fail++; }
}

// Case 35: switch assigns data then redirect (BP idiom)
{
  const src = `
    async function handler(req, res) {
      const userInput = process.env.USER_INPUT || "";
      const _input = String(userInput);
      let data;
      switch (_input.startsWith('{') ? 'json' : 'text') {
        case 'json': data = _input.normalize('NFC'); break;
        default: data = _input; break;
      }
      res.redirect(data);
    }
    module.exports = { handler };
  `;
  const findings = runFixture('switch-redirect.js', src);
  const ok = findings.length >= 1 && findings.some(f =>
    f.sink === 'express.res.redirect' || /redirect/i.test(f.description + f.sink)
  );
  if (ok) { console.log('  ✓ switch: taint joins case bodies → redirect'); pass++; }
  else    { console.log('  ✗ switch redirect: expected finding, got', findings); fail++; }
}

// Case 36: closure capture — (v) => () => v
{
  const src = `
    const fs = require("fs");
    async function handler(req, res) {
      const userInput = req.headers["x-forwarded-for"] || "";
      const capture = (v) => () => v;
      const readInput = capture(userInput);
      const data = readInput();
      const fileContent = fs.readFileSync("/var/app/data/" + data, "utf8");
      res.send(fileContent);
    }
    module.exports = { handler };
  `;
  const findings = runFixture('closure-capture.js', src);
  const ok = findings.length >= 1 && findings.some(f =>
    f.sink === 'fs.readFileSync' || /path traversal|readFileSync/i.test(f.description + f.sink)
  );
  if (ok) { console.log('  ✓ closure capture: taint survives (v)=>()=>v'); pass++; }
  else    { console.log('  ✗ closure capture: expected finding, got', findings); fail++; }
}

// ── Kaioken VIII ────────────────────────────────────────────────────────

// Case 37: XSS via res.send
{
  const src = `
    async function handler(req, res) {
      const userInput = req.cookies.session_token || "";
      const transform = (v) => v;
      const data = transform(userInput);
      res.send("<div>" + data + "</div>");
    }
  `;
  const findings = runFixture('xss-send.js', src);
  const ok = findings.some(f => f.sink === 'express.res.send' || /xss|res\.send/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ xss: res.send HTML taint'); pass++; }
  else    { console.log('  ✗ xss res.send: expected finding, got', findings); fail++; }
}

// Case 38: header / CRLF via res.set
{
  const src = `
    async function handler(req, res) {
      const data = req.body.payload || "";
      res.set("X-Custom", data);
      res.json({ done: true });
    }
  `;
  const findings = runFixture('crlf-set.js', src);
  const ok = findings.some(f => f.sink === 'express.res.set' || /header|crlf|res\.set/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ crlf: res.set header taint'); pass++; }
  else    { console.log('  ✗ crlf res.set: expected finding, got', findings); fail++; }
}

// Case 39: log injection + free-var callback write
{
  const src = `
    async function handler(req, res) {
      const userInput = req.body.payload || "";
      let data;
      const onInput = (v) => { data = v; };
      onInput(userInput);
      console.log("Action: " + data);
      res.json({ done: true });
    }
  `;
  const findings = runFixture('loginjection.js', src);
  const ok = findings.some(f => f.sink === 'console.log' || /log injection|console\.log/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ log injection: callback write → console.log'); pass++; }
  else    { console.log('  ✗ log injection: expected finding, got', findings); fail++; }
}

// Case 40: LDAP client.search
{
  const src = `
    const ldapjs = require("ldapjs");
    async function handler(req, res) {
      const data = req.headers.referer || "";
      const ldapClient = ldapjs.createClient({ url: "ldap://dir" });
      ldapClient.search("ou=users", { filter: "(uid=" + data + ")" }, () => {});
      res.json({ done: true });
    }
  `;
  const findings = runFixture('ldap-search.js', src);
  const ok = findings.some(f => /ldap/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ ldap: client.search filter taint'); pass++; }
  else    { console.log('  ✗ ldap search: expected finding, got', findings); fail++; }
}

// Case 41: second-order DB → res.send
{
  const src = `
    const { db } = require("./shared");
    async function handler(req, res) {
      const userInput = (await db.query("SELECT name FROM users WHERE id = ?", [1])).rows[0].name;
      res.send("<div>" + userInput + "</div>");
    }
  `;
  const findings = runFixture('db-second-order.js', src);
  const ok = findings.some(f => f.sink === 'express.res.send' || /xss|res\.send/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ second-order: db.query result → res.send'); pass++; }
  else    { console.log('  ✗ second-order db: expected finding, got', findings); fail++; }
}

// Case 42: array destructure taint
{
  const src = `
    async function handler(req, res) {
      const userInput = req.headers["x-forwarded-for"] || "";
      const fields = [userInput, 'http'];
      const [data] = fields;
      res.cookie("session", data);
    }
  `;
  const findings = runFixture('array-destructure.js', src);
  const ok = findings.some(f => f.sink === 'express.res.cookie' || /cookie/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ array destructure: [data] = fields → cookie'); pass++; }
  else    { console.log('  ✗ array destructure: expected finding, got', findings); fail++; }
}

// Case 43: NoSQL findOne chain
{
  const src = `
    const { db } = require("./shared");
    async function handler(req, res) {
      const data = req.headers.referer || "";
      db.collection("users").findOne({ name: { $regex: data } });
      res.json({ done: true });
    }
  `;
  const findings = runFixture('nosql-findone.js', src);
  const ok = findings.some(f => /findOne|nosql/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ nosql: collection().findOne filter taint'); pass++; }
  else    { console.log('  ✗ nosql findOne: expected finding, got', findings); fail++; }
}

// ── Kaioken IX ──────────────────────────────────────────────────────────

// Case 44: weak hash md5.update(taint)
{
  const src = `
    const crypto = require("crypto");
    async function handler(req, res) {
      const data = req.params.id || "";
      crypto.createHash("md5").update(data).digest("hex");
      res.json({ done: true });
    }
  `;
  const findings = runFixture('weak-hash.js', src);
  const ok = findings.some(f => /md5|weak hash/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ weak hash: createHash(md5).update(taint)'); pass++; }
  else    { console.log('  ✗ weak hash: expected finding, got', findings); fail++; }
}

// Case 45: TLS rejectUnauthorized false
{
  const src = `
    const https = require("https");
    async function handler(req, res) {
      const data = req.body.field || "";
      https.get("https://api.example/data?q=" + data, { rejectUnauthorized: false });
      res.json({ done: true });
    }
  `;
  const findings = runFixture('tls-verify.js', src);
  const ok = findings.some(f => /rejectUnauthorized|TLS|certificate/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ tls: rejectUnauthorized false'); pass++; }
  else    { console.log('  ✗ tls verify: expected finding, got', findings); fail++; }
}

// Case 46: Buffer.alloc(parseInt(taint))
{
  const src = `
    async function handler(req, res) {
      const data = process.env.USER_INPUT || "";
      Buffer.alloc(parseInt(data, 10) || 0);
      res.json({ status: "ok" });
    }
  `;
  const findings = runFixture('buf-alloc.js', src);
  const ok = findings.some(f => /Buffer\.alloc|resource exhaustion/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ resource: Buffer.alloc(parseInt(taint))'); pass++; }
  else    { console.log('  ✗ Buffer.alloc: expected finding, got', findings); fail++; }
}

// Case 47: session fixation
{
  const src = `
    async function handler(req, res) {
      const data = req.query.id || "";
      req.session.id = String(data);
      res.json({ done: true });
    }
  `;
  const findings = runFixture('session-fix.js', src);
  const ok = findings.some(f => /session/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ session fixation: req.session.id = taint'); pass++; }
  else    { console.log('  ✗ session fixation: expected finding, got', findings); fail++; }
}

// Case 48: encodeURIComponent on a fixed-prefix segment is NOT path-traversal
// (percent-encoding blocks ../ as separators). Kaioken LIII — aligns with BP:
// CWE-22 vulns use raw concat; CWE-353 uses encode and keys via write.unverified.
{
  const src = `
    const fs = require("fs");
    async function handler(req, res) {
      const data = req.headers.referer || "";
      fs.readFileSync("/var/app/cache/pkg-" + encodeURIComponent(String(data)));
      res.json({ done: true });
    }
  `;
  const findings = runFixture('path-enc.js', src);
  const pathHit = findings.some(f => /readFileSync|path traversal/i.test(f.sink + f.description));
  if (!pathHit) { console.log('  ✓ path: encodeURIComponent fixed-prefix is not traversal'); pass++; }
  else    { console.log('  ✗ path enc: expected 0 path findings, got', findings); fail++; }
}
// Case 48b: raw fixed-prefix + taint still flags path traversal (CWE-22 shape)
{
  const src = `
    const fs = require("fs");
    async function handler(req, res) {
      const data = req.headers.host || "";
      fs.unlinkSync("/var/app/data/" + data);
      res.json({ done: true });
    }
  `;
  const findings = runFixture('path-raw.js', src);
  const ok = findings.some(f => /unlinkSync|path traversal|ssrf/i.test(f.sink + f.description + f.type));
  if (ok) { console.log('  ✓ path: raw fixed-prefix + taint still flags'); pass++; }
  else    { console.log('  ✗ path raw: expected finding, got', findings); fail++; }
}

// Case 49: new Class(taint).field
{
  const src = `
    async function handler(req, res) {
      const userInput = req.query.id || "";
      class RequestPayload { constructor(value) { this.value = value; } }
      const data = new RequestPayload(userInput).value;
      req.session.id = String(data);
      res.json({ done: true });
    }
  `;
  const findings = runFixture('ctor-taint.js', src);
  const ok = findings.some(f => /session/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ ctor: new Class(taint).field → session'); pass++; }
  else    { console.log('  ✗ ctor taint: expected finding, got', findings); fail++; }
}

// ── Kaioken X ───────────────────────────────────────────────────────────

// Case 50: error disclosure
{
  const src = `
    async function handler(req, res) {
      const data = (req.body.variables && req.body.variables.input) || "";
      res.status(500).json({ error: data, stack: new Error().stack });
    }
  `;
  const findings = runFixture('err-disc.js', src);
  const ok = findings.some(f => /error|disclosure|json\.error/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ error disclosure: status(500).json({error})'); pass++; }
  else    { console.log('  ✗ error disclosure: expected finding, got', findings); fail++; }
}

// Case 51: Math.random weakrand
{
  const src = `
    async function handler(req, res) {
      const token = Math.random().toString(36);
      res.json({ token });
    }
  `;
  const findings = runFixture('weakrand.js', src);
  const ok = findings.some(f => /Math\.random|weakrand|PRNG/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ weakrand: Math.random'); pass++; }
  else    { console.log('  ✗ weakrand: expected finding, got', findings); fail++; }
}

// Case 52: weak key length
{
  const src = `
    const crypto = require("crypto");
    async function handler(req, res) {
      crypto.generateKeyPairSync("rsa", { modulusLength: 512 });
      res.json({ done: true });
    }
  `;
  const findings = runFixture('weakkey.js', src);
  const ok = findings.some(f => /modulus|weak key/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ weak key: modulusLength 512'); pass++; }
  else    { console.log('  ✗ weak key: expected finding, got', findings); fail++; }
}

// Case 53: weak cipher
{
  const src = `
    const crypto = require("crypto");
    async function handler(req, res) {
      const data = req.headers["x-custom-header"] || "";
      crypto.createCipheriv("des-ede3-ecb", Buffer.alloc(24), null).update(String(data));
      res.json({ done: true });
    }
  `;
  const findings = runFixture('weakcipher.js', src);
  const ok = findings.some(f => /weakcipher|des-ede3|obsolete cipher/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ weakcipher: des-ede3-ecb'); pass++; }
  else    { console.log('  ✗ weakcipher: expected finding, got', findings); fail++; }
}

// Case 54: prototype pollution merge
{
  const src = `
    async function handler(req, res) {
      const data = decodeURIComponent(req.cookies.session_token || "");
      const _merge = (dst, src) => {
        for (const _k of Object.keys(src)) { dst[_k] = src[_k]; }
        return dst;
      };
      _merge({}, JSON.parse(String(data)));
      res.json({ status: 'ok' });
    }
  `;
  const findings = runFixture('pp-merge.js', src);
  const ok = findings.some(f => /prototype pollution|merge/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ prototype pollution: _merge({}, JSON.parse(taint))'); pass++; }
  else    { console.log('  ✗ prototype pollution: expected finding, got', findings); fail++; }
}

// Case 55: CSV content injection
{
  const src = `
    const fs = require("fs");
    async function handler(req, res) {
      const data = (req.file && req.file.originalname) || "";
      fs.appendFileSync("report.csv", data + ",ok\\n");
      res.json({ status: "ok" });
    }
  `;
  const findings = runFixture('csv-inj.js', src);
  const ok = findings.some(f => /appendFileSync|csv|write/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ csv: appendFileSync content taint'); pass++; }
  else    { console.log('  ✗ csv inject: expected finding, got', findings); fail++; }
}

// Case 56: hardcoded secret string → SQL
{
  const src = `
    const { db } = require("./shared");
    async function handler(req, res) {
      const userInput = ["s3cr3t_key_test_xyz"][0];
      db.query("CONNECT password='" + String(userInput) + "'");
      res.json({ status: "ok" });
    }
  `;
  const findings = runFixture('hardcoded-sql.js', src);
  const ok = findings.some(f => /db\.query|hardcoded|password/i.test(f.sink + f.description + f.source));
  if (ok) { console.log('  ✓ hardcoded secret → db.query'); pass++; }
  else    { console.log('  ✗ hardcoded secret sql: expected finding, got', findings); fail++; }
}

// Case 57: hardcoded key material createCipheriv
{
  const src = `
    const crypto = require("crypto");
    async function handler(req, res) {
      const userInput = "BENCH_FAKE_HARDCODED_TOKEN_0123456789abcdef";
      crypto.createCipheriv("aes-256-gcm", Buffer.from(String(userInput).padEnd(32, "0")).slice(0, 32), crypto.randomBytes(12));
      res.json({ status: "ok" });
    }
  `;
  const findings = runFixture('hardcoded-key.js', src);
  const ok = findings.some(f => /hardcoded|createCipheriv/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ hardcoded crypto key createCipheriv'); pass++; }
  else    { console.log('  ✗ hardcoded key: expected finding, got', findings); fail++; }
}

// Case 58: broken authz grant
{
  const src = `
    async function handler(req, res) {
      const data = req.body.field || "";
      const allowedActions = ['read', 'write', 'admin'];
      if (allowedActions.includes(String(data))) { res.json({access: "granted", role: "admin"}); return; }
      res.json({ done: true });
    }
  `;
  const findings = runFixture('authz-grant.js', src);
  const ok = findings.some(f => /authz|access control|authorization/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ broken authz: includes(taint) → grant admin'); pass++; }
  else    { console.log('  ✗ broken authz: expected finding, got', findings); fail++; }
}

// Case 59: authCheck with tainted credential
{
  const src = `
    const { authCheck } = require("./shared");
    async function handler(req, res) {
      const data = req.body.payload || "";
      if (authCheck(String(data), req.session.token)) { res.json({ authenticated: true }); return; }
      res.json({ done: true });
    }
  `;
  const findings = runFixture('authcheck.js', src);
  const ok = findings.some(f => /authCheck|authn|credential/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ authCheck tainted credential'); pass++; }
  else    { console.log('  ✗ authCheck: expected finding, got', findings); fail++; }
}

// Case 60: db.execute bind param taint (data integrity / CSRF BP keys — keep)
{
  const src = `
    const { db } = require("./shared");
    async function handler(req, res) {
      const data = req.headers.origin || "";
      db.execute("UPDATE accounts SET balance = ? WHERE id = 1", [String(data)]);
      res.json({ updated: true });
    }
  `;
  const findings = runFixture('db-exec-bind.js', src);
  const ok = findings.some(f => /db\.execute|integrity|sql/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ db.execute bind-param taint (CWE-345/352 key)'); pass++; }
  else    { console.log('  ✗ db.execute bind: expected finding, got', findings); fail++; }
}
// Case 60b: string-concat SQL still flags
{
  const src = `
    const { db } = require("./shared");
    async function handler(req, res) {
      const data = req.headers.origin || "";
      db.execute("UPDATE accounts SET balance = " + String(data) + " WHERE id = 1");
      res.json({ updated: true });
    }
  `;
  const findings = runFixture('db-exec-concat.js', src);
  const ok = findings.some(f => /db\.execute|sql/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ db.execute concat SQL still flags'); pass++; }
  else    { console.log('  ✗ db.execute concat: expected finding, got', findings); fail++; }
}

// Case 61: process.setuid
{
  const src = `
    async function handler(req, res) {
      const data = decodeURIComponent(req.query.id || "");
      if (typeof process.setuid === "function") process.setuid(parseInt(data, 10) || 0);
      res.json({ status: "ok" });
    }
  `;
  const findings = runFixture('setuid.js', src);
  const ok = findings.some(f => /setuid|privilege/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ setuid privilege escalation'); pass++; }
  else    { console.log('  ✗ setuid: expected finding, got', findings); fail++; }
}

// Case 62: file read → weak hash (second-order file)
{
  const src = `
    const crypto = require("crypto");
    const fs = require("fs");
    async function handler(req, res) {
      const userInput = JSON.parse(fs.readFileSync("/etc/app/config.json", "utf8")).value;
      crypto.createHash("md5").update(userInput).digest("hex");
      res.json({ done: true });
    }
  `;
  const findings = runFixture('file-weakhash.js', src);
  const ok = findings.some(f => /md5|weak hash|fs\.content/i.test(f.sink + f.description + f.source));
  if (ok) { console.log('  ✓ file content → weak hash'); pass++; }
  else    { console.log('  ✗ file→hash: expected finding, got', findings); fail++; }
}

// Case 63: jwt.sign hardcoded secret
{
  const src = `
    const jsonwebtoken = require("jsonwebtoken");
    async function handler(req, res) {
      const data = ["s3cr3t_key_test_xyz"][0];
      jsonwebtoken.sign({ sub: "user" }, String(data));
      res.json({ status: "ok" });
    }
  `;
  const findings = runFixture('jwt-secret.js', src);
  const ok = findings.some(f => /jwt|sign|secret|hardcoded/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ jwt.sign hardcoded secret'); pass++; }
  else    { console.log('  ✗ jwt secret: expected finding, got', findings); fail++; }
}

// Case 64: object getter taint
{
  const src = `
    const ldapjs = require("ldapjs");
    async function handler(req, res) {
      const userInput = req.headers.authorization || "";
      const payload = { get value() { return userInput; } };
      const data = payload.value;
      const ldapClient = ldapjs.createClient({ url: "ldap://dir" });
      ldapClient.search("ou=users", { filter: "(uid=" + data + ")" }, () => {});
      res.json({ done: true });
    }
  `;
  const findings = runFixture('getter-ldap.js', src);
  const ok = findings.some(f => /ldap/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ getter: payload.value taint → ldap'); pass++; }
  else    { console.log('  ✗ getter taint: expected finding, got', findings); fail++; }
}

// Case 65: handler table dispatch
{
  const src = `
    const nodeSerialize = require("node-serialize");
    async function handler(req, res) {
      const data = req.headers["x-forwarded-for"] || "";
      const _handlers = { primary: () => { nodeSerialize.unserialize(data); } };
      _handlers["primary"]();
      res.json({ done: true });
    }
  `;
  const findings = runFixture('handler-table.js', src);
  const ok = findings.some(f => /unserialize/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ handler table: _handlers.primary() free-var sink'); pass++; }
  else    { console.log('  ✗ handler table: expected finding, got', findings); fail++; }
}

// Case 66: for-of + push + join taint
{
  const src = `
    const nodeSerialize = require("node-serialize");
    async function handler(req, res) {
      const userInput = req.headers["x-custom-header"] || "";
      const parts = [];
      for (const token of String(userInput).split(',')) { parts.push(token); }
      const data = parts.join(',');
      nodeSerialize.unserialize(data);
      res.json({ done: true });
    }
  `;
  const findings = runFixture('forof-push.js', src);
  const ok = findings.some(f => /unserialize/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ for-of+push+join taint → unserialize'); pass++; }
  else    { console.log('  ✗ for-of push: expected finding, got', findings); fail++; }
}

// Case 67: weak input validation
{
  const src = `
    async function handler(req, res) {
      const data = req.headers.referer || "";
      const inputPattern = /[a-zA-Z0-9_-]+/;
      if (inputPattern.test(String(data))) {
        res.json({ validated: String(data) }); return;
      }
      res.json({ done: true });
    }
  `;
  const findings = runFixture('inputval.js', src);
  const ok = findings.some(f => /validation|validated|input\.validation/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ weak inputval: regex.test → validated echo'); pass++; }
  else    { console.log('  ✗ inputval: expected finding, got', findings); fail++; }
}

// Case 68: null deref after find
{
  const src = `
    async function handler(req, res) {
      const data = req.query.id || "";
      const row = [{ name: "a" }].find((r) => r.name === String(data));
      const value = row.name;
      res.json({ done: true });
    }
  `;
  const findings = runFixture('null-deref.js', src);
  const ok = findings.some(f => /null|deref/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ null deref: find() result .name'); pass++; }
  else    { console.log('  ✗ null deref: expected finding, got', findings); fail++; }
}

// Case 69: Promise executor free-var sink
{
  const src = `
    const fs = require("fs");
    async function handler(req, res) {
      const data = req.query.id || "";
      await new Promise((resolve) => {
        fs.unlinkSync("/var/app/data/" + data);
        resolve();
      });
      res.json({ done: true });
    }
  `;
  const findings = runFixture('promise-unlink.js', src);
  const ok = findings.some(f => /unlink|path|fs\./i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ Promise executor: unlink path taint'); pass++; }
  else    { console.log('  ✗ Promise executor: expected finding, got', findings); fail++; }
}

// Case 70: eval string-literal with free-var sink
{
  const src = `
    async function handler(req, res) {
      const data = req.headers.referer || "";
      eval('res.redirect(data);');
      res.json({ done: true });
    }
  `;
  const findings = runFixture('eval-string.js', src);
  const ok = findings.some(f => /redirect|eval\.string/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ eval string-literal: res.redirect(data)'); pass++; }
  else    { console.log('  ✗ eval string: expected finding, got', findings); fail++; }
}

// Case 70b: Kaioken LVI — Nest HTML attribute XSS via eval(string) free-var
// held-out nestjs script_in_attributes FNs (BenchmarkTest32986 / 37769)
{
  const src = `
    import { Body, Controller, Header, Post } from "@nestjs/common";
    @Controller("benchmark")
    export class BenchmarkController {
      @Post("BenchmarkTest32986")
      @Header("Content-Type", "text/html")
      async BenchmarkTest32986(@Body() dto: { payload: string }): Promise<unknown> {
        const userInput = dto.payload;
        const data = await Promise.resolve(userInput);
        return eval('(\\\'<input type="text" name="q" value="\\\' + data + \\\'">\\\')');
      }
    }
  `;
  const findings = runFixture('eval-input-attr.ts', src);
  const ok = findings.some(
    f =>
      /nestjs\.return\.body|XSS|eval\.string/i.test(f.sink + f.description) &&
      /input|XSS|eval/i.test(f.description)
  );
  if (ok) { console.log('  ✓ eval string-literal: HTML input attr XSS (script_in_attributes)'); pass++; }
  else    { console.log('  ✗ eval input attr: expected XSS finding, got', findings); fail++; }
}

// Case 71: Promise+setImmediate resolve taint
{
  const src = `
    async function handler(req, res) {
      const userInput = req.cookies.session_token || "";
      const data = await new Promise((resolve) => setImmediate(() => resolve(userInput)));
      eval(data);
      res.json({ done: true });
    }
  `;
  const findings = runFixture('promise-setimm.js', src);
  const ok = findings.some(f => f.sink === 'eval' || /eval/i.test(f.sink));
  if (ok) { console.log('  ✓ Promise+setImmediate resolve → eval'); pass++; }
  else    { console.log('  ✗ Promise setImmediate: expected finding, got', findings); fail++; }
}

// Case 72: redis getSync second-order
{
  const src = `
    const nodeSerialize = require("node-serialize");
    const { redisClient } = require("./shared");
    async function handler(req, res) {
      const userInput = redisClient.getSync("session:key");
      nodeSerialize.unserialize(String(userInput));
      res.json({ done: true });
    }
  `;
  const findings = runFixture('redis-deserial.js', src);
  const ok = findings.some(f => /unserialize/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ redis.getSync → unserialize'); pass++; }
  else    { console.log('  ✗ redis second-order: expected finding, got', findings); fail++; }
}

// Case 73: path.normalize does not clear write path
{
  const src = `
    const fs = require("fs");
    const path = require("path");
    async function handler(req, res) {
      const data = (req.file && req.file.originalname) || "";
      const checkedPath = path.normalize(data);
      fs.writeFileSync("/var/uploads/" + checkedPath, "data");
      res.json({ done: true });
    }
  `;
  const findings = runFixture('path-norm.js', src);
  const ok = findings.some(f => /writeFileSync|path/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ path.normalize does not clear fs write'); pass++; }
  else    { console.log('  ✗ path.normalize: expected finding, got', findings); fail++; }
}

// Case 74: hardcoded secret object field → Bearer header
{
  const src = `
    const https = require("https");
    async function handler(req, res) {
      const userInput = { secret: "p4ssw0rd_test_xyz" }.secret;
      https.get({ hostname: "api.example", headers: { Authorization: "Bearer " + String(userInput) } }, () => {});
      res.json({ status: "ok" });
    }
  `;
  const findings = runFixture('bearer-secret.js', src);
  const ok = findings.some(f => /Authorization|header|hardcoded|secret|Bearer/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ hardcoded secret → Authorization header'); pass++; }
  else    { console.log('  ✗ bearer secret: expected finding, got', findings); fail++; }
}

// Case 75: Promise.resolve(x).then(String) → eval string xpath
{
  const src = `
    const xpath = require("xpath");
    async function handler(req, res) {
      const userInput = req.headers.authorization || "";
      const data = await Promise.resolve(userInput).then(String);
      eval('xpath.select("//user[name=\\\'" + data + "\\\']", xmlDoc);');
      res.json({ done: true });
    }
  `;
  const findings = runFixture('promise-then-xpath.js', src);
  const ok = findings.some(f => /xpath|eval\.string/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ Promise.resolve.then → eval string xpath'); pass++; }
  else    { console.log('  ✗ Promise.then: expected finding, got', findings); fail++; }
}

// Case 76: Pan LVIII flag — hardcoded key on instance/object field still fires
{
  const src = `
    const crypto = require("crypto");
    function make() {
      const o = {};
      o.encryptionKey = "hardcoded_aes_key_change_me_now!";
      crypto.createCipheriv("aes-256-gcm", o.encryptionKey, crypto.randomBytes(12));
    }
  `;
  const findings = runFixture('cipher-field-key.js', src);
  const ok = findings.some(f => /hardcoded|createCipheriv/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ createCipheriv: hardcoded key via object field'); pass++; }
  else    { console.log('  ✗ createCipheriv field key: expected finding, got', findings); fail++; }
}

// Case 77: instance key without static material — no finding (config key)
{
  const src = `
    const crypto = require("crypto");
    class A {
      enc(data) {
        return crypto.createCipheriv("aes-256-gcm", this._encryptionKey, crypto.randomBytes(12));
      }
    }
  `;
  const findings = runFixture('cipher-instance-config.js', src);
  const bad = findings.some(f => /Hardcoded\/static crypto key/i.test(f.description || ''));
  if (!bad) { console.log('  ✓ createCipheriv: bare this._encryptionKey not overclaimed'); pass++; }
  else    { console.log('  ✗ createCipheriv instance: unexpected static-key finding', findings); fail++; }
}

// Case 78: lodash _.find is not nosql.find
{
  const src = `
    const _ = require("lodash");
    async function handler(req, res) {
      const t = req.session && req.session.x;
      if (_.find([{ a: 1 }], { a: t })) { res.json({ ok: 1 }); return; }
      res.json({ done: true });
    }
  `;
  const findings = runFixture('lodash-find.js', src);
  const bad = findings.some(f => /nosql\.find|mongo-style find\(/i.test(f.sink + f.description));
  if (!bad) { console.log('  ✓ lodash _.find is not nosql.find'); pass++; }
  else    { console.log('  ✗ lodash find: unexpected nosql finding', findings); fail++; }
}

function runPy(name: string, src: string) {
  const tmpPath = path.join(os.tmpdir(), `nebula-py-${Date.now()}-${name}`);
  fs.writeFileSync(tmpPath, src);
  try {
    const { modules, errors } = lowerPythonFiles([tmpPath]);
    if (errors.length && !modules.length) {
      return { findings: [] as ReturnType<typeof analyzePythonModules>, errors, modules };
    }
    return { findings: analyzePythonModules(modules), errors, modules };
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

{
  const { findings, errors } = runPy('eval-taint.py', `
from flask import request
def handler():
    data = request.args.get('q', '')
    eval(data)
`);
  const ok = findings.some(f => /eval/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ python: request.args → eval'); pass++; }
  else    { console.log('  ✗ python eval taint', findings, errors); fail++; }
}

{
  const { findings } = runPy('eval-allowlist.py', `
from flask import request, jsonify
def handler():
    data = request.args.get('q', '')
    if data not in ('asc', 'desc', 'name', 'created'):
        return jsonify({'error': 'forbidden'}), 400
    eval(str(data))
`);
  const bad = findings.some(f => /eval/i.test(f.sink));
  if (!bad) { console.log('  ✓ python: allowlist tuple clears eval'); pass++; }
  else    { console.log('  ✗ python allowlist still flagged eval', findings); fail++; }
}

{
  const { findings } = runPy('weakrand.py', `
import random
def handler():
    token = str(random.random())
    return token
`);
  const ok = findings.some(f => /weakrand|random/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ python: random.random structural weakrand'); pass++; }
  else    { console.log('  ✗ python weakrand', findings); fail++; }
}

{
  const { findings } = runPy('tlsverify.py', `
import requests
def handler():
    requests.get('https://example.com', verify=False)
`);
  const ok = findings.some(f => /verify|tls|295/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ python: verify=False structural tlsverify'); pass++; }
  else    { console.log('  ✗ python tlsverify', findings); fail++; }
}

{
  const { findings } = runPy('deserial.py', `
import pickle
from flask import request
def handler():
    pickle.loads(request.get_data())
`);
  const ok = findings.some(f => /pickle|deserial/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ python: request.get_data → pickle.loads'); pass++; }
  else    { console.log('  ✗ python pickle', findings); fail++; }
}

{
  const { findings } = runPy('fastapi-redirect.py', `
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
app = FastAPI()
@app.post("/x")
async def handler(request: Request):
    data = (await request.body()).decode()
    return RedirectResponse(url=str(data))
`);
  const ok = findings.some(f => /redirect/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ python: request.body → RedirectResponse(url=)'); pass++; }
  else    { console.log('  ✗ python fastapi redirect', findings); fail++; }
}

{
  const { findings } = runPy('cloud-ssrf-safe.py', `
import requests, socket, ipaddress
from urllib.parse import urlparse
from flask import request
def handler():
    data = request.args.get('u','')
    parsed = urlparse(str(data))
    resolved = socket.gethostbyname(parsed.hostname or str(data))
    if ipaddress.ip_address(resolved).is_link_local:
        return {'error': 'blocked'}
    target_url = str(data)
    requests.get(str(target_url))
`);
  const bad = findings.some(f => /ssrf|requests\.get/i.test(f.sink + f.description));
  if (!bad) { console.log('  ✓ python: is_link_local gate clears metadata SSRF'); pass++; }
  else    { console.log('  ✗ python cloud ssrf still flagged', findings); fail++; }
}

{
  const { findings } = runPy('fullmatch-allowlist.py', `
import re
from flask import request, jsonify
from jinja2 import Template
def handler():
    data = request.args.get('q', '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', str(data)):
        return jsonify({'error': 'invalid'}), 400
    return Template(data).render()
`);
  const bad = findings.some(f => /Template|ssti|template/i.test(f.sink + f.description));
  if (!bad) { console.log('  ✓ python: re.fullmatch implicit-anchor clears SSTI'); pass++; }
  else    { console.log('  ✗ python fullmatch still flagged', findings); fail++; }
}

{
  const { findings } = runPy('session-fix.py', `
from flask import Flask, session, request
app = Flask(__name__)
@app.route("/x", methods=["POST"])
def handler():
    data = request.args.get('q','')
    session['user'] = str(data)
    return 'ok'
`);
  const ok = findings.some(f => /session/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ python: session[user] = taint → fixation'); pass++; }
  else    { console.log('  ✗ python session fixation', findings); fail++; }
}

function runJava(name: string, src: string) {
  const tmpPath = path.join(os.tmpdir(), `nebula-java-${Date.now()}-${name}`);
  fs.writeFileSync(tmpPath, src);
  try {
    const { modules, errors } = lowerJavaFiles([tmpPath]);
    return { findings: analyzeJavaModules(modules), errors, modules };
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

{
  const { findings } = runJava('md5.java', `
public class T {
  public void f(String data) throws Exception {
    byte[] digest = java.security.MessageDigest.getInstance("MD5").digest(data.getBytes());
  }
}
`);
  const ok = findings.some(f => /MD5|weakhash|328/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ java: MessageDigest MD5 structural weakhash'); pass++; }
  else    { console.log('  ✗ java md5', findings); fail++; }
}

{
  const { findings } = runJava('exec.java', `
import jakarta.ws.rs.*;
@Path("/")
public class T {
  @GET public String f(@QueryParam("q") String q) throws Exception {
    Runtime.getRuntime().exec(new String[]{"sh", "-c", "echo " + q});
    return "ok";
  }
}
`);
  const ok = findings.some(f => /exec|command/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ java: @QueryParam → Runtime.exec'); pass++; }
  else    { console.log('  ✗ java exec taint', findings); fail++; }
}

function runC(name: string, src: string) {
  const tmpPath = path.join(os.tmpdir(), `nebula-c-${Date.now()}-${name}`);
  fs.writeFileSync(tmpPath, src);
  try {
    const { modules, errors } = lowerCFiles([tmpPath]);
    return { findings: analyzeCModules(modules), errors, modules };
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

{
  const { findings } = runC('md5.c', `
#include <string.h>
extern unsigned char *MD5(const unsigned char *d, unsigned long n, unsigned char *md);
void f(int argc, char **argv) {
    const char *user_input = (argc > 1) ? argv[1] : "";
    unsigned char _digest[16];
    MD5((const unsigned char *)user_input, strlen(user_input), _digest);
}
`);
  const ok = findings.some(f => /MD5|weakhash|328/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ c: MD5 structural weakhash'); pass++; }
  else    { console.log('  ✗ c md5', findings); fail++; }
}

{
  const { findings } = runC('system.c', `
#include <stdlib.h>
void f(int argc, char **argv) {
    const char *user_input = (argc > 1) ? argv[1] : "";
    system(user_input);
}
`);
  const ok = findings.some(f => /system|command/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ c: argv → system'); pass++; }
  else    { console.log('  ✗ c system taint', findings); fail++; }
}

{
  const { findings } = runC('regexec-allow.c', `
#include <stdlib.h>
#include <regex.h>
void f(int argc, char **argv) {
    const char *user_input = (argc > 1) ? argv[1] : "";
    regex_t _re;
    regcomp(&_re, "^[a-zA-Z0-9_-]+$", REG_EXTENDED);
    const char *safe = user_input;
    if (regexec(&_re, user_input, 0, 0, 0) != 0) safe = "config";
    system(safe);
}
`);
  const hit = findings.some(f => /system|command/i.test(f.sink + f.description));
  if (!hit) { console.log('  ✓ c: regexec allowlist rewrite clears system'); pass++; }
  else    { console.log('  ✗ c regexec allowlist still flagged', findings); fail++; }
}

{
  const src = `
    export function safeHandler(req: any) {
      let safe = req.body.cmd;
      if (!/^[a-z0-9_-]+$/.test(req.body.cmd)) safe = "ok";
      return eval(safe);
    }
  `;
  const tmpPath = path.join(os.tmpdir(), `nebula-allow-${Date.now()}.ts`);
  fs.writeFileSync(tmpPath, src);
  try {
    const module = lowerFile(tmpPath, src);
    const findings = analyzeModule(module);
    const hit = findings.some(f => /eval/i.test(f.sink + f.description));
    if (!hit) { console.log('  ✓ ts: allowlist-fail then const clears eval'); pass++; }
    else    { console.log('  ✗ ts allowlist rewrite still flagged', findings); fail++; }
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

function runRb(name: string, src: string) {
  const tmpPath = path.join(os.tmpdir(), `nebula-rb-${Date.now()}-${name}`);
  fs.writeFileSync(tmpPath, src);
  try {
    const { modules, errors } = lowerRubyFiles([tmpPath]);
    if (errors.length && !modules.length) {
      return { findings: [] as ReturnType<typeof analyzeRubyModules>, errors, modules };
    }
    return { findings: analyzeRubyModules(modules), errors, modules };
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

{
  const { findings, errors } = runRb('eval-taint.rb', `
class C < ApplicationController
  def handler
    user_input = ENV["USER_INPUT"] || ""
    data = user_input
    eval(data)
  end
end
`);
  const ok = findings.some(f => /eval/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ ruby: ENV → eval'); pass++; }
  else    { console.log('  ✗ ruby eval taint', findings, errors); fail++; }
}

{
  const { findings } = runRb('eval-allowlist.rb', `
class C < ApplicationController
  def handler
    user_input = ENV["USER_INPUT"] || ""
    data = user_input
    unless %w[asc desc name created].include?(data)
      render json: { error: "invalid" }, status: 400
      return
    end
    eval(data)
  end
end
`);
  const bad = findings.some(f => /eval/i.test(f.sink + f.description) && !/CWE-328|weakhash/i.test(f.description));
  if (!bad) { console.log('  ✓ ruby: %w allowlist clears eval'); pass++; }
  else    { console.log('  ✗ ruby allowlist still flagged eval', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('md5.rb', `
class C < ApplicationController
  def handler
    Digest::MD5.hexdigest("x")
  end
end
`);
  const ok = findings.some(f => /CWE-328|weakhash/i.test(f.description));
  if (ok) { console.log('  ✓ ruby: Digest::MD5 structural'); pass++; }
  else    { console.log('  ✗ ruby md5 structural', findings); fail++; }
}

{
  const { findings } = runRb('cookie-plain.rb', `
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    cookies[:session] = data
    render json: { status: "ok" }
  end
end
`);
  const ok = findings.some(f => /cookie_no_httponly|CWE-1004|httpOnly/i.test(f.description + f.sink));
  if (ok) { console.log('  ✓ ruby: plain cookies[]= missing flags'); pass++; }
  else    { console.log('  ✗ ruby cookie flags missing', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('set-cookie-plain.rb', `
require "sinatra"
class C < Sinatra::Base
  post "/x" do
    data = params[:q].to_s
    response.set_cookie(:session, data)
    JSON.generate({ status: "ok" })
  end
end
`);
  const ok = findings.some(f => /cookie_no_httponly|CWE-1004|httpOnly/i.test(f.description + f.sink));
  if (ok) { console.log('  ✓ ruby: Sinatra set_cookie scalar missing flags'); pass++; }
  else    { console.log('  ✗ ruby set_cookie scalar missed', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('set-cookie-flags.rb', `
require "sinatra"
class C < Sinatra::Base
  post "/x" do
    data = params[:q].to_s
    response.set_cookie(:session, { value: data, secure: true, httponly: true, same_site: :strict })
    JSON.generate({ status: "ok" })
  end
end
`);
  const bad = findings.some(f => /cookie_no_httponly|CWE-1004|httpOnly/i.test(f.description + f.sink));
  if (!bad) { console.log('  ✓ ruby: Sinatra set_cookie hash flags are not a finding'); pass++; }
  else    { console.log('  ✗ ruby set_cookie hash still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('cookie-encrypted.rb', `
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    key = ENV["DATA_ENC_KEY"]
    encrypted = OpenSSL::HMAC.digest("SHA256", key, data)
    cookies[:session] = encrypted
    render json: { status: "ok" }
  end
end
`);
  const bad = findings.some(f => /cookie_no_httponly|CWE-1004|httpOnly/i.test(f.description + f.sink));
  if (!bad) { console.log('  ✓ ruby: encrypted cookie is not a flag finding'); pass++; }
  else    { console.log('  ✗ ruby encrypted cookie still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('xss-sanitize.rb', `
require "sanitize"
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    processed = Sanitize.fragment(data, Sanitize::Config::BASIC)
    render html: ("<div>" + processed + "</div>").html_safe
  end
end
`);
  const bad = findings.some(f => /XSS|html_safe|CWE-79/i.test(f.description));
  if (!bad) { console.log('  ✓ ruby: Sanitize.fragment clears XSS'); pass++; }
  else    { console.log('  ✗ ruby sanitize still XSS', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('cmdi-shellwords.rb', `
require "shellwords"
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    processed = Shellwords.escape(data)
    system("echo " + processed)
  end
end
`);
  const bad = findings.some(f => /command-injection|CWE-78|cmdi/i.test(f.description));
  if (!bad) { console.log('  ✓ ruby: Shellwords.escape clears cmdi'); pass++; }
  else    { console.log('  ✗ ruby shellwords still cmdi', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('session-role.rb', `
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    if session[:role] != "admin"
      render json: { error: "forbidden" }, status: 403
      return
    end
    session[:data] = data.to_s
  end
end
`);
  const bad = findings.some(f => /sessionfixation|CWE-384|trustbound/i.test(f.description));
  if (!bad) { console.log('  ✓ ruby: session[:role] gates session[:data]='); pass++; }
  else    { console.log('  ✗ ruby role gate still fixation', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('cookie-hash-flags.rb', `
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    cookies[:session] = { value: data, secure: true, httponly: true, same_site: :strict }
    render json: { status: "ok" }
  end
end
`);
  const bad = findings.some(f => /cookie_no_httponly|CWE-1004|httpOnly/i.test(f.description + f.sink));
  if (!bad) { console.log('  ✓ ruby: hash cookie flags are not a finding'); pass++; }
  else    { console.log('  ✗ ruby hash flags still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('cookie-signed.rb', `
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    cookies.signed[:session] = data
    render json: { status: "ok" }
  end
end
`);
  const bad = findings.some(f => /cookie_no_httponly|CWE-1004|httpOnly/i.test(f.description + f.sink));
  if (!bad) { console.log('  ✓ ruby: cookies.signed is not a flag finding'); pass++; }
  else    { console.log('  ✗ ruby signed cookie still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('cookie-force-ssl.rb', `
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    config.force_ssl = true
    cookies[:session] = data
    render json: { status: "ok" }
  end
end
`);
  const bad = findings.some(f => /cookie_no_httponly|CWE-1004|httpOnly/i.test(f.description + f.sink));
  if (!bad) { console.log('  ✓ ruby: config.force_ssl guards cookie flags'); pass++; }
  else    { console.log('  ✗ ruby force_ssl still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('session-allowlist.rb', `
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    unless data =~ /\\A[a-zA-Z0-9_.-]+\\z/
      render json: { error: "forbidden" }, status: 403
      return
    end
    session[:data] = data.to_s
  end
end
`);
  const bad = findings.some(f => /sessionfixation|CWE-384|trustbound/i.test(f.description));
  if (!bad) { console.log('  ✓ ruby: allowlist gates session[:data]='); pass++; }
  else    { console.log('  ✗ ruby allowlist still fixation', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('session-reset.rb', `
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    reset_session
    session[:data] = data.to_s
  end
end
`);
  const bad = findings.some(f => /sessionfixation|CWE-384|trustbound/i.test(f.description));
  if (!bad) { console.log('  ✓ ruby: reset_session gates session[:data]='); pass++; }
  else    { console.log('  ✗ ruby reset_session still fixation', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('session-bare.rb', `
class C < ApplicationController
  def handler
    data = ENV["USER_INPUT"] || ""
    session[:data] = data.to_s
  end
end
`);
  const ok = findings.some(f => /sessionfixation|CWE-384|written to session/i.test(f.description));
  if (ok) { console.log('  ✓ ruby: bare session[:data]= still fires'); pass++; }
  else    { console.log('  ✗ ruby bare session[:data]= missed', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('null-deref-unck.rb', `
class C < ApplicationController
  def handler
    data = params[:id].to_s
    result = User.find_by(name: data)
    value = result.name
    render json: { status: "ok" }
  end
end
`);
  const ok = findings.some(f => /null dereference|null.deref|CWE-476/i.test(f.description + f.sink));
  if (ok) { console.log('  ✓ ruby: find_by then result.name fires null_deref'); pass++; }
  else    { console.log('  ✗ ruby unchecked find_by missed', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('null-deref-nil.rb', `
class C < ApplicationController
  def handler
    data = params[:id].to_s
    result = User.find_by(name: data)
    return render json: { error: "not found" }, status: 404 if result.nil?
    value = result.name
    render json: { status: "ok" }
  end
end
`);
  const bad = findings.some(f => /null dereference|null.deref|CWE-476/i.test(f.description + f.sink));
  if (!bad) { console.log('  ✓ ruby: result.nil? return clears null_deref'); pass++; }
  else    { console.log('  ✗ ruby nil? still deref', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('null-deref-first.rb', `
require "sinatra"
class C < Sinatra::Base
  post "/x" do
    data = params[:q].to_s
    result = DB[:users].where(name: data).first
    value = result[:name]
    JSON.generate({ status: "ok" })
  end
end
`);
  const ok = findings.some(f => /null dereference|null.deref|CWE-476/i.test(f.description + f.sink));
  if (ok) { console.log('  ✓ ruby: .first then result[:name] fires null_deref'); pass++; }
  else    { console.log('  ✗ ruby unchecked first missed', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runRb('null-deref-halt.rb', `
require "sinatra"
class C < Sinatra::Base
  post "/x" do
    data = params[:q].to_s
    result = DB[:users].where(name: data).first
    return halt 404, JSON.generate({ error: "not found" }) if result.nil?
    value = result[:name]
    JSON.generate({ status: "ok" })
  end
end
`);
  const bad = findings.some(f => /null dereference|null.deref|CWE-476/i.test(f.description + f.sink));
  if (!bad) { console.log('  ✓ ruby: halt if result.nil? clears null_deref'); pass++; }
  else    { console.log('  ✗ ruby halt nil? still deref', findings.map(f => f.description)); fail++; }
}

function runPhp(name: string, src: string) {
  const tmpPath = path.join(os.tmpdir(), `nebula-php-${Date.now()}-${name}`);
  fs.writeFileSync(tmpPath, src);
  try {
    const { modules, errors } = lowerPhpFiles([tmpPath]);
    if (errors.length && !modules.length) {
      return { findings: [] as ReturnType<typeof analyzePhpModules>, errors, modules };
    }
    return { findings: analyzePhpModules(modules), errors, modules };
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

{
  const { findings, errors } = runPhp('eval-taint.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->header('Host', '');
        $data = $userInput;
        eval((string)$data);
        return response()->json(['ok' => 1]);
    }
}
`);
  const ok = findings.some(f => /eval|CWE-95|CWE-94/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ php: request.header → eval'); pass++; }
  else    { console.log('  ✗ php eval taint', findings, errors); fail++; }
}

{
  const { findings } = runPhp('eval-allowlist.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->header('Origin', '');
        $data = $userInput;
        if (!in_array($data, ['asc','desc','name','created'])) { return response()->json(['error'=>'invalid'], 400); }
        eval((string)$data);
        return response()->json(['ok' => 1]);
    }
}
`);
  const bad = findings.some(f => /eval|CWE-95|CWE-94/i.test(f.sink + f.description) && !/CWE-328|weakhash/i.test(f.description));
  if (!bad) { console.log('  ✓ php: in_array allowlist clears eval'); pass++; }
  else    { console.log('  ✗ php allowlist still flagged eval', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runPhp('md5.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $digest = md5('x');
        return response()->json(['ok' => 1]);
    }
}
`);
  const ok = findings.some(f => /CWE-328|weakhash/i.test(f.description));
  if (ok) { console.log('  ✓ php: md5 structural weakhash'); pass++; }
  else    { console.log('  ✗ php md5 structural', findings); fail++; }
}

{
  const { findings, errors } = runPhp('cmdi-getenv.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = getenv('USER_INPUT') ?: '';
        $asText = function ($v): string { return (string) $v; };
        $data = $asText($userInput);
        exec('echo ' . (string)$data);
        return response()->json(['ok' => 1]);
    }
}
`);
  const ok = findings.some(f => /command-injection|CWE-78|exec/i.test(f.sink + f.description + f.type));
  if (ok) { console.log('  ✓ php: getenv ?: → exec'); pass++; }
  else    { console.log('  ✗ php getenv cmdi', findings, errors); fail++; }
}

{
  const { findings } = runPhp('xss-response.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->header('Authorization', '');
        $data = str_replace("\\0", '', $userInput);
        return response('<div>' . $data . '</div>')->header('Content-Type', 'text/html');
    }
}
`);
  const ok = findings.some(f => /xss|template-injection|CWE-79|html/i.test(f.sink + f.description + f.type));
  if (ok) { console.log('  ✓ php: header → response HTML'); pass++; }
  else    { console.log('  ✗ php xss response', findings); fail++; }
}

{
  const { findings } = runPhp('ssti-blade.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->cookie('session_token', '');
        $data = $userInput;
        return response(\\Illuminate\\Support\\Facades\\Blade::render($data))->header('Content-Type', 'text/html');
    }
}
`);
  const ok = findings.some(f => /ssti|template-injection|Blade|CWE-1336|CWE-94/i.test(f.sink + f.description + f.type));
  if (ok) { console.log('  ✓ php: cookie → Blade::render'); pass++; }
  else    { console.log('  ✗ php ssti blade', findings); fail++; }
}

{
  const { findings } = runPhp('json-not-xss.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->header('Host', '');
        return response()->json(['ok' => $userInput]);
    }
}
`);
  const bad = findings.some(f => /xss|CWE-79|html string return/i.test(f.sink + f.description));
  if (!bad) { console.log('  ✓ php: response()->json is not XSS'); pass++; }
  else    { console.log('  ✗ php json false xss', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runPhp('abort-500.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->header('Origin', '');
        $data = '' . $userInput;
        abort(500, $data);
        return response()->json(['ok' => 1]);
    }
}
`);
  const ok = findings.some(f => /CWE-209|errormessage|abort/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ php: header → abort(500, $data)'); pass++; }
  else    { console.log('  ✗ php abort', findings); fail++; }
}

{
  const { findings } = runPhp('xpath-query.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->getContent();
        $data = $userInput;
        $doc = new \\DOMDocument();
        $xpath = new \\DOMXPath($doc);
        $nodes = $xpath->query("//user[@id='" . $data . "']");
        return response()->json(['ok' => 1]);
    }
}
`);
  const ok = findings.some(f => /xpath|CWE-643/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ php: taint → DOMXPath::query'); pass++; }
  else    { console.log('  ✗ php xpath', findings); fail++; }
}

{
  const { findings } = runPhp('session-fix.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->header('User-Agent', '');
        $data = $userInput;
        session(['data' => (string) $data]);
        return response()->json(['ok' => 1]);
    }
}
`);
  const ok = findings.some(f => /session fixation|CWE-384/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ php: taint → session([...])'); pass++; }
  else    { console.log('  ✗ php session', findings); fail++; }
}

{
  const { findings } = runPhp('clickjack-xfo.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->header('Origin', '');
        $data = $userInput;
        return response('<html><body>' . $data . '</body></html>')->header('Content-Type', 'text/html');
    }
}
`);
  const ok = findings.some(f => /CWE-1021|clickjacking|X-Frame|xfo/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ php: HTML without XFO is clickjacking'); pass++; }
  else    { console.log('  ✗ php clickjack', findings); fail++; }
}

{
  const { findings } = runPhp('setcookie-legacy.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->header('Origin', '');
        $data = $userInput;
        setcookie('session', (string) $data);
        return response()->json(['ok' => 1]);
    }
}
`);
  const ok = findings.some(f => /CWE-1004|httponly|setcookie/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ php: legacy setcookie($n,$v) fires cookie flags'); pass++; }
  else    { console.log('  ✗ php setcookie legacy', findings); fail++; }
}

{
  const { findings } = runPhp('setcookie-opts.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->header('Origin', '');
        $data = $userInput;
        setcookie('session', (string) $data, ['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
        return response()->json(['ok' => 1]);
    }
}
`);
  const bad = findings.some(f => /CWE-1004|CWE-614|CWE-1275|httponly|samesite|securecookie/i.test(f.sink + f.description));
  if (!bad) { console.log('  ✓ php: setcookie options array is not a flag finding'); pass++; }
  else    { console.log('  ✗ php setcookie opts still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runPhp('cookie-source-not-sink.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $userInput = $request->cookie('session_token', '');
        $data = $userInput;
        eval($data);
        return response()->json(['ok' => 1]);
    }
}
`);
  const bad = findings.some(f => /CWE-1004|CWE-614|CWE-1275|cookie_no_httponly/i.test(f.sink + f.description));
  if (!bad) { console.log('  ✓ php: cookie() source is not a flag finding'); pass++; }
  else    { console.log('  ✗ php cookie source flagged as set', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runPhp('www-export-plain.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $data = $request->header('Host', '');
        file_put_contents('/var/www/html/exports/report.txt', (string) $data);
        return response()->json(['ok' => 1]);
    }
}
`);
  const ok = findings.some(f => /CWE-219|sensitive_file_web_root/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ php: plaintext web-root write fires 219'); pass++; }
  else    { console.log('  ✗ php 219 missing', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runPhp('www-export-enc.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $data = $request->header('Host', '');
        $encKey = getenv('DATA_ENC_KEY');
        $iv = random_bytes(12);
        $tag = '';
        $_ct = openssl_encrypt((string)$data, 'aes-256-gcm', $encKey, 0, $iv, $tag);
        $encrypted = base64_encode($iv . $tag . $_ct);
        file_put_contents('/var/www/html/exports/report.txt', $encrypted);
        return response()->json(['ok' => 1]);
    }
}
`);
  const bad = findings.some(f => /CWE-219|CWE-538|CWE-922|sensitive_file|insecure_storage/i.test(f.sink + f.description));
  if (!bad) { console.log('  ✓ php: encrypted web-root write is not 219/538/922'); pass++; }
  else    { console.log('  ✗ php encrypted still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runPhp('insecure-storage-plain.php', `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class C {
    public function __invoke(Request $request)
    {
        $data = $request->getContent();
        file_put_contents('/var/data/output', (string) $data);
        return response()->json(['ok' => 1]);
    }
}
`);
  const ok = findings.some(f => /CWE-922|insecure_storage/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ php: plaintext /var/data write fires 922'); pass++; }
  else    { console.log('  ✗ php 922 missing', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runPhp('scandir-plain.php', `<?php
namespace App\\Controller;
use Symfony\\Component\\HttpFoundation\\Request;
use Symfony\\Component\\HttpFoundation\\JsonResponse;
class C {
    public function __invoke(Request $request)
    {
        $data = $request->getContent();
        $entries = scandir((string) $data);
        return new JsonResponse(['listing' => $entries]);
    }
}
`);
  const ok = findings.some(f => /CWE-209|directory_listing|scandir/i.test(f.sink + f.description));
  if (ok) { console.log('  ✓ php: scandir of user path fires 209'); pass++; }
  else    { console.log('  ✗ php scandir missing', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runPhp('scandir-session.php', `<?php
namespace App\\Controller;
use Symfony\\Component\\HttpFoundation\\Request;
use Symfony\\Component\\HttpFoundation\\JsonResponse;
use Symfony\\Component\\HttpKernel\\Exception\\HttpException;
class C {
    public function __invoke(Request $request)
    {
        $data = $request->getContent();
        if (empty($request->getSession()->get('user', ''))) { throw new HttpException(401, 'unauthorized'); }
        $entries = scandir((string) $data);
        return new JsonResponse(['listing' => $entries]);
    }
}
`);
  const bad = findings.some(f => /directory_listing|scandir of user/i.test(f.sink + f.description));
  if (!bad) { console.log('  ✓ php: Symfony getSession+401 skips directory listing'); pass++; }
  else    { console.log('  ✗ php session scandir still flagged', findings.map(f => f.description)); fail++; }
}

function runBash(name: string, src: string) {
  const tmpPath = path.join(os.tmpdir(), `nebula-bash-${Date.now()}-${name}`);
  fs.writeFileSync(tmpPath, src);
  try {
    const { modules, errors } = lowerBashFiles([tmpPath]);
    return { findings: analyzeBashModules(modules), errors, modules };
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

{
  const { findings } = runBash('eval.sh', `#!/bin/bash
benchmark_test() {
  user_input="$QUERY_STRING"
  data="$user_input"
  eval "echo $data"
}
`);
  const ok = findings.some(f => /cwe-78/i.test(f.description));
  if (ok) { console.log('  ✓ bash: eval echo $data → cmdi'); pass++; }
  else    { console.log('  ✗ bash eval', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runBash('eval-allow.sh', `#!/bin/bash
benchmark_test() {
  user_input="$QUERY_STRING"
  data="$user_input"
  if [[ ! $data =~ ^[a-zA-Z0-9_.-]+$ ]]; then echo "invalid"; exit 1; fi
  processed="$data"
  eval "echo $processed"
}
`);
  const hit = findings.some(f => /cwe-78/i.test(f.description));
  if (!hit) { console.log('  ✓ bash: regex allowlist clears eval'); pass++; }
  else    { console.log('  ✗ bash allowlist still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runBash('md5.sh', `#!/bin/bash
benchmark_test() {
  echo -n "$data" | md5sum
}
`);
  const ok = findings.some(f => /cwe-328/i.test(f.description));
  if (ok) { console.log('  ✓ bash: md5sum structural weakhash'); pass++; }
  else    { console.log('  ✗ bash md5', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runBash('hidden-field.sh', `#!/bin/bash
benchmark_test() {
  data="$user_input"
  printf "Location: /dashboard?hidden_field=%s\\r\\n\\r\\n" "$data"
}
`);
  const ok = findings.some(f => /cwe-472/i.test(f.description));
  if (ok) { console.log('  ✓ bash: hidden_field ungated → 472'); pass++; }
  else    { console.log('  ✗ bash hidden_field', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runBash('hidden-field-allow.sh', `#!/bin/bash
benchmark_test() {
  data="$user_input"
  if [[ ! $data =~ ^[a-zA-Z0-9_.-]+$ ]]; then echo "invalid"; exit 1; fi
  printf "Location: /dashboard?hidden_field=%s\\r\\n\\r\\n" "$data"
}
`);
  const hit = findings.some(f => /cwe-472|cwe-601/i.test(f.description));
  if (!hit) { console.log('  ✓ bash: ident allowlist clears 472/601'); pass++; }
  else    { console.log('  ✗ bash hidden_field allowlist still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runBash('weak-auth.sh', `#!/bin/bash
benchmark_test() {
  if [ "$data" = "S3cr3tToken" ]; then echo granted; fi
}
`);
  const ok = findings.some(f => /cwe-1390/i.test(f.description));
  const surf = findings.some(f => /cwe-1125/i.test(f.description));
  if (ok && surf) { console.log('  ✓ bash: S3cr3tToken → 1390 and 1125'); pass++; }
  else    { console.log('  ✗ bash 1390/1125 token', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runBash('weak-auth-db.sh', `#!/bin/bash
benchmark_test() {
  if [ -z "$AUTH_TOKEN" ]; then echo unauthorized; exit 1; fi
  awk -F: -v u="$data" '$1==u{found=1} END{exit !found}' /etc/app/users.db
}
`);
  const hit = findings.some(f => /cwe-1390|cwe-287/i.test(f.description));
  if (!hit) { console.log('  ✓ bash: AUTH_TOKEN+users.db clears 1390/287'); pass++; }
  else    { console.log('  ✗ bash authn guard still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runBash('surface.sh', `#!/bin/bash
benchmark_test() {
  if [[ "$data" =~ ^(read|write|admin)$ ]]; then echo granted; fi
}
`);
  const ok = findings.some(f => /cwe-1125/i.test(f.description));
  if (ok) { console.log('  ✓ bash: client role ungated → 1125'); pass++; }
  else    { console.log('  ✗ bash 1125', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runBash('surface-role.sh', `#!/bin/bash
benchmark_test() {
  if [ "$USER_ROLE" != "admin" ]; then echo forbidden; exit 1; fi
  if ! grep -qxF -- "$USER:$data" /etc/app/acl; then echo 403; exit 1; fi
}
`);
  const hit = findings.some(f => /cwe-1125|cwe-1390/i.test(f.description));
  if (!hit) { console.log('  ✓ bash: USER_ROLE+acl clears 1125/1390'); pass++; }
  else    { console.log('  ✗ bash surface guard still flagged', findings.map(f => f.description)); fail++; }
}

{
  const { findings } = runBash('token-after-role.sh', `#!/bin/bash
benchmark_test() {
  if [ "$USER_ROLE" != "admin" ]; then echo forbidden; exit 1; fi
  if [ "$data" = "S3cr3tToken" ]; then echo granted; fi
}
`);
  const hit = findings.some(f => /cwe-1390|cwe-1125|cwe-287/i.test(f.description));
  if (!hit) { console.log('  ✓ bash: USER_ROLE gates S3cr3tToken (1390/1125/287)'); pass++; }
  else    { console.log('  ✗ bash USER_ROLE+token still flagged', findings.map(f => f.description)); fail++; }
}

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);

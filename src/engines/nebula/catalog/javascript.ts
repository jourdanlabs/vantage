import { ModuleImport } from '../ir';

// JavaScript / TypeScript source / sink / sanitizer catalog for NEBULA v1.
//
// Catalog format: a pattern matches a Value node in the IR. For the v1
// intraprocedural case we recognize:
//   - sources by field access shape, e.g. `req.body`, `req.params.id`
//   - sinks by call shape, e.g. `eval(x)`, `vm.runInNewContext(x, ...)`
//   - sanitizers by call shape, e.g. `encodeURIComponent(x)`
//
// Catalog growth is the perpetual maintenance tax ADR-0002 calls out. Keep
// entries narrow and annotated — every entry needs to survive review by a
// security engineer who's going to ask "why exactly does this sanitize this?"

export interface TaintSource {
  id: string;
  /** Shape this matches in the IR. For now, simple dotted-path matches. */
  fieldPath: string[];   // e.g. ['req', 'body']  — matches req.body or req.body.anything
  kind: 'user-input' | 'env' | 'filesystem' | 'network';
  description: string;
}

export interface TaintSink {
  id: string;
  calleePath: string[];   // e.g. ['eval']  — global eval; ['vm', 'runInNewContext'] — module.fn
  /** Which argument positions receive user data. 0-indexed. */
  dangerousArgs: number[];
  /** Keyword-argument names that are also dangerous (Python RedirectResponse(url=…)). */
  dangerousKwargs?: string[];
  /** What gets run / rendered / executed. */
  danger: 'code-execution' | 'sql-injection' | 'command-injection' | 'template-injection' | 'redirect' | 'ssrf';
  description: string;
}

export interface Sanitizer {
  id: string;
  calleePath: string[];
  /** Which argument positions this sanitizes (0-indexed). Output is always treated as sanitized. */
  sanitizesArgs: number[];
  /** Which danger classes this sanitizer neutralizes. A sanitizer that only
   *  handles `sql-injection` does not neutralize `code-execution`. */
  against: TaintSink['danger'][];
  description: string;
}

export const JAVASCRIPT_SOURCES: TaintSource[] = [
  // ── Express-style (still the majority of the Node ecosystem) ────────────
  { id: 'express.req.body',    fieldPath: ['req', 'body'],    kind: 'user-input', description: 'Express req.body — JSON/form-encoded request payload' },
  { id: 'express.req.params',  fieldPath: ['req', 'params'],  kind: 'user-input', description: 'Express URL route params' },
  { id: 'express.req.query',   fieldPath: ['req', 'query'],   kind: 'user-input', description: 'Express URL query-string fields' },
  { id: 'express.req.headers', fieldPath: ['req', 'headers'], kind: 'user-input', description: 'Express request headers (also attacker-controlled)' },
  { id: 'express.req.cookies', fieldPath: ['req', 'cookies'], kind: 'user-input', description: 'Express request cookies' },
  { id: 'express.req.header',  fieldPath: ['req', 'header'],  kind: 'user-input', description: 'Express req.header (alias shape)' },
  { id: 'express.req.signedCookies', fieldPath: ['req', 'signedCookies'], kind: 'user-input', description: 'Express signed cookies' },
  { id: 'express.req.files',   fieldPath: ['req', 'files'],   kind: 'user-input', description: 'Express multipart files' },
  { id: 'express.req.file',    fieldPath: ['req', 'file'],    kind: 'user-input', description: 'Express multipart single file' },
  { id: 'express.req.file.originalname', fieldPath: ['req', 'file', 'originalname'], kind: 'user-input', description: 'Express multer originalname' },
  { id: 'express.req.session', fieldPath: ['req', 'session'], kind: 'user-input', description: 'Express session — often holds attacker-influenced data' },

  // ── Koa (ctx.*) ─────────────────────────────────────────────────────────
  { id: 'koa.ctx.request.body',    fieldPath: ['ctx', 'request', 'body'],    kind: 'user-input', description: 'Koa ctx.request.body (koa-bodyparser)' },
  { id: 'koa.ctx.request.query',   fieldPath: ['ctx', 'request', 'query'],   kind: 'user-input', description: 'Koa query parameters' },
  { id: 'koa.ctx.request.header',  fieldPath: ['ctx', 'request', 'header'],  kind: 'user-input', description: 'Koa request headers (singular map)' },
  { id: 'koa.ctx.request.headers', fieldPath: ['ctx', 'request', 'headers'], kind: 'user-input', description: 'Koa request headers (plural — BP corpus)' },
  { id: 'koa.ctx.request.files',   fieldPath: ['ctx', 'request', 'files'],   kind: 'user-input', description: 'Koa multipart files (koa-body / formidable)' },
  { id: 'koa.ctx.headers',         fieldPath: ['ctx', 'headers'],            kind: 'user-input', description: 'Koa ctx.headers shortcut' },
  { id: 'koa.ctx.params',          fieldPath: ['ctx', 'params'],             kind: 'user-input', description: 'Koa router params (koa-router / @koa/router)' },
  { id: 'koa.ctx.query',           fieldPath: ['ctx', 'query'],              kind: 'user-input', description: 'Koa query shortcut (ctx.query = ctx.request.query)' },
  { id: 'koa.ctx.cookies',         fieldPath: ['ctx', 'cookies'],            kind: 'user-input', description: 'Koa cookies object' },
  { id: 'koa.ctx.request',         fieldPath: ['ctx', 'request'],            kind: 'user-input', description: 'Koa request object (partial — fields still preferred)' },
  { id: 'koa.ctx.state',           fieldPath: ['ctx', 'state'],              kind: 'user-input', description: 'Koa ctx.state — often populated from upstream user input in middleware' },

  // ── Fastify (request.*) ─────────────────────────────────────────────────
  { id: 'fastify.request.body',    fieldPath: ['request', 'body'],    kind: 'user-input', description: 'Fastify request.body' },
  { id: 'fastify.request.params',  fieldPath: ['request', 'params'],  kind: 'user-input', description: 'Fastify request.params' },
  { id: 'fastify.request.query',   fieldPath: ['request', 'query'],   kind: 'user-input', description: 'Fastify request.query' },
  { id: 'fastify.request.headers', fieldPath: ['request', 'headers'], kind: 'user-input', description: 'Fastify request.headers' },
  { id: 'fastify.request.cookies', fieldPath: ['request', 'cookies'], kind: 'user-input', description: 'Fastify request.cookies (@fastify/cookie)' },

  // ── Hapi (request.payload / request.params) ─────────────────────────────
  { id: 'hapi.request.payload',  fieldPath: ['request', 'payload'],  kind: 'user-input', description: 'Hapi request.payload' },
  // params/query/headers already covered by Fastify entries (same path shape)

  // ── Next.js / Vercel serverless (req.body is same; req.query too — already covered above) ──

  // ── AWS Lambda event objects ────────────────────────────────────────────
  { id: 'lambda.event.body',        fieldPath: ['event', 'body'],                              kind: 'user-input', description: 'AWS Lambda API Gateway proxy: event.body' },
  { id: 'lambda.event.queryParams', fieldPath: ['event', 'queryStringParameters'],             kind: 'user-input', description: 'Lambda queryStringParameters' },
  { id: 'lambda.event.pathParams',  fieldPath: ['event', 'pathParameters'],                    kind: 'user-input', description: 'Lambda pathParameters' },

  // ── Process / env / filesystem ─────────────────────────────────────────
  { id: 'process.argv', fieldPath: ['process', 'argv'], kind: 'env', description: 'Command-line arguments' },
  { id: 'process.env',  fieldPath: ['process', 'env'],  kind: 'env', description: 'Environment variables — attacker-controlled in some deploy scenarios' },
  { id: 'process.stdin', fieldPath: ['process', 'stdin'], kind: 'user-input', description: 'Data read from stdin' },
  // Python sources live in catalog/python.ts — do not merge them here.
];

export const JAVASCRIPT_SINKS: TaintSink[] = [
  // ── Code execution ──────────────────────────────────────────────────────
  { id: 'eval',           calleePath: ['eval'],               dangerousArgs: [0], danger: 'code-execution',   description: 'Global eval — runs arbitrary JavaScript' },
  { id: 'Function-ctor',  calleePath: ['Function'],           dangerousArgs: [0], danger: 'code-execution',   description: 'Function constructor — parses a string as function body' },
  { id: 'vm.runInNewContext', calleePath: ['vm', 'runInNewContext'], dangerousArgs: [0], danger: 'code-execution', description: 'Node vm.runInNewContext — evaluates a string in a sandbox' },
  { id: 'vm.runInContext',    calleePath: ['vm', 'runInContext'],    dangerousArgs: [0], danger: 'code-execution', description: 'Node vm.runInContext — evaluates in an existing context' },
  { id: 'vm.runInThisContext', calleePath: ['vm', 'runInThisContext'], dangerousArgs: [0], danger: 'code-execution', description: 'Node vm.runInThisContext — evaluates in the caller context' },
  { id: 'vm.Script',       calleePath: ['vm', 'Script'],       dangerousArgs: [0], danger: 'code-execution',   description: 'new vm.Script(src) — compiles arbitrary source for later run' },

  // ── Command execution ──────────────────────────────────────────────────
  { id: 'child_process.exec',     calleePath: ['child_process', 'exec'],     dangerousArgs: [0], danger: 'command-injection', description: 'child_process.exec — spawns a shell and runs the command string' },
  { id: 'child_process.execSync', calleePath: ['child_process', 'execSync'], dangerousArgs: [0], danger: 'command-injection', description: 'child_process.execSync' },
  { id: 'child_process.spawn',    calleePath: ['child_process', 'spawn'],    dangerousArgs: [1], danger: 'command-injection', description: 'spawn with user-controlled argv — still risky if shell: true' },
  { id: 'child_process.spawnSync', calleePath: ['child_process', 'spawnSync'], dangerousArgs: [1], danger: 'command-injection', description: 'spawnSync' },
  { id: 'child_process.execFile',  calleePath: ['child_process', 'execFile'],  dangerousArgs: [1], danger: 'command-injection', description: 'execFile argv injection' },
  // Also catch the common `exec` bare-imported pattern
  { id: 'exec.bare', calleePath: ['exec'], dangerousArgs: [0], danger: 'command-injection', description: 'bare exec() — almost certainly child_process.exec imported by name' },
  { id: 'execSync.bare', calleePath: ['execSync'], dangerousArgs: [0], danger: 'command-injection', description: 'bare execSync() — imported child_process.execSync' },

  // ── Template injection ──────────────────────────────────────────────────
  { id: 'pug.compile',     calleePath: ['pug', 'compile'],     dangerousArgs: [0], danger: 'template-injection', description: 'Pug template compile — code execution via unsanitized template' },
  { id: 'pug.render',      calleePath: ['pug', 'render'],      dangerousArgs: [0], danger: 'template-injection', description: 'Pug one-shot render' },
  { id: 'ejs.render',      calleePath: ['ejs', 'render'],      dangerousArgs: [0], danger: 'template-injection', description: 'EJS server-side render' },
  { id: 'ejs.compile',     calleePath: ['ejs', 'compile'],     dangerousArgs: [0], danger: 'template-injection', description: 'EJS compile' },
  { id: 'handlebars.compile', calleePath: ['handlebars', 'compile'], dangerousArgs: [0], danger: 'template-injection', description: 'Handlebars template compile' },
  { id: 'nunjucks.renderString', calleePath: ['nunjucks', 'renderString'], dangerousArgs: [0], danger: 'template-injection', description: 'Nunjucks renderString' },

  // ── SQL injection (raw queries) ─────────────────────────────────────────
  // Sequelize: sequelize.query(sql) — classic raw-query sink
  { id: 'sequelize.query', calleePath: ['sequelize', 'query'], dangerousArgs: [0], danger: 'sql-injection', description: 'Sequelize.query — raw SQL. Use replacements/bind params instead of string interpolation.' },
  { id: 'sequelize.literal', calleePath: ['Sequelize', 'literal'], dangerousArgs: [0], danger: 'sql-injection', description: 'Sequelize.literal — injects raw SQL fragment into a query' },
  // Knex: knex.raw(sql)
  { id: 'knex.raw', calleePath: ['knex', 'raw'], dangerousArgs: [0], danger: 'sql-injection', description: 'Knex.raw — raw SQL fragment' },
  // pg: client.query(text) when text is user-controlled
  { id: 'pg.query', calleePath: ['pg', 'query'], dangerousArgs: [0], danger: 'sql-injection', description: 'node-postgres pg.query with user-controlled SQL text' },
  // mysql / mysql2: connection.query(sql)
  { id: 'mysql.query', calleePath: ['mysql', 'query'], dangerousArgs: [0], danger: 'sql-injection', description: 'mysql/mysql2 raw query' },
  // BenchProctor shared.db helpers (./shared) — very common in JS corpora
  { id: 'db.query',     calleePath: ['db', 'query'],     dangerousArgs: [0], danger: 'sql-injection', description: 'db.query — raw SQL (shared fixture / app db wrapper)' },
  { id: 'db.querySync', calleePath: ['db', 'querySync'], dangerousArgs: [0], danger: 'sql-injection', description: 'db.querySync — raw SQL sync' },
  { id: 'db.execute',   calleePath: ['db', 'execute'],   dangerousArgs: [0, 1], danger: 'sql-injection', description: 'db.execute — raw SQL or untrusted bind params (data integrity)' },
  // Auth helpers (BenchProctor shared.authCheck) — credential decisions.
  // authzCheck is a GUARD (if (!authzCheck) return 403), not a sink: flagging it
  // FPs every safe authz twin. Vuln authz is caught via broken-grant patterns.
  { id: 'authCheck',    calleePath: ['authCheck'],       dangerousArgs: [0, 1], danger: 'code-execution', description: 'authCheck(user, token) with attacker-controlled credential — authn weakness / no rate limit surface' },
  // authzCheck intentionally NOT a sink (Kaioken XXVII)
  // Privilege / JWT
  { id: 'process.setuid',  calleePath: ['process', 'setuid'],  dangerousArgs: [0], danger: 'code-execution', description: 'process.setuid with user-controlled uid — privilege escalation' },
  { id: 'process.setgid',  calleePath: ['process', 'setgid'],  dangerousArgs: [0], danger: 'code-execution', description: 'process.setgid with user-controlled gid' },
  { id: 'setuid.bare',     calleePath: ['setuid'],             dangerousArgs: [0], danger: 'code-execution', description: 'setuid(taint)' },
  { id: 'jsonwebtoken.sign', calleePath: ['jsonwebtoken', 'sign'], dangerousArgs: [1], danger: 'code-execution', description: 'jwt.sign with user/hardcoded secret — weak JWT secret' },
  { id: 'jwt.sign',          calleePath: ['jwt', 'sign'],          dangerousArgs: [1], danger: 'code-execution', description: 'jwt.sign secret arg' },

  // ── XPath / LDAP injection ──────────────────────────────────────────────
  { id: 'xpath.select',  calleePath: ['xpath', 'select'],  dangerousArgs: [0], danger: 'sql-injection', description: 'xpath.select with user-controlled expression — XPath injection' },
  { id: 'xpath.select1', calleePath: ['xpath', 'select1'], dangerousArgs: [0], danger: 'sql-injection', description: 'xpath.select1 with user-controlled expression' },
  { id: 'ldapjs.search', calleePath: ['ldapjs', 'search'], dangerousArgs: [0, 1], danger: 'sql-injection', description: 'ldapjs search with user-controlled DN/filter — LDAP injection' },
  { id: 'ldap.search',   calleePath: ['ldap', 'search'],   dangerousArgs: [0, 1], danger: 'sql-injection', description: 'ldap search filter injection' },

  // ── Filesystem (path traversal when path sourced from user input) ───────
  { id: 'fs.readFile',      calleePath: ['fs', 'readFile'],      dangerousArgs: [0], danger: 'ssrf',     description: 'fs.readFile with user-controlled path — path traversal / arbitrary read' },
  { id: 'fs.readFileSync',  calleePath: ['fs', 'readFileSync'],  dangerousArgs: [0], danger: 'ssrf',     description: 'fs.readFileSync with user-controlled path — path traversal' },
  // dangerousArgs include content (1) for CSV/log injection via writes (Kaioken X)
  { id: 'fs.writeFile',     calleePath: ['fs', 'writeFile'],     dangerousArgs: [0, 1], danger: 'ssrf',     description: 'fs.writeFile with user-controlled path/content — path traversal / CSV injection' },
  { id: 'fs.writeFileSync', calleePath: ['fs', 'writeFileSync'], dangerousArgs: [0, 1], danger: 'ssrf',     description: 'fs.writeFileSync with user-controlled path/content' },
  { id: 'fs.appendFile',    calleePath: ['fs', 'appendFile'],    dangerousArgs: [0, 1], danger: 'ssrf',     description: 'fs.appendFile with user-controlled path/content — CSV/log injection' },
  { id: 'fs.appendFileSync', calleePath: ['fs', 'appendFileSync'], dangerousArgs: [0, 1], danger: 'ssrf',   description: 'fs.appendFileSync with user-controlled path/content — CSV/log injection' },
  { id: 'fs.unlink',        calleePath: ['fs', 'unlink'],        dangerousArgs: [0], danger: 'ssrf',     description: 'fs.unlink with user-controlled path' },
  { id: 'fs.unlinkSync',    calleePath: ['fs', 'unlinkSync'],    dangerousArgs: [0], danger: 'ssrf',     description: 'fs.unlinkSync with user-controlled path' },
  { id: 'fs.readdir',       calleePath: ['fs', 'readdir'],       dangerousArgs: [0], danger: 'ssrf',     description: 'fs.readdir with user-controlled path' },
  { id: 'fs.readdirSync',   calleePath: ['fs', 'readdirSync'],   dangerousArgs: [0], danger: 'ssrf',     description: 'fs.readdirSync with user-controlled path' },
  // Kaioken XLIX — permission / mode control
  { id: 'fs.chmod',         calleePath: ['fs', 'chmod'],         dangerousArgs: [0, 1], danger: 'ssrf', description: 'fs.chmod with user-controlled path/mode — insecure perms' },
  { id: 'fs.chmodSync',     calleePath: ['fs', 'chmodSync'],     dangerousArgs: [0, 1], danger: 'ssrf', description: 'fs.chmodSync with user-controlled path/mode — insecure perms' },
  { id: 'fs.chown',         calleePath: ['fs', 'chown'],         dangerousArgs: [0, 1, 2], danger: 'ssrf', description: 'fs.chown with user-controlled path/uid' },
  { id: 'fs.chownSync',     calleePath: ['fs', 'chownSync'],     dangerousArgs: [0, 1, 2], danger: 'ssrf', description: 'fs.chownSync with user-controlled path/uid' },
  { id: 'fs.createReadStream',  calleePath: ['fs', 'createReadStream'],  dangerousArgs: [0], danger: 'ssrf', description: 'fs.createReadStream with user-controlled path' },
  { id: 'fs.createWriteStream', calleePath: ['fs', 'createWriteStream'], dangerousArgs: [0], danger: 'ssrf', description: 'fs.createWriteStream with user-controlled path' },

  // ── Crypto key management (user-controlled key material) ────────────────
  // CWE-320/321: createCipheriv(algo, key, iv) — key is arg index 1
  { id: 'crypto.createCipheriv',   calleePath: ['crypto', 'createCipheriv'],   dangerousArgs: [1], danger: 'code-execution', description: 'crypto.createCipheriv with user-controlled key material — key management error' },
  { id: 'crypto.createDecipheriv', calleePath: ['crypto', 'createDecipheriv'], dangerousArgs: [1], danger: 'code-execution', description: 'crypto.createDecipheriv with user-controlled key' },
  { id: 'crypto.createCipher',     calleePath: ['crypto', 'createCipher'],     dangerousArgs: [1], danger: 'code-execution', description: 'crypto.createCipher (deprecated) with user-controlled password/key' },
  { id: 'crypto.createDecipher',   calleePath: ['crypto', 'createDecipher'],   dangerousArgs: [1], danger: 'code-execution', description: 'crypto.createDecipher (deprecated) with user-controlled password/key' },
  { id: 'crypto.privateDecrypt',   calleePath: ['crypto', 'privateDecrypt'],   dangerousArgs: [0], danger: 'code-execution', description: 'crypto.privateDecrypt with user-influenced key object' },
  { id: 'crypto.publicEncrypt',    calleePath: ['crypto', 'publicEncrypt'],    dangerousArgs: [0], danger: 'code-execution', description: 'crypto.publicEncrypt with user-influenced key object' },

  // ── Open redirect ───────────────────────────────────────────────────────
  { id: 'express.res.redirect', calleePath: ['res', 'redirect'], dangerousArgs: [0], danger: 'redirect', description: 'Express res.redirect with user-controlled URL — open-redirect vector' },
  { id: 'koa.ctx.redirect',     calleePath: ['ctx', 'redirect'], dangerousArgs: [0], danger: 'redirect', description: 'Koa ctx.redirect with user-controlled URL' },

  // ── XSS / response write (Kaioken VIII) ────────────────────────────────
  // res.json deliberately NOT a sink (API JSON would FP massively).
  { id: 'express.res.send',  calleePath: ['res', 'send'],  dangerousArgs: [0], danger: 'template-injection', description: 'Express res.send with user-controlled body — XSS when HTML is rendered' },
  { id: 'express.res.write', calleePath: ['res', 'write'], dangerousArgs: [0], danger: 'template-injection', description: 'Express res.write with user-controlled body — XSS' },
  { id: 'express.res.end',   calleePath: ['res', 'end'],   dangerousArgs: [0], danger: 'template-injection', description: 'Express res.end with user-controlled body — XSS' },
  // Kaioken LI — Content-Type / misinterpretation from attacker-controlled type
  { id: 'express.res.type',  calleePath: ['res', 'type'],  dangerousArgs: [0], danger: 'template-injection', description: 'Express res.type with user-controlled MIME — content-type misinterpretation' },
  { id: 'express.res.contentType', calleePath: ['res', 'contentType'], dangerousArgs: [0], danger: 'template-injection', description: 'Express res.contentType with user-controlled MIME' },
  { id: 'koa.ctx.body',      calleePath: ['ctx', 'body'],  dangerousArgs: [0], danger: 'template-injection', description: 'Koa ctx.body assignment via call shape — XSS' },

  // ── Header / cookie injection (CRLF) ───────────────────────────────────
  { id: 'express.res.set',       calleePath: ['res', 'set'],       dangerousArgs: [1], danger: 'template-injection', description: 'Express res.set header value — CRLF / response-split when tainted' },
  { id: 'express.res.header',    calleePath: ['res', 'header'],    dangerousArgs: [1], danger: 'template-injection', description: 'Express res.header — CRLF injection' },
  { id: 'express.res.setHeader', calleePath: ['res', 'setHeader'], dangerousArgs: [1], danger: 'template-injection', description: 'Express res.setHeader — CRLF injection' },
  { id: 'express.res.append',    calleePath: ['res', 'append'],    dangerousArgs: [1], danger: 'template-injection', description: 'Express res.append header — CRLF injection' },
  { id: 'express.res.cookie',    calleePath: ['res', 'cookie'],    dangerousArgs: [1], danger: 'template-injection', description: 'Express res.cookie with user-controlled value — cookie injection' },
  // Kaioken XLV — Koa response API (BP koa corpus uses these, not res.*)
  { id: 'koa.ctx.set',           calleePath: ['ctx', 'set'],           dangerousArgs: [1], danger: 'template-injection', description: 'Koa ctx.set header value — CRLF / CORS / clickjacking when tainted' },
  { id: 'koa.ctx.cookies.set',   calleePath: ['ctx', 'cookies', 'set'], dangerousArgs: [1], danger: 'template-injection', description: 'Koa ctx.cookies.set with user-controlled value — cookie injection / missing flags' },

  // ── Log injection ──────────────────────────────────────────────────────
  { id: 'console.log',   calleePath: ['console', 'log'],   dangerousArgs: [0, 1, 2], danger: 'template-injection', description: 'console.log with user-controlled data — log injection' },
  { id: 'console.error', calleePath: ['console', 'error'], dangerousArgs: [0, 1, 2], danger: 'template-injection', description: 'console.error — log injection' },
  { id: 'console.info',  calleePath: ['console', 'info'],  dangerousArgs: [0, 1, 2], danger: 'template-injection', description: 'console.info — log injection' },
  { id: 'console.warn',  calleePath: ['console', 'warn'],  dangerousArgs: [0, 1, 2], danger: 'template-injection', description: 'console.warn — log injection' },

  // ── NoSQL (Mongo-style) ────────────────────────────────────────────────
  { id: 'db.collection.findOne', calleePath: ['db', 'collection', 'findOne'], dangerousArgs: [0], danger: 'sql-injection', description: 'db.collection().findOne with user filter — NoSQL injection' },
  { id: 'db.collection.find',    calleePath: ['db', 'collection', 'find'],    dangerousArgs: [0], danger: 'sql-injection', description: 'db.collection().find with user filter — NoSQL injection' },
  { id: 'findOne.bare',          calleePath: ['findOne'],                     dangerousArgs: [0], danger: 'sql-injection', description: 'findOne(filter) with user-controlled filter — NoSQL injection' },
  { id: 'find.bare',             calleePath: ['find'],                        dangerousArgs: [0], danger: 'sql-injection', description: 'find(filter) with user-controlled filter — NoSQL injection' },

  // ── Resource exhaustion (Kaioken IX) ───────────────────────────────────
  { id: 'Buffer.alloc',       calleePath: ['Buffer', 'alloc'],       dangerousArgs: [0], danger: 'ssrf', description: 'Buffer.alloc with user-controlled size — resource exhaustion' },
  { id: 'Buffer.allocUnsafe', calleePath: ['Buffer', 'allocUnsafe'], dangerousArgs: [0], danger: 'ssrf', description: 'Buffer.allocUnsafe with user-controlled size — resource exhaustion' },
  // Kaioken XLVIII — array/buffer index OOB (BP array_index_oob)
  { id: 'Buffer.readUInt8',   calleePath: ['Buffer', 'readUInt8'],   dangerousArgs: [0], danger: 'ssrf', description: 'Buffer.readUInt8 with user-controlled index — OOB read' },
  { id: 'buf.readUInt8',      calleePath: ['readUInt8'],             dangerousArgs: [0], danger: 'ssrf', description: 'buf.readUInt8(taintIndex) — OOB' },
  { id: 'buf.readInt8',       calleePath: ['readInt8'],              dangerousArgs: [0], danger: 'ssrf', description: 'buf.readInt8(taintIndex)' },
  { id: 'buf.readUInt16LE',   calleePath: ['readUInt16LE'],          dangerousArgs: [0], danger: 'ssrf', description: 'buf.readUInt16LE(taintIndex)' },
  { id: 'buf.readUInt32LE',   calleePath: ['readUInt32LE'],          dangerousArgs: [0], danger: 'ssrf', description: 'buf.readUInt32LE(taintIndex)' },
  // Weak hash (md5/sha1) handled in analyzer — createHash().update(taint) chain

  // ── SSRF (server-side request forgery) ─────────────────────────────────
  { id: 'http.get',     calleePath: ['http', 'get'],     dangerousArgs: [0], danger: 'ssrf', description: 'http.get with user-controlled URL — SSRF vector' },
  // Kaioken XLVIII — cloud object storage writes (BP normal cloud_storage_write)
  { id: 's3.putObject',     calleePath: ['s3', 'putObject'],     dangerousArgs: [0, 1], danger: 'ssrf', description: 'S3 putObject with user-controlled bucket/key' },
  { id: 'S3.putObject',     calleePath: ['S3', 'putObject'],     dangerousArgs: [0, 1], danger: 'ssrf', description: 'S3.putObject' },
  { id: 's3.upload',        calleePath: ['s3', 'upload'],        dangerousArgs: [0, 1], danger: 'ssrf', description: 'S3 upload with user-controlled key' },
  { id: 'http.request', calleePath: ['http', 'request'], dangerousArgs: [0], danger: 'ssrf', description: 'http.request with user-controlled URL' },
  { id: 'https.get',     calleePath: ['https', 'get'],     dangerousArgs: [0], danger: 'ssrf', description: 'https.get with user-controlled URL' },
  { id: 'https.request', calleePath: ['https', 'request'], dangerousArgs: [0], danger: 'ssrf', description: 'https.request with user-controlled URL' },
  { id: 'axios',         calleePath: ['axios'],             dangerousArgs: [0], danger: 'ssrf', description: 'axios(url) with user-controlled URL' },
  { id: 'axios.get',     calleePath: ['axios', 'get'],      dangerousArgs: [0], danger: 'ssrf', description: 'axios.get(url) with user-controlled URL' },
  { id: 'axios.post',    calleePath: ['axios', 'post'],     dangerousArgs: [0], danger: 'ssrf', description: 'axios.post(url) with user-controlled URL' },
  { id: 'fetch',         calleePath: ['fetch'],             dangerousArgs: [0], danger: 'ssrf', description: 'fetch(url) with user-controlled URL' },
  // net.connect(port, host) — host is often arg 1
  { id: 'net.connect',   calleePath: ['net', 'connect'],    dangerousArgs: [0, 1], danger: 'ssrf', description: 'net.connect with user-controlled host — SSRF' },
  { id: 'connect.bare',  calleePath: ['connect'],           dangerousArgs: [0, 1], danger: 'ssrf', description: 'bare connect() — often net.connect' },
  // Cloud / queue / storage (BenchProctor shared stubs)
  { id: 's3.putObject',     calleePath: ['s3', 'putObject'],     dangerousArgs: [1, 2], danger: 'ssrf', description: 's3.putObject with user-controlled key/body' },
  { id: 's3.getObjectSync', calleePath: ['s3', 'getObjectSync'], dangerousArgs: [1], danger: 'ssrf', description: 's3.getObjectSync with user-controlled key' },
  { id: 'sqs.sendMessage',  calleePath: ['sqs', 'sendMessage'],  dangerousArgs: [0, 1], danger: 'ssrf', description: 'sqs.sendMessage with user-controlled queue/body' },
  // roleArn only — sessionName taint is not CWE-269 in BP (safes fix ARN, vary session)
  { id: 'sts.assumeRole',   calleePath: ['sts', 'assumeRole'],   dangerousArgs: [0], danger: 'ssrf', description: 'sts.assumeRole with user-controlled roleArn' },
  { id: 'iam.putRolePolicy', calleePath: ['iam', 'putRolePolicy'], dangerousArgs: [0, 2], danger: 'ssrf', description: 'iam.putRolePolicy with user-controlled role/doc' },

  // ── XXE / XML ──
  { id: 'libxmljs.parseXml', calleePath: ['libxmljs', 'parseXml'], dangerousArgs: [0], danger: 'code-execution', description: 'libxmljs.parseXml with user-controlled XML — XXE risk when entities enabled' },
  { id: 'libxmljs.parseXmlString', calleePath: ['libxmljs', 'parseXmlString'], dangerousArgs: [0], danger: 'code-execution', description: 'libxmljs.parseXmlString — XXE risk' },

  // ── Unsafe deserialization ──
  { id: 'node-serialize.unserialize', calleePath: ['nodeSerialize', 'unserialize'], dangerousArgs: [0], danger: 'code-execution', description: 'node-serialize.unserialize — RCE via crafted payload' },
  { id: 'node-serialize.pkg',         calleePath: ['node-serialize', 'unserialize'], dangerousArgs: [0], danger: 'code-execution', description: 'node-serialize package path unserialize' },
  { id: 'unserialize.bare',           calleePath: ['unserialize'],                  dangerousArgs: [0], danger: 'code-execution', description: 'bare unserialize() — typically node-serialize import' },
  { id: 'serialize-javascript',       calleePath: ['serialize'],                    dangerousArgs: [0], danger: 'code-execution', description: 'unsafe serialize/deserialize pair when paired with eval-style revive' },
  { id: 'js-yaml.load',               calleePath: ['yaml', 'load'],                 dangerousArgs: [0], danger: 'code-execution', description: 'js-yaml load without SAFE_SCHEMA' },
  { id: 'jsyaml.load',                calleePath: ['jsyaml', 'load'],               dangerousArgs: [0], danger: 'code-execution', description: 'js-yaml load alias' },
  { id: 'js-yaml.pkg',                calleePath: ['js-yaml', 'load'],              dangerousArgs: [0], danger: 'code-execution', description: 'js-yaml package path load' },
  // Note: res.send/res.write deliberately NOT sinks — API JSON responses would FP massively.
  // Python sinks live in catalog/python.ts — do not merge them here.
];

export const JAVASCRIPT_SANITIZERS: Sanitizer[] = [
  // Type coercion sanitizers — effective against code-execution because the
  // output can no longer be interpreted as code.
  { id: 'JSON.stringify',     calleePath: ['JSON', 'stringify'], sanitizesArgs: [0], against: ['code-execution', 'template-injection'], description: 'JSON.stringify escapes string literals so they survive re-parse as data, not code' },
  { id: 'Number',             calleePath: ['Number'],             sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection'], description: 'Number() coerces to numeric — strips any string payload' },
  { id: 'parseInt',           calleePath: ['parseInt'],           sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection'], description: 'parseInt() extracts a leading integer and discards the rest' },
  { id: 'parseFloat',         calleePath: ['parseFloat'],         sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection'], description: 'parseFloat() extracts a leading number and discards the rest' },
  { id: 'Boolean',            calleePath: ['Boolean'],            sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection', 'template-injection'], description: 'Boolean() coerces to bool' },
  { id: 'BigInt',             calleePath: ['BigInt'],             sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection'], description: 'BigInt() coerces to integer type' },

  // URL / HTML encoders
  // Kaioken IX: encodeURIComponent does NOT clear path-traversal/ssrf-class fs sinks
  // (BP vuln twins still encodeURIComponent path segments). Only softens redirects.
  { id: 'encodeURIComponent', calleePath: ['encodeURIComponent'], sanitizesArgs: [0], against: ['redirect'], description: 'Percent-encodes URL-unsafe characters; does not prevent code execution or path traversal' },
  { id: 'encodeURI',          calleePath: ['encodeURI'],          sanitizesArgs: [0], against: ['redirect'], description: 'Percent-encodes URLs preserving reserved chars; partial sanitation' },
  { id: 'escape',             calleePath: ['escape'],             sanitizesArgs: [0], against: ['template-injection'], description: 'legacy escape() — weak HTML; treated as template-only' },
  { id: 'he.encode',          calleePath: ['he', 'encode'],       sanitizesArgs: [0], against: ['template-injection'], description: 'he.encode HTML entity encode' },
  { id: 'lodash.escape',      calleePath: ['_', 'escape'],        sanitizesArgs: [0], against: ['template-injection'], description: 'lodash _.escape' },
  { id: 'DOMPurify.sanitize', calleePath: ['DOMPurify', 'sanitize'], sanitizesArgs: [0], against: ['template-injection'], description: 'DOMPurify.sanitize' },
  { id: 'isoDompurify.sanitize', calleePath: ['isoDompurify', 'sanitize'], sanitizesArgs: [0], against: ['template-injection'], description: 'isomorphic-dompurify local alias .sanitize' },

  // SQL escapers
  { id: 'mysql.escape',       calleePath: ['mysql', 'escape'],    sanitizesArgs: [0], against: ['sql-injection'],           description: 'node-mysql.escape — quotes values for SQL; does not prevent identifier injection' },
  { id: 'mysql2.escape',      calleePath: ['mysql2', 'escape'],   sanitizesArgs: [0], against: ['sql-injection'],           description: 'mysql2.escape' },
  { id: 'pg-escape.literal',  calleePath: ['pgEscape', 'literal'], sanitizesArgs: [0], against: ['sql-injection'],          description: 'pg-escape.literal — quotes values for Postgres' },
  { id: 'sqlstring.escape',   calleePath: ['SqlString', 'escape'], sanitizesArgs: [0], against: ['sql-injection'], description: 'sqlstring.escape' },

  // Shell escapers
  { id: 'shell-escape',       calleePath: ['shellEscape'],        sanitizesArgs: [0], against: ['command-injection'],       description: 'Caller-provided shell escaping; matched by function name as used in most ecosystems' },
  { id: 'shlex-quote',        calleePath: ['shlex', 'quote'],     sanitizesArgs: [0], against: ['command-injection'],       description: 'shlex.quote equivalent' },
  { id: 'shell-quote.quote',  calleePath: ['shellQuote', 'quote'], sanitizesArgs: [0], against: ['command-injection'], description: 'shell-quote.quote' },

  // Path validators
  // Kaioken XIX: path.normalize/resolve are NOT full sanitizers for BP path traversal
  // (vuln twins still path.normalize(user) then fs.write). basename still strips dirs.
  { id: 'path.basename',      calleePath: ['path', 'basename'],   sanitizesArgs: [0], against: ['ssrf'], description: 'path.basename — strips directory components' },
  // BenchProctor shared.escapeHtml + common HTML encoders
  { id: 'escapeHtml',         calleePath: ['escapeHtml'],         sanitizesArgs: [0], against: ['template-injection'], description: 'escapeHtml — HTML entity encode' },
  { id: 'he.encode',          calleePath: ['he', 'encode'],       sanitizesArgs: [0], against: ['template-injection'], description: 'he.encode' },

  // Validator libraries (common Node)
  { id: 'validator.escape',   calleePath: ['validator', 'escape'], sanitizesArgs: [0], against: ['template-injection'], description: 'validator.escape' },
  { id: 'validator.toInt',    calleePath: ['validator', 'toInt'],  sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection'], description: 'validator.toInt' },
  { id: 'validator.toFloat',  calleePath: ['validator', 'toFloat'], sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection'], description: 'validator.toFloat' },
  { id: 'validator.toBoolean', calleePath: ['validator', 'toBoolean'], sanitizesArgs: [0], against: ['code-execution', 'sql-injection', 'command-injection'], description: 'validator.toBoolean' },

  // Parameterized query builders — passing user input through these isn't a
  // concatenation sink, so we treat the result as safe for sql-injection.
  { id: 'sequelize.escape',   calleePath: ['sequelize', 'escape'],sanitizesArgs: [0], against: ['sql-injection'],           description: 'sequelize.escape — quotes identifier/value for Sequelize' },

  // UUID / hash (output is not attacker-controlled structure for injection)
  { id: 'crypto.createHash',  calleePath: ['crypto', 'createHash'], sanitizesArgs: [], against: [], description: 'createHash itself is not a value sanitizer — listed for completeness' },
  // Kaioken XXXI — password hashing clears cleartext-storage class (not a secret dump)
  { id: 'crypto.pbkdf2Sync',  calleePath: ['crypto', 'pbkdf2Sync'], sanitizesArgs: [0], against: ['ssrf', 'code-execution', 'sql-injection', 'command-injection', 'template-injection', 'redirect'], description: 'pbkdf2Sync — password hash, not cleartext storage of the secret' },
  { id: 'crypto.pbkdf2',      calleePath: ['crypto', 'pbkdf2'],     sanitizesArgs: [0], against: ['ssrf', 'code-execution', 'sql-injection', 'command-injection', 'template-injection', 'redirect'], description: 'pbkdf2 — password hash' },
  { id: 'crypto.scryptSync',  calleePath: ['crypto', 'scryptSync'], sanitizesArgs: [0], against: ['ssrf', 'code-execution', 'sql-injection', 'command-injection', 'template-injection', 'redirect'], description: 'scryptSync password hash' },
  { id: 'bcrypt.hashSync',    calleePath: ['bcrypt', 'hashSync'],   sanitizesArgs: [0], against: ['ssrf', 'code-execution', 'sql-injection', 'command-injection', 'template-injection', 'redirect'], description: 'bcrypt.hashSync' },
];

/**
 * JS-only suffix / import-aware sink matching. Lives in the JS catalog so
 * analyzer.ts does not grow a third language-guard layer. Python/Java add
 * their own matchSinkExtra instead.
 */
export function matchJavascriptSinkExtra(
  path: string[],
  imports: ModuleImport[]
): TaintSink | null {
  const tail = path[path.length - 1];
  if (
    tail &&
    /^(readUInt8|readInt8|readUInt16LE|readUInt16BE|readUInt32LE|readUInt32BE|readInt16LE|readInt32LE)$/.test(
      tail
    )
  ) {
    return {
      id: `buf.${tail}`,
      calleePath: path,
      dangerousArgs: [0],
      danger: 'ssrf',
      description: `Buffer.${tail} with user-controlled index — array/buffer OOB`,
    };
  }
  if (path.length >= 2 && path[path.length - 1] === 'putObject') {
    return {
      id: 's3.putObject',
      calleePath: path,
      dangerousArgs: [0, 1],
      danger: 'ssrf',
      description: 'S3 putObject with user-controlled bucket/key — cloud storage write',
    };
  }
  if (path.length >= 2 && path[path.length - 1] === 'sendMessage') {
    return {
      id: 'sqs.sendMessage',
      calleePath: path,
      dangerousArgs: [0, 1],
      danger: 'ssrf',
      description: 'SQS sendMessage with user-controlled queue/body — cloud queue publish',
    };
  }
  if (path.length >= 1 && path[path.length - 1] === 'putRolePolicy') {
    return {
      id: 'iam.putRolePolicy',
      calleePath: path,
      dangerousArgs: [0, 2],
      danger: 'ssrf',
      description:
        'iam.putRolePolicy with user-controlled role/policy document — cloud IAM write / privilege management',
    };
  }
  if (path.length >= 1 && path[path.length - 1] === 'assumeRole') {
    return {
      id: 'sts.assumeRole',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'ssrf',
      description: 'sts.assumeRole with user-controlled role ARN — cloud IAM privilege escalation',
    };
  }
  if (path.length >= 1 && path[path.length - 1] === 'unserialize') {
    return {
      id: 'unserialize.any',
      calleePath: path,
      dangerousArgs: [0],
      danger: 'code-execution',
      description: 'unserialize() — unsafe deserialization, RCE via crafted payload',
    };
  }
  if (path.length >= 1 && path[path.length - 1] === 'search') {
    const hasLdap = imports.some(
      i => /ldap/i.test(i.specifier) || /ldap/i.test(i.localName)
    );
    if (hasLdap) {
      return {
        id: 'ldap.search.any',
        calleePath: path,
        dangerousArgs: [0, 1],
        danger: 'sql-injection',
        description: 'LDAP search with user-controlled DN/filter — LDAP injection',
      };
    }
  }
  if (path.length >= 1 && (path[path.length - 1] === 'findOne' || path[path.length - 1] === 'find')) {
    const root = path[0] || '';
    if (
      root === '_' ||
      root === 'lodash' ||
      root === 'underscore' ||
      root === 'R' ||
      root === 'ramda' ||
      /^_\./.test(root)
    ) {
      return null;
    }
    if (path[path.length - 1] === 'find' && path.length < 2) {
      return null;
    }
    return {
      id: `nosql.${path[path.length - 1]}`,
      calleePath: path,
      dangerousArgs: [0],
      danger: 'sql-injection',
      description: `Mongo-style ${path[path.length - 1]}(filter) with user-controlled filter — NoSQL injection`,
    };
  }
  if (path.length >= 1 && path[path.length - 1] === 'authCheck') {
    return {
      id: 'authCheck',
      calleePath: path,
      dangerousArgs: [0, 1],
      danger: 'code-execution',
      description:
        'authCheck(user, token) with attacker-controlled credential — authn weakness / no rate limit surface',
    };
  }
  return null;
}

export function matchJavascriptSanitizerExtra(
  path: string[],
  _imports: ModuleImport[]
): Sanitizer | null {
  if (path.length >= 1 && path[path.length - 1] === 'escapeHtml') {
    return {
      id: 'escapeHtml',
      calleePath: path,
      sanitizesArgs: [0],
      against: ['template-injection'],
      description: 'escapeHtml — HTML entity encode',
    };
  }
  return null;
}

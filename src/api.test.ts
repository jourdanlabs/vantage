// HTTP door correctness. Run with:
//   npx ts-node src/api.test.ts
//
// Does not boot the real pipeline. Does not listen on 7474.

import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import {
  createApp,
  listen,
  resolveAllowedPath,
  tokensEqual,
} from './api';

const TOKEN = 'test-token-not-for-production';
let pass = 0;
let fail = 0;

function assert(name: string, ok: boolean, detail?: string): void {
  if (ok) {
    console.log(`  ✓ ${name}`);
    pass++;
  } else {
    console.log(`  ✗ ${name}${detail ? `\n    ${detail}` : ''}`);
    fail++;
  }
}

type Hit = {
  status: number;
  body: any;
  headers: http.IncomingHttpHeaders;
};

function hit(
  app: ReturnType<typeof createApp>,
  opts: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: unknown;
  }
): Promise<Hit> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        server.close();
        reject(new Error('no port'));
        return;
      }
      const payload = opts.body === undefined ? '' : JSON.stringify(opts.body);
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: addr.port,
          method: opts.method,
          path: opts.url,
          headers: {
            ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
            ...opts.headers,
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c) => chunks.push(c as Buffer));
          res.on('end', () => {
            server.close();
            const raw = Buffer.concat(chunks).toString('utf8');
            let body: any = {};
            try {
              body = raw ? JSON.parse(raw) : {};
            } catch {
              body = { raw };
            }
            resolve({ status: res.statusCode ?? 0, body, headers: res.headers });
          });
        }
      );
      req.on('error', (err) => {
        server.close();
        reject(err);
      });
      if (payload) req.write(payload);
      req.end();
    });
  });
}

async function main(): Promise<void> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vantage-api-'));
  fs.writeFileSync(path.join(root, 'keep.txt'), 'ok');
  const calls: Array<{ target: string; engine: unknown }> = [];
  const stubPipeline = async (target: string, engine: any = null) => {
    calls.push({ target, engine });
    return {
      target,
      timestamp: 'now',
      meteor: {
        files: [],
        metrics: {
          linesOfCode: 0,
          totalComplexity: 0,
          todoCount: 0,
          largeFunctions: [],
          highComplexityFunctions: [],
        },
      },
      aurora: { topIssues: [] },
    };
  };

  const app = createApp({
    token: TOKEN,
    allowedRoot: root,
    runPipeline: stubPipeline as any,
  });

  const health = await hit(app, { method: 'GET', url: '/vantage/health' });
  assert('health is unauthenticated 200', health.status === 200 && health.body.status === 'ok');

  const noAuth = await hit(app, {
    method: 'POST',
    url: '/vantage/analyze',
    body: { path: root },
  });
  assert('analyze without Bearer is 401', noAuth.status === 401);

  const badAuth = await hit(app, {
    method: 'POST',
    url: '/vantage/analyze',
    headers: { authorization: 'Bearer wrong' },
    body: { path: root },
  });
  assert('analyze with wrong Bearer is 401', badAuth.status === 401);

  const quickNoAuth = await hit(app, {
    method: 'POST',
    url: '/vantage/quick',
    body: { path: root },
  });
  assert('quick without Bearer is 401', quickNoAuth.status === 401);

  const outside = await hit(app, {
    method: 'POST',
    url: '/vantage/analyze',
    headers: { authorization: `Bearer ${TOKEN}` },
    body: { path: '/etc/passwd' },
  });
  assert('path outside allowlist is 403', outside.status === 403);
  assert('outside path did not invoke pipeline', calls.length === 0);

  const missing = await hit(app, {
    method: 'POST',
    url: '/vantage/analyze',
    headers: { authorization: `Bearer ${TOKEN}` },
    body: {},
  });
  assert('missing path is 400', missing.status === 400);

  const okAnalyze = await hit(app, {
    method: 'POST',
    url: '/vantage/analyze',
    headers: { authorization: `Bearer ${TOKEN}` },
    body: { path: root },
  });
  assert('analyze with token + in-root path is 200', okAnalyze.status === 200 && okAnalyze.body.success === true);
  assert('analyze invoked stub pipeline once', calls.length === 1 && calls[0].target === fs.realpathSync(root));

  const okQuick = await hit(app, {
    method: 'POST',
    url: '/vantage/quick',
    headers: { authorization: `Bearer ${TOKEN}` },
    body: { path: '.' },
  });
  assert('quick with relative in-root path is 200', okQuick.status === 200 && okQuick.body.success === true);

  const evilCors = await hit(app, {
    method: 'GET',
    url: '/vantage/health',
    headers: { origin: 'https://evil.example' },
  });
  const acao = String(evilCors.headers['access-control-allow-origin'] ?? '');
  assert('non-localhost Origin does not get ACAO', acao !== 'https://evil.example');

  const localCors = await hit(app, {
    method: 'GET',
    url: '/vantage/health',
    headers: { origin: 'http://127.0.0.1:3000' },
  });
  assert(
    'localhost Origin is allowed',
    localCors.headers['access-control-allow-origin'] === 'http://127.0.0.1:3000'
  );

  let listenThrew = false;
  try {
    listen({ token: '   ' });
  } catch (err: any) {
    listenThrew = /VANTAGE_API_TOKEN is required/.test(err.message);
  }
  assert('listen refuses when token unset', listenThrew);

  let bindThrew = false;
  try {
    listen({ token: TOKEN, host: '0.0.0.0' });
  } catch (err: any) {
    bindThrew = /127\.0\.0\.1 or localhost/.test(err.message);
  }
  assert('listen refuses non-loopback bind', bindThrew);

  assert('tokensEqual accepts matching secrets', tokensEqual('abc', 'abc'));
  assert('tokensEqual rejects mismatch', !tokensEqual('abc', 'abd'));

  const allowed = resolveAllowedPath(path.join(root, 'keep.txt'), root);
  assert('resolveAllowedPath accepts in-root file', allowed.ok === true);

  const denied = resolveAllowedPath('/etc/passwd', root);
  assert(
    'resolveAllowedPath denies absolute escape',
    denied.ok === false && denied.status === 403
  );

  const traversal = resolveAllowedPath(path.join(root, '..', 'nope'), root);
  assert(
    'resolveAllowedPath denies .. escape',
    traversal.ok === false && traversal.status === 403
  );

  fs.rmSync(root, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

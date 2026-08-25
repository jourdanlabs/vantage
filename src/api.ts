/**
 * VANTAGE HTTP surface — optional local door, not the product path.
 *
 * Product path is CLI + MCP (`vantage` / `vantage-mcp`). This file is the extra
 * Express listener that used to bind all interfaces on 7474 with no auth and
 * take a filesystem path from the request body.
 *
 * POST /vantage/analyze  — full pipeline (Bearer required)
 * POST /vantage/quick    — METEOR only (Bearer required)
 * GET  /vantage/health   — liveness on loopback (no FS, no auth)
 *
 * Listen refuses to start unless VANTAGE_API_TOKEN is set. Bind is loopback only.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import { runPipeline, EngineFilter } from './engines/index';

export const DEFAULT_API_PORT = 7474;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost']);
const LOCAL_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i;

export type PipelineFn = typeof runPipeline;

export interface ApiOptions {
  token?: string;
  allowedRoot?: string;
  runPipeline?: PipelineFn;
}

function configuredToken(explicit?: string): string {
  const raw = explicit ?? process.env.VANTAGE_API_TOKEN ?? '';
  return raw.trim();
}

function configuredRoot(explicit?: string): string {
  const raw = explicit ?? process.env.VANTAGE_ALLOWED_ROOT ?? process.cwd();
  return path.resolve(raw);
}

/** Constant-time compare of two secrets. Length mismatch still hashes both sides. */
export function tokensEqual(provided: string, expected: string): boolean {
  const a = crypto.createHash('sha256').update(provided, 'utf8').digest();
  const b = crypto.createHash('sha256').update(expected, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}

function audit(event: string, req: Request, extra?: string): void {
  const suffix = extra ? ` ${extra}` : '';
  console.warn(`[VANTAGE API] ${event} ${req.method} ${req.path}${suffix}`);
}

/**
 * Bearer shared-secret check. Named `authenticate` so CRUCIBLE GAP_NO_AUTH
 * sees a real middleware, not a comment. Scheme is env token — the repo had
 * no existing auth library on this surface; this is not OAuth.
 */
export function authenticate(token: string) {
  return function authenticate(req: Request, res: Response, next: NextFunction): void {
    if (!token) {
      audit('auth_unconfigured', req);
      res.status(503).json({ error: 'API token not configured' });
      return;
    }
    const header = req.headers.authorization ?? '';
    const match = /^Bearer\s+(\S+)$/i.exec(header);
    const provided = match ? match[1] : '';
    if (!provided || !tokensEqual(provided, token)) {
      audit('auth_failed', req);
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };
}

export type PathResolution =
  | { ok: true; path: string }
  | { ok: false; status: 400 | 403; error: string };

/**
 * Resolve a request path and refuse anything outside allowedRoot.
 * Existing paths go through realpath to block symlink escape.
 */
export function resolveAllowedPath(targetPath: string | undefined, allowedRoot: string): PathResolution {
  if (!targetPath || typeof targetPath !== 'string') {
    return { ok: false, status: 400, error: 'Missing path' };
  }

  const rootReal = fs.existsSync(allowedRoot)
    ? fs.realpathSync(allowedRoot)
    : path.resolve(allowedRoot);
  const candidate = path.resolve(rootReal, targetPath);

  let resolved = candidate;
  try {
    if (fs.existsSync(candidate)) {
      resolved = fs.realpathSync(candidate);
    }
  } catch {
    return { ok: false, status: 403, error: 'Path not allowed' };
  }

  const prefix = rootReal.endsWith(path.sep) ? rootReal : rootReal + path.sep;
  if (resolved !== rootReal && !resolved.startsWith(prefix)) {
    return { ok: false, status: 403, error: 'Path not allowed' };
  }
  return { ok: true, path: resolved };
}

function corsOrigin(origin: string | undefined, cb: (err: Error | null, allow?: boolean) => void): void {
  if (!origin) {
    cb(null, true);
    return;
  }
  cb(null, LOCAL_ORIGIN.test(origin));
}

export function createApp(opts: ApiOptions = {}) {
  const token = configuredToken(opts.token);
  const allowedRoot = configuredRoot(opts.allowedRoot);
  const pipeline: PipelineFn = opts.runPipeline ?? runPipeline;

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));
  app.use(cors({ origin: corsOrigin }));

  app.get('/vantage/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      engine: 'VANTAGE',
      pipeline: ['METEOR', 'NOVA', 'ECLIPSE', 'PULSAR', 'AURORA'],
      bind: 'loopback',
    });
  });

  const requireAuth = authenticate(token);

  app.post('/vantage/analyze', requireAuth, async (req: Request, res: Response) => {
    const { path: targetPath, engine, threshold } = req.body as {
      path?: string;
      engine?: EngineFilter;
      threshold?: number;
    };

    const allowed = resolveAllowedPath(targetPath, allowedRoot);
    if (allowed.ok === false) {
      audit('path_denied', req, allowed.error);
      return res.status(allowed.status).json({ error: allowed.error });
    }

    const resolvedThreshold = (typeof threshold === 'number' && threshold > 0 && threshold <= 1)
      ? threshold
      : 0.80;

    const logs: string[] = [];

    try {
      const report = await pipeline(
        allowed.path,
        engine ?? null,
        (eng, msg) => {
          logs.push(`[${eng}] ${msg}`);
          console.log(`[VANTAGE] [${eng}] ${msg}`);
        },
        resolvedThreshold
      );

      return res.json({
        success: true,
        data: report,
        logs,
      });
    } catch (err: any) {
      return res.status(500).json({ success: false, error: err.message, logs });
    }
  });

  app.post('/vantage/quick', requireAuth, async (req: Request, res: Response) => {
    const { path: targetPath } = req.body as { path?: string };

    const allowed = resolveAllowedPath(targetPath, allowedRoot);
    if (allowed.ok === false) {
      audit('path_denied', req, allowed.error);
      return res.status(allowed.status).json({ error: allowed.error });
    }

    try {
      const report = await pipeline(allowed.path, 'METEOR');
      const { meteor, aurora } = report;

      const quickAurora = {
        skipped: true,
        summary: 'METEOR only run — no aurora scoring',
        verdict: 'SKIPPED' as const,
        topIssues: aurora?.topIssues ?? [],
      };

      return res.json({
        success: true,
        data: {
          target: report.target,
          timestamp: report.timestamp,
          summary: {
            files: meteor.files.length,
            linesOfCode: meteor.metrics.linesOfCode,
            totalComplexity: meteor.metrics.totalComplexity,
            todos: meteor.metrics.todoCount,
            largeFunctions: meteor.metrics.largeFunctions.length,
            highComplexityFunctions: meteor.metrics.highComplexityFunctions.length,
          },
          aurora: quickAurora,
        },
      });
    } catch (err: any) {
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  return app;
}

export interface ListenOptions extends ApiOptions {
  host?: string;
  port?: number;
}

/**
 * Start the HTTP door. Refuses if the token is unset. Refuses non-loopback bind.
 * Does not listen on import — tests import createApp without opening a port.
 */
export function listen(opts: ListenOptions = {}) {
  const token = configuredToken(opts.token);
  if (!token) {
    throw new Error('VANTAGE_API_TOKEN is required; refusing to listen on an unauthenticated socket');
  }

  const host = opts.host ?? process.env.VANTAGE_API_HOST ?? '127.0.0.1';
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error(`VANTAGE_API_HOST must be 127.0.0.1 or localhost (got ${host})`);
  }

  const port = opts.port ?? Number(process.env.VANTAGE_API_PORT || DEFAULT_API_PORT);
  const app = createApp(opts);
  return app.listen(port, host, () => {
    console.log(`[VANTAGE API] listening on ${host}:${port}`);
  });
}

if (require.main === module) {
  listen();
}

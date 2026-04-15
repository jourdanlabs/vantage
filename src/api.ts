/**
 * VANTAGE API — HTTP interface for VANTAGE COSMIC pipeline
 *
 * POST /vantage/analyze   — full pipeline run on a target path
 * POST /vantage/quick     — single engine (METEOR only, fast)
 * GET  /vantage/health    — health check
 *
 * Port: 7474
 */

import express, { Request, Response } from 'express';
import cors from 'cors';
import { runPipeline, EngineFilter } from './engines/index';

const app = express();
app.use(express.json());
app.use(cors());

// ── Health ─────────────────────────────────────────────────────────────────

app.get('/vantage/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', engine: 'VANTAGE', pipeline: ['METEOR', 'NOVA', 'ECLIPSE', 'PULSAR', 'AURORA'] });
});

// ── POST /vantage/analyze ──────────────────────────────────────────────────
// Full pipeline run. Accepts a target path and optional engine filter.

app.post('/vantage/analyze', async (req: Request, res: Response) => {
  const { path: targetPath, engine } = req.body as { path?: string; engine?: EngineFilter };

  if (!targetPath) {
    return res.status(400).json({ error: 'Missing path' });
  }

  const logs: string[] = [];

  try {
    const report = await runPipeline(
      targetPath,
      engine ?? null,
      (eng, msg) => {
        logs.push(`[${eng}] ${msg}`);
        console.log(`[VANTAGE] [${eng}] ${msg}`);
      }
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

// ── POST /vantage/quick ────────────────────────────────────────────────────
// METEOR-only fast scan. Returns entity graph without full pipeline cost.

app.post('/vantage/quick', async (req: Request, res: Response) => {
  const { path: targetPath } = req.body as { path?: string };

  if (!targetPath) {
    return res.status(400).json({ error: 'Missing path' });
  }

  try {
    const report = await runPipeline(targetPath, 'METEOR');
    const { meteor, aurora } = report;

    // METEOR-only run: aurora hasn't been computed, so don't expose a false score/verdict.
    // Consumers should check aurora.skipped === true and treat as neutral (no penalty).
    const quickAurora = {
      skipped: true,
      summary: "METEOR only run — no aurora scoring",
      verdict: "SKIPPED" as const,
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

// ── Start ──────────────────────────────────────────────────────────────────

const PORT = 7474;
app.listen(PORT, () => {
  console.log(`[VANTAGE API] running on port ${PORT}`);
});

export { app };

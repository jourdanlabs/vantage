// VANTAGE MCP — zod input schemas for all tools

import { z } from 'zod';

export const AnalyzeInput = z.object({
  target_path: z.string().describe('Absolute or relative path to the project or directory to analyze'),
  options: z.object({
    engine: z.enum(['METEOR', 'NOVA', 'ECLIPSE', 'PULSAR', 'NEBULA', 'AURORA']).optional()
      .describe('Run only a specific engine (default: full pipeline)'),
    threshold: z.number().min(0).max(1).optional()
      .describe('AURORA approval threshold 0.0–1.0 (default: 0.80)'),
    semantic: z.boolean().optional()
      .describe('Run NEBULA semantic/taint engine in addition to pattern-based engines. Slower (seconds instead of ms) but catches cross-assignment taint flows that pattern matchers miss. Default: false.'),
    surface: z.enum(['security', 'quality', 'all']).optional()
      .describe('Which finding surface to keep in the report. Findings are always classified; this filters rows. Default: all. Use security for IDE/product demos.'),
    includeTests: z.boolean().optional()
      .describe('Include test/spec/fixture paths (default: false — test paths excluded).'),
  }).optional(),
});

export const VerifyFixInput = z.object({
  target_path: z.string().describe('Path to the project root'),
  patch: z.string().describe('Unified diff patch to apply before re-analyzing'),
  report_id: z.string().describe(
    'Report ID returned by a previous analyze call — identifies the pre-patch baseline'
  ),
  original_findings: z.array(z.string()).describe(
    'Finding IDs from the baseline that the patch is expected to resolve'
  ),
  threshold: z.number().min(0).max(1).optional().describe(
    'AURORA approval threshold for the re-analysis (default: 0.80)'
  ),
});

export const GenerateFixInput = z.object({
  target_path: z.string().describe('Path to the project root'),
  report_id: z.string().describe('Report ID from a prior analyze call'),
  finding_id: z.string().describe(
    'Finding ID (from get_findings output) to generate a fix for'
  ),
  threshold: z.number().min(0).max(1).optional().describe(
    'AURORA approval threshold for verify_fix (default: 0.80)'
  ),
  allow_llm_fallback: z.boolean().optional().describe(
    'If true and no template matches, try an LLM-based generator. v1 stubs this; shipping in v2.'
  ),
});

export const OpenFixPrInput = z.object({
  target_path: z.string().describe('Path to the local git checkout of the project'),
  patch: z.string().describe('Unified diff patch to apply and commit'),
  title: z.string().describe('PR title'),
  body: z.string().optional().describe('PR body (markdown)'),
  branch: z.string().optional().describe('Branch name; auto-generated if omitted'),
  base: z.string().optional().describe('Base branch to target (default: main)'),
});

export const GetFindingsInput = z.object({
  report_id: z.string().describe('Report ID returned by a previous analyze call'),
  filters: z.object({
    severity: z.enum(['HIGH', 'MED', 'LOW']).optional().describe('Filter by severity'),
    engine: z.enum(['PULSAR', 'NOVA', 'ECLIPSE']).optional().describe('Filter by originating engine'),
    file: z.string().optional().describe('Filter to findings in a specific file (substring match)'),
  }).optional(),
});

export type AnalyzeInputType = z.infer<typeof AnalyzeInput>;
export type VerifyFixInputType = z.infer<typeof VerifyFixInput>;
export type GetFindingsInputType = z.infer<typeof GetFindingsInput>;
export type GenerateFixInputType = z.infer<typeof GenerateFixInput>;
export type OpenFixPrInputType = z.infer<typeof OpenFixPrInput>;

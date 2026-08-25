#!/usr/bin/env node
// VANTAGE MCP Server — exposes analyze, verify_fix, get_findings over stdio

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { AnalyzeInput, VerifyFixInput, GetFindingsInput, GenerateFixInput, OpenFixPrInput } from './schemas';
import { toolAnalyze } from './tools/analyze';
import { toolVerifyFix } from './tools/verify-fix';
import { toolGetFindings } from './tools/get-findings';
import { toolGenerateFix } from './tools/generate-fix';
import { toolOpenFixPr } from './tools/open-fix-pr';

const server = new McpServer({
  name: 'vantage',
  version: '1.0.0',
});

// ─── Tool: analyze ───────────────────────────────────────────────────────────

server.tool(
  'analyze',
  'Run the full VANTAGE COSMIC pipeline against a project directory. Returns AURORA verdict, score, top issues, and a report ID for follow-up calls.',
  AnalyzeInput.shape,
  async (input) => {
    try {
      const result = await toolAnalyze(input as any);

      const topIssuesText = result.topIssues.length > 0
        ? result.topIssues.slice(0, 5).map(i =>
            `  [${i.severity}] ${i.file}${i.line ? `:${i.line}` : ''} — ${i.description}`
          ).join('\n')
        : '  (none)';

      const summary = [
        `VANTAGE AURORA: ${result.verdict} (${result.scorePct})`,
        `Report ID: ${result.reportId}`,
        ``,
        `Breakdown:`,
        `  Complexity:  ${(result.breakdown.complexityScore * 100).toFixed(0)}%`,
        `  Dependency:  ${(result.breakdown.dependencyScore * 100).toFixed(0)}%`,
        `  Risk Score:  ${(result.breakdown.riskScore * 100).toFixed(0)}%`,
        `  Adversarial: ${(result.breakdown.adversarialScore * 100).toFixed(0)}%`,
        ``,
        `Metrics: ${result.metrics.files} files · ${result.metrics.functions} functions · ${result.metrics.linesOfCode.toLocaleString()} LOC`,
        `Findings: ${result.metrics.findings} adversarial · ${result.metrics.circularDeps} circular deps · ${result.metrics.todos} TODOs`,
        ``,
        `Top Issues:`,
        topIssuesText,
        ``,
        result.summary,
        result.cached ? `(cached result)` : result.durationMs ? `(${result.durationMs}ms)` : '',
      ].filter(l => l !== undefined).join('\n');

      return {
        content: [
          {
            type: 'text' as const,
            text: summary,
          },
          {
            type: 'text' as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ─── Tool: verify_fix ────────────────────────────────────────────────────────

server.tool(
  'verify_fix',
  'Apply a patch to a working copy and re-run VANTAGE to confirm original findings are resolved and no new findings were introduced.',
  VerifyFixInput.shape,
  async (input) => {
    try {
      const result = await toolVerifyFix(input as any);

      const summary = [
        `Patch applied: ${result.patchApplied}${result.patchError ? ` (error: ${result.patchError})` : ''}`,
        `Post-patch verdict: ${result.verdict} (${result.scorePct})`,
        ``,
        `Resolved findings: ${result.resolvedFindings.length}`,
        result.resolvedFindings.map(id => `  ✓ ${id}`).join('\n') || '',
        `Remaining findings: ${result.remainingFindings.length}`,
        result.remainingFindings.map(id => `  ✗ ${id}`).join('\n') || '',
        `New findings introduced: ${result.newFindings.length}`,
        result.newFindings.slice(0, 5).map(f =>
          `  ⚡ [${f.severity}] ${f.file}${f.line ? `:${f.line}` : ''} — ${f.description}`
        ).join('\n') || '',
      ].filter(l => l !== undefined && l !== '').join('\n');

      return {
        content: [
          { type: 'text' as const, text: summary },
          { type: 'text' as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ─── Tool: get_findings ──────────────────────────────────────────────────────

server.tool(
  'get_findings',
  'Return a filtered subset of findings from a previous analyze call. Avoids re-running the pipeline when you only need findings for specific files or severities.',
  GetFindingsInput.shape,
  async (input) => {
    try {
      const result = await toolGetFindings(input as any);

      const findingsText = result.findings.length > 0
        ? result.findings.map(f =>
            `  [${f.severity}][${f.source}] ${f.file}${f.line ? `:${f.line}` : ''}\n    ${f.description}`
          ).join('\n')
        : '  (none matching filters)';

      const summary = [
        `Findings for report ${result.reportId}: ${result.filtered} of ${result.total} shown`,
        ``,
        findingsText,
      ].join('\n');

      return {
        content: [
          { type: 'text' as const, text: summary },
          { type: 'text' as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ─── Tool: generate_fix ──────────────────────────────────────────────────────

server.tool(
  'generate_fix',
  'Generate a verified patch for a finding from a prior analyze call. Tries deterministic fix templates first; each candidate patch is verified via verify_fix before being returned. v1 ships templates for null-safety and JSON.parse error-boundary; LLM fallback is stubbed and will ship in v2.',
  GenerateFixInput.shape,
  async (input) => {
    try {
      const result = await toolGenerateFix(input as any);

      const lines: string[] = [];
      if (result.success) {
        lines.push(`VANTAGE fix: ${result.templateId}`);
        lines.push(`Finding: ${result.findingId}`);
        if (result.rationale) lines.push(`Rationale: ${result.rationale}`);
        if (result.verification) {
          lines.push(``);
          lines.push(`Post-patch: ${result.verification.verdict} (${result.verification.scorePct})`);
          lines.push(`Resolved: ${result.verification.resolvedFindings.length}  Remaining: ${result.verification.remainingFindings.length}  New: ${result.verification.newFindings.length}`);
        }
        lines.push(``);
        lines.push(`Patch:`);
        lines.push(result.patch ?? '(empty)');
      } else {
        lines.push(`VANTAGE fix: no patch produced`);
        lines.push(`Finding: ${result.findingId}`);
        lines.push(`Reason: ${result.reason ?? 'unknown'}`);
        if (result.attemptedTemplates.length) {
          lines.push(``);
          lines.push(`Attempted templates:`);
          for (const a of result.attemptedTemplates) {
            lines.push(`  - ${a.templateId}: ${a.applied ? (a.verified ? 'verified' : 'applied but failed verification') : 'skipped'}${a.skipReason ? ` — ${a.skipReason}` : ''}`);
          }
        }
      }

      return {
        content: [
          { type: 'text' as const, text: lines.join('\n') },
          { type: 'text' as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ─── Tool: open_fix_pr ───────────────────────────────────────────────────────

server.tool(
  'open_fix_pr',
  'Apply a verified patch to a new branch, commit, push, and open a PR via `gh` CLI. If `gh` is not available, returns the manual command to run. Deliberately uses `gh` rather than an SDK so auth piggy-backs on the user\'s existing GitHub configuration.',
  OpenFixPrInput.shape,
  async (input) => {
    try {
      const result = await toolOpenFixPr(input as any);

      const lines: string[] = [];
      if (result.success) {
        lines.push(`PR opened.`);
        lines.push(`Branch: ${result.branch}`);
        if (result.commitSha) lines.push(`Commit: ${result.commitSha}`);
        if (result.prUrl) lines.push(`URL: ${result.prUrl}`);
        if (result.manualNextStep) lines.push(`Next: ${result.manualNextStep}`);
      } else {
        lines.push(`PR not opened.`);
        if (result.branch) lines.push(`Branch: ${result.branch}`);
        if (result.commitSha) lines.push(`Commit created but not PR'd: ${result.commitSha}`);
        if (result.error) lines.push(`Error: ${result.error}`);
        if (result.manualNextStep) lines.push(`Try: ${result.manualNextStep}`);
      }

      return {
        content: [
          { type: 'text' as const, text: lines.join('\n') },
          { type: 'text' as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ─── Start server ─────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Server runs until process is killed
}

main().catch(err => {
  process.stderr.write(`vantage-mcp fatal: ${err.message}\n`);
  process.exit(1);
});

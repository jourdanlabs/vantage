#!/usr/bin/env node
// GitHub Action auto-fix runner.
//
// Called by action.yml when `autofix: true` and the initial analyze rejected.
// For each fixable finding, tries `generate_fix` via the MCP tool bodies
// directly (no JSON-RPC framing; we're in the same Node process as the
// compiled server).
//
// Each successful fix is committed as its own commit on the PR branch so
// reviewers can see exactly what changed per finding. After the loop, we
// re-run `analyze` and emit the post-fix verdict + count of fixes applied.

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Resolve vantage-mcp location. The Action install step has already put it
// on PATH; we reach into its installed lib for the compiled tool entries.
function resolveMcpLib() {
  // Global install layout
  for (const candidate of [
    '/usr/local/lib/node_modules/vantage-mcp/dist/mcp',
    '/usr/lib/node_modules/vantage-mcp/dist/mcp',
  ]) {
    if (fs.existsSync(path.join(candidate, 'tools', 'analyze.js'))) return candidate;
  }
  // Local repo (action running on its own source)
  const localGuess = path.resolve(__dirname, '..', '..', '..', 'dist', 'mcp');
  if (fs.existsSync(path.join(localGuess, 'tools', 'analyze.js'))) return localGuess;
  throw new Error('Could not locate vantage-mcp dist/mcp. Is vantage-mcp installed?');
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      args[key] = argv[i + 1];
      i++;
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const reportPath = args.report;
  const target = args.target;
  const threshold = parseFloat(args.threshold || '0.80');
  const outPath = args.out;

  if (!reportPath || !target || !outPath) {
    console.error('usage: autofix.js --report <path> --target <path> --threshold <n> --out <path>');
    process.exit(2);
  }

  const mcpLib = resolveMcpLib();
  const { toolAnalyze } = require(path.join(mcpLib, 'tools/analyze'));
  const { toolGetFindings } = require(path.join(mcpLib, 'tools/get-findings'));
  const { toolGenerateFix } = require(path.join(mcpLib, 'tools/generate-fix'));

  // Prime the analyze cache with the existing report so generate_fix can
  // look it up by reportId. We also re-run analyze to get a reportId
  // we control — the reportId in the CI report file isn't guaranteed to
  // exist in the cache (different process).
  const analysis = await toolAnalyze({ target_path: target, options: { threshold } });
  const findings = await toolGetFindings({ report_id: analysis.reportId });

  const fixable = findings.findings.filter(f =>
    ['null-safety', 'error-boundary', 'missing-error-handling'].includes(f.type)
  );

  const results = [];
  let fixesApplied = 0;

  for (const finding of fixable) {
    console.log(`attempting: ${finding.id} (${finding.type}) at ${finding.file}:${finding.line}`);
    const fix = await toolGenerateFix({
      target_path: target,
      report_id: analysis.reportId,
      finding_id: finding.id,
      threshold,
    });

    if (!fix.success) {
      console.log(`  skipped: ${fix.reason}`);
      results.push({ findingId: finding.id, applied: false, reason: fix.reason });
      continue;
    }

    // Apply the patch to the working tree
    const patchFile = `/tmp/vantage-fix-${finding.id}.patch`;
    fs.writeFileSync(patchFile, fix.patch, 'utf8');
    try {
      execSync(`git -C ${JSON.stringify(target)} apply ${JSON.stringify(patchFile)}`, { stdio: 'pipe' });
    } catch (err) {
      console.log(`  patch apply failed: ${err.message}`);
      results.push({ findingId: finding.id, applied: false, reason: 'git apply failed in CI — patch valid against temp copy but not against checked-out tree' });
      continue;
    }
    try { fs.unlinkSync(patchFile); } catch { /* ignore */ }

    const commitMsg = `VANTAGE auto-fix: ${fix.templateId}

Finding: ${finding.id}
File: ${finding.file}:${finding.line}
${fix.rationale || ''}

Post-fix verification:
  Verdict: ${fix.verification?.verdict} (${fix.verification?.scorePct})
  Resolved: ${fix.verification?.resolvedFindings?.length || 0}
  New: ${fix.verification?.newFindings?.length || 0}
`;
    execSync(
      `git -C ${JSON.stringify(target)} add -A && ` +
      `git -C ${JSON.stringify(target)} commit -m ${JSON.stringify(commitMsg)}`,
      { stdio: 'pipe' }
    );
    fixesApplied++;
    results.push({ findingId: finding.id, applied: true, templateId: fix.templateId });
    console.log(`  applied: ${fix.templateId}`);
  }

  // Re-run analyze to capture the post-fix verdict
  let postVerdict = 'UNKNOWN';
  if (fixesApplied > 0) {
    const post = await toolAnalyze({ target_path: target, options: { threshold } });
    postVerdict = post.verdict;
  } else {
    postVerdict = analysis.verdict;  // no fixes, verdict unchanged
  }

  fs.writeFileSync(outPath, JSON.stringify({
    fixesApplied,
    postVerdict,
    results,
    initialVerdict: analysis.verdict,
  }, null, 2));

  console.log(`\nfixesApplied=${fixesApplied} postVerdict=${postVerdict}`);
}

main().catch(err => {
  console.error('FATAL:', err.message);
  console.error(err.stack);
  process.exit(1);
});

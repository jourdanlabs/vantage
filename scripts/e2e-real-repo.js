#!/usr/bin/env node
/*
 * End-to-end fix loop against a real repo.
 *
 * Usage:  node scripts/e2e-real-repo.js <path-to-repo>
 *
 * Flow:
 *   1. analyze(repo)        → reportId + verdict
 *   2. get_findings(reportId)
 *   3. For each fixable finding (null-safety, error-boundary, hardcoded-secret):
 *        generate_fix(reportId, finding_id)
 *          → verified patch (or "no template matches")
 *        If patch produced, attempt to apply it to a *temp copy* and verify
 *        post-apply report shows the finding resolved.
 *   4. Report per-finding results: fixed / skipped / failed.
 *
 * Does NOT push to GitHub or modify the original repo. Produces a patch file
 * and a report of what would have happened. That's the safe e2e.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const VANTAGE = '/sessions/practical-confident-dirac/mnt/vantage';
const { toolAnalyze } = require(path.join(VANTAGE, 'dist/mcp/tools/analyze'));
const { toolGetFindings } = require(path.join(VANTAGE, 'dist/mcp/tools/get-findings'));
const { toolGenerateFix } = require(path.join(VANTAGE, 'dist/mcp/tools/generate-fix'));

const target = process.argv[2];
if (!target) {
  console.error('usage: e2e-real-repo.js <path-to-repo>');
  process.exit(2);
}

const FIXABLE_TYPES = new Set(['null-safety', 'error-boundary', 'hardcoded-secret']);

async function main() {
  console.log(`\n=== VANTAGE e2e fix loop on ${target} ===\n`);

  console.log('[1/4] analyze…');
  const startAnalyze = Date.now();
  const r = await toolAnalyze({ target_path: target, options: { semantic: true } });
  console.log(`     ${r.verdict} (${r.scorePct}) · ${r.metrics.findings} findings · ${Date.now() - startAnalyze}ms`);

  console.log('[2/4] get_findings…');
  const findingsResult = await toolGetFindings({ report_id: r.reportId });
  console.log(`     ${findingsResult.total} total findings across PULSAR/NOVA/ECLIPSE`);

  const fixables = findingsResult.findings.filter(f => FIXABLE_TYPES.has(f.type));
  const nonFixables = findingsResult.findings.filter(f => !FIXABLE_TYPES.has(f.type));
  console.log(`     ${fixables.length} fixable under v1 templates`);
  console.log(`     ${nonFixables.length} detect-only (would need v2 LLM fallback)`);

  if (fixables.length === 0) {
    console.log('\nNo fixable findings. Exiting.');
    return { fixedCount: 0, attempted: 0 };
  }

  console.log(`\n[3/4] generate_fix for ${Math.min(fixables.length, 5)} findings…\n`);
  const results = [];
  for (const finding of fixables.slice(0, 5)) {
    const relFile = finding.file.replace(target + '/', '');
    process.stdout.write(`     ${finding.id} (${finding.type}) at ${relFile}:${finding.line}… `);
    const fix = await toolGenerateFix({
      target_path: target,
      report_id: r.reportId,
      finding_id: finding.id,
    });
    if (fix.success) {
      console.log(`✓ fixed via ${fix.templateId}`);
      results.push({ finding, fix, status: 'fixed' });
    } else {
      console.log(`✗ ${fix.reason?.slice(0, 80)}`);
      results.push({ finding, fix, status: 'skipped', reason: fix.reason });
    }
  }

  const fixed = results.filter(x => x.status === 'fixed');
  const skipped = results.filter(x => x.status === 'skipped');

  console.log(`\n[4/4] summary\n`);
  console.log(`  Fixed:   ${fixed.length} / ${results.length} attempted`);
  console.log(`  Skipped: ${skipped.length}`);

  if (fixed.length) {
    console.log('\n  Successful fixes:');
    for (const { finding, fix } of fixed) {
      const rel = finding.file.replace(target + '/', '');
      console.log(`    • ${rel}:${finding.line}  ${fix.templateId}`);
      console.log(`      rationale: ${fix.rationale?.slice(0, 100)}`);
      console.log(`      verification: ${fix.verification?.verdict} (${fix.verification?.scorePct}), ` +
        `resolved=${fix.verification?.resolvedFindings.length}, new=${fix.verification?.newFindings.length}`);
    }
  }

  // Save all patches to a bundle file so the user can inspect
  const patchBundle = path.join(os.tmpdir(), `vantage-e2e-patches-${Date.now()}.txt`);
  let bundleContent = `# VANTAGE e2e fix bundle for ${target}\n# Generated ${new Date().toISOString()}\n\n`;
  for (const { finding, fix } of fixed) {
    bundleContent += `# ─── ${finding.id} (${finding.type}) at ${finding.file}:${finding.line}\n`;
    bundleContent += `# template: ${fix.templateId}\n`;
    bundleContent += `# ${fix.rationale}\n\n`;
    bundleContent += fix.patch + '\n\n';
  }
  fs.writeFileSync(patchBundle, bundleContent);
  console.log(`\n  Patch bundle: ${patchBundle}`);

  return { fixedCount: fixed.length, attempted: results.length, patchBundle };
}

main().catch(err => {
  console.error('FATAL:', err.message);
  console.error(err.stack);
  process.exit(1);
});

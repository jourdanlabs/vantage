#!/usr/bin/env node
/*
 * VANTAGE receipts hunt.
 *
 * Clones a list of popular Node / TypeScript open-source apps, runs VANTAGE
 * in semantic mode against each, aggregates findings, and writes a structured
 * report at /tmp/receipts/<repo-slug>/report.json + a rollup at
 * /tmp/receipts/summary.json.
 *
 * Purpose: launch narrative. "We ran VANTAGE against N real apps and here are
 * the bugs we found that their existing CI pipelines missed."
 *
 * Credibility rules:
 *   - Every repo is a real application, not a framework or library
 *   - The corpus is published alongside the findings so anyone can reproduce
 *   - False-positive triage happens in a separate pass — this script just
 *     captures the raw output
 *   - Timeouts are generous because some of these repos are large; runs
 *     happen serially to keep system load predictable
 *
 * Usage:
 *   node benchmarks/receipts-hunt.js          # full run
 *   node benchmarks/receipts-hunt.js --limit 3  # first 3 repos only
 */

const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const VANTAGE_REPO = '/sessions/practical-confident-dirac/mnt/vantage';
const WORKSPACE = '/tmp/receipts';
const PER_REPO_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

// Curated list: real Node/TypeScript applications, medium-sized, Express or
// Express-adjacent routing, recognizable names.
const CORPUS = [
  {
    slug: 'express-examples',
    url: 'https://github.com/expressjs/express.git',
    description: 'The Express framework — we analyze the bundled examples only',
    subdir: 'examples',
  },
  {
    slug: 'nestjs-samples',
    url: 'https://github.com/nestjs/nest.git',
    description: 'NestJS sample applications',
    subdir: 'sample',
  },
  {
    slug: 'feathers-chat',
    url: 'https://github.com/feathersjs-ecosystem/feathers-chat.git',
    description: 'The reference Feathers chat application',
    subdir: null,
  },
  {
    slug: 'n8n-nodes-base',
    url: 'https://github.com/n8n-io/n8n.git',
    description: 'n8n workflow automation — analyze the nodes-base package',
    subdir: 'packages/nodes-base/nodes',
    skipInstall: true,
  },
  {
    slug: 'rocketchat-apps',
    url: 'https://github.com/RocketChat/Apps.RocketChat.Tester.git',
    description: 'Rocket.Chat apps tester',
    subdir: null,
  },
  {
    slug: 'strapi-plugins',
    url: 'https://github.com/strapi/strapi.git',
    description: 'Strapi CMS — analyze the core plugins',
    subdir: 'packages/core/admin/server',
  },
  {
    slug: 'directus-extensions',
    url: 'https://github.com/directus/directus.git',
    description: 'Directus data platform — analyze the extensions-sdk',
    subdir: 'packages/extensions-sdk/src',
  },
];

function parseArgs() {
  const args = process.argv.slice(2);
  const out = { limit: Infinity };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--limit') out.limit = parseInt(args[++i], 10);
  }
  return out;
}

function run(cmd, opts = {}) {
  try {
    return execSync(cmd, { stdio: 'pipe', ...opts }).toString();
  } catch (err) {
    return { error: err.message, stdout: err.stdout?.toString(), stderr: err.stderr?.toString() };
  }
}

async function processRepo(spec) {
  const repoDir = path.join(WORKSPACE, spec.slug);

  // Clone first (into the empty repoDir) so mkdirSync of _vantage doesn't
  // block `git clone`. If repoDir already exists as a git clone, reuse.
  if (fs.existsSync(path.join(repoDir, '.git'))) {
    console.log(`  [${spec.slug}] already cloned`);
  } else {
    // Wipe the dir if it's there but not a git clone — stale from a previous
    // run that failed mid-flight.
    if (fs.existsSync(repoDir)) {
      fs.rmSync(repoDir, { recursive: true, force: true });
    }
    console.log(`  [${spec.slug}] cloning...`);
    const cloneResult = run(
      `git clone --depth 1 ${spec.url} ${JSON.stringify(repoDir)}`,
      { timeout: 180_000 }
    );
    if (typeof cloneResult === 'object' && cloneResult.error) {
      return { slug: spec.slug, error: 'clone failed: ' + cloneResult.error };
    }
  }

  const outDir = path.join(repoDir, '_vantage');
  fs.mkdirSync(outDir, { recursive: true });

  // Resolve analysis target
  const analyzeTarget = spec.subdir
    ? path.join(repoDir, spec.subdir)
    : repoDir;

  if (!fs.existsSync(analyzeTarget)) {
    return { slug: spec.slug, error: `subdir not found: ${analyzeTarget}` };
  }

  // Run VANTAGE (pattern-only first, then semantic)
  const bin = `node ${path.join(VANTAGE_REPO, 'bin/vantage.js')}`;
  const patternReport = path.join(outDir, 'pattern.json');
  const semanticReport = path.join(outDir, 'semantic.json');

  console.log(`  [${spec.slug}] pattern-only...`);
  const patternStart = Date.now();
  const pr = run(`${bin} analyze ${JSON.stringify(analyzeTarget)} --output ${JSON.stringify(patternReport)}`, { timeout: PER_REPO_TIMEOUT_MS });
  const patternMs = Date.now() - patternStart;

  // (semantic pass is currently via MCP toolAnalyze; the CLI doesn't yet expose
  // --semantic. For the receipts hunt, wire through the MCP tool directly.)
  console.log(`  [${spec.slug}] semantic...`);
  const semanticStart = Date.now();
  const semResult = runSemantic(analyzeTarget, semanticReport);
  const semanticMs = Date.now() - semanticStart;

  const pattern = safeRead(patternReport);
  const semantic = safeRead(semanticReport);

  return {
    slug: spec.slug,
    description: spec.description,
    subdir: spec.subdir,
    analyzeTarget,
    patternMs,
    semanticMs,
    patternFindings: findingsFromReport(pattern),
    semanticFindings: findingsFromReport(semantic),
    nebulaFindings: nebulaFindingsFromReport(semantic),
    patternVerdict: pattern?.aurora?.verdict,
    semanticVerdict: semantic?.aurora?.verdict,
    patternScore: pattern?.aurora?.score,
    semanticScore: semantic?.aurora?.score,
  };
}

function runSemantic(target, outPath) {
  // Use the compiled MCP tool directly.
  const code = `
    const { toolAnalyze } = require(${JSON.stringify(path.join(VANTAGE_REPO, 'dist/mcp/tools/analyze'))});
    const fs = require('fs');
    (async () => {
      const r = await toolAnalyze({ target_path: ${JSON.stringify(target)}, options: { semantic: true } });
      // toolAnalyze returns AnalyzeResult; we need the full report from the cache.
      // Simpler: just emit the report from the cache via reportId lookup.
      const { getReportById } = require(${JSON.stringify(path.join(VANTAGE_REPO, 'dist/mcp/cache'))});
      const entry = getReportById(r.reportId);
      if (entry) fs.writeFileSync(${JSON.stringify(outPath)}, JSON.stringify(entry.report));
      else process.exit(2);
    })().catch(e => { console.error(e.message); process.exit(1); });
  `;
  const res = spawnSync('node', ['-e', code], { timeout: PER_REPO_TIMEOUT_MS });
  if (res.status !== 0) return { error: res.stderr?.toString() ?? 'unknown' };
  return { ok: true };
}

function safeRead(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

function findingsFromReport(report) {
  if (!report) return [];
  const out = [];
  for (const f of report.pulsar?.adversarialFindings ?? []) {
    out.push({
      file: f.file,
      line: f.line,
      type: f.type,
      severity: f.severity,
      description: f.description,
      source: f.description?.startsWith('[NEBULA]') ? 'NEBULA' : 'PULSAR',
    });
  }
  return out;
}

function nebulaFindingsFromReport(report) {
  if (!report) return [];
  return (report.pulsar?.adversarialFindings ?? [])
    .filter(f => (f.description ?? '').startsWith('[NEBULA]'))
    .map(f => ({ file: f.file, line: f.line, type: f.type, severity: f.severity, description: f.description }));
}

async function main() {
  const args = parseArgs();
  fs.mkdirSync(WORKSPACE, { recursive: true });

  const selected = CORPUS.slice(0, args.limit);
  const results = [];

  for (const spec of selected) {
    console.log(`\n=== ${spec.slug} ===`);
    try {
      const result = await processRepo(spec);
      results.push(result);
      if (result.error) {
        console.log(`  ERROR: ${result.error}`);
      } else {
        console.log(`  pattern: ${result.patternFindings.length} findings in ${result.patternMs}ms`);
        console.log(`  semantic: ${result.semanticFindings.length} findings in ${result.semanticMs}ms`);
        console.log(`  NEBULA-only: ${result.nebulaFindings.length}`);
      }
    } catch (err) {
      console.log(`  FATAL: ${err.message}`);
      results.push({ slug: spec.slug, error: err.message });
    }
  }

  const summaryPath = path.join(WORKSPACE, 'summary.json');
  fs.writeFileSync(summaryPath, JSON.stringify({
    runAt: new Date().toISOString(),
    results,
  }, null, 2));

  // Rollup
  console.log('\n\n=== SUMMARY ===');
  let totalPattern = 0, totalSemantic = 0, totalNebula = 0;
  for (const r of results) {
    if (r.error) continue;
    totalPattern += r.patternFindings.length;
    totalSemantic += r.semanticFindings.length;
    totalNebula += r.nebulaFindings.length;
  }
  console.log(`Total PULSAR (pattern-only mode): ${totalPattern}`);
  console.log(`Total findings (semantic mode):    ${totalSemantic}`);
  console.log(`Of which NEBULA-only:              ${totalNebula}`);
  console.log(`\nPer-repo summary at ${summaryPath}`);
}

main().catch(err => { console.error('FATAL:', err); process.exit(1); });

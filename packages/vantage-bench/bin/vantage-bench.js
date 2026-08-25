#!/usr/bin/env node
// vantage-bench CLI
// Usage:
//   vantage-bench run [--tool <name>] [--corpus <id>] [--clone] [--output results.json]
//   vantage-bench list-tools
//   vantage-bench list-corpora

require('ts-node').register({
  project: require('path').join(__dirname, '..', 'tsconfig.json'),
  transpileOnly: true,
});

const { runBenchmark, ALL_RUNNERS, CORPORA, renderMarkdownReport, renderJsonResults } = require('../src/index');
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const command = args[0] ?? 'run';

function getFlag(flag) {
  const idx = args.indexOf(flag);
  if (idx < 0) return null;
  return args[idx + 1] ?? null;
}

function hasFlag(flag) {
  return args.includes(flag);
}

async function main() {
  if (command === 'list-tools') {
    console.log('Registered runners:');
    for (const r of ALL_RUNNERS) {
      console.log(`  ${r.name}`);
    }
    return;
  }

  if (command === 'list-corpora') {
    console.log('Registered corpora:');
    for (const c of CORPORA) {
      const exists = fs.existsSync(c.localPath);
      console.log(`  ${c.id.padEnd(15)} ${exists ? '✓ present' : '✗ not cloned'}  ${c.localPath}`);
    }
    return;
  }

  if (command !== 'run') {
    console.error(`Unknown command: ${command}. Valid commands: run, list-tools, list-corpora`);
    process.exit(1);
  }

  const toolArg = getFlag('--tool');
  const corpusArg = getFlag('--corpus');
  const outputArg = getFlag('--output') ?? 'benchmark-results.json';
  const clone = hasFlag('--clone');

  const opts = {
    tools: toolArg ? [toolArg] : undefined,
    corpora: corpusArg ? [corpusArg] : undefined,
    ensureCorpora: clone,
    onProgress: msg => process.stdout.write(msg + '\n'),
  };

  let results;
  try {
    results = await runBenchmark(opts);
  } catch (err) {
    console.error('Benchmark failed:', err.message);
    process.exit(1);
  }

  // Write JSON
  const jsonData = renderJsonResults(results);
  fs.writeFileSync(outputArg, JSON.stringify(jsonData, null, 2));
  console.log(`\nResults written to: ${outputArg}`);

  // Write Markdown summary
  const mdOutput = outputArg.replace(/\.json$/, '.md');
  fs.writeFileSync(mdOutput, renderMarkdownReport(results));
  console.log(`Markdown summary: ${mdOutput}`);

  // Print table
  console.log('\n' + '═'.repeat(70));
  console.log('LEADERBOARD');
  console.log('═'.repeat(70));
  for (const entry of jsonData.tools) {
    const ngScore = entry.scores.find(s => s.corpus === 'nodegoat');
    const jsScore = entry.scores.find(s => s.corpus === 'juice-shop');
    console.log(
      `#${entry.rank} ${entry.name.padEnd(12)} ` +
      `NodeGoat F1=${fmtPct(ngScore?.f1)}  ` +
      `JuiceShop F1=${fmtPct(jsScore?.f1)}  ` +
      `Aggregate=${fmtPct(entry.aggregateF1)}  ` +
      `${fmtMs(entry.medianDurationMs)}`
    );
  }
}

function fmtPct(n) {
  if (n === null || n === undefined) return 'N/A  ';
  return `${(n * 100).toFixed(1)}%`.padEnd(6);
}

function fmtMs(n) {
  if (n < 1000) return `${n.toFixed(0)}ms`;
  return `${(n / 1000).toFixed(1)}s`;
}

main().catch(err => {
  console.error('Fatal:', err.message);
  process.exit(1);
});

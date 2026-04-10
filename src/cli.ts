#!/usr/bin/env node
// VANTAGE CLI — Autonomous Code Evolution Engine

import * as path from 'path';
import * as fs from 'fs';
import { runPipeline, EngineFilter } from './engines/index';
import { VantageReport } from './types';

// ANSI colors
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  brightRed: '\x1b[91m',
  brightGreen: '\x1b[92m',
  brightYellow: '\x1b[93m',
  brightCyan: '\x1b[96m',
};

function c(color: keyof typeof C, text: string): string {
  return `${C[color]}${text}${C.reset}`;
}

function line(char = '━', length = 50): string {
  return c('dim', char.repeat(length));
}

const ENGINE_COLORS: Record<string, keyof typeof C> = {
  METEOR: 'yellow',
  NOVA: 'magenta',
  ECLIPSE: 'cyan',
  PULSAR: 'brightRed',
  AURORA: 'brightGreen',
};

function printHeader() {
  console.log();
  console.log(c('bold', c('cyan', 'VANTAGE')) + c('dim', ' — Autonomous Code Evolution Engine'));
  console.log(line());
  console.log();
}

function formatSeverity(sev: 'HIGH' | 'MED' | 'LOW'): string {
  if (sev === 'HIGH') return c('brightRed', '[HIGH]');
  if (sev === 'MED') return c('yellow', '[MED] ');
  return c('gray', '[LOW] ');
}

async function cmdRun(targetPath: string, opts: { engine?: string; output?: string; json?: boolean }) {
  printHeader();

  const absPath = path.resolve(targetPath);
  if (!fs.existsSync(absPath)) {
    console.error(c('red', `Error: path not found: ${absPath}`));
    process.exit(1);
  }

  const engineFilter = (opts.engine?.toUpperCase() as EngineFilter) || null;

  // Track timing and progress per engine
  const engineStatus: Record<string, { msg: string; done: boolean; result?: string }> = {};
  const engineOrder = ['METEOR', 'NOVA', 'ECLIPSE', 'PULSAR', 'AURORA'];

  // Simple progress renderer
  let currentEngine = '';
  const engineTimes: Record<string, number> = {};

  const onProgress = (engine: string, msg: string) => {
    if (engine !== currentEngine) {
      if (currentEngine) {
        // Mark previous as done
        const elapsed = ((Date.now() - engineTimes[currentEngine]) / 1000).toFixed(1);
        process.stdout.write(`\r${c(ENGINE_COLORS[currentEngine] || 'white', `▸ ${currentEngine.padEnd(8)}`)} ${msg.padEnd(45)} ${c('green', '✓')} ${c('dim', `${elapsed}s`)}\n`);
      }
      currentEngine = engine;
      engineTimes[engine] = Date.now();
      process.stdout.write(`${c(ENGINE_COLORS[engine] || 'white', `▸ ${engine.padEnd(8)}`)} ${msg.padEnd(45)}`);
    } else {
      // Update in place
      process.stdout.write(`\r${c(ENGINE_COLORS[engine] || 'white', `▸ ${engine.padEnd(8)}`)} ${msg.padEnd(45)}`);
    }
  };

  let report: VantageReport;
  try {
    report = await runPipeline(absPath, engineFilter, onProgress);
  } catch (err: any) {
    console.error('\n' + c('red', `Pipeline error: ${err.message}`));
    if (process.env.VANTAGE_DEBUG) console.error(err.stack);
    process.exit(1);
  }

  // Close final engine line
  if (currentEngine) {
    const elapsed = ((Date.now() - engineTimes[currentEngine]) / 1000).toFixed(1);
    const auroraScore = report.aurora.score > 0 ? `${report.aurora.score.toFixed(2)} ${report.aurora.verdict}` : '';
    process.stdout.write(`\r${c(ENGINE_COLORS[currentEngine] || 'white', `▸ ${currentEngine.padEnd(8)}`)} ${'final audit'.padEnd(45)} ${c(report.aurora.verdict === 'APPROVED' ? 'green' : 'brightRed', `✓ ${auroraScore}`)} ${c('dim', `${elapsed}s`)}\n`);
  }

  console.log();
  console.log(line());

  // Top Issues
  if (report.aurora.topIssues.length > 0) {
    console.log(c('bold', '━━━ TOP ISSUES') + line('━', 35));
    console.log();

    for (const issue of report.aurora.topIssues.slice(0, 10)) {
      const relPath = path.relative(absPath, issue.file);
      const lineStr = issue.line ? `:${issue.line}` : '';
      console.log(`${formatSeverity(issue.severity)} ${c('white', relPath)}${c('dim', lineStr)}`);
      console.log(`        ${c('gray', issue.description)}`);
      if (issue.fix) {
        console.log(`        ${c('dim', '→')} ${c('cyan', issue.fix.slice(0, 100))}`);
      }
      console.log();
    }
  }

  // Circular deps detail
  if (report.nova.circularDeps.length > 0) {
    console.log(c('bold', '━━━ CIRCULAR DEPENDENCIES') + line('━', 23));
    console.log();
    for (const circ of report.nova.circularDeps.slice(0, 5)) {
      const cycle = circ.cycle.map(f => path.relative(absPath, f)).join(c('red', ' → '));
      console.log(`  ${c('red', '⟳')} ${cycle}`);
    }
    console.log();
  }

  // PULSAR high findings detail
  const highFindings = report.pulsar.adversarialFindings.filter(f => f.severity === 'HIGH');
  if (highFindings.length > 0) {
    console.log(c('bold', '━━━ CRITICAL FINDINGS (PULSAR)') + line('━', 18));
    console.log();
    for (const f of highFindings.slice(0, 8)) {
      const relPath = path.relative(absPath, f.file);
      const lineStr = f.line ? `:${f.line}` : '';
      console.log(`  ${c('brightRed', '⚡')} ${c('white', relPath)}${c('dim', lineStr)}`);
      console.log(`     ${c('gray', f.description)}`);
      console.log(`     ${c('dim', 'Test:')} ${c('yellow', f.testCase.slice(0, 90))}`);
      console.log();
    }
  }

  // AURORA Verdict
  console.log(line('━', 50));
  console.log(c('bold', '━━━ AURORA VERDICT') + line('━', 30));
  console.log();

  const scoreStr = `${(report.aurora.score * 100).toFixed(1)}%`;
  const verdictColor = report.aurora.verdict === 'APPROVED' ? 'brightGreen' : 'brightRed';
  console.log(`  Score:   ${c(verdictColor, c('bold', scoreStr))} / ${c(verdictColor, c('bold', report.aurora.verdict))}`);
  console.log();

  console.log(`  ${c('dim', 'Breakdown:')}`);
  const breakdown = report.aurora.breakdown;
  console.log(`    Complexity   ${progressBar(breakdown.complexityScore)} ${(breakdown.complexityScore * 100).toFixed(0)}%`);
  console.log(`    Dependency   ${progressBar(breakdown.dependencyScore)} ${(breakdown.dependencyScore * 100).toFixed(0)}%`);
  console.log(`    Risk Score   ${progressBar(breakdown.riskScore)} ${(breakdown.riskScore * 100).toFixed(0)}%`);
  console.log(`    Adversarial  ${progressBar(breakdown.adversarialScore)} ${(breakdown.adversarialScore * 100).toFixed(0)}%`);
  console.log();

  console.log(`  ${c('dim', report.aurora.summary)}`);
  console.log();

  if (report.aurora.verdict === 'REJECTED') {
    console.log(`  ${c('red', '✗')} Fix HIGH severity issues above before shipping.`);
  } else {
    console.log(`  ${c('green', '✓')} Codebase is ship-safe. Minor improvements recommended.`);
  }

  // Metrics footer
  console.log();
  console.log(line('─', 50));
  console.log(c('dim',
    `  ${report.meteor.files.length} files  ·  ${report.meteor.functions.length} functions  ·  ${report.meteor.metrics.linesOfCode.toLocaleString()} LOC  ·  ` +
    `${report.meteor.todos.length} TODOs  ·  ${report.nova.circularDeps.length} circ deps  ·  ${report.pulsar.adversarialFindings.length} findings`
  ));
  console.log();

  // Save report
  const outputPath = opts.output || path.join(process.cwd(), 'vantage-report.json');
  const reportData = {
    ...report,
    // Don't include full file contents in report (too large)
    meteor: {
      ...report.meteor,
      files: report.meteor.files.map(f => ({ ...f, content: undefined }))
    }
  };
  fs.writeFileSync(outputPath, JSON.stringify(reportData, null, 2));
  console.log(c('dim', `  Report saved: ${outputPath}`));
  console.log();
}

function progressBar(score: number): string {
  const filled = Math.round(score * 20);
  const bar = '█'.repeat(filled) + '░'.repeat(20 - filled);
  const color: keyof typeof C = score >= 0.7 ? 'green' : score >= 0.4 ? 'yellow' : 'red';
  return c(color, bar);
}

async function cmdReport(targetPath: string, opts: { output?: string }) {
  // Same as run but always saves to specified output
  await cmdRun(targetPath, { output: opts.output });
}

function printHelp() {
  printHeader();
  console.log('  Usage:');
  console.log(`    ${c('cyan', 'vantage run')} <path>                 Run full COSMIC pipeline`);
  console.log(`    ${c('cyan', 'vantage run')} <path> --engine PULSAR  Run single engine only`);
  console.log(`    ${c('cyan', 'vantage report')} <path> --output out.json  Run + save report`);
  console.log();
  console.log('  Options:');
  console.log(`    ${c('dim', '--engine <name>')}   Run only: METEOR, NOVA, ECLIPSE, PULSAR, AURORA`);
  console.log(`    ${c('dim', '--output <file>')}   Save JSON report to file (default: vantage-report.json)`);
  console.log(`    ${c('dim', '--help')},${c('dim', ' -h')}       Show this help`);
  console.log();
  console.log('  Engines:');
  console.log(`    ${c('yellow', 'METEOR')}   — File scanner & code parser`);
  console.log(`    ${c('magenta', 'NOVA')}     — Causal dependency analysis`);
  console.log(`    ${c('cyan', 'ECLIPSE')} — Risk scoring (0.0–1.0 per file)`);
  console.log(`    ${c('brightRed', 'PULSAR')}  — Adversarial stress test`);
  console.log(`    ${c('brightGreen', 'AURORA')}  — Final audit + verdict`);
  console.log();
}

// === Main ===
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  const command = args[0];

  // Parse flags
  const engineIdx = args.indexOf('--engine');
  const engine = engineIdx >= 0 ? args[engineIdx + 1] : undefined;

  const outputIdx = args.indexOf('--output');
  const output = outputIdx >= 0 ? args[outputIdx + 1] : undefined;

  if (command === 'run' || command === 'report') {
    const targetArg = args[1];
    if (!targetArg || targetArg.startsWith('--')) {
      console.error(c('red', `Error: path required. Usage: vantage ${command} <path>`));
      process.exit(1);
    }

    if (command === 'run') {
      await cmdRun(targetArg, { engine, output });
    } else {
      await cmdReport(targetArg, { output });
    }
  } else if (fs.existsSync(path.resolve(command))) {
    // Treat first arg as path if it exists (shorthand: vantage /path/to/project)
    await cmdRun(command, { engine, output });
  } else {
    console.error(c('red', `Unknown command: ${command}`));
    printHelp();
    process.exit(1);
  }
}

main().catch(err => {
  console.error(C.red + 'Fatal: ' + err.message + C.reset);
  if (process.env.VANTAGE_DEBUG) console.error(err.stack);
  process.exit(1);
});

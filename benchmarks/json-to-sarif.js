#!/usr/bin/env node
// Convert a VANTAGE JSON report to SARIF 2.1.0 without re-scanning.
// Usage: node benchmarks/json-to-sarif.js <report.json> <out.sarif> [scanRoot]

const path = require('path');
const fs = require('fs');

// Prefer compiled dist (tsconfig.mcp outDir)
const sarifMod = require(path.join(__dirname, '..', 'dist', 'sarif.js'));
const { writeSarifFile, reportToSarif } = sarifMod;

function main() {
  const [jsonPath, outPath, scanRootArg] = process.argv.slice(2);
  if (!jsonPath || !outPath) {
    console.error('Usage: node benchmarks/json-to-sarif.js <report.json> <out.sarif> [scanRoot]');
    process.exit(2);
  }
  const report = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  const scanRoot = path.resolve(scanRootArg || report.target || process.cwd());
  const { resultCount } = writeSarifFile(report, outPath, {
    scanRoot,
    invocationMode: process.env.VANTAGE_MODE === 'semantic' ? 'semantic' : 'pattern',
  });
  console.log(JSON.stringify({ outPath, resultCount, scanRoot }, null, 2));
}

main();

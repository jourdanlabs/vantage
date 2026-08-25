#!/usr/bin/env node
// VANTAGE CLI entrypoint.
//
// Resolution order:
//   1. Compiled output at dist/cli.js (how installed packages run)
//   2. ts-node fallback at src/cli.ts (dev checkout before `npm run build:mcp`)

const path = require('path');
const fs = require('fs');

const distCli = path.join(__dirname, '..', 'dist', 'cli.js');
const srcCli = path.join(__dirname, '..', 'src', 'cli.ts');

if (fs.existsSync(distCli)) {
  require(distCli);
} else if (fs.existsSync(srcCli)) {
  try {
    require('ts-node').register({ project: path.join(__dirname, '..', 'tsconfig.json') });
    require(srcCli);
  } catch (err) {
    process.stderr.write(
      'vantage: compiled CLI not found at ' + distCli + '\n' +
      'Run `npm run build:mcp` in the source checkout, or install the published package.\n' +
      'Underlying error: ' + err.message + '\n'
    );
    process.exit(1);
  }
} else {
  process.stderr.write('vantage: cannot find CLI at ' + distCli + ' or ' + srcCli + '\n');
  process.exit(1);
}

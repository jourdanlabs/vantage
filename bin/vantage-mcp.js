#!/usr/bin/env node
// VANTAGE MCP server entrypoint
// Usage:
//   vantage-mcp              → run MCP server over stdio
//   vantage-mcp install-hook → install Claude Code PreToolUse hook
//
// Resolution order:
//   1. Compiled output at dist/mcp/server.js  (how installed packages run)
//   2. ts-node fallback at src/mcp/server.ts  (dev checkout before `npm run build`)

const path = require('path');
const fs = require('fs');

const args = process.argv.slice(2);

if (args[0] === 'install-hook') {
  require('./install-hook');
  return;
}

const distServer = path.join(__dirname, '..', 'dist', 'mcp', 'server.js');
const srcServer = path.join(__dirname, '..', 'src', 'mcp', 'server.ts');

if (fs.existsSync(distServer)) {
  require(distServer);
} else if (fs.existsSync(srcServer)) {
  // Dev mode — only reachable in a source checkout without `npm run build`.
  // ts-node is a devDependency; users of the published package never hit this branch.
  try {
    require('ts-node').register({ project: path.join(__dirname, '..', 'tsconfig.json') });
    require(srcServer);
  } catch (err) {
    process.stderr.write(
      'vantage-mcp: compiled server not found at ' + distServer + '\n' +
      'Run `npm run build` in the source checkout, or install a published package.\n' +
      'Underlying error: ' + err.message + '\n'
    );
    process.exit(1);
  }
} else {
  process.stderr.write(
    'vantage-mcp: cannot find server. Looked for:\n' +
    '  ' + distServer + '\n' +
    '  ' + srcServer + '\n'
  );
  process.exit(1);
}

#!/usr/bin/env node
// npx vantage-mcp install-hook
// Writes the PreToolUse hook config into .claude/settings.json

const fs = require('fs');
const path = require('path');

const cwd = process.cwd();
const claudeDir = path.join(cwd, '.claude');
const settingsPath = path.join(claudeDir, 'settings.json');
const hookScriptSrc = path.join(__dirname, '..', 'hooks', 'claude-code', 'pre-commit-gate.sh');

// Determine where to install hook script in the target project
const hookScriptDst = path.join(cwd, '.claude', 'hooks', 'vantage-pre-commit-gate.sh');

function run() {
  console.log('VANTAGE hook installer');
  console.log(`Project root: ${cwd}`);

  // Ensure .claude/hooks exists
  const hooksDir = path.join(claudeDir, 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });

  // Copy hook script
  if (!fs.existsSync(hookScriptSrc)) {
    console.error(`Error: hook script not found at ${hookScriptSrc}`);
    console.error('Make sure you have vantage-mcp installed correctly.');
    process.exit(1);
  }
  fs.copyFileSync(hookScriptSrc, hookScriptDst);
  fs.chmodSync(hookScriptDst, '755');
  console.log(`Hook script installed: ${hookScriptDst}`);

  // Read or initialize settings.json
  let settings = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    } catch {
      console.warn('Warning: .claude/settings.json exists but is not valid JSON — it will be overwritten.');
      settings = {};
    }
  }

  // Merge hook config
  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];

  // Check if already installed
  const hookEntry = {
    matcher: 'Bash',
    hooks: [{
      type: 'command',
      command: hookScriptDst,
    }]
  };

  const alreadyInstalled = settings.hooks.PreToolUse.some(
    h => h.hooks && h.hooks.some(hh => hh.command && hh.command.includes('vantage'))
  );

  if (alreadyInstalled) {
    console.log('VANTAGE hook already present in .claude/settings.json — skipping.');
  } else {
    settings.hooks.PreToolUse.push(hookEntry);
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
    console.log(`Hook config written: ${settingsPath}`);
  }

  console.log('');
  console.log('Done. VANTAGE will now gate git commits in Claude Code sessions.');
  console.log('To skip: include [vantage-skip] in your commit message.');
  console.log('To remove: delete the hook entry from .claude/settings.json');
}

run();

# VANTAGE Hooks

## Claude Code — PreToolUse hook

Gates `git commit` and `git push` commands in Claude Code sessions. If AURORA score is below 0.80, the hook blocks the commit and returns a JSON block explaining which findings need to be fixed.

### Install (one command)

```bash
npx vantage-mcp install-hook
```

This copies the hook script into `.claude/hooks/` and writes the hook entry into `.claude/settings.json`, preserving any existing config.

### Manual install

1. Copy `claude-code/pre-commit-gate.sh` into your project's `.claude/hooks/` directory.
2. Add the hook entry from `claude-code/settings.example.json` into your `.claude/settings.json`.

### Escape hatch

If you need to bypass the gate for a specific commit:
```bash
git commit -m "chore: fix tests [vantage-skip]"
```

---

## pre-commit framework

For projects not using AI coding tools, VANTAGE works with the [pre-commit](https://pre-commit.com) framework.

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/jourdanlabs/vantage
    rev: v1.0.0
    hooks:
      - id: vantage-gate
```

To bypass: `git commit --no-verify` (use sparingly).

---

## GitHub Action

See `.github/actions/vantage/` for the composite action. Example workflow:

```yaml
- uses: jourdanlabs/vantage-action@v1
  with:
    target: .
    threshold: '0.80'
    fail-on-reject: 'true'
```

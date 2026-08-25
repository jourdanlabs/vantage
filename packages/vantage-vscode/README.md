# VANTAGE for VS Code

IDE skin for the same COSMIC / NEBULA engine as the CLI and **MCP server**.

| Surface | Role |
|---------|------|
| **CLI** | `vantage analyze` — batch / CI |
| **MCP** | `vantage-mcp` — Cursor, Claude Code, agents |
| **This extension** | Problems panel, Scan Workspace, settings |

One analyzer. Three doors.

## Features

- **VANTAGE: Scan Workspace** — run against the open folder
- Diagnostics in the **Problems** panel (severity-mapped)
- Settings: `semantic`, `surface` (default **security**), `includeTests`, `cliPath`
- Writes `.vantage/ide-report.json` for the last run

## Install (dev)

From the VANTAGE monorepo:

```bash
# 1. Build the engine CLI
cd ../..   # repo root
npm install
npm run build:mcp

# 2. Build the extension
cd packages/vantage-vscode
npm install
npm run compile

# 3. Open this folder in VS Code and press F5 (Extension Development Host)
#    or: code --install-extension ./vantage-vscode-1.0.0.vsix  after `npm run package`
```

### cliPath

Leave empty to auto-use monorepo `bin/vantage.js`. Otherwise set to a global install:

```json
{
  "vantage.cliPath": "/usr/local/bin/vantage"
}
```

## Recommended settings (product demo)

```json
{
  "vantage.surface": "security",
  "vantage.semantic": false,
  "vantage.includeTests": false
}
```

Enable `"vantage.semantic": true` when you want NEBULA taint (slower; avoid huge compiler trees until stack-safe).

## MCP (agents) — separate install

```json
{
  "mcpServers": {
    "vantage": {
      "command": "node",
      "args": ["/absolute/path/to/vantage/bin/vantage-mcp.js"]
    }
  }
}
```

Or after `npm link` at repo root: `"command": "vantage-mcp"`.

## Sealed engine

Point `cliPath` at a build from tip `134a950`+ (surface split, real-world discipline). The extension does not re-implement analysis.

## License

Apache-2.0 · JourdanLabs

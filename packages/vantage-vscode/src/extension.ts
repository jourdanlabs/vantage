/**
 * VANTAGE VS Code extension — IDE skin over the same CLI/COSMIC engine.
 * MCP remains the agent door; this surfaces diagnostics + commands.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { spawn } from 'child_process';

interface AdversarialFinding {
  file: string;
  line?: number;
  type?: string;
  severity?: string;
  description?: string;
  surface?: string;
  sink?: string;
}

interface VantageReport {
  target?: string;
  aurora?: {
    score?: number;
    verdict?: string;
    summary?: string;
    topIssues?: Array<{ severity?: string; file?: string; line?: number; description?: string }>;
  };
  pulsar?: {
    adversarialFindings?: AdversarialFinding[];
  };
  meteor?: {
    files?: unknown[];
    metrics?: { linesOfCode?: number };
  };
}

let diagnosticCollection: vscode.DiagnosticCollection;
let lastReportPath: string | undefined;
let output: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('vantage');
  output = vscode.window.createOutputChannel('VANTAGE');
  context.subscriptions.push(diagnosticCollection, output);

  context.subscriptions.push(
    vscode.commands.registerCommand('vantage.scanWorkspace', () => scanTarget(workspaceRoot())),
    vscode.commands.registerCommand('vantage.scanFolder', async () => {
      const picked = await vscode.window.showOpenDialog({
        canSelectFiles: false,
        canSelectFolders: true,
        canSelectMany: false,
        openLabel: 'Scan with VANTAGE',
      });
      if (picked?.[0]) await scanTarget(picked[0].fsPath);
    }),
    vscode.commands.registerCommand('vantage.clearDiagnostics', () => {
      diagnosticCollection.clear();
      vscode.window.showInformationMessage('VANTAGE diagnostics cleared.');
    }),
    vscode.commands.registerCommand('vantage.showReport', async () => {
      if (!lastReportPath || !fs.existsSync(lastReportPath)) {
        vscode.window.showWarningMessage('No VANTAGE report yet. Run Scan Workspace first.');
        return;
      }
      const doc = await vscode.workspace.openTextDocument(lastReportPath);
      await vscode.window.showTextDocument(doc, { preview: true });
    })
  );

  output.appendLine('VANTAGE extension active. Commands: Scan Workspace / Scan Folder.');
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
}

function workspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

async function scanTarget(target: string | undefined): Promise<void> {
  if (!target) {
    vscode.window.showErrorMessage('VANTAGE: open a workspace folder first.');
    return;
  }

  const cfg = vscode.workspace.getConfiguration('vantage');
  const semantic = cfg.get<boolean>('semantic', false);
  const surface = cfg.get<string>('surface', 'security') as 'security' | 'quality' | 'all';
  const includeTests = cfg.get<boolean>('includeTests', false);
  const threshold = cfg.get<number>('threshold', 0.8);

  const cli = resolveVantageCli(cfg.get<string>('cliPath', ''));
  if (!cli) {
    vscode.window.showErrorMessage(
      'VANTAGE CLI not found. Set vantage.cliPath or install `vantage` on PATH / build monorepo (npm run build:mcp).'
    );
    return;
  }

  const reportPath = path.join(target, '.vantage', 'ide-report.json');
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `VANTAGE analyzing ${path.basename(target)}…`,
      cancellable: false,
    },
    async () => {
      try {
        const args = buildCliArgs(cli, target, reportPath, {
          semantic,
          surface,
          includeTests,
          threshold,
        });
        output.appendLine(`$ ${args.command} ${args.args.join(' ')}`);
        const { code, stderr } = await runProcess(args.command, args.args, target);
        if (code !== 0 && !fs.existsSync(reportPath)) {
          throw new Error(stderr || `vantage exited ${code}`);
        }
        if (stderr.trim()) output.appendLine(stderr.trim());

        const report = JSON.parse(fs.readFileSync(reportPath, 'utf8')) as VantageReport;
        lastReportPath = reportPath;
        applyDiagnostics(report, surface);
        const verdict = report.aurora?.verdict ?? '?';
        const score = report.aurora?.score != null ? `${(report.aurora.score * 100).toFixed(1)}%` : '?';
        const n = report.pulsar?.adversarialFindings?.length ?? 0;
        vscode.window
          .showInformationMessage(
            `VANTAGE ${verdict} (${score}) · ${n} finding(s) · surface=${surface}`,
            'Open Report'
          )
          .then((choice) => {
            if (choice === 'Open Report') vscode.commands.executeCommand('vantage.showReport');
          });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        output.appendLine(`ERROR: ${msg}`);
        vscode.window.showErrorMessage(`VANTAGE scan failed: ${msg}`);
      }
    }
  );
}

function resolveVantageCli(configured: string): string | undefined {
  if (configured && fs.existsSync(configured)) return configured;

  // Monorepo: packages/vantage-vscode → ../../bin/vantage.js
  const monorepoCli = path.resolve(__dirname, '..', '..', '..', 'bin', 'vantage.js');
  if (fs.existsSync(monorepoCli)) return monorepoCli;

  // Global / PATH name — leave to shell
  return 'vantage';
}

function buildCliArgs(
  cli: string,
  target: string,
  reportPath: string,
  opts: {
    semantic: boolean;
    surface: string;
    includeTests: boolean;
    threshold: number;
  }
): { command: string; args: string[] } {
  const isJsEntry = cli.endsWith('.js') || cli.endsWith('.cjs') || cli.endsWith('.mjs');
  const base = [
    'analyze',
    target,
    '--output',
    reportPath,
    '--surface',
    opts.surface,
  ];
  if (opts.semantic) base.push('--semantic');
  if (opts.includeTests) base.push('--include-tests');

  if (isJsEntry) {
    return { command: process.execPath, args: [cli, ...base] };
  }
  return { command: cli, args: base };
}

function runProcess(
  command: string,
  args: string[],
  cwd: string
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env },
      shell: false,
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d) => {
      stdout += d.toString();
      output.append(d.toString());
    });
    child.stderr?.on('data', (d) => {
      stderr += d.toString();
      output.append(d.toString());
    });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.on('error', (err) => resolve({ code: 1, stdout, stderr: err.message }));
  });
}

function applyDiagnostics(report: VantageReport, surfacePref: string): void {
  diagnosticCollection.clear();
  const findings = report.pulsar?.adversarialFindings ?? [];
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    const surface = f.surface || 'security';
    if (surfacePref === 'security' && surface === 'quality') continue;
    if (surfacePref === 'quality' && surface !== 'quality') continue;

    const filePath = f.file;
    if (!filePath || !fs.existsSync(filePath)) continue;

    const line = Math.max(0, (f.line ?? 1) - 1);
    const severity = mapSeverity(f.severity);
    const range = new vscode.Range(line, 0, line, 200);
    const msg = `[${surface}] ${f.description || f.type || 'finding'}`;
    const diag = new vscode.Diagnostic(range, msg, severity);
    diag.source = 'VANTAGE';
    diag.code = f.type || f.sink || 'vantage';

    const list = byFile.get(filePath) ?? [];
    list.push(diag);
    byFile.set(filePath, list);
  }

  for (const [filePath, diags] of byFile) {
    diagnosticCollection.set(vscode.Uri.file(filePath), diags);
  }
}

function mapSeverity(sev?: string): vscode.DiagnosticSeverity {
  switch ((sev || '').toUpperCase()) {
    case 'HIGH':
    case 'CRITICAL':
      return vscode.DiagnosticSeverity.Error;
    case 'MED':
    case 'MEDIUM':
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

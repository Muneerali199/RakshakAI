import * as vscode from 'vscode';
import axios from 'axios';

interface Finding {
  vulnerability: string | null;
  cwe: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  confidence: number;
  root_cause: string | null;
  attack_scenario: string | null;
  secure_fix: string | null;
  patched_code: string | null;
  references: string[];
}

interface ScanResponse {
  finding: Finding;
  engine: string;
  latency_ms: number;
  v1_prefilter?: any;
}

const RAKSHAK_DIAG = 'rakshakai-v2';

function getConfig() {
  const cfg = vscode.workspace.getConfiguration('rakshakai');
  return {
    serverUrl: cfg.get<string>('serverUrl', 'http://localhost:8080'),
    scanOnSave: cfg.get<boolean>('scanOnSave', true),
    severityFilter: cfg.get<string[]>('severityFilter', ['critical', 'high', 'medium']),
    minConfidence: cfg.get<number>('minConfidence', 0.6),
  };
}

function langIdFor(doc: vscode.TextDocument): string {
  switch (doc.languageId) {
    case 'python':       return 'python';
    case 'javascript':   return 'javascript';
    case 'typescript':   return 'typescript';
    case 'java':         return 'java';
    case 'go':           return 'go';
    case 'rust':         return 'rust';
    case 'c':            return 'c';
    case 'cpp':          return 'cpp';
    default:             return 'text';
  }
}

async function scanDocument(doc: vscode.TextDocument): Promise<void> {
  const cfg = getConfig();
  const code = doc.getText();
  if (!code.trim()) return;

  let resp: ScanResponse;
  try {
    const r = await axios.post<ScanResponse>(
      `${cfg.serverUrl}/v2/scan`,
      { code, language: langIdFor(doc), filename: doc.fileName },
      { timeout: 60_000 }
    );
    resp = r.data;
  } catch (e: any) {
    vscode.window.showWarningMessage(`RakshakAI v2: ${e?.message || 'server unreachable'}`);
    return;
  }

  const f = resp.finding;
  if (!f || !f.cwe) {
    return; // no finding
  }
  if (cfg.severityFilter.indexOf(f.severity ?? 'info') < 0) return;
  if ((f.confidence ?? 0) < cfg.minConfidence) return;

  const line = 0;
  const col = 0;
  const range = new vscode.Range(line, col, line, Math.max(1, code.split('\n')[0].length));
  const sev = vscode.DiagnosticSeverity[
    ({ critical: 'Error', high: 'Error', medium: 'Warning', low: 'Information', info: 'Information' } as any)[f.severity || 'info']
  ] ?? vscode.DiagnosticSeverity.Warning;

  const msg = [
    `[${f.severity?.toUpperCase()}] ${f.cwe} — ${f.vulnerability}`,
    f.root_cause ? `Root: ${f.root_cause}` : '',
    f.secure_fix ? `Fix: ${f.secure_fix}` : '',
  ].filter(Boolean).join('\n');

  const diag = new vscode.Diagnostic(range, msg, sev);
  diag.code = f.cwe ?? 'RAKSHAK';
  diag.source = RAKSHAK_DIAG;
  diag.relatedInformation = (f.references || []).slice(0, 3).map(url =>
    new vscode.DiagnosticRelatedInformation(
      new vscode.Location(doc.uri, range),
      url
    )
  );

  // Attach the patched code as part of the related info via a code action
  (diag as any).patched_code = f.patched_code;
  const collection = vscode.languages.createDiagnosticCollection(RAKSHAK_DIAG);
  collection.set(doc.uri, [diag]);
}

function applyPatchCommand(diag: vscode.Diagnostic): vscode.CodeAction {
  const fix = new vscode.CodeAction('Apply RakshakAI suggested patch', vscode.CodeActionKind.QuickFix);
  fix.diagnostics = [diag];
  fix.isPreferred = true;
  fix.command = {
    title: 'Apply patch',
    command: 'rakshakai.applyPatch',
    arguments: [diag],
  };
  return fix;
}

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.scanFile', () => {
      const ed = vscode.window.activeTextEditor;
      if (ed) scanDocument(ed.document);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.scanWorkspace', async () => {
      const docs = vscode.workspace.textDocuments;
      for (const d of docs) await scanDocument(d);
      vscode.window.showInformationMessage(`RakshakAI v2: scanned ${docs.length} open files`);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.showLastFinding', () => {
      const ed = vscode.window.activeTextEditor;
      if (!ed) return;
      const diags = vscode.languages.getDiagnostics(ed.document.uri);
      const mine = diags.filter(d => d.source === RAKSHAK_DIAG);
      if (!mine.length) {
        vscode.window.showInformationMessage('RakshakAI: no findings on this file.');
        return;
      }
      const panel = vscode.window.createWebviewPanel(
        'rakshakai', 'RakshakAI Finding', vscode.ViewColumn.Beside, { enableScripts: false }
      );
      panel.webview.html = `<pre style="white-space:pre-wrap;font-family:monospace">${mine.map(d => d.message).join('\n\n---\n\n')}</pre>`;
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.applyPatch', async (diag: vscode.Diagnostic) => {
      const ed = vscode.window.activeTextEditor;
      if (!ed) return;
      const patched = (diag as any).patched_code;
      if (!patched) {
        vscode.window.showInformationMessage('RakshakAI: no patch available for this finding.');
        return;
      }
      const fullRange = new vscode.Range(
        ed.document.positionAt(0),
        ed.document.positionAt(ed.document.getText().length)
      );
      await ed.edit(b => b.replace(fullRange, patched));
    })
  );

  // Code action provider
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [
        'python', 'javascript', 'typescript', 'java',
        'go', 'rust', 'c', 'cpp',
      ],
      {
        provideCodeActions: (doc, _range, ctx) =>
          ctx.diagnostics
            .filter(d => d.source === RAKSHAK_DIAG)
            .map(applyPatchCommand),
      }
    )
  );

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const cfg = getConfig();
      if (cfg.scanOnSave) scanDocument(doc);
    })
  );

  // Status bar
  const sb = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  sb.text = '$(shield) RakshakAI';
  sb.tooltip = 'Click to scan current file';
  sb.command = 'rakshakai.scanFile';
  sb.show();
  context.subscriptions.push(sb);
}

export function deactivate() {}

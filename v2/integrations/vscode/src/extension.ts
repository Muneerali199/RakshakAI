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
const abortControllers = new Map<string, AbortController>();
const findingsCache = new Map<string, ScanResponse>();

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
  const map: Record<string, string> = {
    python: 'python', javascript: 'javascript', typescript: 'typescript',
    java: 'java', go: 'go', rust: 'rust', c: 'c', cpp: 'cpp',
    php: 'php', csharp: 'csharp', ruby: 'ruby',
  };
  return map[doc.languageId] || 'text';
}

function checkServerUrlWarning(cfg: ReturnType<typeof getConfig>) {
  const url = cfg.serverUrl;
  if (!url.includes('localhost') && !url.includes('127.0.0.1')) {
    vscode.window.showWarningMessage(
      `RakshakAI: Server URL is not localhost (${url}). Code will be sent to a remote server.`
    );
  }
}

async function scanDocument(doc: vscode.TextDocument): Promise<void> {
  const cfg = getConfig();
  const code = doc.getText();
  if (!code.trim()) return;

  const docId = doc.uri.toString();

  // Cancel any in-flight scan for this document (race condition fix)
  const existing = abortControllers.get(docId);
  if (existing) existing.abort();
  const controller = new AbortController();
  abortControllers.set(docId, controller);

  let resp: ScanResponse;
  try {
    const r = await axios.post<ScanResponse>(
      `${cfg.serverUrl}/v2/scan`,
      { code, language: langIdFor(doc), filename: doc.fileName },
      { timeout: 10_000, signal: controller.signal }
    );
    resp = r.data;
  } catch (e: any) {
    if (e?.code === 'ERR_CANCELED' || e?.name === 'CanceledError') return;
    vscode.window.showWarningMessage(`RakshakAI: ${e?.message || 'server unreachable'}`);
    return;
  } finally {
    abortControllers.delete(docId);
  }

  findingsCache.set(docId, resp);

  const f = resp.finding;
  if (!f || !f.cwe) return;
  if (cfg.severityFilter.indexOf(f.severity ?? 'info') < 0) return;
  if ((f.confidence ?? 0) < cfg.minConfidence) return;

  const range = new vscode.Range(0, 0, 0, Math.max(1, code.split('\n')[0].length));
  const severityMap: Record<string, vscode.DiagnosticSeverity> = {
    critical: vscode.DiagnosticSeverity.Error,
    high: vscode.DiagnosticSeverity.Error,
    medium: vscode.DiagnosticSeverity.Warning,
    low: vscode.DiagnosticSeverity.Information,
    info: vscode.DiagnosticSeverity.Information,
  };
  const sev = severityMap[f.severity || 'info'] ?? vscode.DiagnosticSeverity.Warning;

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

// TreeDataProvider for scanned files
class RakshakTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private items: vscode.TreeItem[] = [];

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    const diags = vscode.languages.getDiagnostics();
    this.items = [];
    for (const [uri, diagList] of diags) {
      const rakshakDiags = diagList.filter(d => d.source === RAKSHAK_DIAG);
      if (rakshakDiags.length > 0) {
        const item = new vscode.TreeItem(uri.fsPath.split('/').pop() || uri.fsPath);
        item.resourceUri = uri;
        item.tooltip = `${rakshakDiags.length} finding(s)`;
        item.iconPath = vscode.ThemeIcon.File;
        item.command = {
          command: 'vscode.open',
          title: 'Open File',
          arguments: [uri],
        };
        this.items.push(item);
      }
    }
    return this.items;
  }
}

export function activate(context: vscode.ExtensionContext) {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection(RAKSHAK_DIAG);
  const treeDataProvider = new RakshakTreeProvider();

  // Register tree view once
  vscode.window.registerTreeDataProvider('rakshak-files', treeDataProvider);

  // Check server URL on activation
  checkServerUrlWarning(getConfig());

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
      treeDataProvider.refresh();
      vscode.window.showInformationMessage(`RakshakAI: scanned ${docs.length} open files`);
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

  // Code action provider — all supported languages
  const supportedLanguages = [
    'python', 'javascript', 'typescript', 'java',
    'go', 'rust', 'c', 'cpp', 'php', 'csharp', 'ruby',
  ];
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      supportedLanguages,
      {
        provideCodeActions: (_doc, _range, ctx) =>
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

  // Cleanup on file close (memory fix)
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(doc => {
      const docId = doc.uri.toString();
      findingsCache.delete(docId);
      abortControllers.delete(docId);
      diagnosticCollection.delete(doc.uri);
    })
  );

  // Status bar
  const sb = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  sb.text = '$(shield) Rakshak';
  sb.tooltip = 'Click to scan current file';
  sb.command = 'rakshakai.scanFile';
  sb.show();
  context.subscriptions.push(sb);
}

export function deactivate() {
  for (const controller of abortControllers.values()) {
    controller.abort();
  }
  abortControllers.clear();
  findingsCache.clear();
}

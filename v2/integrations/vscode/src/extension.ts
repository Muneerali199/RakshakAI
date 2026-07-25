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
}

interface FixResponse {
  patched_code: string;
  explanation: string;
  latency_ms: number;
  provider: string;
}

interface ProviderInfo {
  models: { id: string; name: string; speed: string }[];
  available: boolean;
}

const RAKSHAK_DIAG = 'rakshakai-v2';
const abortControllers = new Map<string, AbortController>();
const findingsCache = new Map<string, Finding>();
let totalScans = 0;
let totalFindings = 0;

function getConfig() {
  const cfg = vscode.workspace.getConfiguration('rakshakai');
  return {
    serverUrl: cfg.get<string>('serverUrl', 'http://localhost:8080'),
    scanOnSave: cfg.get<boolean>('scanOnSave', true),
    severityFilter: cfg.get<string[]>('severityFilter', ['critical', 'high', 'medium']),
    minConfidence: cfg.get<number>('minConfidence', 0.6),
    provider: cfg.get<string>('provider', 'ollama'),
    model: cfg.get<string>('model', ''),
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

// ─── Dashboard Webview ───

function getDashboardHtml(findings: { file: string; finding: Finding }[], provider: string): string {
  const critical = findings.filter(f => f.finding.severity === 'critical').length;
  const high = findings.filter(f => f.finding.severity === 'high').length;
  const medium = findings.filter(f => f.finding.severity === 'medium').length;
  const low = findings.filter(f => f.finding.severity === 'low').length;
  const total = findings.length;

  const findingCards = findings.map(f => {
    const sevColor: Record<string, string> = {
      critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280'
    };
    const sevBg: Record<string, string> = {
      critical: 'rgba(239,68,68,0.1)', high: 'rgba(249,115,22,0.1)', medium: 'rgba(234,179,8,0.1)',
      low: 'rgba(59,130,246,0.1)', info: 'rgba(107,114,128,0.1)'
    };
    const sev = f.finding.severity || 'info';
    const fileShort = f.file.split('/').pop() || f.file;
    return `
      <div style="background:${sevBg[sev]};border:1px solid ${sevColor[sev]}40;border-radius:10px;padding:14px;margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <span style="color:${sevColor[sev]};font-weight:700;font-size:13px;text-transform:uppercase">${sev}</span>
          <span style="color:#888;font-size:11px">${f.finding.cwe || ''}</span>
        </div>
        <div style="color:#e5e5e5;font-size:13px;font-weight:600;margin-bottom:4px">${escapeHtml(f.finding.vulnerability || 'Unknown')}</div>
        <div style="color:#aaa;font-size:11px">${escapeHtml(fileShort)}</div>
        ${f.finding.secure_fix ? `<div style="color:#4ade80;font-size:11px;margin-top:6px">💡 ${escapeHtml(f.finding.secure_fix.slice(0, 120))}</div>` : ''}
      </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #e5e5e5; padding: 24px; }
    .header { text-align: center; margin-bottom: 28px; }
    .logo { font-size: 42px; margin-bottom: 4px; }
    h1 { font-size: 22px; font-weight: 800; background: linear-gradient(135deg, #4ade80, #22d3ee); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .subtitle { color: #888; font-size: 12px; margin-top: 4px; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .stat { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 16px; text-align: center; }
    .stat-num { font-size: 28px; font-weight: 800; }
    .stat-label { font-size: 11px; color: #888; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-critical .stat-num { color: #ef4444; }
    .stat-high .stat-num { color: #f97316; }
    .stat-medium .stat-num { color: #eab308; }
    .stat-total .stat-num { color: #4ade80; }
    .section-title { color: #888; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; font-weight: 600; }
    .provider-badge { display: inline-block; background: #1f2937; border: 1px solid #374151; border-radius: 20px; padding: 6px 14px; font-size: 12px; color: #9ca3af; margin-bottom: 20px; }
    .provider-badge span { color: #4ade80; font-weight: 600; }
    .empty { text-align: center; padding: 48px; color: #555; }
    .empty-icon { font-size: 48px; margin-bottom: 12px; }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">🛡️</div>
    <h1>RakshakAI Dashboard</h1>
    <div class="subtitle">Security Code Analysis</div>
  </div>

  <div style="text-align:center">
    <div class="provider-badge">Provider: <span>${provider}</span> &nbsp;|&nbsp; Scans: <span>${totalScans}</span></div>
  </div>

  <div class="stats">
    <div class="stat stat-critical">
      <div class="stat-num">${critical}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat stat-high">
      <div class="stat-num">${high}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat stat-medium">
      <div class="stat-num">${medium}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat stat-total">
      <div class="stat-num">${total}</div>
      <div class="stat-label">Total</div>
    </div>
  </div>

  <div class="section-title">Findings</div>
  ${total > 0 ? findingCards : `
    <div class="empty">
      <div class="empty-icon">✅</div>
      <div>No vulnerabilities found</div>
      <div style="font-size:12px;color:#555;margin-top:4px">Your code looks secure!</div>
    </div>
  `}
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ─── Scan ───

async function scanDocument(doc: vscode.TextDocument): Promise<void> {
  const cfg = getConfig();
  const code = doc.getText();
  if (!code.trim()) return;

  const docId = doc.uri.toString();
  const existing = abortControllers.get(docId);
  if (existing) existing.abort();
  const controller = new AbortController();
  abortControllers.set(docId, controller);

  const payload: any = { code, language: langIdFor(doc), filename: doc.fileName };
  if (cfg.provider) payload.provider = cfg.provider;
  if (cfg.model) payload.model = cfg.model;

  let resp: ScanResponse;
  try {
    const r = await axios.post<ScanResponse>(
      `${cfg.serverUrl}/v2/scan`, payload,
      { timeout: 30_000, signal: controller.signal }
    );
    resp = r.data;
  } catch (e: any) {
    if (e?.code === 'ERR_CANCELED' || e?.name === 'CanceledError') return;
    return;
  } finally {
    abortControllers.delete(docId);
  }

  totalScans++;
  const f = resp.finding;
  if (!f || !f.cwe) return;
  if (cfg.severityFilter.indexOf(f.severity ?? 'info') < 0) return;
  if ((f.confidence ?? 0) < cfg.minConfidence) return;

  findingsCache.set(docId, f);
  totalFindings++;

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
    `${f.severity?.toUpperCase()} | ${f.cwe} | ${f.vulnerability}`,
    f.root_cause ? `Root: ${f.root_cause}` : '',
    f.secure_fix ? `Fix: ${f.secure_fix}` : '',
  ].filter(Boolean).join('\n');

  const diag = new vscode.Diagnostic(range, msg, sev);
  diag.code = f.cwe ?? 'RAKSHAK';
  diag.source = RAKSHAK_DIAG;

  (diag as any).patched_code = f.patched_code;
  (diag as any).vulnerability = f.vulnerability;
  (diag as any).cwe = f.cwe;
  (diag as any).root_cause = f.root_cause;

  const collection = vscode.languages.createDiagnosticCollection(RAKSHAK_DIAG);
  collection.set(doc.uri, [diag]);
}

// ─── Diff Preview ───

function showDiffPreview(
  oldCode: string, newCode: string, explanation: string, fileName: string
): Thenable<boolean> {
  const panel = vscode.window.createWebviewPanel(
    'rakshakai-diff', `RakshakAI Fix — ${fileName}`,
    vscode.ViewColumn.Beside, { enableScripts: false }
  );

  const oldLines = oldCode.split('\n');
  const newLines = newCode.split('\n');

  let diffHtml = '';
  let adds = 0, dels = 0;
  const maxLen = Math.max(oldLines.length, newLines.length);
  for (let i = 0; i < maxLen; i++) {
    const oldLine = oldLines[i] || '';
    const newLine = newLines[i] || '';
    const lineNum = String(i + 1).padStart(3);
    if (oldLine !== newLine) {
      if (oldLine) { diffHtml += `<div class="del"><span class="ln">${lineNum}</span> - ${escapeHtml(oldLine)}</div>`; dels++; }
      if (newLine) { diffHtml += `<div class="add"><span class="ln">${lineNum}</span> + ${escapeHtml(newLine)}</div>`; adds++; }
    } else {
      diffHtml += `<div class="ctx"><span class="ln">${lineNum}</span>   ${escapeHtml(oldLine)}</div>`;
    }
  }

  panel.webview.html = `<!DOCTYPE html>
<html>
<head>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'SF Mono', 'Fira Code', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; font-size: 13px; }
    .header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
    .header h3 { font-size: 16px; font-weight: 700; color: #4ade80; }
    .badge { display: inline-block; background: #1f2937; border-radius: 12px; padding: 3px 10px; font-size: 11px; color: #9ca3af; }
    .badge.green { border: 1px solid #22c55e40; color: #4ade80; }
    .badge.red { border: 1px solid #ef444440; color: #f87171; }
    .explanation { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #4ade80; padding: 14px; border-radius: 8px; margin-bottom: 16px; font-family: -apple-system, sans-serif; font-size: 13px; color: #e5e5e5; line-height: 1.5; }
    .explanation strong { color: #4ade80; }
    .diff { border: 1px solid #30363d; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }
    .diff-header { background: #161b22; padding: 8px 12px; border-bottom: 1px solid #30363d; font-size: 11px; color: #888; display: flex; justify-content: space-between; }
    .add { background: #0d2818; padding: 2px 12px; border-left: 3px solid #22c55e; color: #4ade80; white-space: pre; }
    .del { background: #2d0f0f; padding: 2px 12px; border-left: 3px solid #ef4444; color: #f87171; white-space: pre; }
    .ctx { padding: 2px 12px; color: #555; white-space: pre; }
    .ln { color: #444; display: inline-block; width: 32px; text-align: right; margin-right: 12px; user-select: none; }
    .buttons { display: flex; gap: 10px; }
    button { padding: 10px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.15s; }
    button:hover { transform: translateY(-1px); }
    .accept { background: linear-gradient(135deg, #22c55e, #16a34a); color: white; box-shadow: 0 2px 8px rgba(34,197,94,0.3); }
    .reject { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
    .reject:hover { border-color: #ef4444; color: #f87171; }
  </style>
</head>
<body>
  <div class="header">
    <h3>🛡️ Security Fix</h3>
    <span class="badge green">+${adds} lines</span>
    <span class="badge red">-${dels} lines</span>
  </div>
  <div class="explanation"><strong>Fix:</strong> ${escapeHtml(explanation)}</div>
  <div class="diff">
    <div class="diff-header"><span>patched code</span><span>${escapeHtml(fileName)}</span></div>
    ${diffHtml}
  </div>
  <div class="buttons">
    <button class="accept">✅ Apply Fix</button>
    <button class="reject">❌ Cancel</button>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    document.querySelector('.accept').addEventListener('click', () => vscode.postMessage({ action: 'accept' }));
    document.querySelector('.reject').addEventListener('click', () => vscode.postMessage({ action: 'reject' }));
  </script>
</body>
</html>`;

  return new Promise<boolean>((resolve) => {
    panel.webview.onDidReceiveMessage((msg) => { panel.dispose(); resolve(msg.action === 'accept'); });
    panel.onDidDispose(() => resolve(false));
  });
}

// ─── Fix with LLM ───

async function fixWithLLM(doc: vscode.TextDocument, diag: vscode.Diagnostic): Promise<void> {
  const cfg = getConfig();
  const code = doc.getText();
  const f = findingsCache.get(doc.uri.toString()) || (diag as any);

  const vuln = f.vulnerability || 'Unknown vulnerability';
  const cwe = f.cwe || diag.code || '';
  const rootCause = f.root_cause || '';

  vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `🛡️ Generating fix via ${cfg.provider}...` },
    async () => {
      const payload: any = {
        code, language: langIdFor(doc),
        vulnerability: vuln, cwe: String(cwe), root_cause: rootCause,
        filename: doc.fileName,
      };
      if (cfg.provider) payload.provider = cfg.provider;
      if (cfg.model) payload.model = cfg.model;

      let fixResp: FixResponse;
      try {
        const r = await axios.post<FixResponse>(`${cfg.serverUrl}/v2/fix`, payload, { timeout: 30_000 });
        fixResp = r.data;
      } catch (e: any) {
        vscode.window.showErrorMessage(`Fix failed: ${e?.message || 'server error'}`);
        return;
      }

      if (!fixResp.patched_code) {
        vscode.window.showWarningMessage('LLM did not return patched code.');
        return;
      }

      const accepted = await showDiffPreview(
        code, fixResp.patched_code,
        fixResp.explanation || 'Security fix applied',
        doc.fileName.split('/').pop() || doc.fileName
      );

      if (accepted) {
        const fullRange = new vscode.Range(doc.positionAt(0), doc.positionAt(code.length));
        const editor = vscode.window.activeTextEditor;
        if (editor) {
          await editor.edit((eb: vscode.TextEditorEdit) => eb.replace(fullRange, fixResp.patched_code));
        }
        vscode.window.showInformationMessage(`✅ Fix applied via ${fixResp.provider || cfg.provider}`);
      }
    }
  );
}

// ─── Code Action ───

function applyPatchCommand(diag: vscode.Diagnostic): vscode.CodeAction {
  const fix = new vscode.CodeAction('🛡️ Fix with RakshakAI', vscode.CodeActionKind.QuickFix);
  fix.diagnostics = [diag];
  fix.isPreferred = true;
  fix.command = { title: 'Fix', command: 'rakshakai.fixIssue', arguments: [diag] };
  return fix;
}

// ─── Tree View ───

class RakshakTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  refresh(): void { this._onDidChangeTreeData.fire(undefined); }
  getTreeItem(el: vscode.TreeItem): vscode.TreeItem { return el; }

  getChildren(): vscode.TreeItem[] {
    const items: vscode.TreeItem[] = [];
    const allDiags = vscode.languages.getDiagnostics();
    let count = 0;

    for (const [uri, diagList] of allDiags) {
      const rakshakDiags = diagList.filter(d => d.source === RAKSHAK_DIAG);
      if (rakshakDiags.length === 0) continue;
      count += rakshakDiags.length;

      const fileItem = new vscode.TreeItem(uri.fsPath.split('/').pop() || uri.fsPath);
      fileItem.resourceUri = uri;
      fileItem.iconPath = new vscode.ThemeIcon('file-code');
      fileItem.command = { command: 'vscode.open', title: 'Open', arguments: [uri] };
      fileItem.description = `${rakshakDiags.length} issue(s)`;
      items.push(fileItem);
    }

    if (items.length === 0) {
      const welcome = new vscode.TreeItem('No findings — code is secure ✅');
      welcome.iconPath = new vscode.ThemeIcon('check');
      items.push(welcome);
    }

    return items;
  }
}

// ─── Activate ───

export function activate(context: vscode.ExtensionContext) {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection(RAKSHAK_DIAG);
  const treeProvider = new RakshakTreeProvider();
  vscode.window.registerTreeDataProvider('rakshak-files', treeProvider);

  const cfg = getConfig();

  // ─── Commands ───

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.scanFile', () => {
      const ed = vscode.window.activeTextEditor;
      if (ed) scanDocument(ed.document);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.scanWorkspace', async () => {
      const docs = vscode.workspace.textDocuments;
      vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: '🛡️ Scanning workspace...' },
        async () => {
          for (const d of docs) await scanDocument(d);
          treeProvider.refresh();
        }
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.showLastFinding', () => {
      const ed = vscode.window.activeTextEditor;
      if (!ed) return;
      const diags = vscode.languages.getDiagnostics(ed.document.uri);
      const mine = diags.filter(d => d.source === RAKSHAK_DIAG);
      if (!mine.length) {
        vscode.window.showInformationMessage('No findings for this file.');
        return;
      }
      const panel = vscode.window.createWebviewPanel(
        'rakshakai', 'RakshakAI Findings', vscode.ViewColumn.Beside, { enableScripts: false }
      );
      panel.webview.html = `<pre style="white-space:pre-wrap;font-family:monospace">${mine.map(d => d.message).join('\n\n---\n\n')}</pre>`;
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.fixIssue', async (diag: vscode.Diagnostic) => {
      const ed = vscode.window.activeTextEditor;
      if (!ed) return;
      await fixWithLLM(ed.document, diag);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.applyPatch', async (diag: vscode.Diagnostic) => {
      const ed = vscode.window.activeTextEditor;
      if (!ed) return;
      const patched = (diag as any).patched_code;
      if (!patched) {
        vscode.window.showInformationMessage('No patch available. Use "Fix with RakshakAI" for AI fix.');
        return;
      }
      const fullRange = new vscode.Range(ed.document.positionAt(0), ed.document.positionAt(ed.document.getText().length));
      await ed.edit(b => b.replace(fullRange, patched));
    })
  );

  // ─── Provider Picker ───

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.chooseProvider', async () => {
      const providers = ['ollama', 'groq', 'fireworks', 'nebius', 'huggingface'];
      const labels: Record<string, string> = {
        ollama: '🦙 Ollama — Local, Free, Private',
        groq: '⚡ Groq — Fast, Free Tier',
        fireworks: '🔥 Fireworks AI — Paid, Fast',
        nebius: '🌐 Nebius — Kimi K2.7, Qwen 3.5',
        huggingface: '🤗 HuggingFace — Free Tier',
      };

      const chosen = await vscode.window.showQuickPick(
        providers.map(p => ({ label: labels[p], description: p })),
        { placeHolder: 'Select LLM provider', title: '🛡️ Choose Provider' }
      );
      if (!chosen) return;

      const provider = chosen.description!;
      let models: { id: string; name: string; speed: string }[] = [];
      try {
        const r = await axios.get<Record<string, ProviderInfo>>(
          `${cfg.serverUrl}/v2/providers`, { timeout: 5_000 }
        );
        models = r.data[provider]?.models || [];
      } catch {
        models = [{ id: 'default', name: 'Default', speed: 'fast' }];
      }

      const picked = await vscode.window.showQuickPick(
        models.map(m => ({
          label: `$(rocket) ${m.name}`,
          description: m.id,
          detail: `Speed: ${m.speed}`,
        })),
        { placeHolder: `Select model for ${provider}`, title: '🛡️ Choose Model' }
      );

      const model = picked?.description || '';
      await vscode.workspace.getConfiguration('rakshakai').update('provider', provider, vscode.ConfigurationTarget.Global);
      await vscode.workspace.getConfiguration('rakshakai').update('model', model, vscode.ConfigurationTarget.Global);
      vscode.window.showInformationMessage(`🛡️ Provider: ${provider} | Model: ${model || 'default'}`);
    })
  );

  // ─── Dashboard ───

  context.subscriptions.push(
    vscode.commands.registerCommand('rakshakai.dashboard', () => {
      const panel = vscode.window.createWebviewPanel(
        'rakshakai-dashboard', '🛡️ RakshakAI Dashboard',
        vscode.ViewColumn.One, { enableScripts: false }
      );

      const findings: { file: string; finding: Finding }[] = [];
      for (const [uri, diagList] of vscode.languages.getDiagnostics()) {
        for (const d of diagList) {
          if (d.source === RAKSHAK_DIAG) {
            const f = findingsCache.get(uri.toString());
            if (f) findings.push({ file: uri.fsPath, finding: f });
          }
        }
      }

      panel.webview.html = getDashboardHtml(findings, cfg.provider);
    })
  );

  // ─── Code Actions ───

  const langs = ['python', 'javascript', 'typescript', 'java', 'go', 'rust', 'c', 'cpp', 'php', 'csharp', 'ruby'];
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(langs, {
      provideCodeActions: (_doc, _range, ctx) =>
        ctx.diagnostics.filter(d => d.source === RAKSHAK_DIAG).map(applyPatchCommand),
    })
  );

  // ─── Events ───

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (getConfig().scanOnSave) scanDocument(doc);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(doc => {
      findingsCache.delete(doc.uri.toString());
      abortControllers.delete(doc.uri.toString());
      diagnosticCollection.delete(doc.uri);
    })
  );

  // ─── Status Bar ───

  const sb = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  sb.text = '$(shield) Rakshak';
  sb.tooltip = `Provider: ${cfg.provider} | Click to scan`;
  sb.command = 'rakshakai.scanFile';
  sb.show();
  context.subscriptions.push(sb);
}

export function deactivate() {
  for (const c of abortControllers.values()) c.abort();
  abortControllers.clear();
  findingsCache.clear();
}

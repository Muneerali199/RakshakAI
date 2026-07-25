"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const axios_1 = __importDefault(require("axios"));
const RAKSHAK_DIAG = 'rakshakai-v2';
const abortControllers = new Map();
const findingsCache = new Map();
function getConfig() {
    const cfg = vscode.workspace.getConfiguration('rakshakai');
    return {
        serverUrl: cfg.get('serverUrl', 'http://localhost:8080'),
        scanOnSave: cfg.get('scanOnSave', true),
        severityFilter: cfg.get('severityFilter', ['critical', 'high', 'medium']),
        minConfidence: cfg.get('minConfidence', 0.6),
    };
}
function langIdFor(doc) {
    const map = {
        python: 'python', javascript: 'javascript', typescript: 'typescript',
        java: 'java', go: 'go', rust: 'rust', c: 'c', cpp: 'cpp',
        php: 'php', csharp: 'csharp', ruby: 'ruby',
    };
    return map[doc.languageId] || 'text';
}
async function scanDocument(doc) {
    const cfg = getConfig();
    const code = doc.getText();
    if (!code.trim())
        return;
    const docId = doc.uri.toString();
    const existing = abortControllers.get(docId);
    if (existing)
        existing.abort();
    const controller = new AbortController();
    abortControllers.set(docId, controller);
    let resp;
    try {
        const r = await axios_1.default.post(`${cfg.serverUrl}/v2/scan`, { code, language: langIdFor(doc), filename: doc.fileName }, { timeout: 10_000, signal: controller.signal });
        resp = r.data;
    }
    catch (e) {
        if (e?.code === 'ERR_CANCELED' || e?.name === 'CanceledError')
            return;
        vscode.window.showWarningMessage(`RakshakAI: ${e?.message || 'server unreachable'}`);
        return;
    }
    finally {
        abortControllers.delete(docId);
    }
    const f = resp.finding;
    if (!f || !f.cwe)
        return;
    if (cfg.severityFilter.indexOf(f.severity ?? 'info') < 0)
        return;
    if ((f.confidence ?? 0) < cfg.minConfidence)
        return;
    findingsCache.set(docId, f);
    const range = new vscode.Range(0, 0, 0, Math.max(1, code.split('\n')[0].length));
    const severityMap = {
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
    diag.patched_code = f.patched_code;
    diag.vulnerability = f.vulnerability;
    diag.cwe = f.cwe;
    diag.root_cause = f.root_cause;
    const collection = vscode.languages.createDiagnosticCollection(RAKSHAK_DIAG);
    collection.set(doc.uri, [diag]);
}
function showDiffPreview(oldCode, newCode, explanation, fileName) {
    const panel = vscode.window.createWebviewPanel('rakshakai-diff', `RakshakAI Fix — ${fileName}`, vscode.ViewColumn.Beside, { enableScripts: false });
    const oldLines = oldCode.split('\n');
    const newLines = newCode.split('\n');
    let diffHtml = '';
    const maxLen = Math.max(oldLines.length, newLines.length);
    for (let i = 0; i < maxLen; i++) {
        const oldLine = oldLines[i] || '';
        const newLine = newLines[i] || '';
        if (oldLine !== newLine) {
            if (oldLine)
                diffHtml += `<div style="background:#3c1e1e;padding:2px 8px;font-family:monospace;color:#f87171">- ${escapeHtml(oldLine)}</div>`;
            if (newLine)
                diffHtml += `<div style="background:#1e3c1e;padding:2px 8px;font-family:monospace;color:#4ade80">+ ${escapeHtml(newLine)}</div>`;
        }
        else {
            diffHtml += `<div style="padding:2px 8px;font-family:monospace;color:#888">  ${escapeHtml(oldLine)}</div>`;
        }
    }
    panel.webview.html = `<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, sans-serif; margin: 0; padding: 16px; background: #1e1e1e; color: #ddd; }
    h3 { color: #4ade80; margin-top: 0; }
    .explanation { background: #2d2d2d; padding: 12px; border-radius: 6px; margin-bottom: 16px; border-left: 3px solid #4ade80; }
    .diff { border: 1px solid #444; border-radius: 6px; overflow: hidden; margin-bottom: 16px; }
    .buttons { display: flex; gap: 8px; }
    button { padding: 8px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; }
    .accept { background: #22c55e; color: white; }
    .reject { background: #ef4444; color: white; }
  </style>
</head>
<body>
  <h3>🛡️ RakshakAI Security Fix</h3>
  <div class="explanation"><strong>Fix:</strong> ${escapeHtml(explanation)}</div>
  <div class="diff">${diffHtml}</div>
  <div class="buttons">
    <button class="accept" onclick="void(0)">✅ Apply Fix</button>
    <button class="reject" onclick="void(0)">❌ Cancel</button>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    document.querySelector('.accept').addEventListener('click', () => vscode.postMessage({ action: 'accept' }));
    document.querySelector('.reject').addEventListener('click', () => vscode.postMessage({ action: 'reject' }));
  </script>
</body>
</html>`;
    return new Promise((resolve) => {
        panel.webview.onDidReceiveMessage((msg) => {
            panel.dispose();
            resolve(msg.action === 'accept');
        });
        panel.onDidDispose(() => resolve(false));
    });
}
function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
async function fixWithLLM(doc, diag) {
    const cfg = getConfig();
    const code = doc.getText();
    const f = findingsCache.get(doc.uri.toString()) || diag;
    const vuln = f.vulnerability || f.vulnerability || 'Unknown vulnerability';
    const cwe = f.cwe || diag.code || '';
    const rootCause = f.root_cause || '';
    // Show loading
    vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'RakshakAI: Generating fix...' }, async () => {
        let fixResp;
        try {
            const r = await axios_1.default.post(`${cfg.serverUrl}/v2/fix`, {
                code,
                language: langIdFor(doc),
                vulnerability: vuln,
                cwe: cwe,
                root_cause: rootCause,
                filename: doc.fileName,
            }, { timeout: 30_000 });
            fixResp = r.data;
        }
        catch (e) {
            vscode.window.showErrorMessage(`RakshakAI: Fix failed — ${e?.message || 'server error'}`);
            return;
        }
        if (!fixResp.patched_code) {
            vscode.window.showWarningMessage('RakshakAI: LLM did not return patched code.');
            return;
        }
        // Show diff preview
        const accepted = await showDiffPreview(code, fixResp.patched_code, fixResp.explanation || 'Security fix applied', doc.fileName.split('/').pop() || doc.fileName);
        if (accepted) {
            const fullRange = new vscode.Range(doc.positionAt(0), doc.positionAt(code.length));
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                await editor.edit((editBuilder) => editBuilder.replace(fullRange, fixResp.patched_code));
            }
            vscode.window.showInformationMessage('RakshakAI: Fix applied!');
        }
    });
}
function applyPatchCommand(diag) {
    const fix = new vscode.CodeAction('🛡️ Fix with RakshakAI', vscode.CodeActionKind.QuickFix);
    fix.diagnostics = [diag];
    fix.isPreferred = true;
    fix.command = {
        title: 'Fix vulnerability',
        command: 'rakshakai.fixIssue',
        arguments: [diag],
    };
    return fix;
}
class RakshakTreeProvider {
    _onDidChangeTreeData = new vscode.EventEmitter();
    onDidChangeTreeData = this._onDidChangeTreeData.event;
    refresh() { this._onDidChangeTreeData.fire(undefined); }
    getTreeItem(element) { return element; }
    getChildren() {
        const items = [];
        for (const [uri, diagList] of vscode.languages.getDiagnostics()) {
            const rakshakDiags = diagList.filter(d => d.source === RAKSHAK_DIAG);
            if (rakshakDiags.length > 0) {
                const item = new vscode.TreeItem(uri.fsPath.split('/').pop() || uri.fsPath);
                item.resourceUri = uri;
                item.tooltip = `${rakshakDiags.length} finding(s)`;
                item.iconPath = vscode.ThemeIcon.File;
                item.command = { command: 'vscode.open', title: 'Open', arguments: [uri] };
                items.push(item);
            }
        }
        return items;
    }
}
function activate(context) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection(RAKSHAK_DIAG);
    const treeDataProvider = new RakshakTreeProvider();
    vscode.window.registerTreeDataProvider('rakshak-files', treeDataProvider);
    // Check server URL
    const cfg = getConfig();
    if (!cfg.serverUrl.includes('localhost') && !cfg.serverUrl.includes('127.0.0.1')) {
        vscode.window.showWarningMessage(`RakshakAI: Non-localhost server URL: ${cfg.serverUrl}`);
    }
    // Commands
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.scanFile', () => {
        const ed = vscode.window.activeTextEditor;
        if (ed)
            scanDocument(ed.document);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.scanWorkspace', async () => {
        const docs = vscode.workspace.textDocuments;
        for (const d of docs)
            await scanDocument(d);
        treeDataProvider.refresh();
        vscode.window.showInformationMessage(`RakshakAI: scanned ${docs.length} files`);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.showLastFinding', () => {
        const ed = vscode.window.activeTextEditor;
        if (!ed)
            return;
        const diags = vscode.languages.getDiagnostics(ed.document.uri);
        const mine = diags.filter(d => d.source === RAKSHAK_DIAG);
        if (!mine.length) {
            vscode.window.showInformationMessage('RakshakAI: no findings.');
            return;
        }
        const panel = vscode.window.createWebviewPanel('rakshakai', 'RakshakAI Finding', vscode.ViewColumn.Beside, { enableScripts: false });
        panel.webview.html = `<pre style="white-space:pre-wrap;font-family:monospace">${mine.map(d => d.message).join('\n\n---\n\n')}</pre>`;
    }));
    // One-click fix via LLM
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.fixIssue', async (diag) => {
        const ed = vscode.window.activeTextEditor;
        if (!ed)
            return;
        await fixWithLLM(ed.document, diag);
    }));
    // Apply patch (direct, no LLM)
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.applyPatch', async (diag) => {
        const ed = vscode.window.activeTextEditor;
        if (!ed)
            return;
        const patched = diag.patched_code;
        if (!patched) {
            vscode.window.showInformationMessage('RakshakAI: no patch available. Use "Fix with RakshakAI" for AI fix.');
            return;
        }
        const fullRange = new vscode.Range(ed.document.positionAt(0), ed.document.positionAt(ed.document.getText().length));
        await ed.edit(b => b.replace(fullRange, patched));
    }));
    // Code action provider
    const supportedLanguages = [
        'python', 'javascript', 'typescript', 'java',
        'go', 'rust', 'c', 'cpp', 'php', 'csharp', 'ruby',
    ];
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider(supportedLanguages, {
        provideCodeActions: (_doc, _range, ctx) => ctx.diagnostics
            .filter(d => d.source === RAKSHAK_DIAG)
            .map(applyPatchCommand),
    }));
    // Scan on save
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(doc => {
        if (getConfig().scanOnSave)
            scanDocument(doc);
    }));
    // Cleanup on file close
    context.subscriptions.push(vscode.workspace.onDidCloseTextDocument(doc => {
        const docId = doc.uri.toString();
        findingsCache.delete(docId);
        abortControllers.delete(docId);
        diagnosticCollection.delete(doc.uri);
    }));
    // Status bar
    const sb = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    sb.text = '$(shield) Rakshak';
    sb.tooltip = 'Click to scan current file';
    sb.command = 'rakshakai.scanFile';
    sb.show();
    context.subscriptions.push(sb);
}
function deactivate() {
    for (const c of abortControllers.values())
        c.abort();
    abortControllers.clear();
    findingsCache.clear();
}

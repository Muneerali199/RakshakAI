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
    switch (doc.languageId) {
        case 'python': return 'python';
        case 'javascript': return 'javascript';
        case 'typescript': return 'typescript';
        case 'java': return 'java';
        case 'go': return 'go';
        case 'rust': return 'rust';
        case 'c': return 'c';
        case 'cpp': return 'cpp';
        default: return 'text';
    }
}
async function scanDocument(doc) {
    const cfg = getConfig();
    const code = doc.getText();
    if (!code.trim())
        return;
    let resp;
    try {
        const r = await axios_1.default.post(`${cfg.serverUrl}/v2/scan`, { code, language: langIdFor(doc), filename: doc.fileName }, { timeout: 60_000 });
        resp = r.data;
    }
    catch (e) {
        vscode.window.showWarningMessage(`RakshakAI v2: ${e?.message || 'server unreachable'}`);
        return;
    }
    const f = resp.finding;
    if (!f || !f.cwe) {
        return; // no finding
    }
    if (cfg.severityFilter.indexOf(f.severity ?? 'info') < 0)
        return;
    if ((f.confidence ?? 0) < cfg.minConfidence)
        return;
    const line = 0;
    const col = 0;
    const range = new vscode.Range(line, col, line, Math.max(1, code.split('\n')[0].length));
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
    diag.relatedInformation = (f.references || []).slice(0, 3).map(url => new vscode.DiagnosticRelatedInformation(new vscode.Location(doc.uri, range), url));
    // Attach the patched code as part of the related info via a code action
    diag.patched_code = f.patched_code;
    const collection = vscode.languages.createDiagnosticCollection(RAKSHAK_DIAG);
    collection.set(doc.uri, [diag]);
}
function applyPatchCommand(diag) {
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
function activate(context) {
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.scanFile', () => {
        const ed = vscode.window.activeTextEditor;
        if (ed)
            scanDocument(ed.document);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.scanWorkspace', async () => {
        const docs = vscode.workspace.textDocuments;
        for (const d of docs)
            await scanDocument(d);
        vscode.window.showInformationMessage(`RakshakAI v2: scanned ${docs.length} open files`);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.showLastFinding', () => {
        const ed = vscode.window.activeTextEditor;
        if (!ed)
            return;
        const diags = vscode.languages.getDiagnostics(ed.document.uri);
        const mine = diags.filter(d => d.source === RAKSHAK_DIAG);
        if (!mine.length) {
            vscode.window.showInformationMessage('RakshakAI: no findings on this file.');
            return;
        }
        const panel = vscode.window.createWebviewPanel('rakshakai', 'RakshakAI Finding', vscode.ViewColumn.Beside, { enableScripts: false });
        panel.webview.html = `<pre style="white-space:pre-wrap;font-family:monospace">${mine.map(d => d.message).join('\n\n---\n\n')}</pre>`;
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.applyPatch', async (diag) => {
        const ed = vscode.window.activeTextEditor;
        if (!ed)
            return;
        const patched = diag.patched_code;
        if (!patched) {
            vscode.window.showInformationMessage('RakshakAI: no patch available for this finding.');
            return;
        }
        const fullRange = new vscode.Range(ed.document.positionAt(0), ed.document.positionAt(ed.document.getText().length));
        await ed.edit(b => b.replace(fullRange, patched));
    }));
    // Code action provider
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider([
        'python', 'javascript', 'typescript', 'java',
        'go', 'rust', 'c', 'cpp',
    ], {
        provideCodeActions: (doc, _range, ctx) => ctx.diagnostics
            .filter(d => d.source === RAKSHAK_DIAG)
            .map(applyPatchCommand),
    }));
    // Scan on save
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(doc => {
        const cfg = getConfig();
        if (cfg.scanOnSave)
            scanDocument(doc);
    }));
    // Status bar
    const sb = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    sb.text = '$(shield) RakshakAI';
    sb.tooltip = 'Click to scan current file';
    sb.command = 'rakshakai.scanFile';
    sb.show();
    context.subscriptions.push(sb);
}
function deactivate() { }

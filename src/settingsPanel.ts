/**
 * FLCN Sec — Settings Dashboard WebviewPanel.
 *
 * Opens as an editor-area tab (like a settings page). Shows live issue cards
 * at the top plus all configuration controls below.
 */

import * as vscode from "vscode";
import { installGitHook, uninstallGitHook, isHookInstalled, getGitRoot } from "./gitHook";
import { OsvFinding } from "./osvScanner";

// ---------------------------------------------------------------------------
// Public serialisable types
// ---------------------------------------------------------------------------

export interface CredIssueData {
  filePath: string;  // workspace-relative
  line: number;
  kind: string;
  preview: string;
}

export interface OsvIssueData {
  manifestFile: string;
  name: string;
  version: string;
  severity: string;
  vulnId: string;
  summary: string;
  url: string;
}

interface DashboardState {
  credIssues: CredIssueData[];
  osvIssues: OsvIssueData[];
  osvEverScanned: boolean;
  enableRealTimeScan: boolean;
  warnOnOpen: boolean;
  warnOnSave: boolean;
  severity: string;
  maxFileSizeKb: number;
  osvEnabled: boolean;
  osvScanOnOpen: boolean;
  osvScanIntervalMinutes: number;
  osvBlockSeverity: string;
  gitRootFound: boolean;
  gitHookInstalled: boolean;
  aiExclusionsInstalled: boolean;
  npmAuditEnabled: boolean;
  ghsaEnabled: boolean;
  nvdEnabled: boolean;
  githubToken: string;
  nvdApiKey: string;
}

type WebviewMsg =
  | { type: "updateSetting"; key: string; value: unknown }
  | { type: "installGitHook" }
  | { type: "uninstallGitHook" }
  | { type: "scanDependencies" }
  | { type: "excludeFromAI" }
  | { type: "openUrl"; url: string };

// ---------------------------------------------------------------------------
// Dashboard panel (editor area WebviewPanel)
// ---------------------------------------------------------------------------

export class SettingsPanel {
  private static _instance?: SettingsPanel;

  private readonly _panel: vscode.WebviewPanel;
  private readonly _output: vscode.OutputChannel;
  private _credIssues: CredIssueData[] = [];
  private _osvIssues: OsvIssueData[] = [];
  private _osvEverScanned = false;
  private _refreshTimer?: ReturnType<typeof setTimeout>;

  private constructor(panel: vscode.WebviewPanel, output: vscode.OutputChannel) {
    this._panel = panel;
    this._output = output;
    SettingsPanel._instance = this;

    panel.webview.options = { enableScripts: true };
    panel.webview.html = buildHtml();

    panel.webview.onDidReceiveMessage((msg: WebviewMsg) => this._handle(msg));

    panel.onDidChangeViewState(() => {
      if (panel.visible) this._sendState();
    });

    panel.onDidDispose(() => {
      if (SettingsPanel._instance === this) SettingsPanel._instance = undefined;
    });

    setTimeout(() => this._sendState(), 150);
  }

  static show(context: vscode.ExtensionContext, output: vscode.OutputChannel): void {
    if (SettingsPanel._instance) {
      SettingsPanel._instance._panel.reveal(vscode.ViewColumn.One);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "flcn-sec.dashboard",
      "FLCN Sec — Security Dashboard",
      vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    context.subscriptions.push(panel);
    new SettingsPanel(panel, output);
  }

  static setScanning(message: string): void {
    const p = SettingsPanel._instance;
    if (!p?._panel.visible) return;
    p._panel.webview.postMessage({ type: "scanning", message });
  }

  static refresh(
    credIssues?: CredIssueData[],
    osvFindings?: OsvFinding[],
    osvEverScanned?: boolean,
  ): void {
    const p = SettingsPanel._instance;
    if (!p) return;

    if (credIssues     !== undefined) p._credIssues     = credIssues;
    if (osvFindings    !== undefined) p._osvIssues      = SettingsPanel._toOsvData(osvFindings);
    if (osvEverScanned !== undefined) p._osvEverScanned = osvEverScanned;

    if (p._refreshTimer) clearTimeout(p._refreshTimer);
    p._refreshTimer = setTimeout(() => p._sendState(), 250);
  }

  private static _toOsvData(findings: OsvFinding[]): OsvIssueData[] {
    const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";
    return findings.map(f => ({
      manifestFile: root && f.manifestFile.startsWith(root)
        ? f.manifestFile.slice(root.length + 1)
        : f.manifestFile,
      name:     f.name,
      version:  f.version,
      severity: f.severity,
      vulnId:   f.vulnId,
      summary:  f.summary,
      url:      f.url,
    }));
  }

  private async _sendState(): Promise<void> {
    if (!this._panel.visible) return;

    const cfg  = vscode.workspace.getConfiguration("flcn-sec");
    const root = getGitRoot(vscode.workspace.workspaceFolders);
    const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";

    const credIssues = this._credIssues.map(c => ({
      ...c,
      filePath: wsRoot && c.filePath.startsWith(wsRoot)
        ? c.filePath.slice(wsRoot.length + 1)
        : c.filePath,
    }));

    const state: DashboardState = {
      credIssues,
      osvIssues:              this._osvIssues,
      osvEverScanned:         this._osvEverScanned,
      enableRealTimeScan:     cfg.get("enableRealTimeScan", true),
      warnOnOpen:             cfg.get("warnOnOpen", true),
      warnOnSave:             cfg.get("warnOnSave", true),
      severity:               cfg.get("severity", "error"),
      maxFileSizeKb:          cfg.get("maxFileSizeKb", 512),
      osvEnabled:             cfg.get("osv.enabled", true),
      osvScanOnOpen:          cfg.get("osv.scanOnOpen", true),
      osvScanIntervalMinutes: cfg.get("osv.scanIntervalMinutes", 60),
      osvBlockSeverity:       cfg.get("osv.blockSeverity", "HIGH"),
      gitRootFound:           !!root,
      gitHookInstalled:       root ? isHookInstalled(root) : false,
      aiExclusionsInstalled:  await this._aiInstalled(),
      npmAuditEnabled:        cfg.get("npmAudit.enabled", true),
      ghsaEnabled:            cfg.get("ghsa.enabled", true),
      nvdEnabled:             cfg.get("nvd.enabled", true),
      githubToken:            cfg.get("github.token", ""),
      nvdApiKey:              cfg.get("nvd.apiKey", ""),
    };

    this._panel.webview.postMessage({ type: "init", state });
  }

  private async _handle(msg: WebviewMsg): Promise<void> {
    switch (msg.type) {
      case "updateSetting":
        await vscode.workspace.getConfiguration("flcn-sec")
          .update(msg.key, msg.value, vscode.ConfigurationTarget.Global);
        break;

      case "installGitHook": {
        const root = getGitRoot(vscode.workspace.workspaceFolders);
        if (!root) {
          vscode.window.showWarningMessage("FLCN Sec: No git repository found.");
          break;
        }
        const ok = await installGitHook(root, this._output);
        vscode.window.showInformationMessage(
          ok ? "FLCN Sec: Pre-commit hook installed." : "FLCN Sec: Could not install hook.",
        );
        this._sendState();
        break;
      }

      case "uninstallGitHook": {
        const root = getGitRoot(vscode.workspace.workspaceFolders);
        if (!root) break;
        const ok = uninstallGitHook(root, this._output);
        vscode.window.showInformationMessage(
          ok ? "FLCN Sec: Pre-commit hook removed." : "FLCN Sec: Hook was not managed by flcn-sec.",
        );
        this._sendState();
        break;
      }

      case "scanDependencies":
        await vscode.commands.executeCommand("flcn-sec.scanDependencies");
        break;

      case "excludeFromAI":
        await vscode.commands.executeCommand("flcn-sec.excludeFromAI");
        this._sendState();
        break;

      case "openUrl":
        if (msg.url) vscode.env.openExternal(vscode.Uri.parse(msg.url));
        break;
    }
  }

  private async _aiInstalled(): Promise<boolean> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders?.length) return false;
    try {
      const bytes = await vscode.workspace.fs.readFile(
        vscode.Uri.file(`${folders[0].uri.fsPath}/.cursorignore`),
      );
      return Buffer.from(bytes).toString().includes("# flcn-sec managed");
    } catch {
      return false;
    }
  }
}

// ---------------------------------------------------------------------------
// HTML — identical content to the dashboard, adapted for panel height
// ---------------------------------------------------------------------------

function getNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from({ length: 32 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

function buildHtml(): string {
  const nonce = getNonce();
  return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FLCN Sec</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--vscode-font-family);
  font-size: var(--vscode-font-size);
  color: var(--vscode-foreground);
  background: var(--vscode-panel-background, var(--vscode-editor-background));
  padding: 0;
  overflow-x: hidden;
}

/* Scrollable content wrapper */
.content { padding: 12px 14px 32px; }

/* ── Section label ── */
.section-label {
  font-size: .7em;
  font-weight: 700;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: var(--vscode-descriptionForeground);
  margin: 18px 0 6px;
}
.section-label:first-child { margin-top: 0; }

/* ── Cards ── */
.card {
  background: var(--vscode-sideBar-background, rgba(255,255,255,.03));
  border: 1px solid var(--vscode-panel-border, #333);
  border-radius: 5px;
  margin-bottom: 8px;
  overflow: hidden;
}
.card-header {
  display: flex; align-items: center; gap: 7px;
  padding: 8px 12px;
  background: var(--vscode-sideBarSectionHeader-background, rgba(255,255,255,.04));
  border-bottom: 1px solid var(--vscode-panel-border, #333);
}
.card-header h2 {
  font-size: .86em; font-weight: 600; flex: 1;
  color: var(--vscode-settings-headerForeground, var(--vscode-foreground));
}
.card-body { padding: 2px 0; }

/* ── Issue summary grid ── */
.issue-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin-bottom: 8px;
}
@media (max-width: 480px) { .issue-grid { grid-template-columns: 1fr; } }
.issue-card .card-header { padding: 7px 12px; }
.issue-card .card-body-scroll {
  max-height: 220px;
  overflow-y: auto;
  overflow-x: hidden;
  scrollbar-width: none;        /* Firefox */
  -ms-overflow-style: none;     /* IE/Edge */
}
.issue-card .card-body-scroll::-webkit-scrollbar { display: none; } /* Chrome/Safari */

/* Count pill */
.count-pill {
  font-size: .72em; font-weight: 700;
  padding: 1px 6px; border-radius: 10px;
  min-width: 20px; text-align: center;
}
.pill-ok   { background: rgba(46,160,67,.2);  color: #3fb950; border: 1px solid rgba(46,160,67,.35); }
.pill-warn { background: rgba(210,153,34,.2); color: #d29922; border: 1px solid rgba(210,153,34,.35); }
.pill-bad  { background: rgba(220,60,60,.2);  color: #f87171; border: 1px solid rgba(220,60,60,.35); }
.pill-dim  { background: rgba(150,150,150,.1); color: var(--vscode-descriptionForeground); border: 1px solid rgba(150,150,150,.2); }

/* All clear / neutral state */
.all-clear {
  padding: 10px 12px; font-size: .82em; color: #3fb950;
  display: flex; align-items: center; gap: 5px;
}
.all-clear.neutral { color: var(--vscode-descriptionForeground); }

/* Issue list */
.issue-list { padding: 2px 0; }
.issue-row {
  padding: 6px 12px;
  border-top: 1px solid var(--vscode-panel-border, #2a2a2a);
}
.issue-row:first-child { border-top: none; }
.issue-row:hover { background: rgba(255,255,255,.03); }
.issue-top {
  display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
}
.issue-kind     { font-size: .8em; font-weight: 600; }
.issue-location { font-size: .75em; color: var(--vscode-descriptionForeground); font-family: var(--vscode-editor-font-family, monospace); }
.issue-preview  { font-size: .75em; color: var(--vscode-descriptionForeground); font-family: var(--vscode-editor-font-family, monospace); margin-top: 1px; }
.issue-pkg      { font-size: .8em; font-weight: 600; }

/* Severity pills */
.sev {
  font-size: .68em; font-weight: 700;
  padding: 1px 5px; border-radius: 3px; letter-spacing: .02em; flex-shrink: 0;
}
.sev-critical { background: rgba(239,68,68,.25);  color: #f87171; border: 1px solid rgba(239,68,68,.35); }
.sev-high     { background: rgba(234,88,12,.2);   color: #fb923c; border: 1px solid rgba(234,88,12,.3); }
.sev-medium   { background: rgba(202,138,4,.18);  color: #facc15; border: 1px solid rgba(202,138,4,.3); }
.sev-low      { background: rgba(59,130,246,.18); color: #60a5fa; border: 1px solid rgba(59,130,246,.3); }
.sev-unknown  { background: rgba(150,150,150,.1); color: var(--vscode-descriptionForeground); border: 1px solid rgba(150,150,150,.2); }

/* Grouped vuln sub-rows */
.vuln-list {
  margin-top: 4px;
  padding: 3px 0 2px 10px;
  border-left: 2px solid var(--vscode-panel-border, #333);
  display: flex; flex-direction: column; gap: 3px;
}
.vuln-item {
  display: flex; align-items: baseline; flex-wrap: wrap; gap: 5px; font-size: .76em;
}
.vuln-summary { color: var(--vscode-descriptionForeground); }
.vuln-id {
  color: var(--vscode-textLink-foreground, #4da3ff);
  cursor: pointer; text-decoration: underline; flex-shrink: 0;
}
.vuln-id:hover { opacity: .8; }
.vuln-count {
  font-size: .7em; color: var(--vscode-descriptionForeground);
  background: rgba(150,150,150,.12); padding: 1px 5px; border-radius: 8px; flex-shrink: 0;
}
.more-vulns {
  font-size: .72em; color: var(--vscode-descriptionForeground); font-style: italic;
}
.more-row {
  padding: 5px 12px; font-size: .76em; font-style: italic;
  color: var(--vscode-descriptionForeground);
  border-top: 1px solid var(--vscode-panel-border, #2a2a2a);
}

/* ── Settings rows ── */
.setting-row {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; padding: 8px 12px;
}
.setting-row + .setting-row { border-top: 1px solid var(--vscode-panel-border, #2a2a2a); }
.setting-row.dim { opacity: .4; pointer-events: none; }
.setting-info { flex: 1; min-width: 0; }
.setting-label {
  display: block; font-size: .85em; font-weight: 500;
  color: var(--vscode-foreground); cursor: pointer;
}
.setting-desc {
  display: block; font-size: .76em; color: var(--vscode-descriptionForeground);
  margin-top: 1px; line-height: 1.4;
}

/* Toggle switch */
.toggle { position: relative; display: inline-block; width: 36px; height: 20px; flex-shrink: 0; }
.toggle input { opacity: 0; width: 0; height: 0; }
.slider {
  position: absolute; inset: 0;
  background: var(--vscode-button-secondaryBackground, #3a3a3a);
  border-radius: 20px; cursor: pointer; transition: background .15s;
}
.slider::before {
  content: ""; position: absolute;
  height: 13px; width: 13px; left: 3px; top: 3px;
  background: var(--vscode-button-secondaryForeground, #bbb);
  border-radius: 50%; transition: transform .15s, background .15s;
}
input:checked + .slider { background: var(--vscode-button-background, #0e639c); }
input:checked + .slider::before {
  transform: translateX(15px); background: var(--vscode-button-foreground, #fff);
}

/* Select & number */
select, input[type="number"], input[type="password"] {
  background: var(--vscode-input-background, #3c3c3c);
  color: var(--vscode-input-foreground, #ccc);
  border: 1px solid var(--vscode-input-border, #555);
  border-radius: 3px; padding: 3px 5px;
  font-family: inherit; font-size: .82em; flex-shrink: 0; outline: none;
}
select { min-width: 108px; }
input[type="number"] { width: 62px; text-align: right; }
select:focus, input[type="number"]:focus, input[type="password"]:focus { border-color: var(--vscode-focusBorder, #007fd4); }
.input-suffix { display: flex; align-items: center; gap: 5px; flex-shrink: 0; }
.input-suffix span { font-size: .78em; color: var(--vscode-descriptionForeground); }

/* Status badge */
.status-badge {
  display: inline-flex; align-items: center; gap: 4px;
  font-size: .76em; font-weight: 600;
  padding: 2px 7px; border-radius: 10px; flex-shrink: 0;
}
.badge-ok   { background: rgba(46,160,67,.18);  color: #3fb950; border: 1px solid rgba(46,160,67,.3); }
.badge-warn { background: rgba(210,153,34,.15); color: #d29922; border: 1px solid rgba(210,153,34,.25); }
.badge-off  { background: rgba(150,150,150,.1); color: var(--vscode-descriptionForeground); border: 1px solid rgba(150,150,150,.2); }

/* Buttons */
.btn {
  display: inline-block; padding: 4px 10px; border: none; border-radius: 3px;
  font-family: inherit; font-size: .82em; cursor: pointer;
  transition: opacity .15s; white-space: nowrap; flex-shrink: 0;
}
.btn:hover   { opacity: .82; }
.btn:active  { opacity: .65; }
.btn:disabled { opacity: .4; cursor: default; }
.btn-primary   { background: var(--vscode-button-background, #0e639c); color: var(--vscode-button-foreground, #fff); }
.btn-secondary { background: var(--vscode-button-secondaryBackground, #3a3a3a); color: var(--vscode-button-secondaryForeground, #ccc); }
.btn-danger    { background: rgba(220,38,38,.2); color: #f87171; border: 1px solid rgba(220,38,38,.3); }

.action-row {
  padding: 8px 12px; border-top: 1px solid var(--vscode-panel-border, #2a2a2a);
  display: flex; gap: 7px; align-items: center;
}
.action-row .spacer { flex: 1; }
.action-row .hint { font-size: .76em; color: var(--vscode-descriptionForeground); }

/* Git hook */
.hook-block { padding: 8px 12px; display: flex; flex-direction: column; gap: 4px; }
.hook-top   { display: flex; align-items: center; gap: 8px; }
.hook-path  { font-size: .74em; color: var(--vscode-descriptionForeground); font-family: var(--vscode-editor-font-family, monospace); }
.no-git-msg { padding: 10px 12px; font-size: .82em; color: var(--vscode-descriptionForeground); font-style: italic; }

code {
  font-family: var(--vscode-editor-font-family, monospace); font-size: .88em;
  background: rgba(255,255,255,.07); padding: 1px 3px; border-radius: 3px;
}

/* ── Scanning spinner ── */
.scan-bar {
  display: none;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  font-size: .75em;
  color: var(--vscode-descriptionForeground);
  border-top: 1px solid var(--vscode-panel-border, #2a2a2a);
}
.scan-bar.visible { display: flex; }
.spinner {
  width: 11px; height: 11px;
  border: 2px solid rgba(150,150,150,.2);
  border-top-color: var(--vscode-progressBar-background, #0e639c);
  border-radius: 50%;
  animation: spin .7s linear infinite;
  flex-shrink: 0;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="content">

<!-- ══════════════════════════════════════════════ Live Issues -->
<div class="section-label">Live Issues</div>

<div class="issue-grid">
  <div class="card issue-card">
    <div class="card-header">
      <span>🔑</span><h2>Credentials</h2>
      <span class="count-pill pill-dim" id="credPill">—</span>
    </div>
    <div id="credBody" class="card-body-scroll"><div class="all-clear neutral">Loading…</div></div>
  </div>

  <div class="card issue-card">
    <div class="card-header">
      <span>🦠</span><h2>Vulnerabilities</h2>
      <span class="count-pill pill-dim" id="osvPill">—</span>
    </div>
    <div id="osvBody" class="card-body-scroll"><div class="all-clear neutral">Loading…</div></div>
    <div class="scan-bar" id="scanBar"><span class="spinner"></span><span id="scanMsg">Scanning…</span></div>
  </div>
</div>

<!-- ══════════════════════════════════════════════ Credential Guard -->
<div class="section-label">Credential Guard</div>
<div class="card"><div class="card-body">

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="enableRealTimeScan">Real-time scanning</label>
      <span class="setting-desc">Show inline diagnostics as you type.</span>
    </div>
    <label class="toggle">
      <input type="checkbox" id="enableRealTimeScan" onchange="upd('enableRealTimeScan',this.checked)">
      <span class="slider"></span>
    </label>
  </div>

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="warnOnOpen">Warn on open</label>
      <span class="setting-desc">Alert when a file with credentials is opened.</span>
    </div>
    <label class="toggle">
      <input type="checkbox" id="warnOnOpen" onchange="upd('warnOnOpen',this.checked)">
      <span class="slider"></span>
    </label>
  </div>

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="warnOnSave">Warn on save</label>
      <span class="setting-desc">Alert when saving a file with credentials.</span>
    </div>
    <label class="toggle">
      <input type="checkbox" id="warnOnSave" onchange="upd('warnOnSave',this.checked)">
      <span class="slider"></span>
    </label>
  </div>

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="severity">Severity</label>
      <span class="setting-desc">Diagnostic level in the Problems panel.</span>
    </div>
    <select id="severity" onchange="upd('severity',this.value)">
      <option value="error">Error</option>
      <option value="warning">Warning</option>
    </select>
  </div>

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="maxFileSizeKb">Max file size</label>
      <span class="setting-desc">Skip files larger than this.</span>
    </div>
    <div class="input-suffix">
      <input type="number" id="maxFileSizeKb" min="64" max="10240" step="128"
             onchange="upd('maxFileSizeKb',+this.value)">
      <span>KB</span>
    </div>
  </div>

</div></div>

<!-- ══════════════════════════════════════════════ OSV Scanner -->
<div class="section-label">OSV Vulnerability Scanner</div>
<div class="card"><div class="card-body">

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="osvEnabled">Enable OSV scanning</label>
      <span class="setting-desc">Query osv.dev for dependency vulnerabilities.</span>
    </div>
    <label class="toggle">
      <input type="checkbox" id="osvEnabled" onchange="upd('osv.enabled',this.checked);syncOsv()">
      <span class="slider"></span>
    </label>
  </div>

  <div class="setting-row" id="row-osvOnOpen">
    <div class="setting-info">
      <label class="setting-label" for="osvScanOnOpen">Scan on project open</label>
      <span class="setting-desc">Automatically scan when the workspace loads.</span>
    </div>
    <label class="toggle">
      <input type="checkbox" id="osvScanOnOpen" onchange="upd('osv.scanOnOpen',this.checked)">
      <span class="slider"></span>
    </label>
  </div>

  <div class="setting-row" id="row-osvInterval">
    <div class="setting-info">
      <label class="setting-label" for="osvInterval">Re-scan interval</label>
      <span class="setting-desc">Periodic re-check for new CVEs. 0 = disabled.</span>
    </div>
    <div class="input-suffix">
      <input type="number" id="osvInterval" min="0" max="1440" step="15"
             onchange="upd('osv.scanIntervalMinutes',+this.value)">
      <span>min</span>
    </div>
  </div>

  <div class="setting-row" id="row-osvSev">
    <div class="setting-info">
      <label class="setting-label" for="osvBlockSev">Error threshold</label>
      <span class="setting-desc">Findings at or above this level show as errors.</span>
    </div>
    <select id="osvBlockSev" onchange="upd('osv.blockSeverity',this.value)">
      <option value="CRITICAL">Critical only</option>
      <option value="HIGH">High &amp; Critical</option>
      <option value="MEDIUM">Medium and above</option>
      <option value="LOW">All (Low+)</option>
      <option value="NONE">Never error</option>
    </select>
  </div>

</div>
<div class="action-row" id="row-osvScan">
  <span class="hint">Scans <code>package.json</code>, <code>requirements.txt</code>, <code>Cargo.toml</code>, <code>Gemfile</code>, <code>go.mod</code></span>
  <span class="spacer"></span>
  <button class="btn btn-primary" id="scanBtn" onclick="scanNow(this)">Scan Now</button>
</div></div>

<!-- ══════════════════════════════════════════════ Additional Scanners -->
<div class="section-label">Additional Scanners</div>
<div class="card"><div class="card-body">

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="npmAuditEnabled">npm audit</label>
      <span class="setting-desc">Run <code>npm audit</code> for Node.js projects with a lock file.</span>
    </div>
    <label class="toggle">
      <input type="checkbox" id="npmAuditEnabled" onchange="upd('npmAudit.enabled',this.checked)">
      <span class="slider"></span>
    </label>
  </div>

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="ghsaEnabled">GitHub Security Advisories (GHSA)</label>
      <span class="setting-desc">Query the GitHub advisory database for all ecosystems.</span>
    </div>
    <label class="toggle">
      <input type="checkbox" id="ghsaEnabled" onchange="upd('ghsa.enabled',this.checked)">
      <span class="slider"></span>
    </label>
  </div>

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="githubTokenInput">GitHub Token (optional)</label>
      <span class="setting-desc">Increases GHSA rate limit from 60 req/hr to 5000 req/hr.</span>
    </div>
    <input type="password" id="githubTokenInput" placeholder="ghp_…" style="width:160px;font-size:.8em"
           onchange="upd('github.token',this.value)">
  </div>

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="nvdEnabled">NVD / NIST CVE Database</label>
      <span class="setting-desc">Query the official NIST CVE database. Slower due to rate limits (cap: 15 pkgs/scan).</span>
    </div>
    <label class="toggle">
      <input type="checkbox" id="nvdEnabled" onchange="upd('nvd.enabled',this.checked)">
      <span class="slider"></span>
    </label>
  </div>

  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label" for="nvdApiKeyInput">NVD API Key (optional)</label>
      <span class="setting-desc">From <a href="https://nvd.nist.gov/developers/request-an-api-key" style="color:var(--vscode-textLink-foreground)">nvd.nist.gov</a>. Without key: 5 req/30s. With key: 50 req/30s.</span>
    </div>
    <input type="password" id="nvdApiKeyInput" placeholder="xxxxxxxx-xxxx-…" style="width:160px;font-size:.8em"
           onchange="upd('nvd.apiKey',this.value)">
  </div>

</div></div>

<!-- ══════════════════════════════════════════════ Git Hooks -->
<div class="section-label">Git Pre-commit Hook</div>
<div class="card"><div class="card-body">
  <div id="noGitMsg" class="no-git-msg" style="display:none">No git repository found in workspace.</div>
  <div id="gitContent" style="display:none">
    <div class="hook-block">
      <div class="hook-top">
        <span class="setting-label">Status</span>
        <span id="hookBadge" class="status-badge badge-off">● Checking…</span>
      </div>
      <span class="hook-path">.git/hooks/pre-commit</span>
      <span class="setting-desc">Scans staged files for credentials before each commit.</span>
    </div>
    <div class="action-row">
      <button id="installBtn"   class="btn btn-primary" onclick="installHook()"   style="display:none">Install Hook</button>
      <button id="uninstallBtn" class="btn btn-danger"  onclick="uninstallHook()" style="display:none">Remove Hook</button>
    </div>
  </div>
</div></div>

<!-- ══════════════════════════════════════════════ AI Exclusions -->
<div class="section-label">AI Context Exclusions</div>
<div class="card"><div class="card-body">
  <div class="setting-row">
    <div class="setting-info">
      <label class="setting-label">Cursor + Copilot exclusions</label>
      <span class="setting-desc">Writes <code>.cursorignore</code> and disables Copilot for <code>.env</code>, <code>*.pem</code>, SSH keys, etc.</span>
    </div>
    <span id="aiExBadge" class="status-badge badge-off">● Checking…</span>
  </div>
</div>
<div class="action-row">
  <span class="hint" id="aiExHint"></span>
  <span class="spacer"></span>
  <button class="btn btn-secondary" id="exBtn" onclick="doExclude(this)">Apply</button>
</div></div>

</div><!-- .content -->

<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
const MAX_CRED = 20, MAX_PKGS = 10, MAX_V = 5;

window.addEventListener('message', e => {
  if (e.data.type === 'scanning') {
    const bar = id('scanBar'), msg = id('scanMsg');
    if (e.data.message) { msg.textContent = e.data.message; bar.classList.add('visible'); }
    else                { bar.classList.remove('visible'); }
    return;
  }
  if (e.data.type === 'init') { id('scanBar')?.classList.remove('visible'); apply(e.data.state); }
});

function apply(s) {
  renderCredCard(s.credIssues);
  renderOsvCard(s.osvIssues, s.osvEverScanned);

  setChk('enableRealTimeScan', s.enableRealTimeScan);
  setChk('warnOnOpen',         s.warnOnOpen);
  setChk('warnOnSave',         s.warnOnSave);
  setSel('severity',           s.severity);
  setNum('maxFileSizeKb',      s.maxFileSizeKb);

  setChk('osvEnabled',    s.osvEnabled);
  setChk('osvScanOnOpen', s.osvScanOnOpen);
  setNum('osvInterval',   s.osvScanIntervalMinutes);
  setSel('osvBlockSev',   s.osvBlockSeverity);
  syncOsv(s.osvEnabled);

  setChk('npmAuditEnabled', s.npmAuditEnabled);
  setChk('ghsaEnabled',     s.ghsaEnabled);
  setChk('nvdEnabled',      s.nvdEnabled);
  setInp('githubTokenInput', s.githubToken);
  setInp('nvdApiKeyInput',   s.nvdApiKey);

  const noGit  = id('noGitMsg');
  const gitCon = id('gitContent');
  if (!s.gitRootFound) {
    noGit.style.display = ''; gitCon.style.display = 'none';
  } else {
    noGit.style.display = 'none'; gitCon.style.display = '';
    const badge  = id('hookBadge');
    const instB  = id('installBtn');
    const unB    = id('uninstallBtn');
    if (s.gitHookInstalled) {
      badge.className = 'status-badge badge-ok';
      badge.textContent = '● Installed';
      instB.style.display = 'none'; unB.style.display = '';
    } else {
      badge.className = 'status-badge badge-warn';
      badge.textContent = '● Not installed';
      instB.style.display = ''; unB.style.display = 'none';
    }
  }

  const aiBadge = id('aiExBadge');
  const aiHint  = id('aiExHint');
  const exBtn   = id('exBtn');
  if (s.aiExclusionsInstalled) {
    aiBadge.className = 'status-badge badge-ok';
    aiBadge.textContent = '● Active';
    aiHint.textContent = '.cursorignore managed — click to refresh.';
    exBtn.textContent = 'Refresh';
  } else {
    aiBadge.className = 'status-badge badge-warn';
    aiBadge.textContent = '● Not applied';
    aiHint.textContent = 'Apply managed exclusions to this workspace.';
    exBtn.textContent = 'Apply';
  }
}

/* ── Issue card renderers ─────────────────────────────────────────────── */
function renderCredCard(issues) {
  const pill = id('credPill'), body = id('credBody'), n = issues.length;
  if (n === 0) {
    pill.textContent = '0'; pill.className = 'count-pill pill-ok';
    body.innerHTML = '<div class="all-clear">✓ No credentials in open files</div>';
    return;
  }
  pill.textContent = n; pill.className = 'count-pill pill-bad';
  const rows = issues.slice(0, MAX_CRED).map(i => \`
    <div class="issue-row">
      <div class="issue-top">
        <span class="issue-kind">\${esc(i.kind)}</span>
        <span class="issue-location">\${esc(i.filePath)}:\${i.line}</span>
      </div>
      \${i.preview ? \`<div class="issue-preview">\${esc(i.preview)}</div>\` : ''}
    </div>\`).join('');
  const more = n > MAX_CRED
    ? \`<div class="more-row">… and \${n - MAX_CRED} more</div>\` : '';
  body.innerHTML = \`<div class="issue-list">\${rows}</div>\${more}\`;
}

function renderOsvCard(issues, everScanned) {
  const pill = id('osvPill'), body = id('osvBody');
  if (!everScanned) {
    pill.textContent = '—'; pill.className = 'count-pill pill-dim';
    body.innerHTML = '<div class="all-clear neutral">Not yet scanned — click Scan Now.</div>';
    return;
  }
  const n = issues.length;
  if (n === 0) {
    pill.textContent = '0'; pill.className = 'count-pill pill-ok';
    body.innerHTML = '<div class="all-clear">✓ No vulnerabilities found</div>';
    return;
  }

  const ord = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4};

  // Group by package (name@version)
  const pkgMap = new Map();
  for (const i of issues) {
    const key = i.name + '@' + i.version;
    if (!pkgMap.has(key)) pkgMap.set(key, {name:i.name,version:i.version,manifestFile:i.manifestFile,vulns:[]});
    pkgMap.get(key).vulns.push(i);
  }
  for (const p of pkgMap.values()) {
    p.vulns.sort((a,b)=>(ord[a.severity]||9)-(ord[b.severity]||9));
    p.worstSev = p.vulns[0].severity;
  }
  const pkgs = [...pkgMap.values()].sort((a,b)=>(ord[a.worstSev]||9)-(ord[b.worstSev]||9));

  const worst = pkgs[0].worstSev;
  pill.textContent = n;
  pill.className = 'count-pill ' + (worst==='CRITICAL'||worst==='HIGH' ? 'pill-bad' : worst==='MEDIUM' ? 'pill-warn' : 'pill-dim');

  const rows = pkgs.slice(0, MAX_PKGS).map(pkg => {
    const vitems = pkg.vulns.slice(0, MAX_V).map(v => \`
      <div class="vuln-item">
        <span class="sev sev-\${v.severity.toLowerCase()}">\${esc(v.severity)}</span>
        <span class="vuln-id" onclick="openUrl('\${esc(v.url)}')">\${esc(v.vulnId)}</span>
        <span class="vuln-summary">\${esc(v.summary||'')}</span>
      </div>\`).join('');
    const moreV = pkg.vulns.length > MAX_V
      ? \`<div class="more-vulns">… and \${pkg.vulns.length-MAX_V} more</div>\` : '';
    return \`
      <div class="issue-row">
        <div class="issue-top">
          <span class="sev sev-\${pkg.worstSev.toLowerCase()}">\${esc(pkg.worstSev)}</span>
          <span class="issue-pkg">\${esc(pkg.name)}@\${esc(pkg.version)}</span>
          <span class="issue-location">\${esc(pkg.manifestFile)}</span>
          \${pkg.vulns.length>1?\`<span class="vuln-count">\${pkg.vulns.length} vulns</span>\`:''}
        </div>
        <div class="vuln-list">\${vitems}\${moreV}</div>
      </div>\`;
  }).join('');

  const morePkgs = pkgs.length > MAX_PKGS
    ? \`<div class="more-row">… and \${pkgs.length-MAX_PKGS} more packages</div>\` : '';
  body.innerHTML = \`<div class="issue-list">\${rows}</div>\${morePkgs}\`;
}

/* ── OSV row dimming ─────────────────────────────────────────────────── */
function syncOsv(en) {
  if (en===undefined) en = id('osvEnabled').checked;
  ['row-osvOnOpen','row-osvInterval','row-osvSev','row-osvScan'].forEach(r=>{
    const el=id(r); if(el) el.classList.toggle('dim',!en);
  });
}

/* ── Actions ─────────────────────────────────────────────────────────── */
function upd(k,v)    { vscode.postMessage({type:'updateSetting',key:k,value:v}); }
function openUrl(u)  { vscode.postMessage({type:'openUrl',url:u}); }
function installHook()   { id('installBtn').disabled=true;   vscode.postMessage({type:'installGitHook'}); }
function uninstallHook() { id('uninstallBtn').disabled=true; vscode.postMessage({type:'uninstallGitHook'}); }
function scanNow(btn) {
  btn.disabled=true; btn.textContent='Scanning…';
  vscode.postMessage({type:'scanDependencies'});
  setTimeout(()=>{btn.disabled=false;btn.textContent='Scan Now';},14000);
}
function doExclude(btn) {
  btn.disabled=true; vscode.postMessage({type:'excludeFromAI'});
  setTimeout(()=>{btn.disabled=false;},3000);
}

/* ── Helpers ─────────────────────────────────────────────────────────── */
function id(s)      { return document.getElementById(s); }
function setChk(i,v){ const e=id(i); if(e) e.checked=!!v; }
function setSel(i,v){ const e=id(i); if(e) e.value=v; }
function setNum(i,v){ const e=id(i); if(e) e.value=v; }
function setInp(i,v){ const e=id(i); if(e && !e.matches(':focus')) e.value=v||''; }
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
</script>
</body>
</html>`;
}

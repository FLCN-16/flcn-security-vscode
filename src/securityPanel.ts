/**
 * FLCN Security — bottom panel view (WebviewViewProvider).
 *
 * Appears as a dedicated tab alongside Output / Debug Console / Terminal.
 * Shows live credential and vulnerability issues in a Problems-panel style,
 * grouped and collapsible. Credential rows navigate to the file on click;
 * vuln rows open the OSV advisory.
 */

import * as vscode from "vscode";
import { OsvFinding } from "./osvScanner";
import { CredIssueData, OsvIssueData } from "./settingsPanel";

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export class SecurityPanelProvider implements vscode.WebviewViewProvider {
  static readonly viewId = "flcn-sec.securityView";
  private static _instance?: SecurityPanelProvider;

  private _view?: vscode.WebviewView;
  private _credIssues: CredIssueData[] = [];
  private _osvIssues: OsvIssueData[] = [];
  private _osvEverScanned = false;
  private _refreshTimer?: ReturnType<typeof setTimeout>;

  constructor() {
    SecurityPanelProvider._instance = this;
  }

  static setScanning(message: string): void {
    const p = SecurityPanelProvider._instance;
    if (!p?._view) return;
    p._view.webview.postMessage({ type: "scanning", message });
  }

  static refresh(
    credIssues?: CredIssueData[],
    osvFindings?: OsvFinding[],
    osvEverScanned?: boolean,
  ): void {
    const p = SecurityPanelProvider._instance;
    if (!p) return;

    if (credIssues    !== undefined) p._credIssues     = credIssues;
    if (osvFindings   !== undefined) p._osvIssues      = SecurityPanelProvider._toOsvData(osvFindings);
    if (osvEverScanned !== undefined) p._osvEverScanned = osvEverScanned;

    if (p._refreshTimer) clearTimeout(p._refreshTimer);
    p._refreshTimer = setTimeout(() => p._push(), 250);
  }

  private static _toOsvData(findings: OsvFinding[]): OsvIssueData[] {
    const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";
    return findings.map(f => ({
      manifestFile: root && f.manifestFile.startsWith(root)
        ? f.manifestFile.slice(root.length + 1) : f.manifestFile,
      name:     f.name,
      version:  f.version,
      severity: f.severity,
      vulnId:   f.vulnId,
      summary:  f.summary,
      url:      f.url,
    }));
  }

  resolveWebviewView(
    view: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken,
  ): void {
    this._view = view;
    view.webview.options = { enableScripts: true };
    view.webview.html = buildHtml();

    view.onDidChangeVisibility(() => { if (view.visible) this._push(); });
    view.webview.onDidReceiveMessage((msg) => this._handle(msg));
    setTimeout(() => this._push(), 150);
  }

  private _push(): void {
    if (!this._view) return;
    this._view.webview.postMessage({
      type: "init",
      credIssues:     this._credIssues,
      osvIssues:      this._osvIssues,
      osvEverScanned: this._osvEverScanned,
    });
  }

  private async _handle(msg: { type: string; filePath?: string; line?: number; url?: string }): Promise<void> {
    if (msg.type === "navigate" && msg.filePath) {
      const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";
      const abs = msg.filePath.startsWith("/") ? msg.filePath : `${wsRoot}/${msg.filePath}`;
      try {
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(abs));
        const line = (msg.line ?? 1) - 1;
        await vscode.window.showTextDocument(doc, {
          selection: new vscode.Range(line, 0, line, 999),
          preserveFocus: false,
        });
      } catch { /* file may not exist yet */ }
    }

    if (msg.type === "openUrl" && msg.url) {
      vscode.env.openExternal(vscode.Uri.parse(msg.url));
    }
  }
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

function getNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from({ length: 32 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

function buildHtml(): string {
  const nonce = getNonce();
  return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--vscode-font-family);
  font-size: 13px;
  color: var(--vscode-foreground);
  background: var(--vscode-panel-background, var(--vscode-editor-background));
  overflow-x: hidden;
  user-select: none;
  -webkit-user-select: none;
}

/* ── Empty / loading states ── */
.status-row {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 12px;
  font-size: 12px;
  color: var(--vscode-descriptionForeground);
}
.status-ok { color: #3fb950; }

/* ── Section ── */
.section { border-bottom: 1px solid var(--vscode-panel-border, #2d2d2d); }

.section-header {
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 5px 8px;
  cursor: pointer;
  background: var(--vscode-sideBarSectionHeader-background, rgba(255,255,255,.04));
  border-bottom: 1px solid var(--vscode-panel-border, #2d2d2d);
}
.section-header:hover { background: var(--vscode-list-hoverBackground); }

.chevron {
  font-size: 10px;
  width: 10px;
  text-align: center;
  color: var(--vscode-descriptionForeground);
  flex-shrink: 0;
  transition: transform .12s;
}
.section-header.open .chevron { transform: rotate(90deg); }

.section-title {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .06em;
  text-transform: uppercase;
  flex: 1;
}

.section-count {
  font-size: 11px;
  color: var(--vscode-descriptionForeground);
  background: rgba(150,150,150,.15);
  padding: 0 6px;
  border-radius: 8px;
  min-width: 18px;
  text-align: center;
}
.count-err  { background: rgba(214,84,84,.2); color: #f87171; }
.count-warn { background: rgba(202,138,4,.18); color: #facc15; }
.count-ok   { background: rgba(46,160,67,.18); color: #3fb950; }

/* Section icons */
.icon-err  { color: var(--vscode-problemsErrorIcon-foreground,   #f14c4c); font-size: 10px; }
.icon-warn { color: var(--vscode-problemsWarningIcon-foreground, #cca700); font-size: 10px; }

/* ── Credential items ── */
.cred-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 3px 8px 3px 24px;
  cursor: pointer;
  border-bottom: 1px solid transparent;
}
.cred-item:hover { background: var(--vscode-list-hoverBackground); }

.cred-kind {
  font-size: 12px;
  font-weight: 500;
  flex-shrink: 0;
}
.cred-sep { color: var(--vscode-descriptionForeground); font-size: 10px; }
.cred-preview {
  font-size: 11px;
  color: var(--vscode-descriptionForeground);
  font-family: var(--vscode-editor-font-family, monospace);
  flex-shrink: 0;
}
.cred-loc {
  font-size: 11px;
  color: var(--vscode-descriptionForeground);
  font-family: var(--vscode-editor-font-family, monospace);
  margin-left: auto;
  white-space: nowrap;
  flex-shrink: 0;
}

/* ── Package groups ── */
.pkg-group { border-bottom: 1px solid var(--vscode-panel-border, #2d2d2d); }
.pkg-group:last-child { border-bottom: none; }

.pkg-header {
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 4px 8px 4px 22px;
  cursor: pointer;
}
.pkg-header:hover { background: var(--vscode-list-hoverBackground); }

.pkg-chevron {
  font-size: 9px;
  width: 9px;
  text-align: center;
  color: var(--vscode-descriptionForeground);
  flex-shrink: 0;
  transition: transform .12s;
}
.pkg-header.open .pkg-chevron { transform: rotate(90deg); }

.sev-dot {
  width: 8px; height: 8px;
  border-radius: 50%; flex-shrink: 0;
}
.dot-critical { background: #f87171; }
.dot-high     { background: #fb923c; }
.dot-medium   { background: #facc15; }
.dot-low      { background: #60a5fa; }
.dot-unknown  { background: var(--vscode-descriptionForeground); }

.pkg-name {
  font-size: 12px;
  font-weight: 600;
}
.pkg-manifest {
  font-size: 11px;
  color: var(--vscode-descriptionForeground);
  font-family: var(--vscode-editor-font-family, monospace);
  margin-left: 2px;
}
.pkg-vuln-count {
  font-size: 11px;
  color: var(--vscode-descriptionForeground);
  margin-left: auto;
  background: rgba(150,150,150,.12);
  padding: 0 5px; border-radius: 8px;
}

/* ── Vuln items ── */
.pkg-vulns { display: none; }
.pkg-vulns.open { display: block; }

.vuln-item {
  display: flex;
  align-items: baseline;
  gap: 6px;
  padding: 3px 8px 3px 46px;
  cursor: pointer;
  font-size: 12px;
}
.vuln-item:hover { background: var(--vscode-list-hoverBackground); }

.sev-label {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .04em;
  flex-shrink: 0;
  width: 48px;
}
.sev-critical { color: #f87171; }
.sev-high     { color: #fb923c; }
.sev-medium   { color: #facc15; }
.sev-low      { color: #60a5fa; }
.sev-unknown  { color: var(--vscode-descriptionForeground); }

.vuln-id {
  font-family: var(--vscode-editor-font-family, monospace);
  font-size: 11px;
  color: var(--vscode-textLink-foreground, #4da3ff);
  flex-shrink: 0;
}
.vuln-summary {
  font-size: 11px;
  color: var(--vscode-descriptionForeground);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.more-row {
  padding: 2px 8px 4px 46px;
  font-size: 11px;
  font-style: italic;
  color: var(--vscode-descriptionForeground);
}

/* ── Scanning progress bar ── */
#scan-progress {
  display: none;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  font-size: 11px;
  color: var(--vscode-descriptionForeground);
  background: var(--vscode-panel-background, var(--vscode-editor-background));
  border-bottom: 1px solid var(--vscode-panel-border, #2d2d2d);
  position: sticky;
  top: 0;
  z-index: 10;
}
#scan-progress.visible { display: flex; }
.spinner {
  width: 12px; height: 12px;
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

<div id="scan-progress"><span class="spinner"></span><span id="scan-msg">Scanning…</span></div>
<div id="root"></div>

<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
const MAX_CRED = 50, MAX_V_PER_PKG = 10, MAX_PKGS = 20;

window.addEventListener('message', e => {
  const m = e.data;
  if (m.type === 'scanning') {
    const bar = document.getElementById('scan-progress');
    if (m.message) {
      document.getElementById('scan-msg').textContent = m.message;
      bar.classList.add('visible');
    } else {
      bar.classList.remove('visible');
    }
    return;
  }
  if (m.type === 'init') {
    document.getElementById('scan-progress').classList.remove('visible');
    render(m.credIssues, m.osvIssues, m.osvEverScanned);
  }
});

function render(creds, osv, osvScanned) {
  const root = document.getElementById('root');
  root.innerHTML = '';

  const noCredIssues = !creds || creds.length === 0;
  const noOsvIssues  = !osv  || osv.length  === 0;

  if (noCredIssues && (noOsvIssues || !osvScanned)) {
    root.innerHTML = \`<div class="status-row status-ok">
      ✓&nbsp; No security issues detected\${!osvScanned ? ' — run an OSV scan to check dependencies' : ''}
    </div>\`;
    return;
  }

  // ── Credentials section ───────────────────────────────────────────────
  root.appendChild(buildCredSection(creds || []));

  // ── OSV section ───────────────────────────────────────────────────────
  root.appendChild(buildOsvSection(osv || [], osvScanned));
}

/* ── Credentials ────────────────────────────────────────────────────── */
function buildCredSection(creds) {
  const n = creds.length;
  const sec = el('div', 'section');

  const hdr = el('div', 'section-header' + (n > 0 ? ' open' : ''));
  hdr.innerHTML = \`
    <span class="chevron">▸</span>
    <span class="icon-err">●</span>
    <span class="section-title">Credentials</span>
    <span class="section-count \${n > 0 ? 'count-err' : 'count-ok'}">\${n}</span>\`;
  hdr.onclick = () => toggleSection(hdr, body);
  sec.appendChild(hdr);

  const body = el('div', 'section-body');
  body.style.display = n > 0 ? 'block' : 'none';

  if (n === 0) {
    body.appendChild(statusRow('✓ No credentials detected in open files', true));
  } else {
    creds.slice(0, MAX_CRED).forEach(c => body.appendChild(buildCredItem(c)));
    if (n > MAX_CRED) body.appendChild(moreRow(n - MAX_CRED));
  }

  sec.appendChild(body);
  return sec;
}

function buildCredItem(c) {
  const row = el('div', 'cred-item');
  row.title = \`\${c.kind} in \${c.filePath}\`;
  row.innerHTML = \`
    <span class="icon-err">●</span>
    <span class="cred-kind">\${esc(c.kind)}</span>
    \${c.preview ? \`<span class="cred-sep">·</span><span class="cred-preview">\${esc(c.preview)}</span>\` : ''}
    <span class="cred-loc">\${esc(c.filePath)}:\${c.line}</span>\`;
  row.onclick = () => vscode.postMessage({ type: 'navigate', filePath: c.filePath, line: c.line });
  return row;
}

/* ── OSV Vulnerabilities ─────────────────────────────────────────────── */
function buildOsvSection(issues, osvScanned) {
  const sec = el('div', 'section');
  const n = issues.length;

  const hdr = el('div', 'section-header' + (n > 0 ? ' open' : ''));

  const worst = n > 0 ? issues.sort((a,b) => sev(a)-sev(b))[0].severity : '';
  const countClass = n === 0 ? 'count-ok' : (worst==='CRITICAL'||worst==='HIGH' ? 'count-err' : 'count-warn');

  hdr.innerHTML = \`
    <span class="chevron">▸</span>
    <span class="icon-warn">●</span>
    <span class="section-title">Vulnerabilities</span>
    <span class="section-count \${countClass}">\${n}\${!osvScanned ? ' (not scanned)' : ''}</span>\`;
  hdr.onclick = () => toggleSection(hdr, body);
  sec.appendChild(hdr);

  const body = el('div', 'section-body');
  body.style.display = n > 0 ? 'block' : 'none';

  if (!osvScanned) {
    body.appendChild(statusRow('Run an OSV scan to check for vulnerabilities'));
  } else if (n === 0) {
    body.appendChild(statusRow('✓ No vulnerabilities found in dependency manifests', true));
  } else {
    // Group by package
    const pkgMap = new Map();
    for (const i of issues) {
      const k = i.name + '@' + i.version;
      if (!pkgMap.has(k)) pkgMap.set(k, { name:i.name, version:i.version, manifestFile:i.manifestFile, vulns:[] });
      pkgMap.get(k).vulns.push(i);
    }
    for (const p of pkgMap.values()) {
      p.vulns.sort((a,b)=>sev(a)-sev(b));
      p.worstSev = p.vulns[0].severity;
    }
    const pkgs = [...pkgMap.values()].sort((a,b)=>sev({severity:a.worstSev})-sev({severity:b.worstSev}));

    pkgs.slice(0, MAX_PKGS).forEach(pkg => body.appendChild(buildPkgGroup(pkg)));
    if (pkgs.length > MAX_PKGS) body.appendChild(moreRow(pkgs.length - MAX_PKGS, 'packages'));
  }

  sec.appendChild(body);
  return sec;
}

function buildPkgGroup(pkg) {
  const grp = el('div', 'pkg-group');

  const hdr = el('div', 'pkg-header open');
  hdr.innerHTML = \`
    <span class="pkg-chevron">▸</span>
    <span class="sev-dot dot-\${pkg.worstSev.toLowerCase()}"></span>
    <span class="pkg-name">\${esc(pkg.name)}@\${esc(pkg.version)}</span>
    <span class="pkg-manifest">\${esc(pkg.manifestFile)}</span>
    \${pkg.vulns.length > 1 ? \`<span class="pkg-vuln-count">\${pkg.vulns.length}</span>\` : ''}\`;

  const vulnList = el('div', 'pkg-vulns open');
  pkg.vulns.slice(0, MAX_V_PER_PKG).forEach(v => vulnList.appendChild(buildVulnItem(v)));
  if (pkg.vulns.length > MAX_V_PER_PKG) vulnList.appendChild(moreRow(pkg.vulns.length - MAX_V_PER_PKG));

  hdr.onclick = () => {
    hdr.classList.toggle('open');
    vulnList.classList.toggle('open');
  };

  grp.appendChild(hdr);
  grp.appendChild(vulnList);
  return grp;
}

function buildVulnItem(v) {
  const row = el('div', 'vuln-item');
  row.title = v.summary || v.vulnId;
  row.innerHTML = \`
    <span class="sev-label sev-\${v.severity.toLowerCase()}">\${esc(v.severity)}</span>
    <span class="vuln-id">\${esc(v.vulnId)}</span>
    <span class="vuln-summary">\${esc(v.summary || '')}</span>\`;
  row.onclick = () => vscode.postMessage({ type: 'openUrl', url: v.url });
  return row;
}

/* ── Helpers ─────────────────────────────────────────────────────────── */
function toggleSection(hdr, body) {
  const open = hdr.classList.toggle('open');
  body.style.display = open ? 'block' : 'none';
}

function statusRow(msg, ok) {
  const d = el('div', 'status-row' + (ok ? ' status-ok' : ''));
  d.textContent = msg;
  return d;
}
function moreRow(n, unit) {
  const d = el('div', 'more-row');
  d.textContent = \`… and \${n} more \${unit || 'items'}\`;
  return d;
}
function el(tag, cls) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  return e;
}
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
const SEV_ORD = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4};
function sev(i) { return SEV_ORD[i.severity] ?? 9; }
</script>
</body>
</html>`;
}

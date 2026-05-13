import * as vscode from "vscode";
import { redactText, safePreview, ScanOptions } from "./detector";
import { DiagnosticsManager, CredentialCodeActionProvider, buildDiagnostics, isSensitivePath } from "./diagnostics";
import { installGitHook, uninstallGitHook, isHookInstalled, getGitRoot } from "./gitHook";
import { scanAllVulnerabilities, OsvFinding, OsvSeverity } from "./osvScanner";
import { SettingsPanel } from "./settingsPanel";
import { SecurityPanelProvider } from "./securityPanel";
import { initSentry, captureException } from "./sentry";

let manager: DiagnosticsManager;
let statusBar: vscode.StatusBarItem;
let output: vscode.OutputChannel;
let osvDiagnostics: vscode.DiagnosticCollection;
let osvScanTimer: ReturnType<typeof setInterval> | undefined;
let osvTotalFindings = 0;
let currentOsvFindings: OsvFinding[] = [];
let osvEverScanned = false;

// Virtual document provider — serves redacted content under flcn-sec:// URIs.
// Used by the "Open Redacted View" command to show a safe, masked copy of a
// file alongside the real one. User-triggered only; does not intercept reads.
class RedactedDocumentProvider implements vscode.TextDocumentContentProvider {
  private _cache = new Map<string, string>();

  async provideTextDocumentContent(uri: vscode.Uri): Promise<string> {
    const realPath = uri.path;
    if (this._cache.has(realPath)) return this._cache.get(realPath)!;
    try {
      const bytes = await vscode.workspace.fs.readFile(vscode.Uri.file(realPath));
      const text = Buffer.from(bytes).toString("utf8");
      const { redacted } = redactText(text);
      const result = `[FLCN Sec — credentials redacted. Real file: ${realPath}]\n\n` + redacted;
      this._cache.set(realPath, result);
      return result;
    } catch {
      return `[FLCN Sec — could not read ${realPath}]`;
    }
  }

  invalidate(realPath: string): void { this._cache.delete(realPath); }
}

const redactedProvider = new RedactedDocumentProvider();

export function activate(context: vscode.ExtensionContext): void {
  const { version } = context.extension.packageJSON as { version: string };
  initSentry(version);

  // Output channel — persistent findings log
  output = vscode.window.createOutputChannel("FLCN Sec");
  context.subscriptions.push(output);

  manager = new DiagnosticsManager(output);
  context.subscriptions.push(manager);

  // Status bar
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = "flcn-sec.openDashboard";
  statusBar.tooltip = "FLCN Sec — click to open Security Dashboard";
  statusBar.show();
  context.subscriptions.push(statusBar);
  updateStatusBar(0);

  // OSV diagnostics collection (separate from credential diagnostics)
  osvDiagnostics = vscode.languages.createDiagnosticCollection("flcn-sec-osv");
  context.subscriptions.push(osvDiagnostics);

  // Security panel view — appears as a tab in the VS Code bottom panel
  const panelProvider = new SecurityPanelProvider();
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(
      SecurityPanelProvider.viewId,
      panelProvider,
      { webviewOptions: { retainContextWhenHidden: true } },
    ),
  );

  // Virtual redacted document provider (flcn-sec:// scheme)
  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider("flcn-sec", redactedProvider),
  );

  // Code action provider
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider("*", new CredentialCodeActionProvider(), {
      providedCodeActionKinds: CredentialCodeActionProvider.providedCodeActionKinds,
    }),
  );

  // Document lifecycle events
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(doc => onOpen(doc)),
    vscode.workspace.onDidChangeTextDocument(e => scanAndRefresh(e.document)),
    vscode.workspace.onDidCloseTextDocument(doc => {
      manager.clear(doc);
      updateStatusBar(manager.totalFindings());
    }),
    vscode.workspace.onDidSaveTextDocument(doc => {
      const findings = manager.update(doc);
      if (
        findings.length > 0 &&
        vscode.workspace.getConfiguration("flcn-sec").get<boolean>("warnOnSave", true)
      ) {
        const kinds = [...new Set(findings.map(f => f.raw.kind))].join(", ");
        vscode.window
          .showWarningMessage(
            `FLCN Sec: ${findings.length} credential(s) saved to disk (${kinds}). Rotate and remove them.`,
            "Redact All Now",
            "Show Log",
            "Dismiss",
          )
          .then(choice => {
            if (choice === "Redact All Now") redactActiveFile(doc);
            else if (choice === "Show Log") output.show();
          });
      }
      updateStatusBar(manager.totalFindings());
      SecurityPanelProvider.refresh(manager.allFindings(), currentOsvFindings, osvEverScanned);
      SettingsPanel.refresh(manager.allFindings(), currentOsvFindings, osvEverScanned);
    }),
  );

  // Re-scan all open documents when any flcn-sec setting changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration("flcn-sec")) {
        manager.refreshAll(vscode.workspace.textDocuments);
        updateStatusBar(manager.totalFindings());
        SecurityPanelProvider.refresh(manager.allFindings(), currentOsvFindings, osvEverScanned);
      SettingsPanel.refresh(manager.allFindings(), currentOsvFindings, osvEverScanned);
      }
    }),
  );

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("flcn-sec.openDashboard", () => {
      SettingsPanel.show(context, output);
    }),

    vscode.commands.registerCommand("flcn-sec.scanFile", () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (!doc) return;
      const findings = manager.update(doc);
      updateStatusBar(manager.totalFindings());
      if (findings.length === 0) {
        vscode.window.showInformationMessage("FLCN Sec: No credentials found in this file.");
      } else {
        const lines = findings.map(
          f => `  Line ${f.range.start.line + 1}: ${f.raw.kind} — ${safePreview(f.raw.matchedValue)}`,
        );
        vscode.window
          .showWarningMessage(
            `FLCN Sec: ${findings.length} credential(s) detected:\n${lines.join("\n")}`,
            "Redact All",
            "Show Log",
            "Dismiss",
          )
          .then(choice => {
            if (choice === "Redact All") redactActiveFile(doc);
            else if (choice === "Show Log") output.show();
          });
      }
    }),

    vscode.commands.registerCommand("flcn-sec.redactFile", () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) redactActiveFile(doc);
    }),

    vscode.commands.registerCommand("flcn-sec.toggleRealTime", () => {
      const cfg = vscode.workspace.getConfiguration("flcn-sec");
      const current = cfg.get<boolean>("enableRealTimeScan", true);
      cfg.update("enableRealTimeScan", !current, vscode.ConfigurationTarget.Global);
      vscode.window.showInformationMessage(
        `FLCN Sec: Real-time scanning ${!current ? "enabled" : "disabled"}.`,
      );
    }),

    vscode.commands.registerCommand("flcn-sec.showLog", () => output.show()),

    vscode.commands.registerCommand("flcn-sec.openSettings", () => {
      vscode.commands.executeCommand("workbench.action.openSettings", "flcn-sec");
    }),

    vscode.commands.registerCommand("flcn-sec.excludeFromAI", () => ensureWorkspaceExclusions()),

    vscode.commands.registerCommand("flcn-sec.openRedactedView", async () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (!doc) return;
      redactedProvider.invalidate(doc.uri.fsPath);
      const virtualUri = vscode.Uri.parse(`flcn-sec://${doc.uri.fsPath}`);
      await vscode.window.showTextDocument(virtualUri, {
        preview: true,
        viewColumn: vscode.ViewColumn.Beside,
      });
    }),

    vscode.commands.registerCommand("flcn-sec.installGitHook", async () => {
      const root = getGitRoot(vscode.workspace.workspaceFolders);
      if (!root) {
        vscode.window.showWarningMessage("FLCN Sec: No git repository found in the current workspace.");
        return;
      }
      const ok = await installGitHook(root, output);
      if (ok) {
        vscode.window.showInformationMessage("FLCN Sec: Git pre-commit hook installed. Commits will be scanned for credentials.");
      } else {
        vscode.window.showErrorMessage("FLCN Sec: Could not install git hook (no .git/hooks directory?).");
      }
    }),

    vscode.commands.registerCommand("flcn-sec.uninstallGitHook", async () => {
      const root = getGitRoot(vscode.workspace.workspaceFolders);
      if (!root) {
        vscode.window.showWarningMessage("FLCN Sec: No git repository found in the current workspace.");
        return;
      }
      const ok = uninstallGitHook(root, output);
      if (ok) {
        vscode.window.showInformationMessage("FLCN Sec: Git pre-commit hook removed.");
      } else {
        vscode.window.showWarningMessage("FLCN Sec: Hook was not managed by flcn-sec — not removed.");
      }
    }),

    vscode.commands.registerCommand("flcn-sec.scanDependencies", () => runOsvScan()),
  );

  // Re-start the OSV timer when scan-interval setting changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration("flcn-sec.osv")) {
        restartOsvTimer();
      }
    }),
  );

  // Offer to install the git hook on first open (once per workspace)
  promptGitHookInstall(context, output);

  // Scan all already-open documents on startup
  vscode.workspace.textDocuments.forEach(doc => scanAndRefresh(doc));

  // Initial OSV scan + start interval timer
  const cfg = vscode.workspace.getConfiguration("flcn-sec");
  if (cfg.get<boolean>("osv.enabled", true)) {
    if (cfg.get<boolean>("osv.scanOnOpen", true)) {
      runOsvScan();
    }
    startOsvTimer();
  }
}

export function deactivate(): void {
  stopOsvTimer();
  manager?.dispose();
  statusBar?.dispose();
  output?.dispose();
  osvDiagnostics?.dispose();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scanAndRefresh(doc: vscode.TextDocument): void {
  manager.update(doc);
  updateStatusBar(manager.totalFindings());
}

async function onOpen(doc: vscode.TextDocument): Promise<void> {
  try {
    return await _onOpen(doc);
  } catch (e) {
    captureException(e, { context: "onOpen", file: doc.fileName });
  }
}

async function _onOpen(doc: vscode.TextDocument): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("flcn-sec");
  const fileName = doc.fileName.split("/").pop() ?? doc.fileName;

  // ---- Sensitive-path files (.env, .aws/credentials, SSH keys, etc.) ----
  if (isSensitivePath(doc.uri.fsPath)) {
    // Real file stays open and fully editable.
    // Silently write AI exclusion configs once — after that, no more prompts.
    if (!await isAlreadyExcluded()) {
      await ensureWorkspaceExclusions();
      vscode.window.showInformationMessage(
        `FLCN Sec: "${fileName}" excluded from Copilot and Cursor. Use "FLCN Sec: Open Redacted View" to share a safe copy with AI chat.`,
      );
    }
    manager.update(doc);
    updateStatusBar(manager.totalFindings());
    return;
  }

  // ---- Regular files with inline credentials ----
  const findings = manager.update(doc);
  updateStatusBar(manager.totalFindings());

  if (findings.length === 0) return;

  if (cfg.get<boolean>("warnOnOpen", true)) {
    const choice = await vscode.window.showWarningMessage(
      `FLCN Sec: ${findings.length} credential(s) detected in "${fileName}". AI assistants can see these values.`,
      "Redact Now",
      "Dismiss",
    );
    if (choice === "Redact Now") {
      await redactActiveFile(doc);
    }
  }
}

async function isAlreadyExcluded(): Promise<boolean> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) return false;
  const root = folders[0].uri.fsPath;
  try {
    const content = Buffer.from(
      await vscode.workspace.fs.readFile(vscode.Uri.file(`${root}/.cursorignore`))
    ).toString();
    return content.includes("# flcn-sec managed");
  } catch {
    return false;
  }
}

// Writes .cursorignore and updates VS Code/Copilot settings so AI tools
// never index or use sensitive credential files as context.
async function ensureWorkspaceExclusions(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) return;
  const root = folders[0].uri.fsPath;

  const sensitiveGlobs = [
    ".env", ".env.*", "!.env.example",
    ".aws/credentials", ".aws/config",
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa",
    ".netrc", ".npmrc", ".pypirc", ".docker/config.json", ".kube/config",
    "*.pem", "*.key",
    "service-account*.json", "gcp-key*.json", "firebase-adminsdk*.json",
  ];

  // 1. .cursorignore — prevents Cursor from indexing these files
  const cursorIgnorePath = vscode.Uri.file(`${root}/.cursorignore`);
  const marker = "# flcn-sec managed";
  let existing = "";
  try { existing = Buffer.from(await vscode.workspace.fs.readFile(cursorIgnorePath)).toString(); } catch {}
  if (!existing.includes(marker)) {
    const block = `\n${marker}\n${sensitiveGlobs.join("\n")}\n`;
    await vscode.workspace.fs.writeFile(
      cursorIgnorePath,
      Buffer.from(existing + block),
    );
  }

  // 2. github.copilot.enable — disables Copilot for each sensitive glob
  const copilotCfg = vscode.workspace.getConfiguration("github.copilot");
  const enableMap: Record<string, boolean> = copilotCfg.get("enable", {});
  let changed = false;
  for (const g of sensitiveGlobs.filter(g => !g.startsWith("!"))) {
    const key = g.startsWith("*.") || g.startsWith("*") ? `**/${g}` : `**/${g}`;
    if (enableMap[key] !== false) { enableMap[key] = false; changed = true; }
  }
  if (changed) {
    await copilotCfg.update("enable", enableMap, vscode.ConfigurationTarget.Workspace);
  }

  vscode.window.showInformationMessage(
    "FLCN Sec: Sensitive files excluded from Cursor indexing and Copilot context.",
  );
}

function updateStatusBar(credTotal: number): void {
  const hasOsv = osvTotalFindings > 0;
  const hasCred = credTotal > 0;

  if (!hasCred && !hasOsv) {
    statusBar.text = "$(shield) FLCN Sec";
    statusBar.tooltip = "FLCN Sec — click to scan active file for credentials";
    statusBar.backgroundColor = undefined;
    statusBar.color = new vscode.ThemeColor("statusBarItem.prominentForeground");
  } else {
    const parts: string[] = [];
    if (hasCred) parts.push(`${credTotal} cred`);
    if (hasOsv)  parts.push(`${osvTotalFindings} vuln`);
    statusBar.text = `$(warning) FLCN Sec: ${parts.join(" · ")}`;
    statusBar.tooltip = [
      hasCred  ? `${credTotal} credential(s) detected in open files` : "",
      hasOsv   ? `${osvTotalFindings} OSV vulnerability/vulnerabilities found in dependencies` : "",
    ].filter(Boolean).join("\n");
    statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    statusBar.color = undefined;
  }
}

function buildRedactOptions(): ScanOptions {
  const cfg = vscode.workspace.getConfiguration("flcn-sec");
  return {
    disabledDetectors: cfg.get<string[]>("disabledDetectors", []),
    // customDetectors and allowlist are applied in diagnostics; redaction uses same disabled list
  };
}

async function redactActiveFile(doc: vscode.TextDocument): Promise<void> {
  const text = doc.getText();
  const { redacted, findings } = redactText(text, buildRedactOptions());

  if (findings.length === 0) {
    vscode.window.showInformationMessage("FLCN Sec: No credentials to redact.");
    return;
  }

  const edit = new vscode.WorkspaceEdit();
  edit.replace(
    doc.uri,
    new vscode.Range(doc.positionAt(0), doc.positionAt(text.length)),
    redacted,
  );
  try {
    await vscode.workspace.applyEdit(edit);
  } catch (e) {
    captureException(e, { context: "redactActiveFile", file: doc.fileName });
    throw e;
  }

  const kinds = [...new Set(findings.map(f => f.kind))].join(", ");
  vscode.window.showInformationMessage(
    `FLCN Sec: ${findings.length} credential(s) redacted (${kinds}). Review changes before saving.`,
  );

  manager.update(doc);
  updateStatusBar(manager.totalFindings());
}

async function promptGitHookInstall(context: vscode.ExtensionContext, output: vscode.OutputChannel): Promise<void> {
  const root = getGitRoot(vscode.workspace.workspaceFolders);
  if (!root) return;
  if (isHookInstalled(root)) return;

  const stateKey = `flcn-sec.gitHookPrompted.${root}`;
  if (context.globalState.get(stateKey)) return;
  await context.globalState.update(stateKey, true);

  const choice = await vscode.window.showInformationMessage(
    "FLCN Sec: Install a git pre-commit hook to block commits containing credentials?",
    "Install Hook",
    "Not Now",
  );
  if (choice === "Install Hook") {
    const ok = await installGitHook(root, output);
    if (ok) {
      vscode.window.showInformationMessage("FLCN Sec: Git pre-commit hook installed.");
    }
  }
}

// ---------------------------------------------------------------------------
// OSV scanning helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<OsvSeverity, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0,
};

function osvSeverityToDiagnostic(severity: OsvSeverity): vscode.DiagnosticSeverity {
  if (severity === "CRITICAL" || severity === "HIGH") return vscode.DiagnosticSeverity.Error;
  if (severity === "MEDIUM") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

async function runOsvScan(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("flcn-sec");
  if (!cfg.get<boolean>("osv.enabled", true)) return;

  output.appendLine("[OSV] Starting dependency vulnerability scan…");
  osvDiagnostics.clear();

  const notifyProgress = (msg: string): void => {
    SecurityPanelProvider.setScanning(msg);
    SettingsPanel.setScanning(msg);
  };
  notifyProgress("Starting scan…");

  let findings: OsvFinding[];
  try {
    findings = await scanAllVulnerabilities(output, notifyProgress);
  } catch (e) {
    output.appendLine(`[OSV] Scan error: ${e}`);
    captureException(e, { context: "runOsvScan" });
    SecurityPanelProvider.setScanning("");
    SettingsPanel.setScanning("");
    return;
  }

  if (findings.length === 0) {
    currentOsvFindings = [];
    osvEverScanned = true;
    osvTotalFindings = 0;
    updateStatusBar(manager.totalFindings());
    SecurityPanelProvider.refresh(manager.allFindings(), [], true);
    SettingsPanel.refresh(manager.allFindings(), [], true);
    return;
  }

  // Group findings by manifest file
  const byFile = new Map<string, OsvFinding[]>();
  for (const f of findings) {
    const arr = byFile.get(f.manifestFile) ?? [];
    arr.push(f);
    byFile.set(f.manifestFile, arr);
  }

  // Create diagnostics
  for (const [filePath, fileFindings] of byFile) {
    const uri = vscode.Uri.file(filePath);
    const diags: vscode.Diagnostic[] = [];

    for (const f of fileFindings) {
      const line = f.manifestLine;
      const range = new vscode.Range(line, 0, line, 200);
      const msg = `[OSV ${f.severity}] ${f.name}@${f.version} — ${f.vulnId}: ${f.summary || "(see advisory)"}`;
      const diag = new vscode.Diagnostic(range, msg, osvSeverityToDiagnostic(f.severity));
      diag.source = "FLCN Sec OSV";
      diag.code = { value: f.vulnId, target: vscode.Uri.parse(f.url) };
      diags.push(diag);
    }

    // Sort by severity descending so highest-risk appear first in Problems panel
    diags.sort((a, b) => {
      const sA = SEVERITY_ORDER[(fileFindings[diags.indexOf(a)]?.severity) ?? "UNKNOWN"] ?? 0;
      const sB = SEVERITY_ORDER[(fileFindings[diags.indexOf(b)]?.severity) ?? "UNKNOWN"] ?? 0;
      return sB - sA;
    });

    osvDiagnostics.set(uri, diags);
  }

  currentOsvFindings = findings;
  osvEverScanned = true;
  osvTotalFindings = findings.length;
  updateStatusBar(manager.totalFindings());
  SecurityPanelProvider.refresh(manager.allFindings(), currentOsvFindings, osvEverScanned);
  SettingsPanel.refresh(manager.allFindings(), currentOsvFindings, osvEverScanned);

  // Show notification for new critical/high findings
  const blocking = findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH");
  if (blocking.length > 0) {
    const label = blocking.length === 1
      ? `${blocking[0].name}@${blocking[0].version} (${blocking[0].vulnId})`
      : `${blocking.length} packages`;
    vscode.window
      .showWarningMessage(
        `FLCN Sec OSV: ${blocking.length} HIGH/CRITICAL vulnerability/vulnerabilities found in ${label}.`,
        "Show Problems",
        "Dismiss",
      )
      .then(choice => {
        if (choice === "Show Problems") {
          vscode.commands.executeCommand("workbench.actions.view.problems");
        }
      });
  }
}

function startOsvTimer(): void {
  stopOsvTimer();
  const cfg = vscode.workspace.getConfiguration("flcn-sec");
  const minutes = cfg.get<number>("osv.scanIntervalMinutes", 60);
  if (minutes <= 0) return;
  osvScanTimer = setInterval(() => runOsvScan(), minutes * 60 * 1_000);
}

function stopOsvTimer(): void {
  if (osvScanTimer !== undefined) {
    clearInterval(osvScanTimer);
    osvScanTimer = undefined;
  }
}

function restartOsvTimer(): void {
  stopOsvTimer();
  const cfg = vscode.workspace.getConfiguration("flcn-sec");
  if (cfg.get<boolean>("osv.enabled", true)) {
    startOsvTimer();
  }
}

export { buildDiagnostics };

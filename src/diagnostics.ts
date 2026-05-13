import * as vscode from "vscode";
import { scanText, safePreview, RawFinding, PatternDef, AllowlistRule, ScanOptions } from "./detector";

const DIAG_SOURCE = "flcn-sec";
const CODE_CREDENTIAL = "credential";

// Matches any style of flcn-sec-disable file-level comment
const FILE_DISABLE_RE = /(?:#|\/\/|\/\*|<!--)\s*flcn-sec-disable\b/;

function fileDisableComment(languageId: string): string {
  const slashLangs = new Set([
    "javascript", "javascriptreact", "typescript", "typescriptreact",
    "go", "java", "c", "cpp", "csharp", "rust", "swift", "kotlin", "scala",
    "groovy", "dart", "php",
  ]);
  const hashLangs = new Set([
    "python", "ruby", "shellscript", "bash", "zsh", "powershell",
    "yaml", "toml", "dockerfile", "perl", "r", "julia",
  ]);
  const htmlLangs = new Set(["html", "xml", "markdown"]);
  const cssLangs  = new Set(["css", "scss", "less"]);

  if (slashLangs.has(languageId)) return "// flcn-sec-disable";
  if (hashLangs.has(languageId))  return "# flcn-sec-disable";
  if (htmlLangs.has(languageId))  return "<!-- flcn-sec-disable -->";
  if (cssLangs.has(languageId))   return "/* flcn-sec-disable */";
  return "# flcn-sec-disable";
}

export interface DocumentFinding {
  raw: RawFinding;
  range: vscode.Range;
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

// Sensitive path patterns — mirrors flcn-sec/lib/detectors.py _SENSITIVE_PATHS
const SENSITIVE_PATH_RES: RegExp[] = [
  /(^|[/\\])\.env(\.[^/\\]+)?$/,
  /[/\\]\.aws[/\\]credentials$/,
  /[/\\]\.ssh[/\\]id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/,
  /(^|[/\\])\.netrc$/,
  /[/\\]\.gcloud[/\\].*\.json$/,
  /(^|[/\\])\.npmrc$/,
  /(^|[/\\])\.pypirc$/,
  /(^|[/\\])\.docker[/\\]config\.json$/,
  /[/\\]\.kube[/\\]config$/,
  /service-account.*\.json$/i,
  /gcp-key.*\.json$/i,
  /firebase-adminsdk.*\.json$/i,
];

export function isSensitivePath(filePath: string): boolean {
  const p = filePath.replace(/\\/g, "/");
  return SENSITIVE_PATH_RES.some(re => re.test(p));
}

interface RawAllowlistRule {
  description?: string;
  valuePattern?: string;
  linePattern?: string;
  filePattern?: string;
  detectorName?: string;
}

function matchesGlob(filePath: string, glob: string): boolean {
  const p = filePath.replace(/\\/g, "/");
  const r = glob
    .replace(/\\/g, "/")
    .replace(/[.+^${}()|[\]]/g, "\\$&")
    .replace(/\*\*\//g, "(?:.+/)?")
    .replace(/\*\*/g, ".*")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]");
  try {
    return new RegExp(`(^|/)${r}(/|$)`).test(p) || new RegExp(`^${r}$`).test(p);
  } catch {
    return false;
  }
}

function shouldSkipFile(filePath: string): boolean {
  const excludePatterns = vscode.workspace
    .getConfiguration("flcn-sec")
    .get<string[]>("excludeFilePatterns", ["**/.git/**", "**/node_modules/**", "**/*.lock"]);
  return excludePatterns.some(g => matchesGlob(filePath, g));
}

interface CustomDetectorConfig {
  name: string;
  pattern: string;
  flags?: string;
  group?: number;
}

function buildScanOptions(doc: vscode.TextDocument): ScanOptions {
  const cfg = vscode.workspace.getConfiguration("flcn-sec");

  const extraPatterns = (cfg.get<CustomDetectorConfig[]>("customDetectors", []))
    .filter(d => d.name && d.pattern)
    .map(d => ({ kind: d.name, pattern: d.pattern, flags: d.flags, group: d.group } as PatternDef));

  const disabledDetectors = cfg.get<string[]>("disabledDetectors", []);

  const rawRules = cfg.get<RawAllowlistRule[]>("allowlist", []);
  const filePath = doc.uri.fsPath.replace(/\\/g, "/");

  // Filter allowlist rules to those that apply to this file (filePattern is file-scoped)
  const allowlist: AllowlistRule[] = [
    // Built-in: honour inline suppress comment regardless of user config
    { linePattern: "#\\s*flcn-sec-ignore" },
    ...rawRules
      .filter(r => !r.filePattern || matchesGlob(filePath, r.filePattern))
      .map(r => ({
        description: r.description,
        valuePattern: r.valuePattern,
        linePattern: r.linePattern,
        detectorName: r.detectorName,
      })),
  ];

  return { extraPatterns, disabledDetectors, allowlist };
}

function getSeverity(): vscode.DiagnosticSeverity {
  const s = vscode.workspace.getConfiguration("flcn-sec").get<string>("severity", "error");
  return s === "warning" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Error;
}

function shouldSkipDoc(doc: vscode.TextDocument): boolean {
  if (doc.uri.scheme !== "file") return true;
  // Skip binary-like files by extension
  const binaryExts = [".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".zip", ".gz", ".tar", ".bin", ".exe", ".dll", ".so", ".dylib"];
  if (binaryExts.some(ext => doc.uri.fsPath.endsWith(ext))) return true;
  const maxKb = vscode.workspace.getConfiguration("flcn-sec").get<number>("maxFileSizeKb", 512);
  if (doc.getText().length > maxKb * 1024) return true;
  if (shouldSkipFile(doc.uri.fsPath)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Core diagnostic builder
// ---------------------------------------------------------------------------

export function buildDiagnostics(
  doc: vscode.TextDocument,
  output?: vscode.OutputChannel,
): {
  diagnostics: vscode.Diagnostic[];
  findings: DocumentFinding[];
} {
  if (shouldSkipDoc(doc)) return { diagnostics: [], findings: [] };

  const text = doc.getText();
  if (FILE_DISABLE_RE.test(text)) return { diagnostics: [], findings: [] };
  const options = buildScanOptions(doc);
  const rawFindings = scanText(text, options);
  const severity = getSeverity();

  const diagnostics: vscode.Diagnostic[] = [];
  const findings: DocumentFinding[] = [];

  for (const raw of rawFindings) {
    const range = new vscode.Range(doc.positionAt(raw.start), doc.positionAt(raw.end));
    const preview = safePreview(raw.matchedValue);
    const diag = new vscode.Diagnostic(
      range,
      `FLCN Sec: ${raw.kind} detected (${preview}). Use a secret manager or env variable instead.`,
      severity,
    );
    diag.source = DIAG_SOURCE;
    diag.code = CODE_CREDENTIAL;
    diag.tags = [vscode.DiagnosticTag.Unnecessary];
    diagnostics.push(diag);
    findings.push({ raw, range });

    if (output) {
      const line = range.start.line + 1;
      const col = range.start.character + 1;
      const file = doc.uri.fsPath;
      output.appendLine(`[${new Date().toISOString()}] ${raw.kind} | ${file}:${line}:${col} | ${preview}`);
    }
  }

  return { diagnostics, findings };
}

// ---------------------------------------------------------------------------
// Code action provider — quick-fix: Redact credential
// ---------------------------------------------------------------------------

export class CredentialCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    doc: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== DIAG_SOURCE || diag.code !== CODE_CREDENTIAL) continue;

      const kindMatch = diag.message.match(/^FLCN Sec: (.+?) detected/);
      const kind = kindMatch ? kindMatch[1] : "Credential";

      // Primary: redact
      const redact = new vscode.CodeAction(`Redact ${kind}`, vscode.CodeActionKind.QuickFix);
      redact.diagnostics = [diag];
      redact.isPreferred = true;
      redact.edit = new vscode.WorkspaceEdit();
      redact.edit.replace(doc.uri, diag.range, `[REDACTED:${kind}]`);
      actions.push(redact);

      // Secondary: add inline allowlist comment
      const suppress = new vscode.CodeAction(
        `Suppress: add flcn-sec-ignore comment`,
        vscode.CodeActionKind.QuickFix,
      );
      suppress.diagnostics = [diag];
      const lineEnd = new vscode.Position(diag.range.start.line, Number.MAX_SAFE_INTEGER);
      suppress.edit = new vscode.WorkspaceEdit();
      suppress.edit.insert(doc.uri, lineEnd, "  # flcn-sec-ignore");
      actions.push(suppress);
    }

    // File-level disable — shown once regardless of how many diagnostics are on the cursor
    if (context.diagnostics.some(d => d.source === DIAG_SOURCE)) {
      const comment = fileDisableComment(doc.languageId);
      const disable = new vscode.CodeAction(
        `Disable FLCN Sec for entire file`,
        vscode.CodeActionKind.QuickFix,
      );
      disable.edit = new vscode.WorkspaceEdit();
      disable.edit.insert(doc.uri, new vscode.Position(0, 0), comment + "\n");
      actions.push(disable);
    }

    return actions;
  }
}

// ---------------------------------------------------------------------------
// DiagnosticsManager
// ---------------------------------------------------------------------------

export class DiagnosticsManager implements vscode.Disposable {
  private collection: vscode.DiagnosticCollection;
  private findingsCache = new Map<string, DocumentFinding[]>();
  private output: vscode.OutputChannel;

  constructor(output: vscode.OutputChannel) {
    this.collection = vscode.languages.createDiagnosticCollection(DIAG_SOURCE);
    this.output = output;
  }

  update(doc: vscode.TextDocument): DocumentFinding[] {
    if (!vscode.workspace.getConfiguration("flcn-sec").get<boolean>("enableRealTimeScan", true)) {
      this.collection.delete(doc.uri);
      this.findingsCache.delete(doc.uri.toString());
      return [];
    }
    const { diagnostics, findings } = buildDiagnostics(doc, this.output);
    this.collection.set(doc.uri, diagnostics);
    this.findingsCache.set(doc.uri.toString(), findings);
    return findings;
  }

  /** Re-scan every currently cached document — called when config changes. */
  refreshAll(docs: readonly vscode.TextDocument[]): void {
    for (const doc of docs) {
      if (this.findingsCache.has(doc.uri.toString())) {
        this.update(doc);
      }
    }
  }

  clear(doc: vscode.TextDocument): void {
    this.collection.delete(doc.uri);
    this.findingsCache.delete(doc.uri.toString());
  }

  findingsFor(doc: vscode.TextDocument): DocumentFinding[] {
    return this.findingsCache.get(doc.uri.toString()) ?? [];
  }

  totalFindings(): number {
    let count = 0;
    this.collection.forEach((_uri, diags) => { count += diags.length; });
    return count;
  }

  allFindings(): { filePath: string; line: number; kind: string; preview: string }[] {
    const result: { filePath: string; line: number; kind: string; preview: string }[] = [];
    for (const [uriStr, docFindings] of this.findingsCache) {
      const filePath = vscode.Uri.parse(uriStr).fsPath;
      for (const f of docFindings) {
        result.push({
          filePath,
          line: f.range.start.line + 1,
          kind: f.raw.kind,
          preview: safePreview(f.raw.matchedValue),
        });
      }
    }
    return result;
  }

  dispose(): void {
    this.collection.dispose();
  }
}

/**
 * npm audit scanner — runs `npm audit --json` and maps results to OsvFinding[].
 */

import * as child_process from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { OsvFinding, OsvSeverity } from "./osvScanner";

// ---------------------------------------------------------------------------
// npm audit v2 types (subset)
// ---------------------------------------------------------------------------

interface NpmAuditVia {
  title?: string;
  url?: string;
  severity?: string;
  cvss?: { score?: number };
}

interface NpmAuditVulnEntry {
  name: string;
  severity: string;
  via: (NpmAuditVia | string)[];
  range?: string;
  nodes?: string[];
}

interface NpmAuditOutput {
  vulnerabilities?: Record<string, NpmAuditVulnEntry>;
  metadata?: {
    vulnerabilities?: { total?: number };
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mapSeverity(s: string): OsvSeverity {
  switch (s.toLowerCase()) {
    case "critical": return "CRITICAL";
    case "high":     return "HIGH";
    case "moderate": return "MEDIUM";
    case "low":      return "LOW";
    default:         return "UNKNOWN";
  }
}

function hasLockFile(dir: string): boolean {
  return (
    fs.existsSync(path.join(dir, "package-lock.json")) ||
    fs.existsSync(path.join(dir, "yarn.lock")) ||
    fs.existsSync(path.join(dir, "pnpm-lock.yaml"))
  );
}

function getInstalledVersion(workspaceRoot: string, name: string, fallback: string): string {
  try {
    const pkgPath = path.join(workspaceRoot, "node_modules", name, "package.json");
    const raw = fs.readFileSync(pkgPath, "utf8");
    const pkg = JSON.parse(raw) as { version?: string };
    return pkg.version ?? fallback;
  } catch {
    return fallback;
  }
}

function findManifestLine(content: string, name: string): number {
  const lines = content.split("\n");
  const idx = lines.findIndex(l => l.includes(`"${name}"`));
  return Math.max(0, idx);
}

function extractVulnId(url: string): string {
  // Last path segment, e.g. GHSA-xxx-xxx-xxx or CVE-2025-XXXXX
  const parts = url.replace(/\/$/, "").split("/");
  return parts[parts.length - 1] ?? url;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function runNpmAudit(workspaceRoot: string, output: vscode.OutputChannel): Promise<OsvFinding[]> {
  if (!hasLockFile(workspaceRoot)) {
    output.appendLine("[npm-audit] No lock file found — skipping npm audit.");
    return [];
  }

  output.appendLine(`[npm-audit] Running npm audit in ${workspaceRoot}…`);

  let rawOutput: string;
  try {
    rawOutput = await new Promise<string>((resolve, reject) => {
      child_process.exec(
        "npm audit --json",
        { cwd: workspaceRoot, timeout: 60_000, maxBuffer: 10 * 1024 * 1024 },
        (_err, stdout, _stderr) => {
          // npm audit exits with non-zero when vulnerabilities are found — that's OK
          resolve(stdout ?? "");
        },
      );
      void reject; // silence unused-variable lint warning — exec callback handles errors
    });
  } catch (e) {
    output.appendLine(`[npm-audit] exec failed: ${e}`);
    return [];
  }

  let auditData: NpmAuditOutput;
  try {
    auditData = JSON.parse(rawOutput) as NpmAuditOutput;
  } catch {
    output.appendLine("[npm-audit] Could not parse npm audit JSON output.");
    return [];
  }

  const { vulnerabilities } = auditData;
  if (!vulnerabilities || Object.keys(vulnerabilities).length === 0) {
    output.appendLine("[npm-audit] No vulnerabilities reported.");
    return [];
  }

  // Find the root package.json for manifest line lookup
  const manifestPath = path.join(workspaceRoot, "package.json");
  let manifestContent = "";
  try {
    manifestContent = fs.readFileSync(manifestPath, "utf8");
  } catch {
    // ok — line will default to 0
  }

  const findings: OsvFinding[] = [];

  for (const [, vulnEntry] of Object.entries(vulnerabilities)) {
    const name = vulnEntry.name;
    const version = getInstalledVersion(workspaceRoot, name, vulnEntry.range ?? "unspecified");
    const manifestLine = manifestContent ? findManifestLine(manifestContent, name) : 0;

    for (const via of vulnEntry.via) {
      if (typeof via === "string") continue; // transitive dep reference — skip

      const advisory = via as NpmAuditVia;
      if (!advisory.url) continue;

      const vulnId = extractVulnId(advisory.url);
      const severity = mapSeverity(advisory.severity ?? vulnEntry.severity);
      const summary = (advisory.title ?? "").slice(0, 200);

      findings.push({
        manifestFile: manifestPath,
        name,
        version,
        ecosystem: "npm",
        vulnId,
        summary,
        severity,
        url: advisory.url,
        manifestLine,
        source: "npm-audit",
      });
    }
  }

  output.appendLine(`[npm-audit] Found ${findings.length} advisory/advisories.`);
  return findings;
}

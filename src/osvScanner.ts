/**
 * OSV.dev vulnerability scanner for dependency manifest files.
 *
 * Discovers package.json / requirements.txt / Cargo.toml / Gemfile / go.mod
 * in the workspace, queries the OSV.dev batch API for known vulnerabilities,
 * then fetches full vuln detail records (concurrently) to resolve severity.
 */

import * as https from "https";
import * as path from "path";
import * as vscode from "vscode";
import { runNpmAudit } from "./npmAudit";
import { scanWithGHSA } from "./ghsaScanner";
import { scanWithNVD } from "./nvdScanner";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type OsvSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface OsvFinding {
  manifestFile: string;   // absolute path to the manifest
  name: string;           // package name
  version: string;        // version as declared (or "unspecified")
  ecosystem: string;      // OSV ecosystem string
  vulnId: string;         // e.g. GHSA-xxxx or CVE-xxxx
  summary: string;
  severity: OsvSeverity;
  url: string;            // advisory URL
  manifestLine: number;   // 0-based line in the manifest (best-effort)
  source: string;         // "OSV", "GHSA", "NVD", "npm-audit"
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface PackageEntry {
  name: string;
  version: string;       // empty string = unspecified
  ecosystem: string;
  manifestFile: string;
  manifestLine: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/";
const REQUEST_TIMEOUT_MS  = 10_000;
const MAX_DETAIL_FETCHES  = 50;
const DETAIL_CONCURRENCY  = 10;
const MAX_FILES_PER_GLOB  = 20;
const EXCLUDE_GLOBS = "{**/node_modules/**,**/.git/**,**/vendor/**,**/dist/**,**/out/**,**/build/**}";

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function findAndScanManifests(output: vscode.OutputChannel): Promise<OsvFinding[]> {
  const entries = await collectManifestEntries(output);
  if (entries.length === 0) {
    output.appendLine("[OSV] No supported manifest files found.");
    return [];
  }
  output.appendLine(`[OSV] Scanning ${entries.length} package(s) across manifests…`);
  return queryOsvBatch(entries, output);
}

// ---------------------------------------------------------------------------
// Manifest discovery
// ---------------------------------------------------------------------------

interface ManifestFinder {
  glob: string;
  parser: (content: string, filePath: string) => PackageEntry[];
}

const FINDERS: ManifestFinder[] = [
  { glob: "**/package.json",       parser: parsePackageJson },
  { glob: "**/requirements*.txt",  parser: parseRequirementsTxt },
  { glob: "**/Cargo.toml",         parser: parseCargoToml },
  { glob: "**/Gemfile",            parser: parseGemfile },
  { glob: "**/go.mod",             parser: parseGoMod },
];

async function collectManifestEntries(output: vscode.OutputChannel): Promise<PackageEntry[]> {
  const all: PackageEntry[] = [];
  for (const { glob, parser } of FINDERS) {
    const uris = await vscode.workspace.findFiles(glob, EXCLUDE_GLOBS, MAX_FILES_PER_GLOB);
    for (const uri of uris) {
      try {
        const bytes = await vscode.workspace.fs.readFile(uri);
        const content = Buffer.from(bytes).toString("utf8");
        const entries = parser(content, uri.fsPath);
        all.push(...entries);
        output.appendLine(`[OSV] Parsed ${entries.length} package(s) from ${path.basename(uri.fsPath)}`);
      } catch (e) {
        output.appendLine(`[OSV] Could not parse ${uri.fsPath}: ${e}`);
      }
    }
  }
  return all;
}

// ---------------------------------------------------------------------------
// Manifest parsers
// ---------------------------------------------------------------------------

function parsePackageJson(content: string, filePath: string): PackageEntry[] {
  let json: Record<string, unknown>;
  try { json = JSON.parse(content); } catch { return []; }

  const lines = content.split("\n");
  const entries: PackageEntry[] = [];

  for (const depKey of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const deps = (json[depKey] ?? {}) as Record<string, string>;
    for (const [name, versionSpec] of Object.entries(deps)) {
      const version = normalizeNpmVersion(versionSpec);
      const manifestLine = lines.findIndex(l => l.includes(`"${name}"`));
      entries.push({ name, version, ecosystem: "npm", manifestFile: filePath, manifestLine: Math.max(0, manifestLine) });
    }
  }
  return entries;
}

function parseRequirementsTxt(content: string, filePath: string): PackageEntry[] {
  const entries: PackageEntry[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].split("#")[0].trim();  // strip inline comments
    if (!line || line.startsWith("-")) continue;

    // name[extras]==version or name>=version or just name
    const m = line.match(/^([A-Za-z0-9_.\-]+)(?:\[.*?\])?\s*([=<>!~^]+\s*[\d.*]+(?:\s*,\s*[=<>!~^]+\s*[\d.*]+)*)?/);
    if (!m) continue;

    const name = m[1];
    const versionStr = m[2]?.trim() ?? "";
    const version = normalizeVersion(versionStr);
    entries.push({ name, version, ecosystem: "PyPI", manifestFile: filePath, manifestLine: i });
  }
  return entries;
}

function parseCargoToml(content: string, filePath: string): PackageEntry[] {
  const entries: PackageEntry[] = [];
  const lines = content.split("\n");
  let inDeps = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (/^\[(.*\.)?dependencies(\.[^\]]+)?\]/.test(line)) {
      inDeps = true;
      continue;
    }
    if (line.startsWith("[") && !/^\[(.*\.)?dependencies/.test(line)) {
      inDeps = false;
      continue;
    }
    if (!inDeps || !line || line.startsWith("#")) continue;

    // name = "version"
    const simple = line.match(/^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"/);
    if (simple) {
      entries.push({ name: simple[1], version: simple[2], ecosystem: "crates.io", manifestFile: filePath, manifestLine: i });
      continue;
    }
    // name = { version = "..." }  or  name = { version = "...", features = [...] }
    const complex = line.match(/^([A-Za-z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"/);
    if (complex) {
      entries.push({ name: complex[1], version: complex[2], ecosystem: "crates.io", manifestFile: filePath, manifestLine: i });
    }
  }
  return entries;
}

function parseGemfile(content: string, filePath: string): PackageEntry[] {
  const entries: PackageEntry[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].split("#")[0].trim();
    const m = line.match(/^gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/);
    if (!m) continue;
    const version = m[2] ? normalizeVersion(m[2]) : "";
    entries.push({ name: m[1], version, ecosystem: "RubyGems", manifestFile: filePath, manifestLine: i });
  }
  return entries;
}

function parseGoMod(content: string, filePath: string): PackageEntry[] {
  const entries: PackageEntry[] = [];
  const lines = content.split("\n");
  let inRequire = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (/^require\s*\($/.test(line)) { inRequire = true; continue; }
    if (inRequire && line === ")") { inRequire = false; continue; }

    // single-line: require module v1.2.3
    const single = line.match(/^require\s+(\S+)\s+(v[\d][^\s]*)/);
    if (single) {
      entries.push({ name: single[1], version: single[2], ecosystem: "Go", manifestFile: filePath, manifestLine: i });
      continue;
    }
    if (inRequire) {
      const inner = line.match(/^(\S+)\s+(v[\d][^\s]*)/);
      if (inner && !inner[1].startsWith("//")) {
        entries.push({ name: inner[1], version: inner[2], ecosystem: "Go", manifestFile: filePath, manifestLine: i });
      }
    }
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Version normalisation helpers
// ---------------------------------------------------------------------------

function normalizeNpmVersion(spec: string): string {
  if (!spec) return "";
  // workspace:, file:, github:, etc. — not scannable
  if (/^(workspace|file|github|git|link):/.test(spec)) return "";
  // Strip leading ^ ~ >= > <= < = characters
  return spec.replace(/^[\^~>=<]+/, "").trim().split(" ")[0] ?? "";
}

function normalizeVersion(spec: string): string {
  if (!spec) return "";
  // Take the first specifier if there are multiple (e.g. ">=2.0, <3.0")
  const first = spec.split(",")[0].trim();
  return first.replace(/^[=!<>~^*]+/, "").trim();
}

// ---------------------------------------------------------------------------
// OSV.dev batch query
// ---------------------------------------------------------------------------

async function queryOsvBatch(entries: PackageEntry[], output: vscode.OutputChannel): Promise<OsvFinding[]> {
  // Build OSV batch queries (deduplicate by name+version+ecosystem)
  const seen = new Set<string>();
  const queries: { package: { name: string; ecosystem: string }; version?: string }[] = [];
  const queryIndex: PackageEntry[] = [];

  for (const e of entries) {
    const key = `${e.ecosystem}:${e.name}:${e.version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const q: typeof queries[0] = { package: { name: e.name, ecosystem: e.ecosystem } };
    if (e.version) q.version = e.version;
    queries.push(q);
    queryIndex.push(e);
  }

  // OSV batch: max 1000 queries per call; chunk if needed
  const CHUNK = 500;
  const allStubs: { entry: PackageEntry; vulnId: string }[] = [];

  for (let i = 0; i < queries.length; i += CHUNK) {
    const chunkQ = queries.slice(i, i + CHUNK);
    const chunkE = queryIndex.slice(i, i + CHUNK);

    let body: { results: { vulns?: { id: string }[] }[] };
    try {
      const raw = await httpsPost(OSV_BATCH_URL, JSON.stringify({ queries: chunkQ }));
      body = JSON.parse(raw);
    } catch (e) {
      output.appendLine(`[OSV] Batch query failed: ${e}`);
      continue;
    }

    for (let j = 0; j < chunkE.length; j++) {
      const result = body.results[j];
      if (!result?.vulns) continue;
      for (const vuln of result.vulns) {
        if (vuln.id) allStubs.push({ entry: chunkE[j], vulnId: vuln.id });
      }
    }
  }

  if (allStubs.length === 0) {
    output.appendLine("[OSV] No vulnerabilities found.");
    return [];
  }

  output.appendLine(`[OSV] Found ${allStubs.length} vulnerability reference(s); fetching details…`);

  // Fetch full vuln details concurrently for severity
  const uniqueIds = [...new Set(allStubs.map(s => s.vulnId))].slice(0, MAX_DETAIL_FETCHES);
  const detailMap = await fetchVulnDetails(uniqueIds);

  // Build findings, mapping original package entries back (first match per name+version+ecosystem)
  // so we get the right manifest line number
  const entryByKey = new Map<string, PackageEntry>();
  for (const e of entries) {
    const key = `${e.ecosystem}:${e.name}:${e.version}`;
    if (!entryByKey.has(key)) entryByKey.set(key, e);
  }

  const findings: OsvFinding[] = [];
  for (const { entry, vulnId } of allStubs) {
    const detail = detailMap.get(vulnId);
    const summary = String(detail?.summary ?? detail?.details ?? "").slice(0, 200);
    const severity = detail ? parseSeverity(detail) : "UNKNOWN";
    const refs = (detail?.references ?? []) as { url: string; type: string }[];
    const url =
      refs.find(r => r.type === "ADVISORY")?.url ??
      refs[0]?.url ??
      `https://osv.dev/vulnerability/${vulnId}`;

    // Map back to original entry (with correct manifestLine)
    const key = `${entry.ecosystem}:${entry.name}:${entry.version}`;
    const origEntry = entryByKey.get(key) ?? entry;

    findings.push({
      manifestFile: origEntry.manifestFile,
      name: entry.name,
      version: entry.version || "unspecified",
      ecosystem: entry.ecosystem,
      vulnId,
      summary,
      severity,
      url,
      manifestLine: origEntry.manifestLine,
      source: "OSV",
    });
  }

  const bySev = findings.reduce<Record<string, number>>((a, f) => {
    a[f.severity] = (a[f.severity] ?? 0) + 1;
    return a;
  }, {});
  output.appendLine(`[OSV] Scan complete: ${findings.length} vuln(s) — ${JSON.stringify(bySev)}`);

  return findings;
}

// ---------------------------------------------------------------------------
// Vuln detail fetching (concurrent)
// ---------------------------------------------------------------------------

async function fetchVulnDetails(ids: string[]): Promise<Map<string, Record<string, unknown>>> {
  const map = new Map<string, Record<string, unknown>>();

  for (let i = 0; i < ids.length; i += DETAIL_CONCURRENCY) {
    const batch = ids.slice(i, i + DETAIL_CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(id => httpsGet(OSV_VULN_URL + id))
    );
    for (let j = 0; j < batch.length; j++) {
      const r = results[j];
      if (r.status === "fulfilled") {
        try { map.set(batch[j], JSON.parse(r.value)); } catch {}
      }
    }
  }

  return map;
}

// ---------------------------------------------------------------------------
// Severity parsing (mirrors Python lib/osv_scan.py)
// ---------------------------------------------------------------------------

function parseSeverity(vuln: Record<string, unknown>): OsvSeverity {
  const dbSev = (
    (vuln.database_specific as Record<string, string> | null)?.severity ??
    (vuln.ecosystem_specific as Record<string, string> | null)?.severity ??
    ""
  ).toUpperCase();

  if (dbSev) {
    if (dbSev.includes("CRITICAL")) return "CRITICAL";
    if (dbSev.includes("HIGH"))     return "HIGH";
    if (dbSev.includes("MODERATE") || dbSev.includes("MEDIUM")) return "MEDIUM";
    if (dbSev.includes("LOW"))      return "LOW";
  }

  for (const entry of (vuln.severity as { type: string; score: string }[] | null) ?? []) {
    const score = parseCvssScore(entry.score);
    if (score !== null) return scoreToSeverity(score);
  }

  return "UNKNOWN";
}

function parseCvssScore(vector: string): number | null {
  // Strip prefix CVSS:3.x/
  const stripped = vector.replace(/^CVSS:[23]\.[01]\//, "");
  const parts = Object.fromEntries(
    stripped.split("/").filter(s => s.includes(":")).map(s => s.split(":") as [string, string])
  );

  const AV_MAP: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
  const AC_MAP: Record<string, number> = { L: 0.77, H: 0.44 };
  const UI_MAP: Record<string, number> = { N: 0.85, R: 0.62 };
  const CIA_MAP: Record<string, number> = { N: 0.00, L: 0.22, H: 0.56 };
  const PR_MAP: Record<string, [number, number]> = { N: [0.85, 0.85], L: [0.62, 0.68], H: [0.27, 0.50] };

  const S   = parts["S"] ?? "U";
  const AV  = AV_MAP[parts["AV"] ?? ""];
  const AC  = AC_MAP[parts["AC"] ?? ""];
  const prV = PR_MAP[parts["PR"] ?? ""];
  const PR  = prV ? (S === "C" ? prV[1] : prV[0]) : undefined;
  const UI  = UI_MAP[parts["UI"] ?? ""];
  const C   = CIA_MAP[parts["C"] ?? ""];
  const I   = CIA_MAP[parts["I"] ?? ""];
  const A   = CIA_MAP[parts["A"] ?? ""];

  if ([AV, AC, PR, UI, C, I, A].some(v => v === undefined)) return null;

  const ISS = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact = S === "C"
    ? 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15)
    : 6.42 * ISS;

  if (impact <= 0) return 0;

  const exploit = 8.22 * AV! * AC! * PR! * UI!;
  const raw = S === "C"
    ? Math.min(1.08 * (impact + exploit), 10)
    : Math.min(impact + exploit, 10);

  return Math.ceil(raw * 10) / 10;
}

function scoreToSeverity(score: number): OsvSeverity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0.0)  return "LOW";
  return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function httpsPost(url: string, body: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const bodyBuf = Buffer.from(body);
    const req = https.request(
      {
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": bodyBuf.length,
        },
      },
      res => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks).toString()));
      },
    );
    req.setTimeout(REQUEST_TIMEOUT_MS, () => { req.destroy(); reject(new Error("timeout")); });
    req.on("error", reject);
    req.write(bodyBuf);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Unified multi-source scan
// ---------------------------------------------------------------------------

export async function scanAllVulnerabilities(
  output: vscode.OutputChannel,
  onProgress?: (message: string) => void,
): Promise<OsvFinding[]> {
  const cfg = vscode.workspace.getConfiguration("flcn-sec");

  // 1. OSV scan (always runs when osv.enabled)
  onProgress?.("Scanning OSV.dev…");
  const osvFindings = await findAndScanManifests(output);

  // Collect unique package entries for GHSA/NVD
  const entries = await collectManifestEntries(output);
  const packageMap = new Map<string, { name: string; version: string; ecosystem: string; manifestFile: string; manifestLine: number }>();
  for (const e of entries) {
    const key = `${e.ecosystem}:${e.name}:${e.version}`;
    if (!packageMap.has(key)) {
      packageMap.set(key, {
        name: e.name,
        version: e.version || "unspecified",
        ecosystem: e.ecosystem,
        manifestFile: e.manifestFile,
        manifestLine: e.manifestLine,
      });
    }
  }
  const packages = [...packageMap.values()];

  const allFindings: OsvFinding[] = [...osvFindings];

  // 2. npm audit (for npm projects with a lock file)
  onProgress?.("Running npm audit…");
  if (cfg.get<boolean>("npmAudit.enabled", true)) {
    const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
    for (const folder of workspaceFolders) {
      try {
        const npmFindings = await runNpmAudit(folder.uri.fsPath, output);
        allFindings.push(...npmFindings);
      } catch (e) {
        output.appendLine(`[npm-audit] Error: ${e}`);
      }
    }
  }

  // 3. GHSA scan
  onProgress?.("Scanning GitHub Advisories…");
  if (cfg.get<boolean>("ghsa.enabled", true) && packages.length > 0) {
    const token = cfg.get<string>("github.token", "") || undefined;
    try {
      const ghsaFindings = await scanWithGHSA(packages, token || undefined, output);
      allFindings.push(...ghsaFindings);
    } catch (e) {
      output.appendLine(`[GHSA] Error: ${e}`);
    }
  }

  // 4. NVD scan (optional, slower)
  onProgress?.("Scanning NVD (this may take a moment)…");
  if (cfg.get<boolean>("nvd.enabled", true) && packages.length > 0) {
    const apiKey = cfg.get<string>("nvd.apiKey", "") || undefined;
    try {
      const nvdFindings = await scanWithNVD(packages, apiKey || undefined, output);
      allFindings.push(...nvdFindings);
    } catch (e) {
      output.appendLine(`[NVD] Error: ${e}`);
    }
  }

  // 5. Deduplicate: key = name@version:vulnId (normalized)
  const seen = new Set<string>();
  const deduped: OsvFinding[] = [];
  for (const f of allFindings) {
    // Normalize: prefer GHSA ID form; both CVE and GHSA for same advisory → keep first seen
    const key = `${f.name.toLowerCase()}@${f.version}:${f.vulnId.toUpperCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(f);
    }
  }

  output.appendLine(`[Scan] Total after deduplication: ${deduped.length} finding(s) from all sources.`);
  return deduped;
}

function httpsGet(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = https.request(
      { hostname: parsed.hostname, path: parsed.pathname + parsed.search, method: "GET" },
      res => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks).toString()));
      },
    );
    req.setTimeout(REQUEST_TIMEOUT_MS, () => { req.destroy(); reject(new Error("timeout")); });
    req.on("error", reject);
    req.end();
  });
}

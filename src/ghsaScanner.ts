/**
 * GitHub Security Advisories (GHSA) scanner.
 *
 * Queries https://api.github.com/advisories?affects=<ecosystem>/<package>
 * for each package and maps results to OsvFinding[].
 */

import * as https from "https";
import * as vscode from "vscode";
import { OsvFinding, OsvSeverity } from "./osvScanner";

// ---------------------------------------------------------------------------
// Ecosystem mapping
// ---------------------------------------------------------------------------

const ECOSYSTEM_MAP: Record<string, string> = {
  npm:       "npm",
  PyPI:      "pip",
  "crates.io": "rust",
  RubyGems:  "rubygems",
  Go:        "go",
};

// ---------------------------------------------------------------------------
// GHSA API types (subset)
// ---------------------------------------------------------------------------

interface GhsaAdvisory {
  ghsa_id: string;
  cve_id?: string;
  summary?: string;
  severity?: string;
  html_url?: string;
  vulnerabilities?: {
    package?: { ecosystem?: string; name?: string };
    vulnerable_version_range?: string;
    patched_versions?: string;
  }[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mapSeverity(s: string): OsvSeverity {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return "CRITICAL";
    case "high":     return "HIGH";
    case "moderate": return "MEDIUM";
    case "medium":   return "MEDIUM";
    case "low":      return "LOW";
    default:         return "UNKNOWN";
  }
}

function httpsGet(url: string, headers: Record<string, string>): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = https.request(
      {
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        method: "GET",
        headers,
      },
      res => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks).toString()));
      },
    );
    req.setTimeout(15_000, () => { req.destroy(); reject(new Error("timeout")); });
    req.on("error", reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function scanWithGHSA(
  packages: Array<{ name: string; version: string; ecosystem: string; manifestFile: string; manifestLine: number }>,
  token: string | undefined,
  output: vscode.OutputChannel,
): Promise<OsvFinding[]> {
  const MAX_PACKAGES = 30;

  const headers: Record<string, string> = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "flcn-sec-vscode",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const findings: OsvFinding[] = [];
  const capped = packages.slice(0, MAX_PACKAGES);

  output.appendLine(`[GHSA] Scanning ${capped.length} package(s) via GitHub Security Advisories…`);

  for (const pkg of capped) {
    const ghEcosystem = ECOSYSTEM_MAP[pkg.ecosystem];
    if (!ghEcosystem) {
      output.appendLine(`[GHSA] Skipping ${pkg.name} — unsupported ecosystem ${pkg.ecosystem}`);
      continue;
    }

    const url = `https://api.github.com/advisories?affects=${encodeURIComponent(ghEcosystem)}/${encodeURIComponent(pkg.name)}&per_page=10`;

    let raw: string;
    try {
      raw = await httpsGet(url, headers);
    } catch (e) {
      output.appendLine(`[GHSA] Request failed for ${pkg.name}: ${e}`);
      continue;
    }

    let advisories: GhsaAdvisory[];
    try {
      advisories = JSON.parse(raw) as GhsaAdvisory[];
      if (!Array.isArray(advisories)) continue;
    } catch {
      output.appendLine(`[GHSA] Could not parse response for ${pkg.name}`);
      continue;
    }

    for (const adv of advisories) {
      const vulnId = adv.cve_id ?? adv.ghsa_id;
      const severity = mapSeverity(adv.severity ?? "");
      const url2 = adv.html_url ?? `https://github.com/advisories/${adv.ghsa_id}`;
      const summary = (adv.summary ?? "").slice(0, 200);

      findings.push({
        manifestFile: pkg.manifestFile,
        name: pkg.name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
        vulnId,
        summary,
        severity,
        url: url2,
        manifestLine: pkg.manifestLine,
        source: "GHSA",
      });
    }
  }

  output.appendLine(`[GHSA] Scan complete: ${findings.length} finding(s).`);
  return findings;
}

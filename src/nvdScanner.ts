/**
 * NVD (NIST) CVE scanner.
 *
 * Queries https://services.nvd.nist.gov/rest/json/cves/2.0 by keyword for each package.
 * Rate limits: 5 req/30s without API key, 50 req/30s with key.
 */

import * as https from "https";
import * as vscode from "vscode";
import { OsvFinding, OsvSeverity } from "./osvScanner";

// ---------------------------------------------------------------------------
// NVD API types (subset)
// ---------------------------------------------------------------------------

interface NvdCvssV2 {
  cvssData?: { baseScore?: number; baseSeverity?: string };
}

interface NvdCvssV3 {
  cvssData?: { baseScore?: number; baseSeverity?: string };
}

interface NvdCve {
  id: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: {
    cvssMetricV31?: NvdCvssV3[];
    cvssMetricV30?: NvdCvssV3[];
    cvssMetricV2?: NvdCvssV2[];
  };
  references?: { url: string }[];
  configurations?: unknown[];
}

interface NvdResponse {
  vulnerabilities?: { cve: NvdCve }[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function mapSeverity(s: string): OsvSeverity {
  switch ((s ?? "").toUpperCase()) {
    case "CRITICAL": return "CRITICAL";
    case "HIGH":     return "HIGH";
    case "MEDIUM":   return "MEDIUM";
    case "LOW":      return "LOW";
    default:         return "UNKNOWN";
  }
}

function scoreToSeverity(score: number): OsvSeverity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0.0)  return "LOW";
  return "UNKNOWN";
}

function extractSeverity(cve: NvdCve): OsvSeverity {
  // Try CVSS v3.1 first, then v3.0, then v2
  const v31 = cve.metrics?.cvssMetricV31?.[0];
  if (v31?.cvssData?.baseSeverity) return mapSeverity(v31.cvssData.baseSeverity);
  if (v31?.cvssData?.baseScore !== undefined) return scoreToSeverity(v31.cvssData.baseScore);

  const v30 = cve.metrics?.cvssMetricV30?.[0];
  if (v30?.cvssData?.baseSeverity) return mapSeverity(v30.cvssData.baseSeverity);
  if (v30?.cvssData?.baseScore !== undefined) return scoreToSeverity(v30.cvssData.baseScore);

  const v2 = cve.metrics?.cvssMetricV2?.[0];
  if (v2?.cvssData?.baseScore !== undefined) return scoreToSeverity(v2.cvssData.baseScore);

  return "UNKNOWN";
}

function getEnglishDesc(cve: NvdCve): string {
  const desc = cve.descriptions?.find(d => d.lang === "en");
  return (desc?.value ?? "").slice(0, 200);
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
    req.setTimeout(30_000, () => { req.destroy(); reject(new Error("timeout")); });
    req.on("error", reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function scanWithNVD(
  packages: Array<{ name: string; version: string; ecosystem: string; manifestFile: string; manifestLine: number }>,
  apiKey: string | undefined,
  output: vscode.OutputChannel,
): Promise<OsvFinding[]> {
  const MAX_PACKAGES = 15;
  const delayMs = apiKey ? 600 : 6000;

  const headers: Record<string, string> = {
    "User-Agent": "flcn-sec-vscode",
  };
  if (apiKey) {
    headers["apiKey"] = apiKey;
  }

  const capped = packages.slice(0, MAX_PACKAGES);
  output.appendLine(`[NVD] Scanning ${capped.length} package(s) via NVD CVE API (delay: ${delayMs}ms/req)…`);

  const findings: OsvFinding[] = [];

  for (let i = 0; i < capped.length; i++) {
    if (i > 0) {
      await sleep(delayMs);
    }

    const pkg = capped[i];
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(pkg.name)}&resultsPerPage=10`;

    let raw: string;
    try {
      raw = await httpsGet(url, headers);
    } catch (e) {
      output.appendLine(`[NVD] Request failed for ${pkg.name}: ${e}`);
      continue;
    }

    let nvdData: NvdResponse;
    try {
      nvdData = JSON.parse(raw) as NvdResponse;
    } catch {
      output.appendLine(`[NVD] Could not parse response for ${pkg.name}`);
      continue;
    }

    for (const item of nvdData.vulnerabilities ?? []) {
      const cve = item.cve;
      if (!cve?.id) continue;

      const severity = extractSeverity(cve);
      const description = getEnglishDesc(cve);

      // Prefer NVD canonical URL
      const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cve.id}`;
      const refUrl = cve.references?.[0]?.url ?? nvdUrl;
      const advisoryUrl = refUrl.includes("nvd.nist.gov") ? refUrl : nvdUrl;

      // Filter: if CPE configurations present, verify keyword relevance.
      // If not present, include with a note.
      let summary = description;
      const hasConfigs = Array.isArray(cve.configurations) && cve.configurations.length > 0;
      if (!hasConfigs && !description.toLowerCase().includes(pkg.name.toLowerCase())) {
        summary = `[NVD keyword match — verify relevance] ${description}`.slice(0, 200);
      }

      findings.push({
        manifestFile: pkg.manifestFile,
        name: pkg.name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
        vulnId: cve.id,
        summary,
        severity,
        url: advisoryUrl,
        manifestLine: pkg.manifestLine,
        source: "NVD",
      });
    }
  }

  output.appendLine(`[NVD] Scan complete: ${findings.length} finding(s).`);
  return findings;
}

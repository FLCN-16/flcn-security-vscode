/**
 * Credential detector — pure functions, no VS Code dependency.
 * Ported from flcn-sec/lib/detectors.py; patterns stay in sync manually.
 */

export interface RawFinding {
  kind: string;
  start: number;   // char offset in the full text
  end: number;
  matchedValue: string;
}

export interface PatternDef {
  kind: string;
  pattern: string;
  flags?: string;
  group?: number;      // capture group that IS the secret (default 0 = full match)
  coPattern?: string;  // must also match somewhere in text (GCP service account)
}

export interface AllowlistRule {
  description?: string;
  /** Regex matched against the detected credential value */
  valuePattern?: string;
  /** Regex matched against the full line containing the match */
  linePattern?: string;
  /** Only suppress when coming from this detector name */
  detectorName?: string;
}

export interface ScanOptions {
  /** Extra patterns to detect beyond the built-ins */
  extraPatterns?: PatternDef[];
  /** Built-in detector names to skip */
  disabledDetectors?: string[];
  /** Rules to suppress specific findings */
  allowlist?: AllowlistRule[];
}

// ---------------------------------------------------------------------------
// Built-in pattern registry
// ---------------------------------------------------------------------------

export const BUILTIN_PATTERNS: PatternDef[] = [
  // No trailing \b: the greedy [A-Za-z0-9] naturally stops at non-alphanumeric so \b
  // is redundant and wrong (fails when the key is directly followed by _ or -)
  { kind: "Anthropic API Key",           pattern: String.raw`\bsk-ant-[A-Za-z0-9_\-]{40,}` },
  { kind: "OpenAI API Key",              pattern: String.raw`\bsk-(?!ant-)[A-Za-z0-9]{20,}` },
  { kind: "AWS Access Key ID",           pattern: String.raw`\bAKIA[0-9A-Z]{16}\b` },
  {
    kind: "AWS Secret Access Key",
    pattern: String.raw`aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9\/+=]{39,41})['"]?`,
    flags: "gi",
    group: 1,
  },
  { kind: "GitHub Token",                pattern: String.raw`\bgh[pousr]_[A-Za-z0-9]{36,}\b` },
  { kind: "Slack Token",                 pattern: String.raw`\bxox[abprs]-[A-Za-z0-9\-]{10,}\b` },
  { kind: "Stripe Secret Key",           pattern: String.raw`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b` },
  { kind: "Google API Key",              pattern: String.raw`\bAIza[0-9A-Za-z_\-]{35}\b` },
  {
    kind: "JSON Web Token",
    pattern: String.raw`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`,
  },
  {
    kind: "PEM Private Key",
    pattern: String.raw`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`,
  },
  {
    kind: "GCP Service Account",
    pattern: String.raw`"type"\s*:\s*"service_account"`,
    coPattern: String.raw`"private_key"`,
  },
  { kind: "HuggingFace Token",           pattern: String.raw`\bhf_[A-Za-z0-9]{34,}\b` },
  { kind: "npm Token",                   pattern: String.raw`\bnpm_[A-Za-z0-9]{36,}\b` },
  { kind: "Docker Hub PAT",              pattern: String.raw`\bdckr_pat_[A-Za-z0-9_\-]{43,}\b` },
  { kind: "SendGrid API Key",            pattern: String.raw`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` },
  { kind: "DigitalOcean Token",          pattern: String.raw`\bdop_v1_[A-Za-z0-9]{64}\b` },
  { kind: "Databricks Token",            pattern: String.raw`\bdapi[a-z0-9]{32}\b` },
  {
    kind: "Azure Storage Key",
    pattern: String.raw`AccountKey=([A-Za-z0-9+/=]{86,88})`,
    group: 1,
  },
  {
    kind: "MongoDB Connection String",
    pattern: String.raw`mongodb(?:\+srv)?://[^:\s]+:([^@\s]{8,})@`,
    group: 1,
  },
  {
    kind: "Env-style Secret Assignment",
    pattern: String.raw`^(?:export\s+)?[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Z0-9_]*\s*=\s*(\S{12,})`,
    flags: "gim",
    group: 1,
  },
];

// ---------------------------------------------------------------------------
// Core scan logic
// ---------------------------------------------------------------------------

function groupStart(fullMatch: string, fullMatchIndex: number, group: string): number {
  const offset = fullMatch.lastIndexOf(group);
  return fullMatchIndex + (offset >= 0 ? offset : 0);
}

function applyAllowlist(findings: RawFinding[], text: string, rules: AllowlistRule[]): RawFinding[] {
  if (!rules.length) return findings;
  const lines = text.split("\n");

  return findings.filter(f => {
    for (const rule of rules) {
      if (rule.detectorName && rule.detectorName !== f.kind) continue;

      let matches = true;
      if (rule.valuePattern) {
        try {
          matches = matches && new RegExp(rule.valuePattern, "i").test(f.matchedValue);
        } catch { matches = false; }
      }
      if (rule.linePattern && matches) {
        const lineIdx = text.slice(0, f.start).split("\n").length - 1;
        const line = lines[lineIdx] ?? "";
        try {
          matches = matches && new RegExp(rule.linePattern).test(line);
        } catch { matches = false; }
      }
      // If all specified conditions matched → suppress this finding
      if (matches) return false;
    }
    return true;
  });
}

export function scanText(text: string, options: ScanOptions = {}): RawFinding[] {
  const { extraPatterns = [], disabledDetectors = [], allowlist = [] } = options;
  const disabled = new Set(disabledDetectors);

  const allPatterns = [
    ...BUILTIN_PATTERNS.filter(p => !disabled.has(p.kind)),
    ...extraPatterns,
  ];

  const candidates: RawFinding[] = [];

  for (const def of allPatterns) {
    const baseFlags = def.flags ?? "g";
    const flags = baseFlags.includes("g") ? baseFlags : baseFlags + "g";
    const regex = new RegExp(def.pattern, flags);
    const group = def.group ?? 0;

    if (def.coPattern && !new RegExp(def.coPattern).test(text)) continue;

    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      if (match[0].length === 0) { regex.lastIndex++; continue; }

      const matchedValue = group > 0 ? (match[group] ?? match[0]) : match[0];
      if (!matchedValue) continue;
      // Skip our own redaction markers — avoids false positives on already-redacted text
      if (matchedValue.startsWith("[REDACTED:")) continue;

      const start = group > 0 ? groupStart(match[0], match.index, matchedValue) : match.index;
      const end = start + matchedValue.length;
      candidates.push({ kind: def.kind, start, end, matchedValue });
    }
  }

  // Sort by start, keep non-overlapping (first match wins)
  candidates.sort((a, b) => a.start - b.start);
  const findings: RawFinding[] = [];
  let lastEnd = -1;
  for (const c of candidates) {
    if (c.start >= lastEnd) {
      findings.push(c);
      lastEnd = c.end;
    }
  }

  return applyAllowlist(findings, text, allowlist);
}

export function safePreview(value: string, keep = 4): string {
  if (value.length <= keep * 2 + 3) return "*".repeat(value.length);
  return value.slice(0, keep) + "…" + value.slice(-keep);
}

export function redactText(
  text: string,
  options: ScanOptions = {},
): { redacted: string; findings: RawFinding[] } {
  const findings = scanText(text, options);
  let result = text;
  for (const f of [...findings].reverse()) {
    result = result.slice(0, f.start) + `[REDACTED:${f.kind}]` + result.slice(f.end);
  }
  return { redacted: result, findings };
}

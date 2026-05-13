# FLCN Security — Credential & Vulnerability Guard

Real-time protection against leaking secrets, API keys, and vulnerable dependencies to AI coding assistants and public repositories.

---

## Features

### Credential Detection
- **Real-time scanning** — underlines detected credentials as you edit, with inline diagnostics
- **20 built-in detectors** — covers all major cloud providers and services (AWS, OpenAI, Anthropic, GitHub, Stripe, GCP, and more)
- **Quick-fix actions** — redact a credential or suppress with an inline comment in one click
- **Warn on open / save** — alerts whenever a file containing credentials is opened or saved
- **Redact file** — replaces every detected credential in the active file with `[REDACTED:Kind]`

### Dependency Vulnerability Scanning
- **OSV.dev** — queries the Open Source Vulnerabilities database for all dependency manifests
- **GitHub Security Advisories (GHSA)** — queries the GitHub Advisory Database directly for same-day CVE coverage
- **NVD (NIST)** — queries the National Vulnerability Database for CVEs not yet in OSV
- **npm audit** — runs `npm audit` locally for Node.js projects; catches advisories the moment they are published
- Supports `package.json`, `requirements.txt`, `Cargo.toml`, `Gemfile`, and `go.mod`
- Configurable scan interval (default: every 60 minutes) and auto-scan on project open
- Results shown inline in the Problems panel and in the dedicated **FLCN Security** panel

### Security Dashboard
- Open with `FLCN Sec: Open Security Dashboard` or click the status bar item
- **Live Issues** — credential and vulnerability cards at the top, updated in real time
- **Settings controls** — toggle every option without leaving VS Code
- **Loading progress** — per-scanner status ("Scanning GHSA…", "Scanning NVD…") while scans run

### FLCN Security Panel
- Dedicated tab in the bottom panel (alongside Output and Terminal)
- Problems-panel style — credentials and vulnerabilities in collapsible sections
- Click a credential row to jump to the file and line
- Click a vulnerability ID to open the advisory in your browser

### Git Pre-commit Hook
- Installs a `pre-commit` hook that blocks commits containing credentials
- Manage from the dashboard or via command palette

### AI Context Exclusions
- Writes `.cursorignore` and disables Copilot for `.env`, `*.pem`, SSH keys, and other sensitive file types
- Applied automatically when a sensitive file is first opened

---

## Built-in Detectors

| Detector | Pattern |
|---|---|
| Anthropic API Key | `sk-ant-api03-…` |
| OpenAI API Key | `sk-proj-…` |
| AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Access Key | `aws_secret_access_key = …` |
| GitHub Token | `ghp_…`, `gho_…`, `ghs_…` |
| Slack Token | `xoxb-…`, `xoxp-…` |
| Stripe Secret Key | `sk_live_…`, `rk_test_…` |
| Google API Key | `AIzaSy…` |
| JSON Web Token | `eyJ…` |
| PEM Private Key | `-----BEGIN … PRIVATE KEY-----` |
| GCP Service Account | JSON with `"type": "service_account"` |
| HuggingFace Token | `hf_…` |
| npm Token | `npm_…` |
| Docker Hub PAT | `dckr_pat_…` |
| SendGrid API Key | `SG.…` |
| DigitalOcean Token | `dop_v1_…` |
| Databricks Token | `dapi…` |
| Azure Storage Key | `AccountKey=…` |
| MongoDB Connection String | `mongodb://user:password@…` |
| Env-style Secret Assignment | `MY_TOKEN=abc123…` |

---

## Commands

| Command | Description |
|---|---|
| `FLCN Sec: Open Security Dashboard` | Open the dashboard editor tab |
| `FLCN Sec: Scan Current File for Credentials` | One-shot scan with results notification |
| `FLCN Sec: Redact All Credentials in File` | Replace every detected credential |
| `FLCN Sec: Open Redacted View` | Open a safe copy alongside the real file |
| `FLCN Sec: Toggle Real-time Scanning` | Enable / disable live diagnostics |
| `FLCN Sec: Show Findings Log` | Open the output channel |
| `FLCN Sec: Scan Dependencies for Vulnerabilities` | Trigger a manual vulnerability scan |
| `FLCN Sec: Install Git Pre-commit Hook` | Install the hook in the current workspace |
| `FLCN Sec: Uninstall Git Pre-commit Hook` | Remove the hook |
| `FLCN Sec: Exclude Sensitive Files from AI` | Write `.cursorignore` and Copilot settings |

---

## Settings

### Credential Guard

| Setting | Default | Description |
|---|---|---|
| `flcn-sec.enableRealTimeScan` | `true` | Scan as you type |
| `flcn-sec.warnOnOpen` | `true` | Alert when a file with credentials is opened |
| `flcn-sec.warnOnSave` | `true` | Alert when saving a file with credentials |
| `flcn-sec.severity` | `"error"` | Diagnostic level: `"error"` or `"warning"` |
| `flcn-sec.maxFileSizeKb` | `512` | Skip files larger than this (KB) |
| `flcn-sec.excludeFilePatterns` | see docs | Glob patterns for files to skip entirely |
| `flcn-sec.customDetectors` | `[]` | Add regex-based detectors for your own secrets |
| `flcn-sec.allowlist` | `[]` | Suppress specific findings by value, line, file, or detector |
| `flcn-sec.disabledDetectors` | `[]` | Disable specific built-in detectors by name |

### Vulnerability Scanning

| Setting | Default | Description |
|---|---|---|
| `flcn-sec.osv.enabled` | `true` | Enable OSV.dev scanning |
| `flcn-sec.osv.scanOnOpen` | `true` | Scan automatically when the workspace opens |
| `flcn-sec.osv.scanIntervalMinutes` | `60` | Re-scan interval (0 = disabled) |
| `flcn-sec.osv.blockSeverity` | `"HIGH"` | Show as error at or above this severity |
| `flcn-sec.ghsa.enabled` | `true` | Enable GitHub Security Advisories scanning |
| `flcn-sec.github.token` | `""` | GitHub PAT for higher GHSA rate limits |
| `flcn-sec.nvd.enabled` | `true` | Enable NVD (NIST) CVE scanning |
| `flcn-sec.nvd.apiKey` | `""` | NVD API key for higher rate limits |
| `flcn-sec.npmAudit.enabled` | `true` | Enable npm audit for Node.js projects |

### Custom Detectors

```json
"flcn-sec.customDetectors": [
  {
    "name": "MyApp Token",
    "pattern": "myapp_[A-Za-z0-9]{32}",
    "flags": "g"
  },
  {
    "name": "DB Password",
    "pattern": "DB_PASSWORD\\s*=\\s*(\\S{12,})",
    "flags": "gim",
    "group": 1
  }
]
```

### Allowlist

Suppress known-safe findings without disabling the detector:

```json
"flcn-sec.allowlist": [
  {
    "description": "Placeholder values in docs",
    "valuePattern": "^(YOUR_|REPLACE_ME|example|placeholder)",
    "detectorName": "Env-style Secret Assignment"
  },
  {
    "description": "JWTs in test fixtures are fake",
    "detectorName": "JSON Web Token",
    "filePattern": "**/*.test.*"
  }
]
```

---

## Claude Code Integration

FLCN Sec ships with a companion Claude Code hooks plugin that adds hook-level protection to the Claude Code CLI:

- **UserPromptSubmit** — blocks prompts containing credentials before they reach the model
- **PreToolUse** — redacts credentials from file reads and bash output; hard-blocks writes containing secrets; scans package install commands (pip, npm, cargo, gem) against OSV/GHSA/NVD before executing
- **PostToolUse** — alerts if a credential slipped through in a tool result

See the companion `hooks/` directory for setup instructions.

---

## License

[GNU Affero General Public License v3.0](LICENSE.txt)

Any project that uses, modifies, or builds on FLCN Security must also be released as open source under the AGPL v3 (or a compatible license). This includes projects that expose the extension's functionality over a network.

# Changelog

All notable changes to FLCN Security are documented here.

## [1.6.1]

### Added
- **Sentry error monitoring** — unhandled exceptions in credential scanning, redaction, and OSV vulnerability scanning are now captured and reported to Sentry for faster diagnosis

### Changed
- Build system switched from plain `tsc` to **esbuild** — bundles the extension and all runtime dependencies into a single `out/extension.js` for faster load times and self-contained packaging

## [1.6.0]

## [1.5.0]

### Added
- **GitHub Security Advisories (GHSA)** scanner — queries the GitHub Advisory Database per package for same-day CVE coverage
- **NVD (NIST) CVE** scanner — queries the National Vulnerability Database for CVEs not yet in OSV; optional API key for higher rate limits
- **npm audit** integration — runs `npm audit --json` locally for Node.js projects with a lock file
- Per-scanner enable/disable settings: `flcn-sec.ghsa.enabled`, `flcn-sec.nvd.enabled`, `flcn-sec.npmAudit.enabled`
- `flcn-sec.github.token` and `flcn-sec.nvd.apiKey` settings for authenticated API access
- Loading progress indicator in both the Dashboard and FLCN Security panel showing the active scanner step
- Scrollable issue cards on the Dashboard (max height with hidden scrollbar)
- "Additional Scanners" section in the Settings Dashboard

## [1.4.0]

### Added
- **OSV.dev vulnerability scanning** — scans `package.json`, `requirements.txt`, `Cargo.toml`, `Gemfile`, `go.mod` against the Open Source Vulnerabilities database
- **FLCN Security panel** — dedicated bottom panel tab (alongside Output/Terminal) with a Problems-panel style view; collapsible sections for credentials and vulnerabilities; click-to-navigate for credentials, click-to-open-advisory for vulnerabilities
- **Settings Dashboard** — full editor-area tab with live issue cards at the top and all configuration controls below
- Per-package vulnerability grouping in the Dashboard (one row per package, sub-rows per CVE)
- `flcn-sec.osv.enabled`, `flcn-sec.osv.scanOnOpen`, `flcn-sec.osv.scanIntervalMinutes`, `flcn-sec.osv.blockSeverity` settings
- `flcn-sec.scanDependencies` command for on-demand vulnerability scans
- Status bar shows combined credential + vulnerability counts

## [1.3.0]

### Added
- **Git pre-commit hook** — installs a hook that blocks commits containing credentials
- `flcn-sec.installGitHook` and `flcn-sec.uninstallGitHook` commands
- One-time prompt to install the hook when a git workspace is first opened

## [1.2.0]

### Added
- **AI context exclusions** — writes `.cursorignore` and disables GitHub Copilot for sensitive file types (`.env`, `*.pem`, SSH keys, etc.)
- `flcn-sec.excludeFromAI` command
- Auto-applies exclusions when a sensitive file is first opened
- **Open Redacted View** — opens a masked copy of the active file alongside the real one for safe sharing with AI chat

## [1.1.0]

### Added
- `flcn-sec.warnOnOpen` setting — alert when a file containing credentials is opened
- `flcn-sec.allowlist` setting — suppress specific findings by value pattern, line pattern, file glob, or detector name
- Inline `# flcn-sec-ignore` comment support to suppress individual lines
- `flcn-sec.customDetectors` — add regex-based detectors for proprietary secret formats with capture-group support
- `flcn-sec.disabledDetectors` — disable specific built-in detectors by name

## [1.0.0]

### Added
- Initial release
- Real-time credential scanning with inline diagnostics
- 20 built-in detectors covering AWS, OpenAI, Anthropic, GitHub, Stripe, GCP, and more
- Quick-fix actions: redact credential, add suppress comment
- `flcn-sec.redactFile` command — redact all credentials in the active file
- Findings log output channel
- `flcn-sec.severity`, `flcn-sec.maxFileSizeKb`, `flcn-sec.excludeFilePatterns` settings

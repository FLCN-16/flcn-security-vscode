# Contributing to FLCN Security

Thank you for taking the time to contribute! This document covers everything you need to get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Commit Style](#commit-style)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to uphold it.

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/flcn-security-vscode.git
   cd flcn-security-vscode
   ```
3. **Install dependencies:**
   ```bash
   npm install
   ```
4. **Open in VS Code** and press `F5` to launch the Extension Development Host.

---

## How to Contribute

| Type | Where to start |
|---|---|
| Bug fix | Open a bug report issue first (unless trivial), then a PR |
| New detector | Open a feature request issue; include example patterns |
| New vulnerability scanner | Discuss in an issue before coding |
| Docs / typo | PR directly — no issue needed |
| Refactor | Open an issue first to align on scope |

---

## Development Setup

### Prerequisites

- Node.js ≥ 18
- VS Code ≥ 1.85

### Build

```bash
# Type-check
npm run compile

# Bundle (produces out/extension.js)
npm run bundle

# Watch mode
npm run watch
```

### Running the Extension

Press `F5` in VS Code to open an Extension Development Host with the extension loaded.

### Packaging Locally

```bash
npm run package          # produces flcn-sec-<version>.vsix
code --install-extension flcn-sec-<version>.vsix
```

---

## Submitting a Pull Request

1. Create a branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Make your changes and ensure `npm run compile` passes with no errors.
3. Update `CHANGELOG.md` under an `[Unreleased]` section.
4. Push to your fork and open a PR against `main`.
5. Fill out the PR template completely.

PRs that skip the PR template or break the build will not be merged until fixed.

---

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add HuggingFace token detector
fix: correct AWS secret key regex to handle newlines
docs: update README settings table
chore: bump esbuild to 0.29
```

---

## Reporting Bugs

Use the **Bug Report** issue template on GitHub. Include:

- VS Code version
- Extension version
- Steps to reproduce
- Expected vs. actual behavior
- Relevant logs from **FLCN Sec: Show Findings Log**

**Security vulnerabilities** must be reported privately — see [SECURITY.md](SECURITY.md).

---

## Suggesting Features

Use the **Feature Request** issue template. Describe the use case and why existing functionality doesn't cover it. New detectors should include:

- The service/token type
- A safe example pattern (no real credentials)
- A reference to the service's documentation on token format

---

## Questions?

Open a [Discussion](https://github.com/FLCN-16/flcn-security-vscode/discussions) rather than an issue for general questions.

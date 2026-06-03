# Sentinel Oracle Core — Skills / Tools Reference

## Tool Categories

Tools are defined in `src/oracle/tools.ts` (18 total). Each tool has:
- `name` — unique identifier
- `description` — what the AI sees to decide when to use it
- `parameters` — JSON Schema for arguments
- `run(args)` — synchronous function returning string output

## Permission Requirements

| Mode | Behavior | Permission Needed? |
|------|----------|-------------------|
| `execute` (default) | Tools run after user approval | Yes (Enter/Esc per tool) |
| `auto` | Tools run immediately | No |
| `plan` | Tools are NOT executed | N/A (plan only) |

---

## Category 1: Scanning Tools

### `scan`
- **Description:** Scan a directory or file for security threats using LiteScanner (30 SAST rules including secrets, eval, network, env access)
- **Parameters:**
  - `path` (string, optional) — File or directory path to scan (default: current dir)
- **Implementation:** Calls `sentinel scan <path> --json` via subprocess
- **When to use:** Any request involving local code analysis, finding secrets, detecting malicious patterns in files
- **Permission:** ⚠️ Execute mode requires approval

### `doctor`
- **Description:** System health check for npm dependencies in a project — scans for known vulnerabilities, capability risks, and outdated packages
- **Parameters:**
  - `path` (string, optional) — Project path to scan (default: current dir)
  - `deep` (string, `--deep`, optional) — Pass `--deep` for full dependency tree scan
- **Implementation:** Calls `sentinel doctor [--deep] <path>` via subprocess
- **When to use:** User asks about dependency health, vulnerability assessment of a project
- **Permission:** ⚠️ Requires approval

### `verify-pkg`
- **Description:** Audit an npm package via npm pack (zero-install) — detects typosquatting, secret leaks, hardcoded credentials, and supply chain threats in the tarball
- **Parameters:**
  - `package` (string, required) — npm package name to audit (e.g. axios, lodash)
- **Implementation:** Calls `sentinel verify-pkg <package>` via subprocess
- **When to use:** User asks about a specific npm package's safety before installation
- **Permission:** ⚠️ Requires approval

### `check-classified`
- **Description:** Check staged files in a git repo against the classified documents database. Blocks commits when classified files are staged.
- **Parameters:**
  - `path` (string, optional) — Git repository path (default: current dir)
- **Implementation:** Calls `sentinel check-classified <path>` via subprocess
- **When to use:** User wants to verify staged files don't contain classified/sensitive content
- **Permission:** ⚠️ Requires approval

### `integrity`
- **Description:** Verify Sentinel host integrity — checks code hash, PATH poisoning, vault integrity, clock anomalies, signed manifest, and persistent integrity chain
- **Parameters:** (none)
- **Implementation:** Calls `sentinel integrity` via subprocess
- **When to use:** User wants to verify Sentinel itself hasn't been tampered with
- **Permission:** ⚠️ Requires approval

### `memory`
- **Description:** Query the Signal Vault (local SQLite) for past scan results, findings, threat correlations, and session history
- **Parameters:**
  - `action` (string, optional) — Action like `--findings`, `--sessions`, `--threats`
  - `query` (string, optional) — Optional search term
- **Implementation:** Calls `sentinel memory <action> <query>` via subprocess
- **When to use:** User asks about past scans, historical findings, previous session data
- **Permission:** ⚠️ Requires approval

---

## Category 2: GitHub / SecuriGit Tools

### `gh-pr-list`
- **Description:** List open pull requests in the current GitHub repository. Returns PR number, title, author, and status.
- **Parameters:**
  - `repo` (string, optional) — Repo in format `owner/name` (default: current dir repo)
  - `limit` (string, optional) — Max PRs to return (default: 10)
  - `state` (string, enum: `open`, `closed`, `all`, optional) — PR state filter
- **Implementation:** Calls `gh pr list --json number,title,author,headRefName,baseRefName,createdAt,state` via subprocess
- **When to use:** User wants to see open PRs, check what PRs exist in a repo
- **Permission:** ⚠️ Requires approval. Also requires `gh` authenticated.

### `gh-pr-view`
- **Description:** View detailed information about a specific pull request: diff stats, changed files, labels, reviewers, and CI status.
- **Parameters:**
  - `number` (string, required) — PR number to view
  - `repo` (string, optional) — Repo in format `owner/name` (default: current dir repo)
- **Implementation:** Calls `gh pr view <number> --json title,body,author,state,mergeable,reviews,additions,deletions,files,labels,...`
- **When to use:** User asks about a specific PR's details, needs to see what files changed
- **Permission:** ⚠️ Requires approval

### `gh-pr-diff`
- **Description:** Get the full diff of a pull request. Returns the raw diff output which can be piped directly into sentinel scan for SAST analysis.
- **Parameters:**
  - `number` (string, required) — PR number to get diff from
  - `repo` (string, optional) — Repo in format `owner/name` (default: current dir repo)
- **Implementation:** Calls `gh pr diff <number>` directly via `execFileSync` (larger buffer: 50MB)
- **When to use:** User wants security analysis of a PR's code changes. Often used before scan
- **Permission:** ⚠️ Requires approval

### `gh-pr-comment`
- **Description:** Post a comment on a pull request. Use to deliver security audit results directly on the PR.
- **Parameters:**
  - `number` (string, required) — PR number to comment on
  - `body` (string, required) — Comment body text
  - `repo` (string, optional) — Repo in format `owner/name` (default: current dir repo)
- **Implementation:** Writes body to temp file, calls `gh pr comment <number> --body-file <file>`, cleans up temp file
- **When to use:** After security analysis, to post findings as a PR comment. Safety: uses temp file to avoid shell injection
- **Permission:** ⚠️ Requires approval. Destructive action — user should explicitly consent.

### `gh-repo-list`
- **Description:** List GitHub repositories for the authenticated user or organization. Shows name, visibility, and description.
- **Parameters:**
  - `owner` (string, optional) — User or organization name (default: authenticated user)
  - `limit` (string, optional) — Max repos to return (default: 20)
- **Implementation:** Calls `gh repo list --json name,owner,visibility,description,url,isFork` via subprocess
- **When to use:** User asks about available repos, wants to find a repo by name
- **Permission:** ⚠️ Requires approval

---

## Category 3: Package Management Tools

### `download-verify-pkg`
- **Description:** Download an npm package to a temp directory and scan it with sentinel. Does NOT install. Reports typosquatting, secrets, malicious patterns before any installation.
- **Parameters:**
  - `package` (string, required) — npm package name to download and analyze
- **Implementation:** `npm pack <package> --pack-destination <tmpdir>` → `sentinel verify-pkg <tarball>` → cleanup
- **When to use:** User wants to thoroughly vet a package before deciding to install. Safety: downloads to temp dir, never installs, cleans up
- **Permission:** ⚠️ Requires approval

### `install-pkg`
- **Description:** Install an npm package. ONLY use after verifying with `download-verify-pkg` AND after the user explicitly asks to install.
- **Parameters:**
  - `package` (string, required) — npm package name to install
  - `global` (string, `--global`, optional) — For global install
- **Implementation:** `npm install [--global] <package>` via subprocess
- **When to use:** ONLY after verifying a package is safe AND user explicitly requests installation
- **Permission:** ⚠️ Requires approval. Guard: AI restricted by hard rules from installing without prior verification

### `remove-pkg`
- **Description:** Remove an installed npm package. Use when a package is found to be malicious or unwanted.
- **Parameters:**
  - `package` (string, required) — npm package name to remove
  - `global` (string, `--global`, optional) — If globally installed
- **Implementation:** `npm uninstall [--global] <package>` via subprocess
- **When to use:** Package was found malicious, user wants to remove a compromised dependency
- **Permission:** ⚠️ Requires approval

---

## Category 4: Machine Analysis Tools

### `machine-classify`
- **Description:** Classify a file against the classified documents database. Detects if a file contains classified/sensitive content.
- **Parameters:**
  - `file` (string, required) — File path to classify
- **Implementation:** Calls `sentinel classify <file>` via subprocess
- **When to use:** User asks if a specific file contains classified or sensitive information
- **Permission:** ⚠️ Requires approval

### `machine-integrity`
- **Description:** Run Sentinel integrity check on the host system — verifies code hash, PATH, vault, clock, and manifest integrity.
- **Parameters:** (none)
- **Implementation:** Calls `sentinel integrity` via subprocess
- **When to use:** General system integrity checks (alias for `integrity` with different context naming)
- **Permission:** ⚠️ Requires approval

### `machine-memory`
- **Description:** Query the Signal Vault (local SQLite) for past scan results, findings, threat correlations, and session history.
- **Parameters:**
  - `action` (string, optional) — Action: `--findings`, `--sessions`, `--threats`, or custom query
  - `query` (string, optional) — Optional search term
- **Implementation:** Calls `sentinel memory <action> <query>` via subprocess
- **When to use:** Historical data queries (alias for `memory` with different context naming)
- **Permission:** ⚠️ Requires approval

## Tool Selection Heuristics

The AI (via system prompt tool descriptions) decides which tool to use based on:

| User Intent | Likely Tools | Notes |
|---|---|---|
| "Scan this code" | `scan` | With optional `path` argument |
| "Is this package safe?" | `verify-pkg` or `download-verify-pkg` | Zero-install audit first |
| "Check my dependencies" | `doctor` | With optional `--deep` |
| "What PRs are open?" | `gh-pr-list` | SecuriGit flow |
| "Review PR #5" | `gh-pr-view` + `gh-pr-diff` | Then pipe diff to `scan` |
| "Post results on PR" | `gh-pr-comment` | After analysis |
| "Check integrity" | `integrity` or `machine-integrity` | |
| "Classify this file" | `machine-classify` | |
| "Check npm package then install" | `download-verify-pkg` → `install-pkg` | Two-step workflow |
| "Remove this malicious package" | `remove-pkg` | |
| "Check past findings" | `memory` or `machine-memory` | |
| "Any threats from author X?" | `memory --threats` + threat DB | Correlation is automatic on scan results |

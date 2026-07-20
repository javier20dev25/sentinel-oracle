# Attack Vector Analysis: GitHub Account Compromise

## The Problem

Sentinel Oracle assumes the **workstation is compromised** and physically isolates
merge authority. However, if the **GitHub account itself** is compromised, the attacker
can bypass the Oracle entirely by interacting with GitHub directly.

---

## Attack Vectors

### Vector A: GitHub Credential Theft

| Step | Description |
|------|-------------|
| 1 | Attacker phishes the repo admin's GitHub credentials or session cookie |
| 2 | Attacker logs into github.com as the admin |
| 3 | Attacker disables branch protection rules (requires admin) |
| 4 | Attacker pushes directly to `main` or merges PRs without status checks |
| 5 | Oracle is never involved — no audit trail on Oracle side |

**Impact**: Critical. Complete bypass of Oracle. No forensic trace.

### Vector B: PAT / SSH Key Leak

| Step | Description |
|------|-------------|
| 1 | Attacker steals a PAT or SSH key from CI/CD, developer machine, or Oracle server |
| 2 | Attacker uses the PAT to call `pulls.merge()` via GitHub API directly |
| 3 | If PAT has `repo` scope, they can merge regardless of branch protection |
| 4 | Oracle is unaware the merge happened |

**Impact**: Critical. PAT from Oracle server is especially dangerous.

### Vector C: GitHub App Compromise

| Step | Description |
|------|-------------|
| 1 | Attacker gains access to GitHub App private key or installation JWT |
| 2 | Attacker impersonates the GitHub App to GitHub API |
| 3 | App may have merge permissions depending on installation scope |

**Impact**: High. Depends on App permissions.

### Vector D: Org/Repo Owner Insider Threat

| Step | Description |
|------|-------------|
| 1 | Authorized GitHub admin performs unauthorized merge via web UI |
| 2 | Branch protection is bypassed (admins can override) |
| 3 | Oracle has no record of the merge |

**Impact**: Critical. No technical defense against repo admin.

---

## Current Mitigations

| Mitigation | Effectiveness vs Account Compromise |
|------------|--------------------------------------|
| Physical isolation of merge authority | **None** — attacker bypasses Oracle entirely |
| WebAuthn passkey on phone | **None** — attacker uses GitHub, not Oracle |
| Enrollment password | **None** — attacker uses GitHub, not Oracle |
| Encrypted device keys at rest | **None** — attacker uses GitHub, not Oracle |
| GitHub PAT with limited scope | **Partial** — fine-grained PAT limited to specific repos reduces blast radius |
| Sentinel Authorization status check | **Partial** — if branch protection REQUIRES this check, admin must disable protection first |
| Audit logging on Oracle | **None** — attacker bypasses Oracle entirely |

The Oracle's security model is **Merge Authority Isolation**, which protects against
workstation compromise. It does NOT protect against GitHub account compromise.

---

## Contingency Plan

### Layer 1: Prevention (Branch Protection)

**GitHub branch protection rules are the primary defense against account compromise:**

```
Required status checks:  [x] Sentinel Authorization
Dismiss stale reviews:   [x]
Require review:          [x] (at least 1)
Restrict who can push:   [x] (matching branches)
Do not allow bypass:     [x] (admins MUST also pass status checks)
```

The last option (`Do not allow bypass` / `Include administrators`) is critical.
Without it, admins can merge bypassing the status check.

**Implementation**: Add a `GET /api/status/branch-protection` endpoint that fetches
the current branch protection config and warns if `Sentinel Authorization` is not
a required check.

### Layer 2: Detection (Unauthorized Merge Monitoring)

Add a background monitor that periodically checks GitHub for merges to `main` and
compares them against Oracle's authorized list. Any merge that happened without
Oracle authorization triggers an alert.

**Implementation**:
1. Poll `GET /repos/:owner/:repo/commits?sha=main&per_page=10` every 60s
2. For each commit, check if it's a merge commit
3. Check Oracle DB for matching authorization
4. If unauthorized, log to audit + show warning on dashboard

### Layer 3: Response (Automated Lockdown)

If an unauthorized merge is detected:
1. Automatically activate lockdown (prevent further Oracle authorizations)
2. Log forensic evidence (commit SHA, timestamp, committer)
3. Display prominent warning on Oracle dashboard
4. Optionally: revert the merge via GitHub API (destructive — opt-in)

### Layer 4: Recovery

After account compromise:
1. Rotate ALL GitHub credentials (PAT, SSH keys, deploy keys)
2. Review GitHub audit log for unauthorized actions
3. Reset branch protection rules
4. Revoke compromised sessions via GitHub
5. Rotate Oracle encryption key
6. Re-enroll all devices

---

## Product Adaptations

### 1. Branch Protection Verification (MVP)

Add an endpoint + dashboard warning if branch protection is misconfigured.

```
GET /api/status/branch-protection
→ { enabled: true, requiresSentinelCheck: true, includesAdmins: false, warnings: [...] }
```

### 2. Unauthorized Merge Detection

Add a monitor that compares GitHub merge commits against Oracle's authorization log.

**New table**: `monitored_merges`
```
commit_sha TEXT PRIMARY KEY
pr_number INTEGER
authorized INTEGER DEFAULT 0  -- 1 = authorized via Oracle
detected_at INTEGER
```

**New dashboard section**: Alerts showing unauthorized merges.

### 3. Required Status Check Enforcement

The Oracle should set a commit status on EVERY PR, even if not yet authorized.
Branch protection should REQUIRE this status check.

Already implemented: `setCommitStatus(pr.sha, 'pending', 'Awaiting physical authorization')`

### 4. GitHub Audit Log Integration

Use GitHub's audit log API to cross-reference Oracle events with GitHub events.
This provides forensic evidence in case of dispute.

### 5. Approval Delay (future)

Time-based delay before merge execution gives time to detect and respond to
compromised authorizations.

---

## Summary

| Vector | Primary Defense | Oracle Enhancement |
|--------|----------------|-------------------|
| Credential theft | Branch protection (include admins) | Detection monitor |
| PAT leak | Fine-grained PAT, minimal scope | Alert on unauthorized merge |
| GitHub App compromise | Private key protection | App permission audit |
| Insider threat | Branch protection, org policies | Forensic audit trail |

The Oracle cannot prevent a GitHub admin from merging. What it can do is:
1. **Ensure the admin must actively bypass protection** (not just merge freely)
2. **Detect and alert** when an unauthorized merge happens
3. **Provide forensic evidence** after the fact

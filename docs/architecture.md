# Sentinel Oracle Architecture

## System Overview

Sentinel Oracle is a physically isolated merge authorization server for GitHub pull requests. Merge authority resides on a dedicated device (Raspberry Pi, NUC, mini PC, or Android phone) on the local network. The workstation that develops code never holds the credentials to merge it.

The system implements a three-device trust model connected via a zero-trust mesh network (Tailscale or WireGuard).

## Device Topology

### Device 1: Workstation (untrusted)

The developer's daily machine. Runs the IDE, browser, node_modules, and third-party extensions. Polls the oracle dashboard via HTTPS over Tailscale. Displays merge authorization requests (QR codes) and their status.

The workstation never holds GitHub credentials with merge scope. The oracle dashboard is read-only: no API endpoint on the oracle server accepts merge commands from the workstation.

### Device 2: Oracle Server (trusted authority)

A dedicated physical device running the sentinel-oracle server. Responsibilities:
- Polls GitHub for open PRs that have passed CI
- Generates HMAC-SHA256 signed challenges with 45-second TTL
- Verifies WebAuthn assertions against stored credentials
- Executes merge operations via the GitHub API
- Exposes an HTTPS dashboard bound to the Tailscale interface only

No ports are open to the public internet.

### Device 3: Phone (identity proof)

The operator's personal smartphone. Registers a WebAuthn passkey (platform authenticator, biometric-bound) with the oracle server.

The phone never interacts with GitHub directly. It only communicates with the oracle server via WebAuthn assertions.

## Authorization Protocol

### Challenge-Response Flow

1. Workstation opens the oracle dashboard
2. Oracle polls GitHub for open PRs that have passed CI checks
3. Oracle generates an HMAC-SHA256 challenge bound to a specific PR number (45-second TTL, one-time use)
4. Challenge stored in SQLite as a pending authorization
5. QR payload returned to the workstation dashboard
6. Phone scans QR code, biometric verification unlocks the passkey
7. Phone signs the assertion with the passkey private key
8. Assertion POSTed to the oracle server
9. Oracle verifies HMAC signature (constant-time comparison)
10. Oracle verifies WebAuthn assertion against stored credential
11. Oracle verifies PR number matches the challenge
12. Challenge marked as consumed (atomic SQLite write)
13. Oracle calls the GitHub merge API with the stored credential

### Cryptographic components

- HMAC-SHA256: Challenge signing (server-side secret seed, 256-bit)
- WebAuthn (FIDO2 CTAP2): Passkey-based authentication (platform authenticator)
- SHA-256: Challenge token integrity, scan dedup hash
- AES-256-GCM: Database field encryption (encryption key stored in `.encryption_key`)

## Module Architecture

### Source structure

```
src/
├── index.ts                 Entry point, CLI arg parsing, startup orchestration
├── server.ts                Express app factory, all API routes
├── config.ts                Configuration loading (env, file, defaults)
├── startup.ts               Startup banner, setup mode detection
│
├── auth/
│   ├── webauthn.ts          WebAuthn registration and assertion (FIDO2 CTAP2)
│   └── challenge.ts         QR challenge creation and verification
│
├── crypto/
│   ├── signing.ts           HMAC-SHA256 challenge signing
│   └── password.ts          Argon2-style password hashing and verification
│
├── github/
│   ├── client.ts            GitHub API client (PRs, merge, checks, files)
│   ├── monitor.ts           PR polling service (interval-based)
│   └── auth.ts              GitHub App authentication (JWT + installation token)
│
├── queue/
│   └── authorization.ts     Authorization queue management, challenge lifecycle
│
├── middleware/
│   ├── security.ts          Security headers (CSP, HSTS), CORS block, audit logger, CSRF
│   ├── session.ts           Session management (cookie-based, WebAuthn-bound)
│   └── rateLimit.ts         Rate limiting (auth, API)
│
├── storage/
│   ├── database.ts          SQLite database layer (schema, migrations, CRUD)
│   └── encryption.ts        AES-256-GCM field-level encryption
│
├── inventory/
│   └── tokens.ts            Token inventory scanner (GitHub API + repo scan)
│
└── scanner/
    ├── index.ts             Scan orchestrator (rules + intel)
    ├── rules.ts             Security rules engine (secrets, tokens, workflows)
    │
    └── intel/
        ├── index.ts         Intel orchestrator (runIntelAnalysis)
        ├── types.ts         All shared types (IntelReport, CapabilitySnapshot, etc.)
        │
        ├── capabilities.ts  CapabilityIntel: filesystem, network, shell, dynamic code, database, crypto
        ├── endpoints.ts     EndpointIntel: URLs, IPs, domains
        ├── services.ts      ServiceIntel: SDK integrations (Stripe, AWS, OpenAI, etc.)
        ├── permissions.ts   PermissionIntel: workflow permission changes
        ├── dependencies.ts  DependencyIntel: npm/Python/Go/Rust dep changes
        ├── secrets.ts       SecretSurfaceIntel: env var exposure
        ├── trust.ts         TrustBoundaryIntel: data flow across trust boundaries
        ├── crypto.ts        CryptoIntel: algorithm changes, key length changes
        ├── auth.ts          AuthIntel: new routes, middleware removal
        ├── infrastructure.ts InfrastructureIntel: Docker, K8s, Terraform changes
        ├── deep-dependency.ts DependencyDelta: EXPERIMENTAL tarball diff
        ├── workflow-intelligence.ts WorkflowIntel: CI baselines, evasion, campaign detection
        ├── trust-drift.ts   TrustDriftIntel: collaborators, secrets, runners, apps, permissions
        ├── security-dna.ts  Security DNA: capability aggregator (CapabilitySnapshot)
        └── ci-policy.ts     CI policy parser and enforcement
```

### Module dependency graph

```
PR Files
  ├──> rules.ts (syntactic scan: secrets, tokens, workflow patterns)
  │
  └──> Intel Analysis (semantic scan)
        ├── capabilities.ts     (patterns → capability categories)
        ├── endpoints.ts        (URLs/IPs → external surface)
        ├── services.ts         (SDK imports → service integrations)
        ├── permissions.ts      (YAML → permission changes)
        ├── dependencies.ts     (manifests → dependency changes)
        ├── secrets.ts          (env access → secret exposure)
        ├── trust.ts            (data flow → trust boundaries)
        ├── crypto.ts           (crypto params → weakness detection)
        ├── auth.ts             (routes/middleware → auth gaps)
        ├── infrastructure.ts   (config → infra drift)
        ├── deep-dependency.ts  (tarball → EXPERIMENTAL dep delta)
        ├── workflow-intelligence.ts (CI telemetry → anomalies)
        └── trust-drift.ts      (org changes → trust erosion)
              │
              ▼
        security-dna.ts  ←  capability aggregator (observes, does not detect)
```

## Data Flow

### Scan Pipeline

```
GitHub PR webhook / manual trigger
  │
  ▼
GitHub API: PR diff (files + patches)
  │
  ▼
runRules()         → Finding[]
runIntelAnalysis() → IntelReport
  │
  ▼
ScanResult (riskScore + findings + intel)
  │
  ▼
Database (scan_results)
  │
  ▼
buildCapabilitySnapshot(IntelReport) → CapabilitySnapshot
  │
  ▼
Database (capability_snapshots)
```

### Security DNA Flow

```
IntelReport
  │
  ▼
buildCapabilitySnapshot()
  │ reads: report.capabilities, .endpoints, .services, .trustDrift, .workflowIntel
  │ never reads raw files — only pre-computed intel
  │
  ▼
CapabilitySnapshot (14 capability counts + totalRiskScore)
  │
  ▼
GET /api/dna
  │
  ▼
buildDNAReport(current, history) → { current, history, changes, summary }
  │
  ▼
Frontend (capability bars + drift indicators)
```

## Database Schema

### Tables

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `pending_prs` | PR queue | pr_number, owner, repo, sha, ci_status, auth_status |
| `auth_devices` | Registered WebAuthn passkeys | credential_id, public_key, counter |
| `challenges` | Pending authorization challenges | id, pr_number, type, expires_at, used |
| `sessions` | Web session store | id, credential_id, csrf_token |
| `audit_log` | Immutable audit trail | timestamp, action, pr_number, detail |
| `config` | Key-value configuration store | key, value |
| `scan_results` | Cached scan outputs | pr_number, scan_hash, risk_score, findings_json, intel_json |
| `pr_files` | Per-PR file metadata | pr_number, filename, status, size_bytes |
| `workflow_times` | CI timing telemetry | filename, sha, check_name, duration_ms |
| `workflow_steps` | Step-level CI telemetry | job_name, step_name, duration_ms |
| `workflow_fingerprints` | CI fingerprint history | pr_number, sha, fingerprint_hash, job_structure_json |
| `ci_policy` | CI integrity policy store | repo, policy_json |
| `capability_snapshots` | Security DNA history | owner, repo, pr_number, snapshot_json |
| `token_inventory` | Token lifecycle tracking | token_type, name, fingerprint, risk_score |

## Key Design Decisions

### Physical separation

Merge credentials never reside on the development workstation. The oracle server is a separate physical device on the local network. This prevents workstation compromise (npm RCE, VS Code extension exploit, phishing) from granting merge authority.

### No public internet exposure

The oracle server binds to the Tailscale/WireGuard interface only. No ports are open to the public internet. The GitHub API is accessed outbound only.

### WebAuthn as sole identity proof

No passwords for merge authorization. The passkey is biometric-bound and cannot be exfiltrated by phishing or malware on the workstation.

### Read-only dashboard

The web interface has zero mutating endpoints accessible from the workstation. Merge authorization requires cryptographic proof from the phone.

### Security DNA as aggregator

DNA describes capabilities, not risk. It reads from existing intel modules and never analyzes raw files. This prevents duplicate processing and keeps the DNA layer lightweight.

### Test classification

Tests are organized by intent, not by module:
- `regression/` — must-pass tests (CI fails on failure)
- `evasion/` — documented bypasses (PASS = no-detection expected)
- `red-team/` — adversarial scenarios (PASS = detection verified)
- `integration/` — multi-layer tests (HTTP, DB, WebAuthn)

## Limitations

- Single-repo deployment per oracle instance
- No high-availability or failover configuration
- Merge conflicts must be resolved on the workstation before authorization
- Dependency deep scan is EXPERIMENTAL (tarball diff only, no semantic analysis)
- Database not encrypted at rest (only specific fields use AES-256-GCM)

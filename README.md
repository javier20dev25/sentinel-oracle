# Sentinel Oracle

Physically isolated merge authorization server for GitHub pull requests.
Merge authority resides on a separate device -- Raspberry Pi, NUC, mini PC,
or an old Android phone -- on the local network. The workstation that
develops code never holds the credentials to merge it.

This is not a replacement for GitHub branch protection rules. Oracle
operates as an additional enforcement layer. Repository administrators with
direct push or bypass permissions remain a valid threat path independent of
Oracle's controls.

---

## Misión / Visión

**Misión**: Separar físicamente la autoridad de merge del entorno de
desarrollo. Sentinel Oracle garantiza que ninguna estación de trabajo
comprometida —por malware, extensiones maliciosas, npm supply chain attacks
o phishing— pueda fusionar código a producción sin autorización biométrica
desde un dispositivo independiente.

El merge no es una operación de CI. Es un acto de autoridad que debe
requerir presencia física y consentimiento explícito.

**Visión**: Un ecosistema donde el ciclo de vida del código tenga tres
roles irreducibles: el desarrollador escribe y prueba, la CI verifica
calidad, y un dispositivo físico aislado —el Oracle— concede el merge.
Ningún ataque que comprometa solo un eslabón puede completar un merge
malicioso.

**Qué NO es**: No es un linter, ni un reemplazo de branch protection, ni
un code review tool, ni un CI/CD pipeline. Sentinel Oracle es una
**capa de autorización** que cierra el último vector de ataque antes de
producción: la workstation comprometida con credenciales de merge.

---

Two authentication modes are supported: Personal Access Token (PAT) and GitHub App (recommended). See [GITHUB_APP_SETUP.md](./GITHUB_APP_SETUP.md) for detailed GitHub App setup instructions.

---

## Documentation

Full architecture, API reference, and operational guide are in the `docs/` directory:

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | System architecture, module dependency graph, data flow, database schema |
| [docs/api.md](docs/api.md) | Complete API reference with request/response examples |
| [docs/guide.md](docs/guide.md) | Operational guide: installation, configuration, CLI reference, troubleshooting, AI setup |
| [docs/security-dna.md](docs/security-dna.md) | Security DNA aggregator: design, data flow, validation results |

---

## Quick Start (Global CLI)

```bash
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install -g .
sentinel-oracle
```

After cloning and installing globally, the `sentinel-oracle` command is available
from anywhere. The server starts and prints the dashboard URL in the terminal.

### Setup Checklist (antes de empezar)

- [ ] Tailscale instalado en los 3 dispositivos (servidor, workstation, telefono)
- [ ] Los 3 dispositivos conectados al mismo tailnet (`tailscale status`)
- [ ] Node.js >= 20 en el servidor Oracle
- [ ] GitHub App creada y instalada en tu repositorio

### First-Time Setup (paso a paso)

**1. Instalar Tailscale** (si no lo tiene):

```bash
# En el servidor Oracle, workstation, y telefono:
# Descargar desde https://tailscale.com/download
tailscale up
tailscale status   # Verificar que los 3 dispositivos aparecen
```

**2. Crear GitHub App** (ver [GITHUB_APP_SETUP.md](GITHUB_APP_SETUP.md) para detalles):

- Vaya a `github.com/settings/apps/new`
- Nombre: `sentinel-oracle-tu-org`
- Permisos: Pull requests (Read & write), Checks (Read & write), Contents (Read)
- Genere private key → descarga archivo `.pem`

**3. Instalar la app en tu repositorio:**

- En la pagina de la app → sidebar **Install App** → **Install**
- Seleccione su repositorio → **Install**
- Click engranaje ⚙️ al lado del repo instalado
- **Anote el Installation ID** de la URL: `settings/installations/<NUMERO>`

**4. Iniciar el servidor:**

```bash
sentinel-oracle
```

**5. Configurar via web:**

Abra `https://{IP_TAILSCALE}:3443/setup` y siga los pasos:
1. Owner + Repository
2. App ID + Installation ID + Private Key (pegue el contenido del .pem o la ruta)
3. Opciones de scan
4. Test connection → Save

**6. Registrar el telefono:**

En el telefono (con Tailscale conectado), abra la misma URL del dashboard.
Click **Register Device** → biometria.

Listo. Los PRs abiertos apareceran en la cola. Para autorizar un merge:
click Authorize → escanear QR con el telefono → biometria → merge.

---

## CLI Reference

```bash
sentinel-oracle                    Start the server (default)
sentinel-oracle start              Start the server
sentinel-oracle scan               Run a one-time security scan on the configured repository
sentinel-oracle --version, -v      Print version
sentinel-oracle --help, -h         Print help
```

---

## Security Scanner

Sentinel Oracle includes a multi-layered security scanner that analyzes PR diffs across 14 intel modules. Scans are deduplicated by SHA-256 of PR sha + file metadata.

### Intel Modules

| Module | Analyzes |
|--------|----------|
| Capabilities | Filesystem, network, shell, dynamic code, database, crypto operations |
| Endpoints | URLs, IP addresses, external domains |
| Services | SDK integrations (Stripe, AWS, OpenAI, etc.) |
| Permissions | Workflow permission changes |
| Dependencies | npm, Python, Go, Rust dependency changes (EXPERIMENTAL: tarball diff) |
| Secrets | Environment variable exposure, hardcoded credentials |
| Trust | Data flow across trust boundaries |
| Crypto | Algorithm changes, key length changes |
| Auth | New routes, authentication middleware removal |
| Infrastructure | Docker, Kubernetes, Terraform changes |
| CI Integrity | Step redistribution, cache camouflage, fingerprint churn, synthetic telemetry, evasion signals, campaign detection |
| Trust Drift | New collaborators, GitHub Apps, secrets, runners, environments, branch protection removals, permission escalations |
| Security DNA | Capability fingerprint aggregator (14 dimensions) |

### Auto Scan

When enabled in Settings (toggle switch), all PRs are scanned automatically on queue refresh. Manual SCAN button appears when auto-scan is OFF. Scans are cached per PR SHA and never re-executed for identical code.

### Security Categories

| Severity | Score Range | Examples |
|----------|-------------|---------|
| Critical | >=10 | Secrets, credential leaks, auth bypass |
| High | >=7 | Permission escalation, crypto weakness, CI anomalies |
| Medium | >=4 | New capabilities, external endpoints, campaign signals |
| Low | >=1 | Info-level findings, new dependencies |
| None | 0 | No issues |

---

## AI PR Intelligence

Sentinel Oracle includes an AI-powered PR analysis engine that generates structured summaries, identifies architectural changes, flags security-relevant diffs, detects instruction manipulation attempts, and assigns review priorities.

### Backends

Two AI backends are supported:

| Backend | Setup | Performance |
|---------|-------|-------------|
| **Ollama** (recommended) | Install [Ollama](https://ollama.com), pull a model (`ollama pull qwen2.5:1.5b`) | ~2-10s per analysis |
| **GGUF** (local) | Download a `.gguf` file to `~/.sentinel/models/` | ~5-30s per analysis (via node-llama-cpp) |

The server auto-detects available models at `/api/ai/models`. When both backends are present, Ollama is preferred.

### Model Selector

A dropdown in Settings > AI Intelligence lists all detected models. Select one explicitly, or leave it on `auto` for automatic detection.

### Features

- **PR Summarization**: Structured executive summary with architectural changes, dependencies, and reviewer notes
- **Security-Relevant Change Detection**: Flags files touching auth, secrets, permissions, and encryption
- **Instruction Manipulation Detection**: Scans diffs for prompt injection, hidden instructions, role redefinition, suppression attempts, and config manipulation
- **Review Priority Assignment**: Computes `reviewPriority` (low/critical), `impactLevel`, and `estimatedComplexity` from file metadata and LLM output
- **Output Sanitization**: All LLM output is sanitized server-side — markdown (bold, code blocks, links, HTML tags) is stripped before storage

### Health Check

`GET /api/ai/status` returns model availability, health status, and backend type. The health check verifies:
- For Ollama: runs `ollama show <model>`
- For GGUF: checks file existence on disk

### Auto-Analyze

When enabled in Settings, all PRs are automatically analyzed after scanning. Analyses are cached per PR SHA — identical PRs never re-trigger the LLM.

### API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/ai/status` | None | AI backend status, health, available models |
| GET | `/api/ai/models` | None | List detected models (Ollama + GGUF) |
| POST | `/api/prs/:number/ai-analyze` | Cookie | Run AI analysis on a specific PR |

---

## CI Integrity Engine

The CI Integrity engine monitors GitHub Actions workflows for anomalous behavior using three comparison windows (7-day, 30-day, full history) with MAD-based z-score computation.

### Detection Modules

- **Step Redistribution**: Detects workflow steps moving between jobs between commits
- **Cache Camouflage**: Detects cache key manipulation across commits
- **Fingerprint Churn**: Detects CI job structure changes between commits
- **Synthetic Telemetry**: Detects fake workflow events injected into the API
- **Evasion Signals**: Detects YAML anchors, merge tags, template variables used to obfuscate workflow changes
- **Campaign Detection**: Cross-PR weighted scoring (exec=10, escalation=8, runner=8, secret=6, capability=2 capped at 20, domain=1 capped at 10, endpoint=1 capped at 10)

### Multi-window Baselines

Each check's baselines are computed independently for three windows:
- **All history**: No minimum sample requirement
- **30-day**: Requires >=3 samples
- **7-day**: Requires >=3 samples

An anomaly triggers when any window exceeds its z-score threshold (z>10=critical, z>5=high, else 10pts deduction). The worst z-score across all windows is used.

### Integrity Score

Starting from 100, deductions are applied per anomaly:
- Critical anomaly: -25 points
- High anomaly: -15 points
- Medium anomaly: -5 points
- Low anomaly: -1 point
- Z-score > 10: -40 points
- Z-score > 5: -20 points
- Z-score else: -10 points
- Missing sensor data: -10 points

### Trusted Baselines

Only PRs explicitly marked with `trusted: true` train the baseline model. Records without explicit trust are excluded when `trustedOnly` is enabled.

---

## Trust Drift Detection

Trust Drift monitors the GitHub organization for changes that weaken the repository's security posture. Seven signals are tracked:

| Signal | Weight | What it detects |
|--------|--------|-----------------|
| Collaborator | 2 | New users added with write/admin access |
| GitHub App | 3 | New GitHub Apps installed on the repo |
| Secret | 3 | New secrets added to environments |
| Runner | 3 | New self-hosted runners registered |
| Environment | 2 | New environments created |
| Branch Protection | 4 | Removal of branch protection rules |
| Permission Escalation | 4 | Escalated permissions in YAML workflow files |

**Thresholds**: >=10 = critical, >=6 = high, >=3 = medium

---

## Security DNA

Security DNA is a capability aggregator that reads from existing IntelReport modules to produce a repository capability fingerprint. It is NOT a new detector.

### 14 Capability Dimensions

| Capability | Description |
|------------|-------------|
| filesystem | File read/write operations |
| network | Network requests, HTTP calls |
| shell | Command execution, subprocesses |
| dynamicCode | Eval, code generation |
| database | Database queries, migrations |
| crypto | Cryptography operations |
| secrets | Secret/hardcoded credential usage |
| runners | CI runner configuration changes |
| environments | Environment variable manipulation |
| collaborators | New collaborator additions |
| permissionEscalations | Workflow permission changes |
| newDomains | New external domains |
| newIntegrations | New service integrations |
| workflowCount | Number of workflow files |

### API

`GET /api/dna` -- returns `{ current, history, changes, summary, snapshotCount }`

### Storage

Snapshots are stored in the `capability_snapshots` SQLite table, auto-generated after every scan.

### Validation

Validated against 5 real open-source repositories (Kubernetes, Next.js, Home Assistant, OpenTelemetry Collector, Open WebUI). Produces differentiated fingerprints correlating with each project's technical domain.

---

## Test Classification

Tests are organized by intention:

| Directory | Intent | CI Behavior |
|-----------|--------|-------------|
| `test/regression/` | Must-pass tests verifying core functionality | FAIL on failure |
| `test/evasion/` | Documented bypasses (attacker perspective) | PASS = no detection expected |
| `test/red-team/` | Adversarial attack scenarios | PASS = detection confirmed |
| `test/integration/` | Multi-layer integration (HTTP, DB, WebAuthn) | FAIL on failure |

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Architecture](#architecture)
- [Authorization Flow](#authorization-flow)
- [Cryptographic Protocol](#cryptographic-protocol)
- [Threat Model](#threat-model)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Configuration Reference](#configuration-reference)
- [GitHub App Setup](#github-app-setup)
- [API Endpoints](#api-endpoints)
- [Database Schema](#database-schema)
- [Network Architecture](#network-architecture)
- [Tailscale Integration](#tailscale-integration)
- [Deployment](#deployment)
  - [Linux (Raspberry Pi / Debian / Ubuntu)](#linux-raspberry-pi--debian--ubuntu)
  - [Windows](#windows)
  - [macOS](#macos)
  - [Android / Termux](#android--termux)
- [Security Considerations](#security-considerations)
- [Known Limitations](#known-limitations)
- [Verification Checklist](#verification-checklist)
- [Environment and File Reference](#environment-and-file-reference)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Problem Statement

Conventional CI/CD pipelines conflate development capability with deployment
authority. The same workstation used to write, build, and test code also holds
the credentials (SSH keys, API tokens, GitHub personal access tokens) to merge
pull requests and deploy to production.

This creates a single point of compromise:

- A malicious npm package achieves remote code execution on the workstation.
- A compromised VS Code extension exfiltrates a GitHub PAT from the local
  credential store.
- A phishing attack harvests a session token with merge scope.

In all cases, the attacker gains merge authority without additional
authentication. Sentinel Oracle eliminates this vector by enforcing physical
separation: the workstation never holds credentials with merge scope, the
oracle server executes merges only after cryptographic verification, and the
phone provides ephemeral biometric consent for each individual pull request.

---

## Architecture

Sentinel Oracle implements a three-device trust model with three physically
independent devices connected via a zero-trust mesh network (Tailscale /
WireGuard).

### Device 1: Workstation (untrusted)

The developer's daily machine. Runs the IDE, browser, node_modules, and
third-party extensions. Polls the oracle dashboard via HTTPS over Tailscale.
Displays merge authorization requests (QR codes) and their status.

The workstation never holds GitHub credentials with merge scope. The oracle
dashboard is read-only: no API endpoint on the oracle server accepts merge
commands from the workstation.

### Device 2: Oracle Server (trusted authority)

A dedicated physical device (Raspberry Pi 2W+, Intel NUC, thin client, old
Android phone running Termux, or any Linux server) running the
sentinel-oracle server.

Responsibilities:

- Polls GitHub for open PRs that have passed CI.
- Generates HMAC-SHA256 signed challenges with 45-second TTL.
- Verifies WebAuthn assertions against stored credentials.
- Executes merge operations via the GitHub API.
- Exposes an HTTPS dashboard bound to the Tailscale interface only.

No ports are open to the public internet.

### Device 3: Phone (identity proof)

The operator's personal smartphone. Registers a WebAuthn passkey (platform
authenticator, biometric-bound) with the oracle server.

When a merge requires authorization:

1. The phone scans a QR code displayed on the workstation dashboard.
2. Biometric verification (Face ID, fingerprint) unlocks the passkey.
3. The phone sends a cryptographically signed assertion back to the oracle
   server.

The assertion includes the challenge, the PR number, and a timestamp, all
signed by the passkey's private key. The phone never interacts with GitHub
directly.

---

## Authorization Flow

### Phase 1: Challenge Generation

1. Workstation opens the oracle dashboard in the browser.
2. Oracle polls GitHub for open PRs that have passed CI checks.
3. Oracle generates an HMAC-SHA256 challenge bound to the specific PR number
   (45-second TTL, one-time use).
4. Oracle stores the challenge in SQLite.
5. Oracle returns a QR payload to the workstation dashboard.

### Phase 2: Phone Authentication

6. Workstation displays the QR code on screen.
7. Phone scans the QR code via the device camera.
8. Phone parses the challenge payload (challenge ID, host, signature).
9. WebAuthn biometric prompt appears on the phone.
10. Phone signs the assertion with the passkey private key.
11. Phone POSTs the signed assertion to `/api/authorize` on the oracle server.

### Phase 3: Server Verification

12. Oracle verifies the HMAC signature on the challenge (constant-time).
13. Oracle verifies the WebAuthn assertion against the stored credential.
14. Oracle verifies the PR number in the assertion matches the challenge.
15. Oracle marks the challenge as consumed (atomic SQLite write).

### Phase 4: Merge Execution

16. Oracle calls the GitHub merge API with the stored PAT.
17. Oracle returns the merge result to the workstation dashboard.

Total round-trip: approximately 10-20 seconds (including human interaction).
Critical window (scan to authorize): 40 seconds (WebAuthn timeout).
Challenge TTL: 45 seconds.

---

## Cryptographic Protocol

All cryptographic operations use the Web Crypto API (`crypto.subtle`) on both
the server and client sides.

### HMAC Challenge Signing

```
HMAC_KEY = HKDF-SHA256(master_secret, salt="sentinel-oracle-v1", info=server_fingerprint)

function GenerateChallenge(prNumber, sessionId):
  nonce = crypto.getRandomValues(new Uint8Array(32))
  payload = JSON.stringify({
    pr: prNumber,
    nonce: hex(nonce),
    sessionId,
    ttl: Date.now() + 45000
  })
  signature = HMAC-SHA256(HMAC_KEY, payload)
  return { payload, signature }
```

The HMAC key is derived once at server startup via HKDF from the configured
master secret (environment variable `ORACLE_MASTER_SECRET`, minimum 32 bytes).

Each challenge is bound to exactly one PR number. The nonce ensures
uniqueness. The TTL limits the replay window. The server rejects expired
challenges.

### QR Encoding

```
challengeId = SHA256(payload + signature).slice(0, 16)
qrPayload = JSON.stringify({
  v: 1,
  cid: challengeId,
  sig: hex(signature),
  host: "https://100.x.y.z:3443"
})
```

The QR is displayed once and never re-displayed for the same challenge. The
host field tells the phone which Tailscale IP to send the assertion to.

### WebAuthn Assertion

The WebAuthn challenge field is set to `challengeId` (derived from the
HMAC-signed challenge payload). This creates a cryptographic chain: the
phone's assertion cannot be forged without both the HMAC key (held only by the
oracle server) and the WebAuthn private key (held only by the phone's secure
enclave).

```javascript
assertion = await navigator.credentials.get({
  publicKey: {
    challenge: new Uint8Array(challengeId),
    allowCredentials: [{ id: credentialId, type: "public-key" }],
    userVerification: "required",
    timeout: 40000
  }
})
```

### Merge Execution Verification

The server performs the following checks in order before executing a merge:

1. Challenge lookup by `challengeId` -- rejects if not found.
2. Challenge consumption check -- rejects if already used.
3. Challenge expiry check -- rejects if TTL exceeded.
4. HMAC signature verification -- constant-time comparison.
5. WebAuthn assertion verification -- ECDSA P-256 signature, RP ID hash,
   origin, user presence, signature counter.
6. PR number binding verification -- the PR in the challenge payload must
   match the PR in the request.
7. Challenge consumption (atomic DB write) -- single-use gating.
8. GitHub merge API call via Octokit -- squash merge method.

Steps 1-6 are designed such that any single failure aborts the operation with
no state mutation. Challenge consumption (step 7) happens before the GitHub
API call to prevent race conditions on retry.

---

## CSRF Protection

Every mutating API endpoint (POST, PUT, DELETE) requires a per-session CSRF
token. The token is generated at session creation and returned via
`GET /api/session/csrf-token`. Frontend requests must include the token in the
`X-CSRF-Token` header:

```http
POST /api/lockdown
Cookie: sentinel_session=<sid>
X-CSRF-Token: <token>
Content-Type: application/json

{ "reAssertToken": "..." }
```

Without a valid CSRF token, the server returns 403.

## WebAuthn Re-assertion

Sensitive actions (lockdown, unlock, device revocation, PR rejection) require
fresh biometric confirmation via WebAuthn re-assertion in addition to the
session cookie and CSRF token.

The re-assertion flow:

1. Client calls `POST /api/auth/re-assert` with `{ action: "lockdown" }`
2. Server generates a WebAuthn assertion challenge and stores it in the config
   table
3. Client calls `navigator.credentials.get()` with the challenge
4. Client sends the assertion to `POST /api/auth/re-assert/complete`
5. Server verifies the assertion and returns a one-time `reAssertToken`
   (60-second TTL)
6. Client includes the `reAssertToken` in the sensitive action request body

This ensures that even with an active session, an attacker cannot lock down
the system, revoke devices, or reject PRs without physical access to a
registered device.

---

## Threat Model

### Attack Vector Analysis

| Vector | Risk | Controls | Residual Risk |
|--------|------|----------|---------------|
| Workstation RCE | Assets: dashboard session (read-only) | No merge credentials on workstation; dashboard is read-only | Attacker can display fake QR codes but cannot complete authorization without phone biometric |
| Phone theft | Assets: WebAuthn passkey private key | Passkey is biometric-bound; device PIN required after restart | Attacker with device unlock and live biometric could authorize merges within 45s window |
| Oracle physical theft | Assets: GitHub PAT, HMAC secret, credentials | Full-disk encryption; BIOS password; secure boot | Attacker with unlimited physical access and FDE passphrase can extract all secrets |
| Oracle remote compromise | Assets: all merge authority | Minimal OS; Tailscale ACLs; no writable endpoints without auth | Zero-day in Node.js or Tailscale daemon |
| Network MITM | Assets: challenge, assertion in transit | Tailscale WireGuard encryption; self-signed TLS; 45s TTL | Attacker on the tailnet node itself |
| Replay attack | Assets: re-use of captured challenge | Single-use (atomic DB); 45s TTL; PR binding | Zero |
| QR phishing | Assets: assertion to attacker server | User must verify PR number visually; host field in QR | User error |

### Emergency Lockdown

When lockdown is activated (via the dashboard or a physical button on the
oracle server), the server immediately:

1. Invalidates all pending challenges in the database.
2. Sets all open PRs to a blocked/failure commit status.
3. Rejects all new challenge generation requests.
4. Persists the lockdown flag to disk.

Lockdown persists across server restarts. Deactivation requires physical
access to the oracle server.

---

## Installation

```bash
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install
npm run build
```

### Requirements

- Node.js >= 20
- Tailscale (recommended) or direct LAN connectivity
- WebAuthn-compatible phone browser (Chrome, Safari, Edge)
- GitHub Personal Access Token with `pull-requests: write` scope

### Supported Devices

| Device | Power | Notes |
|--------|-------|-------|
| Raspberry Pi 2W+ | ~5W | Recommended. Always-on, low power, silent. |
| Intel NUC / thin client | ~10-15W | x86 compatible, more CPU for larger repos. |
| Old Android phone | ~2-5W | Termux + Node.js. Built-in UPS (battery). Zero e-waste. |
| Linux VPS | Varies | Requires Tailscale. Only outbound to GitHub API. |
| Windows PC | ~50-100W | NSSM for background service. |
| macOS | ~10-30W | LaunchAgent for auto-start. |

---

## Quick Start

```bash
# Configure environment
export GITHUB_TOKEN="github_pat_..."
export ORACLE_MASTER_SECRET="$(openssl rand -hex 32)"

# Create config
mkdir -p ~/.sentinel-oracle
# Edit ~/.sentinel-oracle/config.json with your repository details

# Start the server
npm start
```

The server listens on `https://<tailscale-ip>:3443`. Open the dashboard in
your phone browser via Tailscale, register a passkey, and authorize merges
with your biometric.

### Setup Script

```bash
npm run setup
```

The setup script walks through each dependency:

1. Node.js version check (requires >= 20).
2. TLS certificate generation (self-signed if missing).
3. Tailscale detection and optional configuration.
4. Config file validation at `~/.sentinel-oracle/config.json`.

---

## Configuration

Create `~/.sentinel-oracle/config.json`:

```json
{
  "githubToken": "github_pat_...",
  "repoOwner": "your-org",
  "repoName": "your-repo",
  "bindAddress": "100.x.y.z",
  "rpId": "100.x.y.z",
  "serverOrigin": "https://100.x.y.z:3443",
  "port": 3443,
  "tlsCert": "./cert.pem",
  "tlsKey": "./key.pem",
  "locked": false
}
```

Alternatively, use environment variables for secrets:

```
export GITHUB_TOKEN="github_pat_..."
export ORACLE_MASTER_SECRET="$(openssl rand -hex 32)"
```

---

## Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | number | `3443` | HTTPS listen port. Use >= 1024 on Linux to avoid root. |
| `host` | string | `"0.0.0.0"` | Bind address (all interfaces). Change to specific IP for strict binding. |
| `bindAddress` | string | auto | IP for QR URLs and WebAuthn origin. Auto-detection: Tailscale Funnel URL > Tailscale IP (100.x.x.x) > first non-loopback IPv4. |
| `dataDir` | string | `~/.sentinel-oracle` | Directory for SQLite database, encryption key, TLS certs, config. |
| `githubToken` | string | `""` | GitHub PAT with pull-requests:write scope. Required. |
| `githubOwner` | string | `""` | GitHub organization or user that owns the target repository. |
| `githubRepo` | string | `""` | Repository name (without owner prefix). |
| `githubStatusContext` | string | `"Sentinel Authorization"` | Commit status context name. Must match the required status check in branch protection. |
| `serverOrigin` | string | auto | Origin URL for WebAuthn Relying Party. Auto-assembled from bindAddress + port. |
| `rpId` | string | auto | WebAuthn Relying Party ID (domain without port). Auto-assembled from bindAddress. |
| `challengeTtlMs` | number | `45000` | QR challenge TTL in milliseconds. |
| `rateLimitAuth` | number | `5` | Maximum authorization attempts per rateLimitWindowMs. |
| `rateLimitWindowMs` | number | `60000` | Rate limit window in milliseconds. |
| `encryptionKey` | Buffer | auto | AES-256 key for HMAC signing key derivation. Generated once. DO NOT SET IN CONFIG. |
| `approveReasonRequired` | boolean | `false` | If true, /confirm requires non-empty "reason" field. |
| `locked` | boolean | `false` | Emergency lockdown. Persisted state. |
| `passwordHash` | string | `""` | SHA-256 hash of dashboard password. Empty = no password. |
| `enrollmentTokenTtlMs` | number | `120000` | First-time device enrollment token TTL. |
| `githubAppId` | string | `""` | GitHub App ID for JWT authentication |
| `githubInstallationId` | string | `""` | GitHub App installation ID |
| `githubPrivateKeyPath` | string | `""` | Path to GitHub App private key PEM file |
| `githubWebhookSecret` | string | `""` | Secret for verifying GitHub webhook payloads |

---

## GitHub App Setup

Sentinel Oracle supports two authentication modes for GitHub API access:

1. **Personal Access Token (PAT)** — The traditional approach. A fine-grained PAT with `pull-requests: write` scope is stored on the oracle server. Simple to set up but creates a long-lived credential.
2. **GitHub App (recommended)** — Installation tokens with 1-hour TTL, auto-refresh, and repository-scoped permissions. No long-lived credentials are stored on the oracle server.

### Why GitHub App?

| Aspect | PAT | GitHub App |
|--------|-----|------------|
| Token lifetime | Long-lived (user-managed rotation) | 1 hour TTL, auto-refreshed |
| Scope | User-scoped (all repos the user can access) | Repository-scoped (specific repos only) |
| Risk profile | High — token exfiltration grants wide access | Low — compromised token expires within 1 hour |
| Rotation | Manual, periodic | Automatic, every hour |

Using a GitHub App eliminates the risk of a long-lived PAT being exfiltrated from the oracle server. Even if an attacker gains access to the server, the installation token expires within 60 minutes and is scoped to a single repository.

See [GITHUB_APP_SETUP.md](./GITHUB_APP_SETUP.md) for complete setup instructions, including registering a GitHub App, installing it on your organization, generating a private key, and configuring the required environment variables.

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/status` | None | Server status, uptime, locked state, setup required |
| GET | `/api/session/check` | Cookie | Session validation. Returns `{ authenticated, deviceName }` |
| GET | `/api/session/csrf-token` | Cookie | Returns CSRF token for mutating requests |
| POST | `/api/session/logout` | Cookie | Destroy current session |
| POST | `/api/webauthn/register/begin` | Cookie | Start WebAuthn credential registration |
| POST | `/api/webauthn/register/complete` | Cookie | Complete WebAuthn credential registration |
| POST | `/api/webauthn/assert/begin` | None | Start WebAuthn assertion (login) |
| POST | `/api/webauthn/assert/complete` | None | Complete WebAuthn assertion (login) |
| POST | `/api/auth/re-assert` | Cookie | Generate re-assertion challenge for sensitive actions |
| POST | `/api/auth/re-assert/complete` | Cookie | Verify re-assertion, returns one-time token |
| GET | `/api/prs` | Cookie | List pending PRs (triggers poll) |
| GET | `/api/prs/history` | Cookie | List completed/authorized PRs |
| POST | `/api/prs/:number/authorize` | Cookie | Initiate authorization, returns QR challenge |
| POST | `/api/prs/:number/confirm` | Cookie | Confirm with WebAuthn assertion, executes merge |
| POST | `/api/prs/:number/reject` | Cookie+CSRF+RA | Reject authorization (needs re-assertion token) |
| POST | `/api/prs/:number/scan` | Cookie | Trigger SAST scan on PR files |
| GET | `/api/prs/:number/checks` | Cookie | Check run results for a PR |
| GET | `/api/prs/:number/file-history/:filename` | Cookie | File modification history + CI duration chart data |
| POST | `/api/lockdown` | Cookie+CSRF+RA | Emergency lockdown (needs re-assertion token) |
| POST | `/api/unlock` | Cookie+CSRF+RA | Deactivate lockdown (needs re-assertion token) |
| GET | `/api/devices` | Cookie | List registered WebAuthn credentials |
| POST | `/api/devices/:credentialId/revoke` | Cookie+CSRF+RA | Revoke a device (needs re-assertion token) |
| GET | `/api/audit` | Cookie | Authorization audit log |
| GET | `/api/metrics` | Cookie | Aggregated metrics and per-author stats |
| GET | `/api/status/branch-protection` | Cookie | Branch protection status for main |
| POST | `/api/admin/backfill-history` | Cookie | Backfill historical PR data for charts |
| GET | `/api/admin/backfill-status` | Cookie | Backfill progress (current/total/done) |
| POST | `/api/webhook/github` | HMAC | GitHub webhook receiver |
| GET | `/api/inventory/tokens` | Cookie | Token inventory listing |
| POST | `/api/inventory/tokens/scan` | Cookie | Scan repo for leaked tokens |
| GET | `/api/ai/status` | None | AI backend status, health, model info |
| GET | `/api/ai/models` | None | List detected AI models (Ollama + GGUF) |
| POST | `/api/prs/:number/ai-analyze` | Cookie | Run AI PR intelligence analysis |
| GET | `/api/prs/:number/scan-result` | Cookie | Cached SAST scan result for a PR |

**Auth key:** Cookie = `sentinel_session` cookie. CSRF = `X-CSRF-Token` header. RA = `reAssertToken` in request body.

### POST /api/prs

Request:
```json
{ "prNumber": 142 }
```

Response:
```json
{
  "challengeId": "uuid",
  "qrDataUrl": "data:image/png;base64,...",
  "prNumber": 142,
  "expiresAt": "2026-06-06T..."
}
```

### POST /api/prs/:number/confirm

Request:
```json
{
  "challengeId": "uuid",
  "credential": { "id": "...", "response": { ... }, "clientExtensionResults": {} },
  "challenge": "webauthn-server-challenge",
  "reason": "optional reason string"
}
```

Response:
```json
{
  "authorized": true,
  "prNumber": 142,
  "merged": true
}
```

### POST /api/lockdown

```json
{ "reason": "Compromised workstation reported" }
```

Rejects all pending challenges, sets all open PRs to failure commit status,
persists locked state to SQLite.

### GET /api/status/branch-protection

Returns current branch protection status for the main branch:

- Checks whether required status checks are configured.
- Verifies admin enforcement is enabled.
- Detects force push settings.
- Returns a JSON summary of each check and an overall pass/fail status.

### GET /api/prs/{number}/checks

Returns detailed check run results for a specific PR:

```json
{
  "prNumber": 142,
  "checks": [
    {
      "name": "CI / test (18.x)",
      "conclusion": "success",
      "status": "completed",
      "startedAt": "2026-06-10T10:00:00Z",
      "completedAt": "2026-06-10T10:02:30Z",
      "durationMs": 150000
    }
  ],
  "diff": {
    "filesChanged": 12,
    "additions": 45,
    "deletions": 8
  }
}
```

### GET /api/metrics

Returns aggregated metrics for audit and analysis:

```json
{
  "summary": {
    "total": 150,
    "pending": 3,
    "authorized": 120,
    "rejected": 20,
    "expired": 7
  },
  "mergeTimes": [
    {
      "prNumber": 142,
      "requestedAt": "2026-06-10T10:00:00Z",
      "authorizedAt": "2026-06-10T10:02:00Z",
      "approvedAt": "2026-06-10T10:02:30Z",
      "approvalWaitMs": 120000,
      "totalDurationMs": 150000
    }
  ],
  "perAuthor": [
    {
      "author": "javier20dev25",
      "mergedCount": 45,
      "rejectionCount": 5,
      "averageWaitMs": 95000
    }
  ]
}
```

### POST /api/webhook/github

GitHub webhook receiver. Accepts `pull_request` and `push` events.

Used for:
- Real-time PR notifications when new pull requests are opened or updated.
- Unauthorized merge detection — triggers alerts when merges bypass Oracle.

Requires `Content-Type: application/json` header.

If `githubWebhookSecret` is configured, Oracle verifies the `X-Hub-Signature-256` header to authenticate the webhook payload.

---

## Database Schema

SQLite database at `{dataDir}/oracle.db`. Three tables:

### challenges

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | UUID v4 challenge identifier |
| pr_number | INTEGER | Target PR number |
| signature | TEXT | HMAC-SHA256 signature |
| expires_at | INTEGER | Unix ms timestamp, challenge invalid after |
| consumed | INTEGER | 0 or 1. One-time consumption flag |
| created_at | TEXT | ISO 8601 timestamp |

### auth_devices

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| name | TEXT | Human-readable label (e.g., "Pixel 7") |
| credential_id | TEXT | WebAuthn credential ID (base64url, unique) |
| public_key | TEXT | COSE-encoded ECDSA P-256 public key |
| counter | INTEGER | WebAuthn signature counter |
| transports | TEXT | JSON array of authenticator transports |
| created_at | INTEGER | Unix ms registration timestamp |
| last_used_at | INTEGER | Nullable. Unix ms last authorization |

### sessions

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | UUID v4 session identifier |
| credential_id | TEXT | WebAuthn credential that created this session |
| device_name | TEXT | Human-readable device label |
| created_at | INTEGER | Unix ms creation timestamp |
| expires_at | INTEGER | Unix ms expiry (24h from creation) |
| last_used_at | INTEGER | Unix ms last activity (idle timeout 30min) |
| csrf_token | TEXT | Per-session CSRF token (32 byte hex) |
| user_agent | TEXT | Browser user agent at session creation |

### audit_log

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| timestamp | INTEGER | Unix ms event timestamp |
| action | TEXT | Event type: challenge_created, authorization_granted, authorization_rejected, merge_executed, merge_failed, lockdown_activated, lockdown_deactivated, device_registered, device_revoked, backfill, etc. |
| pr_number | INTEGER | Nullable. Target PR number |
| detail | TEXT | Free-text detail or JSON metadata |

### pending_prs

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| pr_number | INTEGER | Unique PR number |
| owner | TEXT | GitHub owner |
| repo | TEXT | GitHub repo |
| title | TEXT | PR title |
| author | TEXT | PR author login |
| sha | TEXT | HEAD commit SHA |
| ci_status | TEXT | CI pass/fail/pending |
| sentinel_status | TEXT | Sentinel scan result |
| auth_status | TEXT | pending/authorized/rejected/expired |
| created_at | INTEGER | Unix ms PR creation |
| authorized_at | INTEGER | Nullable. Unix ms authorization |
| device_name | TEXT | Device that authorized |
| check_run_id | INTEGER | GitHub check run ID |

### pr_files

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| pr_number | INTEGER | PR number |
| filename | TEXT | File path |
| sha | TEXT | Commit SHA |
| status | TEXT | added/modified/removed |
| additions | INTEGER | Lines added |
| deletions | INTEGER | Lines removed |
| auth_status | TEXT | pending/authorized/rejected |
| scanned_at | INTEGER | Unix ms scan timestamp |

### workflow_times

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| filename | TEXT | File path |
| sha | TEXT | Commit SHA |
| pr_number | INTEGER | PR number |
| check_name | TEXT | CI check name |
| duration_ms | INTEGER | Check duration in ms |
| scanned_at | INTEGER | Unix ms when fetched |

### token_inventory

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| token_type | TEXT | github_pat / github_app / github_oauth / generic / found_secret |
| name | TEXT | Token name/label |
| source | TEXT | github_api / repo_scan / manual |
| scopes | TEXT | Comma-separated scopes |
| fingerprint | TEXT | SHA256 fingerprint (never stores raw token) |
| first_seen_at | INTEGER | Unix ms discovery |
| last_seen_at | INTEGER | Nullable. Unix ms last verification |
| expires_at | INTEGER | Nullable. Unix ms token expiry |
| last_rotation | INTEGER | Nullable. Unix ms last rotation |
| risk_score | TEXT | low / medium / high / critical |
| notes | TEXT | Free-text notes |
| metadata | TEXT | JSON blob |

### config

| Column | Type | Description |
|--------|------|-------------|
| key | TEXT | Unique config key |
| value | TEXT | Config value |

---

## Network Architecture

### IP Auto-Detection Priority

Oracle uses three discovery methods in order:

1. **Tailscale Funnel** (highest priority): Reads `tailscale funnel status
   --json` for existing HTTPS proxy configurations. If a proxy targets
   Oracle's port, the MagicDNS hostname is used. Valid HTTPS from Let's
   Encrypt.

2. **Tailscale IP** (medium priority): Scans network interfaces for the
   Tailscale virtual adapter (100.64.0.0/10 range). Stable across reboots.
   Encrypted mesh connectivity.

3. **LAN IP** (fallback): First non-loopback IPv4 interface. May select
   Docker, VPN, or VirtualBox adapters on machines with multiple active
   interfaces. Set `bindAddress` explicitly if auto-detection selects the
   wrong address.

### Traffic Flow

```
Phone (Tailscale app)
  |
  |-- Tailscale encrypted WireGuard tunnel
  |
Oracle Server (100.x.y.z:3443)
  |
  |-- HTTPS (outbound, port 443)
  |
  GitHub API (api.github.com)
```

No ports are open to the public internet. All traffic flows through
Tailscale's encrypted mesh.

### Traffic Flow Matrix

| Source | Destination | Protocol | Description |
|--------|-------------|----------|-------------|
| Workstation | Oracle | HTTPS | GET /api/dashboard, /api/status |
| Phone | Oracle | HTTPS | POST /api/authorize (WebAuthn assertion) |
| Oracle | GitHub | HTTPS | POST /repos/:owner/:repo/pulls/:number/merge |
| Oracle | Phone | HTTPS | Response to /api/authorize |
| Oracle | Workstation | HTTPS | Response to /api/dashboard (QR + status) |
| Phone | Workstation | NONE | QR is optical, out-of-band |

---

## Tailscale Integration

### Why Tailscale

The LAN-only model is the most secure -- the server is not exposed to the
internet at all. However, the phone must be on the same network to scan the
QR, and the self-signed TLS certificate produces a browser warning.

Tailscale solves both without opening ports:

1. **Valid HTTPS**: `tailscale serve --bg 3443` provisions a Let's Encrypt
   certificate automatically. No browser warnings on the phone.

2. **Remote access**: the phone can authorize from anywhere (4G, another
   office) via the encrypted Tailscale network. No port forwarding needed.

### Setup

```bash
# On each device:
sudo tailscale up --authkey tskey-xxxx

# On the oracle server (optional HTTPS proxy):
sudo tailscale serve --bg 3443

# Verify connectivity:
tailscale status
curl -k https://100.1.2.5:3443/api/status
```

### Threat Model Impact

Tailscale does NOT expose Oracle publicly. Traffic flows through Tailscale's
encrypted WireGuard mesh, not through the public internet.

```
Phone -- Tailscale encrypted tunnel -- Oracle (no open ports)
```

Cloudflare Tunnel (explicitly not used) would expose Oracle to the public
internet, expanding the attack surface. Tailscale keeps the server private.

### Priority

| Mode | Risk | Reach | Status |
|------|------|-------|--------|
| LAN | Lowest | Same network | MVP (default) |
| VPN (Tailscale/WireGuard) | Low | Anywhere | v1.1 (auto-detected) |
| Public tunnel | Higher | Anywhere | Not planned |

---

## Deployment

### Linux (Raspberry Pi / Debian / Ubuntu)

```bash
# Install Node.js 20+
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs git

# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Clone and install
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install && npm run build

# Configure secrets
export GITHUB_TOKEN="github_pat_..."
export ORACLE_MASTER_SECRET="$(openssl rand -hex 32)"

# Set up systemd service
sudo tee /etc/systemd/system/sentinel-oracle.service << 'EOF'
[Unit]
Description=Sentinel Oracle Merge Authorization Server
After=network.target tailscaled.service
Wants=tailscaled.service

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/sentinel-oracle
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=10
Environment=NODE_ENV=production
Environment=GITHUB_TOKEN=...
Environment=ORACLE_MASTER_SECRET=...

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-oracle
```

### Windows

```powershell
# Install Node.js from https://nodejs.org (>= 20 LTS)
# Install Tailscale
winget install Tailscale.Tailscale
tailscale up

# Clone and install
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install && npm run build

# Set environment variables
$env:GITHUB_TOKEN="github_pat_..."
$env:ORACLE_MASTER_SECRET="..."

# Run
npm start

# Optional: Windows service with NSSM
nssm install SentinelOracle "C:\Program Files\nodejs\node.exe" "dist\index.js"
nssm set SentinelOracle AppDirectory "C:\Users\you\sentinel-oracle"
nssm set SentinelOracle Start SERVICE_AUTO_START
nssm start SentinelOracle
```

### macOS

```bash
# Install Node.js via Homebrew
brew install node@22

# Install Tailscale
brew install --cask tailscale

# Clone and install
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install && npm run build

# Run
npm start

# Optional: LaunchAgent for auto-start
```

### Android / Termux

```bash
# Install Termux from F-Droid (not Play Store)
pkg update && pkg upgrade
pkg install nodejs git tailscale

# Clone and install
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install && npm run build

# Keep the phone plugged in
# Use termux-wake-lock to prevent CPU sleep
termux-wake-lock
export GITHUB_TOKEN="github_pat_..."
export ORACLE_MASTER_SECRET="..."
npm start
```

---

## Security Considerations

### Physical Security

The oracle server is the single trusted component. It should be:

- Located in a locked room or locked enclosure.
- Equipped with full-disk encryption (LUKS or BitLocker).
- Configured with BIOS/UEFI password and Secure Boot.
- Running no other workloads.

### Key Management

- The GitHub PAT should be a fine-grained token with `pull-requests: write`
  scope only. Rotate every 90 days.
- `ORACLE_MASTER_SECRET` must have at least 256 bits of entropy.
- The encryption key is auto-generated at startup and stored at
  `{dataDir}/.encryption_key` with `0o600` permissions.
- Rotate the master secret every 6 months.

### Clock Synchronization

WebAuthn relies on accurate timestamps. The oracle server must run NTP.
A clock skew of more than 30 seconds will cause WebAuthn assertion
verification to fail.

```bash
sudo timedatectl set-ntp true
sudo timedatectl status
```

### Logging and Auditing

All merge authorization events are logged with: timestamp, PR number,
challenge ID, credential ID, client IP (Tailscale IP), and result
(success/failure/denied). Forward logs to a centralized system for
alerting and forensic analysis.

### Backup Strategy

The only persistent state is the SQLite database and config file. Back up the
database daily, encrypted, and stored separately from the oracle server. Test
restoration quarterly.

### GitHub App Mode

When using GitHub App authentication, no long-lived credentials are stored on the oracle server. Installation tokens are generated on-demand with a 1-hour TTL and are scoped to a single repository. This eliminates the risk of PAT exfiltration and reduces the blast radius of a server compromise.

### Webhook Verification

The optional `githubWebhookSecret` configures HMAC-SHA256 verification of incoming webhook payloads. Oracle verifies the `X-Hub-Signature-256` header against the request body, ensuring that only legitimate GitHub webhook events are processed. This prevents spoofed webhook deliveries from triggering unauthorized actions.

### Branch Protection Auto-Verification

Oracle automatically verifies branch protection settings on the main branch before processing merge requests. It checks for required status checks, admin enforcement, and force push settings. If branch protection is misconfigured, Oracle logs a warning and returns the status via the `/api/status/branch-protection` endpoint.

---

## Known Limitations

- Branch protection rules must be configured independently on GitHub.
  Oracle's authorization flow is bypassed if administrators can push directly
  or force-push.
- PAT with merge permissions is stored on the oracle server. Network
  segmentation and TPM-backed storage reduce this risk.
- WebAuthn credential storage and encryption key share the same SQLite
  database. A full disk compromise yields both.
- LAN IP auto-detection may select a Docker, VPN, or VirtualBox interface
  if the machine has multiple active network adapters. Set `bindAddress`
  explicitly in config.json if this occurs.
- Branch protection verification is read-only — Oracle detects issues but does not auto-fix them.
- Webhook delivery is not guaranteed — polling serves as fallback.
- Unauthorized merge detection relies on webhook availability.

---

## Verification Checklist

- [ ] All three devices visible in `tailscale status`.
- [ ] Oracle dashboard accessible from workstation:
      `https://100.1.2.5:3443`.
- [ ] Oracle dashboard accessible from phone browser (via Tailscale).
- [ ] GitHub PAT works:
      `curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/repos/owner/repo`.
- [ ] WebAuthn passkey registration works (register from phone browser).
- [ ] Full end-to-end merge: generate challenge, scan QR, biometric, merge.
- [ ] Emergency lockdown activates and deactivates correctly.
- [ ] Lockdown persists across server restart.
- [ ] Server restart does not corrupt the database.
- [ ] NTP is enabled on the oracle server.

---

## Environment and File Reference

| Path | Purpose | Auto-created |
|------|---------|-------------|
| `~/.sentinel-oracle/config.json` | User configuration | No (defaults used if absent) |
| `~/.sentinel-oracle/.encryption_key` | AES-256 HMAC signing key (32 bytes) | Yes |
| `~/.sentinel-oracle/oracle.db` | SQLite database | Yes |
| `~/.sentinel-oracle/server.key` | TLS private key | Yes (by setup script) |
| `~/.sentinel-oracle/server.cert` | TLS certificate (self-signed) | Yes (by setup script) |
| `./scripts/setup.cjs` | Interactive setup wizard | Part of repo |
| `./start.cmd` | Windows start shortcut | Part of repo |

---

## Troubleshooting

### Phone cannot reach the dashboard

1. Verify phone is connected to Tailscale and the same tailnet.
2. Run `tailscale status` on the oracle server to confirm all three devices
   are visible.
3. Check ACLs in the Tailscale admin console.
4. Verify the oracle server is listening:
   `curl -k https://localhost:3443/health`.
5. From the phone browser:
   `http://{tailscale-ip}:3443/health`.

### Self-signed certificate warning

- **Recommended**: Install Tailscale on the phone and use
  `tailscale serve --bg 3443`.
- **Alternative**: Add the self-signed certificate to the phone's trust
  store.
- **Not recommended**: Disable TLS.

### WebAuthn registration fails

1. Ensure the phone browser supports WebAuthn (Chrome, Safari, Edge).
2. Check that `rpId` matches the domain/IP the phone uses to reach the
   server.
3. Verify `serverOrigin` is a valid origin.
4. If using a self-signed certificate, WebAuthn may reject on some browsers.
   Use Tailscale for valid HTTPS.

### Server won't start

```bash
node --version                     # Must be >= 20
npm run build                      # Check for TypeScript errors
node --stack-trace-limit=100 dist/index.js
node -e "console.log(JSON.parse(require('fs').readFileSync(require('os').homedir() + '/.sentinel-oracle/config.json', 'utf8')))"
```

---

---

## Community

Sentinel Oracle is a community-driven project. Contributions of all kinds are
welcome — code, bug reports, feature ideas, documentation improvements, and
security research.

| Resource | Purpose |
|----------|---------|
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to contribute, coding guidelines, PR process |
| [SECURITY.md](./SECURITY.md) | How to report a vulnerability |
| [Issues](https://github.com/javier20dev25/sentinel-oracle/issues) | Bug reports and feature requests |
| [Pull Requests](https://github.com/javier20dev25/sentinel-oracle/pulls) | Open PRs awaiting review |

We have no paid security team — we rely on the community to help keep this
project secure. Vulnerability reports are sincerely appreciated.

### License and Commercial Use

Sentinel Oracle is released under the **Business Source License 1.1** (see
[LICENSE](./LICENSE)). In plain language:

- ✅ **You can** use, modify, and improve Sentinel Oracle for your own
  development, internal operations, or maintenance — whether you're an
  individual developer, a startup, a bank, or a large enterprise.
- ❌ **You cannot** sell, sublicense, or charge for the software itself, nor
  incorporate it into a paid commercial product or a hosted/managed service
  (SaaS, PaaS, cloud hosting).
- ✅ **Internal business use is always permitted.** You can build internal
  tools, dashboards, or custom integrations on top of Sentinel Oracle without
  restriction, as long as they are not sold or monetized externally.
- ✅ **Contributions back to the project** (bug fixes, features,
  documentation) are welcome and encouraged under the same license terms.

> *If your company relies on Sentinel Oracle to protect your merge pipeline
> and you want to give back — contributions, security research, and
> documentation improvements are the best way. No payment required.*

---

## License

BUSSL-1.1 -- see LICENSE for terms.

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

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/prs` | Request authorization for a PR. Returns QR challenge. |
| POST | `/api/prs/:number/confirm` | Confirm authorization with WebAuthn assertion. Executes merge. |
| POST | `/api/prs/:number/reject` | Reject authorization for a PR. |
| POST | `/api/lockdown` | Emergency lockdown. Invalidates all challenges. |
| GET | `/api/devices` | List registered WebAuthn credentials. |
| DELETE | `/api/devices/:id` | Revoke a registered device. |
| GET | `/api/audit` | Paginated authorization audit log. |

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

### credentials

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | WebAuthn credential ID (base64url) |
| device_name | TEXT | Human-readable label (e.g., "Pixel 7") |
| public_key | TEXT | COSE-encoded ECDSA P-256 public key |
| credential_id | TEXT | Raw credential ID buffer (hex) |
| transports | TEXT | JSON array of authenticator transports |
| counter | INTEGER | WebAuthn signature counter |
| created_at | TEXT | ISO 8601 registration timestamp |
| last_used_at | TEXT | ISO 8601 last authorization timestamp |

### audit_log

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| pr_number | INTEGER | Target PR number |
| action | TEXT | Event type: authorization_requested, authorization_confirmed, merge_executed, merge_failed, authorization_rejected, lockdown_activated, lockdown_deactivated, device_registered, device_revoked |
| device_id | TEXT | WebAuthn credential ID that performed the action |
| challenge_id | TEXT | Associated challenge UUID |
| metadata | TEXT | JSON blob with error messages, reasons, PR titles, commit SHAs |
| created_at | TEXT | ISO 8601 timestamp |

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

### "Access token not provided" in supabase link (sentinel-cloud)

The `backup.yml` workflow requires `SUPABASE_ACCESS_TOKEN` as a GitHub
Actions secret. Add the secret in the repository settings (Settings > Secrets
and variables > Actions > New repository secret).

---

## License

BUSSL-1.1 -- see LICENSE for terms.

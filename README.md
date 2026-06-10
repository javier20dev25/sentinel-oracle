# Sentinel Oracle

Physically isolated merge authorization server for GitHub pull requests.
Merge authority resides on a separate device — Raspberry Pi, NUC, or mini
PC — on the local network. The architecture is designed to resist
workstation compromise: an attacker who gains full control of the developer
laptop cannot authorize a merge without physical access to a second device
and a WebAuthn passkey.

This is not a replacement for GitHub branch protection rules. Oracle
operates as an additional enforcement layer. Repository administrators with
direct push or bypass permissions remain a valid threat path independent of
Oracle's controls.

## Architecture

Sentinel Oracle implements a three-device trust model:

- **Workstation** (untrusted): displays a QR challenge on the Oracle
  dashboard and initiates authorization requests. Does not hold GitHub
  credentials with merge scope.
- **Oracle server** (trusted authority): polls GitHub for open PRs.
  Accepts authorization initiation requests from the workstation, generates
  QR challenges, verifies WebAuthn assertions, and executes the merge via
  the GitHub API. The workstation cannot invoke merge directly — only
  the phone-confirmed path can produce the merge API call.
- **Phone** (identity proof): scans the QR, opens the /authorize page, and
  authenticates via WebAuthn passkey (biometric, PIN, or FIDO2 security
  key depending on the authenticator). The phone never interacts with
  GitHub directly.

## Authorization Flow

1. **PR Polling** — Oracle polls GitHub for open pull requests and tracks
   their commit statuses in SQLite.
2. **Initiation** — The workstation calls
   `POST /api/prs/:number/authorize` for a specific PR. Oracle generates
   an HMAC-signed QR challenge encoding a challenge ID and PR number. TTL
   is 45 seconds. One-time use.
3. **Phone Authentication** — The phone scans the QR, opens
   /authorize?cid=xxx&pr=142, and issues a WebAuthn passkey assertion
   bound to the specific PR number. The assertion challenge is generated
   server-side with the PR number embedded.
4. **Assertion Verification** — Oracle verifies the assertion signature
   against the stored credential, confirms the challenge ID matches an
   active challenge, checks the PR number embedded in the assertion
   matches the PR number in the challenge, and marks the challenge
   consumed.
5. **Merge Execution** — Oracle calls
   `POST /repos/:owner/:repo/pulls/:number/merge` via Octokit with
   squash merge method. The workstation never executes the merge API
   call — only the server, after cryptographic verification, does.

## Threat Model

Merge attacks typically exploit the developer workstation — a compromised
laptop, a stolen session token, or a malicious IDE plugin can trigger an
unauthorized merge. Sentinel Oracle eliminates that vector by enforcing
physical separation: the workstation holds no tokens with merge scope,
the Oracle server executes merge only after WebAuthn + challenge
verification, and the phone provides ephemeral consent for each
individual PR.

Workstation compromise alone is insufficient to authorize a merge.
Oracle compromise remains a risk — the server stores a GitHub PAT with
merge permissions and an AES encryption key on the same SQLite database.
Enterprise deployments should mitigate Oracle-level risk with TPM-backed
key storage and network segmentation.

## GitHub Branch Protection

Oracle does not replace GitHub's branch protection rules. To make the
authorization flow effective, the target branch must be configured with:

- Require status checks: add `Sentinel Authorization` as a required check
- Disable force pushes
- Disable administrator bypass (or ensure administrators also go through
  Oracle)

Without these settings, users with direct push or bypass permissions can
merge independently of Oracle's authorization flow.

## Installation

```bash
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install
npm run build
```

## Quick Start

```bash
npm run setup          # checks Node.js, TLS, Tailscale, config
npm start              # start the server
```

The setup script walks through each dependency:

1. **Node.js** — verifies >= 20
2. **TLS certificates** — generates self-signed if missing
3. **Tailscale** (optional, recommended) — installs via winget, runs
   `tailscale up` and `tailscale serve --bg 3443` for automatic HTTPS
4. **config.json** — verifies it exists at `~/.sentinel-oracle/config.json`

Without Tailscale, the server still works on LAN but the phone
browser will show a certificate warning (self-signed cert).

With Tailscale, the QR code points to the Tailscale IP (`100.x.x.x`)
and HTTPS is automatically valid via Let's Encrypt.

## Configuration

Create config.json in the project root:

```json
{
  "githubToken": "ghp_...",
  "repoOwner": "your-org",
  "repoName": "your-repo",
  "bindAddress": "192.168.1.100",
  "rpId": "192.168.1.100",
  "serverOrigin": "https://192.168.1.100:3443",
  "port": 3443,
  "tlsCert": "./cert.pem",
  "tlsKey": "./key.pem",
  "locked": false
}
```

| Field | Description |
|-------|-------------|
| githubToken | GitHub PAT with repo scope and merge permissions |
| repoOwner | GitHub organization or user that owns the target repository |
| repoName | Repository name |
| bindAddress | IP address the server binds to (auto-detected from LAN if omitted). Detection returns the first non-loopback IPv4 interface, which may select Docker, VPN, or VirtualBox adapters on machines with multiple active interfaces. Set explicitly if auto-detection selects the wrong address. |
| rpId | WebAuthn relying party ID (auto-detected from bindAddress if omitted) |
| serverOrigin | Origin URL for WebAuthn (auto-assembled if omitted) |
| port | HTTPS port (default 3443) |
| tlsCert | Path to TLS certificate |
| tlsKey | Path to TLS private key |
| locked | If true, all /confirm endpoints reject immediately |

## API Endpoints

### POST /api/prs - Request authorization for a pull request

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

### POST /api/prs/:number/confirm - Confirm authorization with WebAuthn assertion

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

### POST /api/prs/:number/reject - Reject authorization

```json
{ "reason": "Unsafe diff detected" }
```

### POST /api/lockdown - Emergency lock

```json
{ "reason": "Compromised workstation reported" }
```

Response: rejects all pending challenges, sets commit status to failure on
all open PRs, persists locked state to SQLite.

### GET /api/devices - List registered WebAuthn credentials

Returns array of device descriptors with creation time and last-used timestamp.

### DELETE /api/devices/:id - Revoke a device

Removes credential from SQLite storage and logs revocation.

### GET /api/audit - Authorization audit log

Returns paginated authorization attempts with timestamps, PR numbers,
verdicts, and device identifiers.

## Dependencies

- Node.js >= 20
- @simplewebauthn/server for WebAuthn assertion verification
- @octokit/rest for GitHub API calls
- better-sqlite3 for persistent challenge, credential, and audit storage
- express + helmet for HTTP server with security headers
- express-rate-limit for request throttling
- qrcode for QR generation
- uuid for challenge identifiers

## Tailscale (optional, recommended)

Oracle auto-detects Tailscale during startup. If a `100.x.x.x` IP is found on
the Tailscale interface, it is used as `bindAddress` and for the QR URL instead
of the LAN IP. No configuration change needed — just install Tailscale and run.

### Why Tailscale

The LAN-only model (MVP) is the most secure — the server is not exposed to the
internet at all. However, the phone must be on the same network to scan the QR,
and the self-signed TLS certificate produces a browser warning.

Tailscale solves both without opening ports:

1. **Valid HTTPS**: `tailscale serve --bg 3443` provisions a Let's Encrypt
   certificate automatically. No browser warnings on the phone.
2. **Remote access**: the phone can authorize from anywhere (4G, another
   office) via the encrypted Tailscale network. No port forwarding needed.

### Setup

```
winget install Tailscale.Tailscale          # Windows
tailscale up                                 # authenticate to tailnet
tailscale serve --bg 3443                    # HTTPS proxy to Oracle
```

Oracle detects the Tailscale IP on next startup and uses it automatically.

### Threat model impact

Tailscale does NOT expose Oracle publicly. The traffic flows through
Tailscale's encrypted wire, not through the public internet:

```
Phone — Tailscale encrypted tunnel — Oracle (no open ports)
```

Cloudflare Tunnel (explicitly not used) would expose Oracle to the public
internet, expanding the attack surface. Tailscale keeps the server private.

### Priority

| Mode | Risk | Reach | Status |
|------|------|-------|--------|
| LAN | Lowest | Same network | MVP (default) |
| VPN (Tailscale/WireGuard) | Low | Anywhere | v1.1 (detected automatically) |
| Public tunnel | Higher | Anywhere | Not planned |

## Security Considerations

- Encryption key (`~/.sentinel-oracle/.encryption_key`) resides on the
  same disk as the SQLite database in the MVP. Enterprise deployments
  should use TPM-backed or HSM-backed key storage.
- HMAC signing uses a server-side secret derived from the encryption key.
  Core security relies on nonce + server-side validation + TTL + one-time
  consumption + WebAuthn assertion — HMAC is defense-in-depth.
- TLS is required. The server binds to the LAN IP by default and logs a
  warning if configured on loopback (127.0.0.1).
- CSP includes `script-src 'unsafe-inline'` and `style-src 'unsafe-inline'`
  because the /authorize page serves inline JavaScript for the WebAuthn
  flow and inline styles for the mobile UI. This is acceptable for a
  LAN-bound admin server. A future version should migrate to external
  scripts with integrity hashes or nonces.
- `img-src 'self' data:` is required for QR code data URIs served inline.
- Do not expose this server to the public internet.

## Known Limitations

- Branch protection rules must be configured independently on GitHub.
  Oracle's authorization flow is bypassed if administrators can push
  directly or force-push.
- PAT with merge permissions is stored on the Oracle server. Compromise
  of the server yields the PAT. Network segmentation and TPM-backed
  storage reduce this risk.
- WebAuthn credential storage and encryption key share the same SQLite
  database. A full disk compromise yields both.
- LAN IP auto-detection may select a Docker, VPN, or VirtualBox interface
  if the machine has multiple active network adapters. Set `bindAddress`
  explicitly in config.json if this occurs.

---

## Pre-Deployment Checklist

Hardware:
- [ ] Dedicated device (Raspberry Pi 4/5, NUC, mini PC) on 24/7 power
- [ ] Static LAN IP or DHCP reservation
- [ ] Tailscale installed on all three devices (or alternative WireGuard mesh)
- [ ] Phone with WebAuthn-compatible browser (Chrome, Safari, Edge)

GitHub:
- [ ] Personal Access Token (classic) with `repo` scope generated
- [ ] Target branch has "Require status checks" enabled
- [ ] Status check name matches `githubStatusContext` (default: "Sentinel Authorization")
- [ ] No direct-push or administrator bypass on branch protection

Server:
- [ ] Node.js >= 20 installed
- [ ] OpenSSL available for certificate generation
- [ ] Port 3443 (or custom port) reachable from workstation and phone over Tailscale
- [ ] config.json created at ~/.sentinel-oracle/config.json
- [ ] TLS certificates generated (or auto-generated by setup script)

---

## Configuration Reference

Full config.json schema with types, defaults, and descriptions.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | number | `3443` | HTTPS listen port. Use >= 1024 on Linux to avoid root. |
| `host` | string | `"0.0.0.0"` | Bind address (all interfaces). Change to specific IP for strict binding. |
| `bindAddress` | string | auto (LAN/Tailscale) | IP used for QR URLs and WebAuthn origin. Auto-detection order: Tailscale Funnel URL > Tailscale IP (100.x.x.x) > first non-loopback IPv4. |
| `dataDir` | string | `~/.sentinel-oracle` | Directory for SQLite database, encryption key, TLS certs, config. |
| `githubToken` | string | `""` | GitHub PAT with repo scope. Required unless githubAppId/githubInstallationId/githubPrivateKeyPath are set. |
| `githubAppId` | string | `""` | GitHub App ID (alternative to PAT mode). |
| `githubInstallationId` | string | `""` | GitHub App installation ID. |
| `githubPrivateKeyPath` | string | `""` | Path to GitHub App private key PEM file. |
| `githubOwner` | string | `""` | GitHub organization or user that owns the target repository. |
| `githubRepo` | string | `""` | Repository name (without owner prefix). |
| `githubStatusContext` | string | `"Sentinel Authorization"` | Commit status context name. Must match the required status check in branch protection. |
| `serverOrigin` | string | auto | Origin URL for WebAuthn Relying Party. Auto-assembled from bindAddress + port. |
| `rpId` | string | auto | WebAuthn Relying Party ID (domain without port). Auto-assembled from bindAddress. |
| `challengeTtlMs` | number | `45000` | QR challenge TTL in milliseconds. After expiry, the QR must be regenerated. |
| `rateLimitAuth` | number | `5` | Maximum authorization attempts per rateLimitWindowMs. |
| `rateLimitWindowMs` | number | `60000` | Rate limit window in milliseconds. |
| `encryptionKey` | Buffer | auto-generated | AES-256 key for HMAC signing key derivation. Generated once and stored at dataDir/.encryption_key. DO NOT SET IN CONFIG. |
| `approveReasonRequired` | boolean | `false` | If true, the /confirm endpoint requires a non-empty "reason" field. |
| `locked` | boolean | `false` | Emergency lockdown. When true, all /confirm endpoints reject immediately. Persisted state. |
| `passwordHash` | string | `""` | SHA-256 hash of dashboard password. Empty = no password required. |
| `enrollmentTokenTtlMs` | number | `120000` | First-time device enrollment token TTL in milliseconds. |

---

## Database Schema

SQLite database at `{dataDir}/oracle.db`. Three tables:

### `challenges`

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | UUID v4 challenge identifier |
| pr_number | INTEGER | Target PR number |
| signature | TEXT | HMAC-SHA256 signature (challengeId:prNumber:timestamp) |
| expires_at | INTEGER | Unix ms timestamp after which challenge is invalid |
| consumed | INTEGER | 0 or 1. One-time consumption flag |
| created_at | TEXT | ISO 8601 timestamp |

### `credentials`

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | WebAuthn credential ID (base64url) |
| device_name | TEXT | Human-readable label (e.g., "Pixel 7") |
| public_key | TEXT | COSE-encoded ECDSA P-256 public key |
| credential_id | TEXT | Raw credential ID buffer (hex) |
| transports | TEXT | JSON array of authenticator transports (usb, nfc, ble, internal) |
| counter | INTEGER | WebAuthn signature counter (monotonically increasing) |
| created_at | TEXT | ISO 8601 registration timestamp |
| last_used_at | TEXT | ISO 8601 last authorization timestamp |

### `audit_log`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| pr_number | INTEGER | Target PR number |
| action | TEXT | Event type: "authorization_requested", "authorization_confirmed", "merge_executed", "merge_failed", "authorization_rejected", "lockdown_activated", "lockdown_deactivated", "device_registered", "device_revoked" |
| device_id | TEXT | WebAuthn credential ID that performed the action (null for server-originated events) |
| challenge_id | TEXT | Associated challenge UUID (null for non-challenge events) |
| metadata | TEXT | JSON blob with additional context (error messages, reasons, PR titles, commit SHAs) |
| created_at | TEXT | ISO 8601 timestamp |

---

## Cryptographic Specification

### HMAC Challenge Signing

Key derivation:
```
derived_key = HMAC-SHA256(encryption_key, "sentinel-oracle-hmac-key-v1")
```

Challenge token format:
```
payload = challengeId + ":" + prNumber + ":" + timestamp
signature = HMAC-SHA256(derived_key, payload)
```

Verification uses `crypto.timingSafeEqual` to prevent timing attacks. Max TTL is `challengeTtlMs` (default 45s). Negative age (clock drift) is rejected.

### Encryption Key

Generated once at startup with `crypto.randomBytes(32)`. Stored at `{dataDir}/.encryption_key` with filesystem permission `0o600` (owner read/write only). Never stored in config.json. Used solely for HMAC key derivation. If the encryption key file is lost, all pending challenges become invalid but the server continues to operate — a new key is generated and new challenges use the new key.

### WebAuthn Assertion Verification

Library: `@simplewebauthn/server`. Verification steps:

1. Parse the assertion response (credential ID, authenticator data, signature, user handle, client data)
2. Look up credential ID in `credentials` table
3. Verify authenticator data: RP ID hash matches SHA-256(rpId), user present flag set, signature counter >= stored counter
4. Verify client data: challenge equals the server-generated WebAuthn challenge, origin matches serverOrigin, type equals "webauthn.get"
5. Verify assertion signature against stored ECDSA P-256 public key
6. Update counter in credentials table
7. Return verified status

The WebAuthn challenge is bound to the PR number server-side before the assertion is created. This prevents replay of assertions across different PRs.

---

## Network Architecture

### IP Auto-Detection Priority

Oracle uses three discovery methods in order:

1. **Tailscale Funnel** (highest priority): Reads `tailscale funnel status --json` and `tailscale serve status --json` for existing HTTPS proxy configurations. If a proxy targets Oracle's port, the MagicDNS hostname is used. This enables valid HTTPS certificates from Let's Encrypt automatically.

2. **Tailscale IP** (medium priority): Scans network interfaces for the Tailscale virtual adapter (detected by name containing "tailscale" and IP matching 100.64.0.0/10 range). The Tailscale IP is stable across reboots and provides encrypted mesh connectivity.

3. **LAN IP** (fallback): First non-loopback IPv4 interface that is not internal. May select Docker, VPN, or VirtualBox adapters on machines with multiple active interfaces. Set `bindAddress` explicitly if auto-detection selects the wrong address.

### Traffic Flow

```
Phone (Tailscale app)
  |
  |-- Tailscale encrypted WireGuard tunnel
  |
Oracle Server (Tailscale IP: 100.x.x.x:3443)
  |
  |-- HTTPS (mutual TLS via Tailscale)
  |
  GitHub API (outbound, port 443)
```

No ports are open to the public internet. All traffic flows through Tailscale's encrypted mesh. When using Tailscale Funnel, only the proxy endpoint is public — the Oracle server itself still binds to the private Tailscale IP.

---

## Platform-Specific Deployment

### Linux (Raspberry Pi / Debian / Ubuntu)

```bash
# Install Node.js 20+
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs git

# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Clone and install Oracle
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install
npm run build

# Configure
cp .env.example .env
nano ~/.sentinel-oracle/config.json   # or use .env

# Set up systemd service (recommended)
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
npm install
npm run build

# Create config at ~\.sentinel-oracle\config.json
# Run
npm start

# Optional: Register as Windows service using NSSM
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
# Log in via the Tailscale GUI app

# Clone and install
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install
npm run build

# Run
npm start

# Optional: Register as LaunchAgent for auto-start
```

---

## Environment and File Reference

| Path | Purpose | Auto-created |
|------|---------|-------------|
| `~/.sentinel-oracle/config.json` | User configuration | No (defaults used if absent) |
| `~/.sentinel-oracle/.encryption_key` | AES-256 HMAC signing key (32 bytes) | Yes |
| `~/.sentinel-oracle/oracle.db` | SQLite database (challenges, credentials, audit) | Yes |
| `~/.sentinel-oracle/server.key` | TLS private key | Yes (by setup script) |
| `~/.sentinel-oracle/server.cert` | TLS certificate (self-signed) | Yes (by setup script) |
| `./scripts/setup.cjs` | Interactive setup wizard | Part of repo |
| `./start.cmd` | Windows start shortcut | Part of repo |

## Troubleshooting

### "Access token not provided" in supabase link

The `backup.yml` workflow requires `SUPABASE_ACCESS_TOKEN` as a GitHub Actions secret. Add the secret in the repository settings (Settings > Secrets and variables > Actions > New repository secret). The workflow now uses `SUPABASE_ACCESS_TOKEN` instead of the deprecated `--password` flag.

### Phone cannot reach the dashboard

1. Verify phone is connected to Tailscale and the same tailnet
2. Run `tailscale status` on the Oracle server to confirm all three devices are visible
3. Check ACLs in the Tailscale admin console — ensure `tag:phone` or the phone's user has access to `tag:oracle:3443`
4. Verify the Oracle server is listening: `curl -k https://localhost:3443/health`
5. From the phone browser, navigate to `http://{tailscale-ip}:3443/health` (HTTP is fine inside Tailscale)

### Self-signed certificate warning

Tailscale automatically provisions Let's Encrypt certificates when using `tailscale serve`. Without Tailscale, the server uses a self-signed certificate generated by the setup script. To suppress browser warnings on the phone:

- **Recommended**: Install Tailscale on the phone and use `tailscale serve --bg 3443`
- **Alternative**: Add the self-signed certificate to the phone's trust store (device-dependent)
- **Not recommended**: Disable TLS (use HTTP on local network only)

### WebAuthn registration fails

1. Ensure the phone browser supports WebAuthn (Chrome, Safari, Edge)
2. Check that `rpId` in config.json matches the domain/IP the phone uses to reach the server
3. Verify `serverOrigin` is a valid origin (https://... or http://localhost)
4. Check the browser console for WebAuthn-specific error messages (e.g., "invalid domain", "credential already exists")
5. If using a self-signed certificate, WebAuthn may reject on some browsers — use Tailscale for valid HTTPS

### Server won't start

```bash
# Check Node.js version
node --version  # Must be >= 20

# Check for TypeScript compilation errors
npm run build

# Run with verbose error output
node --stack-trace-limit=100 dist/index.js

# Check config file syntax
node -e "console.log(JSON.parse(require('fs').readFileSync(require('os').homedir() + '/.sentinel-oracle/config.json', 'utf8')))"
```

## License

BUSSL-1.1 — see LICENSE for terms.

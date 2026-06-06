# Sentinel Oracle

Physically isolated merge authorization server for GitHub pull requests.
The workstation never holds merge credentials. Merge authority resides on a
separate device — Raspberry Pi, NUC, or mini PC — on the local network.

## Architecture

Sentinel Oracle implements a three-device trust model:

- **Workstation** (untrusted): displays a QR challenge on the Oracle dashboard.
  Does not hold GitHub credentials with merge permission.
- **Oracle server** (trusted authority): polls GitHub for PRs with pending
  Sentinel status. Accepts no commands from the workstation. Executes merge
  via GitHub API after cryptographic verification.
- **Phone** (identity proof): scans the QR, opens the /authorize page, and
  authenticates via WebAuthn passkey. The phone never interacts with GitHub
  directly.

## Authorization Flow

1. **PR Polling** — Oracle polls GitHub for pull requests where Sentinel
   status checks have passed but authorization is still pending.
2. **QR Challenge** — Oracle generates an HMAC-signed QR code encoding a
   challenge ID and PR number. TTL is 45 seconds. One-time use.
3. **Phone Authentication** — The phone scans the QR, opens
   /authorize?cid=xxx&pr=142, and issues a WebAuthn biometric assertion
   bound to the specific PR number.
4. **Assertion Verification** — Oracle verifies the assertion signature,
   confirms the challenge ID matches an active challenge, checks the PR
   number in the assertion matches the PR number in the challenge, and marks
   the challenge consumed.
5. **Merge Execution** — Oracle calls POST /repos/:owner/:repo/pulls/:number/merge
   via Octokit. The workstation never touches the merge button.

## Threat Model

Merge attacks typically exploit the developer workstation — a compromised
laptop, a stolen session token, or a malicious IDE plugin can trigger an
unauthorized merge. Sentinel Oracle eliminates that vector by enforcing
physical separation: the workstation holds no tokens with merge scope, the
Oracle server holds the PAT but never accepts instructions from the
workstation, and the phone provides ephemeral biometric consent for each
individual PR. Compromise of any single device is insufficient to authorize
a merge.

## Installation

```bash
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install
npm run build
```

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
| bindAddress | IP address the server binds to (auto-detected from LAN if omitted) |
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

### POST /api/confirm - Confirm authorization with WebAuthn assertion

Request:
```json
{
  "challengeId": "uuid",
  "assertion": { ... }
}
```

Response:
```json
{
  "status": "approved",
  "prNumber": 142,
  "mergeSuccess": true
}
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

## Security Considerations

- Encryption key resides on the same disk as the SQLite database in the MVP.
  Enterprise deployments should use TPM-backed or HSM-backed key storage.
- HMAC signing uses a server-side secret derived from the encryption key.
  Core security relies on nonce + server-side validation + TTL + one-time
  consumption + WebAuthn assertion — HMAC is defense-in-depth.
- TLS is required. The server binds to the LAN IP by default and logs a
  warning if configured on loopback (127.0.0.1).
- The /authorize page serves inline JavaScript. CSP is set to
  script-src 'unsafe-inline' as the page is served over LAN and is
  admin-only. Do not expose this server to the public internet.

## License

BUSSL-1.1 — see LICENSE for terms.

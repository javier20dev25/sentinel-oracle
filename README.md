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

## License

BUSSL-1.1 — see LICENSE for terms.

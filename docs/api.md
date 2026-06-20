# Sentinel Oracle API

## Overview

All API endpoints serve over HTTPS on the configured port (default 8443). Authentication is required except for setup endpoints. Responses are JSON.

## Authentication

### WebAuthn-based Session

```
GET /api/auth/status
```
Returns whether a WebAuthn credential is registered:
```json
{ "registered": true, "session": false }
```

```
POST /api/auth/register/begin
POST /api/auth/register/complete
```
FIDO2 CTAP2 registration ceremony (PublicKeyCredentialCreationOptions).

```
POST /api/auth/login/begin
POST /api/auth/login/complete
```
FIDO2 CTAP2 assertion ceremony (PublicKeyCredentialRequestOptions).

```
POST /api/auth/logout
```
Destroys the current session.

### Session Cookie

All authenticated routes require a valid `sentinel-session` cookie with a matching CSRF token. Sessions are Server-signed (HMAC-SHA256) and expire on browser close.

## PR Queue

### List Open PRs

```
GET /api/prs
```

Returns all open PRs being tracked:

```json
{
  "prs": [
    {
      "prNumber": 42,
      "title": "Fix critical bug",
      "author": "javier20dev25",
      "status": "awaiting_ci",
      "sha": "abc123...",
      "ciStatus": "completed",
      "authStatus": "pending",
      "url": "https://github.com/owner/repo/pull/42"
    }
  ]
}
```

### Authorize PR

```
POST /api/prs/:number/authorize
```

Body: `{ "prNumber": 42 }` — initiates challenge generation for the PR.

### Scan PR

```
POST /api/prs/:number/scan
```

Initiates a security scan of the PR. Returns the cached result immediately if a scan has already been run for the same PR SHA.

```json
{ "scanResult": { "riskScore": 0, "findings": [], "intel": {} } }
```

### Queue Auth Check

```
POST /api/prs/:number/check
```

Requests the oracle to poll status of a single PR.

## Authorization and Challenges

### Get Challenge Payload

```
GET /api/challenge/:id/qr
```

Returns QR-code-encodable payload:

```json
{
  "challengeId": "abc123",
  "prNumber": 42,
  "token": "abc123def456...",
  "expiresAt": 1719000000000
}
```

### Verify Challenge

```
POST /api/verify
```

Body: `{ "challengeId": "abc123", "assertion": {...} }` — verifies challenge token + WebAuthn assertion + PR number.

```json
{ "success": true, "merged": true, "prNumber": 42 }
```

## Security Scan

### Get Scan Results

```
GET /api/scan/:prNumber
```

Returns cached scan results for a PR:

```json
{
  "prNumber": 42,
  "sha": "abc123...",
  "riskScore": 0,
  "cached": true,
  "findings": [
    {
      "rule": "hardcoded-secret",
      "severity": "high",
      "file": "src/config.js",
      "line": 15,
      "description": "Hardcoded API key detected"
    }
  ],
  "intel": {
    "capabilities": { "filesystem": 2, "network": 1 },
    "endpoints": { "urls": ["https://api.example.com"] },
    "services": { "services": ["stripe"] },
    "permissions": { ... },
    "dependencies": { "added": [], "removed": [] },
    "secrets": { "exposedVars": [] },
    "trust": { "risk": "low" },
    "crypto": { "risk": "low" },
    "auth": { "risk": "low" },
    "infrastructure": { "risk": "low" },
    "workflowIntel": { "risk": "low", "anomalies": [], "campaignDelta": {} },
    "trustDrift": { "risk": "low", "signals": [] },
    "deepDependency": { "risk": "low", "deltas": [] }
  },
  "scannedAt": "2026-06-19T12:00:00.000Z"
}
```

## Security DNA

### Get DNA Report

```
GET /api/dna
```

Returns capability snapshot with history and drift analysis:

```json
{
  "current": {
    "filesystem": 2,
    "network": 1,
    "shell": 0,
    "dynamicCode": 3,
    "database": 0,
    "crypto": 1,
    "secrets": 1,
    "runners": 0,
    "environments": 0,
    "collaborators": 0,
    "permissionEscalations": 0,
    "newDomains": 0,
    "newIntegrations": 1,
    "workflowCount": 1,
    "totalRiskScore": 9,
    "scannedAt": "2026-06-19T12:00:00.000Z"
  },
  "history": [
    { "filesystem": 1, "totalRiskScore": 5, "scannedAt": "2026-06-18T12:00:00.000Z" }
  ],
  "changes": {
    "filesystem": { "absoluteChange": 1, "percentageChange": 100 }
  },
  "summary": "filesystem increased by 1 (100%). New integrations detected.",
  "snapshotCount": 5
}
```

## CI Integrity

### Submit Step Telemetry

```
POST /api/ci/steps
```
Body: `{ "filename": ".github/workflows/ci.yml", "sha": "abc123...", "checkName": "CI / test (14)", "jobs": [...] }`

### Submit Fingerprint

```
POST /api/ci/fingerprint
```
Body: `{ "prNumber": 42, "sha": "abc123...", "fingerprintHash": "sha256...", "jobStructure": {...} }`

### Get Anomalies

```
GET /api/ci/anomalies/:prNumber
```

Returns CI integrity anomalies detected for a PR.

### Get Baseline

```
GET /api/ci/baselines/:sha
```

Returns multi-window baselines for a commit SHA.

## Policy

### Get Policy

```
GET /api/policy
```

Returns the current CI policy configuration:

```json
{
  "allowedRunners": ["ubuntu-latest"],
  "maxJobs": 10,
  "allowedActions": ["actions/checkout"],
  "blockedPatterns": [],
  "enabled": false
}
```

### Set Policy

```
POST /api/policy
```

Updates the CI policy. Requires authentication.

## Security Events

### List Events

```
GET /api/events
```

Returns paginated audit log events:

```json
{
  "events": [
    {
      "id": 1,
      "timestamp": "2026-06-19T12:00:00.000Z",
      "action": "merge",
      "prNumber": 42,
      "detail": "Merged PR #42 by operator"
    }
  ]
}
```

## Token Inventory

### List Tokens

```
GET /api/tokens
```

Returns token inventory with risk assessment:

```json
{
  "tokens": [
    {
      "type": "github_app",
      "name": "sentinel-oracle",
      "fingerprint": "sha256:abc123...",
      "riskScore": 0,
      "metadata": {}
    }
  ]
}
```

### Scan Tokens

```
POST /api/tokens/scan
```

Triggers on-demand token inventory scan of the configured repository.

## Setup

### Create Admin Credential

```
POST /api/setup/webhook
```
Configures the GitHub webhook URL.

### Verify Setup

```
GET /api/setup/status
```
Returns setup completion status:

```json
{
  "githubConfigured": true,
  "webhookConfigured": true,
  "webauthnConfigured": true,
  "complete": true
  "githubAppId": 123456,
  "webhookUrl": "https://api.github.com/repos/owner/repo/hooks/789",
  "error": null
}
```

## Error Responses

All endpoints return errors in the format:

```json
{
  "error": "string",
  "code": "ERROR_CODE"
}
```

Standard HTTP status codes:
- `200` — Success
- `400` — Bad request (invalid parameters)
- `401` — Unauthorized (no session)
- `403` — Forbidden (WRONG DEVICE, missing CSRF)
- `404` — Not found
- `429` — Rate limited
- `500` — Internal server error

## Rate Limiting

- Auth endpoints: 5 requests per minute per IP
- API endpoints: 60 requests per minute per session
- Challenge endpoints: 3 requests per minute per IP
- Scan endpoints: 10 requests per minute per session

Rate limit headers are included in all responses:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 57
X-RateLimit-Reset: 1719000060
```

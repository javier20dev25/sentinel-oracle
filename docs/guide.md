# Sentinel Oracle Operational Guide

## Overview

Sentinel Oracle is a physically isolated merge authorization server for GitHub. Merge credentials live on a dedicated device (the oracle) on your local network. The development workstation never holds the authority to merge.

This guide covers installation, configuration, operation, and troubleshooting.

## Prerequisites

### Hardware

- **Oracle server**: Raspberry Pi 4/5 (4GB+ RAM), NUC, mini PC, or dedicated Android phone with Termux
- **Phone**: Modern smartphone with platform biometric authentication (fingerprint, Face ID)
- **Workstation**: Any machine with a web browser (daily development machine)
- **Network**: Tailscale or Wireguard mesh VPN between all three devices

### Software

- **Node.js**: v20+ LTS
- **npm**: v10+
- **SQLite**: Built-in (bundled via better-sqlite3)
- **GitHub App**: Created in your GitHub organization or personal account

## Installation

### From npm

```bash
npm install -g @sentinel/oracle
sentinel-oracle --help
```

### From source

```bash
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install
npm run build
npm link
sentinel-oracle --help
```

## Configuration

Configuration is loaded from environment variables with file-based overrides.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_CONFIG_DIR` | `~/.config/sentinel-oracle` | Configuration directory |
| `SENTINEL_PORT` | `8443` | HTTPS server port |
| `SENTINEL_HOST` | `localhost` | Bind address (use Tailscale IP) |
| `NODE_OPTIONS` | — | Passed to Node.js (use `--max-old-space-size=4096`) |

### GitHub App Setup

1. Create a GitHub App at https://github.com/settings/apps
2. Set repository permissions:
   - Contents: Read & write (for merge)
   - Pull requests: Read & write
   - Checks: Read
   - Metadata: Read
3. Generate a private key (download `.pem` file)
4. Generate a webhook secret
5. Note the App ID

Place the private key at `~/.config/sentinel-oracle/github-private-key.pem`.

## First Run

Start the server:

```bash
sentinel-oracle
```

The server starts in setup mode if no GitHub credentials are configured. Open https://{ORACLE_TAILSCALE_IP}:8443/setup in a browser on the workstation.

### Setup Steps

1. Configure GitHub App credentials (App ID, private key, webhook secret)
2. Register a WebAuthn passkey using the phone
3. Verify the webhook is configured

After setup, the oracle begins polling GitHub for open PRs.

## Operation

### Dashboard

The dashboard is at https://{ORACLE_TAILSCALE_IP}:8443/. It requires WebAuthn authentication.

**Tabs:**
- **Security Posture** (default): Overall security status, risk score, scan timeline
- **PR Queue**: Open pull requests requiring authorization
- **Scan Details**: Per-PR security scan output
- **Security DNA**: Capability fingerprint aggregated across all scanned PRs
- **Events**: Audit log of all authorization and merge operations

### Merge Authorization Flow

1. Developer opens the oracle dashboard on the workstation
2. PR is visible in the queue with its CI status and security scan result
3. Developer clicks Authorize on the PR
4. A QR code is displayed on the workstation screen
5. Developer scans the QR code with the phone
6. Phone performs biometric verification
7. Phone signs the assertion with the registered passkey
8. Server verifies the assertion and merges the PR

### Security Scan

Manual scan: Click "SCAN" button on a PR in the queue.

Auto scan: Enable in Settings (toggle). When enabled, all PRs are scanned automatically on queue refresh.

Scans are deduplicated by SHA-256 hash of PR sha + file metadata. Same code is never scanned twice.

### Security Categories

Scan results are organized into:

| Category | Severity | Description |
|----------|----------|-------------|
| **Critical** | `>=10` | Secrets, credential leaks, auth bypass, token exposure |
| **High** | `>=7` | Permission escalation, crypto weakness, CI anomalies |
| **Medium** | `>=4` | New capabilities, external endpoints, service integrations |
| **Low** | `>=1` | Info-level findings, new dependencies |
| **None** | `0` | No issues detected |

### Security DNA

Security DNA shows the capability fingerprint of the repository across all scanned PRs. It tracks 14 dimensions:

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

### CI Integrity

The CI Integrity engine monitors for:

- **Step redistribution**: Workflow steps moving between jobs
- **Cache camouflage**: Cache keys being manipulated
- **Fingerprint churn**: CI job structure changing between commits
- **Synthetic telemetry**: Fake workflow events injected into the API
- **Evasion signals**: YAML anchors, merge tags, template variables
- **Campaign detection**: Cross-PR pattern analysis with weighted scoring

Baselines are computed using MAD (median absolute deviation) for robustness against poisoning. Three windows are maintained: 7-day, 30-day, and full history.

### Trust Drift

Trust Drift detects changes in the GitHub organization that affect security posture:

- New collaborators added to the repository
- New GitHub Apps installed
- New secrets added to environments
- New environments created
- New self-hosted runners
- Branch protection rule removals
- Permission escalations in workflow YAML files

### Dependency Deep Scan (EXPERIMENTAL)

Downloads dependency tarballs and diffs source files between versions. No semantic analysis, no domain extraction, no postinstall detection, no transitive dependency analysis.

## Policy File

A repository can optionally include `sentinel.policy.yml` at the root:

```yaml
allowed_runners:
  - ubuntu-latest
  - ubuntu-22.04
max_jobs: 10
allowed_actions:
  - actions/checkout@v4
  - actions/setup-node@v4
blocked_patterns:
  - "curl .* | bash"
  - "npm install --unsafe-perm"
enabled: true
```

## CLI Reference

```bash
sentinel-oracle                    Start the server (default)
sentinel-oracle start              Start the server
sentinel-oracle scan               Run a one-time security scan
sentinel-oracle --version, -v      Print version
sentinel-oracle --help, -h         Print help
```

## Security Considerations

### Trust Model

- The oracle server is trusted to hold merge credentials
- The workstation is untrusted (may be compromised)
- The phone is trusted solely for biometric identity proof
- Tailscale/WireGuard provides encrypted mesh networking

### Audit Trail

All merge operations are logged to an append-only SQLite table. The audit log includes timestamp, PR number, action type, and a detail field. No delete or update operations are performed on the audit log.

### Physical Security

- Store the oracle server in a physically secured location
- Do not expose SSH on the oracle to the public internet
- Keep the oracle OS updated
- Use full-disk encryption on the oracle

## Troubleshooting

### Server won't start

Check that port 8443 is available:
```bash
netstat -ano | findstr :8443
```

Verify configuration exists:
```bash
ls ~/.config/sentinel-oracle/
```

### GitHub API errors

Verify the private key is valid and the GitHub App has correct permissions. Check the GitHub App permissions page:
- Repository: Contents (Read & write), Pull requests (Read & write), Checks (Read), Metadata (Read)

### WebAuthn not working

- Ensure the phone is on the same Tailscale network as the oracle
- Check that the domain matches exactly (including port)
- WebAuthn requires HTTPS (self-signed is OK for Tailscale)

### No PRs showing

- Verify the GitHub App is installed on the repository
- Check the webhook is configured and delivering
- Run `sentinel-oracle scan` from the CLI to test connectivity

### Memory issues

Add `NODE_OPTIONS=--max-old-space-size=4096` to the environment:
```bash
set NODE_OPTIONS=--max-old-space-size=4096 && sentinel-oracle
```

## Maintenance

### Database Backup

```bash
copy ~/.config/sentinel-oracle/sentinel.db sentinel-backup.db
```

### Log Rotation

Server logs are written to stdout. Redirect to a file with the shell:
```bash
sentinel-oracle >> sentinel.log 2>&1
```

### Updates

```bash
cd sentinel-oracle
git pull
npm install
npm run build
```

## Architecture Summary

See [architecture.md](architecture.md) for full architectural documentation. See [api.md](api.md) for complete API reference.

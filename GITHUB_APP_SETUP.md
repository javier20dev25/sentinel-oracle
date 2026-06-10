# GitHub App Setup for Sentinel Oracle

Sentinel Oracle supports two authentication modes with GitHub:

| Mode | Token Lifespan | Scoped to | Risk if Leaked |
|------|---------------|-----------|---------------|
| **PAT (Personal Access Token)** | Permanent until revoked | User account | High — full access per scope |
| **GitHub App (recommended)** | 1 hour, auto-refreshed | Single installation | Low — time-limited, repo-scoped |

This guide covers GitHub App setup. Each Sentinel Oracle instance requires its own GitHub App installation.

---

## Step 1: Create a GitHub App

1. Go to **GitHub Settings > Developer settings > GitHub Apps > New GitHub App**
   (https://github.com/settings/apps/new)

2. Fill in the form:

   | Field | Value |
   |-------|-------|
   | **GitHub App name** | `sentinel-oracle-<your-org-or-name>` (must be unique) |
   | **Homepage URL** | `https://github.com/<owner>/<repo>` |
   | **Callback URL** | Leave empty |
   | **Webhook URL** | `https://<oracle-ip>:3443/api/webhook/github` (see note below) |
   | **Webhook secret** | Generate: `openssl rand -hex 32` (save this) |
   | **Active** | Yes |

3. Under **Repository Permissions**, set:

   | Permission | Level |
   |------------|-------|
   | Checks | **Read & write** |
   | Contents | **Read & write** (needed to merge PRs) |
   | Metadata | **Read** (always required) |
   | Pull requests | **Read & write** |
   | Commit statuses | **Read & write** |

4. Under **Organization Permissions** (if applicable):

   | Permission | Level |
   |------------|-------|
   | Members | **Read** (optional) |

5. Under **Where can this GitHub App be installed?**, select **Any account** or **Only on this account**.

6. Click **Create GitHub App**.

---

## Step 2: Generate a Private Key

1. After creating the app, scroll to the bottom of the app settings page.
2. Click **Generate a private key**.
3. A `.pem` file will be downloaded automatically.
4. Save this file to a secure location on your oracle server.

   ```
   C:\Users\sentinel\.sentinel-oracle\github-app-key.pem
   ```

   The file should look like:

   ```
   -----BEGIN RSA PRIVATE KEY-----
   MIIEpAIBAAKCAQEA...
   ...
   -----END RSA PRIVATE KEY-----
   ```

5. Set file permissions so only the oracle process can read it:
   - **Linux**: `chmod 600 /home/sentinel/.sentinel-oracle/github-app-key.pem`
   - **Windows**: Right-click > Properties > Security > Remove inheritance > Add your user only

---

## Step 3: Install the App on Your Repository

1. On the app settings page, scroll to **Install App** (left sidebar).
2. Click **Install** next to your account or organization.
3. Select **Only select repositories** and choose the repository(s) you want Sentinel Oracle to protect.
4. Click **Install**.

5. After installation, note the **Installation ID**:
   - Go to `https://api.github.com/app/installations` (authenticated with your personal account)
   - Find the installation for your app
   - The `id` field is your installation ID
   - Alternatively, the URL of your installation page contains the ID:
     `https://github.com/settings/installations/<INSTALLATION_ID>`

---

## Step 4: Configure Sentinel Oracle

Edit your `config.json` (`~/.sentinel-oracle/config.json`):

```json
{
  "githubAppId": "123456",
  "githubInstallationId": "654321",
  "githubPrivateKeyPath": "C:\\Users\\sentinel\\.sentinel-oracle\\github-app-key.pem",
  "githubOwner": "your-org-or-user",
  "githubRepo": "your-repo",
  "githubStatusContext": "Sentinel Authorization",
  "host": "0.0.0.0",
  "port": 3443
}
```

Remove the `githubToken` field if present — if both are provided, GitHub App mode takes precedence.

---

## Step 5: Configure Webhook Secret (Optional but Recommended)

In `config.json`:

```json
{
  "githubWebhookSecret": "your-openssl-generated-secret"
}
```

The webhook secret verifies that incoming webhooks are genuinely from GitHub. If you set a webhook URL during app creation, this is strongly recommended.

---

## Step 6: Configure Branch Protection

Branch protection must require the `Sentinel Authorization` status check:

1. Go to your repository **Settings > Branches > Add rule** (or edit existing).
2. Set **Branch name pattern**: `main`
3. Under **Protect matching branches**:
   - [x] **Require status checks to pass before merging**
   - [x] **Require branches to be up to date**
   - Status checks: search for and select **Sentinel Authorization**
   - [x] **Require pull request reviews before merging** (at least 1)
   - [x] **Dismiss stale pull request approvals when new commits are pushed**
   - [x] **Do not allow bypassing the above settings** (admins must pass too)
   - [ ] ~~Allow force pushes~~ (leave unchecked)
   - [ ] ~~Allow deletions~~ (leave unchecked)
4. Click **Create** or **Save changes**.

---

## How It Works

```
┌──────────────┐     JWT (RS256 signed)     ┌──────────────────┐
│  Oracle      │ ──────────────────────────> │  GitHub API      │
│  Server      │     POST /app/installations │  (api.github.com)│
│              │     /{id}/access_tokens     │                  │
│  generates   │ <────────────────────────── │                  │
│  JWT from    │     Installation Token      │                  │
│  private key │     (ghs_..., 1hr TTL)     │                  │
└──────────────┘                             └──────────────────┘
       │
       │  Uses installation token for all API calls:
       │  - GET /repos/{owner}/{repo}/pulls
       │  - POST /repos/{owner}/{repo}/statuses/{sha}
       │  - PUT /repos/{owner}/{repo}/pulls/{num}/merge
       │  - GET /repos/{owner}/{repo}/branches/main/protection
       ▼
┌──────────────┐
│  GitHub       │
│  Repository   │
└──────────────┘
```

### Token Lifecycle

1. Oracle server starts → reads private key from disk → generates JWT (RS256, 10 min TTL).
2. Exchanges JWT for installation token (POST to GitHub API).
3. Installation token is cached locally.
4. All GitHub API calls use the cached token.
5. When token is within 5 minutes of expiry, a new one is fetched automatically.
6. If token fetch fails, existing token is used until it expires, then operations fail.

### Security Properties

- **No long-lived secrets on disk**: Only the private key PEM file. Installation tokens are ephemeral.
- **No user account dependency**: GitHub App tokens represent the app, not a person.
- **Repository-scoped**: The app can only access repos it's installed on.
- **Auditable**: GitHub's audit log shows which app made each API call.
- **Auto-refreshing**: Tokens expire every hour, limiting exposure if leaked.

---

## Required Permissions Summary

| Permission | Purpose |
|-----------|---------|
| Pull requests: **Read & write** | List PRs, read PR metadata |
| Checks: **Read & write** | Read check run results, determine CI status |
| Commit statuses: **Read & write** | Set Sentinel Authorization status |
| Contents: **Read & write** | Merge pull requests via API |
| Metadata: **Read** | Access repo info (always required) |

---

## Verification

After setup, verify the app works:

```bash
# Start the oracle server
sentinel-oracle

# Expected output should include:
# [auth] Using GitHub App authentication
# GitHub App (sentinel-oracle) — installation token acquired
```

Then check the `/api/status` endpoint:

```json
{
  "authMode": "github_app",
  "uptime": 123.45,
  ...
}
```

And check `/api/status/branch-protection`:

```json
{
  "enabled": true,
  "requiredStatusChecks": ["Sentinel Authorization"],
  "adminEnforced": true,
  "secure": true,
  "issues": []
}
```

---

## Troubleshooting

| Problem | Likely Cause | Solution |
|---------|-------------|----------|
| `Failed to obtain installation token` | Private key mismatch or wrong app ID | Verify app ID in GitHub settings, regenerate key |
| `401 Bad credentials` | Installation token expired or invalid | Check system clock sync (NTP). Token refresh requires <5min clock skew |
| `403 Forbidden` during merge | Missing Contents permission | Check GitHub App permissions — Contents must be Read & write |
| `Branch not protected` | No branch protection rule | Create branch protection rule requiring Sentinel Authorization |
| Webhook returns 401 | Wrong webhook secret | Verify secret matches what's in config.json |

---

## Migrating from PAT to GitHub App

1. Complete Steps 1-3 above.
2. Edit `config.json` to add the GitHub App fields.
3. **Do not remove the `githubToken` field yet** — start the server to verify.
4. Once confirmed working, remove `githubToken` from `config.json`.
5. Revoke the old PAT from GitHub Settings > Tokens.

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
 | Contents | **Read** |
 | Metadata | **Read** (always required) |
 | Pull requests | **Read & write** |
 | Commit statuses | **Read** |

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
4. Abra el archivo con Notepad o cualquier editor de texto.

   El contenido se ve asi:

   ```
   -----BEGIN RSA PRIVATE KEY-----
   MIIEpAIBAAKCAQEA...
   ...
   -----END RSA PRIVATE KEY-----
   ```

5. **No necesita copiar el archivo al servidor.** En el setup web (paso 2 del formulario)
   hay un textarea donde puede pegar el contenido directamente. El servidor lo guarda solo.

   > Si prefiere usar la ruta del archivo: copie el .pem al servidor Oracle
   > (ej. `C:\Users\sleyt\.sentinel-oracle\app.private-key.pem`) y escriba la ruta
   > absoluta en el campo "Private Key File Path".

---

## Step 3: Install the App on Your Repository

1. On the app settings page, scroll to **Install App** (left sidebar).
2. Click **Install** next to your account or organization.
3. Select **Only select repositories** and choose the repository(s) you want Sentinel Oracle to protect.
4. Click **Install**.

5. **Obtenga el Installation ID** (importante: no esta en la pagina de la app):

   Hay dos formas de encontrarlo:

   **Forma A — Desde la pagina de la app:**
   - En `github.com/settings/apps/tu-app` → sidebar **Install App**
   - Al lado del repositorio instalado, haga click en el engranaje ⚙️ **Configure**
   - La URL del navegador cambia a: `https://github.com/settings/installations/<INSTALLATION_ID>`
   - Ejemplo: si la URL es `https://github.com/settings/installations/139924356`,
     el Installation ID es `139924356`

   **Forma B — Desde el repositorio:**
   - Vaya a `github.com/tu-org/tu-repo/settings`
   - Sidebar izquierdo → **GitHub Apps** (bajo "Integrations")
   - Al lado de "Sentinel Oracle" → click **Configure**
   - Misma URL: `https://github.com/settings/installations/<INSTALLATION_ID>`

   > :warning: NO es el App ID (`4119820`) ni el Client ID (`Iv23li...`).
   > El Installation ID es un numero distinto que solo aparece DESPUES de instalar
   > la app en un repositorio.

---

## Step 4: Configure Sentinel Oracle

### Opcion A — Usando el setup web (recomendado)

Abra `https://{IP_TAILSCALE}:3443/setup` en un navegador. El formulario paso a paso le
pedira: Owner, Repository, App ID, Installation ID, y Private Key.

En el campo de Private Key tiene dos alternativas:
- **Pegar el contenido**: Abra el .pem con Notepad, copie todo (incluyendo `-----BEGIN` y
  `-----END`), y peguelo en el textarea "O pega el contenido del PEM directamente"
- **Ruta de archivo**: Copie el .pem al servidor y ponga la ruta absoluta

### Opcion B — Editando config.json directamente

```json
{
  "githubAppId": "4119820",
  "githubInstallationId": "139924356",
  "githubPrivateKeyPath": "C:\\Users\\sleyt\\.sentinel-oracle\\github-app-key.pem",
  "githubOwner": "tu-org",
  "githubRepo": "tu-repo",
  "githubStatusContext": "Sentinel Authorization",
  "host": "0.0.0.0",
  "port": 3443
}
```

> Si usa la Opcion B, el archivo .pem DEBE existir en la ruta especificada en el servidor.
> En Windows use doble backslash `\\` en la ruta.

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

| Permission | Level | Endpoints Used | Purpose |
|-----------|-------|---------------|---------|
| Pull requests | **Read & write** | `GET /pulls`, `GET /pulls/{n}/files`, `PUT /pulls/{n}/merge` | List PRs, read diff files, merge PRs |
| Checks | **Read & write** | `GET /commits/{sha}/check-runs`, `POST /check-runs`, `PATCH /check-runs/{id}` | Read CI status, create/update "Sentinel Authorization" check |
| Contents | **Read** | `GET /compare/{base}...{head}`, `GET /commits` | Compare diffs for scanning, file history |
| Commit statuses | **Read** | `GET /commits/{sha}/status` | Read combined commit status (CI pass/fail) |
| Metadata | **Read** (auto) | `GET /repos/{owner}/{repo}` | Repository info (always auto-granted by GitHub) |

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
| `403 Forbidden` during merge | Missing Pull requests write permission | Check GitHub App permissions — Pull requests must be Read & write |
| `Branch not protected` | No branch protection rule | Create branch protection rule requiring Sentinel Authorization |
| Webhook returns 401 | Wrong webhook secret | Verify secret matches what's in config.json |

---

## Migrating from PAT to GitHub App

1. Complete Steps 1-3 above.
2. Edit `config.json` to add the GitHub App fields.
3. **Do not remove the `githubToken` field yet** — start the server to verify.
4. Once confirmed working, remove `githubToken` from `config.json`.
5. Revoke the old PAT from GitHub Settings > Tokens.

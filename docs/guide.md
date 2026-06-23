# Sentinel Oracle Operational Guide

## Overview

Sentinel Oracle is a physically isolated merge authorization server for GitHub. Merge credentials live on a dedicated device (the oracle) on your local network. The development workstation never holds the authority to merge.

This guide covers installation, configuration, operation, and troubleshooting.

## Prerequisites

Complete estos pasos **antes** de iniciar el servidor por primera vez.

### 1. Hardware

| Dispositivo | Requisito | Rol |
|-------------|-----------|-----|
| **Oracle server** | Raspberry Pi 4/5 (4GB+), NUC, mini PC, PC viejo, o Android con Termux | Ejecuta el servidor, tiene las credenciales de merge |
| **Phone** | Smartphone con biometricos (Face ID, huella) | Aprueba merges con WebAuthn |
| **Workstation** | Cualquier maquina con navegador web | Maquina de desarrollo diario, solo lectura |

### 2. Tailscale (obligatorio)

Instale Tailscale en los 3 dispositivos. Sentinel Oracle necesita una red mesh
privada — no funciona con IP publica.

```bash
# En cada dispositivo:
# 1. Descargar e instalar desde https://tailscale.com/download
# 2. Autenticar:
tailscale up

# 3. Verificar que los 3 dispositivos se ven:
tailscale status

# 4. (Opcional) HTTPS valido sin certificado autofirmado:
#    En el oracle server:
sudo tailscale serve --bg 3443
```

La IP de Tailscale (100.x.x.x) se autodetecta al iniciar el servidor.

### 3. Node.js

```bash
node --version   # Requiere >= 20
```

### 4. GitHub App

Cree una GitHub App antes de iniciar el servidor (ver [GITHUB_APP_SETUP.md](GITHUB_APP_SETUP.md)).
Necesitara:
- **App ID** (pagina principal de la app)
- **Installation ID** (de la URL al instalar la app en tu repo)
- **Private Key** (archivo .pem, descargado al crear la app)

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

## First Run

### 1. Iniciar el servidor

```bash
sentinel-oracle
```

Si es la primera vez, el servidor arranca en **modo setup** (sin GitHub configurado).
Abra `https://{IP_DE_TAILSCALE}:3443/setup` en un navegador desde su workstation.

> **Nota**: Si el puerto 3443 ya esta en uso: `taskkill /F /IM node.exe`

### 2. Configurar GitHub App (paso a paso en la web)

Necesita estos 3 datos antes de empezar:

#### App ID
- En `github.com/settings/apps` → click en su app
- El **App ID** aparece en la parte superior de la pagina
- Copielo (ej. `4119820`)

#### Private Key
- En la pagina de su app, scroll abajo → **Generate a private key**
- Se descarga un archivo `.pem`
- En el setup web tiene **dos opciones**:
  - **Opcion A** (recomendada): Abra el .pem con Notepad, copie todo el contenido, y peguelo en el textarea "O pega el contenido del PEM directamente"
  - **Opcion B**: Copie el archivo .pem al servidor Oracle y ponga la ruta absoluta (ej. `C:\Users\sleyt\.sentinel-oracle\app.private-key.pem`)

#### Installation ID (el que falta)
Este NO esta en la pagina de la app. Se obtiene al **instalar** la app en su repositorio:

1. En la pagina de su app → sidebar izquierdo → **Install App**
2. Al lado de su organizacion/usuario → click **Install**
3. Seleccione el repositorio → **Install**
4. **Despues de instalar**, haga click en el engranaje ⚙️ al lado del repositorio instalado
5. La URL del navegador sera: `https://github.com/settings/installations/<AQUI_EL_ID>`
6. Copie ese numero (ej. `139924356`)

**Alternativa**: Vaya a su repositorio en GitHub → Settings → GitHub Apps (sidebar)
→ "Configure" al lado de Sentinel Oracle → misma URL con el ID.

### 3. Llenar el formulario web

En `https://{IP_TAILSCALE}:3443/setup` paso 2:

| Campo | Que poner |
|-------|-----------|
| **Owner** | Su usuario u organizacion de GitHub |
| **Repository** | Nombre del repo (sin el owner) |
| **App ID** | `4119820` (el numero de arriba) |
| **Installation ID** | El numero de la URL: `settings/installations/<AQUI>` |
| **Private Key** | Pegue el contenido del .pem O ponga la ruta del archivo |

### 4. Registrar el telefono (WebAuthn)

1. Despues de configurar GitHub, abra el dashboard en `https://{IP_TAILSCALE}:3443`
2. En el telefono (misma red Tailscale) abra la misma URL
3. Click **Register Device** → biometria (Face ID / huella)
4. El telefono queda registrado como dispositivo de autorizacion

### 5. Verificar

- El dashboard muestra los PRs abiertos de su repositorio
- Los PRs aparecen en la cola con estado "awaiting authorization"
- Proceso completo: click Authorize → escanear QR con el telefono → biometria → merge

> **Importante**: Si el servidor ya tenia configuracion previa, reinicielo despues de cambiar la config:
> `Ctrl+C` → `sentinel-oracle`

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

## AI PR Intelligence

Sentinel Oracle includes an AI engine that analyzes pull requests and produces structured summaries, architectural insights, security-relevant observations, and review priorities.

### Setup

#### Option 1: Ollama (recommended)

```bash
# Install Ollama from https://ollama.com
# Pull a model
ollama pull qwen2.5:1.5b
# Verify
ollama list
```

The server auto-detects Ollama and lists available models in Settings > AI Intelligence.

#### Option 2: Local GGUF

Place a `.gguf` model file (e.g., Qwen 2.5 1.5B Instruct Q4_K_M) in:

```bash
mkdir -p ~/.sentinel/models
# Download a .gguf file and place it there
```

### Configuration

1. Open Settings > AI Intelligence in the dashboard
2. Toggle "Enable AI Analysis" on
3. (Optional) Enable "Auto-Analyze" to run AI on every new PR
4. Select a model from the dropdown — all detected models (Ollama + GGUF) are listed
5. Click Save

### How It Works

1. **Detection**: At startup and on status check, the server scans for Ollama CLI and `.gguf` files in `~/.sentinel/models/`
2. **Analysis**: When triggered, the AI reviews each file's diff, detects instruction manipulation, then aggregates findings into a structured report
3. **Sanitization**: All LLM output is cleaned server-side — bold, italic, code blocks, HTML tags, and links are stripped before storage
4. **Fallback**: If the LLM is unavailable (model not found, timeout, error), a deterministic analysis based on file metadata is used

### What the AI Detects

| Feature | Description |
|---------|-------------|
| Executive Summary | 2-4 bullet points summarizing the PR's purpose and scope |
| Architectural Changes | Cross-cutting changes with impact assessment |
| Security-Relevant Changes | Auth, secrets, permissions, crypto modifications |
| Dependency Changes | Package.json, requirements.txt, go.mod, etc. |
| Instruction Manipulation | Prompt injection, hidden instructions, role redefinition, config manipulation |
| Review Hotspots | Files flagged for manual review with specific reasons |
| Review Priority | Priority (low to critical), impact level, complexity |

### API

- `GET /api/ai/status` — Backend status, health, selected model
- `GET /api/ai/models` — List available models
- `POST /api/prs/:number/ai-analyze` — Run analysis on a PR (requires auth)

### Troubleshooting

**"No AI backend detected"**
- Verify Ollama is installed: `ollama --version`
- Verify at least one model is pulled: `ollama list`
- For GGUF: verify files exist in `~/.sentinel/models/`

**"Model not found" health check failure**
- For Ollama: run `ollama show <model>` to verify the model is downloaded
- For GGUF: check the file path in the model list

**Slow analysis**
- Ollama models run locally — Qwen 2.5 1.5B typically takes 2-10s
- Larger models (7B+) will be significantly slower

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

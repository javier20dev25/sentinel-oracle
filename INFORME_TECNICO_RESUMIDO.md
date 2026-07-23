# Informe Técnico Resumido — Sentinel CLI + Sentinel Oracle

**Fecha:** 23 de julio de 2026
**Autor:** Javier Astaroth
**Proyectos:** sentinel-cli (v4.0.0) · sentinel-oracle (v2.x)

---

## 1. Resumen Ejecutivo

Este informe documenta el trabajo realizado en dos sesiones sobre los repositorios `sentinel-cli` y `sentinel-oracle`. Se completaron 5 commits, 1 force-push, y se añadieron ~2,000 líneas de código y documentación.

| Proyecto | Commits | Líneas añadidas | Archivos modificados |
|----------|---------|-----------------|---------------------|
| sentinel-cli | 2 | ~850 | 28 |
| sentinel-oracle | 2 | ~2,000 | 14 |

---

## 2. Cambios en Sentinel CLI

### 2.1 Reescritura del README (commit d791698)

El README anterior estaba desactualizado y centrado exclusivamente en build intelligence. Se reescribió para reflejar las 10 capacidades del producto como co-iguales:

| # | Capacidad | Descripción |
|---|-----------|-------------|
| 1 | **SAST** | 30 reglas deterministas (secrets, eval, inyección, crypto) |
| 2 | **Supply Chain** | CVE (OSV.dev), typosquat, provenance, reputación registry |
| 3 | **Network Auditor** | 31 clasificadores de comportamiento, evidencia SHA-256 |
| 4 | **Build Intelligence** | Observación de builds, trust scoring, explicabilidad |
| 5 | **GitHub Integration** | PR Bot, audit de PRs, Check Runs |
| 6 | **System Integrity** | Verificación chain-of-trust, baseline, permissions |
| 7 | **Sentinel Guard** | Intercepción OS-level de npm/yarn/pip |
| 8 | **Threat Memory** | Signal Vault para inteligencia de amenazas |
| 9 | **Red Team** | 26 escenarios, 10 campañas, Atomic RT |
| 10 | **Hub + MCP** | TUI interactivo, 17 herramientas MCP |

Secciones añadidas al README:
- Tabla de navegación ("I want to... Go to")
- Tabla de madurez por área
- "What Sentinel Does NOT Do" (limitaciones honestas)
- Design Philosophy (6 principios)
- Tabla comparativa con CodeQL/Snyk/Trivy/Falco/Sysmon/Sigstore
- Use Cases con 10 escenarios reales
- Demo con output real de `build observe` y `pr-audit`
- Benchmark numbers con cobertura por corpus
- Evidence Trust Hierarchy (Tier 1-4)
- Documentation index con 10 documentos

### 2.2 Rename del comando global (commit 706d1d6)

**Problema:** El comando global era `sentinel` (definido en `package.json` bin field). El usuario intentaba ejecutar `sentinel-hub` que no existía.

**Solución:** Cambiar `bin.sentinel` → `bin.sentinel-cli` en `package.json`.

**Alcance:** 23 archivos modificados:
- `package.json` — bin field
- `README.md` — todas las referencias de comando
- `INFORME_TECNICO_v2.md` — referencias
- 6 docs (`BUILD_INTELLIGENCE.md`, `NETWORK_AUDITOR.md`, `SKILLS.md`, `TRUST_MODEL.md`, `build-flight-recorder.md`, `recording-guide.md`, `replay-system.md`)
- 7 skill adapters (`claude`, `cline`, `codex`, `cursor`, `gemini`, `opencode`, `roo`, `windsurf`)
- 3 fixtures de agentes (`safe/GEMINI.md`, `safe/CLAUDE.md`, `dangerous/CLAUDE.md`)
- `CONSTITUTION.md`, `GENERIC.md`

### 2.3 Correcciones menores

| Archivo | Cambio |
|---------|--------|
| `ARCHITECTURE.md` | Test count 901 → 1040 |
| `LICENSE` | "Sentinel Security Oracle CLI" → "Sentinel CLI" |
| `.gitignore` | Añadido `test-output.txt` |
| `docs/SKILLS.md` | "Oracle dependency" → "external dependency" |

---

## 3. Cambios en Sentinel Oracle

### 3.1 Commits existentes (commit 6f2b76b — pre-push)

Se confirmaron y pushearon cambios locales previos que contenían:

**Backend (server.ts + database.ts):**
- `GET /api/scans` — listado de resultados de scan
- `POST/GET /api/prs/:number/ai-explain` — guardar/cargar explicaciones AI
- Sistema de blacklist de PRs (add/remove/list)
- `scanHash` incluido en respuestas de PR
- Tablas DB: `saved_explanations`, `blacklist_prs`

**AI Analyzer (analyzer.ts):**
- Detección de contaminación de prompts (`isResponseContaminated`)
- Fallback mejorado para `explainPR` — clasifica archivos por dominio (frontend/backend/security/config/infra/deps/tests)
- Fallback mejorado para `explainScanFindings` — agrupa por categoría/archivo, detecta inyección/secrets/XSS/SQL/path traversal
- Validación de respuestas LLM

**Scanner Intel (intel/index.ts):**
- Security delta ahora incluye nombres de módulos en el output

**Frontend (app.js, index.html, style.css):**
- Actualizaciones UI para nuevas features
- Nuevo logo

### 3.2 Build Intelligence para PR Scan (commit 6a6d53e)

**Nuevo módulo:** `src/scanner/build-intel.ts` (400 líneas)

Analiza diffs de PR para señales de seguridad de build:

| Señal | Ejemplos detectados | Riesgo |
|-------|-------------------|--------|
| **Build Tools** | Docker, GitHub Actions, Terraform, Make | low-medium |
| **Build Scripts** | Shell execution, network access, destructive ops | low-high |
| **Dependency Changes** | Wildcard versions, range specifiers | low-high |
| **Supply Chain** | Lifecycle scripts, unpinned versions, eval | medium-critical |
| **CI/CD Changes** | pull_request_target, mutable refs, excessive perms | low-critical |
| **Process Indicators** | exec(), spawn(), child_process | high |
| **Network Indicators** | fetch(), axios, HTTP clients | low-medium |

**Scoring:**
- Trust Score: 0-100 (100 = limpio, penalizado por cada señal)
- Verdict: `CLEAN` (≥70, sin critical/high) | `REVIEW` (<70 o high) | `CRITICAL` (cualquier critical)

**Integración:**
- `scanner/index.ts`: `analyzeBuildIntelligence()` se ejecuta automáticamente en cada PR scan
- Frontend scan panel: sección inline con tools, supply chain, CI/CD, process indicators
- Full report modal: tablas detalladas para cada tipo de señal

---

## 4. Estado de los repositorios

| Repositorio | Branch | Estado | Último commit |
|-------------|--------|--------|---------------|
| sentinel-cli | master | ✅ Pushed | `706d1d6` — refactor: rename global command |
| sentinel-oracle | main | ✅ Pushed | `6a6d53e` — feat: add Build Intelligence |

---

## 5. Commits realizados

```
sentinel-cli:
  d791698  docs: rewrite README to reflect full Sentinel platform
  706d1d6  refactor: rename global command from 'sentinel' to 'sentinel-cli'

sentinel-oracle:
  6f2b76b  feat: enhanced AI explanations, scan history, blacklist
  6a6d53e  feat: add Build Intelligence to PR scan results
```

---

## 6. Métricas de calidad

| Métrica | Sentinel CLI | Sentinel Oracle |
|---------|-------------|-----------------|
| Tests | 1,040 (53 suites) | Pendiente |
| TypeScript errors | 0 | 0 |
| Archivos modificados | 28 | 14 |
| Líneas añadidas | ~850 | ~2,000 |

---

*Informe generado automáticamente — opencode/big-pickle*

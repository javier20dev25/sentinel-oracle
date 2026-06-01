# Sentinel Oracle Core — CLI 2

> AI-Powered Security Assistant · SAST Scanner · SecuriGit · MCP Protocol · Threat Intelligence

Sentinel Oracle Core is an open-source, local-first AI security assistant. It combines a static analysis engine (LiteScanner, 30 SAST rules) with a multi-provider AI Oracle that reasons about threats, queries GitHub via SecuriGit, explores supply chains, and guides remediation — all from your terminal.

```
┌──────────────────────────────────────────────────────────────┐
│  Welcome to Sentinel Oracle Core v4.0                        │
│  CLI 2 · Multi-Provider · Tool-Orchestrated · Permissions    │
└──────────────────────────────────────────────────────────────┘
```

---

## Features

### 🔬 LiteScanner (30 SAST Rules)
Detect secrets, unsafe code, network exfiltration, env leaks, and supply chain risks in any codebase or PR diff.

### 🤖 Oracle AI Assistant
Chat with a security-specialized AI via Gemini, Claude, OpenAI, or Ollama. The Oracle has 16+ tools, multi-step reasoning, and a permission system.

### 🔬 MCP Protocol
Model Context Protocol server lets Claude Desktop, Cursor, Cline and other AI tools query Sentinel's 12 security tools directly via stdio JSON-RPC.

### 🔗 GitHub Integration
Scan PRs, view diffs, post findings as comments — all through `gh` with your existing GitHub authentication.

### 🧠 Local Threat Intelligence
SQLite-based threat database that correlates findings by author, pattern, and signature. Learns from every scan.

### 👥 Specialized Agents
- **Blue Team** — defensive posture, remediation-focused
- **Red Team** — offensive mindset, attack chain analysis
- **Auditor** — compliance mapping (OWASP, CWE, NIST, ISO 27001, SOC2, PCI-DSS)

### 🔐 Prompt Injection Defense
Three-layer protection: data markers, system prompt rules, and semantic validation. Prevents attackers from silencing findings.

### 📊 Reports & Audit
Export findings as Markdown or JSON. Local audit dashboard shows rules, threats, permissions, and system health.

---

## Quick Start

```bash
# Install globally
npm install -g @sentinel/cli

# Quick scan
sentinel scan ./src --json

# Start the Oracle AI
sentinel oracle

# Scan a PR diff
gh pr diff 42 | sentinel pr-scan
```

### Oracle Interactive Mode

```bash
sentinel oracle
```

This launches the interactive terminal UI:

```
oracle> scan my project for secrets
```

The Oracle will:
1. Suggest running `scan` on your project
2. Request your permission (Enter/Esc/A)
3. Execute the scan
4. Analyze and explain every finding with evidence

### Commands

| Command | Description |
|---------|-------------|
| `sentinel` | Launch Oracle interactive session (default) |
| `sentinel scan <path>` | SAST scan with 30 rules |
| `sentinel doctor [--deep]` | System health check |
| `sentinel integrity` | Verify host integrity |
| `sentinel oracle` | Interactive AI Oracle session |
| `sentinel oracle ask <question>` | One-shot AI query |
| `sentinel oracle auth set <provider> <key>` | Configure API key |

### SecuriGit — GitHub Security Module

Sentinel's GitHub integration is branded as **SecuriGit**. All tools use your existing `gh` authentication:

| Tool | Description |
|------|-------------|
| `gh-pr-list` | List open PRs with details |
| `gh-pr-view` | View PR info, files, reviewers |
| `gh-pr-diff` | Get raw diff piped into SAST scanning |
| `gh-pr-comment` | Post security report as comment |
| `gh-repo-list` | List repos for user/org |

The CI/CD PR Bot auto-scans every PR in GitHub Actions using SecuriGit.

### Oracle Slash Commands

Press `Tab` to autocomplete. Key commands:

- `/mode plan|execute|auto` — Change Oracle behavior
- `/agent set blue|red|auditor|default` — Switch agent
- `/tono` — Interactive tone selector
- `/findings` — Show last scan results in formatted box
- `/audit` — Local database and system audit
- `/guard` — Connection security check
- `/report md|json [file]` — Generate reports
- `/cli1-import` — Import from CLI v1
- `/rule add|remove|list|toggle` — Custom rules
- `/threat list|query|correlate` — Threat intelligence

---

## Providers

Configure any of these via `sentinel oracle auth set <provider> <key>`:

| Provider | Models |
|----------|--------|
| **Gemini** | `gemini-2.0-flash`, `gemini-2.0-pro`, `gemini-1.5-pro` |
| **Claude** | `claude-sonnet-4-20250514`, `claude-3-opus`, `claude-3-haiku` |
| **OpenAI** | `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, `gpt-3.5-turbo` |
| **Ollama** | `llama3`, `mistral`, `codellama`, `gemma2`, `phi3` |

Or set env vars: `SENTINEL_PROVIDER`, `SENTINEL_GEMINI_KEY`, etc.

---

## Requirements

- **Node.js** >= 18.0.0
- **npm** >= 9
- **Git** (for SecuriGit GitHub tools)
- **gh** CLI (for GitHub PR tools — optional)

---

## Architecture

```
sentinel/
├── src/
│   ├── cli/               # CLI commands + intelligence modules
│   │   ├── main.ts        # Commander entry point
│   │   ├── pr_scan.ts     # PR diff scanning
│   │   ├── guard.ts       # Connection guard
│   │   ├── classify.ts    # Document classification
│   │   ├── hub.ts         # Interactive hub
│   │   └── intelligence/  # Signal vault, integrity, baselines, etc.
│   ├── oracle/            # AI Oracle core
│   │   ├── engine.ts      # Chat loop, tool orchestration, modes
│   │   ├── tools.ts       # 16+ tool definitions
│   │   ├── command.ts     # Interactive CLI + slash commands
│   │   ├── providers/     # AI provider implementations
│   │   │   ├── gemini.ts  # Google Gemini
│   │   │   ├── claude.ts  # Anthropic Claude
│   │   │   ├── openai.ts  # OpenAI / Azure
│   │   │   └── ollama.ts  # Local Ollama
│   │   ├── auth.ts        # API key management
│   │   ├── agents/        # Blue/Red/Auditor agents
│   │   ├── prompt_guard.ts # Anti-injection defense
│   │   ├── threat_db.ts   # SQLite threat intelligence
│   │   ├── cli1_bridge.ts # CLI v1 migration
│   │   ├── viz.ts         # Terminal UI components
│   │   ├── spinner.ts     # Animated spinner
│   │   └── mcp_server.ts  # MCP protocol server
│   └── core/lite/         # LiteScanner SAST engine
├── .github/workflows/     # CI/CD + PR Bot
├── vitest.config.ts       # Test configuration
└── package.json
```

---

## License

**Business Source License 1.1** — see [LICENSE](./LICENSE).

- Free to use, modify, and redistribute
- Cannot be used as a competing Security Tool or Service

## Legal

See [LEGAL.md](./LEGAL.md) for:
- **Privacy Policy** — what data is collected, stored, and retained
- **Terms & Conditions** — license terms, acceptable use, disclaimers
- **Compliance** — data retention, GDPR, security framework alignment
- **Intellectual Property** — ownership, trademarks, third-party components
- Changes to GPL v2.0 on Change Date (2030-05-20)

---

## Security

Found a vulnerability in Sentinel itself? **Do not open a public issue.** Email: `javier20dev25@sentinel.security`

---

*Built for developers who take security seriously.*

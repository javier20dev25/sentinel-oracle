# Sentinel Oracle Core — Architecture

## Overview

Sentinel Oracle Core (CLI 2) is an AI-powered security assistant built on top of the original Sentinel CLI (CLI 1).
It provides a multi-provider AI orchestration layer that invokes deterministic tools (scan, doctor, integrity, gh-*)
and streams responses through an Ink 7 TUI.

## CLI 1 (Original Sentinel) vs CLI 2 (Oracle Core)

| Aspect | CLI 1 | CLI 2 (Oracle Core) |
|--------|-------|---------------------|
| Entry point | `src/cli/main.ts` | Same binary — `sentinel` launches Oracle interactive by default |
| Scanner | `LiteScanner` (30 SAST rules) | Same scanner, invoked as tool |
| User interface | Raw terminal output | Ink 7 TUI (React 19) + readline fallback |
| Intelligence | Static `verify-pkg`, `doctor` | AI orchestrates tools, correlates findings, streams analysis |
| Data | Individual scan results | Threat DB (SQLite), Signal Vault, Integrity Chain |
| GitHub | None | SecuriGit: `gh-pr-list`, `gh-pr-view`, `gh-pr-diff`, `gh-pr-comment`, `gh-repo-list` |
| Config | `~/.sentinel/config.json` | Same — shared with CLI 1 |
| MCP | None | Model Context Protocol server for Claude Desktop/Cursor/Cline |

## Directory Structure

```
src/
├── cli/                          # CLI 1 commands (Commander-based)
│   ├── main.ts                   # Binary entry point: scan, doctor, integrity, oracle subcommands
│   └── intelligence/             # CLI 1 intelligence subsystems
│       ├── integrity_chain.ts    # Persistent integrity chain with verified uptime
│       ├── integrity_manager.ts  # Host integrity verification
│       ├── signal_vault.ts       # Local SQLite vault for scan history
│       └── system_auditor.ts     # System health auditor (doctor command)
├── core/
│   └── lite/
│       └── lite_scanner.ts       # 30-rule SAST scanner (core detection engine)
├── oracle/                       # CLI 2 — Oracle Core
│   ├── engine.ts                 # Orchestration engine: oracleChat, oracleChatStream
│   ├── tools.ts                  # 18 tool definitions + runTool dispatch
│   ├── auth.ts                   # Provider API key management
│   ├── command.ts                # Interactive mode: slash commands, permission system
│   ├── providers/                # AI provider implementations
│   │   ├── base.ts               # Abstract BaseProvider, Message, ToolCall, ChatChunk, ChatResponse, ToolDef
│   │   ├── gemini.ts             # Google Gemini provider
│   │   ├── claude.ts             # Anthropic Claude provider
│   │   ├── openai.ts             # OpenAI provider (also base for Ollama)
│   │   ├── ollama.ts             # Local Ollama (extends OpenAI provider)
│   │   └── qwen.ts               # Qwen local GGUF via node-llama-cpp
│   ├── ui/                        # Ink 7 TUI (React 19)
│   │   ├── renderer.tsx          # Ink render entry point (startUI)
│   │   ├── app.tsx               # App component: loading → setup → ready phases
│   │   ├── bridge.ts             # ChatBridge — connects UI ↔ engine
│   │   ├── chat-input.ts         # Readline-based multi-line chat input
│   │   ├── components/
│   │   │   ├── chat.tsx          # Main Chat component (message list + input)
│   │   │   ├── message.tsx       # Message renderer (user/assistant/tool/system/error)
│   │   │   ├── splash.tsx        # Splash screen
│   │   │   ├── welcome.tsx       # Provider setup wizard
│   │   │   └── status-bar.tsx    # Status bar component
│   │   └── styles.ts             # Shared TUI styles
│   ├── agents/index.ts           # Agent system: Default, Blue Team, Red Team, Auditor
│   ├── cli1_bridge.ts            # CLI 1 data detection and import
│   ├── config_migration.ts       # Config import/export
│   ├── gh_guard.ts               # Connection security guard (machine → gh → GitHub)
│   ├── mcp_server.ts             # Model Context Protocol server
│   ├── prompt_guard.ts           # 3-layer anti-injection: data markers, rules, validation
│   ├── rules.ts                  # Custom rules engine
│   ├── threat_db.ts              # Local SQLite threat intelligence DB
│   ├── tono.ts                   # Tone/mood system + terminal modal selector
│   ├── reports.ts                # Markdown/JSON report generation
│   ├── spinner.ts                # Terminal spinner
│   └── viz.ts                    # Terminal visualization: attack chains, severity charts, etc.
├── test-setup.ts                 # Global test setup
web/
└── index.html                    # Landing page for the project
```

## Component Relationships

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        USER TERMINAL                                     │
│  sentinel [scan|doctor|integrity]  │  sentinel (Oracle interactive)     │
└────────────────────────┬────────────────────────┬───────────────────────┘
                         │                        │
                         ▼                        ▼
┌──────────────────────────────────┐  ┌──────────────────────────────────┐
│         CLI 1 (Commander)        │  │      CLI 2 — Oracle Core         │
│  src/cli/main.ts                 │  │  src/oracle/                     │
│                                  │  │                                  │
│  scan  → LiteScanner             │  │  Ink 7 TUI (React 19)           │
│  doctor → SystemAuditor          │  │  ├── App (splash → setup → chat)│
│  integrity → IntegrityManager    │  │  ├── Chat (message list)         │
│  verify-pkg → npm pack + scan    │  │  ├── ChatInput                   │
│  check-classified → DB check     │  │  └── Message renderer            │
│  memory → Signal Vault SQLite    │  │              │                   │
└──────────────────────────────────┘  │              ▼                   │
                                      │  ┌────────────────────┐         │
                                      │  │    ChatBridge      │         │
                                      │  │  bridge.ts         │         │
                                      │  │  ┌─ sendMessage()  │         │
                                      │  │  ├─ /slash cmds    │         │
                                      │  │  └─ permission mgmt│         │
                                      │  └────────┬───────────┘         │
                                      │           ▼                     │
                                      │  ┌────────────────────┐         │
                                      │  │   Engine (engine.ts)│         │
                                      │  │  oracleChatStream() │         │
                                      │  │  buildSystemPrompt()│         │
                                      │  └────────┬───────────┘         │
                                      │           ▼                     │
                                      │  ┌────────────────────┐         │
                                      │  │    Providers       │         │
                                      │  │  Gemini / Claude   │         │
                                      │  │  OpenAI / Ollama   │         │
                                      │  │  Qwen (local GGUF) │         │
                                      │  └────────┬───────────┘         │
                                      │           ▼                     │
                                      │  ┌────────────────────┐         │
                                      │  │  tools.ts (18)     │         │
                                      │  │  runTool()         │         │
                                      │  └────────┬───────────┘         │
                                      └───────────┼─────────────────────┘
                                                  │
                    ┌─────────────────────────────┼──────────────────────┐
                    │                             │                      │
                    ▼                             ▼                      ▼
         ┌──────────────────┐         ┌──────────────────┐   ┌──────────────────┐
         │  Sentinel CLI    │         │    GitHub CLI    │   │  External APIs   │
         │  (subprocess)    │         │  gh pr list,     │   │                  │
         │  scan, doctor,   │         │  gh pr diff,     │   │  Sentinel API    │
         │  verify-pkg,     │         │  gh pr comment,  │   │  /api/scan/pr    │
         │  integrity, etc. │         │  gh repo list    │   │                  │
         └──────────────────┘         └──────────────────┘   └──────────────────┘
```

## External Dependencies

| Dependency | Purpose |
|---|---|
| `Sentinel CLI` | Subprocess invoked by tools: `scan`, `doctor`, `verify-pkg`, `integrity`, `memory`, `check-classified`, `classify` |
| `GitHub CLI (gh)` | Subprocess invoked by SecuriGit tools: `gh-pr-list`, `gh-pr-view`, `gh-pr-diff`, `gh-pr-comment`, `gh-repo-list` |
| `~/.sentinel/config.json` | Shared config between CLI 1 and CLI 2 (providers, keys, model) |
| `~/.sentinel/threats.db` | SQLite threat intelligence DB (authors, patterns, correlations) |
| `~/.sentinel/vault/signal_vault.db` | Signal Vault from CLI 1 for scan history |
| `~/.sentinel/classified/` | Classified documents database |
| AI Provider APIs | Gemini, Claude, OpenAI — HTTPS REST; Ollama/Qwen — local |

## Data Flow

1. User runs `sentinel` → `oracleInteractive()` → `startUI()` → Ink renders `App`
2. `App` initializes `ChatBridge`, detects provider, transitions through Splash → Setup → Chat
3. User types in `Chat` component → calls `ChatBridge.sendMessage(text)`
4. Bridge handles `/slash` commands or forwards to `oracleChatStream()`
5. Engine builds system prompt (rules + tone + agent), calls provider's `stream()`
6. Provider returns text chunks + optional tool calls
7. Engine executes tools via `runTool()` → subprocess → wraps output in data markers
8. Tool results fed back to AI for next iteration (up to 5 iterations)
9. Final response streamed back through Bridge → UI

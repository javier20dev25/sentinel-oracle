# Sentinel Oracle -- AI-Native Security Assistant

## Abstract

Orchestration layer for multi-provider AI-assisted code security analysis.
Extends the deterministic Sentinel scanner engine with contextual reasoning
via large language model integration, MCP (Model Context Protocol) server
capabilities, and interactive audit workflows.

## Table of Contents

1. [Architecture](#architecture)
2. [Providers](#providers)
3. [MCP Server](#mcp-server)
4. [Agent System](#agent-system)
5. [Slash Commands](#slash-commands)
6. [CLI Reference](#cli-reference)
7. [License](#license)

## Architecture

Sentinel Oracle operates as a proxy layer between the user and the deterministic
Sentinel engine (CLI 1). All AI requests pass through a validation pipeline that
enforces prompt boundaries, injects system context, and audits responses for
integrity compliance.

### Request Pipeline

1. **Input Routing** -- parses slash commands and natural language
2. **Context Assembly** -- builds system prompt with file context, scan results, and agent persona
3. **Provider Dispatch** -- routes to configured LLM provider (OpenAI, Anthropic, Google, Ollama)
4. **Response Validation** -- integrity chain check, content safety filter
5. **Audit Logging** -- persists request/response pair to local SQLite store

## Providers

| Provider | Protocol | Models | Auth Method |
|----------|----------|--------|-------------|
| OpenAI | HTTP/REST | GPT-4o, GPT-4o-mini | API key |
| Anthropic | HTTP/REST | Claude 3.5 Sonnet, Claude 3 Opus | API key |
| Google Gemini | gRPC/REST | Gemini 1.5 Pro, Gemini 1.5 Flash | API key |
| Ollama | HTTP/REST | Any local model | None (local) |

Provider failover: if primary provider returns non-2xx, Oracle falls back
to the next configured provider in priority order.

## MCP Server

Implements the Model Context Protocol specification for integration with
MCP-compatible AI IDEs (Claude Desktop, Cursor, Cline).

### Tools Exposed

| Tool | Input | Output |
|------|-------|--------|
| `scan_path` | path: string, scanners: string[] | ScanOutput JSON |
| `verify_dependency` | name: string, registry?: string | VerificationResult |
| `query_threat_intel` | query: string | ThreatIntel[] |
| `pr_scan` | diff: string | ScanOutput |

## Agent System

Four agent personas, each with distinct system prompt and temperature:

| Agent | Temperature | Role |
|-------|-------------|------|
| Blue | 0.1 | Defensive analysis, vulnerability assessment |
| Red | 0.7 | Offensive security, penetration testing support |
| Auditor | 0.3 | Compliance verification, code review |
| Default | 0.3 | General assistance, code explanation |

## Slash Commands

| Command | Args | Description |
|---------|------|-------------|
| `/ask` | free text | Query any configured AI model |
| `/auth` | --provider, --set-key | Configure authentication for a provider |
| `/scan` | path, --json | Run scan and discuss results |
| `/audit` | path | Full audit with integrity chain verification |

## CLI Reference

```
npx @sentinel/oracle [command] [options]
```

### Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `ask [prompt]` | `--provider`, `--model` | Send prompt to AI provider |
| `scan [path]` | `--json`, `--provide-context` | Scan and analyze with AI |
| `mcp` | `--port` | Start MCP server |
| `interactive` | | Launch REPL session |

## Data Formats

### Audit Log Schema

```typescript
interface AuditEntry {
  id: string; // UUIDv4
  timestamp: string; // ISO 8601
  provider: string;
  model: string;
  prompt: string;
  response: string;
  integrityHash: string; // SHA-256 of (prompt + response + timestamp)
  verdict: 'PASS' | 'FLAGGED' | 'BLOCKED';
}
```

## License

Business Source License 1.1 -- see `LICENSE` for terms.
Change Date: 2030-05-20
Change License: GNU General Public License v2.0

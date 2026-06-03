# Sentinel Oracle -- AI-Native Security Assistant

Multi-provider AI assistant with local model support. No central API keys — each user brings their own or runs fully offline.

## Why Use It?

- **Bring your own key** — Gemini, Claude, OpenAI, Ollama, Anthropic
- **Or go fully local** — Qwen 2.5 via `node-llama-cpp`, no API key needed, no rate limits, 100% offline
- **Transparent provider system** — every provider is a standalone file. Add your own in minutes.
- **Interactive TUI** powered by Ink 7 + React 19 — no Electron bloat
- **MCP server** for AI IDE integration (Claude Desktop, Cursor, Cline)

## Getting Started

```bash
npx github:javier20dev25/sentinel-oracle
```

Or clone and run locally:

```bash
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install
npm run build
npm link --force
sentinel
```

Select a provider in the Welcome screen and you're in.

## Providers

### Cloud Providers (API key required)

| Provider | Models | How it works |
|----------|--------|-------------|
| Gemini | Gemini 2.0 Flash, Gemini 1.5 Pro | API key from Google AI Studio |
| Claude | Claude 3.5 Sonnet, Claude 3 Opus | API key from Anthropic |
| OpenAI | GPT-4o, GPT-4o-mini | API key from OpenAI |
| Ollama | Any local model via Ollama | No key, local server required |

### Local (no API key, no rate limits)

| Provider | Model | Size | How it works |
|----------|-------|------|-------------|
| **Qwen** | Qwen 2.5 1.5B Instruct (GGUF) | ~900 MB | Downloads on first select, cached at `~/.sentinel/models/`. 100% offline after that. |

> **Built by the community for the community.** The Qwen provider was contributed by [@sleyt](https://github.com/sleyt) — anyone can add a new provider by dropping a file into `src/oracle/providers/` and registering it in `index.ts`. No approval needed, no central coordination.

## Slash Commands

Available inside the chat TUI:

| Command | What it does |
|---------|-------------|
| `/logout` | Remove API key, return to Welcome screen |
| `/key` | Change API key and provider interactively |
| `/key <provider> <key>` | Set key and provider in one command |
| `/provider <name>` | Switch provider instantly |
| `/help` | Show help |

## Architecture

All AI requests route through a pipeline: User → Chat UI → Bridge → Engine → Provider → Tools → Response.

Providers are standalone modules implementing a `BaseProvider` interface — the same interface regardless of whether it's Gemini Cloud or Qwen running on your laptop. See `docs/` for full documentation:

- `docs/ARCHITECTURE.md` — component overview, data flow
- `docs/ORCHESTRATION.md` — request pipeline, state machine, streaming
- `docs/SKILLS.md` — available tools and parameters
- `docs/METHODS.md` — interfaces and types

## License

Business Source License 1.1 -- see `LICENSE` for terms.
Change Date: 2030-05-20
Change License: GNU General Public License v2.0

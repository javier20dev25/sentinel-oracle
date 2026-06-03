# Sentinel Oracle Core — Orchestration Flow

## Full Flow: User Input → AI → Tool → Result → AI → Response

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  USER types in Ink TUI                                                        │
│  ────────────────────────────                                                 │
│  Chat component (chat.tsx) captures input via useInput hook                   │
│  Calls: bridge.sendMessage(text)                                              │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  ChatBridge.sendMessage(text)  (bridge.ts)                                    │
│  ──────────────────────────────                                               │
│                                                                               │
│  STEP 1: Check pending interactive command (API key setup flow)               │
│   - If this.pendingCmd exists → handlePendingCmd(text)                        │
│     (multi-step provider/key input wizard)                                    │
│     Returns early without hitting AI                                          │
│                                                                               │
│  STEP 2: Check slash commands                                                 │
│   text.startsWith('/') → parse and handle:                                    │
│                                                                               │
│   ├── /key <provider> <key>     → Store API key + create provider            │
│   ├── /logout                   → Remove API key, restart                    │
│   ├── /provider <name>          → Switch active provider                     │
│                                                                               │
│   (All other /commands handled at CLI level in command.ts: 30+ commands)      │
│                                                                               │
│  STEP 3: If not a slash command → send to AI                                  │
│   - Push user message to conversationHistory                                  │
│   - Emit 'user' BridgeMessage via callbacks.onMessage()                       │
│   - Create empty 'assistant' BridgeMessage (thinking: true)                   │
│   - Get or create provider (getOrCreateProvider())                            │
│   - Call oracleChatStream(text, history, provider, permissionCb, mode)        │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  oracleChatStream()  (engine.ts)                                              │
│  ──────────────────────────────                                               │
│                                                                               │
│  STEP 4: Build conversation messages                                          │
│   - If no history: [systemPrompt, userInput]                                  │
│   - If has history: [...history, userInput]                                   │
│                                                                               │
│  systemPrompt built via buildSystemPrompt():                                  │
│   - Provider list from getToolDefs()                                          │
│   - 8 hard rules (no code mod, no arbitrary cmds, etc.)                       │
│   - Anti-injection rules (ANTI_INJECTION_RULES)                               │
│   - COVER response format                                                     │
│   - Language instruction (match user's language)                              │
│   - Tone instruction (getToneSystemPrompt())                                  │
│   - Agent role (getAgentSystemPrompt())                                       │
│   - Custom rules (getActiveRulesText())                                       │
│   - Evidence citation requirement                                             │
│                                                                               │
│  STEP 5: Multi-iteration tool loop (MAX_TOOL_ITERATIONS = 5)                  │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────┐          │
│  │  ITERATION LOOP                                                │          │
│  │                                                               │          │
│  │  5a. Call provider.stream(messages, toolDefs)                  │          │
│  │      ┌──────────────────────────────┐                         │          │
│  │      │ Provider sends chunks:        │                         │          │
│  │      │  - content: "Let me scan..."  │ → yield chunk.content  │          │
│  │      │  - toolCalls: [{name,args}]   │ → captured as pending  │          │
│  │      └──────────────────────────────┘                         │          │
│  │                                                               │          │
│  │  5b. Push assistant message to history                         │          │
│  │                                                               │          │
│  │  5c. Check for tool calls → if none, validate + return        │          │
│  │                                                               │          │
│  │  5d. For each tool call:                                      │          │
│  │      ├── Plan mode? → Build plan message, skip execution      │          │
│  │      ├── Execute mode + permission callback?                  │          │
│  │      │   └── Call permissionCb(toolName, args)                │          │
│  │      │       └── Bridge shows permission prompt               │          │
│  │      │           ├── approvePermission() → resolve(true)      │          │
│  │      │           └── denyPermission() → resolve(false)        │          │
│  │      ├── Denied? → Tool denied message + continue             │          │
│  │      └── Allowed? → runTool(toolName, args)                   │          │
│  │                                                               │          │
│  │  5e. Tool result processing:                                  │          │
│  │      ├── Detect prompt injection in tool output               │          │
│  │      ├── Auto-correlate against threat DB                     │          │
│  │      │   (scan/gh-pr-diff/verify-pkg only)                    │          │
│  │      ├── Wrap in ⟨⟨⟨SENTINEL_DATA⟩⟩⟩ markers                  │          │
│  │      ├── Add injection warning if detected                    │          │
│  │      └── Push as 'tool' message to history                    │          │
│  │                                                               │          │
│  │  5f. Loop back to 5a with updated history                     │          │
│  │      (AI sees tool results → decides next action)             │          │
│  └────────────────────────────────────────────────────────────────┘          │
│                                                                               │
│  STEP 6: Final response                                                       │
│   - Validate response against tool evidence (validateResponse)                │
│   - Emit any validation warnings                                             │
│   - Save history to streamingResult.history for Bridge to consume             │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  Response flows back up through Bridge to UI                                  │
│  ────────────────────────────────────────────────                            │
│                                                                               │
│  Bridge receives chunks from oracleChatStream async iterator:                 │
│   - First chunk → onStreamingStart(msgId)                                     │
│   - Each chunk  → onStreamingChunk(msgId, chunk) → appended to message       │
│   - Stream ends  → onStreamingEnd(msgId)                                     │
│                                                                               │
│  Chat component updates via setMessages:                                      │
│   - onStreamingChunk appends text to the assistant message content            │
│   - onToolStart/onToolEnd show/hide tool execution cards                     │
│   - onError shows error message                                               │
│                                                                               │
│  Bridge updates conversationHistory from streamingResult.history              │
│                                                                               │
│  RESULT: User sees streaming response in terminal, tool cards for each        │
│  tool executed, and final AI analysis with threat correlation                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

## ChatBridge State Machine

```
┌──────────┐   initialize()    ┌──────────┐   sendMessage(text)   ┌──────────────┐
│ UNINIT   │ ───────────────► │  READY   │ ──────────────────►   │  PROCESSING  │
└──────────┘                  └──────────┘                       └──────────────┘
                                │     ▲                               │
                                │     │                               │
                                │     │       ┌────────────────┐     │
                                │     └───────│  SLASH_HANDLER  │◄────┤
                                │             │ /key /provider  │     │
                                │             │ /logout         │     │
                                │             └────────────────┘     │
                                │                                    │
                                │           ┌────────────────┐       │
                                ├──────────►│  KEY_WIZARD    │       │
                                │           │ (pendingCmd)   │       │
                                │           └────────────────┘       │
                                │                                    │
                                │           ┌────────────────┐       │
                                │     ┌────►│  PERMISSION    │       │
                                │     │     │  PENDING       │       │
                                │     │     │ approve/deny   │       │
                                │     │     └────────────────┘       │
                                │     │                                    │
                                ◄─────┘────────────────────────────────────┘
```

State transitions:
- `UNINIT` → `READY`: `initialize()` detects configured provider
- `READY`: idle, waiting for input
- `READY` → `PROCESSING`: `sendMessage()` called with non-slash text
- `READY` → `SLASH_HANDLER`: text starts with `/`
- `READY` → `KEY_WIZARD`: `/key` without args triggers multi-step key setup
- `PROCESSING` → `PERMISSION_PENDING`: tool call requires approval (execute mode)
- `PERMISSION_PENDING` → `PROCESSING`: user approves or denies
- `PROCESSING` → `READY`: stream ends, response complete
- `READY` → `UNINIT`: `/logout` or error triggers restart

## Permission System

Three modes, controlled by `OracleMode` type:

```typescript
type OracleMode = 'execute' | 'plan' | 'auto';
```

### Execute Mode (default)
- AI proposes tool calls → Bridge creates a `permissionCb` Promise
- UI shows permission prompt: "⚠ Tool requires approval"
- User presses Enter (approve) or Esc (deny)
- `approvePermission()` resolves the promise with `true`
- `denyPermission()` resolves with `false` → tool output shows "denied"
- CLI interactive mode (non-Ink): raw keypress input, Enter/Esc/A auto-approve all
- Permission caching: `permissionCache` set caches approved `toolName:args` pairs

### Auto Mode
- All tools execute without prompting (permissionCb returns `true` immediately)

### Plan Mode
- Tools are NOT executed — AI receives a plan message explaining what would run
- UI shows `[PLAN] Would run: <tool> <args>` instead of actual results

## Error Propagation

```
Layer                   Error Type                   Propagation
─────────────────────────────────────────────────────────────────────
Provider                API error, network timeout   Caught in engine, yielded as error message
Engine                  Max iterations exceeded      Returns warning message + partial history
Tool (runTool)          Subprocess failure            Stderr/stdout returned as tool output string
Tool (permission)       User denied                   Denied message wrapped in data markers
Prompt Guard            Injection detected            Warning appended to tool output
Threat Correlation      DB error                      Non-fatal: silently caught, tool output unmodified
Bridge                  Stream error                  callbacks.onError(message) → UI shows error message
UI                      Component error               Ink error boundary (process.exit fallback)
```

## Streaming Architecture

```
Provider.stream() returns AsyncIterable<ChatChunk>:
  { content?: string }       → Streamed text to UI immediately
  { toolCalls?: ToolCall[] }  → Accumulated tool calls (emitted at stream end)

Engine yields string chunks:
  - Text content from provider
  - Tool cards (running/done/denied): "\n\n◆ toolName args Running...\n"
  - Tool raw output in code blocks: "```\n...\n```\n"
  - Threat correlation info
  - Injection warnings

ChatBridge.onStreamingChunk(msgId, chunk):
  - Appended to assistant message content via setMessages map callback
  - React re-renders message with updated text

Tool results returned to AI:
  - Wrapped in ⟨⟨⟨SENTINEL_DATA⟩⟩⟩ markers (syntactic separation)
  - Pushed as { role: 'tool', content: wrapped, tool_call_id: tc.id }
  - AI sees tool results in next iteration → can decide next action
```

## Full Loop Example

```
User: "Scan this repo and check the PRs"

  1. User input → Chat → ChatBridge.sendMessage()
  2. Bridge emits user message, calls oracleChatStream()
  3. System prompt built with tools, rules, tone, agent
  4. AI receives prompt → decides to use scan tool
  5. Stream yields "Let me scan the current directory..."
  6. Stream yields toolCalls: [{name: "scan", args: {path: "."}}]
  7. Permission prompt shown → user approves
  8. runTool("scan", {path: "."}) → execFileSync("node", ["main.js", "scan", ".", "--json"])
  9. Output received → injection check → threat correlation
  10. Tool output wrapped in DATA markers → pushed to AI
  11. AI processes findings → "I found 3 CRITICAL issues..."
  12. AI decides to also check PRs → toolCalls: [{name: "gh-pr-list"}]
  13. Permission prompt → user approves
  14. runTool("gh-pr-list", {}) → execFileSync("gh", ["pr", "list", ...])
  15. Results wrapped → pushed to AI
  16. AI says "There are 2 open PRs. PR #1 by attacker1337 modifies auth..."
  17. AI decides to get diff → toolCalls: [{name: "gh-pr-diff", args: {number: "1"}}]
  18. Permission → runTool → results wrapped → AI
  19. AI analyzes PR diff → "This PR introduces a backdoor in auth.js..."
  20. No more tool calls → validateResponse → return final text
  21. Stream ends → Bridge saves history → UI shows complete response
```

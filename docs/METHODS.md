# Sentinel Oracle Core — Key Interfaces & Contracts

## BaseProvider (Abstract Class)

**File:** `src/oracle/providers/base.ts`

```typescript
abstract class BaseProvider {
  constructor(
    public readonly name: string,
    public readonly model: string,
    protected apiKey: string
  )

  // Non-streaming chat — returns complete response
  abstract chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse>

  // Streaming chat — yields chunks as they arrive
  abstract stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk>

  // Default: checks apiKey is non-empty
  validateConfig(): boolean
}
```

**Contract:**
- `chat()` must return the full response, including any tool calls the AI wants to make
- `stream()` must yield text content chunks as they arrive from the provider, then yield any accumulated tool calls at the end (with `done: true`)
- Implementations translate the generic `Message`/`ToolDef` format to provider-specific API formats

---

## Core Types

**File:** `src/oracle/providers/base.ts`

```typescript
interface Message {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string
  tool_call_id?: string       // Required for role === 'tool'
}

interface ToolCall {
  id: string                   // Unique ID for this tool invocation
  name: string                 // Must match a registered tool name
  arguments: Record<string, string>
}

interface ChatResponse {
  content: string
  toolCalls?: ToolCall[]
}

interface ChatChunk {
  content?: string             // Text delta from streaming
  toolCalls?: ToolCall[]       // Emitted when streaming completes and tool calls are detected
  done: boolean                // True when stream is complete
}

interface ToolDef {
  name: string
  description: string          // AI-readable description of when/how to use
  parameters: {
    type: 'object'
    properties: Record<string, ToolParameterProperty>
    required?: string[]
  }
}

interface ToolParameterProperty {
  type: string                 // 'string', 'integer', etc.
  description?: string
  enum?: string[]
}
```

---

## Tool System

**File:** `src/oracle/tools.ts`

```typescript
interface Tool {
  name: string
  description: string
  parameters: ToolDef['parameters']
  run: (args: Record<string, string>) => string
}

// Get all tool definitions (for AI system prompt)
function getToolDefs(): ToolDef[]

// Execute a tool by name
function runTool(name: string, args: Record<string, string>): string
```

**Contract:**
- `getToolDefs()` returns all tool descriptions — called by `buildSystemPrompt()` to inform the AI
- `runTool()` is synchronous; all subprocess calls use `execFileSync` with shell:false
- Output is always a string — errors are returned as strings (not thrown)
- Tool output may be truncated if >2000 chars (in streaming mode)

---

## ChatBridge (Public API)

**File:** `src/oracle/ui/bridge.ts`

```typescript
class ChatBridge {
  constructor(callbacks?: BridgeCallbacks)

  // Lifecycle
  initialize(): Promise<boolean>           // Detect configured provider
  setCallbacks(callbacks: BridgeCallbacks): void

  // Sending
  sendMessage(text: string): Promise<void> // Main entry point: slash cmd or AI chat

  // Provider management
  configureProvider(provider: string, apiKey: string): Promise<boolean>
  getProvider(): string

  // Mode
  setMode(mode: 'execute' | 'plan' | 'auto'): void

  // History
  clearHistory(): void

  // Permission system
  hasPendingPermission(): boolean
  approvePermission(): void                // Resolves permission promise with true
  denyPermission(): void                   // Resolves permission promise with false
}

interface BridgeCallbacks {
  onMessage: (msg: BridgeMessage) => void
  onStreamingStart: (msgId: string) => void
  onStreamingChunk: (msgId: string, chunk: string) => void
  onStreamingEnd: (msgId: string) => void
  onToolStart: (toolName: string) => void
  onToolEnd: (toolName: string, result: string) => void
  onError: (error: string) => void
  onPermissionRequest?: (toolName: string, args: Record<string, any>) => void
  onRestart?: () => void
}

interface BridgeMessage {
  id: string
  type: 'user' | 'assistant' | 'tool' | 'system' | 'error'
  content: string
  timestamp: Date
  toolName?: string
  collapsed?: boolean
  thinking?: boolean
}
```

**Contract:**
- `sendMessage()` is async; it handles the entire lifecycle (slash commands → AI → tools → response)
- Three permission modes: `execute` (prompt per tool), `auto` (no prompt), `plan` (no execution)
- Streams text through `onStreamingChunk`, tool status through `onToolStart`/`onToolEnd`
- Errors propagate to `onError`
- Conversation history maintained internally; updated from `streamingResult.history` after each message

---

## Auth Module

**File:** `src/oracle/auth.ts`

```typescript
// Storage: ~/.sentinel/config.json (JSON, chmod 600 on non-Windows)

// Read API key — checks env vars first, then config file
function getApiKey(provider: string): string

// Write API key to config file
function setApiKey(provider: string, key: string): void

// Remove API key from config file
function removeApiKey(provider: string): void

// List all providers that have keys stored
function listProviders(): string[]

// Read current config
function getConfig(): { provider?: string; model?: string }

// Set default provider + optional model
function setConfig(provider: string, model?: string): void
```

**Env var fallback order for `getApiKey()`:**
1. `SENTINEL_GEMINI_KEY` / `SENTINEL_CLAUDE_KEY` / `SENTINEL_OPENAI_KEY`
2. `config.json` → `keys[provider]`
3. Empty string (handled by caller)

---

## Orchestration Engine

**File:** `src/oracle/engine.ts`

```typescript
// The core streaming function
async function* oracleChatStream(
  userInput: string,
  history: Message[],
  provider?: BaseProvider,
  onBeforeToolCall?: ToolPermissionCallback,  // Permission hook
  mode?: OracleMode                            // 'execute' | 'plan' | 'auto'
): AsyncIterable<string>

// Non-streaming variant
async function oracleChat(
  userInput: string,
  history: Message[],
  provider?: BaseProvider,
  onBeforeToolCall?: ToolPermissionCallback,
  mode?: OracleMode
): Promise<{ response: string; history: Message[] }>

// Builds the dynamic system prompt
function buildSystemPrompt(): string

// Gets configured provider from config/env
function getDefaultProvider(): BaseProvider | null

// Permission callback signature
type ToolPermissionCallback = (toolName: string, args: Record<string, any>) => boolean | Promise<boolean>

// Oracle execution modes
type OracleMode = 'execute' | 'plan' | 'auto'

// Global mutable streaming result
const streamingResult: { history: Message[] }
```

**Engine behavior:**
- System prompt is built fresh each call with current rules, tone, agent, and tool list
- Multi-iteration loop (max 5): AI → tool calls → execute → feed results back to AI
- Tool output is wrapped in `⟨⟨⟨SENTINEL_DATA⟩⟩⟩` markers (syntactic separation)
- Prompt injection detection runs on every tool output
- Threat DB auto-correlation enriches scan/PR/package results
- Response validation warns if AI contradicts tool evidence
- `streamingResult.history` is the shared mutable history that `ChatBridge` reads after streaming completes

---

## Prompt Guard

**File:** `src/oracle/prompt_guard.ts`

```typescript
// Layer 1: Data markers — syntactic separation of tool output
function wrapToolOutput(output: string, toolName: string): string
// Returns: "⟨⟨⟨SENTINEL_DATA⟩⟩⟩ TOOL:scan LENGTH:1234\n...output...\n⟨⟨⟨/SENTINEL_DATA⟩⟩⟩"

// Layer 2: Anti-injection system prompt rules (exported constant)
const ANTI_INJECTION_RULES: string

// Layer 3: Validate AI response against tool evidence
function validateResponse(aiResponse: string, toolResults: ToolResult[]): ValidationResult
// Returns warnings if AI says "no threats" when tools found findings

// Injection detection in code/tool output
function detectPromptInjection(code: string): InjectionAttempt[]
function formatInjections(attempts: InjectionAttempt[]): string

interface ValidationResult {
  passed: boolean
  warnings: string[]
}

interface InjectionAttempt {
  line: number
  snippet: string
  type: 'ignore-finding' | 'override-rules' | 'false-positive-claim' | 'system-override'
}
```

---

## Provider Factory

**File:** `src/oracle/providers/index.ts`

```typescript
type ProviderName = 'gemini' | 'claude' | 'openai' | 'ollama' | 'qwen'

function createProvider(name: ProviderName, apiKey: string, model?: string): BaseProvider
```

**Provider instances:**

| Provider | Class | Base URL | API Key | Model Default |
|----------|-------|----------|---------|---------------|
| Gemini | `GeminiProvider` | `generativelanguage.googleapis.com` | Required | `gemini-2.0-flash` |
| Claude | `ClaudeProvider` | `api.anthropic.com` | Required | `claude-sonnet-4-20250514` |
| OpenAI | `OpenAIProvider` | `api.openai.com` (configurable) | Required | `gpt-4o` |
| Ollama | `OllamaProvider` | `http://localhost:11434/v1` | None | `llama3` |
| Qwen | `QwenProvider` | Local GGUF file | None (local) | `qwen2.5-1.5b` |

---

## Provider-Specific Tool Call Formats

| Provider | Tool Call Format | Notes |
|----------|-----------------|-------|
| OpenAI | Native `tool_calls` in chat completion | Standard `function` type |
| Claude | `tool_use` content blocks in messages | Tool results sent as `tool_result` blocks |
| Gemini | `functionCall` in response parts | Tools passed as `functionDeclarations` |
| Ollama | OpenAI-compatible (uses OpenAIProvider) | Same format as OpenAI |
| Qwen | Custom JSON parsing from text | AI responds with ````json {"tool": "...", "args": {...}} ```` |

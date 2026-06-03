import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef, ToolCall } from './base.js';

const QWEN_MODEL_URL = 'https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf';
const MODEL_FILENAME = 'qwen2.5-1.5b-instruct-q4_k_m.gguf';
const MODELS_DIR = path.join(os.homedir(), '.sentinel', 'models');

const DEFAULT_SYSTEM = `You are Sentinel Oracle Core — an AI security assistant.
You have access to tools for code scanning, dependency verification, system diagnostics, and more.
Use tools when needed. Answer concisely and accurately.`;

function getModelPath(): string {
  if (!fs.existsSync(MODELS_DIR)) fs.mkdirSync(MODELS_DIR, { recursive: true });
  return path.join(MODELS_DIR, MODEL_FILENAME);
}

function formatToolDefs(tools?: ToolDef[]): string {
  if (!tools || tools.length === 0) return '';
  const lines = tools.map(t => {
    const params = t.parameters ? JSON.stringify(t.parameters, null, 2) : '{}';
    return `- ${t.name}: ${t.description}\n  Parameters:\n  ${params}`;
  });
  return `\n\n## Available Tools\n${lines.join('\n')}\n\nWhen you want to call a tool, respond with ONLY a JSON object in a code block:\n\`\`\`json\n{"tool": "<name>", "args": {...}}\n\`\`\`\nDo NOT explain what you're doing — just output the JSON.`;
}

export class QwenProvider extends BaseProvider {
  private modelPath: string;
  private _session: any = null;
  private _initialized = false;
  private _initPromise: Promise<void> | null = null;
  private _cachedSystemBase: string = '';

  constructor(model?: string) {
    super('qwen', model || 'qwen2.5-1.5b', 'local');
    this.modelPath = getModelPath();
  }

  isDownloaded(): boolean {
    return fs.existsSync(this.modelPath);
  }

  getModelSize(): number {
    if (!fs.existsSync(this.modelPath)) return 0;
    return fs.statSync(this.modelPath).size;
  }

  async download(progressCb?: (downloaded: number, total: number) => void): Promise<void> {
    if (this.isDownloaded()) return;

    const response = await fetch(QWEN_MODEL_URL);
    if (!response.ok) throw new Error(`Failed to download model: ${response.status} ${response.statusText}`);
    const total = parseInt(response.headers.get('content-length') || '0', 10);
    const reader = response.body!.getReader();
    const writer = fs.createWriteStream(this.modelPath);
    let downloaded = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      writer.write(Buffer.from(value));
      downloaded += value.length;
      progressCb?.(downloaded, total);
    }

    writer.end();
    await new Promise<void>((resolve, reject) => {
      writer.on('finish', resolve);
      writer.on('error', reject);
    });
  }

  private async ensureInitialized(): Promise<void> {
    if (this._initialized) return;
    if (this._initPromise) return this._initPromise;

    this._initPromise = (async () => {
      const { getLlama, LlamaModel, LlamaChatSession, QwenChatWrapper } = await import('node-llama-cpp');
      const llama = await getLlama({ gpu: false });
      const model = await (LlamaModel as any)._create({ modelPath: this.modelPath, gpuLayers: 0 }, { _llama: llama });
      const context = await model.createContext();
      const sequence = context.getSequence();
      this._session = new LlamaChatSession({
        contextSequence: sequence,
        chatWrapper: new QwenChatWrapper(),
      });
      this._initialized = true;
    })();

    await this._initPromise;
  }

  private buildSystemPrompt(messages: Message[], tools?: ToolDef[]): string {
    const sysMsg = messages.find(m => m.role === 'system');
    const base = sysMsg?.content || this._cachedSystemBase || DEFAULT_SYSTEM;
    if (sysMsg && !this._cachedSystemBase) {
      this._cachedSystemBase = sysMsg.content;
    }
    const toolBlock = formatToolDefs(tools);
    return base + toolBlock;
  }

  private toSessionHistory(messages: Message[], systemPrompt: string): any[] {
    const history: any[] = [{ type: 'system', text: systemPrompt }];
    for (const msg of messages) {
      if (msg.role === 'system') continue;
      if (msg.role === 'user') {
        history.push({ type: 'user', text: msg.content });
      } else if (msg.role === 'assistant') {
        history.push({ type: 'model', response: [msg.content] });
      } else if (msg.role === 'tool') {
        history.push({ type: 'user', text: `[Tool result from ${msg.tool_call_id || 'unknown'}]: ${msg.content}` });
      }
    }
    return history;
  }

  private parseToolCalls(text: string): ToolCall[] {
    const calls: ToolCall[] = [];
    const jsonBlockRegex = /```json\s*({[\s\S]*?})\s*```/g;
    let match;
    while ((match = jsonBlockRegex.exec(text)) !== null) {
      try {
        const parsed = JSON.parse(match[1]);
        if (parsed.tool && parsed.args) {
          calls.push({
            id: `${parsed.tool}-${Date.now()}`,
            name: parsed.tool,
            arguments: parsed.args,
          });
        }
      } catch { /* skip invalid json */ }
    }
    return calls;
  }

  async chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse> {
    await this.ensureInitialized();

    const systemPrompt = this.buildSystemPrompt(messages, tools);
    const lastUserIdx = messages.map(m => m.role).lastIndexOf('user');
    const historyMsgs = lastUserIdx >= 0 ? messages.slice(0, lastUserIdx) : messages;
    const history = this.toSessionHistory(historyMsgs, systemPrompt);
    this._session.setChatHistory(history);

    const promptText = lastUserIdx >= 0 ? messages[lastUserIdx].content : messages[messages.length - 1]?.content || '';

    const response = await this._session.prompt(promptText, {
      temperature: 0.6,
      maxTokens: 2048,
      topP: 0.9,
      repeatPenalty: 1.1,
    });

    const toolCalls = this.parseToolCalls(response);
    return {
      content: response,
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
    };
  }

  async *stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk> {
    await this.ensureInitialized();

    const systemPrompt = this.buildSystemPrompt(messages, tools);
    const lastUserIdx = messages.map(m => m.role).lastIndexOf('user');
    const historyMsgs = lastUserIdx >= 0 ? messages.slice(0, lastUserIdx) : messages;
    const history = this.toSessionHistory(historyMsgs, systemPrompt);
    this._session.setChatHistory(history);

    const promptText = lastUserIdx >= 0 ? messages[lastUserIdx].content : messages[messages.length - 1]?.content || '';

    const queue: string[] = [];
    let resolveQueue: (() => void) | null = null;
    let queueDone = false;

    this._session.prompt(promptText, {
      temperature: 0.6,
      maxTokens: 2048,
      topP: 0.9,
      repeatPenalty: 1.1,
      onTextChunk: (text: string) => {
        queue.push(text);
        const r = resolveQueue;
        resolveQueue = null;
        r?.();
      },
    }).then(() => { queueDone = true; const r = resolveQueue; resolveQueue = null; r?.(); });

    let fullText = '';
    while (!queueDone || queue.length > 0) {
      if (queue.length > 0) {
        const chunk = queue.shift()!;
        fullText += chunk;
        yield { content: chunk, done: false };
      } else {
        await new Promise<void>(resolve => { resolveQueue = resolve; });
      }
    }

    const toolCalls = this.parseToolCalls(fullText);
    if (toolCalls.length > 0) {
      yield { toolCalls, done: true };
      return;
    }
    yield { done: true };
  }

  validateConfig(): boolean {
    return true;
  }
}

import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef, ToolCall } from './base.js';

const QWEN_MODEL_URL = 'https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf';
const MODEL_FILENAME = 'qwen2.5-1.5b-instruct-q4_k_m.gguf';
const MODELS_DIR = path.join(os.homedir(), '.sentinel', 'models');

function getModelPath(): string {
  if (!fs.existsSync(MODELS_DIR)) fs.mkdirSync(MODELS_DIR, { recursive: true });
  return path.join(MODELS_DIR, MODEL_FILENAME);
}

export class QwenProvider extends BaseProvider {
  private modelPath: string;
  private _llama: any = null;
  private _model: any = null;
  private _context: any = null;
  private _sequence: any = null;
  private _initialized = false;
  private _initPromise: Promise<void> | null = null;

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
    const buf = new Uint8Array(1024 * 64);

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
      const { getLlama } = await import('node-llama-cpp');
      this._llama = await getLlama();
      this._model = new this._llama.LlamaModel({ modelPath: this.modelPath });
      this._context = await this._model.createContext();
      this._sequence = this._context.getSequence();
      this._initialized = true;
    })();

    await this._initPromise;
  }

  private async *runInference(
    messages: Message[],
    tools?: ToolDef[]
  ): AsyncIterable<{ content?: string; toolCalls?: ToolCall[]; done: boolean }> {
    await this.ensureInitialized();

    const systemMsg = messages.find(m => m.role === 'system');
    const chatMessages = messages.filter(m => m.role !== 'system').map(m => {
      if (m.role === 'tool') {
        return { role: 'tool' as const, content: m.content, name: m.tool_call_id || 'function' };
      }
      if (m.role === 'assistant') {
        return { role: 'assistant' as const, content: m.content };
      }
      return { role: 'user' as const, content: m.content };
    });

    const prompt = this.buildPrompt(
      systemMsg?.content || 'You are Sentinel Oracle, a security AI assistant.',
      chatMessages,
      tools
    );

    // Tokenize to estimate
    const tokens = this._model.tokenize(prompt);
    const maxTokens = Math.min(4096 - tokens.length, 2048);

    let fullText = '';
    for await (const chunk of this._sequence.complete(prompt, {
      temperature: 0.6,
      maxTokens,
      topP: 0.9,
      repeatPenalty: 1.1,
      stream: true,
    })) {
      const text = typeof chunk === 'string' ? chunk : (chunk as any).text || '';
      if (text) {
        fullText += text;
        yield { content: text, done: false };
      }
    }

    // Try to parse tool calls from the response
    const toolCalls = this.parseToolCalls(fullText);
    if (toolCalls.length > 0) {
      yield { toolCalls, done: true };
      return;
    }

    yield { done: true };
  }

  private buildPrompt(system: string, messages: { role: string; content: string; name?: string }[], tools?: ToolDef[]): string {
    let prompt = `<|im_start|>system\n${system}`;
    if (tools && tools.length > 0) {
      prompt += `\n\nYou have access to the following tools. When you want to use a tool, respond with a JSON block:\n\`\`\`json\n{"tool": "<tool_name>", "args": {...}}\n\`\`\`\n\nTools:\n${JSON.stringify(tools.map(t => ({ name: t.name, description: t.description, parameters: t.parameters })), null, 2)}`;
    }
    prompt += `<|im_end|>\n`;

    for (const msg of messages) {
      if (msg.role === 'tool') {
        prompt += `<|im_start|>tool\n${msg.content}<|im_end|>\n`;
      } else if (msg.role === 'assistant') {
        prompt += `<|im_start|>assistant\n${msg.content}<|im_end|>\n`;
      } else {
        prompt += `<|im_start|>user\n${msg.content}<|im_end|>\n`;
      }
    }

    prompt += `<|im_start|>assistant\n`;
    return prompt;
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
    let fullContent = '';
    let toolCalls: ToolCall[] | undefined;

    for await (const chunk of this.runInference(messages, tools)) {
      if (chunk.content) fullContent += chunk.content;
      if (chunk.toolCalls) toolCalls = chunk.toolCalls;
    }

    return { content: fullContent, toolCalls };
  }

  async *stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk> {
    for await (const chunk of this.runInference(messages, tools)) {
      yield {
        content: chunk.content || '',
        toolCalls: chunk.toolCalls,
        done: chunk.done,
      };
    }
  }

  validateConfig(): boolean {
    return true;
  }
}

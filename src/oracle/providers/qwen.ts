import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef, ToolCall } from './base.js';

const QWEN_MODEL_URL = 'https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf';
const MODEL_FILENAME = 'qwen2.5-1.5b-instruct-q4_k_m.gguf';
const MODELS_DIR = path.join(os.homedir(), '.sentinel', 'models');

const DEFAULT_SYSTEM = `You are Sentinel Oracle Core — an AI security assistant. Answer concisely and use tools when needed.`;

function getModelPath(): string {
  if (!fs.existsSync(MODELS_DIR)) fs.mkdirSync(MODELS_DIR, { recursive: true });
  return path.join(MODELS_DIR, MODEL_FILENAME);
}

function formatToolDefs(tools?: ToolDef[]): string {
  if (!tools || tools.length === 0) return '';
  const lines = tools.map(t => {
    const params = t.parameters ? JSON.stringify(t.parameters, null, 2) : '{}';
    return `- ${t.name}: ${t.description}\n  Schema: ${params}`;
  });
  return `\n\n## Available Tools\n${lines.join('\n')}\n\nTo call a tool respond with ONLY:\n\`\`\`json\n{"tool": "<name>", "args": {...}}\n\`\`\`\nNo explanations before or after.`;
}

export class QwenProvider extends BaseProvider {
  private modelPath: string;
  private _model: any = null;
  private _llama: any = null;
  private _initialized = false;
  private _initPromise: Promise<void> | null = null;
  private _cachedSystemBase: string = '';
  private _context: any = null;

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
      const { getLlama, LlamaModel } = await import('node-llama-cpp');
      this._llama = await getLlama({ gpu: false });
      this._model = await (LlamaModel as any)._create({ modelPath: this.modelPath, gpuLayers: 0 }, { _llama: this._llama });
      this._context = await this._model.createContext();
      this._initialized = true;
    })();

    await this._initPromise;
  }

  private async resetContext(): Promise<any> {
    if (this._context) {
      await this._context.dispose();
    }
    this._context = await this._model.createContext();
    const { LlamaCompletion } = await import('node-llama-cpp');
    const sequence = this._context.getSequence();
    return new LlamaCompletion({ contextSequence: sequence });
  }

  private buildPrompt(messages: Message[], tools?: ToolDef[]): string {
    const sysMsg = messages.find(m => m.role === 'system');
    const base = sysMsg?.content || this._cachedSystemBase || DEFAULT_SYSTEM;
    if (sysMsg && !this._cachedSystemBase) {
      this._cachedSystemBase = sysMsg.content;
    }
    let prompt = `<|im_start|>system\n${base}${formatToolDefs(tools)}<|im_end|>\n`;

    for (const msg of messages) {
      if (msg.role === 'system') continue;
      if (msg.role === 'user') {
        prompt += `<|im_start|>user\n${msg.content}<|im_end|>\n`;
      } else if (msg.role === 'assistant') {
        prompt += `<|im_start|>assistant\n${msg.content}<|im_end|>\n`;
      } else if (msg.role === 'tool') {
        prompt += `<|im_start|>user\n[Tool result]\n${msg.content}<|im_end|>\n`;
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
    await this.ensureInitialized();

    const prompt = this.buildPrompt(messages, tools);
    const completion = await this.resetContext();
    const response = await completion.generateCompletion(prompt, {
      temperature: 0.6,
      maxTokens: 512,
      topP: 0.9,
      repeatPenalty: 1.1,
      customStopTriggers: ['<|im_end|>'],
    });

    const toolCalls = this.parseToolCalls(response);
    return {
      content: response,
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
    };
  }

  async *stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk> {
    const result = await this.chat(messages, tools);
    if (result.content) {
      yield { content: result.content, done: false };
    }
    if (result.toolCalls) {
      yield { toolCalls: result.toolCalls, done: true };
      return;
    }
    yield { done: true };
  }

  validateConfig(): boolean {
    return true;
  }
}

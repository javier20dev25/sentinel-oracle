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
  private _session: any = null;
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

  private toSessionHistory(messages: Message[]): any[] {
    const history: any[] = [];
    for (const msg of messages) {
      if (msg.role === 'system') {
        history.push({ type: 'system', text: msg.content });
      } else if (msg.role === 'user') {
        history.push({ type: 'user', text: msg.content });
      } else if (msg.role === 'assistant') {
        history.push({ type: 'model', response: [msg.content] });
      } else if (msg.role === 'tool') {
        history.push({ type: 'user', text: `[Tool result]: ${msg.content}` });
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

    const lastUserIdx = messages.map(m => m.role).lastIndexOf('user');
    const historyMsgs = lastUserIdx >= 0 ? messages.slice(0, lastUserIdx) : messages;
    this._session.setChatHistory(this.toSessionHistory(historyMsgs));

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

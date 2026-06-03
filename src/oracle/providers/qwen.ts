import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { spawn } from 'child_process';
import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef, ToolCall } from './base.js';

const MODEL_VARIANTS: Record<string, { url: string; filename: string }> = {
  'base': {
    url: 'https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf',
    filename: 'qwen2.5-1.5b-instruct-q4_k_m.gguf',
  },
  'fast': {
    url: 'https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf',
    filename: 'qwen2.5-0.5b-instruct-q4_k_m.gguf',
  },
};
const MODELS_DIR = path.join(os.homedir(), '.sentinel', 'models');
const BIN_DIR = path.join(os.homedir(), '.sentinel', 'bin');
const LLAMA_CLI = path.join(BIN_DIR, 'llama-cli.exe');

const DEFAULT_SYSTEM = `You are Sentinel Oracle Core — an AI security assistant. Answer concisely and use tools when needed.`;

function getModelPath(variant: string = 'base'): string {
  if (!fs.existsSync(MODELS_DIR)) fs.mkdirSync(MODELS_DIR, { recursive: true });
  const info = MODEL_VARIANTS[variant];
  if (!info) throw new Error(`Unknown model variant: ${variant}. Choose 'base' (1.5B) or 'fast' (0.5B).`);
  return path.join(MODELS_DIR, info.filename);
}

function formatToolDefs(tools?: ToolDef[]): string {
  if (!tools || tools.length === 0) return '';
  const lines = tools.map(t => {
    const params = t.parameters ? JSON.stringify(t.parameters, null, 2) : '{}';
    return `- ${t.name}: ${t.description}\n  Schema: ${params}`;
  });
  return `\n\n## Available Tools\n${lines.join('\n')}\n\nTo call a tool respond with ONLY:\n\`\`\`json\n{"tool": "<name>", "args": {...}}\n\`\`\`\nNo explanations before or after.`;
}

function buildPrompt(messages: Message[], tools?: ToolDef[]): string {
  const sysMsg = messages.find(m => m.role === 'system');
  const base = sysMsg?.content || DEFAULT_SYSTEM;
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

function parseToolCalls(text: string): ToolCall[] {
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

function runLlama(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = spawn(LLAMA_CLI, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    proc.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

    proc.on('error', reject);
    proc.on('close', (code) => {
      if (code === 0 || code === null) {
        resolve(stdout);
      } else {
        reject(new Error(`llama-cli exited with code ${code}: ${stderr}`));
      }
    });
  });
}

export class QwenProvider extends BaseProvider {
  private modelPath: string;
  private variant: string;

  constructor(model?: string, variant?: string) {
    super('qwen', model || 'qwen2.5-0.5b', 'local');
    this.variant = model === 'base' ? 'base' : (variant || 'fast');
    this.modelPath = getModelPath(this.variant);
  }

  isDownloaded(): boolean {
    return fs.existsSync(this.modelPath) && fs.existsSync(LLAMA_CLI);
  }

  getModelSize(): number {
    if (!fs.existsSync(this.modelPath)) return 0;
    return fs.statSync(this.modelPath).size;
  }

  async download(progressCb?: (downloaded: number, total: number) => void): Promise<void> {
    if (!fs.existsSync(LLAMA_CLI)) {
      throw new Error(`llama-cli not found at ${LLAMA_CLI}. Run bootstrap or reinstall.`);
    }
    if (fs.existsSync(this.modelPath)) return;

    const modelInfo = MODEL_VARIANTS[this.variant];
    const response = await fetch(modelInfo.url);
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

  async chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse> {
    const prompt = buildPrompt(messages, tools);
    const tempFile = path.join(os.tmpdir(), `qwen-prompt-${Date.now()}.txt`);
    fs.writeFileSync(tempFile, prompt, 'utf-8');

    try {
      const stdout = await runLlama([
        '-m', this.modelPath,
        '-f', tempFile,
        '-n', '512',
        '--temp', '0.6',
        '--top-p', '0.9',
        '--repeat-penalty', '1.1',
        '--no-display-prompt',
        '--simple-io',
        '--single-turn',
        '-t', '8',
      ]);

      const output = stdout.replace(/\[end of text\]/g, '').trim();
      const toolCalls = parseToolCalls(output);
      return {
        content: output,
        toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      };
    } finally {
      try { fs.unlinkSync(tempFile); } catch { /* ignore */ }
    }
  }

  async *stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk> {
    const prompt = buildPrompt(messages, tools);
    const tempFile = path.join(os.tmpdir(), `qwen-prompt-${Date.now()}.txt`);
    fs.writeFileSync(tempFile, prompt, 'utf-8');

    const proc = spawn(LLAMA_CLI, [
      '-m', this.modelPath,
      '-f', tempFile,
      '-n', '512',
      '--temp', '0.6',
      '--top-p', '0.9',
      '--repeat-penalty', '1.1',
      '--no-display-prompt',
      '--simple-io',
      '--single-turn',
      '-t', '8',
    ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });

    const stderrChunks: Buffer[] = [];
    let fullContent = '';

    try {
      for await (const chunk of proc.stdout) {
        const text = chunk.toString();
        fullContent += text;
        yield { content: text, done: false };
      }

      proc.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

      await new Promise<void>((resolve, reject) => {
        proc.on('error', reject);
        proc.on('close', (code) => {
          if (code === 0 || code === null) resolve();
          else reject(new Error(`llama-cli exited with code ${code}`));
        });
      });
    } finally {
      try { fs.unlinkSync(tempFile); } catch { /* ignore */ }
    }

    const output = fullContent.replace(/\[end of text\]/g, '').trim();
    const toolCalls = parseToolCalls(output);
    if (toolCalls.length > 0) {
      yield { toolCalls, done: true };
    } else {
      yield { done: true };
    }
  }

  validateConfig(): boolean {
    return true;
  }
}

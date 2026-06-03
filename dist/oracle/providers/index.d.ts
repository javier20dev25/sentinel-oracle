import { BaseProvider } from './base.js';
export { BaseProvider, Message, ChatResponse, ToolDef, ToolCall } from './base.js';
export { GeminiProvider } from './gemini.js';
export { ClaudeProvider } from './claude.js';
export { OpenAIProvider } from './openai.js';
export { OllamaProvider } from './ollama.js';
export { QwenProvider } from './qwen.js';
export type ProviderName = 'gemini' | 'claude' | 'openai' | 'ollama' | 'qwen';
export declare function createProvider(name: ProviderName, apiKey: string, model?: string): BaseProvider;

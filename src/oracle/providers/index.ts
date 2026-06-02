import { BaseProvider, Message, ChatResponse, ToolDef, ToolCall } from './base.js';
import { GeminiProvider } from './gemini.js';
import { ClaudeProvider } from './claude.js';
import { OpenAIProvider } from './openai.js';
import { OllamaProvider } from './ollama.js';
export { BaseProvider, Message, ChatResponse, ToolDef, ToolCall } from './base.js';
export { GeminiProvider } from './gemini.js';
export { ClaudeProvider } from './claude.js';
export { OpenAIProvider } from './openai.js';
export { OllamaProvider } from './ollama.js';

export type ProviderName = 'gemini' | 'claude' | 'openai' | 'ollama';

export function createProvider(name: ProviderName, apiKey: string, model?: string): BaseProvider {
  switch (name) {
    case 'gemini': return new GeminiProvider(apiKey, model);
    case 'claude': return new ClaudeProvider(apiKey, model);
    case 'openai': return new OpenAIProvider(apiKey, model);
    case 'ollama': return new OllamaProvider(model);
    default: throw new Error(`Unknown provider: ${name}`);
  }
}

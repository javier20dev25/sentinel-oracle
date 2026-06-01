import { BaseProvider, Message, ChatResponse, ToolDef, ToolCall } from './base';
import { GeminiProvider } from './gemini';
import { ClaudeProvider } from './claude';
import { OpenAIProvider } from './openai';
import { OllamaProvider } from './ollama';
export { BaseProvider, Message, ChatResponse, ToolDef, ToolCall } from './base';
export { GeminiProvider } from './gemini';
export { ClaudeProvider } from './claude';
export { OpenAIProvider } from './openai';
export { OllamaProvider } from './ollama';

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

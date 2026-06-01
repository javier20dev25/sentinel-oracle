import { BaseProvider } from './base';
export { BaseProvider, Message, ChatResponse, ToolDef, ToolCall } from './base';
export { GeminiProvider } from './gemini';
export { ClaudeProvider } from './claude';
export { OpenAIProvider } from './openai';
export { OllamaProvider } from './ollama';
export type ProviderName = 'gemini' | 'claude' | 'openai' | 'ollama';
export declare function createProvider(name: ProviderName, apiKey: string, model?: string): BaseProvider;

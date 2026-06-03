import { GeminiProvider } from './gemini.js';
import { ClaudeProvider } from './claude.js';
import { OpenAIProvider } from './openai.js';
import { OllamaProvider } from './ollama.js';
import { QwenProvider } from './qwen.js';
export { BaseProvider } from './base.js';
export { GeminiProvider } from './gemini.js';
export { ClaudeProvider } from './claude.js';
export { OpenAIProvider } from './openai.js';
export { OllamaProvider } from './ollama.js';
export { QwenProvider } from './qwen.js';
export function createProvider(name, apiKey, model) {
    switch (name) {
        case 'gemini': return new GeminiProvider(apiKey, model);
        case 'claude': return new ClaudeProvider(apiKey, model);
        case 'openai': return new OpenAIProvider(apiKey, model);
        case 'ollama': return new OllamaProvider(model);
        case 'qwen': return new QwenProvider(model);
        default: throw new Error(`Unknown provider: ${name}`);
    }
}

import { OpenAIProvider } from './openai.js';

export class OllamaProvider extends OpenAIProvider {
  constructor(model = 'llama3') {
    super('', model, 'http://localhost:11434/v1');
    (this as any).name = 'ollama';
  }

  validateConfig(): boolean {
    return true; // No API key needed for local Ollama
  }
}

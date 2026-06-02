import { OpenAIProvider } from './openai.js';
export class OllamaProvider extends OpenAIProvider {
    constructor(model = 'llama3') {
        super('', model, 'http://localhost:11434/v1');
        this.name = 'ollama';
    }
    validateConfig() {
        return true; // No API key needed for local Ollama
    }
}

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OllamaProvider = void 0;
const openai_1 = require("./openai");
class OllamaProvider extends openai_1.OpenAIProvider {
    constructor(model = 'llama3') {
        super('', model, 'http://localhost:11434/v1');
        this.name = 'ollama';
    }
    validateConfig() {
        return true; // No API key needed for local Ollama
    }
}
exports.OllamaProvider = OllamaProvider;

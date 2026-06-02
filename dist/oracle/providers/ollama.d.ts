import { OpenAIProvider } from './openai.js';
export declare class OllamaProvider extends OpenAIProvider {
    constructor(model?: string);
    validateConfig(): boolean;
}

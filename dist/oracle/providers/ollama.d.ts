import { OpenAIProvider } from './openai';
export declare class OllamaProvider extends OpenAIProvider {
    constructor(model?: string);
    validateConfig(): boolean;
}

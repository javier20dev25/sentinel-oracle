import OpenAI from 'openai';
import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef } from './base';
export declare class OpenAIProvider extends BaseProvider {
    protected client: OpenAI;
    constructor(apiKey: string, model?: string, baseURL?: string);
    chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse>;
    stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk>;
}

import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef } from './base.js';
export declare class ClaudeProvider extends BaseProvider {
    private client;
    constructor(apiKey: string, model?: string);
    chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse>;
    stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk>;
}

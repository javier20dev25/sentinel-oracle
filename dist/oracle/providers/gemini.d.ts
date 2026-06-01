import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef } from './base';
export declare class GeminiProvider extends BaseProvider {
    private client;
    private modelInst;
    constructor(apiKey: string, model?: string);
    chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse>;
    stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk>;
}

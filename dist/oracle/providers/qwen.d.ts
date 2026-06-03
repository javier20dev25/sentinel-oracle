import { BaseProvider, Message, ChatResponse, ChatChunk, ToolDef } from './base.js';
export declare class QwenProvider extends BaseProvider {
    private modelPath;
    private _llama;
    private _model;
    private _context;
    private _sequence;
    private _initialized;
    private _initPromise;
    constructor(model?: string);
    isDownloaded(): boolean;
    getModelSize(): number;
    download(progressCb?: (downloaded: number, total: number) => void): Promise<void>;
    private ensureInitialized;
    private runInference;
    private buildPrompt;
    private parseToolCalls;
    chat(messages: Message[], tools?: ToolDef[]): Promise<ChatResponse>;
    stream(messages: Message[], tools?: ToolDef[]): AsyncIterable<ChatChunk>;
    validateConfig(): boolean;
}

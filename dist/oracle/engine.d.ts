import { BaseProvider, Message } from './providers/base';
export declare function buildSystemPrompt(): string;
export declare function getDefaultProvider(): BaseProvider | null;
export type ToolPermissionCallback = (toolName: string, args: Record<string, any>) => boolean | Promise<boolean>;
export type OracleMode = 'execute' | 'plan' | 'auto';
export declare const streamingResult: {
    history: Message[];
};
export declare function oracleChat(userInput: string, history: Message[], provider?: BaseProvider, onBeforeToolCall?: ToolPermissionCallback, mode?: OracleMode): Promise<{
    response: string;
    history: Message[];
}>;
export declare function oracleChatStream(userInput: string, history: Message[], provider?: BaseProvider, onBeforeToolCall?: ToolPermissionCallback, mode?: OracleMode): AsyncIterable<string>;

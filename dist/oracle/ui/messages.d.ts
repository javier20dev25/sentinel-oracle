export type MessageType = 'user' | 'assistant' | 'tool' | 'system' | 'error';
export interface ChatMessage {
    type: MessageType;
    content: string;
    timestamp: Date;
    toolName?: string;
    collapsed?: boolean;
}
export declare class MessageRenderer {
    private messages;
    private maxMessages;
    private _renderedLineCount;
    get renderedLineCount(): number;
    addMessage(msg: ChatMessage): void;
    updateLastAssistantContent(content: string): void;
    clear(): void;
    renderAll(): number;
    private get stdout();
    private getBoxWidth;
    private renderMessage;
    private renderUserMessage;
    private renderAssistantMessage;
    private renderToolMessage;
    private renderSystemMessage;
    private renderErrorMessage;
}

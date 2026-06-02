import React from 'react';
export interface ChatMessage {
    id: string;
    type: 'user' | 'assistant' | 'tool' | 'system' | 'error';
    content: string;
    timestamp: Date;
    toolName?: string;
    collapsed?: boolean;
    thinking?: boolean;
}
interface MessageProps {
    message: ChatMessage;
    isStreaming?: boolean;
    terminalWidth?: number;
}
export declare function Message({ message, isStreaming, terminalWidth }: MessageProps): React.JSX.Element | null;
export {};

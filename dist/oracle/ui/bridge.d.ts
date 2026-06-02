export interface BridgeMessage {
    id: string;
    type: 'user' | 'assistant' | 'tool' | 'system' | 'error';
    content: string;
    timestamp: Date;
    toolName?: string;
    collapsed?: boolean;
    thinking?: boolean;
}
export interface BridgeCallbacks {
    onMessage: (msg: BridgeMessage) => void;
    onStreamingStart: (msgId: string) => void;
    onStreamingChunk: (msgId: string, chunk: string) => void;
    onStreamingEnd: (msgId: string) => void;
    onToolStart: (toolName: string) => void;
    onToolEnd: (toolName: string, result: string) => void;
    onError: (error: string) => void;
    onPermissionRequest?: (toolName: string, args: Record<string, any>) => void;
    onRestart?: () => void;
}
export declare class ChatBridge {
    private provider;
    private providerName;
    private conversationHistory;
    private callbacks;
    private mode;
    private pendingPermission;
    private activeToolNames;
    constructor(callbacks?: BridgeCallbacks);
    setCallbacks(callbacks: BridgeCallbacks): void;
    initialize(): Promise<boolean>;
    private getOrCreateProvider;
    sendMessage(text: string): Promise<void>;
    configureProvider(provider: string, apiKey: string): Promise<boolean>;
    setMode(mode: 'execute' | 'plan' | 'auto'): void;
    getProvider(): string;
    clearHistory(): void;
    hasPendingPermission(): boolean;
    approvePermission(): void;
    denyPermission(): void;
}

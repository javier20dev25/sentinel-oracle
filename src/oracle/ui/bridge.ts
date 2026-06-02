import { oracleChatStream, getDefaultProvider, streamingResult } from '../engine.js';
import { getApiKey, setApiKey as storeApiKey, setConfig as storeConfig, removeApiKey } from '../auth.js';
import { createProvider } from '../providers/index.js';
import type { Message as ProviderMessage } from '../providers/base.js';

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

export class ChatBridge {
  private provider: any;
  private providerName: string = '';
  private conversationHistory: ProviderMessage[] = [];
  private callbacks: BridgeCallbacks;
  private mode: 'execute' | 'plan' | 'auto' = 'execute';
  private pendingPermission: { resolve: (value: boolean) => void } | null = null;
  private activeToolNames: Set<string> = new Set();

  constructor(callbacks?: BridgeCallbacks) {
    this.callbacks = callbacks || {
      onMessage: () => {},
      onStreamingStart: () => {},
      onStreamingChunk: () => {},
      onStreamingEnd: () => {},
      onToolStart: () => {},
      onToolEnd: () => {},
      onError: () => {},
    };
  }

  setCallbacks(callbacks: BridgeCallbacks): void {
    this.callbacks = callbacks;
  }

  async initialize(): Promise<boolean> {
    try {
      const p = getDefaultProvider();
      if (p) {
        this.provider = p;
        this.providerName = p.name;
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  private getOrCreateProvider(): any {
    if (this.provider) return this.provider;

    const config = getDefaultProvider();
    if (config) {
      this.provider = config;
      this.providerName = config.name;
      return config;
    }

    return null;
  }

  async sendMessage(text: string): Promise<void> {
    if (text.startsWith('/')) {
      const parts = text.slice(1).split(/\s+/);
      const cmd = parts[0].toLowerCase();

      if (cmd === 'logout') {
        if (this.providerName) {
          removeApiKey(this.providerName);
          storeConfig('');
        }
        this.callbacks.onRestart?.();
        return;
      }

      if (cmd === 'key') {
        const provider = parts[1];
        const key = parts.slice(2).join(' ');
        if (!provider || !key) {
          this.callbacks.onError('Usage: /key <provider> <api_key>');
          return;
        }
        storeApiKey(provider, key);
        this.callbacks.onMessage({
          id: `cmd-${Date.now()}`,
          type: 'system',
          content: `✓ API key saved for ${provider}`,
          timestamp: new Date(),
        });
        return;
      }

      if (cmd === 'provider') {
        const name = parts[1];
        if (!name) {
          this.callbacks.onError('Usage: /provider <name> (gemini, claude, openai, ollama)');
          return;
        }
        storeConfig(name);
        const key = getApiKey(name);
        const p = createProvider(name as any, key);
        if (p) {
          this.provider = p;
          this.providerName = name;
        }
        this.callbacks.onMessage({
          id: `cmd-${Date.now()}`,
          type: 'system',
          content: `✓ Switched to provider: ${name}`,
          timestamp: new Date(),
        });
        return;
      }
    }

    this.conversationHistory.push({ role: 'user', content: text });

    const userMsgId = `msg-user-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    this.callbacks.onMessage({
      id: userMsgId,
      type: 'user',
      content: text,
      timestamp: new Date(),
    });

    const asstMsgId = `msg-asst-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    this.callbacks.onMessage({
      id: asstMsgId,
      type: 'assistant',
      content: '',
      timestamp: new Date(),
      thinking: true,
    });

    const p = this.getOrCreateProvider();
    if (!p) {
      this.callbacks.onError('No provider configured. Please configure a provider first.');
      return;
    }

    const mode = this.mode;

    const permissionCb = async (toolName: string, args: Record<string, any>): Promise<boolean> => {
      this.activeToolNames.add(toolName);
      this.callbacks.onToolStart(toolName);

      if (mode === 'auto') return true;

      if (this.callbacks.onPermissionRequest) {
        this.callbacks.onPermissionRequest(toolName, args);
      }

      return new Promise(resolve => {
        this.pendingPermission = { resolve };
      });
    };

    let firstChunk = true;

    try {
      const stream = oracleChatStream(
        text,
        this.conversationHistory.filter(m => m.role !== 'system'),
        p,
        permissionCb,
        mode
      );

      for await (const chunk of stream) {
        if (firstChunk) {
          this.callbacks.onStreamingStart(asstMsgId);
          firstChunk = false;
        }
        this.callbacks.onStreamingChunk(asstMsgId, chunk);
      }

      this.callbacks.onStreamingEnd(asstMsgId);

      if (streamingResult.history.length > 0) {
        this.conversationHistory = streamingResult.history;
      }

      for (const tn of this.activeToolNames) {
        this.callbacks.onToolEnd(tn, '');
      }
      this.activeToolNames.clear();
    } catch (e: any) {
      this.callbacks.onError(e.message || 'An error occurred while processing your request.');
    }
  }

  async configureProvider(provider: string, apiKey: string): Promise<boolean> {
    try {
      storeApiKey(provider, apiKey);
      storeConfig(provider);

      const p = createProvider(provider as any, apiKey);
      if (p) {
        this.provider = p;
        this.providerName = provider;
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  setMode(mode: 'execute' | 'plan' | 'auto'): void {
    this.mode = mode;
  }

  getProvider(): string {
    return this.providerName;
  }

  clearHistory(): void {
    this.conversationHistory = [];
  }

  hasPendingPermission(): boolean {
    return this.pendingPermission !== null;
  }

  approvePermission(): void {
    if (this.pendingPermission) {
      this.pendingPermission.resolve(true);
      this.pendingPermission = null;
    }
  }

  denyPermission(): void {
    if (this.pendingPermission) {
      this.pendingPermission.resolve(false);
      this.pendingPermission = null;
    }
  }
}

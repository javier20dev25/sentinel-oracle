var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
import { oracleChatStream, getDefaultProvider, streamingResult } from '../engine.js';
import { getApiKey, setApiKey as storeApiKey, setConfig as storeConfig, removeApiKey } from '../auth.js';
import { createProvider } from '../providers/index.js';
export class ChatBridge {
    constructor(callbacks) {
        this.providerName = '';
        this.conversationHistory = [];
        this.mode = 'execute';
        this.pendingPermission = null;
        this.activeToolNames = new Set();
        this.callbacks = callbacks || {
            onMessage: () => { },
            onStreamingStart: () => { },
            onStreamingChunk: () => { },
            onStreamingEnd: () => { },
            onToolStart: () => { },
            onToolEnd: () => { },
            onError: () => { },
        };
    }
    setCallbacks(callbacks) {
        this.callbacks = callbacks;
    }
    initialize() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const p = getDefaultProvider();
                if (p) {
                    this.provider = p;
                    this.providerName = p.name;
                    return true;
                }
                return false;
            }
            catch (_a) {
                return false;
            }
        });
    }
    getOrCreateProvider() {
        if (this.provider)
            return this.provider;
        const config = getDefaultProvider();
        if (config) {
            this.provider = config;
            this.providerName = config.name;
            return config;
        }
        return null;
    }
    sendMessage(text) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, e_1, _b, _c;
            var _d, _e;
            if (text.startsWith('/')) {
                const parts = text.slice(1).split(/\s+/);
                const cmd = parts[0].toLowerCase();
                if (cmd === 'logout') {
                    if (this.providerName) {
                        removeApiKey(this.providerName);
                        storeConfig('');
                    }
                    (_e = (_d = this.callbacks).onRestart) === null || _e === void 0 ? void 0 : _e.call(_d);
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
                    const p = createProvider(name, key);
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
            const permissionCb = (toolName, args) => __awaiter(this, void 0, void 0, function* () {
                this.activeToolNames.add(toolName);
                this.callbacks.onToolStart(toolName);
                if (mode === 'auto')
                    return true;
                if (this.callbacks.onPermissionRequest) {
                    this.callbacks.onPermissionRequest(toolName, args);
                }
                return new Promise(resolve => {
                    this.pendingPermission = { resolve };
                });
            });
            let firstChunk = true;
            try {
                const stream = oracleChatStream(text, this.conversationHistory.filter(m => m.role !== 'system'), p, permissionCb, mode);
                try {
                    for (var _f = true, stream_1 = __asyncValues(stream), stream_1_1; stream_1_1 = yield stream_1.next(), _a = stream_1_1.done, !_a; _f = true) {
                        _c = stream_1_1.value;
                        _f = false;
                        const chunk = _c;
                        if (firstChunk) {
                            this.callbacks.onStreamingStart(asstMsgId);
                            firstChunk = false;
                        }
                        this.callbacks.onStreamingChunk(asstMsgId, chunk);
                    }
                }
                catch (e_1_1) { e_1 = { error: e_1_1 }; }
                finally {
                    try {
                        if (!_f && !_a && (_b = stream_1.return)) yield _b.call(stream_1);
                    }
                    finally { if (e_1) throw e_1.error; }
                }
                this.callbacks.onStreamingEnd(asstMsgId);
                if (streamingResult.history.length > 0) {
                    this.conversationHistory = streamingResult.history;
                }
                for (const tn of this.activeToolNames) {
                    this.callbacks.onToolEnd(tn, '');
                }
                this.activeToolNames.clear();
            }
            catch (e) {
                this.callbacks.onError(e.message || 'An error occurred while processing your request.');
            }
        });
    }
    configureProvider(provider, apiKey) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                storeApiKey(provider, apiKey);
                storeConfig(provider);
                const p = createProvider(provider, apiKey);
                if (p) {
                    this.provider = p;
                    this.providerName = provider;
                    return true;
                }
                return false;
            }
            catch (_a) {
                return false;
            }
        });
    }
    setMode(mode) {
        this.mode = mode;
    }
    getProvider() {
        return this.providerName;
    }
    clearHistory() {
        this.conversationHistory = [];
    }
    hasPendingPermission() {
        return this.pendingPermission !== null;
    }
    approvePermission() {
        if (this.pendingPermission) {
            this.pendingPermission.resolve(true);
            this.pendingPermission = null;
        }
    }
    denyPermission() {
        if (this.pendingPermission) {
            this.pendingPermission.resolve(false);
            this.pendingPermission = null;
        }
    }
}

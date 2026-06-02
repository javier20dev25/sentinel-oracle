"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.ChatBridge = void 0;
const engine_js_1 = require("../engine.js");
const auth_js_1 = require("../auth.js");
const index_js_1 = require("../providers/index.js");
class ChatBridge {
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
                const p = (0, engine_js_1.getDefaultProvider)();
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
        const config = (0, engine_js_1.getDefaultProvider)();
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
                const stream = (0, engine_js_1.oracleChatStream)(text, this.conversationHistory.filter(m => m.role !== 'system'), p, permissionCb, mode);
                try {
                    for (var _d = true, stream_1 = __asyncValues(stream), stream_1_1; stream_1_1 = yield stream_1.next(), _a = stream_1_1.done, !_a; _d = true) {
                        _c = stream_1_1.value;
                        _d = false;
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
                        if (!_d && !_a && (_b = stream_1.return)) yield _b.call(stream_1);
                    }
                    finally { if (e_1) throw e_1.error; }
                }
                this.callbacks.onStreamingEnd(asstMsgId);
                if (engine_js_1.streamingResult.history.length > 0) {
                    this.conversationHistory = engine_js_1.streamingResult.history;
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
                (0, auth_js_1.setApiKey)(provider, apiKey);
                (0, auth_js_1.setConfig)(provider);
                const p = (0, index_js_1.createProvider)(provider, apiKey);
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
exports.ChatBridge = ChatBridge;

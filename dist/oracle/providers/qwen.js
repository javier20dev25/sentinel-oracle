var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __await = (this && this.__await) || function (v) { return this instanceof __await ? (this.v = v, this) : new __await(v); }
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
var __asyncGenerator = (this && this.__asyncGenerator) || function (thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = Object.create((typeof AsyncIterator === "function" ? AsyncIterator : Object).prototype), verb("next"), verb("throw"), verb("return", awaitReturn), i[Symbol.asyncIterator] = function () { return this; }, i;
    function awaitReturn(f) { return function (v) { return Promise.resolve(v).then(f, reject); }; }
    function verb(n, f) { if (g[n]) { i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; if (f) i[n] = f(i[n]); } }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
};
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { BaseProvider } from './base.js';
const QWEN_MODEL_URL = 'https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf';
const MODEL_FILENAME = 'qwen2.5-1.5b-instruct-q4_k_m.gguf';
const MODELS_DIR = path.join(os.homedir(), '.sentinel', 'models');
function getModelPath() {
    if (!fs.existsSync(MODELS_DIR))
        fs.mkdirSync(MODELS_DIR, { recursive: true });
    return path.join(MODELS_DIR, MODEL_FILENAME);
}
export class QwenProvider extends BaseProvider {
    constructor(model) {
        super('qwen', model || 'qwen2.5-1.5b', 'local');
        this._llama = null;
        this._model = null;
        this._context = null;
        this._sequence = null;
        this._initialized = false;
        this._initPromise = null;
        this.modelPath = getModelPath();
    }
    isDownloaded() {
        return fs.existsSync(this.modelPath);
    }
    getModelSize() {
        if (!fs.existsSync(this.modelPath))
            return 0;
        return fs.statSync(this.modelPath).size;
    }
    download(progressCb) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.isDownloaded())
                return;
            const response = yield fetch(QWEN_MODEL_URL);
            if (!response.ok)
                throw new Error(`Failed to download model: ${response.status} ${response.statusText}`);
            const total = parseInt(response.headers.get('content-length') || '0', 10);
            const reader = response.body.getReader();
            const writer = fs.createWriteStream(this.modelPath);
            let downloaded = 0;
            const buf = new Uint8Array(1024 * 64);
            while (true) {
                const { done, value } = yield reader.read();
                if (done)
                    break;
                writer.write(Buffer.from(value));
                downloaded += value.length;
                progressCb === null || progressCb === void 0 ? void 0 : progressCb(downloaded, total);
            }
            writer.end();
            yield new Promise((resolve, reject) => {
                writer.on('finish', resolve);
                writer.on('error', reject);
            });
        });
    }
    ensureInitialized() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this._initialized)
                return;
            if (this._initPromise)
                return this._initPromise;
            this._initPromise = (() => __awaiter(this, void 0, void 0, function* () {
                const { getLlama } = yield import('node-llama-cpp');
                this._llama = yield getLlama();
                this._model = new this._llama.LlamaModel({ modelPath: this.modelPath });
                this._context = yield this._model.createContext();
                this._sequence = this._context.getSequence();
                this._initialized = true;
            }))();
            yield this._initPromise;
        });
    }
    runInference(messages, tools) {
        return __asyncGenerator(this, arguments, function* runInference_1() {
            var _a, e_1, _b, _c;
            yield __await(this.ensureInitialized());
            const systemMsg = messages.find(m => m.role === 'system');
            const chatMessages = messages.filter(m => m.role !== 'system').map(m => {
                if (m.role === 'tool') {
                    return { role: 'tool', content: m.content, name: m.tool_call_id || 'function' };
                }
                if (m.role === 'assistant') {
                    return { role: 'assistant', content: m.content };
                }
                return { role: 'user', content: m.content };
            });
            const prompt = this.buildPrompt((systemMsg === null || systemMsg === void 0 ? void 0 : systemMsg.content) || 'You are Sentinel Oracle, a security AI assistant.', chatMessages, tools);
            // Tokenize to estimate
            const tokens = this._model.tokenize(prompt);
            const maxTokens = Math.min(4096 - tokens.length, 2048);
            let fullText = '';
            try {
                for (var _d = true, _e = __asyncValues(this._sequence.complete(prompt, {
                    temperature: 0.6,
                    maxTokens,
                    topP: 0.9,
                    repeatPenalty: 1.1,
                    stream: true,
                })), _f; _f = yield __await(_e.next()), _a = _f.done, !_a; _d = true) {
                    _c = _f.value;
                    _d = false;
                    const chunk = _c;
                    const text = typeof chunk === 'string' ? chunk : chunk.text || '';
                    if (text) {
                        fullText += text;
                        yield yield __await({ content: text, done: false });
                    }
                }
            }
            catch (e_1_1) { e_1 = { error: e_1_1 }; }
            finally {
                try {
                    if (!_d && !_a && (_b = _e.return)) yield __await(_b.call(_e));
                }
                finally { if (e_1) throw e_1.error; }
            }
            // Try to parse tool calls from the response
            const toolCalls = this.parseToolCalls(fullText);
            if (toolCalls.length > 0) {
                yield yield __await({ toolCalls, done: true });
                return yield __await(void 0);
            }
            yield yield __await({ done: true });
        });
    }
    buildPrompt(system, messages, tools) {
        let prompt = `<|im_start|>system\n${system}`;
        if (tools && tools.length > 0) {
            prompt += `\n\nYou have access to the following tools. When you want to use a tool, respond with a JSON block:\n\`\`\`json\n{"tool": "<tool_name>", "args": {...}}\n\`\`\`\n\nTools:\n${JSON.stringify(tools.map(t => ({ name: t.name, description: t.description, parameters: t.parameters })), null, 2)}`;
        }
        prompt += `<|im_end|>\n`;
        for (const msg of messages) {
            if (msg.role === 'tool') {
                prompt += `<|im_start|>tool\n${msg.content}<|im_end|>\n`;
            }
            else if (msg.role === 'assistant') {
                prompt += `<|im_start|>assistant\n${msg.content}<|im_end|>\n`;
            }
            else {
                prompt += `<|im_start|>user\n${msg.content}<|im_end|>\n`;
            }
        }
        prompt += `<|im_start|>assistant\n`;
        return prompt;
    }
    parseToolCalls(text) {
        const calls = [];
        const jsonBlockRegex = /```json\s*({[\s\S]*?})\s*```/g;
        let match;
        while ((match = jsonBlockRegex.exec(text)) !== null) {
            try {
                const parsed = JSON.parse(match[1]);
                if (parsed.tool && parsed.args) {
                    calls.push({
                        id: `${parsed.tool}-${Date.now()}`,
                        name: parsed.tool,
                        arguments: parsed.args,
                    });
                }
            }
            catch ( /* skip invalid json */_a) { /* skip invalid json */ }
        }
        return calls;
    }
    chat(messages, tools) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, e_2, _b, _c;
            let fullContent = '';
            let toolCalls;
            try {
                for (var _d = true, _e = __asyncValues(this.runInference(messages, tools)), _f; _f = yield _e.next(), _a = _f.done, !_a; _d = true) {
                    _c = _f.value;
                    _d = false;
                    const chunk = _c;
                    if (chunk.content)
                        fullContent += chunk.content;
                    if (chunk.toolCalls)
                        toolCalls = chunk.toolCalls;
                }
            }
            catch (e_2_1) { e_2 = { error: e_2_1 }; }
            finally {
                try {
                    if (!_d && !_a && (_b = _e.return)) yield _b.call(_e);
                }
                finally { if (e_2) throw e_2.error; }
            }
            return { content: fullContent, toolCalls };
        });
    }
    stream(messages, tools) {
        return __asyncGenerator(this, arguments, function* stream_1() {
            var _a, e_3, _b, _c;
            try {
                for (var _d = true, _e = __asyncValues(this.runInference(messages, tools)), _f; _f = yield __await(_e.next()), _a = _f.done, !_a; _d = true) {
                    _c = _f.value;
                    _d = false;
                    const chunk = _c;
                    yield yield __await({
                        content: chunk.content || '',
                        toolCalls: chunk.toolCalls,
                        done: chunk.done,
                    });
                }
            }
            catch (e_3_1) { e_3 = { error: e_3_1 }; }
            finally {
                try {
                    if (!_d && !_a && (_b = _e.return)) yield __await(_b.call(_e));
                }
                finally { if (e_3) throw e_3.error; }
            }
        });
    }
    validateConfig() {
        return true;
    }
}

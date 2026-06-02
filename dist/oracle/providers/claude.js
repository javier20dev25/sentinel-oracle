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
import Anthropic from '@anthropic-ai/sdk';
import { BaseProvider } from './base.js';
function toClaudeTools(tools) {
    if (!tools || tools.length === 0)
        return undefined;
    return tools.map(t => ({
        name: t.name,
        description: t.description,
        input_schema: t.parameters,
    }));
}
export class ClaudeProvider extends BaseProvider {
    constructor(apiKey, model = 'claude-sonnet-4-20250514') {
        super('claude', model, apiKey);
        this.client = new Anthropic({ apiKey });
    }
    chat(messages, tools) {
        return __awaiter(this, void 0, void 0, function* () {
            const systemMsg = messages.find(m => m.role === 'system');
            const chatMessages = messages
                .filter(m => m.role !== 'system')
                .map(m => {
                if (m.role === 'tool') {
                    return {
                        role: 'user',
                        content: [{ type: 'tool_result', tool_use_id: m.tool_call_id || '', content: m.content }],
                    };
                }
                return { role: m.role, content: m.content };
            });
            const msg = yield this.client.messages.create({
                model: this.model,
                max_tokens: 4096,
                system: (systemMsg === null || systemMsg === void 0 ? void 0 : systemMsg.content) || undefined,
                messages: chatMessages,
                tools: toClaudeTools(tools),
            });
            const toolCalls = [];
            let text = '';
            for (const block of msg.content) {
                if (block.type === 'text') {
                    text += block.text;
                }
                else if (block.type === 'tool_use') {
                    toolCalls.push({
                        id: block.id,
                        name: block.name,
                        arguments: block.input,
                    });
                }
            }
            if (toolCalls.length > 0) {
                return { content: text, toolCalls };
            }
            return { content: text };
        });
    }
    stream(messages, tools) {
        return __asyncGenerator(this, arguments, function* stream_1() {
            var _a, e_1, _b, _c;
            var _d, _e, _f, _g, _h;
            const systemMsg = messages.find(m => m.role === 'system');
            const chatMessages = messages
                .filter(m => m.role !== 'system')
                .map(m => {
                if (m.role === 'tool') {
                    return {
                        role: 'user',
                        content: [{ type: 'tool_result', tool_use_id: m.tool_call_id || '', content: m.content }],
                    };
                }
                return { role: m.role, content: m.content };
            });
            const stream = yield __await(this.client.messages.create({
                model: this.model,
                max_tokens: 4096,
                system: (systemMsg === null || systemMsg === void 0 ? void 0 : systemMsg.content) || undefined,
                messages: chatMessages,
                tools: toClaudeTools(tools),
                stream: true,
            }));
            const toolCallAccum = {};
            try {
                for (var _j = true, stream_2 = __asyncValues(stream), stream_2_1; stream_2_1 = yield __await(stream_2.next()), _a = stream_2_1.done, !_a; _j = true) {
                    _c = stream_2_1.value;
                    _j = false;
                    const event = _c;
                    if (event.type === 'content_block_delta' && ((_d = event.delta) === null || _d === void 0 ? void 0 : _d.type) === 'text_delta') {
                        yield yield __await({ content: event.delta.text, done: false });
                    }
                    if (event.type === 'content_block_start' && ((_e = event.content_block) === null || _e === void 0 ? void 0 : _e.type) === 'tool_use') {
                        const idx = (_f = event.index) !== null && _f !== void 0 ? _f : 0;
                        toolCallAccum[idx] = {
                            id: event.content_block.id,
                            name: event.content_block.name,
                            input: '',
                        };
                    }
                    if (event.type === 'content_block_delta' && ((_g = event.delta) === null || _g === void 0 ? void 0 : _g.type) === 'input_json_delta') {
                        const idx = (_h = event.index) !== null && _h !== void 0 ? _h : 0;
                        if (toolCallAccum[idx]) {
                            toolCallAccum[idx].input += event.delta.partial_json || '';
                        }
                    }
                }
            }
            catch (e_1_1) { e_1 = { error: e_1_1 }; }
            finally {
                try {
                    if (!_j && !_a && (_b = stream_2.return)) yield __await(_b.call(stream_2));
                }
                finally { if (e_1) throw e_1.error; }
            }
            const toolCalls = Object.values(toolCallAccum).map(tc => ({
                id: tc.id,
                name: tc.name,
                arguments: (() => { try {
                    return JSON.parse(tc.input);
                }
                catch (_a) {
                    return {};
                } })(),
            }));
            if (toolCalls.length > 0) {
                yield yield __await({ toolCalls, done: true });
            }
            else {
                yield yield __await({ done: true });
            }
        });
    }
}

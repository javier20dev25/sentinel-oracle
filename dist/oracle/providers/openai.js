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
import OpenAI from 'openai';
import { BaseProvider } from './base.js';
function toOpenAITools(tools) {
    if (!tools || tools.length === 0)
        return undefined;
    return tools.map(t => ({
        type: 'function',
        function: {
            name: t.name,
            description: t.description,
            parameters: t.parameters,
        },
    }));
}
export class OpenAIProvider extends BaseProvider {
    constructor(apiKey, model = 'gpt-4o', baseURL) {
        super('openai', model, apiKey);
        this.client = new OpenAI({ apiKey, baseURL });
    }
    chat(messages, tools) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.client.chat.completions.create({
                model: this.model,
                messages: messages,
                max_tokens: 4096,
                tools: toOpenAITools(tools),
            });
            const choice = response.choices[0];
            const msg = choice === null || choice === void 0 ? void 0 : choice.message;
            if (!msg)
                return { content: '' };
            if (msg.tool_calls && msg.tool_calls.length > 0) {
                const toolCalls = msg.tool_calls.map(tc => {
                    const fn = tc.function || { name: '', arguments: '{}' };
                    return {
                        id: tc.id,
                        name: fn.name,
                        arguments: (() => {
                            try {
                                return JSON.parse(fn.arguments);
                            }
                            catch (_a) {
                                return {};
                            }
                        })(),
                    };
                });
                return { content: msg.content || '', toolCalls };
            }
            return { content: msg.content || '' };
        });
    }
    stream(messages, tools) {
        return __asyncGenerator(this, arguments, function* stream_1() {
            var _a, e_1, _b, _c;
            var _d, _e, _f, _g, _h;
            const stream = yield __await(this.client.chat.completions.create({
                model: this.model,
                messages: messages,
                max_tokens: 4096,
                tools: toOpenAITools(tools),
                stream: true,
            }));
            const toolCallAccum = {};
            try {
                for (var _j = true, stream_2 = __asyncValues(stream), stream_2_1; stream_2_1 = yield __await(stream_2.next()), _a = stream_2_1.done, !_a; _j = true) {
                    _c = stream_2_1.value;
                    _j = false;
                    const chunk = _c;
                    const delta = (_e = (_d = chunk.choices) === null || _d === void 0 ? void 0 : _d[0]) === null || _e === void 0 ? void 0 : _e.delta;
                    if (!delta)
                        continue;
                    if (delta.content) {
                        yield yield __await({ content: delta.content, done: false });
                    }
                    if (delta.tool_calls) {
                        for (const tc of delta.tool_calls) {
                            const index = tc.index;
                            if (!toolCallAccum[index]) {
                                toolCallAccum[index] = { id: tc.id || '', name: ((_f = tc.function) === null || _f === void 0 ? void 0 : _f.name) || '', args: '' };
                            }
                            if (tc.id)
                                toolCallAccum[index].id = tc.id;
                            if ((_g = tc.function) === null || _g === void 0 ? void 0 : _g.name)
                                toolCallAccum[index].name += tc.function.name;
                            if ((_h = tc.function) === null || _h === void 0 ? void 0 : _h.arguments)
                                toolCallAccum[index].args += tc.function.arguments;
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
                    return JSON.parse(tc.args);
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

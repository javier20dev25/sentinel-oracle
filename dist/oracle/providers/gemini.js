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
import { GoogleGenerativeAI } from '@google/generative-ai';
import { BaseProvider } from './base.js';
function toGeminiTools(tools) {
    if (!tools || tools.length === 0)
        return undefined;
    return tools.map(t => ({
        functionDeclarations: [{
                name: t.name,
                description: t.description,
                parameters: t.parameters,
            }],
    }));
}
function toRole(role) {
    if (role === 'assistant')
        return 'model';
    if (role === 'tool')
        return 'function';
    return 'user';
}
function extractToolCalls(parts) {
    const calls = [];
    for (const p of parts) {
        if (p.functionCall) {
            calls.push({
                id: p.functionCall.name,
                name: p.functionCall.name,
                arguments: (() => {
                    try {
                        const obj = {};
                        if (p.functionCall.args) {
                            for (const [k, v] of Object.entries(p.functionCall.args)) {
                                obj[k] = String(v);
                            }
                        }
                        return obj;
                    }
                    catch (_a) {
                        return {};
                    }
                })(),
            });
        }
    }
    return calls.length > 0 ? calls : undefined;
}
export class GeminiProvider extends BaseProvider {
    constructor(apiKey, model = 'gemini-2.0-flash') {
        super('gemini', model, apiKey);
        this.client = new GoogleGenerativeAI(apiKey);
        this.modelInst = this.client.getGenerativeModel({ model });
    }
    chat(messages, tools) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b, _c;
            const history = messages.slice(0, -1).map(m => ({
                role: toRole(m.role),
                parts: [{ text: m.content }],
            }));
            const lastMsg = messages[messages.length - 1];
            const chat = this.modelInst.startChat({
                history,
                tools: toGeminiTools(tools),
            });
            const result = yield chat.sendMessage(lastMsg.content);
            const response = result.response;
            const parts = ((_c = (_b = (_a = response.candidates) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.content) === null || _c === void 0 ? void 0 : _c.parts) || [];
            const toolCalls = extractToolCalls(parts);
            if (toolCalls) {
                return { content: '', toolCalls };
            }
            return { content: response.text() };
        });
    }
    stream(messages, tools) {
        return __asyncGenerator(this, arguments, function* stream_1() {
            var _a, e_1, _b, _c;
            var _d, _e, _f;
            const history = messages.slice(0, -1).map(m => ({
                role: toRole(m.role),
                parts: [{ text: m.content }],
            }));
            const lastMsg = messages[messages.length - 1];
            const chat = this.modelInst.startChat({
                history,
                tools: toGeminiTools(tools),
            });
            const result = yield __await(chat.sendMessageStream(lastMsg.content));
            try {
                for (var _g = true, _h = __asyncValues(result.stream), _j; _j = yield __await(_h.next()), _a = _j.done, !_a; _g = true) {
                    _c = _j.value;
                    _g = false;
                    const chunk = _c;
                    const textChunk = chunk.text();
                    if (textChunk) {
                        yield yield __await({ content: textChunk, done: false });
                    }
                }
            }
            catch (e_1_1) { e_1 = { error: e_1_1 }; }
            finally {
                try {
                    if (!_g && !_a && (_b = _h.return)) yield __await(_b.call(_h));
                }
                finally { if (e_1) throw e_1.error; }
            }
            const response = yield __await(result.response);
            const parts = ((_f = (_e = (_d = response.candidates) === null || _d === void 0 ? void 0 : _d[0]) === null || _e === void 0 ? void 0 : _e.content) === null || _f === void 0 ? void 0 : _f.parts) || [];
            const toolCalls = extractToolCalls(parts);
            if (toolCalls) {
                yield yield __await({ toolCalls, done: true });
                return yield __await(void 0);
            }
            yield yield __await({ done: true });
        });
    }
}

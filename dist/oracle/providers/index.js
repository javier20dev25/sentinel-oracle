"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OllamaProvider = exports.OpenAIProvider = exports.ClaudeProvider = exports.GeminiProvider = exports.BaseProvider = void 0;
exports.createProvider = createProvider;
const gemini_1 = require("./gemini");
const claude_1 = require("./claude");
const openai_1 = require("./openai");
const ollama_1 = require("./ollama");
var base_1 = require("./base");
Object.defineProperty(exports, "BaseProvider", { enumerable: true, get: function () { return base_1.BaseProvider; } });
var gemini_2 = require("./gemini");
Object.defineProperty(exports, "GeminiProvider", { enumerable: true, get: function () { return gemini_2.GeminiProvider; } });
var claude_2 = require("./claude");
Object.defineProperty(exports, "ClaudeProvider", { enumerable: true, get: function () { return claude_2.ClaudeProvider; } });
var openai_2 = require("./openai");
Object.defineProperty(exports, "OpenAIProvider", { enumerable: true, get: function () { return openai_2.OpenAIProvider; } });
var ollama_2 = require("./ollama");
Object.defineProperty(exports, "OllamaProvider", { enumerable: true, get: function () { return ollama_2.OllamaProvider; } });
function createProvider(name, apiKey, model) {
    switch (name) {
        case 'gemini': return new gemini_1.GeminiProvider(apiKey, model);
        case 'claude': return new claude_1.ClaudeProvider(apiKey, model);
        case 'openai': return new openai_1.OpenAIProvider(apiKey, model);
        case 'ollama': return new ollama_1.OllamaProvider(model);
        default: throw new Error(`Unknown provider: ${name}`);
    }
}

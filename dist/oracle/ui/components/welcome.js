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
Object.defineProperty(exports, "__esModule", { value: true });
exports.Welcome = Welcome;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const ink_1 = require("ink");
const oauth_js_1 = require("../oauth.js");
const auth_js_1 = require("../../auth.js");
const PROVIDERS = [
    { id: 'gemini', icon: '☀️', name: 'Gemini', desc: 'Google AI models', needsKey: true },
    { id: 'claude', icon: '🧠', name: 'Claude', desc: 'Anthropic AI assistant', needsKey: true },
    { id: 'openai', icon: '⚡', name: 'OpenAI', desc: 'GPT-4 and GPT models', needsKey: true },
    { id: 'ollama', icon: '💻', name: 'Ollama', desc: 'Local open-source models', needsKey: false },
];
function Welcome({ onComplete }) {
    const [phase, setPhase] = (0, react_1.useState)('select');
    const [selectedIndex, setSelectedIndex] = (0, react_1.useState)(0);
    const [chosenProvider, setChosenProvider] = (0, react_1.useState)(null);
    const [apiKey, setApiKey] = (0, react_1.useState)('');
    const [oauthStatus, setOauthStatus] = (0, react_1.useState)('');
    const [oauthError, setOauthError] = (0, react_1.useState)('');
    const finishSetup = (0, react_1.useCallback)((provider, key) => {
        (0, auth_js_1.setApiKey)(provider, key);
        (0, auth_js_1.setConfig)(provider);
        setPhase('done');
        onComplete({ provider, apiKey: key });
    }, [onComplete]);
    const tryOAuth = (0, react_1.useCallback)((prov) => __awaiter(this, void 0, void 0, function* () {
        setPhase('oauth');
        setOauthStatus(`Opening browser for ${prov.name} authentication...`);
        setOauthError('');
        const token = yield (0, oauth_js_1.oauthLogin)(prov.id);
        if (token) {
            finishSetup(prov.id, token);
        }
        else {
            setOauthStatus('');
            setOauthError('OAuth failed or timed out. You can paste your API key manually.');
            setPhase('input');
        }
    }), [finishSetup]);
    const handleSelectProvider = (0, react_1.useCallback)((input, key) => {
        if (key.upArrow) {
            setSelectedIndex(i => (i > 0 ? i - 1 : PROVIDERS.length - 1));
        }
        else if (key.downArrow) {
            setSelectedIndex(i => (i < PROVIDERS.length - 1 ? i + 1 : 0));
        }
        else if (key.return) {
            const prov = PROVIDERS[selectedIndex];
            setChosenProvider(prov);
            if (prov.needsKey) {
                tryOAuth(prov);
            }
            else {
                finishSetup(prov.id, 'local');
            }
        }
        else if (key.escape) {
            onComplete(null);
        }
    }, [selectedIndex, onComplete, tryOAuth, finishSetup]);
    const handleApiInput = (0, react_1.useCallback)((input, key) => {
        if (key.return) {
            if (apiKey.trim().length > 0 && chosenProvider) {
                finishSetup(chosenProvider.id, apiKey.trim());
            }
        }
        else if (key.escape) {
            setApiKey('');
            setOauthError('');
            setPhase('select');
        }
        else if (key.backspace || key.delete) {
            setApiKey(prev => prev.slice(0, -1));
        }
        else if (input && input.length === 1 && input.charCodeAt(0) >= 32) {
            setApiKey(prev => prev + input);
        }
    }, [apiKey, chosenProvider, finishSetup]);
    (0, ink_1.useInput)(phase === 'select' ? handleSelectProvider :
        phase === 'input' ? handleApiInput :
            () => { });
    if (phase === 'done') {
        return ((0, jsx_runtime_1.jsxs)(ink_1.Box, { flexDirection: "column", alignItems: "center", padding: 1, children: [(0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#22c55e", bold: true, children: "\u2713 Connected" }) }), (0, jsx_runtime_1.jsxs)(ink_1.Box, { children: [(0, jsx_runtime_1.jsxs)(ink_1.Text, { color: "#e0e0e0", children: [chosenProvider === null || chosenProvider === void 0 ? void 0 : chosenProvider.icon, " "] }), (0, jsx_runtime_1.jsx)(ink_1.Text, { bold: true, color: "#00d4aa", children: chosenProvider === null || chosenProvider === void 0 ? void 0 : chosenProvider.name })] })] }));
    }
    return ((0, jsx_runtime_1.jsxs)(ink_1.Box, { flexDirection: "column", padding: 1, paddingX: 2, children: [(0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { bold: true, color: "#00d4aa", children: "\u2726 Sentinel Oracle" }) }), (0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", children: "AI Security Assistant" }) }), (0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#e0e0e0", children: "Let's connect your AI provider." }) }), phase === 'select' && ((0, jsx_runtime_1.jsxs)(ink_1.Box, { flexDirection: "column", marginBottom: 1, children: [PROVIDERS.map((prov, i) => {
                        const isSelected = i === selectedIndex;
                        return ((0, jsx_runtime_1.jsxs)(ink_1.Box, Object.assign({ paddingX: 1, paddingY: 0 }, (isSelected ? { backgroundColor: '#1a1a2e' } : {}), { children: [(0, jsx_runtime_1.jsx)(ink_1.Text, { color: isSelected ? '#00d4aa' : '#6b7280', children: isSelected ? '▸ ' : '  ' }), (0, jsx_runtime_1.jsxs)(ink_1.Text, { color: "#e0e0e0", children: [prov.icon, " ", prov.name] }), (0, jsx_runtime_1.jsxs)(ink_1.Text, { dimColor: true, color: "#6b7280", children: [" \u2014 ", prov.desc] })] }), prov.id));
                    }), (0, jsx_runtime_1.jsx)(ink_1.Box, { marginTop: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", children: "  \u2191\u2193 Navigate \u00B7 Enter select \u00B7 Esc cancel" }) })] })), phase === 'oauth' && ((0, jsx_runtime_1.jsxs)(ink_1.Box, { flexDirection: "column", marginBottom: 1, children: [(0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#a78bfa", children: oauthStatus }) }), (0, jsx_runtime_1.jsx)(ink_1.Box, { children: (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", children: "Waiting for browser authentication..." }) })] })), phase === 'input' && ((0, jsx_runtime_1.jsxs)(ink_1.Box, { flexDirection: "column", marginBottom: 1, children: [oauthError && ((0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#ef4444", children: oauthError }) })), (0, jsx_runtime_1.jsx)(ink_1.Box, { marginBottom: 1, children: (0, jsx_runtime_1.jsxs)(ink_1.Text, { color: "#e0e0e0", children: ["Paste your ", chosenProvider === null || chosenProvider === void 0 ? void 0 : chosenProvider.name, " API key:"] }) }), (0, jsx_runtime_1.jsx)(ink_1.Box, { borderStyle: "round", borderColor: "#00d4aa", paddingX: 1, minWidth: 40, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { color: "#e0e0e0", children: apiKey.length === 0
                                ? (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", children: "Enter API key..." })
                                : apiKey.split('').map((ch, i) => i < apiKey.length - 4 ? '•' : ch).join('') }) }), (0, jsx_runtime_1.jsx)(ink_1.Box, { marginTop: 1, children: (0, jsx_runtime_1.jsx)(ink_1.Text, { dimColor: true, color: "#6b7280", children: "  Enter confirm \u00B7 Esc back" }) })] }))] }));
}

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useCallback } from 'react';
import { Box, Text, useInput } from 'ink';
import { execFileSync } from 'child_process';
import { oauthLogin } from '../oauth.js';
import { setApiKey as storeApiKey, setConfig as storeConfig } from '../../auth.js';
import { QwenProvider } from '../../providers/qwen.js';
const PROVIDERS = [
    { id: 'gemini', icon: '☀️', name: 'Gemini', desc: 'Google AI models', needsKey: true },
    { id: 'claude', icon: '🧠', name: 'Claude', desc: 'Anthropic AI assistant', needsKey: true },
    { id: 'openai', icon: '⚡', name: 'OpenAI', desc: 'GPT-4 and GPT models', needsKey: true },
    { id: 'ollama', icon: '💻', name: 'Ollama', desc: 'Local open-source models', needsKey: false },
    { id: 'qwen', icon: '🔌', name: 'Qwen', desc: 'Local 1.5B model (download on first use)', needsKey: false },
];
export function Welcome({ onComplete }) {
    const [phase, setPhase] = useState('select');
    const [selectedIndex, setSelectedIndex] = useState(0);
    const [chosenProvider, setChosenProvider] = useState(null);
    const [apiKey, setApiKey] = useState('');
    const [oauthStatus, setOauthStatus] = useState('');
    const [oauthError, setOauthError] = useState('');
    const [downloadProgress, setDownloadProgress] = useState(0);
    const [downloadTotal, setDownloadTotal] = useState(0);
    const finishSetup = useCallback((provider, key) => {
        storeApiKey(provider, key);
        storeConfig(provider);
        setPhase('done');
        onComplete({ provider, apiKey: key });
    }, [onComplete]);
    const tryOAuth = useCallback((prov) => __awaiter(this, void 0, void 0, function* () {
        setPhase('oauth');
        setOauthStatus(`Opening browser for ${prov.name} authentication...`);
        setOauthError('');
        const token = yield oauthLogin(prov.id);
        if (token) {
            finishSetup(prov.id, token);
        }
        else {
            setOauthStatus('');
            setOauthError('OAuth failed or timed out. You can paste your API key manually.');
            setPhase('input');
        }
    }), [finishSetup]);
    const handleSelectProvider = useCallback((input, key) => {
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
            else if (prov.id === 'qwen') {
                // Check if model exists
                const qwen = new QwenProvider();
                if (qwen.isDownloaded()) {
                    finishSetup(prov.id, 'local');
                }
                else {
                    startDownload(qwen);
                }
            }
            else {
                finishSetup(prov.id, 'local');
            }
        }
        else if (key.escape) {
            onComplete(null);
        }
    }, [selectedIndex, onComplete, tryOAuth, finishSetup]);
    const startDownload = useCallback((qwen) => __awaiter(this, void 0, void 0, function* () {
        setPhase('downloading');
        try {
            yield qwen.download((downloaded, total) => {
                setDownloadProgress(downloaded);
                setDownloadTotal(total);
            });
            finishSetup('qwen', 'local');
        }
        catch (e) {
            setPhase('select');
        }
    }), [finishSetup]);
    const pasteFromClipboard = useCallback(() => {
        try {
            const clipboard = execFileSync('powershell', ['-command', 'Get-Clipboard'], { timeout: 2000, encoding: 'utf-8' });
            if (clipboard)
                setApiKey(prev => prev + clipboard.trim());
        }
        catch (_a) { }
    }, []);
    const handleApiInput = useCallback((input, key) => {
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
        else if (key.ctrl && key.name === 'v') {
            pasteFromClipboard();
        }
        else if (input && input.charCodeAt(0) >= 32) {
            setApiKey(prev => prev + input);
        }
    }, [apiKey, chosenProvider, finishSetup, pasteFromClipboard]);
    useInput(phase === 'select' ? handleSelectProvider :
        phase === 'input' ? handleApiInput :
            () => { });
    if (phase === 'done') {
        return (_jsxs(Box, { flexDirection: "column", alignItems: "center", padding: 1, children: [_jsx(Box, { marginBottom: 1, children: _jsx(Text, { color: "#22c55e", bold: true, children: "\u2713 Connected" }) }), _jsxs(Box, { children: [_jsxs(Text, { color: "#e0e0e0", children: [chosenProvider === null || chosenProvider === void 0 ? void 0 : chosenProvider.icon, " "] }), _jsx(Text, { bold: true, color: "#00d4aa", children: chosenProvider === null || chosenProvider === void 0 ? void 0 : chosenProvider.name })] })] }));
    }
    return (_jsxs(Box, { flexDirection: "column", padding: 1, paddingX: 2, children: [_jsx(Box, { marginBottom: 1, children: _jsx(Text, { bold: true, color: "#00d4aa", children: "\u2726 Sentinel Oracle" }) }), _jsx(Box, { marginBottom: 1, children: _jsx(Text, { dimColor: true, color: "#6b7280", children: "AI Security Assistant" }) }), _jsx(Box, { marginBottom: 1, children: _jsx(Text, { color: "#e0e0e0", children: "Let's connect your AI provider." }) }), phase === 'select' && (_jsxs(Box, { flexDirection: "column", marginBottom: 1, children: [PROVIDERS.map((prov, i) => {
                        const isSelected = i === selectedIndex;
                        return (_jsxs(Box, Object.assign({ paddingX: 1, paddingY: 0 }, (isSelected ? { backgroundColor: '#1a1a2e' } : {}), { children: [_jsx(Text, { color: isSelected ? '#00d4aa' : '#6b7280', children: isSelected ? '▸ ' : '  ' }), _jsxs(Text, { color: "#e0e0e0", children: [prov.icon, " ", prov.name] }), _jsxs(Text, { dimColor: true, color: "#6b7280", children: [" \u2014 ", prov.desc] })] }), prov.id));
                    }), _jsx(Box, { marginTop: 1, children: _jsx(Text, { dimColor: true, color: "#6b7280", children: "  \u2191\u2193 Navigate \u00B7 Enter select \u00B7 Esc cancel" }) })] })), phase === 'oauth' && (_jsxs(Box, { flexDirection: "column", marginBottom: 1, children: [_jsx(Box, { marginBottom: 1, children: _jsx(Text, { color: "#a78bfa", children: oauthStatus }) }), _jsx(Box, { children: _jsx(Text, { dimColor: true, color: "#6b7280", children: "Waiting for browser authentication..." }) })] })), phase === 'downloading' && (_jsxs(Box, { flexDirection: "column", marginBottom: 1, children: [_jsx(Box, { marginBottom: 1, children: _jsx(Text, { color: "#a78bfa", children: "\u2726 Downloading Qwen 2.5 1.5B model..." }) }), _jsx(Box, { children: _jsx(Text, { dimColor: true, color: "#6b7280", children: downloadTotal > 0
                                ? `${(downloadProgress / 1024 / 1024).toFixed(1)} MB / ${(downloadTotal / 1024 / 1024).toFixed(1)} MB`
                                : 'Starting download...' }) }), downloadTotal > 0 && (_jsx(Box, { marginTop: 1, width: 40, children: _jsx(Box, { width: Math.round(40 * downloadProgress / downloadTotal), children: _jsx(Text, { color: "#00d4aa", children: '█'.repeat(Math.max(1, Math.round(40 * downloadProgress / downloadTotal))) }) }) }))] })), phase === 'input' && (_jsxs(Box, { flexDirection: "column", marginBottom: 1, children: [oauthError && (_jsx(Box, { marginBottom: 1, children: _jsx(Text, { color: "#ef4444", children: oauthError }) })), _jsx(Box, { marginBottom: 1, children: _jsxs(Text, { color: "#e0e0e0", children: ["Paste your ", chosenProvider === null || chosenProvider === void 0 ? void 0 : chosenProvider.name, " API key:"] }) }), _jsx(Box, { borderStyle: "round", borderColor: "#00d4aa", paddingX: 1, minWidth: 40, children: _jsx(Text, { color: "#e0e0e0", children: apiKey.length === 0
                                ? _jsx(Text, { dimColor: true, color: "#6b7280", children: "Enter API key..." })
                                : apiKey.split('').map((ch, i) => i < apiKey.length - 4 ? '•' : ch).join('') }) }), _jsx(Box, { marginTop: 1, children: _jsx(Text, { dimColor: true, color: "#6b7280", children: "  Enter confirm \u00B7 Esc back" }) })] }))] }));
}
